/**
 * The soft-gated guard wired to the file-backed operator approval channel:
 * an `ask` is recorded as pending, the operator (not the agent) approves it, and
 * the retry of the exact same call is released once.
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import { addToAllowlist, guardToolCall } from "../guard.js";
import {
	clearOperatorApprovalKeyCache,
	listPendingAsks,
	type OperatorApprovalStoreOptions,
	recordOperatorApproval,
} from "../operator-approvals.js";
import type { Verdict } from "../types.js";

vi.mock("../evaluator.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return { ...original, evaluateToolCall: vi.fn() };
});
vi.mock("../config.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return { ...original, loadConfig: vi.fn() };
});
vi.mock("../allowlist.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return {
		...original,
		loadAllowlist: vi.fn(async () => ({ urls: {}, commands: {}, filePaths: {} })),
		saveAllowlist: vi.fn(async () => true),
	};
});

const { evaluateToolCall } = await import("../evaluator.js");
const { loadConfig } = await import("../config.js");
const { saveAllowlist } = await import("../allowlist.js");

const ASK: Verdict = {
	decision: "ask",
	category: "permissions",
	confidence: 0.9,
	severity: "warning",
	source: "heuristic",
	artifacts: [],
	matchedThreatId: "CLT-TEST-001",
	reasons: ["World-writable permissions"],
};

const request = {
	sessionId: "session-1",
	toolName: "bash",
	toolInput: { command: "chmod 777 ./deploy.sh" },
	artifacts: [{ type: "command" as const, value: "chmod 777 ./deploy.sh" }],
};
const context = {
	threatsDir: "/threats",
	allowlistsDir: "/allowlists",
	agentRuntime: "openclaw" as const,
};

let dir: string;
let operatorApprovals: OperatorApprovalStoreOptions;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-guard-operator-"));
	clearOperatorApprovalKeyCache();
	const key = randomBytes(32);
	operatorApprovals = {
		path: join(dir, "approvals.json"),
		keyProvider: { load: () => ({ key, location: "file", store: "file" }) },
	};
	vi.mocked(evaluateToolCall).mockResolvedValue(ASK);
	vi.mocked(loadConfig).mockResolvedValue({
		sensitivity: "balanced",
		allowlist: { path: join(dir, "allowlist.json") },
	} as unknown as Awaited<ReturnType<typeof loadConfig>>);
});

afterEach(() => {
	clearOperatorApprovalKeyCache();
	rmSync(dir, { recursive: true, force: true });
	vi.clearAllMocks();
});

describe("guardToolCall with the operator approval channel", () => {
	it("records every ask as a pending ask the operator can see", async () => {
		const result = await guardToolCall(request, context, new ApprovalStore(), {
			operatorApprovals,
		});
		expect(result.verdict.decision).toBe("ask");
		expect(result.pendingRecorded).toBe(true);
		const pending = await listPendingAsks(operatorApprovals);
		expect(pending.map((p) => p.actionId)).toEqual([result.actionId]);
		expect(pending[0]?.connector).toBe("openclaw");
		expect(pending[0]?.verified).toBe(true);
	});

	it("releases the retry once after an operator approval, then blocks again", async () => {
		const store = new ApprovalStore();
		const blocked = await guardToolCall(request, context, store, { operatorApprovals });
		await recordOperatorApproval(blocked.actionId as string, { approver: "op" }, operatorApprovals);

		const released = await guardToolCall(request, context, store, { operatorApprovals });
		expect(released.verdict.decision).toBe("allow");
		expect(released.verdict.source).toBe("operator_approval");
		expect(released.approvedBy).toBe("operator");

		const again = await guardToolCall(request, context, store, { operatorApprovals });
		expect(again.verdict.decision).toBe("ask");
	});

	it("does not release a different call or a different session", async () => {
		const store = new ApprovalStore();
		const blocked = await guardToolCall(request, context, store, { operatorApprovals });
		await recordOperatorApproval(blocked.actionId as string, { approver: "op" }, operatorApprovals);

		const otherCommand = {
			...request,
			toolInput: { command: "chmod 777 ./other.sh" },
			artifacts: [{ type: "command" as const, value: "chmod 777 ./other.sh" }],
		};
		expect(
			(await guardToolCall(otherCommand, context, store, { operatorApprovals })).verdict.decision,
		).toBe("ask");
		const otherSession = { ...request, sessionId: "session-2" };
		expect(
			(await guardToolCall(otherSession, context, store, { operatorApprovals })).verdict.decision,
		).toBe("ask");
	});

	it("never releases a deny, including a paranoid-promoted ask", async () => {
		const store = new ApprovalStore();
		const blocked = await guardToolCall(request, context, store, { operatorApprovals });
		await recordOperatorApproval(blocked.actionId as string, { approver: "op" }, operatorApprovals);

		vi.mocked(loadConfig).mockResolvedValue({
			sensitivity: "paranoid",
		} as unknown as Awaited<ReturnType<typeof loadConfig>>);
		const result = await guardToolCall(request, context, store, { operatorApprovals });
		expect(result.verdict.decision).toBe("deny");
	});

	it("keeps the block and reports it when the pending ask cannot be recorded", async () => {
		const result = await guardToolCall(request, context, new ApprovalStore(), {
			operatorApprovals: { ...operatorApprovals, keyProvider: { load: () => null } },
		});
		expect(result.verdict.decision).toBe("ask");
		expect(result.pendingRecorded).toBe(false);
	});

	it("can be disabled", async () => {
		const result = await guardToolCall(request, context, new ApprovalStore(), {
			operatorApprovals: false,
		});
		expect(result.pendingRecorded).toBeUndefined();
		expect(await listPendingAsks(operatorApprovals)).toEqual([]);
	});
});

describe("addToAllowlist with an operator grant", () => {
	it("refuses without a grant and accepts exactly one entry with --permit-allowlist", async () => {
		const store = new ApprovalStore();
		const value = request.artifacts[0].value;
		const refused = await addToAllowlist(
			store,
			"command",
			value,
			undefined,
			undefined,
			undefined,
			operatorApprovals,
		);
		expect(refused).toContain("no recent user approval");
		expect(refused).toContain("aidr approve");

		const blocked = await guardToolCall(request, context, store, { operatorApprovals });
		await recordOperatorApproval(
			blocked.actionId as string,
			{ approver: "op", permitAllowlist: true },
			operatorApprovals,
		);
		const added = await addToAllowlist(
			store,
			"command",
			value,
			undefined,
			undefined,
			undefined,
			operatorApprovals,
		);
		expect(added).toContain("Added command");
		expect(vi.mocked(saveAllowlist)).toHaveBeenCalledTimes(1);

		const second = await addToAllowlist(
			store,
			"command",
			value,
			undefined,
			undefined,
			undefined,
			operatorApprovals,
		);
		expect(second).toContain("no recent user approval");
	});

	it("does not accept an approval the operator did not mark allowlist-eligible", async () => {
		const store = new ApprovalStore();
		const blocked = await guardToolCall(request, context, store, { operatorApprovals });
		await recordOperatorApproval(blocked.actionId as string, { approver: "op" }, operatorApprovals);
		const msg = await addToAllowlist(
			store,
			"command",
			request.artifacts[0].value,
			undefined,
			undefined,
			undefined,
			operatorApprovals,
		);
		expect(msg).toContain("no recent user approval");
	});
});
