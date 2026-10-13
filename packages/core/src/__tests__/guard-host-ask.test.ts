/**
 * `resolveHostAsk`: the ask path for hosts with a native confirmation dialog
 * (Claude Code, Cursor / VS Code). In `operator_approvals.mode: operator` the
 * ask is held as a deny, recorded in the operator store, and released for ONE
 * retry only after an operator approval. In the default `host_dialog` mode the
 * verdict is unchanged and the ask is listed in `aidr pending` as an
 * informational record that can never be approved.
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import { guardToolCall, hostAskMode, resolveHostAsk } from "../guard.js";
import {
	clearOperatorApprovalKeyCache,
	listHostDialogAsks,
	listPendingAsks,
	OperatorApprovalError,
	type OperatorApprovalStoreOptions,
	recordOperatorApproval,
} from "../operator-approvals.js";
import type { Config, Verdict } from "../types.js";

vi.mock("../config.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return { ...original, loadConfig: vi.fn() };
});
vi.mock("../evaluator.js", async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return { ...original, evaluateToolCall: vi.fn() };
});

const { loadConfig } = await import("../config.js");
const { evaluateToolCall } = await import("../evaluator.js");

const ASK: Verdict = {
	decision: "ask",
	category: "permissions",
	confidence: 0.9,
	severity: "warning",
	source: "heuristic",
	artifacts: ["chmod 777 ./deploy.sh"],
	matchedThreatId: "CLT-TEST-001",
	reasons: ["World-writable permissions"],
};

const request = {
	sessionId: "session-1",
	toolName: "Bash",
	toolInput: { command: "chmod 777 ./deploy.sh" },
	artifacts: [{ type: "command" as const, value: "chmod 777 ./deploy.sh" }],
};

let dir: string;
let operatorApprovals: OperatorApprovalStoreOptions;

function setConfig(operator: Record<string, unknown>, extra: Record<string, unknown> = {}): void {
	vi.mocked(loadConfig).mockResolvedValue({
		mode: "local",
		sensitivity: "balanced",
		operator_approvals: { key_storage: "os-vault", dashboard_only: false, ...operator },
		...extra,
	} as unknown as Config);
}

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "aidr-host-ask-"));
	clearOperatorApprovalKeyCache();
	const key = randomBytes(32);
	let ledger: string | null = null;
	operatorApprovals = {
		path: join(dir, "approvals.json"),
		keyProvider: {
			load: () => ({ key, location: "os-vault", store: "macos-keychain" }),
			anchor: () => ({
				location: "os-vault",
				read: () => ledger,
				write: (value) => {
					ledger = value;
				},
			}),
		},
	};
	setConfig({});
});

afterEach(() => {
	clearOperatorApprovalKeyCache();
	rmSync(dir, { recursive: true, force: true });
	vi.clearAllMocks();
});

const context = { agentRuntime: "claude-code" as const };
const opts = () => ({ operatorApprovals, dashboardApprovals: false as const });

describe("hostAskMode", () => {
	it("defaults to host_dialog and honours operator", () => {
		expect(hostAskMode(undefined)).toBe("host_dialog");
		expect(hostAskMode({ operator_approvals: {} } as unknown as Config)).toBe("host_dialog");
		expect(hostAskMode({ operator_approvals: { mode: "operator" } } as unknown as Config)).toBe(
			"operator",
		);
	});

	it("dashboard_only in managed mode wins over operator mode", () => {
		expect(
			hostAskMode({
				mode: "managed",
				operator_approvals: { mode: "operator", dashboard_only: true },
			} as unknown as Config),
		).toBe("host_dialog");
	});
});

describe("resolveHostAsk in host_dialog mode (default)", () => {
	it("keeps the verdict and lists the ask as informational", async () => {
		const result = await resolveHostAsk(request, ASK, context, opts());
		expect(result.mode).toBe("host_dialog");
		expect(result.verdict).toBe(ASK);
		expect(result.operatorHold).toBeUndefined();
		expect(result.informationalRecorded).toBe(true);
		const informational = await listHostDialogAsks(operatorApprovals);
		expect(informational).toHaveLength(1);
		expect(informational[0]?.connector).toBe("claude-code");
		expect(informational[0]?.channel).toBe("host_dialog");
		// Never an approvable pending ask.
		expect(await listPendingAsks(operatorApprovals)).toEqual([]);
	});

	it("an informational record can never be approved, even if edited", async () => {
		await resolveHostAsk(request, ASK, context, opts());
		const [ask] = await listHostDialogAsks(operatorApprovals);
		await expect(
			recordOperatorApproval(ask?.actionId as string, { approver: "op" }, operatorApprovals),
		).rejects.toMatchObject({ code: "not_pending" });

		// Moving it into the approvable list by hand fails verification (no MAC).
		const path = operatorApprovals.path as string;
		const doc = JSON.parse(readFileSync(path, "utf8"));
		doc.pending = doc.host_asks.map((h: Record<string, unknown>) => ({
			...h,
			mac: "0".repeat(64),
		}));
		writeFileSync(path, JSON.stringify(doc));
		const error = await recordOperatorApproval(
			ask?.actionId as string,
			{ approver: "op" },
			operatorApprovals,
		).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(OperatorApprovalError);
		expect((error as OperatorApprovalError).code).toBe("tampered");
	});

	it("leaves non-ask verdicts untouched and records nothing", async () => {
		const deny = { ...ASK, decision: "deny" as const };
		const result = await resolveHostAsk(request, deny, context, opts());
		expect(result.verdict).toBe(deny);
		expect(await listHostDialogAsks(operatorApprovals)).toEqual([]);
	});

	it("a broken store never changes the verdict", async () => {
		const result = await resolveHostAsk(request, ASK, context, {
			dashboardApprovals: false,
			operatorApprovals: { ...operatorApprovals, path: join(dir, "missing", "\0bad") },
		});
		expect(result.verdict).toBe(ASK);
		expect(result.informationalRecorded).toBe(false);
	});
});

describe("resolveHostAsk in operator mode", () => {
	beforeEach(() => setConfig({ mode: "operator" }));

	it("holds the ask as a deny with an actionId-only reference and records it", async () => {
		const result = await resolveHostAsk(request, ASK, context, opts());
		expect(result.mode).toBe("operator");
		expect(result.operatorHold?.pendingRecorded).toBe(true);
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);
		expect(result.operatorHold?.actionId).toBe(actionId);
		expect(result.operatorHold?.message).toContain(`Approval reference: ${actionId}`);
		expect(result.operatorHold?.message).toContain("you cannot approve this action");
		expect(result.operatorHold?.message).toContain(`aidr approve ${actionId.slice(0, 8)}`);
		const pending = await listPendingAsks(operatorApprovals);
		expect(pending.map((p) => p.actionId)).toEqual([actionId]);
		expect(pending[0]?.verified).toBe(true);
	});

	it("releases exactly one retry after `aidr approve`, then holds again", async () => {
		const held = await resolveHostAsk(request, ASK, context, opts());
		await recordOperatorApproval(
			held.operatorHold?.actionId as string,
			{ approver: "op (interactive)" },
			operatorApprovals,
		);

		const released = await resolveHostAsk(request, ASK, context, opts());
		expect(released.verdict.decision).toBe("allow");
		expect(released.verdict.source).toBe("operator_approval");
		expect(released.approvedBy).toBe("operator");
		expect(released.operatorHold).toBeUndefined();

		const again = await resolveHostAsk(request, ASK, context, opts());
		expect(again.verdict.decision).toBe("ask");
		expect(again.operatorHold).toBeDefined();
	});

	it("an approval does not release a different call or session", async () => {
		const held = await resolveHostAsk(request, ASK, context, opts());
		await recordOperatorApproval(
			held.operatorHold?.actionId as string,
			{ approver: "op" },
			operatorApprovals,
		);
		const otherSession = await resolveHostAsk(
			{ ...request, sessionId: "session-2" },
			ASK,
			context,
			opts(),
		);
		expect(otherSession.operatorHold).toBeDefined();
		const otherCall = await resolveHostAsk(
			{
				...request,
				toolInput: { command: "chmod 777 ./other.sh" },
				artifacts: [{ type: "command", value: "chmod 777 ./other.sh" }],
			},
			ASK,
			context,
			opts(),
		);
		expect(otherCall.operatorHold).toBeDefined();
	});

	it("paranoid sensitivity turns the ask into a deny no channel can release", async () => {
		setConfig({ mode: "operator" }, { sensitivity: "paranoid" });
		const result = await resolveHostAsk(request, ASK, context, opts());
		expect(result.verdict.decision).toBe("deny");
		expect(result.operatorHold).toBeUndefined();
		expect(await listPendingAsks(operatorApprovals)).toEqual([]);
	});

	it("keeps the hold (and says so) when approvals are unavailable", async () => {
		const result = await resolveHostAsk(request, ASK, context, {
			dashboardApprovals: false,
			operatorApprovals: {
				path: join(dir, "approvals.json"),
				keyProvider: {
					load: () => {
						throw new OperatorApprovalError("approvals_disabled", "no vault");
					},
				},
			},
		});
		expect(result.verdict.decision).toBe("ask");
		expect(result.operatorHold?.pendingRecorded).toBe(false);
		expect(result.operatorHold?.message).toContain("could not be saved for approval");
	});
});

describe("parity with the soft-gated guard", () => {
	it("an approval recorded from a host hold releases the same call through guardToolCall too", async () => {
		setConfig({ mode: "operator" });
		vi.mocked(evaluateToolCall).mockResolvedValue(ASK);
		const held = await resolveHostAsk(request, ASK, context, opts());
		const guarded = await guardToolCall(
			request,
			{ threatsDir: "/t", allowlistsDir: "/a", agentRuntime: "openclaw" },
			new ApprovalStore(),
			{ operatorApprovals, dashboardApprovals: false },
		);
		// Same action id, same store, same message shape.
		expect(guarded.actionId).toBe(held.operatorHold?.actionId);
		expect(guarded.verdict.decision).toBe("ask");
		await recordOperatorApproval(guarded.actionId as string, { approver: "op" }, operatorApprovals);
		const released = await resolveHostAsk(request, ASK, context, opts());
		expect(released.approvedBy).toBe("operator");
		// Spent once in the shared ledger: the guard cannot spend it again.
		const second = await guardToolCall(
			request,
			{ threatsDir: "/t", allowlistsDir: "/a", agentRuntime: "openclaw" },
			new ApprovalStore(),
			{ operatorApprovals, dashboardApprovals: false },
		);
		expect(second.verdict.decision).toBe("ask");
	});
});

describe("resolveHostAsk with an unreadable configuration", () => {
	it("blocks the ask instead of handing it to the host's own dialog", async () => {
		// The approval mode cannot be known: falling back to the native dialog
		// could bypass a configured operator channel.
		vi.mocked(loadConfig).mockRejectedValueOnce(new Error("config unreadable"));
		const resolution = await resolveHostAsk(request, ASK, { agentRuntime: "claude-code" });
		expect(resolution.verdict.decision).toBe("deny");
		expect(resolution.verdict.reasons.join(" ")).toMatch(/could not read its configuration/);
	});
});
