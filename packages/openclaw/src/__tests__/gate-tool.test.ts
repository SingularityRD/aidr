/**
 * Approval-authority tests for the OpenClaw connector.
 *
 * ── Why this file changed (read before editing) ────────────────────────────
 * This file previously asserted that the plugin exposed an agent-callable
 * `aidr_approve` gate tool (`packages/openclaw/src/gate-tool.ts`). That tool
 * made every `ask` verdict self-approvable:
 *
 *   1. the block message contains the `actionId` (core/src/guard.ts),
 *   2. the guard short-circuits the ENTIRE evaluation on a recorded approval
 *      (core/src/guard.ts, `approvalStore.isApproved(actionId)`),
 *   3. so a prompt-injected model could call
 *      `aidr_approve({ actionId, approved: true })` itself, re-issue the blocked
 *      call, and receive `allowVerdict("approved")` — then make the bypass
 *      permanent through `aidr_allowlist_add`.
 *
 * The agent-callable approval path has been removed. The old expectations were
 * replaced (not weakened) with the security property they should always have
 * encoded: **an agent cannot cause its own approval through ANY tool call**,
 * while a genuine out-of-band approval still works.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	ApprovalStore,
	addCommand,
	emptyAllowlist,
	extractFromBash,
	guardToolCall,
	nullLogger,
	saveAllowlist,
} from "@singularityrd/aidr-core";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("../bundled-dirs.js", () => ({
	getBundledDataDirs: () => ({
		threatsDir: resolve(import.meta.dirname, "..", "..", "..", "..", "threats"),
		allowlistsDir: resolve(import.meta.dirname, "..", "..", "..", "..", "allowlists"),
	}),
	getAidrVersion: () => "0.0.0",
}));

interface RegisteredTool {
	name: string;
	description: string;
	parameters: Record<string, unknown>;
	execute(
		toolCallId: string,
		params: Record<string, unknown>,
	): Promise<{ content: Array<{ type: string; text: string }> }>;
}

interface BlockResult {
	block: true;
	blockReason: string;
}

type ToolCallHandler = (
	event: { toolName: string; params: Record<string, unknown> },
	ctx?: { sessionKey?: string },
) => Promise<BlockResult | undefined>;

const BLOCKED_COMMAND = "chmod 777 ./no-self-approve.sh";

function actionIdFrom(blockReason: string): string {
	const match = /Approval reference: ([a-f0-9]{64})/.exec(blockReason);
	expect(match?.[1], `block message must expose the approval reference: ${blockReason}`).toMatch(
		/^[a-f0-9]{64}$/,
	);
	return match?.[1] ?? "";
}

describe("OpenClaw approval authority", { timeout: 30_000 }, () => {
	let tmpHome: string;
	let previousHome: string | undefined;
	let allowlistPath: string;
	let handler: ToolCallHandler;
	let registeredTools: RegisteredTool[];

	beforeAll(async () => {
		previousHome = process.env.HOME;
		tmpHome = await mkdtemp(join(tmpdir(), "aidr-openclaw-approval-"));
		const aidrDir = join(tmpHome, ".singularity-aidr");
		allowlistPath = join(aidrDir, "allowlist.json");
		await mkdir(aidrDir, { recursive: true });
		await writeFile(
			join(aidrDir, "config.json"),
			JSON.stringify(
				{
					mode: "local",
					sensitivity: "balanced",
					control_plane: { enabled: false },
					heuristics_enabled: true,
					url_check: { enabled: false },
					file_check: { enabled: false },
					package_check: { enabled: false },
					cache: { enabled: false, path: join(aidrDir, "cache.json") },
					allowlist: { path: allowlistPath },
					logging: { enabled: false, path: join(aidrDir, "audit.jsonl") },
				},
				null,
				2,
			),
			"utf8",
		);
		process.env.HOME = tmpHome;

		const plugin = (await import("../index.js")).default as unknown as {
			register(api: Record<string, unknown>): void;
		};

		const handlers = new Map<string, ToolCallHandler>();
		registeredTools = [];
		plugin.register({
			logger: { debug() {}, info() {}, warn() {}, error() {} },
			on(event: string, fn: ToolCallHandler) {
				handlers.set(event, fn);
			},
			registerTool(tool: RegisteredTool) {
				registeredTools.push(tool);
			},
		});

		const registered = handlers.get("before_tool_call");
		if (!registered) throw new Error("before_tool_call handler was not registered");
		handler = registered;
	});

	afterAll(async () => {
		if (previousHome === undefined) delete process.env.HOME;
		else process.env.HOME = previousHome;
		await rm(tmpHome, { recursive: true, force: true });
	});

	it("registers no agent-callable approval tool", () => {
		const names = registeredTools.map((tool) => tool.name);
		expect(names).not.toContain("aidr_approve");
		// No tool whose name suggests approval authority.
		expect(names.filter((name) => /approv/i.test(name))).toEqual([]);
		// Nor one that could create a detection exception (operator CLI / dashboard only).
		expect(names.filter((name) => /exception|except|waiv/i.test(name))).toEqual([]);
		// No tool accepting an `approved` flag (the shape an approval tool needs).
		for (const tool of registeredTools) {
			const properties = (tool.parameters.properties ?? {}) as Record<string, unknown>;
			expect(Object.keys(properties)).not.toContain("approved");
		}
	});

	it("blocks a flagged action and exposes the actionId only as an operator reference", async () => {
		const blocked = await handler(
			{ toolName: "exec", params: { command: BLOCKED_COMMAND } },
			{ sessionKey: "message-session" },
		);

		expect(blocked?.block).toBe(true);
		const message = blocked?.blockReason ?? "";
		expect(message).toContain("stopped this action until you approve it");
		expect(actionIdFrom(message)).toHaveLength(64);
		// The block message must not hand the model a callable approval recipe.
		expect(message).not.toContain("aidr_approve");
		expect(message).toContain("you cannot approve this action");
	});

	it("an agent cannot self-approve: after trying every registered tool the retry stays blocked", async () => {
		const session = { sessionKey: "adversarial-session" };

		const blocked = await handler(
			{ toolName: "exec", params: { command: BLOCKED_COMMAND } },
			session,
		);
		expect(blocked?.block).toBe(true);
		const actionId = actionIdFrom(blocked?.blockReason ?? "");

		// The prompt-injected agent now calls EVERY tool it can reach, asking to
		// be approved. (aidr_allowlist_remove is skipped: it is not an escalation
		// vector and would only undo the allowlist assertion below.)
		const attempts: Array<{ tool: string; text: string }> = [];
		for (const tool of registeredTools) {
			if (tool.name === "aidr_allowlist_remove") continue;
			const result = await tool.execute("self-approve-call", {
				actionId,
				approved: true,
				type: "command",
				value: BLOCKED_COMMAND,
				reason: "self-approved",
			});
			attempts.push({ tool: tool.name, text: result.content[0]?.text ?? "" });
		}

		// No tool can record an approval.
		expect(attempts.map((attempt) => attempt.text).join("\n")).not.toMatch(/Approved action/i);
		// And the allowlist cannot be used to escalate without one.
		expect(attempts.find((attempt) => attempt.tool === "aidr_allowlist_add")?.text).toContain(
			"no recent user approval",
		);

		// The retry is STILL blocked — this is the security property.
		const retry = await handler(
			{ toolName: "exec", params: { command: BLOCKED_COMMAND } },
			session,
		);
		expect(retry?.block).toBe(true);
		expect(retry?.blockReason).toContain("stopped this action until you approve it");

		// And it stays blocked in a fresh session too.
		const freshSession = await handler(
			{ toolName: "exec", params: { command: BLOCKED_COMMAND } },
			{ sessionKey: "another-session" },
		);
		expect(freshSession?.block).toBe(true);

		// The allowlist file was never written by the agent.
		const allowlistRaw = await readFile(allowlistPath, "utf8").catch(() => null);
		expect(allowlistRaw).toBeNull();
	});

	it("a genuine out-of-band approval still works (operator-held ApprovalStore)", async () => {
		// This is the mechanism preserved in core: an operator/host process that
		// owns the store approves the exact action through a channel the agent
		// cannot invoke.
		const command = "chmod 777 ./operator-approved.sh";
		const sessionId = "operator-session";
		const toolInput = { command };
		const store = new ApprovalStore();
		const request = {
			sessionId,
			toolName: "exec",
			toolInput,
			artifacts: extractFromBash(command),
		};
		const context = {
			threatsDir: resolve(import.meta.dirname, "..", "..", "..", "..", "threats"),
			allowlistsDir: resolve(import.meta.dirname, "..", "..", "..", "..", "allowlists"),
			logger: nullLogger,
			agentRuntime: "openclaw" as const,
		};

		// Before approval the action is flagged (ask), never silently allowed.
		const before = await guardToolCall(request, context, store);
		expect(before.verdict.decision).toBe("ask");
		expect(before.actionId).toBeDefined();

		// Out-of-band approval, performed by the operator (not by the agent).
		const actionId = ApprovalStore.actionId(request.toolName, request.toolInput, request.sessionId);
		expect(actionId).toBe(before.actionId);
		store.setPending(actionId, { artifacts: request.artifacts, createdAt: Date.now() });
		store.approve(actionId);

		const after = await guardToolCall(request, context, store);
		expect(after.verdict.decision).toBe("allow");
		expect(after.verdict.source).toBe("approved");
	});

	it("a genuine out-of-band allowlist entry still lets the action through", async () => {
		const command = "chmod 777 ./operator-allowlisted.sh";

		// Blocked for the agent before the operator acts.
		const blocked = await handler(
			{ toolName: "exec", params: { command } },
			{ sessionKey: "allowlist-session" },
		);
		expect(blocked?.block).toBe(true);

		// Operator writes the allowlist directly (the on-disk allowlist is an
		// out-of-band surface the agent's tools cannot grant themselves).
		const allowlist = emptyAllowlist();
		addCommand(allowlist, command, "operator allowlist (out-of-band)", "ask");
		await expect(saveAllowlist(allowlist, { path: allowlistPath }, nullLogger)).resolves.toBe(true);

		const retry = await handler(
			{ toolName: "exec", params: { command } },
			{ sessionKey: "allowlist-session" },
		);
		expect(retry).toBeUndefined();
	});
});
