/**
 * `operator_approvals.mode` across every host-dialog connector, through the
 * BUILT hooks (one process per call, like the real hosts):
 *
 * - Claude Code PreToolUse (`pre-tool-use.cjs`)
 * - Cursor hook (`aidr-hook.cjs cursor`)
 * - VS Code hook (`aidr-hook.cjs vscode`)
 *
 * `operator`: the ask is denied with an actionId-only approval reference and
 * recorded as an approvable pending ask; an operator approval (what `aidr
 * approve` records) releases exactly one retry; the next retry is held again.
 * `host_dialog` (default): the native ask is unchanged and the ask is listed in
 * `aidr pending` as informational only.
 */

import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	clearOperatorApprovalKeyCache,
	createDefaultOperatorKeyProvider,
	listHostDialogAsks,
	listPendingAsks,
	type OperatorApprovalStoreOptions,
	recordOperatorApproval,
} from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const CLAUDE_HOOK = resolve(__dirname, "..", "..", "dist", "pre-tool-use.cjs");
const EXTENSION_HOOK = resolve(__dirname, "..", "..", "..", "extension", "dist", "aidr-hook.cjs");

type Host = "claude-code" | "cursor" | "vscode";

interface HostCase {
	host: Host;
	args: string[];
	payload: Record<string, unknown>;
	/** The host's decision field for a PreToolUse-style answer. */
	decision: (response: Record<string, unknown>) => unknown;
	/** Every text the agent or user is shown. */
	text: (response: Record<string, unknown>) => string;
}

const hso = (r: Record<string, unknown>) => (r.hookSpecificOutput ?? {}) as Record<string, unknown>;

const CASES: HostCase[] = [
	{
		host: "claude-code",
		args: [CLAUDE_HOOK],
		payload: {
			tool_name: "WebFetch",
			tool_input: { url: "https://example.com" },
			session_id: "parity-session",
			tool_use_id: "toolu_parity",
		},
		decision: (r) => hso(r).permissionDecision ?? "allow",
		text: (r) =>
			`${String(hso(r).permissionDecisionReason ?? "")}\n${String(r.systemMessage ?? "")}`,
	},
	{
		host: "cursor",
		args: [EXTENSION_HOOK, "cursor"],
		payload: {
			hook_event_name: "beforeMCPExecution",
			conversation_id: "parity-session",
			mcp_server_name: "github",
			tool_name: "create_issue",
			tool_input: JSON.stringify({ title: "x" }),
		},
		decision: (r) => r.permission,
		text: (r) => `${String(r.user_message ?? "")}\n${String(r.agent_message ?? "")}`,
	},
	{
		host: "vscode",
		args: [EXTENSION_HOOK, "vscode"],
		payload: {
			hook_event_name: "PreToolUse",
			session_id: "parity-session",
			tool_name: "WebFetch",
			tool_input: { url: "https://example.com" },
		},
		decision: (r) => hso(r).permissionDecision ?? "allow",
		text: (r) => String(hso(r).permissionDecisionReason ?? ""),
	},
];

let home: string;

function writeConfig(mode?: "host_dialog" | "operator"): void {
	const dir = join(home, ".singularity-aidr");
	mkdirSync(dir, { recursive: true });
	writeFileSync(
		join(dir, "config.json"),
		JSON.stringify({
			url_check: { enabled: false },
			policy: { enabled: true, mcp: { enabled: true, require_approval_servers: ["github"] } },
			operator_approvals: { key_storage: "file", ...(mode ? { mode } : {}) },
		}),
	);
}

function store(): OperatorApprovalStoreOptions {
	const directory = join(home, ".singularity-aidr");
	return {
		path: join(directory, "approvals.json"),
		keyProvider: createDefaultOperatorKeyProvider({ directory, keyStorage: "file" }),
	};
}

function runHook(c: HostCase): Promise<Record<string, unknown>> {
	const env: Record<string, string | undefined> = {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		APPDATA: join(home, "AppData", "Roaming"),
		XDG_CONFIG_HOME: join(home, ".config"),
		XDG_STATE_HOME: join(home, ".local", "state"),
		XDG_CACHE_HOME: join(home, ".cache"),
	};
	for (const key of Object.keys(env)) {
		if (key.startsWith("AIDR_")) delete env[key];
	}
	return new Promise((done, fail) => {
		const child = execFile("node", c.args, { timeout: 30_000, env }, (error, stdout) => {
			if (error && !stdout) {
				fail(error);
				return;
			}
			done(JSON.parse(stdout.trim() || "{}") as Record<string, unknown>);
		});
		child.stdin?.end(JSON.stringify(c.payload));
	});
}

beforeEach(() => {
	home = mkdtempSync(join(tmpdir(), "aidr-operator-parity-"));
	clearOperatorApprovalKeyCache();
});

afterEach(() => {
	clearOperatorApprovalKeyCache();
	rmSync(home, { recursive: true, force: true });
});

describe.each(CASES)("$host in operator mode", (c) => {
	it("denies with the approval reference, then releases exactly one retry after approval", async () => {
		writeConfig("operator");

		const held = await runHook(c);
		expect(c.decision(held)).toBe("deny");
		const text = c.text(held);
		const match = /actionId: "([a-f0-9]{64})"/.exec(text);
		expect(match).not.toBeNull();
		const actionId = match?.[1] as string;
		expect(text).toContain("You cannot approve this action yourself");
		expect(text).toContain("aidr approve <actionId>");

		const pending = await listPendingAsks(store());
		expect(pending.map((p) => p.actionId)).toEqual([actionId]);
		expect(pending[0]?.verified).toBe(true);
		expect(pending[0]?.connector).toBe(c.host);

		// What `aidr approve <actionId>` records after its TTY confirmation.
		await recordOperatorApproval(actionId, { approver: "operator (interactive)" }, store());

		const released = await runHook(c);
		expect(c.decision(released)).toBe("allow");

		const again = await runHook(c);
		expect(c.decision(again)).toBe("deny");
	}, 120_000);
});

describe.each(CASES)("$host in host_dialog mode (default)", (c) => {
	it("keeps the host's behaviour and lists the ask in `aidr pending` as informational", async () => {
		writeConfig();
		const response = await runHook(c);
		// Claude Code and VS Code show the native dialog; Cursor's MCP event supports ask too.
		expect(c.decision(response)).toBe("ask");
		expect(await listPendingAsks(store())).toEqual([]);
		const informational = await listHostDialogAsks(store());
		expect(informational).toHaveLength(1);
		expect(informational[0]?.connector).toBe(c.host);
		await expect(
			recordOperatorApproval(informational[0]?.actionId as string, { approver: "op" }, store()),
		).rejects.toMatchObject({ code: "not_pending" });
	}, 60_000);
});
