/// <reference types="node" />
/**
 * Hook-runner hardening for Cursor and VS Code (built bundle): the internal
 * deadline, exit-0 deny verdicts for oversized/undecodable input, routing by
 * explicit event name, malformed commands, per-event `ask` support and MCP
 * server identity.
 */

import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { type HookEvaluation, toCursorResponse } from "../aidr-hook.js";

const AIDR_HOOK = resolve(__dirname, "..", "..", "dist", "aidr-hook.cjs");
type HookMode = "cursor" | "vscode";

const homes: string[] = [];
afterAll(async () => {
	await Promise.all(homes.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeHome(config?: Record<string, unknown>): Promise<string> {
	const home = await mkdtemp(join(tmpdir(), "aidr-hook-hardening-"));
	homes.push(home);
	if (config) {
		await mkdir(join(home, ".singularity-aidr"), { recursive: true });
		await writeFile(join(home, ".singularity-aidr", "config.json"), JSON.stringify(config));
	}
	return home;
}

function runHook(
	mode: HookMode,
	input: Record<string, unknown> | string | Buffer | null,
	options: { home?: string; env?: Record<string, string> } = {},
): Promise<{ stdout: string; code: number | null; elapsedMs: number }> {
	return new Promise((resolveRun) => {
		const env: NodeJS.ProcessEnv = { ...process.env, ...options.env };
		if (options.home) {
			env.HOME = options.home;
			env.USERPROFILE = options.home;
			env.APPDATA = join(options.home, "AppData", "Roaming");
		}
		const started = Date.now();
		const child = execFile(
			"node",
			[AIDR_HOOK, mode],
			{ env, timeout: 20_000, maxBuffer: 16 * 1024 * 1024 },
			(_error, stdout) =>
				resolveRun({ stdout, code: child.exitCode, elapsedMs: Date.now() - started }),
		);
		child.stdin?.on("error", () => {});
		if (input === null) {
			// Partial payload and no EOF: only the watchdog can end the hook.
			child.stdin?.write('{"hook_event_name":"preToolUse",');
			return;
		}
		child.stdin?.end(
			Buffer.isBuffer(input) || typeof input === "string" ? input : JSON.stringify(input),
		);
	});
}

function parse(stdout: string): Record<string, unknown> {
	const lines = stdout.trim().split("\n");
	expect(lines).toHaveLength(1);
	return JSON.parse(lines[0] as string) as Record<string, unknown>;
}

function vsDecision(response: Record<string, unknown>): unknown {
	return (response.hookSpecificOutput as Record<string, unknown> | undefined)?.permissionDecision;
}

describe("hook watchdog", () => {
	it.each(["cursor", "vscode"] as const)(
		"%s: denies with exit 0 at the deadline when stdin never closes",
		async (mode) => {
			const run = await runHook(mode, null, {
				env: { AIDR_EXTENSION_HOOK_DEADLINE_MS: "1500" },
			});
			expect(run.elapsedMs).toBeLessThan(10_000);
			expect(run.code).toBe(0);
			const response = parse(run.stdout);
			expect(mode === "cursor" ? response.permission : vsDecision(response)).toBe("deny");
			expect(response.continue).toBe(false);
		},
		25_000,
	);

	it("exits promptly after answering", async () => {
		const run = await runHook("cursor", {
			hook_event_name: "beforeShellExecution",
			command: "git log -n 3",
			cwd: tmpdir(),
		});
		expect(run.code).toBe(0);
		expect(parse(run.stdout).permission).toBe("allow");
		expect(run.elapsedMs).toBeLessThan(5_000);
	}, 20_000);
});

describe("oversized and undecodable input", () => {
	const big = "a".repeat(1024 * 1024 + 16);

	it("cursor preToolUse: exit 0 with a deny verdict", async () => {
		const run = await runHook("cursor", {
			hook_event_name: "preToolUse",
			tool_name: "Write",
			tool_input: { file_path: "notes.txt", content: big },
		});
		expect(run.code).toBe(0);
		const response = parse(run.stdout);
		expect(response.permission).toBe("deny");
		expect(JSON.stringify(response)).toContain("processing limit");
	}, 20_000);

	it("vscode PreToolUse: exit 0 with a PreToolUse deny", async () => {
		const run = await runHook("vscode", {
			hook_event_name: "PreToolUse",
			tool_name: "Write",
			tool_input: { file_path: "notes.txt", content: big },
		});
		expect(run.code).toBe(0);
		expect(vsDecision(parse(run.stdout))).toBe("deny");
	}, 20_000);

	it("vscode with no identifiable event: exit 0 with a block covering every event", async () => {
		const run = await runHook("vscode", { tool_name: "Write", tool_input: { content: big } });
		expect(run.code).toBe(0);
		const response = parse(run.stdout);
		expect(vsDecision(response)).toBe("deny");
		expect(response.decision).toBe("block");
		expect(response.continue).toBe(false);
	}, 20_000);

	it("cursor postToolUse: annotates without claiming a block", async () => {
		const run = await runHook("cursor", {
			hook_event_name: "postToolUse",
			tool_name: "Shell",
			tool_output: big,
		});
		expect(run.code).toBe(0);
		const response = parse(run.stdout);
		expect(response.permission).toBeUndefined();
		expect(String(response.additional_context)).toContain("not classified as clean");
	}, 20_000);

	it.each(["cursor", "vscode"] as const)(
		"%s: invalid UTF-8 input is denied with exit 0",
		async (mode) => {
			const payload = Buffer.concat([
				Buffer.from('{"hook_event_name":"preToolUse","command":"rm -rf '),
				Buffer.from([0xff, 0xfe, 0xfd]),
				Buffer.from('"}'),
			]);
			const run = await runHook(mode, payload);
			expect(run.code).toBe(0);
			const response = parse(run.stdout);
			expect(mode === "cursor" ? response.permission : vsDecision(response)).toBe("deny");
		},
		20_000,
	);
});

describe("VS Code routing by explicit event name", () => {
	it("evaluates a PreToolUse payload that also carries tool_response", async () => {
		const run = await runHook("vscode", {
			hookEventName: "PreToolUse",
			tool_name: "Bash",
			tool_input: { command: "rm -rf / --no-preserve-root" },
			tool_response: "ignored",
		});
		expect(vsDecision(parse(run.stdout))).toBe("deny");
	}, 20_000);

	it("never treats a payload without an event name as completed output", async () => {
		const run = await runHook("vscode", {
			tool_name: "Bash",
			tool_input: { command: "rm -rf / --no-preserve-root" },
			tool_response: "ignored",
		});
		expect(vsDecision(parse(run.stdout))).toBe("deny");
	}, 20_000);
});

describe("malformed shell commands", () => {
	it.each(["rm -rf /tmp/x\u0000", "echo \ud800"])(
		"denies %j on Cursor and VS Code",
		async (command) => {
			const cursor = await runHook("cursor", {
				hook_event_name: "beforeShellExecution",
				command,
				cwd: tmpdir(),
			});
			expect(parse(cursor.stdout).permission).toBe("deny");
			const vscode = await runHook("vscode", {
				hookEventName: "PreToolUse",
				tool_name: "Bash",
				tool_input: { command },
			});
			expect(vsDecision(parse(vscode.stdout))).toBe("deny");
		},
		30_000,
	);
});

describe("Cursor ask support per event", () => {
	const ask: HookEvaluation = {
		verdict: {
			decision: "ask",
			category: "mcp_tool_call",
			confidence: 0.9,
			severity: "warning",
			source: "policy",
			artifacts: [],
			matchedThreatId: "POL-MCP-007",
			reasons: ["MCP server requires approval"],
		},
		dashboardNotice: null,
		dashboardOnly: false,
	};

	it.each([
		["beforeShellExecution", "ask"],
		["beforeMCPExecution", "ask"],
		["beforeReadFile", "deny"],
		["preToolUse", "deny"],
	] as const)("%s maps ask to %s", (event, expected) => {
		const response = toCursorResponse(ask, event);
		expect(response.permission).toBe(expected);
		expect(response.decision).toBe(expected);
	});

	it("maps ask to deny everywhere under dashboard_only", () => {
		expect(
			toCursorResponse({ ...ask, dashboardOnly: true }, "beforeShellExecution").permission,
		).toBe("deny");
	});
});

describe("MCP server identity", () => {
	const policy = (mcp: Record<string, unknown>) => ({
		policy: { enabled: true, mcp: { enabled: true, ...mcp } },
	});

	it("Cursor beforeMCPExecution applies server policy from the payload's server name", async () => {
		const home = await makeHome(policy({ deny_servers: ["github"] }));
		const run = await runHook(
			"cursor",
			{
				hook_event_name: "beforeMCPExecution",
				mcp_server_name: "github",
				tool_name: "create_issue",
				tool_input: JSON.stringify({ title: "x" }),
			},
			{ home },
		);
		const response = parse(run.stdout);
		expect(response.permission).toBe("deny");
		expect(JSON.stringify(response)).toContain("MCP server denied by policy");
	}, 20_000);

	it("Cursor beforeMCPExecution derives the server from the workspace mcp.json", async () => {
		const home = await makeHome(policy({ require_approval_servers: ["github"] }));
		const workspace = await mkdtemp(join(tmpdir(), "aidr-cursor-ws-"));
		homes.push(workspace);
		await mkdir(join(workspace, ".cursor"), { recursive: true });
		await writeFile(
			join(workspace, ".cursor", "mcp.json"),
			JSON.stringify({ mcpServers: { github: { command: "npx", args: ["-y", "@mcp/github"] } } }),
		);
		const run = await runHook(
			"cursor",
			{
				hook_event_name: "beforeMCPExecution",
				command: "npx -y @mcp/github",
				tool_name: "create_issue",
				tool_input: "{}",
				workspace_roots: [workspace],
			},
			{ home },
		);
		// beforeMCPExecution supports a native approval prompt.
		expect(parse(run.stdout).permission).toBe("ask");
	}, 20_000);

	it("VS Code mcp_<server>_<tool> applies server policy", async () => {
		const home = await makeHome(policy({ deny_servers: ["my_github"] }));
		const run = await runHook(
			"vscode",
			{
				hookEventName: "PreToolUse",
				tool_name: "mcp_my_github_create_issue",
				tool_input: { title: "x" },
			},
			{ home },
		);
		const response = parse(run.stdout);
		expect(vsDecision(response)).toBe("deny");
		expect(JSON.stringify(response)).toContain("MCP server denied by policy");
	}, 20_000);
});
