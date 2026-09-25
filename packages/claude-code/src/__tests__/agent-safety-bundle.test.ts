/**
 * Agent-safety guardrails through the BUILT Claude Code hooks: each call is a
 * separate hook process sharing one HOME, exactly as Claude Code runs them, so
 * the runaway guard's session state must survive across processes.
 */
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { toolResponseFailed } from "../tool-outcome.js";

const DIST_DIR = resolve(__dirname, "..", "..", "dist");
const PRE_TOOL_USE = resolve(DIST_DIR, "pre-tool-use.cjs");
const POST_TOOL_USE = resolve(DIST_DIR, "post-tool-use.cjs");

let home: string;

function runHook(script: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
	const env: Record<string, string | undefined> = {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		XDG_CONFIG_HOME: join(home, ".config"),
		XDG_STATE_HOME: join(home, ".local", "state"),
	};
	for (const key of Object.keys(env)) if (key.startsWith("AIDR_")) delete env[key];
	return new Promise((resolvePromise, reject) => {
		const child = execFile("node", [script], { timeout: 30_000, env }, (error, stdout) => {
			if (error && !stdout) return reject(error);
			resolvePromise(JSON.parse(stdout.trim() || "{}") as Record<string, unknown>);
		});
		child.stdin?.end(JSON.stringify(input));
	});
}

function decision(response: Record<string, unknown>): string {
	const output = response.hookSpecificOutput as Record<string, unknown> | undefined;
	return (output?.permissionDecision as string | undefined) ?? "allow";
}

function reason(response: Record<string, unknown>): string {
	const output = response.hookSpecificOutput as Record<string, unknown> | undefined;
	return `${String(output?.permissionDecisionReason ?? "")}\n${String(response.systemMessage ?? "")}`;
}

function pre(sessionId: string, toolName: string, toolInput: Record<string, unknown>) {
	return runHook(PRE_TOOL_USE, {
		session_id: sessionId,
		hook_event_name: "PreToolUse",
		tool_name: toolName,
		tool_input: toolInput,
		tool_use_id: `tu_${Math.random().toString(36).slice(2)}`,
	});
}

beforeAll(() => {
	home = mkdtempSync(join(tmpdir(), "aidr-claude-agent-safety-"));
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
	writeFileSync(
		join(home, ".singularity-aidr", "config.json"),
		JSON.stringify({ agent_safety: { runaway: { max_consecutive_identical_calls: 3 } } }),
	);
});

afterAll(() => {
	rmSync(home, { recursive: true, force: true });
});

describe("Claude Code bundle: agent-safety guardrails", { timeout: 120_000 }, () => {
	it("asks before a test skip, denies an unattended agent launch, asks before terraform destroy", async () => {
		const skip = await pre("cc-1", "Edit", {
			file_path: "/repo/src/auth.test.ts",
			old_string: "it('logs in', () => {",
			new_string: "it.skip('logs in', () => {",
		});
		expect(decision(skip)).toBe("ask");
		expect(reason(skip)).toContain("Test skipped or disabled");

		const launch = await pre("cc-1", "Bash", {
			command: "claude --dangerously-skip-permissions -p x",
		});
		expect(decision(launch)).toBe("deny");

		const destroy = await pre("cc-1", "Bash", { command: "terraform destroy" });
		expect(decision(destroy)).toBe("ask");
		expect(reason(destroy)).toContain("Irreversible action");

		expect(decision(await pre("cc-1", "Bash", { command: "terraform plan" }))).toBe("allow");
	});

	it("pauses a loop across separate hook processes", async () => {
		const call = { command: "ls -la" };
		for (let i = 0; i < 3; i++) {
			expect(decision(await pre("cc-loop", "Bash", call))).toBe("allow");
		}
		const paused = await pre("cc-loop", "Bash", call);
		expect(decision(paused)).toBe("ask");
		expect(reason(paused)).toContain("repeated 4 times in a row");
	});

	it("PostToolUse failures feed the repeated-failure signal", async () => {
		const toolInput = { command: "make build" };
		for (let i = 0; i < 3; i++) {
			expect(decision(await pre("cc-fail", "Bash", toolInput))).toBe("allow");
			// An unrelated call in between keeps the consecutive-loop signal out of it.
			await pre("cc-fail", "Read", { file_path: `/repo/file${i}.ts` });
			await runHook(POST_TOOL_USE, {
				session_id: "cc-fail",
				hook_event_name: "PostToolUse",
				tool_name: "Bash",
				tool_input: toolInput,
				tool_response: { stdout: "", stderr: "make: *** [build] Error 2", exit_code: 2 },
				tool_use_id: `tu_fail_${i}`,
			});
		}
		const retry = await pre("cc-fail", "Bash", toolInput);
		expect(decision(retry)).toBe("ask");
		expect(reason(retry)).toContain("already failed 3 times");
	});
});

describe("toolResponseFailed", () => {
	it("recognises only explicit failure markers", () => {
		expect(toolResponseFailed({ exit_code: 1 })).toBe(true);
		expect(toolResponseFailed({ is_error: true })).toBe(true);
		expect(toolResponseFailed({ exit_code: 0, stdout: "ok" })).toBe(false);
		expect(toolResponseFailed({ stdout: "Error: something" })).toBe(false);
		expect(toolResponseFailed("Error")).toBe(false);
		expect(toolResponseFailed(null)).toBe(false);
	});
});
