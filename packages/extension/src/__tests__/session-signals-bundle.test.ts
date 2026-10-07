/// <reference types="node" />
/**
 * Canary credentials and runaway failure tracking through the BUILT hook
 * (dist/aidr-hook.cjs) for both hosts: a prompt carrying a decoy value is
 * blocked and recorded, tool output carrying one is recorded as a canary
 * incident, and a tool result that reports a failure counts towards the
 * repeated-failure signal of the next identical call.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type CanaryRecord, deployCanaries } from "../../../core/src/canary/index.js";

const AIDR_HOOK = resolve(__dirname, "..", "..", "dist", "aidr-hook.cjs");
/** The runaway guard's repeated-failure reason (CLT-AGENT-RUN-004). */
const FAILURE_LOOP = "already failed 3 times";

let home: string;
let records: CanaryRecord[];

function runHook(
	mode: "cursor" | "vscode",
	input: Record<string, unknown>,
): Promise<{ response: Record<string, unknown>; code: number | null }> {
	const env: NodeJS.ProcessEnv = {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		XDG_CONFIG_HOME: join(home, ".config"),
		XDG_STATE_HOME: join(home, ".local", "state"),
		XDG_CACHE_HOME: join(home, ".cache"),
	};
	for (const key of Object.keys(env)) if (key.startsWith("AIDR_")) delete env[key];
	return new Promise((resolveRun) => {
		const child = execFile(
			process.execPath,
			[AIDR_HOOK, mode],
			{ env, timeout: 30_000 },
			(error, stdout) => {
				resolveRun({
					response: JSON.parse(stdout.trim()) as Record<string, unknown>,
					code: error?.code ? Number(error.code) : child.exitCode,
				});
			},
		);
		child.stdin?.end(JSON.stringify(input));
	});
}

function token(kind: CanaryRecord["kind"], index = 0): string {
	const path = records.find((record) => record.kind === kind)?.path as string;
	return [...readFileSync(path, "utf8").matchAll(/[A-Za-z0-9]{20,}/g)][index]?.[0] as string;
}

function auditEntries(): Array<Record<string, unknown>> {
	try {
		return readFileSync(join(home, ".singularity-aidr", "audit.jsonl"), "utf8")
			.split("\n")
			.filter((line) => line.trim())
			.map((line) => JSON.parse(line) as Record<string, unknown>);
	} catch {
		return [];
	}
}

beforeEach(() => {
	home = mkdtempSync(join(tmpdir(), "aidr-extension-signals-"));
	records = deployCanaries({
		homeDir: home,
		projectDir: join(home, "project"),
		registryPath: join(home, ".singularity-aidr", "canary", "registry.json"),
	}).deployed;
});

afterEach(() => {
	rmSync(home, { recursive: true, force: true });
});

describe("Cursor / VS Code canary credentials (built hook)", { timeout: 60_000 }, () => {
	it("Cursor beforeSubmitPrompt blocks a prompt carrying a decoy value", async () => {
		const secret = token("aws");
		const { response, code } = await runHook("cursor", {
			hook_event_name: "beforeSubmitPrompt",
			conversation_id: "conv-canary",
			prompt: `deploy with ${secret}`,
		});
		expect(code).toBe(0);
		expect(response.continue).toBe(false);
		expect(String(response.user_message)).toContain("canary credential");
		expect(JSON.stringify(response)).not.toContain(secret);
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({
				category: "canary_triggered",
				tool_name: "beforeSubmitPrompt",
				session_id: "conv-canary",
			}),
		);
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});

	it("VS Code UserPromptSubmit blocks a prompt carrying a decoy value", async () => {
		const { response } = await runHook("vscode", {
			hook_event_name: "UserPromptSubmit",
			session_id: "vs-canary",
			prompt: `use ${token("github")}`,
		});
		expect(response.continue).toBe(false);
		expect(String(response.stopReason)).toContain("canary credential");
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({ category: "canary_triggered", tool_name: "UserPromptSubmit" }),
		);
	});

	it("Cursor postToolUse records tool output carrying a decoy value", async () => {
		const secret = token("env", 1);
		const { response } = await runHook("cursor", {
			hook_event_name: "postToolUse",
			conversation_id: "conv-out",
			tool_name: "Shell",
			tool_input: { command: "grep -rn SECRET ." },
			tool_output: JSON.stringify({ exitCode: 0, stdout: `.env.backup:4:JWT_SECRET=${secret}` }),
		});
		expect(JSON.stringify(response)).toContain("OUT-CANARY-001");
		expect(JSON.stringify(response)).not.toContain(secret);
		const entry = auditEntries().find((candidate) => candidate.category === "canary_triggered");
		expect(entry).toMatchObject({ tool_name: "Bash", source: "canary", session_id: "conv-out" });
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});

	it("VS Code PostToolUse records tool output carrying a decoy value", async () => {
		const secret = token("openai");
		const { response } = await runHook("vscode", {
			hook_event_name: "PostToolUse",
			session_id: "vs-out",
			tool_name: "readFile",
			tool_input: { filePath: "/tmp/notes.txt" },
			tool_response: `OPENAI_API_KEY=${secret}`,
		});
		expect(response.decision).toBe("block");
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({
				category: "canary_triggered",
				tool_name: "readFile",
				session_id: "vs-out",
			}),
		);
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});
});

describe("Cursor / VS Code runaway failure tracking (built hook)", { timeout: 90_000 }, () => {
	it("Cursor: a shell command that failed three times is paused on its next retry", async () => {
		const failedRun = {
			hook_event_name: "postToolUse",
			conversation_id: "conv-loop",
			tool_name: "Shell",
			tool_input: { command: "npm run build" },
			tool_output: JSON.stringify({ exitCode: 1, stdout: "", stderr: "build failed" }),
		};
		for (let attempt = 0; attempt < 3; attempt += 1) await runHook("cursor", failedRun);
		const retry = await runHook("cursor", {
			hook_event_name: "beforeShellExecution",
			conversation_id: "conv-loop",
			command: "npm run build",
		});
		expect(JSON.stringify(retry.response)).toContain(FAILURE_LOOP);
		expect(retry.response.permission).not.toBe("allow");

		// A successful result is not a failure, and another session is not affected.
		const other = await runHook("cursor", {
			hook_event_name: "beforeShellExecution",
			conversation_id: "conv-other",
			command: "npm run build",
		});
		expect(JSON.stringify(other.response)).not.toContain(FAILURE_LOOP);
	});

	it("VS Code: successful results never count as failures", async () => {
		const call = {
			session_id: "vs-loop",
			tool_name: "runInTerminal",
			tool_input: { command: "npm test" },
		};
		for (let attempt = 0; attempt < 4; attempt += 1) {
			await runHook("vscode", {
				...call,
				hook_event_name: "PostToolUse",
				tool_response: { exit_code: 0, output: "ok" },
			});
		}
		const retry = await runHook("vscode", { ...call, hook_event_name: "PreToolUse" });
		expect(JSON.stringify(retry.response)).not.toContain(FAILURE_LOOP);

		for (let attempt = 0; attempt < 3; attempt += 1) {
			await runHook("vscode", {
				...call,
				hook_event_name: "PostToolUse",
				tool_response: { exit_code: 2, output: "failed" },
			});
		}
		const paused = await runHook("vscode", { ...call, hook_event_name: "PreToolUse" });
		expect(JSON.stringify(paused.response)).toContain(FAILURE_LOOP);
	});
});
