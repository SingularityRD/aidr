/**
 * Built-bundle tests for canary credentials in the Claude Code connector: the
 * PreToolUse hook denies a decoy read, PostToolUse blocks and records tool
 * output carrying a decoy value, and UserPromptSubmit blocks a prompt that
 * carries one. Requires the core and claude-code builds.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type CanaryRecord, deployCanaries } from "../../../core/src/canary/index.js";

const DIST_DIR = resolve(__dirname, "..", "..", "dist");

let home: string;
let records: CanaryRecord[];

function runHook(
	script: string,
	input: Record<string, unknown>,
): Promise<{ stdout: string; code: number | null }> {
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
			[resolve(DIST_DIR, script)],
			{ timeout: 30_000, env },
			(error, stdout) => {
				resolveRun({ stdout, code: error?.code ? Number(error.code) : child.exitCode });
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
	home = mkdtempSync(join(tmpdir(), "aidr-canary-hook-home-"));
	records = deployCanaries({
		homeDir: home,
		projectDir: join(home, "project"),
		registryPath: join(home, ".singularity-aidr", "canary", "registry.json"),
	}).deployed;
});

afterEach(() => {
	rmSync(home, { recursive: true, force: true });
});

describe("Claude Code canary enforcement (built bundles)", () => {
	it("PreToolUse denies a read of a decoy credential file", async () => {
		const aws = records.find((record) => record.kind === "aws") as CanaryRecord;
		const result = await runHook("pre-tool-use.cjs", {
			session_id: "s-canary",
			tool_name: "Read",
			tool_input: { file_path: aws.path },
		});
		expect(result.code).toBe(0);
		const output = JSON.parse(result.stdout) as {
			systemMessage: string;
			hookSpecificOutput: { permissionDecision: string };
		};
		expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
		expect(output.systemMessage).toContain("canary_triggered");
		expect(output.systemMessage).not.toContain(aws.path);
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({ category: "canary_triggered", verdict: "deny" }),
		);
	});

	it("PostToolUse blocks tool output carrying a decoy value and records it", async () => {
		const secret = token("env", 1);
		const result = await runHook("post-tool-use.cjs", {
			session_id: "s-canary",
			tool_name: "Bash",
			tool_use_id: "toolu_canary",
			tool_input: { command: "grep -rn SECRET ." },
			tool_response: { stdout: `./.env.backup:4:JWT_SECRET=${secret}`, stderr: "" },
		});
		expect(result.code).toBe(0);
		expect(result.stdout).toContain('"decision":"block"');
		expect(result.stdout).toContain("OUT-CANARY-001");
		expect(result.stdout).not.toContain(secret);
		const entry = auditEntries().find((candidate) => candidate.category === "canary_triggered");
		expect(entry).toMatchObject({ tool_name: "Bash", source: "canary", verdict: "deny" });
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});

	it("UserPromptSubmit blocks a prompt carrying a decoy value", async () => {
		const result = await runHook("user-prompt-submit.cjs", {
			session_id: "s-canary",
			hook_event_name: "UserPromptSubmit",
			prompt: `use this key: ${token("aws")}`,
		});
		expect(result.code).toBe(0);
		const output = JSON.parse(result.stdout) as { decision: string; reason: string };
		expect(output.decision).toBe("block");
		expect(output.reason).toContain("canary credential");
		expect(auditEntries()).toContainEqual(
			expect.objectContaining({ category: "canary_triggered", tool_name: "UserPromptSubmit" }),
		);
	});
});
