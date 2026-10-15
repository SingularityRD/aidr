/**
 * Built-bundle regression tests for CON-9: the PostToolUse hook must never let
 * uninspected output reach Claude. Large results (a secret at the very end of
 * more than 1 MiB), input above the configured ceiling and a forced deadline
 * all answer with an `updatedToolOutput` quarantine replacement, not only a
 * block annotation. Requires the core and claude-code builds.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const HOOK = resolve(__dirname, "..", "..", "dist", "post-tool-use.cjs");
// Assembled at runtime so secret scanners do not flag the fixture.
const GITHUB_TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("");
const PADDING = "build log line\n".repeat(80_000); // ~1.2 MB

let home: string;

interface HookRun {
	stdout: string;
	response: Record<string, unknown>;
}

function runHook(
	input: string,
	env: Record<string, string> = {},
	{ keepStdinOpen = false } = {},
): Promise<HookRun> {
	const childEnv: NodeJS.ProcessEnv = {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		XDG_CONFIG_HOME: join(home, ".config"),
		XDG_STATE_HOME: join(home, ".local", "state"),
		XDG_CACHE_HOME: join(home, ".cache"),
	};
	for (const key of Object.keys(childEnv)) if (key.startsWith("AIDR_")) delete childEnv[key];
	Object.assign(childEnv, env);
	return new Promise((resolveRun, reject) => {
		const child = execFile(
			process.execPath,
			[HOOK],
			{ timeout: 30_000, env: childEnv, maxBuffer: 16 * 1024 * 1024 },
			(error, stdout) => {
				if (error && error.code !== 0) {
					reject(error);
					return;
				}
				resolveRun({ stdout, response: JSON.parse(stdout) as Record<string, unknown> });
			},
		);
		// Oversized input: the hook answers and exits before reading the rest.
		child.stdin?.on("error", () => {});
		if (keepStdinOpen) child.stdin?.write(input);
		else child.stdin?.end(input);
	});
}

function hookInput(toolName: string, toolResponse: unknown): string {
	return JSON.stringify({
		session_id: "s-con9",
		hook_event_name: "PostToolUse",
		tool_name: toolName,
		tool_input: { command: "cat build.log" },
		tool_response: toolResponse,
		tool_use_id: "toolu_con9",
	});
}

function specific(run: HookRun): Record<string, unknown> {
	return run.response.hookSpecificOutput as Record<string, unknown>;
}

beforeEach(() => {
	home = mkdtempSync(join(tmpdir(), "aidr-post-tool-fail-closed-"));
});

afterEach(() => {
	rmSync(home, { recursive: true, force: true });
});

describe("Claude Code PostToolUse never passes uninspected output through (CON-9)", () => {
	it("replaces a >1 MiB Bash result with a secret at the end", async () => {
		const run = await runHook(
			hookInput("Bash", {
				stdout: `${PADDING}${GITHUB_TOKEN}\n`,
				stderr: "",
				interrupted: false,
				isImage: false,
				noOutputExpected: false,
			}),
		);
		expect(run.response.decision).toBe("block");
		expect(specific(run).updatedToolOutput).toMatchObject({
			stdout: expect.stringContaining("quarantined"),
			stderr: expect.any(String),
			interrupted: false,
		});
		expect(run.stdout).not.toContain(GITHUB_TOKEN);
	});

	it("replaces a >1 MiB MCP result with a secret at the end", async () => {
		const run = await runHook(
			hookInput("mcp__docs__fetch", [{ type: "text", text: `${PADDING}${GITHUB_TOKEN}` }]),
		);
		expect(run.response.decision).toBe("block");
		expect(specific(run).updatedToolOutput).toEqual([
			{ type: "text", text: expect.stringContaining("quarantined") },
		]);
		expect(run.stdout).not.toContain(GITHUB_TOKEN);
	});

	it.each([
		["Bash", { stdout: `${PADDING}${GITHUB_TOKEN}`, stderr: "", interrupted: false }],
		["mcp__docs__fetch", [{ type: "text", text: `${PADDING}${GITHUB_TOKEN}` }]],
	])("replaces %s input above the configured ceiling by tool name", async (tool, response) => {
		const run = await runHook(hookInput(tool, response), {
			AIDR_POST_TOOL_USE_MAX_INPUT_BYTES: String(1024 * 1024),
		});
		expect(run.response.decision).toBe("block");
		expect(String(run.response.reason)).toContain("processing limit");
		expect(specific(run).updatedToolOutput).toBeDefined();
		expect(JSON.stringify(specific(run).updatedToolOutput)).toContain("quarantined");
		expect(run.stdout).not.toContain(GITHUB_TOKEN);
	});

	it("withholds the output when the deadline passes before the input is complete", async () => {
		const partial = hookInput("Bash", { stdout: `token ${GITHUB_TOKEN}` }).slice(0, -3);
		const run = await runHook(
			partial,
			{ AIDR_POST_TOOL_USE_DEADLINE_MS: "300" },
			{ keepStdinOpen: true },
		);
		expect(run.response.decision).toBe("block");
		expect(String(run.response.reason)).toContain("did not finish in time");
		expect(specific(run).updatedToolOutput).toEqual({
			stdout: expect.stringContaining("quarantined"),
			stderr: "",
			interrupted: false,
		});
		expect(run.stdout).not.toContain(GITHUB_TOKEN);
	});

	it("still replaces a small Bash result carrying a secret", async () => {
		const run = await runHook(
			hookInput("Bash", { stdout: `token ${GITHUB_TOKEN}`, stderr: "", interrupted: false }),
		);
		expect(specific(run).updatedToolOutput).toHaveProperty("stdout");
		expect(run.stdout).not.toContain(GITHUB_TOKEN);
	});

	it("leaves a clean result untouched", async () => {
		const run = await runHook(
			hookInput("Bash", { stdout: "Build succeeded", stderr: "", interrupted: false }),
		);
		expect(run.response).toEqual({});
	});
});
