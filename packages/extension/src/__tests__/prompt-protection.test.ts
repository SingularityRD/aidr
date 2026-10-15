/**
 * Built-bundle tests for prompt protection in the Cursor (`beforeSubmitPrompt`)
 * and VS Code Local (`UserPromptSubmit`) hooks. They spawn `dist/aidr-hook.cjs`
 * the way the managed hook command does, so they require the extension build.
 */

/// <reference types="node" />

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import {
	provisionTenantDetectorPolicy,
	TEST_DLP_MARKER,
} from "../../../core/src/__tests__/detector-provisioning-fixtures.js";

const AIDR_HOOK = resolve(__dirname, "..", "..", "dist", "aidr-hook.cjs");

// Synthetic values built at runtime so no literal credential sits in the source.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;
// Checksum-valid synthetic identifiers (TC Kimlik check digits, IBAN mod-97).
const TC_KIMLIK = "10000000146";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";

const homes: string[] = [];
let home: string;

function childEnv(extra: Record<string, string>): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = { ...process.env };
	for (const key of Object.keys(env)) {
		if (key.startsWith("AIDR_")) delete env[key];
	}
	return {
		...env,
		HOME: home,
		USERPROFILE: home,
		APPDATA: join(home, "AppData", "Roaming"),
		LOCALAPPDATA: join(home, "AppData", "Local"),
		XDG_CONFIG_HOME: join(home, ".config"),
		XDG_STATE_HOME: join(home, ".local", "state"),
		...extra,
	};
}

function runHook(
	mode: "cursor" | "vscode",
	input: Record<string, unknown> | string,
	env: Record<string, string> = {},
): Promise<{ code: number | null; response: Record<string, unknown>; stdout: string }> {
	return new Promise((resolveRun) => {
		const child = execFile(
			process.execPath,
			[AIDR_HOOK, mode],
			{ env: childEnv(env), timeout: 60_000, maxBuffer: 16 * 1024 * 1024 },
			(error, stdout) => {
				resolveRun({
					code: error?.code ? Number(error.code) : child.exitCode,
					stdout,
					response: JSON.parse(stdout.trim()) as Record<string, unknown>,
				});
			},
		);
		child.stdin?.end(typeof input === "string" ? input : JSON.stringify(input));
	});
}

function cursorPrompt(prompt: unknown): Record<string, unknown> {
	return {
		hook_event_name: "beforeSubmitPrompt",
		conversation_id: "conversation-1",
		generation_id: "generation-1",
		prompt,
		attachments: [],
		workspace_roots: [home],
	};
}

function vscodePrompt(prompt: unknown): Record<string, unknown> {
	return {
		hook_event_name: "UserPromptSubmit",
		timestamp: new Date().toISOString(),
		session_id: "session-1",
		cwd: home,
		prompt,
	};
}

async function writeConfig(overrides: Record<string, unknown> = {}): Promise<void> {
	const dir = join(home, ".singularity-aidr");
	await mkdir(dir, { recursive: true });
	await writeFile(
		join(dir, "config.json"),
		JSON.stringify({
			mode: "local",
			logging: { enabled: true, path: join(dir, "audit.jsonl") },
			...overrides,
		}),
	);
}

async function auditLog(): Promise<string> {
	const path = join(home, ".singularity-aidr", "audit.jsonl");
	return existsSync(path) ? readFile(path, "utf8") : "";
}

beforeEach(async () => {
	expect(existsSync(AIDR_HOOK), "run the extension build first").toBe(true);
	home = await mkdtemp(join(tmpdir(), "aidr-ext-prompt-"));
	homes.push(home);
	await writeConfig();
});

afterAll(async () => {
	await Promise.all(homes.map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("Cursor beforeSubmitPrompt", () => {
	it("lets a clean prompt continue", async () => {
		const run = await runHook("cursor", cursorPrompt("add input validation to the form"));
		expect(run.code).toBe(0);
		expect(run.response).toEqual({ continue: true });
		expect(await auditLog()).toBe("");
	});

	it("stops a prompt carrying a secret and never echoes it", async () => {
		const run = await runHook("cursor", cursorPrompt(`deploy with token ${GITHUB_TOKEN}`));
		expect(run.code).toBe(0);
		expect(run.response.continue).toBe(false);
		expect(run.response.user_message).toContain("GitHub token");
		expect(run.stdout).not.toContain(GITHUB_TOKEN);
		const log = await auditLog();
		expect(log).toContain('"tool_name":"beforeSubmitPrompt"');
		expect(log).toContain('"category":"prompt_protection"');
		expect(log).not.toContain(GITHUB_TOKEN);
	});

	it("recognises the event by shape when hook_event_name is absent", async () => {
		const run = await runHook("cursor", { prompt: `key ${GITHUB_TOKEN}`, attachments: [] });
		expect(run.response.continue).toBe(false);
	});

	it("sends Turkish personal data with a notice under the default warn policy", async () => {
		const run = await runHook("cursor", cursorPrompt(`TCKN ${TC_KIMLIK} ve IBAN ${IBAN}`));
		expect(run.response.continue).toBe(true);
		expect(run.response.user_message).toContain("Turkish ID number (TC Kimlik)");
		expect(run.stdout).not.toContain(TC_KIMLIK);
		expect(await auditLog()).toContain("prompt_protection_warning");
	});

	it("follows prompt_protection from config", async () => {
		await writeConfig({ prompt_protection: { secrets: "off", pii: "block" } });
		expect((await runHook("cursor", cursorPrompt(`key ${GITHUB_TOKEN}`))).response).toEqual({
			continue: true,
		});
		expect((await runHook("cursor", cursorPrompt(`IBAN ${IBAN}`))).response.continue).toBe(false);
	});

	it("fails closed on a prompt it cannot read", async () => {
		const run = await runHook("cursor", cursorPrompt({ text: "not a string" }));
		expect(run.response.continue).toBe(false);
		expect(run.response.user_message).toContain("could not inspect this prompt");
	});

	it("blocks an oversized prompt by default and sends it with a notice when secrets are not blocked", async () => {
		const oversized = cursorPrompt("x".repeat(1024 * 1024 + 16));
		const blocked = await runHook("cursor", oversized);
		expect(blocked.response.continue).toBe(false);
		expect(blocked.response.user_message).toContain("could not inspect this prompt");

		await writeConfig({ prompt_protection: { secrets: "warn", pii: "warn" } });
		const warned = await runHook("cursor", oversized);
		expect(warned.response.continue).toBe(true);
		expect(warned.response.user_message).toContain("sent without prompt protection");
	});

	it("stops the prompt when the hook itself fails before reading it", async () => {
		// A commercial build without its signed manifest fails integrity verification.
		const run = await runHook("cursor", cursorPrompt("hello"), { AIDR_COMMERCIAL: "1" });
		expect(run.code).toBe(0);
		expect(run.response.continue).toBe(false);
		expect(run.response.permission).toBe("deny");
	});
});

describe("VS Code Local UserPromptSubmit", () => {
	it("returns no decision for a clean prompt", async () => {
		const run = await runHook("vscode", vscodePrompt("explain this stack trace"));
		expect(run.code).toBe(0);
		expect(run.response).toEqual({});
	});

	it("stops the request for a secret with continue:false", async () => {
		const run = await runHook("vscode", vscodePrompt(`aws key AKIA${"ABCDEFGHIJKLMNOP"}`));
		expect(run.response.continue).toBe(false);
		expect(run.response.stopReason).toContain("AWS access key");
		expect(run.response.hookSpecificOutput).toBeUndefined();
		expect(await auditLog()).toContain('"tool_name":"UserPromptSubmit"');
	});

	it("recognises a prompt payload without hook_event_name", async () => {
		const run = await runHook("vscode", { session_id: "s", prompt: `key ${GITHUB_TOKEN}` });
		expect(run.response.continue).toBe(false);
		expect(run.stdout).not.toContain(GITHUB_TOKEN);
	});

	it("warns with systemMessage for personal data", async () => {
		const run = await runHook("vscode", vscodePrompt(`IBAN ${IBAN}`));
		expect(run.response).toEqual({ systemMessage: expect.stringContaining("IBAN") });
		expect(run.stdout).not.toContain(IBAN);
	});

	it("blocks an oversized prompt instead of answering with a tool-shaped response", async () => {
		const run = await runHook("vscode", vscodePrompt("y".repeat(1024 * 1024 + 16)));
		expect(run.response.continue).toBe(false);
		expect(run.response.stopReason).toContain("could not inspect this prompt");
	});

	it("applies a signed tenant DLP policy to the prompt", async () => {
		await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "vscode" });
		const run = await runHook("vscode", vscodePrompt(`ship ${TEST_DLP_MARKER} today`));
		expect(run.response.continue).toBe(false);
		expect(run.response.stopReason).toContain("organization DLP policy");
		expect(run.stdout).not.toContain(TEST_DLP_MARKER);
	});

	it("stops the prompt when the hook itself fails before reading it", async () => {
		const run = await runHook("vscode", vscodePrompt("hello"), { AIDR_COMMERCIAL: "1" });
		expect(run.code).toBe(0);
		expect(run.response.continue).toBe(false);
		// A commercial build without release metadata cannot verify itself: the
		// stop reason says so and names the fix.
		expect(run.response.stopReason).toContain("cannot verify its own installation");
	});
});
