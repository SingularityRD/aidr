/**
 * Built-bundle tests for DLP redaction (PreToolUse `updatedInput`) and prompt
 * protection (UserPromptSubmit). Both spawn `dist/*.cjs` as Claude Code would,
 * so they require the core and claude-code builds.
 */

import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	detectorPolicyPayload,
	provisionTenantDetectorPolicy,
	syntheticDlpPolicy,
	TEST_DLP_MARKER,
	TEST_TENANT_ID,
} from "../../../core/src/__tests__/detector-provisioning-fixtures.js";
import {
	DEFAULT_USER_PROMPT_SUBMIT_DEADLINE_MS,
	resolveUserPromptSubmitDeadlineMs,
	USER_PROMPT_SUBMIT_HOST_TIMEOUT_MS,
} from "../hook-input.js";

const DIST_DIR = resolve(__dirname, "..", "..", "dist");
const PRE_TOOL_USE = resolve(DIST_DIR, "pre-tool-use.cjs");
const USER_PROMPT_SUBMIT = resolve(DIST_DIR, "user-prompt-submit.cjs");

// Synthetic token built at runtime so no literal credential sits in the source.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;
// Checksum-valid synthetic identifiers (TC Kimlik check digits, IBAN mod-97).
const TC_KIMLIK = "10000000146";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";
/** An invalid percent-escape the privacy rules cannot decode, so they skip the text. */
const UNDECODABLE_PROMPT = "discount 100%ff on everything";

let home: string;

function childEnv(): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = {
		...process.env,
		HOME: home,
		USERPROFILE: home,
		APPDATA: join(home, "AppData", "Roaming"),
		LOCALAPPDATA: join(home, "AppData", "Local"),
		XDG_CONFIG_HOME: join(home, ".config"),
		XDG_DATA_HOME: join(home, ".local", "share"),
		XDG_STATE_HOME: join(home, ".local", "state"),
		XDG_CACHE_HOME: join(home, ".cache"),
	};
	for (const key of Object.keys(env)) {
		if (key.startsWith("AIDR_")) delete env[key];
	}
	return env;
}

function runBundle(
	script: string,
	stdin: string,
	env: Record<string, string> = {},
): Promise<{ stdout: string; stderr: string; code: number | null }> {
	return new Promise((resolveRun) => {
		const child = execFile(
			process.execPath,
			[script],
			{ timeout: 30_000, env: { ...childEnv(), ...env }, maxBuffer: 16 * 1024 * 1024 },
			(error, stdout, stderr) => {
				resolveRun({
					stdout,
					stderr,
					code: error?.code ? Number(error.code) : child.exitCode,
				});
			},
		);
		child.stdin?.end(stdin);
	});
}

async function submitPrompt(prompt: string, env: Record<string, string> = {}) {
	const result = await runBundle(
		USER_PROMPT_SUBMIT,
		JSON.stringify({
			session_id: "session-prompt",
			transcript_path: join(home, "transcript.jsonl"),
			cwd: home,
			permission_mode: "default",
			hook_event_name: "UserPromptSubmit",
			prompt,
		}),
		env,
	);
	expect(result.code).toBe(0);
	return {
		...result,
		response: result.stdout.trim() === "" ? null : JSON.parse(result.stdout.trim()),
	};
}

async function writeLocalConfig(overrides: Record<string, unknown> = {}): Promise<void> {
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

/** Merge fields into the config a provisioning fixture wrote, keeping its keys. */
async function patchConfig(overrides: Record<string, unknown>): Promise<void> {
	const path = join(home, ".singularity-aidr", "config.json");
	const current = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
	await writeFile(path, JSON.stringify({ ...current, ...overrides }));
}

async function auditLog(): Promise<string> {
	const path = join(home, ".singularity-aidr", "audit.jsonl");
	return existsSync(path) ? readFile(path, "utf8") : "";
}

beforeEach(async () => {
	expect(existsSync(PRE_TOOL_USE), "run the claude-code build first").toBe(true);
	expect(existsSync(USER_PROMPT_SUBMIT), "run the claude-code build first").toBe(true);
	home = await mkdtemp(join(tmpdir(), "aidr-prompt-protection-"));
});

afterEach(async () => {
	await rm(home, { recursive: true, force: true });
});

describe("UserPromptSubmit bundle", () => {
	it("allows an ordinary prompt with no output", async () => {
		await writeLocalConfig();
		const { response } = await submitPrompt("refactor the parser and add tests");
		expect(response).toBeNull();
		expect(await auditLog()).toBe("");
	}, 30_000);

	it("blocks a secret by default without echoing it, and audits kinds only", async () => {
		await writeLocalConfig();
		const { response, stdout, stderr } = await submitPrompt(`deploy with ${GITHUB_TOKEN} now`);
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("GitHub token");
		expect(stdout + stderr).not.toContain(GITHUB_TOKEN);

		const audit = await auditLog();
		expect(audit).toContain('"category":"prompt_protection"');
		expect(audit).toContain('"verdict":"deny"');
		expect(audit).not.toContain(GITHUB_TOKEN);
		expect(audit).not.toContain("deploy with");
	}, 30_000);

	it("blocks a private key on a fresh install with no config file", async () => {
		const { response } = await submitPrompt(
			"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
		);
		expect(response).toMatchObject({ decision: "block" });
		expect(JSON.stringify(response)).not.toContain("b3BlbnNzaC1rZXktdjEAAAAA");
	}, 30_000);

	it("warns on PII with a user notice and model context", async () => {
		await writeLocalConfig();
		const { response } = await submitPrompt("email jane.doe@example.com the report");
		expect(response).toMatchObject({
			systemMessage: expect.stringContaining("email address"),
			hookSpecificOutput: {
				hookEventName: "UserPromptSubmit",
				additionalContext: expect.stringContaining("email address"),
			},
		});
		expect(response.decision).toBeUndefined();
		expect(JSON.stringify(response)).not.toContain("jane.doe@example.com");
		const audit = await auditLog();
		expect(audit).toContain('"category":"prompt_protection_warning"');
		expect(audit).not.toContain("jane.doe@example.com");
	}, 30_000);

	it("warns on Turkish PII in the tail of a prompt over 1 MiB", async () => {
		await writeLocalConfig();
		const prompt = `${"lorem ipsum 7 ".repeat(80_000)} TC ${TC_KIMLIK} IBAN ${IBAN}`;
		expect(prompt.length).toBeGreaterThan(1024 * 1024);
		const { response, stdout } = await submitPrompt(prompt);
		expect(response.decision).toBeUndefined();
		expect(response.systemMessage).toContain("Turkish ID number (TC Kimlik)");
		expect(response.systemMessage).toContain("IBAN");
		expect(response.systemMessage).not.toContain("could not inspect");
		expect(stdout).not.toContain(TC_KIMLIK);
		expect(stdout).not.toContain("TR33");
		const audit = await auditLog();
		expect(audit).toContain("TC Kimlik");
		expect(audit).not.toContain(TC_KIMLIK);
	}, 30_000);

	it("never reports an incompletely inspected prompt as clean", async () => {
		await writeLocalConfig();
		const warned = await submitPrompt(UNDECODABLE_PROMPT);
		expect(warned.response.decision).toBeUndefined();
		expect(warned.response.systemMessage).toContain("could not inspect the whole prompt");
		expect(warned.response.hookSpecificOutput).toMatchObject({
			hookEventName: "UserPromptSubmit",
			additionalContext: expect.stringContaining("Do not repeat personal data"),
		});
		const audit = await auditLog();
		expect(audit).toContain('"category":"prompt_protection_warning"');
		expect(audit).toContain("personal-data inspection incomplete (INVALID_ENCODING)");
		expect(audit).not.toContain("discount");

		await writeLocalConfig({ prompt_protection: { secrets: "block", pii: "block" } });
		const blocked = await submitPrompt(UNDECODABLE_PROMPT);
		expect(blocked.response).toMatchObject({ decision: "block" });
		expect(blocked.response.reason).toContain("could not fully inspect it for personal data");
		expect(blocked.stdout).not.toContain("discount");
	}, 60_000);

	it("honours prompt_protection modes", async () => {
		await writeLocalConfig({ prompt_protection: { secrets: "warn", pii: "block" } });
		const secret = await submitPrompt(`token ${GITHUB_TOKEN}`);
		expect(secret.response.decision).toBeUndefined();
		expect(secret.response.hookSpecificOutput.additionalContext).toContain("GitHub token");
		const pii = await submitPrompt("ssn 123-45-6789");
		expect(pii.response).toMatchObject({ decision: "block" });

		await writeLocalConfig({ prompt_protection: { secrets: "off", pii: "off" } });
		expect((await submitPrompt(`token ${GITHUB_TOKEN} jane.doe@example.com`)).response).toBeNull();
	}, 60_000);

	it("blocks uninspectable input only when secrets policy is block", async () => {
		await writeLocalConfig();
		const blocked = await runBundle(USER_PROMPT_SUBMIT, "{ not json secret-marker");
		expect(blocked.code).toBe(0);
		const blockedResponse = JSON.parse(blocked.stdout.trim());
		expect(blockedResponse).toMatchObject({ decision: "block" });
		expect(blocked.stdout).not.toContain("secret-marker");

		await writeLocalConfig({ prompt_protection: { secrets: "warn", pii: "warn" } });
		const passed = await runBundle(USER_PROMPT_SUBMIT, JSON.stringify({ prompt: 42 }));
		expect(passed.code).toBe(0);
		const passedResponse = JSON.parse(passed.stdout.trim());
		expect(passedResponse.decision).toBeUndefined();
		expect(passedResponse.systemMessage).toContain("could not inspect");
	}, 60_000);

	describe("oversized prompt (over the 2 MiB hook input limit)", () => {
		const OVERSIZED = `${"lorem ipsum 7 ".repeat(160_000)} email jane.doe@example.com`;

		it("is sent with a notice only when no rule would have blocked", async () => {
			expect(OVERSIZED.length).toBeGreaterThan(2 * 1024 * 1024);
			await writeLocalConfig({ prompt_protection: { secrets: "warn", pii: "warn" } });
			const { response, stdout } = await submitPrompt(OVERSIZED);
			expect(response.decision).toBeUndefined();
			expect(response.systemMessage).toContain("could not inspect");
			expect(stdout).not.toContain("jane.doe@example.com");
		}, 30_000);

		it("blocks when personal data is in block mode, even with secrets warn", async () => {
			await writeLocalConfig({ prompt_protection: { secrets: "warn", pii: "block" } });
			// The same personal data in a normal-size prompt is blocked by the scan…
			expect((await submitPrompt("email jane.doe@example.com")).response).toMatchObject({
				decision: "block",
			});
			// …and an oversized one cannot slip past it as a warning.
			const { response, stdout } = await submitPrompt(OVERSIZED);
			expect(response).toMatchObject({ decision: "block" });
			expect(stdout).not.toContain("jane.doe@example.com");
		}, 60_000);

		it("blocks when a tenant DLP policy is provisioned, even with local protection relaxed", async () => {
			await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "claude-code" });
			await patchConfig({ prompt_protection: { secrets: "warn", pii: "warn" } });
			// Benign twin: the tenant policy verifies and an ordinary prompt passes.
			expect((await submitPrompt("refactor the parser")).response).toBeNull();
			const { response } = await submitPrompt(OVERSIZED);
			expect(response).toMatchObject({ decision: "block" });
			expect(response.reason).not.toContain("could not verify");
		}, 30_000);

		it("blocks as unverified when the provisioned tenant policy cannot be verified", async () => {
			await provisionTenantDetectorPolicy({
				homeDir: home,
				agentRuntime: "claude-code",
				tamperPolicy: "signature",
			});
			await patchConfig({ prompt_protection: { secrets: "warn", pii: "warn" } });
			const { response } = await submitPrompt(OVERSIZED);
			expect(response).toMatchObject({ decision: "block" });
			expect(response.reason).toContain("could not verify");
		}, 30_000);
	});

	it("blocks unreadable input when jailbreak is in block mode, even with secrets warn", async () => {
		await writeLocalConfig({
			prompt_protection: { secrets: "warn", pii: "warn", jailbreak: "block" },
		});
		const result = await runBundle(USER_PROMPT_SUBMIT, JSON.stringify({ prompt: 42 }));
		expect(result.code).toBe(0);
		expect(JSON.parse(result.stdout.trim())).toMatchObject({ decision: "block" });
	}, 30_000);

	it("applies a provisioned tenant DLP policy to the prompt", async () => {
		await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "claude-code" });
		const { response } = await submitPrompt(`summarize ${TEST_DLP_MARKER} for me`);
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("Tenant restricted value");
		expect(JSON.stringify(response)).not.toContain(TEST_DLP_MARKER);
	}, 30_000);

	it("blocks when a provisioned tenant policy cannot be verified", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "claude-code",
			tamperPolicy: "signature",
		});
		const { response } = await submitPrompt("an ordinary prompt");
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("could not verify");
	}, 30_000);
});

describe("UserPromptSubmit bundle deadline", () => {
	/** ~1.5 MB of email addresses: the shape that used to take ~30 s to scan. */
	const EMAILS = Array.from({ length: 110_000 }, (_, i) => `u${i}@c${i}.io `).join("");
	const FORCED_DEADLINE = { AIDR_USER_PROMPT_SUBMIT_DEADLINE_MS: "100" };

	it("inspects a large adversarial prompt fully, well before the deadline", async () => {
		await writeLocalConfig();
		const started = Date.now();
		const { response, stdout } = await submitPrompt(`${EMAILS} my token ${GITHUB_TOKEN}`);
		expect(Date.now() - started).toBeLessThan(DEFAULT_USER_PROMPT_SUBMIT_DEADLINE_MS);
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("GitHub token");
		expect(stdout).not.toContain(GITHUB_TOKEN);
		expect(await auditLog()).toContain("counts are lower bounds");
	}, 30_000);

	it("blocks a prompt it could not finish inspecting when secrets policy is block", async () => {
		await writeLocalConfig();
		const { response, stdout } = await submitPrompt(EMAILS, FORCED_DEADLINE);
		expect(stdout.trim().split("\n")).toHaveLength(1);
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("could not finish inspecting this prompt in time");
		expect(stdout).not.toContain("u1@c1.io");
	}, 30_000);

	it("blocks an unfinished prompt when personal data is in block mode, even with secrets warn", async () => {
		await writeLocalConfig({ prompt_protection: { secrets: "warn", pii: "block" } });
		const { response, stdout } = await submitPrompt(EMAILS, FORCED_DEADLINE);
		expect(stdout.trim().split("\n")).toHaveLength(1);
		expect(response).toMatchObject({ decision: "block" });
		expect(response.reason).toContain("could not finish inspecting this prompt in time");
		expect(stdout).not.toContain("u1@c1.io");
	}, 30_000);

	it("sends an unfinished prompt with a visible notice when secrets policy is warn", async () => {
		await writeLocalConfig({ prompt_protection: { secrets: "warn", pii: "warn" } });
		const { response, stdout } = await submitPrompt(`${EMAILS} ${GITHUB_TOKEN}`, FORCED_DEADLINE);
		expect(stdout.trim().split("\n")).toHaveLength(1);
		expect(response.decision).toBeUndefined();
		expect(response.systemMessage).toContain("could not finish inspecting this prompt in time");
		expect(response.systemMessage).toContain("without being fully inspected");
		expect(stdout).not.toContain(GITHUB_TOKEN);
	}, 30_000);
});

describe("resolveUserPromptSubmitDeadlineMs", () => {
	it("defaults to 7 s, below the 10 s hooks.json timeout", () => {
		const hooks = JSON.parse(
			readFileSync(resolve(__dirname, "../../../../hooks/hooks.json"), "utf8"),
		) as { hooks: { UserPromptSubmit: { hooks: { timeout: number }[] }[] } };
		const hostTimeoutMs = (hooks.hooks.UserPromptSubmit[0]?.hooks[0]?.timeout ?? 0) * 1000;
		expect(hostTimeoutMs).toBe(USER_PROMPT_SUBMIT_HOST_TIMEOUT_MS);
		expect(resolveUserPromptSubmitDeadlineMs({})).toBe(DEFAULT_USER_PROMPT_SUBMIT_DEADLINE_MS);
		expect(DEFAULT_USER_PROMPT_SUBMIT_DEADLINE_MS).toBe(7_000);
		expect(resolveUserPromptSubmitDeadlineMs({})).toBeLessThan(hostTimeoutMs);
	});

	it.each([
		["2500", 2500],
		["100", 100],
		["9000", 9000],
		["9001", 7000],
		["10000", 7000],
		["99", 7000],
		["-5", 7000],
		["1.5", 7000],
		["abc", 7000],
		["", 7000],
	])("resolves %j to %d ms", (value, expected) => {
		expect(resolveUserPromptSubmitDeadlineMs({ AIDR_USER_PROMPT_SUBMIT_DEADLINE_MS: value })).toBe(
			expected,
		);
	});
});

describe("PreToolUse bundle DLP redaction", () => {
	function redactPolicyPayload() {
		const policy = syntheticDlpPolicy(TEST_TENANT_ID) as {
			rules: Array<Record<string, unknown>>;
		};
		policy.rules = policy.rules.map((rule) => ({ ...rule, action: "redact" }));
		return detectorPolicyPayload(TEST_TENANT_ID, { dlp: { enabled: true, policy } });
	}

	it("emits updatedInput without a permission decision", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "claude-code",
			payload: redactPolicyPayload(),
		});
		const result = await runBundle(
			PRE_TOOL_USE,
			JSON.stringify({
				session_id: "session-redact",
				tool_name: "Write",
				tool_input: { file_path: "notes.txt", content: `value=${TEST_DLP_MARKER}` },
			}),
		);
		expect(result.code).toBe(0);
		const response = JSON.parse(result.stdout.trim());
		expect(response.hookSpecificOutput).toEqual({
			hookEventName: "PreToolUse",
			updatedInput: { file_path: "notes.txt", content: "value=REDACTED" },
			additionalContext: expect.stringContaining("redaction markers"),
		});
		expect(response.hookSpecificOutput.permissionDecision).toBeUndefined();
		expect(response.systemMessage).toContain("redacted");
		expect(result.stdout + result.stderr).not.toContain(TEST_DLP_MARKER);
	}, 30_000);

	it("keeps a block policy as a deny", async () => {
		await provisionTenantDetectorPolicy({ homeDir: home, agentRuntime: "claude-code" });
		const result = await runBundle(
			PRE_TOOL_USE,
			JSON.stringify({
				tool_name: "Write",
				tool_input: { file_path: "notes.txt", content: TEST_DLP_MARKER },
			}),
		);
		const response = JSON.parse(result.stdout.trim());
		expect(response.hookSpecificOutput).toMatchObject({ permissionDecision: "deny" });
		expect(response.hookSpecificOutput.updatedInput).toBeUndefined();
	}, 30_000);
});
