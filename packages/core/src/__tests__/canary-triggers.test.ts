import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toolResultReportsFailure } from "../agent-safety/tool-outcome.js";
import { type CanaryRecord, deployCanaries, invalidateCanaryIndex } from "../canary/index.js";
import {
	CANARY_PROMPT_BLOCK_MESSAGE,
	checkPromptForCanaries,
	recordToolOutputCanaries,
} from "../canary-triggers.js";
import { inspectUserPrompt } from "../prompt-inspection.js";
import { type Config, ConfigSchema } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

let root: string;
let home: string;
let auditPath: string;
let configPath: string;
let records: CanaryRecord[];

function config(): Config {
	return ConfigSchema.parse({ mode: "local", logging: { enabled: true, path: auditPath } });
}

function auditEntries(): Array<Record<string, unknown>> {
	try {
		return readFileSync(auditPath, "utf8")
			.split("\n")
			.filter((line) => line.trim())
			.map((line) => JSON.parse(line) as Record<string, unknown>);
	} catch {
		return [];
	}
}

function token(kind: CanaryRecord["kind"], index = 0): string {
	const path = records.find((entry) => entry.kind === kind)?.path as string;
	return [...readFileSync(path, "utf8").matchAll(/[A-Za-z0-9]{20,}/g)][index]?.[0] as string;
}

beforeEach(async () => {
	root = await makeTmpDir();
	home = join(root, "home");
	mkdirSync(home, { recursive: true });
	vi.stubEnv("HOME", home);
	auditPath = join(home, ".singularity-aidr", "audit.jsonl");
	configPath = join(root, "config.json");
	writeFileSync(
		configPath,
		JSON.stringify({ mode: "local", logging: { enabled: true, path: auditPath } }),
	);
	invalidateCanaryIndex();
	records = deployCanaries({ projectDir: join(root, "project"), homeDir: home }).deployed;
});

afterEach(async () => {
	vi.unstubAllEnvs();
	invalidateCanaryIndex();
	await removeTmpDir(root);
});

describe("canary values in prompts (shared connector path)", () => {
	for (const runtime of ["cursor", "vscode", "codex", "opencode", "openclaw"] as const) {
		it(`inspectUserPrompt blocks and records a canary prompt for ${runtime}`, async () => {
			const secret = token("openai");
			const outcome = await inspectUserPrompt({
				runtime,
				hookEvent: "PromptHook",
				sessionId: `s-${runtime}`,
				prompt: `please call the API with ${secret}`,
				deadlineAt: Date.now() + 10_000,
				config: config(),
				loadTenantDlp: async () => undefined,
			});
			expect(outcome).toEqual({
				decision: "block",
				reason: "canary",
				userMessage: CANARY_PROMPT_BLOCK_MESSAGE,
			});
			const entries = auditEntries();
			// One entry: the canary recorder's, not a second prompt-protection one.
			expect(entries).toHaveLength(1);
			expect(entries[0]).toMatchObject({
				category: "canary_triggered",
				source: "canary",
				tool_name: "PromptHook",
				verdict: "deny",
				session_id: `s-${runtime}`,
			});
			expect(JSON.stringify(entries)).not.toContain(secret);
		});
	}

	it("blocks a canary even when prompt protection is set to warn or off", async () => {
		const outcome = await inspectUserPrompt({
			runtime: "cursor",
			hookEvent: "beforeSubmitPrompt",
			sessionId: "s-off",
			prompt: `key ${token("aws")}`,
			deadlineAt: Date.now() + 10_000,
			config: ConfigSchema.parse({
				mode: "local",
				logging: { enabled: true, path: auditPath },
				prompt_protection: { secrets: "off", pii: "off", jailbreak: "off" },
			}),
			loadTenantDlp: async () => undefined,
		});
		expect(outcome.decision).toBe("block");
		expect(outcome.reason).toBe("canary");
	});

	it("leaves a prompt without canary values to the regular scan", async () => {
		const outcome = await inspectUserPrompt({
			runtime: "codex",
			hookEvent: "UserPromptSubmit",
			sessionId: "s-clean",
			prompt: "rename the helper",
			deadlineAt: Date.now() + 10_000,
			config: config(),
			loadTenantDlp: async () => undefined,
		});
		expect(outcome).toEqual({ decision: "allow", reason: "clean" });
		expect(auditEntries()).toEqual([]);
	});

	it("skips (and logs) an unreadable registry instead of reporting a clean check", async () => {
		writeFileSync(join(home, ".singularity-aidr", "canary", "registry.json"), "{not json");
		invalidateCanaryIndex();
		const warnings: string[] = [];
		const status = await checkPromptForCanaries({
			sessionId: "s",
			hookEvent: "UserPromptSubmit",
			prompt: `key ${token("aws")}`,
			agentRuntime: "codex",
			config: config(),
			logger: {
				debug() {},
				info() {},
				warn(message: string) {
					warnings.push(message);
				},
				error() {},
			},
		});
		expect(status).toBe("unavailable");
		expect(warnings.join("\n")).toContain("Canary check of the prompt unavailable");
	});
});

describe("canary values in tool output (shared connector path)", () => {
	it("records an output trigger with canary ids only", async () => {
		const secret = token("env", 1);
		const status = await recordToolOutputCanaries({
			sessionId: "s-out",
			toolName: "read_file",
			toolOutput: { content: [{ type: "text", text: `JWT_SECRET=${secret}` }] },
			agentRuntime: "opencode",
			configPath,
		});
		expect(status).toBe("triggered");
		const entry = auditEntries().find((candidate) => candidate.category === "canary_triggered");
		expect(entry).toMatchObject({ tool_name: "read_file", source: "canary", verdict: "deny" });
		expect(JSON.stringify(auditEntries())).not.toContain(secret);
	});

	it("reports clear output and writes nothing", async () => {
		expect(
			await recordToolOutputCanaries({
				sessionId: "s-out",
				toolName: "Bash",
				toolOutput: "all tests passed",
				agentRuntime: "cursor",
				configPath,
			}),
		).toBe("clear");
		expect(auditEntries()).toEqual([]);
	});
});

describe("toolResultReportsFailure", () => {
	it("counts only explicit failure markers", () => {
		expect(toolResultReportsFailure({ exit_code: 2 })).toBe(true);
		expect(toolResultReportsFailure({ exitCode: 1, stdout: "" })).toBe(true);
		expect(toolResultReportsFailure({ is_error: true })).toBe(true);
		expect(toolResultReportsFailure({ isError: true, content: [] })).toBe(true);
		expect(toolResultReportsFailure(JSON.stringify({ exitCode: 127, stdout: "" }))).toBe(true);
		expect(toolResultReportsFailure({ exit_code: 0 })).toBe(false);
		expect(toolResultReportsFailure(JSON.stringify({ exitCode: 0 }))).toBe(false);
		expect(toolResultReportsFailure("Process exited with code 1")).toBe(false);
		expect(toolResultReportsFailure("{not json")).toBe(false);
		expect(toolResultReportsFailure(["exit_code", 1])).toBe(false);
		expect(toolResultReportsFailure(null)).toBe(false);
		expect(toolResultReportsFailure({ exit_code: "1" })).toBe(false);
	});
});
