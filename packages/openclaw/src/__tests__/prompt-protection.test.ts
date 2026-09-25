/**
 * Prompt protection through the built plugin (dist/index.cjs): register() with a
 * mock OpenClaw API, then drive the `before_agent_run` gate and the
 * `before_prompt_build` notice the way OpenClaw's embedded/CLI runners do.
 * Decision shapes follow OpenClaw's `InputGateDecision` (hook-decision-types.ts):
 * a pass has exactly `{ outcome: "pass" }`; a block has a non-empty `reason` and
 * `message` and only the allowed keys. Anything else fails closed in the host.
 */

import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { toInputGateDecision } from "../prompt-protection.js";

const require = createRequire(import.meta.url);
const PLUGIN_DIST = resolve(__dirname, "..", "..", "dist", "index.cjs");

// Synthetic values built at runtime so no literal credential sits in the source.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;
// Checksum-valid synthetic identifiers (TC Kimlik check digits, IBAN mod-97).
const TC_KIMLIK = "10000000146";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";

type Handler = (event: unknown, ctx?: unknown) => Promise<unknown>;

/** Mirrors OpenClaw's isHookDecision() acceptance rules. */
function isHostAcceptedDecision(value: unknown): boolean {
	if (!value || typeof value !== "object") return false;
	const decision = value as Record<string, unknown>;
	const keys = Object.keys(decision);
	if (decision.outcome === "pass") return keys.length === 1;
	if (decision.outcome !== "block") return false;
	const allowed = new Set(["outcome", "reason", "message", "category", "metadata"]);
	return (
		keys.every((key) => allowed.has(key)) &&
		typeof decision.reason === "string" &&
		decision.reason.trim() !== "" &&
		typeof decision.message === "string" &&
		decision.message.trim() !== ""
	);
}

const saved: Record<string, string | undefined> = {};
let home: string;
let aidrDir: string;
const handlers = new Map<string, { handler: Handler; priority?: number }>();

async function writeConfig(overrides: Record<string, unknown> = {}): Promise<void> {
	await writeFile(
		join(aidrDir, "config.json"),
		JSON.stringify({
			mode: "local",
			logging: { enabled: true, path: join(aidrDir, "audit.jsonl") },
			...overrides,
		}),
	);
}

async function auditLog(): Promise<string> {
	const path = join(aidrDir, "audit.jsonl");
	return existsSync(path) ? readFile(path, "utf8") : "";
}

function gate(prompt: unknown, sessionKey = "agent:main:session-1"): Promise<unknown> {
	const entry = handlers.get("before_agent_run");
	if (!entry) throw new Error("before_agent_run was not registered");
	return entry.handler({ prompt, messages: [] }, { sessionKey, trigger: "user" });
}

function promptBuild(event: Record<string, unknown>): Promise<unknown> {
	const entry = handlers.get("before_prompt_build");
	if (!entry) throw new Error("before_prompt_build was not registered");
	return entry.handler({ messages: [], ...event }, { sessionKey: "agent:main:session-1" });
}

beforeAll(async () => {
	for (const key of ["HOME", "USERPROFILE", "XDG_CONFIG_HOME"]) saved[key] = process.env[key];
	home = await mkdtemp(join(tmpdir(), "aidr-openclaw-prompt-"));
	process.env.HOME = home;
	process.env.USERPROFILE = home;
	process.env.XDG_CONFIG_HOME = join(home, ".config");
	aidrDir = join(home, ".singularity-aidr");
	await mkdir(aidrDir, { recursive: true });
	await writeConfig();

	// eslint-disable-next-line @typescript-eslint/no-require-imports
	const plugin = require(PLUGIN_DIST).default;
	plugin.register({
		logger: { debug() {}, info() {}, warn() {}, error() {} },
		on(event: string, handler: Handler, options?: { priority?: number }) {
			handlers.set(event, { handler, priority: options?.priority });
		},
		registerTool() {},
	});
});

beforeEach(async () => {
	await writeConfig();
	await rm(join(aidrDir, "audit.jsonl"), { force: true });
});

afterAll(async () => {
	for (const [key, value] of Object.entries(saved)) {
		if (value === undefined) delete process.env[key];
		else process.env[key] = value;
	}
	await rm(home, { recursive: true, force: true });
});

describe("OpenClaw before_agent_run prompt gate", () => {
	it("registers the gate at high priority", () => {
		expect(handlers.get("before_agent_run")?.priority).toBe(100);
	});

	it("passes a clean prompt with an explicit pass decision", async () => {
		const decision = await gate("refactor the retry loop");
		expect(decision).toEqual({ outcome: "pass" });
		expect(isHostAcceptedDecision(decision)).toBe(true);
		expect(await auditLog()).toBe("");
	});

	it("blocks a secret with a host-accepted block decision that never echoes it", async () => {
		const decision = (await gate(`use ${GITHUB_TOKEN} to push`)) as Record<string, string>;
		expect(isHostAcceptedDecision(decision)).toBe(true);
		expect(decision.outcome).toBe("block");
		expect(decision.reason).toBe("aidr_prompt_protection:findings");
		expect(decision.category).toBe("prompt_protection");
		expect(decision.message).toContain("GitHub token");
		expect(JSON.stringify(decision)).not.toContain(GITHUB_TOKEN);
		const log = await auditLog();
		expect(log).toContain('"tool_name":"before_agent_run"');
		expect(log).not.toContain(GITHUB_TOKEN);
	});

	it("passes personal data under the default warn policy and blocks it under block", async () => {
		expect(await gate(`TCKN ${TC_KIMLIK}`)).toEqual({ outcome: "pass" });
		await writeConfig({ prompt_protection: { secrets: "block", pii: "block" } });
		const decision = (await gate(`IBAN ${IBAN} for the refund`)) as Record<string, string>;
		expect(decision.outcome).toBe("block");
		expect(decision.message).toContain("IBAN");
		expect(decision.message).not.toContain(IBAN);
	});

	it("fails closed on a missing prompt when secrets are blocked", async () => {
		const decision = (await gate(undefined)) as Record<string, string>;
		expect(isHostAcceptedDecision(decision)).toBe(true);
		expect(decision).toMatchObject({
			outcome: "block",
			reason: "aidr_prompt_protection:not_inspected",
		});
	});
});

describe("OpenClaw before_prompt_build prompt notice", () => {
	it("prepends a model notice for personal data and audits it once across both hooks", async () => {
		const prompt = `Müşteri IBAN ${IBAN}, TCKN ${TC_KIMLIK}`;
		const built = (await promptBuild({ prompt, currentUserMessage: prompt })) as {
			prependContext?: string;
		};
		expect(built.prependContext).toContain('source="aidr-prompt-protection"');
		expect(built.prependContext).toContain("Turkish ID number (TC Kimlik)");
		expect(built.prependContext).toContain("Tell the user");
		expect(built.prependContext).not.toContain(IBAN);
		expect(await gate(prompt)).toEqual({ outcome: "pass" });
		const entries = (await auditLog()).trim().split("\n");
		expect(entries).toHaveLength(1);
		expect(entries[0]).toContain("prompt_protection_warning");
	});

	it("inspects currentUserMessage rather than a prompt with reconstructed history", async () => {
		const built = await promptBuild({
			prompt: `earlier turn: IBAN ${IBAN}\ncurrent: hello`,
			currentUserMessage: "hello",
		});
		expect(built).toBeUndefined();
	});

	it("adds nothing for a clean or blocked prompt (the gate owns blocks)", async () => {
		expect(await promptBuild({ prompt: "hello there" })).toBeUndefined();
		expect(await promptBuild({ prompt: `token ${GITHUB_TOKEN}` })).toBeUndefined();
	});
});

describe("InputGateDecision mapping", () => {
	it("emits only host-accepted shapes", () => {
		expect(
			isHostAcceptedDecision(toInputGateDecision({ decision: "allow", reason: "clean" })),
		).toBe(true);
		expect(
			isHostAcceptedDecision(
				toInputGateDecision({
					decision: "warn",
					reason: "findings",
					userMessage: "notice",
					modelContext: "context",
				}),
			),
		).toBe(true);
		expect(
			isHostAcceptedDecision(
				toInputGateDecision({ decision: "block", reason: "deadline", userMessage: "late" }),
			),
		).toBe(true);
	});
});
