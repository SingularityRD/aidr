import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DlpPolicySchema } from "../dlp/policy.js";
import {
	inspectUserPrompt,
	type PromptInspectionRequest,
	resolvePromptInspectionDeadlineMs,
	uninspectedPromptOutcome,
} from "../prompt-inspection.js";
import { type Config, ConfigSchema } from "../types.js";

// Synthetic values built at runtime so no literal credential sits in the source.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;
// Checksum-valid synthetic identifiers (TC Kimlik check digits, IBAN mod-97).
const TC_KIMLIK = "10000000146";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";

let dir: string;

function config(overrides: Record<string, unknown> = {}): Config {
	return ConfigSchema.parse({
		mode: "local",
		logging: { enabled: true, path: join(dir, "audit.jsonl") },
		...overrides,
	});
}

function request(overrides: Partial<PromptInspectionRequest> = {}): PromptInspectionRequest {
	return {
		runtime: "cursor",
		hookEvent: "beforeSubmitPrompt",
		sessionId: "session-1",
		prompt: "refactor the parser",
		deadlineAt: Date.now() + 10_000,
		config: config(),
		loadTenantDlp: async () => undefined,
		...overrides,
	};
}

async function audit(): Promise<string> {
	try {
		return await readFile(join(dir, "audit.jsonl"), "utf8");
	} catch {
		return "";
	}
}

beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "aidr-prompt-inspection-"));
});

afterEach(async () => {
	await rm(dir, { recursive: true, force: true });
});

describe("inspectUserPrompt", () => {
	it("allows a clean prompt and writes no audit entry", async () => {
		expect(await inspectUserPrompt(request())).toEqual({ decision: "allow", reason: "clean" });
		expect(await audit()).toBe("");
	});

	it("blocks a secret by default and audits kinds without the value", async () => {
		const outcome = await inspectUserPrompt(request({ prompt: `use ${GITHUB_TOKEN} now` }));
		expect(outcome.decision).toBe("block");
		expect(outcome.reason).toBe("findings");
		expect(outcome.userMessage).toContain("GitHub token");
		expect(outcome.userMessage).not.toContain(GITHUB_TOKEN);
		const log = await audit();
		expect(log).toContain('"tool_name":"beforeSubmitPrompt"');
		expect(log).toContain("GitHub token x1");
		expect(log).not.toContain(GITHUB_TOKEN);
	});

	it("warns on Turkish ID numbers and IBANs with a model notice", async () => {
		const outcome = await inspectUserPrompt(
			request({ prompt: `Müşteri TCKN ${TC_KIMLIK}, IBAN ${IBAN}` }),
		);
		expect(outcome.decision).toBe("warn");
		if (outcome.decision !== "warn") return;
		expect(outcome.userMessage).toContain("Turkish ID number (TC Kimlik)");
		expect(outcome.userMessage).toContain("IBAN");
		expect(outcome.modelContext).toContain("Do not repeat it");
		expect(`${outcome.userMessage}${outcome.modelContext}`).not.toContain(TC_KIMLIK);
		expect(await audit()).toContain("prompt_protection_warning");
	});

	it("honours prompt_protection modes from config", async () => {
		const blockPii = await inspectUserPrompt(
			request({
				prompt: `IBAN ${IBAN}`,
				config: config({ prompt_protection: { secrets: "block", pii: "block" } }),
			}),
		);
		expect(blockPii.decision).toBe("block");
		const off = await inspectUserPrompt(
			request({
				prompt: `use ${GITHUB_TOKEN}`,
				config: config({ prompt_protection: { secrets: "off", pii: "off" } }),
			}),
		);
		expect(off).toEqual({ decision: "allow", reason: "clean" });
	});

	it("fails closed on an uninspectable prompt when secrets are blocked, visibly otherwise", async () => {
		const blocked = await inspectUserPrompt(request({ prompt: undefined }));
		expect(blocked).toMatchObject({ decision: "block", reason: "not_inspected" });
		expect(await audit()).toContain("prompt not inspected (not_inspected)");

		const warned = await inspectUserPrompt(
			request({
				prompt: 42,
				config: config({ prompt_protection: { secrets: "warn", pii: "warn" } }),
			}),
		);
		expect(warned).toMatchObject({ decision: "warn", reason: "not_inspected" });
		expect(uninspectedPromptOutcome("off").decision).toBe("warn");
	});

	it("blocks when the tenant DLP policy cannot be loaded, even with local protection off", async () => {
		const outcome = await inspectUserPrompt(
			request({
				config: config({ prompt_protection: { secrets: "off", pii: "off" } }),
				loadTenantDlp: async () => {
					throw new Error("bad signature");
				},
			}),
		);
		expect(outcome).toMatchObject({ decision: "block", reason: "tenant_policy_unverified" });
		expect(outcome.decision === "block" && outcome.userMessage).not.toContain("bad signature");
	});

	it("applies a provisioned tenant DLP policy to the prompt", async () => {
		const policy = DlpPolicySchema.parse({
			version: 1,
			tenantId: "tenant-a",
			maxContentBytes: 4_096,
			supportedFormats: ["application/json"],
			unavailableAction: "block",
			labels: [
				{ id: "p", tenantId: "tenant-a", name: "Project codename", sensitivity: "restricted" },
			],
			rules: [
				{
					id: "codename",
					tenantId: "tenant-a",
					labelId: "p",
					name: "Codename",
					action: "redact",
					directions: ["input"],
					matchers: [{ type: "keyword", values: ["BLUEFALCON"], wholeWord: true }],
				},
			],
			exceptions: [],
		});
		const outcome = await inspectUserPrompt(
			request({
				prompt: "ship BLUEFALCON today",
				loadTenantDlp: async () => ({ tenantId: "tenant-a", policy }),
			}),
		);
		expect(outcome.decision).toBe("block");
		expect(outcome.decision === "block" && outcome.userMessage).toContain("Project codename");
	});

	it("answers at the deadline when loading stalls: block by default, warn when secrets are not blocked", async () => {
		const stalled = () => new Promise<undefined>(() => {});
		const started = Date.now();
		const blocked = await inspectUserPrompt(
			request({ deadlineAt: Date.now() + 50, loadTenantDlp: stalled }),
		);
		expect(blocked).toMatchObject({ decision: "block", reason: "deadline" });
		expect(Date.now() - started).toBeLessThan(5_000);

		const warned = await inspectUserPrompt(
			request({
				deadlineAt: Date.now() + 50,
				loadTenantDlp: stalled,
				config: config({ prompt_protection: { secrets: "warn", pii: "warn" } }),
			}),
		);
		expect(warned).toMatchObject({ decision: "warn", reason: "deadline" });
	});

	it("blocks an expired deadline even when the scan itself would pass", async () => {
		const outcome = await inspectUserPrompt(request({ deadlineAt: Date.now() - 1 }));
		expect(outcome).toMatchObject({ decision: "block", reason: "deadline" });
	});
});

describe("resolvePromptInspectionDeadlineMs", () => {
	it("accepts integers within range and falls back otherwise", () => {
		const env = (value?: string) => ({ AIDR_PROMPT_INSPECTION_DEADLINE_MS: value });
		expect(resolvePromptInspectionDeadlineMs(env(), 7_000, 9_000)).toBe(7_000);
		expect(resolvePromptInspectionDeadlineMs(env("500"), 7_000, 9_000)).toBe(500);
		expect(resolvePromptInspectionDeadlineMs(env("9001"), 7_000, 9_000)).toBe(7_000);
		expect(resolvePromptInspectionDeadlineMs(env("99"), 7_000, 9_000)).toBe(7_000);
		expect(resolvePromptInspectionDeadlineMs(env("1e3"), 7_000, 9_000)).toBe(7_000);
	});
});
