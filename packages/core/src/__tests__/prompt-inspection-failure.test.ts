/**
 * Prompt inspection failure policy: an uninspected (oversized, unreadable),
 * failed (detector exception), unverifiable (tenant load failure) or late
 * (deadline) prompt is blocked whenever any rule that would have applied blocks,
 * and when the tenant policy that would have applied is not known.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { detectorPolicyPath } from "../detector-provisioning.js";
import { DlpPolicySchema } from "../dlp/policy.js";
import {
	initialPromptFailureState,
	inspectUserPrompt,
	type PromptInspectionRequest,
	promptFailureBlocks,
} from "../prompt-inspection.js";
import { type Config, ConfigSchema } from "../types.js";

const scanControl = vi.hoisted(() => ({ mode: "real" as "real" | "throw" | "deadline" }));

vi.mock("../prompt-protection.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../prompt-protection.js")>();
	return {
		...actual,
		scanPrompt: (...args: Parameters<typeof actual.scanPrompt>) => {
			if (scanControl.mode === "throw") throw new TypeError("detector exploded");
			if (scanControl.mode === "deadline") throw new actual.PromptScanDeadlineError();
			return actual.scanPrompt(...args);
		},
	};
});

const ALL_WARN = { secrets: "warn", pii: "warn" };
const tenantDlp = {
	tenantId: "tenant-a",
	policy: DlpPolicySchema.parse({
		version: 1,
		tenantId: "tenant-a",
		maxContentBytes: 4_096,
		supportedFormats: ["application/json"],
		unavailableAction: "block",
		labels: [{ id: "p", tenantId: "tenant-a", name: "Codename", sensitivity: "restricted" }],
		rules: [
			{
				id: "codename",
				tenantId: "tenant-a",
				labelId: "p",
				name: "Codename",
				action: "block",
				directions: ["input"],
				matchers: [{ type: "keyword", values: ["BLUEFALCON"], wholeWord: true }],
			},
		],
		exceptions: [],
	}),
};

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
		sessionId: "session-failure",
		prompt: "refactor the parser",
		deadlineAt: Date.now() + 10_000,
		config: config({ prompt_protection: ALL_WARN }),
		loadTenantDlp: async () => undefined,
		...overrides,
	};
}

beforeEach(async () => {
	dir = await mkdtemp(join(tmpdir(), "aidr-prompt-failure-"));
	scanControl.mode = "real";
});

afterEach(async () => {
	scanControl.mode = "real";
	await rm(dir, { recursive: true, force: true });
});

describe("uninspectable prompt (oversized or unreadable input)", () => {
	it("warns only when no rule would have blocked", async () => {
		expect(await inspectUserPrompt(request({ prompt: undefined }))).toMatchObject({
			decision: "warn",
			reason: "not_inspected",
		});
	});

	it.each([
		["pii block", { prompt_protection: { ...ALL_WARN, pii: "block" } }],
		["jailbreak block", { prompt_protection: { ...ALL_WARN, jailbreak: "block" } }],
		[
			"content-safety category set to block",
			{ prompt_protection: { ...ALL_WARN, content_safety: { malware: "block" } } },
		],
	])("blocks with %s and secrets warn", async (_name, overrides) => {
		expect(
			await inspectUserPrompt(request({ prompt: undefined, config: config(overrides) })),
		).toMatchObject({ decision: "block", reason: "not_inspected" });
	});

	it("loads the tenant DLP policy before deciding, and blocks when it applies", async () => {
		const loadTenantDlp = vi.fn(async () => tenantDlp);
		expect(await inspectUserPrompt(request({ prompt: undefined, loadTenantDlp }))).toMatchObject({
			decision: "block",
			reason: "not_inspected",
		});
		expect(loadTenantDlp).toHaveBeenCalledOnce();
	});

	it("blocks when the tenant prompt-safety floor blocks", async () => {
		const outcome = await inspectUserPrompt(
			request({
				prompt: undefined,
				loadTenantPromptSafety: async () => ({ content_safety: { self_harm: "block" } }),
			}),
		);
		expect(outcome).toMatchObject({ decision: "block", reason: "not_inspected" });
	});

	it("blocks as unverified when the tenant policy fails to load", async () => {
		const outcome = await inspectUserPrompt(
			request({
				prompt: undefined,
				loadTenantDlp: async () => {
					throw new Error("bad signature");
				},
			}),
		);
		expect(outcome).toMatchObject({ decision: "block", reason: "tenant_policy_unverified" });
	});
});

describe("detector exception", () => {
	it("warns only when no rule would have blocked", async () => {
		scanControl.mode = "throw";
		expect(await inspectUserPrompt(request())).toMatchObject({
			decision: "warn",
			reason: "not_inspected",
		});
	});

	it("blocks when personal data is in block mode, even with secrets warn", async () => {
		scanControl.mode = "throw";
		const outcome = await inspectUserPrompt(
			request({ config: config({ prompt_protection: { secrets: "warn", pii: "block" } }) }),
		);
		expect(outcome).toMatchObject({ decision: "block", reason: "not_inspected" });
	});

	it("blocks when a tenant DLP policy applies", async () => {
		scanControl.mode = "throw";
		const outcome = await inspectUserPrompt(request({ loadTenantDlp: async () => tenantDlp }));
		expect(outcome).toMatchObject({ decision: "block", reason: "not_inspected" });
	});
});

describe("deadline", () => {
	it("blocks a scan that runs out of time when personal data is in block mode", async () => {
		scanControl.mode = "deadline";
		const outcome = await inspectUserPrompt(
			request({ config: config({ prompt_protection: { secrets: "warn", pii: "block" } }) }),
		);
		expect(outcome).toMatchObject({ decision: "block", reason: "deadline" });
		scanControl.mode = "deadline";
		expect(await inspectUserPrompt(request())).toMatchObject({
			decision: "warn",
			reason: "deadline",
		});
	});

	it("blocks a scan that runs out of time under a blocking tenant prompt-safety floor", async () => {
		scanControl.mode = "deadline";
		const outcome = await inspectUserPrompt(
			request({ loadTenantPromptSafety: async () => ({ jailbreak: "block" }) }),
		);
		expect(outcome).toMatchObject({ decision: "block", reason: "deadline" });
	});

	it("blocks when a configured tenant policy has not loaded by the deadline", async () => {
		const stalled = () => new Promise<undefined>(() => {});
		const managed = await inspectUserPrompt(
			request({
				deadlineAt: Date.now() + 50,
				loadTenantDlp: stalled,
				config: config({ mode: "managed", prompt_protection: ALL_WARN }),
			}),
		);
		expect(managed).toMatchObject({ decision: "block", reason: "deadline" });

		// An installed detector policy file makes the tenant policy configured in local mode too.
		const policyFile = detectorPolicyPath("cursor");
		await mkdir(dirname(policyFile), { recursive: true });
		await writeFile(policyFile, "{}");
		try {
			const provisioned = await inspectUserPrompt(
				request({ deadlineAt: Date.now() + 50, loadTenantDlp: stalled }),
			);
			expect(provisioned).toMatchObject({ decision: "block", reason: "deadline" });
		} finally {
			await rm(policyFile, { force: true });
		}

		// Nothing configured: an unloaded tenant policy is absent, so the warn mode stands.
		const unconfigured = await inspectUserPrompt(
			request({ deadlineAt: Date.now() + 50, loadTenantDlp: stalled }),
		);
		expect(unconfigured).toMatchObject({ decision: "warn", reason: "deadline" });
	});
});

describe("promptFailureBlocks", () => {
	it("starts fail-closed and blocks on a malformed state", () => {
		expect(promptFailureBlocks(initialPromptFailureState())).toBe(true);
		const malformed = {
			...initialPromptFailureState(),
			tenantPolicyLoaded: true,
			policy: { secrets: "warn", pii: "warn" },
			get tenantPromptSafety(): never {
				throw new Error("broken");
			},
		} as never;
		expect(promptFailureBlocks(malformed)).toBe(true);
	});
});
