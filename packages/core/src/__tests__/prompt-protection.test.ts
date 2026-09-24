import { describe, expect, it } from "vitest";
import { DlpPolicySchema } from "../dlp/policy.js";
import {
	DEFAULT_PROMPT_PROTECTION,
	PromptScanDeadlineError,
	scanPrompt,
} from "../prompt-protection.js";
import { ConfigSchema } from "../types.js";

// Synthetic values built at runtime so no literal credential sits in the source.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLE12";
const PRIVATE_KEY_HEADERS = [
	"-----BEGIN PRIVATE KEY-----",
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN OPENSSH PRIVATE KEY-----",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
	"-----BEGIN PGP PRIVATE KEY BLOCK-----",
];

function tenantPolicy(action: "block" | "redact" | "ask") {
	return DlpPolicySchema.parse({
		version: 1,
		tenantId: "tenant-a",
		maxContentBytes: 4_096,
		supportedFormats: ["application/json"],
		unavailableAction: "block",
		labels: [
			{ id: "project", tenantId: "tenant-a", name: "Project codename", sensitivity: "restricted" },
		],
		rules: [
			{
				id: "codename",
				tenantId: "tenant-a",
				labelId: "project",
				name: "Codename",
				action,
				directions: ["input"],
				matchers: [{ type: "keyword", values: ["BLUEFALCON"], wholeWord: true }],
			},
		],
		exceptions: [],
	});
}

describe("scanPrompt", () => {
	it("defaults to block secrets and warn on PII, matching the config schema", () => {
		expect(DEFAULT_PROMPT_PROTECTION).toEqual({ secrets: "block", pii: "warn" });
		expect(ConfigSchema.parse({}).prompt_protection).toEqual({ secrets: "block", pii: "warn" });
	});

	it("blocks a token without echoing it", () => {
		const result = scanPrompt(`please use ${GITHUB_TOKEN} for the API`);
		expect(result.decision).toBe("block");
		expect(result.findings).toEqual([{ category: "secret", kind: "GitHub token", count: 1 }]);
		expect(result.userMessage).toContain("GitHub token");
		expect(JSON.stringify(result)).not.toContain(GITHUB_TOKEN);
	});

	it.each(PRIVATE_KEY_HEADERS)("blocks a private key (%s)", (header) => {
		const result = scanPrompt(`here is the key:\n${header}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n`);
		expect(result.decision).toBe("block");
		expect(result.findings.map((finding) => finding.kind)).toContain("private key");
		expect(JSON.stringify(result)).not.toContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC");
	});

	it("blocks a keyed AWS secret and a bare random-looking one", () => {
		expect(scanPrompt(`aws_secret_access_key=${AWS_SECRET}`).decision).toBe("block");
		expect(scanPrompt(`the value is ${AWS_SECRET} ok`).decision).toBe("block");
	});

	it("does not treat long paths, hashes or plain numbers as secrets or PII", () => {
		for (const prompt of [
			"please edit /home/user/projects/something/abcdefg/hijklmnop.ts now",
			"fix packages/core/src/__tests__/detector-provisioning-fixtures.ts please",
			"compare commit 3f786850e387550fdab836ed7e6dc881de23001b with main",
			"run the build with timeout 1234567890 and port 8080",
			"order id 123456789 failed",
		]) {
			expect(scanPrompt(prompt), prompt).toEqual({ decision: "allow", findings: [] });
		}
	});

	it("warns on PII with a model notice that does not repeat the value", () => {
		const result = scanPrompt("email jane.doe@example.com or call (202) 555-0100 about it");
		expect(result.decision).toBe("warn");
		expect(result.findings).toEqual([
			{ category: "pii", kind: "email address", count: 1 },
			{ category: "pii", kind: "phone number", count: 1 },
		]);
		expect(result.modelContext).toContain("email address");
		expect(result.userMessage).toContain("It was sent to the model");
		expect(JSON.stringify(result)).not.toContain("jane.doe@example.com");
		expect(JSON.stringify(result)).not.toContain("555-0100");
	});

	it("detects Luhn-valid card numbers and formatted SSNs, not random digit runs", () => {
		expect(scanPrompt("card 4111 1111 1111 1111").findings).toEqual([
			{ category: "pii", kind: "payment card number", count: 1 },
		]);
		expect(scanPrompt("card 4111 1111 1111 1112").decision).toBe("allow");
		expect(scanPrompt("ssn 123-45-6789").findings).toEqual([
			{ category: "pii", kind: "social security number", count: 1 },
		]);
	});

	it("honours per-category modes", () => {
		const prompt = `token ${GITHUB_TOKEN} and jane.doe@example.com`;
		expect(scanPrompt(prompt, { secrets: "off", pii: "off" })).toEqual({
			decision: "allow",
			findings: [],
		});
		expect(scanPrompt(prompt, { secrets: "warn", pii: "off" }).decision).toBe("warn");
		const blocked = scanPrompt(prompt, { secrets: "off", pii: "block" });
		expect(blocked.decision).toBe("block");
		expect(blocked.findings).toEqual([{ category: "pii", kind: "email address", count: 1 }]);
		// A blocking secret ends the scan: the PII warning is not collected.
		const both = scanPrompt(prompt, DEFAULT_PROMPT_PROTECTION);
		expect(both.decision).toBe("block");
		expect(both.partial).toBe(true);
		expect(both.findings.map((finding) => finding.category)).toEqual(["secret"]);
		const warned = scanPrompt(prompt, { secrets: "warn", pii: "warn" });
		expect(warned.findings.map((finding) => finding.category)).toEqual(["secret", "pii"]);
		expect(warned.partial).toBeUndefined();
	});

	it("counts a value matched by several detectors once, and every separate value", () => {
		// Each token is matched by both the secret detector and the legacy credential patterns.
		const prompt = `a ${GITHUB_TOKEN} b ${GITHUB_TOKEN} c ${GITHUB_TOKEN} and ${AWS_SECRET} ok`;
		expect(scanPrompt(prompt, { secrets: "warn", pii: "off" }).findings).toEqual([
			{ category: "secret", kind: "AWS secret key", count: 1 },
			{ category: "secret", kind: "GitHub token", count: 3 },
		]);
	});

	it("stops a blocking scan at the first secret and marks the counts partial", () => {
		const prompt = `${GITHUB_TOKEN} `.repeat(50) + "jane.doe@example.com";
		const blocked = scanPrompt(prompt);
		expect(blocked).toMatchObject({ decision: "block", partial: true });
		expect(blocked.findings).toEqual([{ category: "secret", kind: "GitHub token", count: 1 }]);
		expect(scanPrompt(prompt, { secrets: "warn", pii: "warn" }).findings).toEqual([
			{ category: "secret", kind: "GitHub token", count: 50 },
			{ category: "pii", kind: "email address", count: 1 },
		]);
	});

	it("skips the tenant policy once the local policy has blocked", () => {
		const result = scanPrompt(
			"ship BLUEFALCON to jane.doe@example.com",
			{ secrets: "off", pii: "block" },
			{ tenantId: "tenant-a", policy: tenantPolicy("block") },
		);
		expect(result).toMatchObject({ decision: "block", partial: true });
		expect(result.findings).toEqual([{ category: "pii", kind: "email address", count: 1 }]);
	});

	it("throws PromptScanDeadlineError once the deadline has passed", () => {
		expect(() =>
			scanPrompt("hello", DEFAULT_PROMPT_PROTECTION, undefined, { deadlineAt: 0 }),
		).toThrow(PromptScanDeadlineError);
		expect(
			scanPrompt("hello", DEFAULT_PROMPT_PROTECTION, undefined, {
				deadlineAt: Date.now() + 60_000,
			}),
		).toEqual({ decision: "allow", findings: [] });
	});

	it("applies a tenant DLP policy regardless of local modes and blocks every non-allow action", () => {
		for (const action of ["block", "redact", "ask"] as const) {
			const result = scanPrompt(
				"ship BLUEFALCON on friday",
				{ secrets: "off", pii: "off" },
				{ tenantId: "tenant-a", policy: tenantPolicy(action) },
			);
			expect(result.decision, action).toBe("block");
			expect(result.findings[0]).toMatchObject({ category: "tenant_dlp", count: 1 });
			expect(result.userMessage).toContain("Project codename");
			expect(JSON.stringify(result)).not.toContain("BLUEFALCON");
		}
		expect(
			scanPrompt("nothing restricted", DEFAULT_PROMPT_PROTECTION, {
				tenantId: "tenant-a",
				policy: tenantPolicy("block"),
			}).decision,
		).toBe("allow");
	});

	it("blocks when the tenant policy cannot inspect the prompt", () => {
		const policy = DlpPolicySchema.parse({ ...tenantPolicy("block"), maxContentBytes: 16 });
		const result = scanPrompt("a prompt longer than sixteen bytes", DEFAULT_PROMPT_PROTECTION, {
			tenantId: "tenant-a",
			policy,
		});
		expect(result.decision).toBe("block");
		expect(result.findings[0]?.category).toBe("tenant_dlp");
	});
});

/**
 * Regression for a fail-open: Claude Code kills the prompt hook after 10 s and
 * then sends the prompt. Overlap checks used to be quadratic (a 1.47 MB prompt
 * of 88k emails plus one token took ~30 s) and several patterns rescanned long
 * runs from every word boundary. Each prompt here is ~1.5 MB of adversarial
 * text; the full (non-short-circuited) scan must finish well inside the budget.
 */
describe("scanPrompt cost on large adversarial prompts", () => {
	const MAX_SCAN_MS = 2_000;
	const TARGET_CHARS = 1_500_000;
	const fill = (unit: string): string => unit.repeat(Math.ceil(TARGET_CHARS / unit.length));
	const emails = (count: number): string =>
		Array.from({ length: count }, (_, i) => `u${i}@c${i}.io `).join("");
	const adversarial: Record<string, () => string> = {
		"emails then a token": () => `${emails(110_000)} my token ${GITHUB_TOKEN}`,
		"a token then emails": () => `my token ${GITHUB_TOKEN} ${emails(110_000)}`,
		"dotted local part": () => fill("a."),
		"dotted domain": () => `x@${fill("a.")}`,
		"percent-encoded run": () => fill("%41"),
		"dash-joined JWT prefixes": () => fill("eyJ-"),
		"many tokens": () => fill(`${GITHUB_TOKEN} `),
		"dash-separated digits": () => fill("123-"),
		"spaced digits": () => fill("1 "),
		"base64 run": () => fill("QUJD"),
	};

	function bestOfThree(run: () => void): number {
		let best = Number.POSITIVE_INFINITY;
		for (let attempt = 0; attempt < 3; attempt++) {
			const started = performance.now();
			run();
			best = Math.min(best, performance.now() - started);
		}
		return best;
	}

	it.each(Object.keys(adversarial))(
		"scans %s in under 2 s",
		(name) => {
			const prompt = adversarial[name]?.() ?? "";
			expect(prompt.length).toBeGreaterThanOrEqual(TARGET_CHARS);
			const fullScan = { secrets: "warn", pii: "warn" } as const;
			expect(bestOfThree(() => scanPrompt(prompt, fullScan))).toBeLessThan(MAX_SCAN_MS);
			expect(bestOfThree(() => scanPrompt(prompt))).toBeLessThan(MAX_SCAN_MS);
		},
		60_000,
	);

	it("still reports every email and the token in the original repro prompt", () => {
		const prompt = `${emails(88_000)} my token ${GITHUB_TOKEN}`;
		expect(scanPrompt(prompt, { secrets: "warn", pii: "warn" }).findings).toEqual([
			{ category: "secret", kind: "GitHub token", count: 1 },
			{ category: "pii", kind: "email address", count: 88_000 },
		]);
		expect(scanPrompt(prompt)).toMatchObject({
			decision: "block",
			findings: [{ category: "secret", kind: "GitHub token", count: 1 }],
		});
	}, 60_000);
});
