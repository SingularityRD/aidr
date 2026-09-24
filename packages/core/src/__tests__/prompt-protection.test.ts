import { describe, expect, it, vi } from "vitest";
import { DlpPolicySchema } from "../dlp/policy.js";
import { PRIVACY_DETECTOR_MAX_CHARS, scanPrivacyDetectors } from "../dlp/privacy-detectors.js";
import {
	DEFAULT_PROMPT_PROTECTION,
	PromptScanDeadlineError,
	scanPrompt,
} from "../prompt-protection.js";
import { ConfigSchema } from "../types.js";

// Synthetic values built at runtime so no literal credential sits in the source.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5".repeat(4)}`;
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLE12";
// Checksum-valid synthetic identifiers (TC Kimlik check digits, IBAN mod-97).
const TC_KIMLIK = "10000000146";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";
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

	it("warns on Turkish ID numbers, IBANs and TR phone numbers without echoing them", () => {
		const result = scanPrompt(
			`TC kimlik ${TC_KIMLIK}, IBAN ${IBAN}, cep 0532 123 45 67 adresine yaz`,
		);
		expect(result.decision).toBe("warn");
		expect(result.findings).toEqual([
			{ category: "pii", kind: "Turkish ID number (TC Kimlik)", count: 1 },
			{ category: "pii", kind: "IBAN", count: 1 },
			{ category: "pii", kind: "phone number", count: 1 },
		]);
		expect(result.incomplete).toBeUndefined();
		const serialized = JSON.stringify(result);
		for (const value of [TC_KIMLIK, IBAN, "0532 123 45 67", "TR33"]) {
			expect(serialized).not.toContain(value);
		}
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
 * The AIDR Privacy rules (TC Kimlik, IBAN, TR phones) report `incomplete` for
 * input over 1 MiB and for an unterminated quoted label value, with no findings
 * at all. The prompt scan must neither lose those detections nor treat an
 * incomplete inspection as clean.
 */
describe("scanPrompt personal-data inspection coverage", () => {
	/** An invalid percent-escape: the rules cannot decode it, so they skip the text. */
	const UNDECODABLE = "discount 100%ff on everything";
	/** Plain text with digits, so every window goes through the privacy rules. */
	const filler = (chars: number): string =>
		"lorem ipsum 7 ".repeat(Math.ceil(chars / 14)).slice(0, chars);

	it("finds a TC Kimlik in the tail of a prompt over 1 MiB", () => {
		const prompt = `${filler(1_200_000)} kimlik ${TC_KIMLIK} son`;
		expect(prompt.length).toBeGreaterThan(PRIVACY_DETECTOR_MAX_CHARS);
		// The rules alone give up on the whole prompt.
		expect(scanPrivacyDetectors(prompt, ["tc_kimlik"])).toMatchObject({
			matches: [],
			incomplete: true,
			reasons: ["INPUT_LIMIT"],
		});
		const result = scanPrompt(prompt);
		expect(result.decision).toBe("warn");
		expect(result.findings).toEqual([
			{ category: "pii", kind: "Turkish ID number (TC Kimlik)", count: 1 },
		]);
		expect(result.incomplete).toBeUndefined();
		expect(scanPrompt(prompt, { secrets: "block", pii: "block" }).decision).toBe("block");
	});

	it("checks the scan deadline before every privacy window", () => {
		const prompt = `${filler(1_200_000)} ${TC_KIMLIK}`;
		const windows = Math.ceil(prompt.length / (60 * 1024));
		let now = 0;
		const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
		try {
			scanPrompt(prompt, DEFAULT_PROMPT_PROTECTION, undefined, { deadlineAt: 1 });
			expect(clock.mock.calls.length).toBeGreaterThanOrEqual(windows);
			// Time runs out part-way through the windows: the scan throws, never returns.
			clock.mockClear();
			clock.mockImplementation(() => (clock.mock.calls.length > windows / 2 ? 2 : 0));
			expect(() =>
				scanPrompt(prompt, DEFAULT_PROMPT_PROTECTION, undefined, { deadlineAt: 1 }),
			).toThrow(PromptScanDeadlineError);
		} finally {
			clock.mockRestore();
		}
	});

	it("counts every value once across window boundaries, including one straddling a boundary", () => {
		const repeated = `${TC_KIMLIK} `.repeat(20_000);
		expect(scanPrompt(repeated).findings).toEqual([
			{ category: "pii", kind: "Turkish ID number (TC Kimlik)", count: 20_000 },
		]);
		for (const offset of [2, 5, 2_048, 4_094]) {
			const prompt = `${filler(64 * 1024 - offset)} ${IBAN} ${filler(10_000)}`;
			expect(scanPrompt(prompt).findings, String(offset)).toEqual([
				{ category: "pii", kind: "IBAN", count: 1 },
			]);
		}
	});

	it("finds an IBAN after an unterminated quoted label value", () => {
		const prompt = `name: "Ayşe Yılmaz, IBAN ${IBAN} hesabına gönder`;
		// The rules alone stop at the unterminated field.
		expect(scanPrivacyDetectors(prompt, ["iban"])).toMatchObject({
			matches: [],
			incomplete: true,
			reasons: ["INCOMPLETE_FIELD"],
		});
		const result = scanPrompt(prompt, { secrets: "block", pii: "block" });
		expect(result).toMatchObject({
			decision: "block",
			findings: [{ category: "pii", kind: "IBAN", count: 1 }],
		});
		expect(result.incomplete).toBeUndefined();
		expect(result.userMessage).toContain("IBAN");
		expect(JSON.stringify(result)).not.toContain("TR33");
	});

	it("finds Turkish PII after an unterminated quoted credential or key block", () => {
		for (const prefix of ['password: "abc', "-----BEGIN PRIVATE KEY-----\nabc"]) {
			const result = scanPrompt(`${prefix} ${TC_KIMLIK} ve 0532 123 45 67`, {
				secrets: "off",
				pii: "warn",
			});
			expect(result.findings, prefix).toEqual([
				{ category: "pii", kind: "Turkish ID number (TC Kimlik)", count: 1 },
				{ category: "pii", kind: "phone number", count: 1 },
			]);
			expect(result.incomplete, prefix).toBeUndefined();
		}
	});

	it("sends an incompletely inspected prompt under warn with a notice for the user and the model", () => {
		const result = scanPrompt(UNDECODABLE);
		expect(result).toMatchObject({
			decision: "warn",
			findings: [],
			incomplete: { category: "pii", reasons: ["INVALID_ENCODING"] },
		});
		expect(result.userMessage).toContain("could not inspect the whole prompt");
		expect(result.userMessage).toContain("It was sent to the model");
		expect(result.modelContext).toContain("could not fully inspect");
		expect(result.modelContext).toContain("Do not repeat personal data");

		const withFinding = scanPrompt(`mail jane.doe@example.com ${UNDECODABLE}`);
		expect(withFinding).toMatchObject({
			decision: "warn",
			findings: [{ category: "pii", kind: "email address", count: 1 }],
			incomplete: { category: "pii" },
		});
		expect(withFinding.modelContext).toContain("email address");
		expect(withFinding.modelContext).toContain("could not fully inspect");
		expect(JSON.stringify(withFinding)).not.toContain("jane.doe@example.com");
	});

	it("blocks an incompletely inspected prompt under a block PII policy", () => {
		const result = scanPrompt(UNDECODABLE, { secrets: "block", pii: "block" });
		expect(result).toMatchObject({
			decision: "block",
			findings: [],
			incomplete: { category: "pii", reasons: ["INVALID_ENCODING"] },
		});
		expect(result.userMessage).toContain("could not fully inspect it for personal data");
		expect(result.modelContext).toBeUndefined();

		// Secret warnings are kept alongside the incomplete-inspection block.
		const withSecret = scanPrompt(`${GITHUB_TOKEN} ${UNDECODABLE}`, {
			secrets: "warn",
			pii: "block",
		});
		expect(withSecret).toMatchObject({
			decision: "block",
			findings: [{ category: "secret", kind: "GitHub token", count: 1 }],
			incomplete: { category: "pii" },
		});

		// A tenant policy is not consulted once the prompt is blocked.
		expect(
			scanPrompt(
				`BLUEFALCON ${UNDECODABLE}`,
				{ secrets: "off", pii: "block" },
				{ tenantId: "tenant-a", policy: tenantPolicy("block") },
			),
		).toMatchObject({ decision: "block", partial: true, findings: [] });
	});

	it("leaves secret detection and an off PII policy unaffected", () => {
		const blocked = scanPrompt(`${GITHUB_TOKEN} ${UNDECODABLE}`);
		expect(blocked).toMatchObject({
			decision: "block",
			findings: [{ category: "secret", kind: "GitHub token", count: 1 }],
		});
		expect(blocked.incomplete).toBeUndefined();
		expect(scanPrompt(UNDECODABLE, { secrets: "block", pii: "off" })).toEqual({
			decision: "allow",
			findings: [],
		});
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
		// Digits keep the privacy rules from skipping the text.
		"Turkish text": () => fill("Çağrı İşığı 42 öğüş "),
		"labelled Turkish IDs": () => fill(`tc: ${TC_KIMLIK} tel: 0532 123 45 67 `),
		"unterminated quoted labels": () => fill('ad: "Ayşe 7 '),
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
