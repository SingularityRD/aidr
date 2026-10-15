/**
 * T38: tenant-defined DLP labels. A tenant admin authors labels plus rules
 * (keyword/dictionary terms, bounded regexes with an optional fixed checksum
 * validator), the server validates them with this schema, the signed tenant
 * bundle carries them, and the engine reports matches with the label id and
 * the configured action. All values below are synthetic test data.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	DLP_MAX_POLICY_KEYWORD_TERMS,
	DLP_MAX_POLICY_REGEX_MATCHERS,
	DlpPolicySchema,
	regexRiskIssue,
	scanDlpInput,
	scanDlpOutput,
} from "../../dlp/index.js";
import { scanProvisionedOutput } from "../../provisioned-output-scanner.js";
import {
	detectorPolicyPayload,
	provisionTenantDetectorPolicy,
} from "../detector-provisioning-fixtures.js";
import { makeTmpDir } from "../test-utils.js";

const TENANT = "tenant-a";
const PROJECT_CODE = "PRJ-ACME-123456";

// biome-ignore lint/suspicious/noExplicitAny: test fixtures are mutated freely to build invalid policies
type Row = Record<string, any>;

function customPolicy(action: "redact" | "block" | "ask" = "block"): Row {
	return {
		version: 1,
		tenantId: TENANT,
		supportedFormats: ["text/*", "application/json"],
		unavailableAction: "block",
		labels: [
			{
				id: "acme-project-code",
				tenantId: TENANT,
				name: "ACME project code",
				description: "Synthetic internal project identifier",
				sensitivity: "restricted",
				redactionToken: "[PROJECT-CODE]",
			},
			{
				id: "acme-card",
				tenantId: TENANT,
				name: "Card number (Luhn-checked)",
				sensitivity: "confidential",
			},
		],
		rules: [
			{
				id: "acme-project-code-rule",
				tenantId: TENANT,
				labelId: "acme-project-code",
				name: "Project code",
				action,
				directions: ["input", "output"],
				matchMode: "any",
				matchers: [
					{ type: "regex", pattern: "\\bPRJ-[A-Z]{2,8}-[0-9]{6}\\b", flags: "" },
					{ type: "keyword", values: ["Project Nightjar"], caseSensitive: false, wholeWord: true },
				],
			},
			{
				id: "acme-card-rule",
				tenantId: TENANT,
				labelId: "acme-card",
				name: "Card number",
				action: "redact",
				directions: ["input"],
				matchers: [
					{
						type: "regex",
						pattern: "\\b[0-9]{4} ?[0-9]{4} ?[0-9]{4} ?[0-9]{4}\\b",
						flags: "",
						validator: "luhn",
					},
				],
			},
		],
		exceptions: [],
	};
}

function issuesOf(policy: unknown): string[] {
	const parsed = DlpPolicySchema.safeParse(policy);
	return parsed.success ? [] : parsed.error.issues.map((issue) => issue.message);
}

describe("tenant custom label schema", () => {
	it("accepts tenant labels with regex, dictionary and checksum-validated detectors", () => {
		const parsed = DlpPolicySchema.parse(customPolicy());
		expect(parsed.labels.map((label) => label.id)).toEqual(["acme-project-code", "acme-card"]);
		expect(parsed.rules[1]?.matchers[0]).toMatchObject({ type: "regex", validator: "luhn" });
	});

	it.each([
		["nested group quantifier", "((a+))+"],
		["quantified alternation", "(a|aa)+"],
		["star height two", "(\\w+\\s?)*x"],
		["bounded nesting", "(?:a{1,100}){1,100}"],
		["oversized repeat", "x{1,5000}"],
		["too many unbounded quantifiers", "a+b+c+d+e+"],
		["named back-reference", "(?<x>a)\\k<x>"],
		["numbered back-reference", "(a)\\1"],
	])("rejects a ReDoS-prone pattern: %s", (_name, pattern) => {
		const policy = customPolicy();
		policy.rules[0].matchers = [{ type: "regex", pattern, flags: "" }];
		expect(issuesOf(policy)).toContain("pattern contains a high-risk regular-expression construct");
	});

	it("keeps ordinary bounded identifiers accepted", () => {
		for (const pattern of [
			"\\bPRJ-[A-Z]{2,8}-[0-9]{6}\\b",
			"EMP-[0-9]{6}",
			"secret-[0-9]+",
			"(?:INV|PO)-[0-9]{4,10}",
			"(?:[0-9]{4}-){3}[0-9]{4}",
			"[A-Z]{2}[0-9]{2}(?:[A-Z0-9]{4}){3,7}",
		]) {
			expect(regexRiskIssue(pattern)).toBeUndefined();
		}
	});

	it("rejects oversized patterns, unknown validators, duplicate label ids and unknown fields", () => {
		const oversized = customPolicy();
		oversized.rules[0].matchers = [{ type: "regex", pattern: `A${"[0-9]".repeat(103)}` }];
		expect(issuesOf(oversized).length).toBeGreaterThan(0);

		const unknownValidator = customPolicy();
		unknownValidator.rules[1].matchers[0].validator = "custom_js";
		expect(issuesOf(unknownValidator).length).toBeGreaterThan(0);

		const duplicate = customPolicy();
		duplicate.labels[1].id = "acme-project-code";
		expect(issuesOf(duplicate)).toContain("label ids must be unique");

		const unknownField = customPolicy();
		unknownField.labels[0].color = "red";
		expect(issuesOf(unknownField).length).toBeGreaterThan(0);
	});

	it("bounds regex matchers and dictionary terms across the whole policy", () => {
		const regexes = customPolicy();
		regexes.rules = Array.from({ length: Math.ceil((DLP_MAX_POLICY_REGEX_MATCHERS + 1) / 50) }, (_, index) => ({
			...regexes.rules[0],
			id: `bulk-regex-${index}`,
			matchers: Array.from({ length: 50 }, (_, m) => ({ type: "regex", pattern: `ID${index}-${m}-[0-9]{4}` })),
		}));
		expect(issuesOf(regexes)).toContain(
			`a policy may contain at most ${DLP_MAX_POLICY_REGEX_MATCHERS} regex matchers`,
		);

		const keywords = customPolicy();
		keywords.rules = Array.from({ length: Math.ceil((DLP_MAX_POLICY_KEYWORD_TERMS + 1) / 500) }, (_, index) => ({
			...keywords.rules[0],
			id: `bulk-keyword-${index}`,
			matchers: [{ type: "keyword", values: Array.from({ length: 500 }, (_, k) => `term-${index}-${k}`) }],
		}));
		expect(issuesOf(keywords)).toContain(
			`a policy may contain at most ${DLP_MAX_POLICY_KEYWORD_TERMS} keyword terms`,
		);
	});
});

describe("tenant custom label evaluation", () => {
	it.each(["block", "ask", "redact"] as const)(
		"catches the synthetic project code with the label id and %s action on input and output",
		(action) => {
			const policy = DlpPolicySchema.parse(customPolicy(action));
			for (const scan of [scanDlpInput, scanDlpOutput]) {
				const result = scan(policy, {
					tenantId: TENANT,
					content: `Deploy ${PROJECT_CODE} tonight`,
					contentType: "text/plain",
				});
				expect(result).toMatchObject({ status: "inspected", action });
				expect(result.findings).toEqual([
					expect.objectContaining({ labelId: "acme-project-code", ruleId: "acme-project-code-rule", action }),
				]);
				expect(JSON.stringify(result.findings)).not.toContain(PROJECT_CODE);
				if (action === "redact" && result.status === "inspected") {
					expect(result.transformedContent).toBe("Deploy [PROJECT-CODE] tonight");
				}
			}
		},
	);

	it("matches dictionary terms and lets benign text pass", () => {
		const policy = DlpPolicySchema.parse(customPolicy());
		expect(
			scanDlpInput(policy, { tenantId: TENANT, content: "status of project nightjar?", contentType: "text/plain" })
				.findings[0],
		).toMatchObject({ labelId: "acme-project-code" });
		const benign = scanDlpInput(policy, {
			tenantId: TENANT,
			content: "PRJ-ACME-12345 is too short and PRJ-acme-123456 is lowercase",
			contentType: "text/plain",
		});
		expect(benign).toMatchObject({ status: "inspected", action: "allow", findings: [] });
	});

	it("reports only checksum-valid matches when a validator is configured", () => {
		const policy = DlpPolicySchema.parse(customPolicy());
		const valid = scanDlpInput(policy, { tenantId: TENANT, content: "card 4111 1111 1111 1111", contentType: "text/plain" });
		expect(valid.findings).toEqual([expect.objectContaining({ labelId: "acme-card", action: "redact" })]);
		const invalid = scanDlpInput(policy, { tenantId: TENANT, content: "order 4111 1111 1111 1112", contentType: "text/plain" });
		expect(invalid).toMatchObject({ action: "allow", findings: [] });
	});

	it("reports an unsupported format as unavailable instead of clean", () => {
		const policy = DlpPolicySchema.parse(customPolicy());
		const result = scanDlpInput(policy, { tenantId: TENANT, content: PROJECT_CODE, contentType: "application/pdf" });
		expect(result).toMatchObject({ status: "unavailable", action: "block", unavailable: { reason: "unsupported_format" } });
	});

	it("applies the exception lifecycle to custom label rules", () => {
		const base = customPolicy();
		base.exceptions = [
			{
				id: "acme-project-exception",
				tenantId: TENANT,
				ruleId: "acme-project-code-rule",
				ownerId: "security-owner",
				justification: "Synthetic approved false positive",
				scope: "rule",
				createdAt: "2020-01-01T00:00:00Z",
				expiresAt: "2999-01-01T00:00:00Z",
			},
		];
		const result = scanDlpInput(DlpPolicySchema.parse(base), {
			tenantId: TENANT,
			content: PROJECT_CODE,
			contentType: "text/plain",
		});
		expect(result).toMatchObject({ action: "allow", appliedExceptionIds: ["acme-project-exception"] });
		const expired = scanDlpInput(DlpPolicySchema.parse(base), {
			tenantId: TENANT,
			content: PROJECT_CODE,
			contentType: "text/plain",
			scannedAt: "3000-01-01T00:00:00Z",
		});
		expect(expired.action).toBe("block");
	});
});

describe("signed tenant bundle carries custom labels to the endpoint", () => {
	let home: string;
	beforeEach(async () => {
		home = await makeTmpDir();
		vi.stubEnv("HOME", home);
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.restoreAllMocks();
	});

	it("withholds output carrying the custom secret and passes benign output", async () => {
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "openclaw",
			payload: detectorPolicyPayload(TENANT, { dlp: { enabled: true, policy: customPolicy("block") } }),
		});
		const findings = await scanProvisionedOutput([`Use ${PROJECT_CODE} for the build`], "openclaw");
		expect(findings).toContainEqual(
			expect.objectContaining({ ruleId: "OUT-DLP-acme-project-code-rule", severity: "critical" }),
		);
		expect(JSON.stringify(findings)).not.toContain(PROJECT_CODE);
		expect(await scanProvisionedOutput(["The build passed."], "openclaw")).toEqual([]);
	});

	it("fails closed instead of dropping a signed label whose pattern is unsafe", async () => {
		const unsafe = customPolicy("block");
		unsafe.rules[0].matchers = [{ type: "regex", pattern: "(a|aa)+b" }];
		await provisionTenantDetectorPolicy({
			homeDir: home,
			agentRuntime: "openclaw",
			payload: detectorPolicyPayload(TENANT, { dlp: { enabled: true, policy: unsafe } }),
		});
		expect(await scanProvisionedOutput(["The build passed."], "openclaw")).toContainEqual(
			expect.objectContaining({ ruleId: "OUT-DLP-UNAVAILABLE" }),
		);
	});
});
