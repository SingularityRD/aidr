import { describe, expect, it } from "vitest";
import {
	createDlpMatchFingerprint,
	DlpExceptionSchema,
	DlpPolicySchema,
	DlpTenantIsolationError,
	scanDlpInput,
	scanDlpOutput,
} from "../../dlp/index.js";

function createPolicy(overrides: Record<string, unknown> = {}) {
	return DlpPolicySchema.parse({
		version: 1,
		tenantId: "tenant-acme",
		maxContentBytes: 1_024,
		supportedFormats: ["text/*", "application/json"],
		unavailableAction: "block",
		labels: [
			{
				id: "label-employee-id",
				tenantId: "tenant-acme",
				name: "Employee ID",
				sensitivity: "confidential",
				redactionToken: "[EMPLOYEE-ID]",
			},
			{
				id: "label-project",
				tenantId: "tenant-acme",
				name: "Project Codename",
				sensitivity: "restricted",
			},
		],
		rules: [
			{
				id: "rule-employee-id",
				tenantId: "tenant-acme",
				labelId: "label-employee-id",
				name: "Employee identifier",
				action: "redact",
				directions: ["input", "output"],
				matchers: [{ type: "regex", pattern: "EMP-[0-9]{6}", flags: "" }],
			},
			{
				id: "rule-project-codename",
				tenantId: "tenant-acme",
				labelId: "label-project",
				name: "Project codename",
				action: "block",
				directions: ["output"],
				matchers: [
					{ type: "keyword", values: ["Project Atlas"], caseSensitive: false, wholeWord: true },
				],
			},
		],
		exceptions: [],
		...overrides,
	});
}

describe("tenant DLP policy", () => {
	it("redacts organization-specific labels on both common scan entry points", () => {
		const policy = createPolicy();
		const input = scanDlpInput(policy, {
			tenantId: "tenant-acme",
			content: "Assign EMP-123456 to the ticket",
			contentType: "text/plain; charset=utf-8",
		});
		const output = scanDlpOutput(policy, {
			tenantId: "tenant-acme",
			content: '{"employee":"EMP-654321"}',
			contentType: "application/json",
		});

		expect(input).toMatchObject({
			status: "inspected",
			action: "redact",
			transformedContent: "Assign [EMPLOYEE-ID] to the ticket",
		});
		expect(output).toMatchObject({
			status: "inspected",
			action: "redact",
			transformedContent: '{"employee":"[EMPLOYEE-ID]"}',
		});
		expect(JSON.stringify(input)).not.toContain("EMP-123456");
		expect(input.findings[0]).toMatchObject({
			labelId: "label-employee-id",
			action: "redact",
		});
	});

	it("applies block over ask and redact without leaking the blocked value", () => {
		const base = createPolicy();
		const policy = DlpPolicySchema.parse({
			...base,
			rules: [
				...base.rules,
				{
					id: "rule-project-review",
					tenantId: "tenant-acme",
					labelId: "label-project",
					name: "Human review",
					action: "ask",
					directions: ["output"],
					matchers: [{ type: "keyword", values: ["Atlas"] }],
				},
			],
		});

		const result = scanDlpOutput(policy, {
			tenantId: "tenant-acme",
			content: "Project Atlas belongs to EMP-123456",
			contentType: "text/markdown",
		});

		expect(result.status).toBe("inspected");
		expect(result.action).toBe("block");
		expect(result).not.toHaveProperty("transformedContent");
		expect(result.findings.map((finding) => finding.action)).toEqual(
			expect.arrayContaining(["redact", "ask", "block"]),
		);
		expect(JSON.stringify(result)).not.toContain("Project Atlas");
	});

	it("does not treat a keyword embedded in another word as a finding", () => {
		const policy = createPolicy({
			rules: [
				{
					id: "rule-project-codename",
					tenantId: "tenant-acme",
					labelId: "label-project",
					name: "Project codename",
					action: "ask",
					matchers: [{ type: "keyword", values: ["Atlas"] }],
				},
			],
		});

		const falsePositive = scanDlpInput(policy, {
			tenantId: "tenant-acme",
			content: "The Atlasian format and atlas_v2 are harmless identifiers.",
			contentType: "text/plain",
		});
		const truePositive = scanDlpInput(policy, {
			tenantId: "tenant-acme",
			content: "Atlas is the internal codename.",
			contentType: "text/plain",
		});

		expect(falsePositive).toMatchObject({ status: "inspected", action: "allow", findings: [] });
		expect(truePositive).toMatchObject({ status: "inspected", action: "ask" });
	});

	it("suppresses only an active, fingerprint-bound false positive", () => {
		const matchedValue = "EMP-000001";
		const activeFingerprint = createDlpMatchFingerprint(
			"tenant-acme",
			"rule-employee-id",
			matchedValue,
		);
		const base = createPolicy();
		const policy = DlpPolicySchema.parse({
			...base,
			exceptions: [
				{
					id: "exception-approved-fixture",
					tenantId: "tenant-acme",
					ruleId: "rule-employee-id",
					ownerId: "security-owner-1",
					justification: "Approved documentation fixture",
					scope: "match",
					fingerprint: activeFingerprint,
					expiresAt: "2027-01-01T00:00:00.000Z",
				},
			],
		});

		const approved = scanDlpInput(policy, {
			tenantId: "tenant-acme",
			content: `fixture ${matchedValue}`,
			contentType: "text/plain",
			scannedAt: "2026-09-12T00:00:00.000Z",
		});
		const differentValue = scanDlpInput(policy, {
			tenantId: "tenant-acme",
			content: "fixture EMP-000002",
			contentType: "text/plain",
			scannedAt: "2026-09-12T00:00:00.000Z",
		});
		const expired = scanDlpInput(policy, {
			tenantId: "tenant-acme",
			content: `fixture ${matchedValue}`,
			contentType: "text/plain",
			scannedAt: "2027-01-01T00:00:00.000Z",
		});

		expect(approved).toMatchObject({
			status: "inspected",
			action: "allow",
			appliedExceptionIds: ["exception-approved-fixture"],
		});
		expect(differentValue.action).toBe("redact");
		expect(expired.action).toBe("redact");
	});

	it("requires attributable, expiring exception records", () => {
		const incomplete = {
			id: "exception-1",
			tenantId: "tenant-acme",
			ruleId: "rule-employee-id",
			ownerId: "",
			justification: "Temporary fixture",
			scope: "match",
			expiresAt: "not-a-time",
		};

		expect(DlpExceptionSchema.safeParse(incomplete).success).toBe(false);
		expect(
			DlpExceptionSchema.safeParse({
				...incomplete,
				ownerId: "security-owner-1",
				scope: "rule",
				createdAt: "2026-09-13T00:00:00.000Z",
				expiresAt: "2026-09-12T00:00:00.000Z",
			}).success,
		).toBe(false);
	});

	it("rejects high-risk custom regular expressions", () => {
		const base = createPolicy();
		const result = DlpPolicySchema.safeParse({
			...base,
			rules: [
				{
					...base.rules[0],
					matchers: [{ type: "regex", pattern: "(a+)+$", flags: "" }],
				},
			],
		});

		expect(result.success).toBe(false);
	});

	it("rejects cross-tenant policy members and scan requests", () => {
		const base = createPolicy();
		const crossTenantLabel = DlpPolicySchema.safeParse({
			...base,
			labels: base.labels.map((label, index) =>
				index === 0 ? { ...label, tenantId: "tenant-other" } : label,
			),
		});
		const crossTenantRule = DlpPolicySchema.safeParse({
			...base,
			rules: base.rules.map((rule, index) =>
				index === 0 ? { ...rule, tenantId: "tenant-other" } : rule,
			),
		});
		const crossTenantException = DlpPolicySchema.safeParse({
			...base,
			exceptions: [
				{
					id: "exception-cross-tenant",
					tenantId: "tenant-other",
					ruleId: "rule-employee-id",
					ownerId: "security-owner-1",
					justification: "Must not cross tenant boundary",
					scope: "rule",
					expiresAt: "2027-01-01T00:00:00.000Z",
				},
			],
		});

		expect(crossTenantLabel.success).toBe(false);
		expect(crossTenantRule.success).toBe(false);
		expect(crossTenantException.success).toBe(false);
		expect(() =>
			scanDlpInput(base, {
				tenantId: "tenant-other",
				content: "EMP-123456",
				contentType: "text/plain",
			}),
		).toThrow(DlpTenantIsolationError);
	});

	it("returns an explicit fail-closed state for unsupported and oversized content", () => {
		const askPolicy = createPolicy({ unavailableAction: "ask", maxContentBytes: 4 });
		const unsupported = scanDlpOutput(askPolicy, {
			tenantId: "tenant-acme",
			content: "%PDF",
			contentType: "application/pdf",
		});
		const oversized = scanDlpInput(askPolicy, {
			tenantId: "tenant-acme",
			content: "Şifre",
			contentType: "text/plain",
		});

		expect(unsupported).toMatchObject({
			status: "unavailable",
			action: "ask",
			unavailable: { reason: "unsupported_format" },
		});
		expect(oversized).toMatchObject({
			status: "unavailable",
			action: "ask",
			byteLength: 6,
			unavailable: { reason: "oversize" },
		});
	});

	it("requires every matcher when a rule uses all mode", () => {
		const policy = createPolicy({
			rules: [
				{
					id: "rule-combined-context",
					tenantId: "tenant-acme",
					labelId: "label-project",
					name: "Combined context",
					action: "ask",
					matchMode: "all",
					matchers: [
						{ type: "keyword", values: ["Project Atlas"] },
						{ type: "keyword", values: ["acquisition"] },
					],
				},
			],
		});

		expect(
			scanDlpInput(policy, {
				tenantId: "tenant-acme",
				content: "Project Atlas status",
				contentType: "text/plain",
			}).action,
		).toBe("allow");
		expect(
			scanDlpInput(policy, {
				tenantId: "tenant-acme",
				content: "Project Atlas acquisition status",
				contentType: "text/plain",
			}).action,
		).toBe("ask");
	});
});
