import { describe, expect, it } from "vitest";
import {
	createDlpContentFingerprint,
	createDlpMatchFingerprint,
	DLP_EXPIRED_EXCEPTION_DOMINANCE,
	DlpExceptionSchema,
	DlpPolicySchema,
	DlpTenantIsolationError,
	pruneExpiredExceptions,
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

/**
 * Attributable exception fixture. Rule scope by default (which must carry no
 * fingerprint); a content or match record binds its own SHA-256 explicitly.
 */
function createException(overrides: Record<string, unknown> = {}) {
	return {
		id: "exception-fixture",
		tenantId: "tenant-acme",
		ruleId: "rule-employee-id",
		ownerId: "security-owner-1",
		justification: "Documented false-positive fixture",
		scope: "rule",
		createdAt: "2019-01-01T00:00:00.000Z",
		expiresAt: "2999-01-01T00:00:00.000Z",
		...overrides,
	};
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

	it("ignores and prunes an expired exception instead of letting it suppress a finding", () => {
		const matchedValue = "EMP-000123";
		const content = `fixture ${matchedValue}`;
		const expiredAt = "2020-01-01T00:00:00.000Z";
		// Three expired records against four live ones: the list is not dominated,
		// so the policy itself is accepted and the scanner has to drop the dead
		// records before it matches anything.
		const policy = DlpPolicySchema.parse({
			...createPolicy(),
			exceptions: [
				createException({ id: "exception-expired-rule", expiresAt: expiredAt }),
				createException({
					id: "exception-expired-content",
					scope: "content",
					fingerprint: createDlpContentFingerprint("tenant-acme", content),
					expiresAt: expiredAt,
				}),
				createException({
					id: "exception-expired-match",
					scope: "match",
					fingerprint: createDlpMatchFingerprint("tenant-acme", "rule-employee-id", matchedValue),
					expiresAt: expiredAt,
				}),
				...Array.from({ length: 4 }, (_, index) =>
					createException({
						id: `exception-live-${index}`,
						scope: "match",
						fingerprint: createDlpMatchFingerprint(
							"tenant-acme",
							"rule-employee-id",
							`EMP-9${String(index).padStart(5, "0")}`,
						),
					}),
				),
			],
		});
		const scannedAt = new Date("2026-06-01T00:00:00.000Z");
		const request = {
			tenantId: "tenant-acme",
			content,
			contentType: "text/plain",
			scannedAt: scannedAt.toISOString(),
		};

		const scanned = scanDlpInput(policy, request);
		const pruned = pruneExpiredExceptions(policy, scannedAt);

		expect(scanned).toMatchObject({
			status: "inspected",
			action: "redact",
			transformedContent: "fixture [EMPLOYEE-ID]",
			appliedExceptionIds: [],
		});
		expect(scanned.findings).toHaveLength(1);
		// Dead records are removed from the list, not merely skipped per match:
		// they no longer sit in the exception set the scanner carries and can
		// never be reported as applied.
		expect(pruned.exceptions.map((exception) => exception.id)).toEqual([
			"exception-live-0",
			"exception-live-1",
			"exception-live-2",
			"exception-live-3",
		]);
		expect(pruned.tenantId).toBe("tenant-acme");
		expect(pruned.rules).toEqual(policy.rules);
		// Pruning is verdict-preserving: the pruned policy scans identically.
		expect(scanDlpInput(pruned, request)).toEqual(scanned);
	});

	it("rejects a policy whose exception list is dominated by expired entries", () => {
		const expiredAt = "2020-01-01T00:00:00.000Z";
		const activeAt = "2999-01-01T00:00:00.000Z";
		const exceptions = (expired: number, active: number) => [
			...Array.from({ length: expired }, (_, index) =>
				createException({ id: `exception-expired-${index}`, expiresAt: expiredAt }),
			),
			...Array.from({ length: active }, (_, index) =>
				createException({ id: `exception-active-${index}`, expiresAt: activeAt }),
			),
		];

		const dominated = DlpPolicySchema.safeParse({
			...createPolicy(),
			exceptions: exceptions(6, 4),
		});

		expect(dominated.success).toBe(false);
		expect(dominated.error?.issues).toEqual(
			expect.arrayContaining([
				expect.objectContaining({
					path: ["exceptions"],
					message: expect.stringContaining(DLP_EXPIRED_EXCEPTION_DOMINANCE),
				}),
			]),
		);

		// An exactly half-expired list is churn, not dominance: the scanner prunes
		// those records and the tenant keeps every rule in its policy.
		expect(
			DlpPolicySchema.safeParse({ ...createPolicy(), exceptions: exceptions(5, 5) }).success,
		).toBe(true);
		// A single expired record cannot dominate a list of one, and it is pruned
		// rather than turned into a refusal of the whole policy.
		expect(
			DlpPolicySchema.safeParse({ ...createPolicy(), exceptions: exceptions(1, 0) }).success,
		).toBe(true);
	});

	it("keeps suppressing a finding while an exception is still active", () => {
		const matchedValue = "EMP-000321";
		const policy = DlpPolicySchema.parse({
			...createPolicy(),
			exceptions: [
				createException({
					id: "exception-live",
					scope: "match",
					createdAt: "2026-01-01T00:00:00.000Z",
					fingerprint: createDlpMatchFingerprint("tenant-acme", "rule-employee-id", matchedValue),
				}),
				createException({
					id: "exception-stale",
					scope: "match",
					fingerprint: createDlpMatchFingerprint("tenant-acme", "rule-employee-id", "EMP-000322"),
					expiresAt: "2020-01-01T00:00:00.000Z",
				}),
			],
		});
		const scannedAt = new Date("2026-06-01T00:00:00.000Z");
		const pruned = pruneExpiredExceptions(policy, scannedAt);

		expect(pruned.exceptions.map((exception) => exception.id)).toEqual(["exception-live"]);
		// Nothing left to prune: the caller gets the same policy back.
		expect(pruneExpiredExceptions(pruned, scannedAt)).toBe(pruned);
		expect(
			scanDlpInput(pruned, {
				tenantId: "tenant-acme",
				content: `fixture ${matchedValue}`,
				contentType: "text/plain",
				scannedAt: scannedAt.toISOString(),
			}),
		).toMatchObject({
			status: "inspected",
			action: "allow",
			appliedExceptionIds: ["exception-live"],
		});
		// The live record stays bound to its own fingerprint.
		expect(
			scanDlpInput(pruned, {
				tenantId: "tenant-acme",
				content: "fixture EMP-000323",
				contentType: "text/plain",
				scannedAt: scannedAt.toISOString(),
			}).action,
		).toBe("redact");
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
