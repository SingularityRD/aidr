import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type DlpPolicy, DlpPolicySchema } from "../dlp/policy.js";
import { createDlpContentFingerprint, createDlpMatchFingerprint } from "../dlp/scanner.js";
import { evaluateToolCall, type ToolEvaluationContext } from "../evaluator.js";
import { evaluateCommonPiiBaseline } from "../pii-baseline.js";
import { makeTmpDir } from "./test-utils.js";

let configPath: string;
let homeDir: string;

const TENANT = "tenant-a";
const EMAIL = "synthetic.user@example.com";
const OTHER_EMAIL = "someone.else@example.org";
const FAR_FUTURE = "2099-01-01T00:00:00.000Z";

type RuleOverrides = {
	enabled?: boolean;
	action?: "block" | "ask" | "redact";
	directions?: string[];
};

function policy(
	options: { emailRule?: RuleOverrides; exceptions?: Array<Record<string, unknown>> } = {},
): DlpPolicy {
	const rules: Array<Record<string, unknown>> = [
		{
			id: "private-rule",
			tenantId: TENANT,
			labelId: "private-label",
			name: "Private value rule",
			action: "block",
			directions: ["input"],
			matchers: [{ type: "keyword", values: ["COMPANY-SECRET-123"], wholeWord: false }],
		},
	];
	if (options.emailRule) {
		rules.push({
			id: "pii-email",
			tenantId: TENANT,
			labelId: "private-label",
			name: "Email addresses",
			action: options.emailRule.action ?? "block",
			enabled: options.emailRule.enabled ?? true,
			directions: options.emailRule.directions ?? ["input", "output"],
			// Tenant matchers for the reserved rule extend the baseline; this one
			// never matches the fixtures below.
			matchers: [{ type: "keyword", values: ["NEVER-PRESENT-MARKER"] }],
		});
	}
	return DlpPolicySchema.parse({
		version: 1,
		tenantId: TENANT,
		supportedFormats: ["application/json"],
		labels: [{ id: "private-label", tenantId: TENANT, name: "Private", sensitivity: "restricted" }],
		rules,
		exceptions: options.exceptions ?? [],
	});
}

function exception(scope: "rule" | "content" | "match", fingerprint?: string) {
	return {
		id: `exc-${scope}`,
		tenantId: TENANT,
		ruleId: "pii-email",
		ownerId: "owner-1",
		justification: "Support mailbox is public",
		scope,
		...(fingerprint ? { fingerprint } : {}),
		expiresAt: FAR_FUTURE,
	};
}

function context(dlpPolicy: DlpPolicy): ToolEvaluationContext {
	return {
		threatsDir: join(homeDir, "empty-threats"),
		allowlistsDir: join(homeDir, "empty-allowlists"),
		configPath,
		runtimeDetectors: { tenantId: TENANT, dlp: { enabled: true, policy: dlpPolicy } },
	};
}

function request(body: string) {
	return { sessionId: "session-a", toolName: "CustomTool", toolInput: { body }, artifacts: [] };
}

beforeEach(async () => {
	homeDir = await makeTmpDir();
	vi.stubEnv("HOME", homeDir);
	await mkdir(join(homeDir, ".singularity-aidr"), { recursive: true });
	configPath = join(homeDir, "config.json");
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			control_plane: { enabled: false },
			licensing: { require_signed_entitlements: false },
			heuristics_enabled: false,
			url_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: true, path: "~/.singularity-aidr/audit.jsonl" },
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
		}),
	);
});

afterEach(() => vi.unstubAllEnvs());

describe("built-in common-PII baseline respects tenant DLP policy", () => {
	it("blocks an email by default when the tenant wrote no pii-email rule", async () => {
		const verdict = await evaluateToolCall(request(`Email: ${EMAIL}`), context(policy()));
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "pii-email" });
	});

	it("allows an email when the tenant disables the pii-email rule", async () => {
		const verdict = await evaluateToolCall(
			request(`Email: ${EMAIL}`),
			context(policy({ emailRule: { enabled: false } })),
		);
		expect(verdict.decision).toBe("allow");
	});

	it("allows an email when the tenant scopes pii-email to output only", async () => {
		const verdict = await evaluateToolCall(
			request(`Email: ${EMAIL}`),
			context(policy({ emailRule: { directions: ["output"] } })),
		);
		expect(verdict.decision).toBe("allow");
	});

	it("applies the tenant's ask action instead of the baseline block", async () => {
		const verdict = await evaluateToolCall(
			request(`Email: ${EMAIL}`),
			context(policy({ emailRule: { action: "ask" } })),
		);
		expect(verdict).toMatchObject({
			decision: "ask",
			category: "dlp",
			matchedThreatId: "pii-email",
		});
		expect(verdict.reasons.join(" ")).toContain("requires approval");
		expect(JSON.stringify(verdict)).not.toContain(EMAIL);
	});

	it("allows an email under an active rule-scoped exception", async () => {
		const verdict = await evaluateToolCall(
			request(`Email: ${EMAIL}`),
			context(policy({ emailRule: {}, exceptions: [exception("rule")] })),
		);
		expect(verdict.decision).toBe("allow");
	});

	it("allows only the fingerprinted address under a match-scoped exception", async () => {
		const dlpPolicy = policy({
			emailRule: {},
			exceptions: [exception("match", createDlpMatchFingerprint(TENANT, "pii-email", EMAIL))],
		});
		expect((await evaluateToolCall(request(`Email: ${EMAIL}`), context(dlpPolicy))).decision).toBe(
			"allow",
		);
		expect(
			await evaluateToolCall(request(`Email: ${EMAIL}, cc ${OTHER_EMAIL}`), context(dlpPolicy)),
		).toMatchObject({ decision: "deny", matchedThreatId: "pii-email" });
	});

	it("honours a content-scoped exception for the exact serialized payload", () => {
		const content = JSON.stringify({ body: `Email: ${EMAIL}` });
		const dlpPolicy = policy({
			emailRule: {},
			exceptions: [exception("content", createDlpContentFingerprint(TENANT, content))],
		});
		expect(evaluateCommonPiiBaseline(dlpPolicy, content)).toEqual({
			finding: null,
			appliedExceptionIds: ["exc-content"],
		});
		expect(
			evaluateCommonPiiBaseline(dlpPolicy, JSON.stringify({ body: `Email: ${OTHER_EMAIL}` }))
				.finding,
		).toMatchObject({ decision: "deny", type: "email" });
	});

	it("ignores an expired exception", () => {
		const dlpPolicy = policy({ emailRule: {}, exceptions: [exception("rule")] });
		const later = new Date("2100-01-01T00:00:00.000Z");
		expect(evaluateCommonPiiBaseline(dlpPolicy, EMAIL, { now: later }).finding).toMatchObject({
			decision: "deny",
			ruleId: "pii-email",
		});
	});

	it("still blocks other PII types when the tenant allows email", async () => {
		const verdict = await evaluateToolCall(
			request(`Email: ${EMAIL} SSN: 123-45-6789`),
			context(policy({ emailRule: { enabled: false } })),
		);
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "pii-ssn" });
	});

	it("lets a tenant block rule win over a baseline ask", async () => {
		const verdict = await evaluateToolCall(
			request(`Email: ${EMAIL} COMPANY-SECRET-123`),
			context(policy({ emailRule: { action: "ask" } })),
		);
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "private-rule" });
	});

	it.each([
		["epoch timestamps", "created 1727190000 updated 1727190000123"],
		["order ids", "order 123456789 invoice 4155552671"],
		["ip addresses", "host 10.0.0.12 and 192.168.1.254"],
		["non-Luhn digit groups", "ref 1234 5678 9012 3456"],
	])("does not report %s as common PII", async (_label, body) => {
		const verdict = await evaluateToolCall(request(body), context(policy()));
		expect(verdict.decision).toBe("allow");
	});
});
