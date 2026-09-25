// Contract suite for the `governance-digest` Edge Function: the scheduled
// dispatch path (service credential only, claim -> summary -> mail -> complete,
// fail-closed on malformed data) and the owner/admin test send (identity
// barrier, role, rate limit, receipt). It also pins the counts-only e-mail and
// the function's registration.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	deliveryStatus,
	digestIdempotencyKey,
	GovernanceDigestError,
	governanceDigestEmail,
	parseDigestClaims,
	parseGovernanceSummary,
	secretsEqual,
} from "../_shared/governance-digest.ts";
import type { MailMessage, Mailer, MailResult } from "../_shared/mailer.ts";
import { GOVERNANCE_OWNER, GOVERNANCE_TENANT, governanceSummaryFixture } from "./governance-fixtures.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through GovernanceDigestDeps.client");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SERVICE_KEY = "service-role-key-for-contract-tests";
const OTHER_TENANT = "44444444-4444-4444-8444-444444444444";
const URL_BASE = "https://project.supabase.co/functions/v1/governance-digest";
const NOW = Date.parse("2026-09-28T06:30:00.000Z");

interface Options {
	role?: string | null;
	requireMfa?: boolean;
	assurance?: string;
	rateAllowed?: boolean;
	claims?: unknown;
	claimError?: boolean;
	summary?: unknown;
	summaryError?: boolean;
	completeError?: boolean;
	context?: unknown;
	receiptError?: boolean;
}

function claimsFixture(recipients: string[][] = [["owner@acme.example", "admin@acme.example"], []]) {
	return {
		applied: true,
		due: recipients.length,
		claims: recipients.map((list, index) => ({
			tenant_id: index === 0 ? GOVERNANCE_TENANT : OTHER_TENANT,
			tenant_name: index === 0 ? "Acme <Security>" : "Other",
			claim_id: `aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa${index}`,
			cadence: "weekly",
			period_from: "2026-09-21T00:00:00+00:00",
			period_to: "2026-09-28T00:00:00+00:00",
			recipients: list,
		})),
	};
}

function database(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => token === "user-token"
				? { data: { user: { id: GOVERNANCE_OWNER } }, error: null }
				: { data: { user: null }, error: new Error("invalid") }),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({
					data: { currentLevel: options.assurance ?? "aal2" },
					error: null,
				})),
			},
		},
		from(table: string) {
			const filters: Record<string, unknown> = {};
			const builder = {
				select: () => builder,
				eq: (column: string, value: unknown) => {
					filters[column] = value;
					return builder;
				},
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") {
						return { data: { require_mfa: options.requireMfa ?? false, required_saml_provider_id: null }, error: null };
					}
					if (table === "tenant_members") {
						if (filters.tenant_id !== GOVERNANCE_TENANT || options.role === null) return { data: null, error: null };
						return { data: { role: options.role ?? "owner", expires_at: null }, error: null };
					}
					if (table === "tenants") return { data: { id: filters.id, status: "active" }, error: null };
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			switch (name) {
				case "consume_tenant_rate_limit":
					return { data: { allowed: options.rateAllowed ?? true, remaining: 1 }, error: null };
				case "claim_due_governance_digests":
					if (options.claimError) return { data: null, error: { message: "db_down" } };
					return {
						data: options.claims ?? (args.p_apply ? claimsFixture() : { applied: false, due: 2, claims: [] }),
						error: null,
					};
				case "governance_digest_summary":
					if (options.summaryError) return { data: null, error: { message: "db_down" } };
					return { data: "summary" in options ? options.summary : governanceSummaryFixture(7), error: null };
				case "complete_governance_digest":
					return { data: { retry: false }, error: options.completeError ? { code: "40001", message: "claim lost" } : null };
				case "governance_digest_test_context":
					return {
						data: options.context ?? {
							tenant_name: "Acme Security",
							cadence: "weekly",
							period_from: "2026-09-21T06:30:00+00:00",
							period_to: "2026-09-28T06:30:00+00:00",
							recipients: ["owner@acme.example", "admin@acme.example"],
						},
						error: null,
					};
				case "record_governance_digest_test":
					return { data: null, error: options.receiptError ? { message: "db_down" } : null };
				default:
					throw new Error(`unexpected rpc ${name}`);
			}
		}),
	};
	return { db, rpcCalls };
}

function recordingMailer(fail: (message: MailMessage) => boolean = () => false, provider: "resend" | "none" = "resend") {
	const sent: MailMessage[] = [];
	const mailer: Mailer = {
		provider,
		send: vi.fn(async (message: MailMessage): Promise<MailResult> => {
			if (provider === "none") return { ok: false, reason: "not_configured" };
			sent.push(message);
			return fail(message) ? { ok: false, reason: "unavailable" } : { ok: true, provider: "resend", messageId: `m-${sent.length}` };
		}),
	};
	return { mailer, sent };
}

async function handler(options: Options = {}, mailer = recordingMailer(), env: Record<string, string> = {}) {
	const fake = database(options);
	const mod = await import("../governance-digest/index.ts");
	const handle = mod.createGovernanceDigestHandler({
		env: (name) => ({
			SUPABASE_URL: "https://project.supabase.co",
			SUPABASE_SERVICE_ROLE_KEY: SERVICE_KEY,
			AIDR_DASHBOARD_URL: "https://console.example.com/",
			...env,
		})[name],
		client: () => fake.db as never,
		mailer: mailer.mailer,
		now: () => NOW,
	});
	return { handle, ...fake, sent: mailer.sent, mailer: mailer.mailer };
}

function post(body: unknown, token: string | null = SERVICE_KEY): Request {
	return new Request(URL_BASE, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
		body: JSON.stringify(body),
	});
}

vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });

afterEach(() => {
	vi.clearAllMocks();
});

describe("governance-digest dispatch (service credential)", () => {
	it("refuses the scheduled path without the deployment credential", async () => {
		const { handle, rpcCalls } = await handler();
		for (const token of ["user-token", `${SERVICE_KEY}x`, SERVICE_KEY.slice(0, -1)]) {
			const response = await handle(post({ action: "dispatch", apply: true }, token));
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "service_credential_required" });
		}
		const missing = await handle(post({ action: "dispatch", apply: true }, null));
		expect(missing.status).toBe(401);
		expect(rpcCalls).toEqual([]);
	});

	it("a dry run only counts due schedules", async () => {
		const { handle, rpcCalls, sent } = await handler();
		const response = await handle(post({ action: "dispatch", apply: false }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, applied: false, due: 2, processed: 0, sent: 0 });
		expect(rpcCalls.map((call) => call.name)).toEqual(["claim_due_governance_digests"]);
		expect(rpcCalls[0].args).toEqual({ p_limit: 50, p_apply: false });
		expect(sent).toEqual([]);
	});

	it("sends one counts-only message per recipient and records every outcome", async () => {
		const { handle, rpcCalls, sent } = await handler();
		const response = await handle(post({ action: "dispatch", apply: true, limit: 10 }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			ok: true, applied: true, due: 2, processed: 2, mail_transport: "resend",
			sent: 1, partial: 0, failed: 0, no_transport: 0, no_recipients: 1, errors: 0,
		});
		expect(sent.map((message) => message.to)).toEqual(["owner@acme.example", "admin@acme.example"]);
		const completes = rpcCalls.filter((call) => call.name === "complete_governance_digest").map((call) => call.args);
		expect(completes).toEqual([
			{ p_tenant_id: GOVERNANCE_TENANT, p_claim_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa0", p_status: "sent", p_recipients: 2, p_delivered: 2 },
			{ p_tenant_id: OTHER_TENANT, p_claim_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", p_status: "no_recipients", p_recipients: 0, p_delivered: 0 },
		]);
		const summaryCalls = rpcCalls.filter((call) => call.name === "governance_digest_summary");
		expect(summaryCalls).toHaveLength(1);
		expect(summaryCalls[0].args).toEqual({
			p_tenant_id: GOVERNANCE_TENANT,
			p_from: "2026-09-21T00:00:00.000Z",
			p_to: "2026-09-28T00:00:00.000Z",
		});

		const [message] = sent;
		expect(message.subject).toBe("Weekly AI governance summary: Acme <Security>");
		expect(message.html).toContain("Acme &lt;Security&gt;");
		expect(message.html).not.toContain("<Security>");
		expect(message.text).toContain("Coding agents active: 9 of 12 enrolled");
		expect(message.text).toContain("Allowed: 1,200 · held for approval: 40 · denied: 25");
		expect(message.text).toContain("Median decision time: 43 s");
		expect(message.text).toContain("Approvers to review (fast-approval pattern): 1 of 3");
		expect(message.text).toContain("Acceptable-use notice acme-aup v3: acknowledged on 25 browser install(s)");
		expect(message.text).toContain("Runtime policy v7, last changed 147 day(s) ago");
		expect(message.text).toContain("Open the governance scorecard: https://console.example.com/governance");
		// Different recipients, different de-duplication keys, none carrying an address.
		expect(new Set(sent.map((m) => m.idempotencyKey)).size).toBe(2);
		for (const m of sent) expect(m.idempotencyKey).not.toContain("@");
	});

	it("records partial and failed deliveries so the schedule can retry", async () => {
		const partial = await handler({}, recordingMailer((message) => message.to.startsWith("admin")));
		expect(await (await partial.handle(post({ action: "dispatch", apply: true }))).json()).toMatchObject({ partial: 1 });
		const failed = await handler({}, recordingMailer(() => true));
		expect(await (await failed.handle(post({ action: "dispatch", apply: true }))).json()).toMatchObject({ failed: 1 });
		expect(failed.rpcCalls.find((call) => call.name === "complete_governance_digest")?.args).toMatchObject({
			p_status: "failed", p_recipients: 2, p_delivered: 0,
		});
	});

	it("never mails a summary it cannot validate, and never mails without a transport", async () => {
		for (const summary of [{ ...governanceSummaryFixture(), decisions: { allow: -1 } }, "not json", null]) {
			const run = await handler({ summary });
			const body = await (await run.handle(post({ action: "dispatch", apply: true }))).json();
			expect(body).toMatchObject({ failed: 1, sent: 0 });
			expect(run.sent).toEqual([]);
		}
		const down = await handler({ summaryError: true });
		expect(await (await down.handle(post({ action: "dispatch", apply: true }))).json()).toMatchObject({ failed: 1 });

		const none = await handler({}, recordingMailer(() => false, "none"));
		const body = await (await none.handle(post({ action: "dispatch", apply: true }))).json();
		expect(body).toMatchObject({ mail_transport: "none", no_transport: 1, no_recipients: 1, sent: 0 });
		expect(none.rpcCalls.some((call) => call.name === "governance_digest_summary")).toBe(false);
	});

	it("fails closed on an unreadable or malformed claim batch and counts lost claims", async () => {
		const unavailable = await handler({ claimError: true });
		expect((await unavailable.handle(post({ action: "dispatch", apply: true }))).status).toBe(503);
		for (const claims of [{ applied: true, due: 1, claims: [{ tenant_id: "not-a-uuid" }] }, { claims: "x" }]) {
			const malformed = await handler({ claims });
			const response = await malformed.handle(post({ action: "dispatch", apply: true }));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "governance_digest_invalid" });
		}
		const lost = await handler({ completeError: true });
		expect(await (await lost.handle(post({ action: "dispatch", apply: true }))).json()).toMatchObject({ errors: 2, sent: 0 });
	});

	it("rejects malformed bodies before any database access", async () => {
		const { handle, rpcCalls } = await handler();
		for (const body of [
			{ action: "dispatch" },
			{ action: "dispatch", apply: "yes" },
			{ action: "dispatch", apply: true, limit: 0 },
			{ action: "dispatch", apply: true, limit: 201 },
			{ action: "dispatch", apply: true, recipients: ["attacker@example.com"] },
			{ action: "send_test", tenant_id: GOVERNANCE_TENANT, to: "attacker@example.com" },
			{ action: "send_test", tenant_id: "nope" },
			{ action: "other" },
		]) {
			const response = await handle(post(body));
			expect(response.status, JSON.stringify(body)).toBe(400);
		}
		expect(rpcCalls).toEqual([]);
	});
});

describe("governance-digest test send (owner/admin session)", () => {
	const testBody = { action: "send_test", tenant_id: GOVERNANCE_TENANT };

	it("sends the last window to the workspace's own recipients and records a receipt", async () => {
		const { handle, sent, rpcCalls } = await handler();
		const response = await handle(post(testBody, "user-token"));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "sent", recipients: 2, delivered: 2 });
		expect(sent.map((m) => m.to)).toEqual(["owner@acme.example", "admin@acme.example"]);
		expect(sent[0].subject).toBe("[Test] Weekly AI governance summary: Acme Security");
		expect(rpcCalls.find((call) => call.name === "record_governance_digest_test")?.args).toMatchObject({
			p_tenant_id: GOVERNANCE_TENANT, p_actor_user_id: GOVERNANCE_OWNER, p_status: "sent", p_recipients: 2, p_delivered: 2,
		});
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({
			p_endpoint: "governance-digest:test", p_subject_limit: 2, p_tenant_limit: 4,
		});
	});

	it("enforces session, identity barrier, role and rate limit before any send", async () => {
		const cases: Array<[Options, string | null, number, string]> = [
			[{}, null, 401, "missing_access_token"],
			[{}, "bad-token", 401, "invalid_access_token"],
			[{ role: "member" }, "user-token", 403, "governance_role_insufficient"],
			[{ role: "viewer" }, "user-token", 403, "governance_role_insufficient"],
			[{ role: null }, "user-token", 403, "workspace_forbidden"],
			[{ requireMfa: true, assurance: "aal1" }, "user-token", 403, "mfa_required"],
			[{ rateAllowed: false }, "user-token", 429, "rate_limited"],
			[{}, SERVICE_KEY, 403, "user_session_required"],
		];
		for (const [options, token, status, error] of cases) {
			const run = await handler(options);
			const response = await run.handle(post(testBody, token));
			expect(response.status, error).toBe(status);
			expect(await response.json()).toMatchObject({ error });
			expect(run.sent).toEqual([]);
		}
		const other = await handler();
		const response = await other.handle(post({ ...testBody, tenant_id: OTHER_TENANT }, "user-token"));
		expect(response.status).toBe(403);
	});

	it("reports a missing mail transport and still records the attempt", async () => {
		const run = await handler({}, recordingMailer(() => false, "none"));
		const response = await run.handle(post(testBody, "user-token"));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "mail_not_configured" });
		expect(run.rpcCalls.find((call) => call.name === "record_governance_digest_test")?.args).toMatchObject({
			p_status: "no_transport", p_delivered: 0,
		});
	});

	it("refuses to answer without a receipt", async () => {
		const run = await handler({ receiptError: true });
		const response = await run.handle(post(testBody, "user-token"));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "governance_digest_audit_unavailable" });
	});
});

describe("governance summary projection and e-mail", () => {
	it("accepts the SQL shape and rejects negative, fractional or missing counts", () => {
		const summary = parseGovernanceSummary(governanceSummaryFixture());
		expect(summary.agents).toEqual({ enrolled: 12, active: 9 });
		expect(summary.acceptableUse).toEqual({ noticeId: "acme-aup", noticeVersion: 3, installs: 25 });
		for (const mutate of [
			(s: Record<string, any>) => { s.decisions.deny = -1; },
			(s: Record<string, any>) => { s.usage.agents.active = 1.5; },
			(s: Record<string, any>) => { delete s.incidents; },
			(s: Record<string, any>) => { s.acceptable_use.versions[0].notice_id = "<script>"; },
			(s: Record<string, any>) => { s.period.from = "yesterday"; },
		]) {
			const broken = structuredClone(governanceSummaryFixture()) as Record<string, any>;
			mutate(broken);
			expect(() => parseGovernanceSummary(broken)).toThrow(GovernanceDigestError);
		}
	});

	it("keeps identities and content out of the message", () => {
		const fixture = governanceSummaryFixture() as Record<string, any>;
		fixture.oversight.by_approver = [{ email: "fast.approver@acme.example" }];
		const message = governanceDigestEmail({
			to: "owner@acme.example",
			workspaceName: "Acme\nSecurity\u0007",
			cadence: "monthly",
			summary: parseGovernanceSummary(fixture),
			dashboardUrl: null,
			idempotencyKey: "governance-digest/x/y",
			test: false,
		});
		expect(message.subject).toBe("Monthly AI governance summary: Acme Security");
		expect(message.subject).not.toMatch(/[\r\n]/);
		expect(`${message.text}${message.html}`).not.toContain("fast.approver");
		expect(message.text).not.toContain("Open the governance scorecard");
		expect(message.text).toContain("Counts only");
	});

	it("claims drop addresses the mailer would refuse", () => {
		const claims = parseDigestClaims(claimsFixture([["owner@acme.example", "not an address", "owner@acme.example"]]));
		expect(claims.claims[0].recipients).toEqual(["owner@acme.example"]);
	});

	it("derives delivery status, idempotency keys and constant-time credential checks", async () => {
		expect([deliveryStatus(0, 0), deliveryStatus(2, 2), deliveryStatus(2, 1), deliveryStatus(2, 0)])
			.toEqual(["no_recipients", "sent", "partial", "failed"]);
		const key = await digestIdempotencyKey("tenant/1", "Owner@Acme.example");
		expect(key).toBe(await digestIdempotencyKey("tenant/1", "owner@acme.example"));
		expect(key).toMatch(/^governance-digest\/tenant\/1\/[a-f0-9]{16}$/);
		expect(await secretsEqual("abc", "abc")).toBe(true);
		expect(await secretsEqual("abc", "abd")).toBe(false);
		expect(await secretsEqual("", "")).toBe(false);
	});
});

describe("governance-digest registration", () => {
	it("is registered with JWT verification, a contract test and service-only SQL", () => {
		const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
		expect(config).toMatch(/\[functions\.governance-digest\]\n(?:#[^\n]*\n)*verify_jwt = true/);
		const manifest = JSON.parse(
			readFileSync(join(ROOT, "docs", "production-readiness", "edge-function-contract-manifest.json"), "utf8"),
		) as { functions: Record<string, { tests: string[] }> };
		expect(manifest.functions["governance-digest"]?.tests).toContain(
			"supabase/functions/__tests__/governance-digest-contract.test.ts",
		);
		const schedule = readFileSync(
			join(ROOT, "supabase", "migrations", "20260927000061_governance_digest_schedule.sql"),
			"utf8",
		);
		for (const fn of [
			"claim_due_governance_digests(integer, boolean)",
			"complete_governance_digest(uuid, uuid, text, integer, integer)",
			"governance_digest_summary(uuid, timestamptz, timestamptz)",
			"governance_digest_test_context(uuid, uuid)",
		]) {
			expect(schedule).toContain(`revoke all on function public.${fn} from public, anon, authenticated;`);
			expect(schedule).toContain(`grant execute on function public.${fn} to service_role;`);
		}
	});
});
