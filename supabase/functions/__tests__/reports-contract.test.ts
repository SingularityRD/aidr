// Contract suite for the `reports` Edge Function (executive summary, team
// rollup, printable report, scheduled-report options; E6) and for the shared
// executive report builder.
//
// The handler runs against an in-memory service-role double. Covers: owner/admin
// only, AAL2 for option changes, the team rollup listing only the caller's own
// administered workspaces and withholding figures where that workspace's
// identity barrier refuses the session, the localized (English/Turkish)
// headlines, the self-contained printable document, and fail-closed reads.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
	executiveReportDocument,
	executiveSummary,
	parseTriageSummary,
	reportSections,
} from "../_shared/executive-report.ts";
import { parseGovernanceSummary } from "../_shared/governance-digest.ts";
import { GOVERNANCE_OWNER, GOVERNANCE_TENANT, governanceSummaryFixture } from "./governance-fixtures.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through ReportsDeps.client");
	},
}));

const served: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => served.push(handler),
};

const { createReportsHandler, reportWindow } = await import("../reports/index.ts");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const HANDLER_SOURCE = readFileSync(join(ROOT, "supabase", "functions", "reports", "index.ts"), "utf8");
const SECOND_TENANT = "33333333-3333-4333-8333-333333333333";
const SSO_TENANT = "44444444-4444-4444-8444-444444444444";
const MEMBER = "55555555-5555-4555-8555-555555555555";
const T0 = Date.parse("2026-10-14T10:00:00.000Z");
const ENV = { SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "service-role" } as Record<string, string>;

type Row = Record<string, unknown>;

function triage(overrides: Row = {}): Row {
	return {
		total: 14, open: 3, acknowledged: 2, resolved: 7, false_positive: 2, snoozed: 1,
		unassigned_active: 2, active_critical: 1, active_high: 2, median_close_seconds: 5400, ...overrides,
	};
}

interface Options {
	aal?: "aal1" | "aal2";
	role?: string;
	summaryError?: boolean;
	triage?: unknown;
	optionsError?: boolean;
}

function world(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Row }> = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) =>
				token === "owner-token"
					? { data: { user: { id: GOVERNANCE_OWNER } }, error: null }
					: token === "member-token"
						? { data: { user: { id: MEMBER } }, error: null }
						: { data: { user: null }, error: new Error("invalid") }),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: options.aal ?? "aal2" }, error: null })),
			},
		},
		from(table: string) {
			const filters: Row = {};
			const builder = {
				select: () => builder,
				eq: (column: string, value: unknown) => {
					filters[column] = value;
					return builder;
				},
				maybeSingle: async () => {
					switch (table) {
						case "identity_user_session_state":
							return { data: null, error: null };
						case "tenant_identity_policies":
							// The third workspace requires MFA, which an AAL1 session does not meet.
							return {
								data: filters.tenant_id === SSO_TENANT ? { require_mfa: true, required_saml_provider_id: null } : null,
								error: null,
							};
						case "tenant_members":
							if (filters.user_id === MEMBER) return { data: { role: "member", expires_at: null }, error: null };
							return { data: { role: options.role ?? "owner", expires_at: null }, error: null };
						case "tenants":
							return { data: { id: filters.id, name: "Acme <Security>", status: "active" }, error: null };
						case "tenant_governance_settings":
							if (options.optionsError) return { data: null, error: { message: "db_down" } };
							return { data: { digest_language: "tr", digest_attachment: true, digest_enabled: true, digest_cadence: "weekly" }, error: null };
						default:
							throw new Error(`unexpected table ${table}`);
					}
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Row) => {
			rpcCalls.push({ name, args });
			switch (name) {
				case "consume_tenant_rate_limit":
					return { data: { allowed: true, remaining: 5 }, error: null };
				case "governance_digest_summary":
					if (options.summaryError) return { data: null, error: { message: "db_down" } };
					return { data: governanceSummaryFixture(7), error: null };
				case "incident_triage_summary":
					return { data: options.triage ?? triage(), error: null };
				case "executive_report_teams":
					return {
						data: [
							{ tenant_id: GOVERNANCE_TENANT, name: "Acme <Security>", role: "owner" },
							{ tenant_id: SECOND_TENANT, name: "Payments", role: "admin" },
							{ tenant_id: SSO_TENANT, name: "Treasury", role: "admin" },
						],
						error: null,
					};
				case "set_governance_report_options":
					return { data: { digest_language: args.p_language, digest_attachment: args.p_attachment }, error: null };
				default:
					throw new Error(`unexpected rpc ${name}`);
			}
		}),
	};
	return { db, rpcCalls };
}

async function call(body: unknown, options: Options = {}, token = "owner-token") {
	const fake = world(options);
	const handle = createReportsHandler({ env: (name) => ENV[name], client: () => fake.db as never, now: () => T0 });
	const response = await handle(
		new Request("https://project.supabase.co/functions/v1/reports", {
			method: "POST",
			headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
			body: JSON.stringify(body),
		}),
	);
	return { status: response.status, body: (await response.json()) as Row, rpcCalls: fake.rpcCalls };
}

describe("reports handler", () => {
	it("returns the executive summary in the workspace language, or the requested one", async () => {
		const result = await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 });
		expect(result.status).toBe(200);
		expect(result.body.language).toBe("tr");
		expect(result.body.options).toEqual({ language: "tr", attachment: true, digestEnabled: true, digestCadence: "weekly" });
		const executive = result.body.executive as { status: string; headlines: Array<{ level: string; text: string }> };
		expect(executive.status).toBe("attention");
		expect(executive.headlines[0]).toEqual({
			level: "attention",
			text: "1 kritik ve 2 yüksek önem dereceli vaka hâlâ açık ya da üstlenilmiş durumda.",
		});
		expect(result.rpcCalls.find((c) => c.name === "governance_digest_summary")?.args).toEqual({
			p_tenant_id: GOVERNANCE_TENANT,
			...Object.fromEntries(Object.entries(reportWindow(7, T0)).map(([key, value]) => [`p_${key}`, value])),
		});
		const english = await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7, language: "en" });
		expect((english.body.executive as { headlines: Array<{ text: string }> }).headlines[0].text).toBe(
			"1 critical and 2 high-severity incident(s) are still open or acknowledged.",
		);
	});

	it("rolls up only the caller's administered workspaces and withholds figures the session may not see", async () => {
		const result = await call({ action: "rollup", tenant_id: GOVERNANCE_TENANT, days: 30 }, { aal: "aal1" });
		expect(result.status).toBe(200);
		const teams = result.body.teams as Array<{ tenantId: string; figures: Row | null }>;
		expect(teams.map((team) => team.tenantId)).toEqual([GOVERNANCE_TENANT, SECOND_TENANT, SSO_TENANT]);
		expect(teams[0].figures).toMatchObject({ agentsActive: 9, deny: 25, incidentsActive: 5, incidentsCritical: 1 });
		expect(teams[2].figures).toBeNull();
		expect(result.rpcCalls.find((c) => c.name === "executive_report_teams")?.args).toEqual({ p_actor_user_id: GOVERNANCE_OWNER });
		// No figures were read for the workspace whose identity policy refused the session.
		expect(result.rpcCalls.filter((c) => c.args.p_tenant_id === SSO_TENANT && c.name !== "consume_tenant_rate_limit")).toEqual([]);
	});

	it("returns the printable, self-contained report document", async () => {
		const result = await call({ action: "document", tenant_id: GOVERNANCE_TENANT, days: 7, language: "tr", include_teams: true });
		expect(result.status).toBe(200);
		expect(result.body.filename).toBe("aidr-yonetici-raporu-2026-10-14.html");
		const html = String(result.body.html);
		expect(html).toContain('<html lang="tr">');
		expect(html).toContain("Ekip bazında özet");
		expect(html).toContain("Payments");
		expect(html).toContain("Acme &lt;Security&gt;");
		expect(html).not.toMatch(/<script|src=|href=/i);
	});

	it("changes the scheduled-report options only at AAL2", async () => {
		const ok = await call({ action: "set_options", tenant_id: GOVERNANCE_TENANT, language: "tr", attachment: false });
		expect(ok).toMatchObject({ status: 200, body: { ok: true, options: { language: "tr", attachment: false } } });
		expect(ok.rpcCalls.find((c) => c.name === "set_governance_report_options")?.args).toEqual({
			p_tenant_id: GOVERNANCE_TENANT, p_actor_user_id: GOVERNANCE_OWNER, p_language: "tr", p_attachment: false,
		});
		const aal1 = await call({ action: "set_options", tenant_id: GOVERNANCE_TENANT, language: "tr", attachment: false }, { aal: "aal1" });
		expect(aal1).toMatchObject({ status: 403, body: { error: "mfa_required" } });
	});

	it("lets the read-only auditor read every report but never change the options", async () => {
		const auditor = { role: "auditor" } as const;
		expect((await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 }, auditor)).status).toBe(200);
		expect((await call({ action: "rollup", tenant_id: GOVERNANCE_TENANT, days: 30 }, auditor)).status).toBe(200);
		expect((await call({ action: "document", tenant_id: GOVERNANCE_TENANT, days: 7, language: "en", include_teams: false }, auditor)).status).toBe(200);
		const write = await call({ action: "set_options", tenant_id: GOVERNANCE_TENANT, language: "tr", attachment: false }, auditor);
		expect(write).toMatchObject({ status: 403, body: { error: "report_role_insufficient" } });
		// Refused before the rate limit and before the write RPC.
		expect(write.rpcCalls.map((c) => c.name)).toEqual([]);
		for (const role of ["viewer", "support_jit", "superuser"]) {
			expect(await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 }, { role })).toMatchObject({ status: 403 });
		}
	});

	it("refuses members, malformed requests and unreadable figures", async () => {
		expect(await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 }, {}, "member-token")).toMatchObject({
			status: 403, body: { error: "report_role_insufficient" },
		});
		expect((await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 }, {}, "nobody")).status).toBe(401);
		for (const [body, error] of [
			[{ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 14 }, "invalid_window"],
			[{ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7, language: "de" }, "invalid_language"],
			[{ action: "document", tenant_id: GOVERNANCE_TENANT, days: 7, language: "en" }, "invalid_request"],
			[{ action: "set_options", tenant_id: GOVERNANCE_TENANT, language: "en", attachment: "yes" }, "invalid_request"],
			[{ action: "rollup", tenant_id: GOVERNANCE_TENANT, days: 7, recipients: ["x@example.com"] }, "invalid_request"],
			[{ action: "summary", tenant_id: "nope", days: 7 }, "invalid_tenant_id"],
		] as const) {
			expect(await call(body), JSON.stringify(body)).toMatchObject({ status: 400, body: { error } });
		}
		expect(await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 }, { summaryError: true })).toMatchObject({
			status: 503, body: { error: "report_unavailable" },
		});
		expect(await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 }, { triage: triage({ open: -1 }) })).toMatchObject({
			status: 503, body: { error: "report_invalid" },
		});
		expect(await call({ action: "summary", tenant_id: GOVERNANCE_TENANT, days: 7 }, { optionsError: true })).toMatchObject({
			status: 503, body: { error: "report_unavailable" },
		});
	});

	it("is registered with JWT verification, a contract test and no API-key path", () => {
		const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
		expect(config).toMatch(/\[functions\.reports\]\n(?:#[^\n]*\n)*verify_jwt = true/);
		expect(config).toMatch(/\[functions\.incidents\]\n(?:#[^\n]*\n)*verify_jwt = true/);
		expect(HANDLER_SOURCE).not.toContain("authenticateTenantApiKey");
		expect(HANDLER_SOURCE).toContain("checkIdentityBarrier(db, token, userId, tenantId)");
		expect(served).toHaveLength(1);
	});
});

describe("executive report builder", () => {
	const summary = parseGovernanceSummary(governanceSummaryFixture(7));

	it("says no action is needed only when nothing needs attention", () => {
		const calm = parseGovernanceSummary({
			...governanceSummaryFixture(7),
			approvals: { ...(governanceSummaryFixture(7).approvals as Row), expired_without_decision: 0 },
			oversight: { ...(governanceSummaryFixture(7).oversight as Row), review_prompts: 0 },
			usage: {
				...(governanceSummaryFixture(7).usage as Row),
				mcp_servers: { distinct: 6, not_approved: 0 },
			},
			policies: { ...(governanceSummaryFixture(7).policies as Row), runtime: { version: 7, updated_at: "2026-09-01T00:00:00Z", age_days: 30 } },
		});
		const quiet = parseTriageSummary(triage({ active_critical: 0, active_high: 0, unassigned_active: 0 }));
		const result = executiveSummary(calm, quiet, "en");
		expect(result.status).toBe("ok");
		expect(result.headlines[0].text).toMatch(/^No open critical or high incidents/);
		expect(executiveSummary(summary, parseTriageSummary(triage()), "en").status).toBe("attention");
	});

	it("formats Turkish numbers and durations, and English exactly as the summary e-mail always has", () => {
		const tr = reportSections(summary, parseTriageSummary(triage()), "tr");
		expect(tr.find((s) => s.title === "Ajan işlemleri için kararlar")?.lines[0]).toBe(
			"İzin verilen: 1.200 · onaya bekletilen: 40 · engellenen: 25",
		);
		expect(tr.find((s) => s.title === "Vakalar")?.lines[2]).toContain("ortanca kapanma süresi: 1,5 sa");
		const en = reportSections(summary, null, "en");
		expect(en.find((s) => s.title === "Incidents")?.lines).toHaveLength(1);
		expect(en.find((s) => s.title === "Policies")?.lines).toEqual([
			"Runtime policy v7, last changed 147 day(s) ago",
			"DLP policy v3, last changed 5 day(s) ago",
		]);
	});

	it("escapes the workspace name and carries no identities or notes", () => {
		const html = executiveReportDocument({
			language: "en",
			workspaceName: '<img src=x onerror="alert(1)">',
			periodFrom: "2026-10-07T00:00:00.000Z",
			periodTo: "2026-10-14T00:00:00.000Z",
			generatedAt: "2026-10-14T10:00:00.000Z",
			summary,
			triage: parseTriageSummary(triage()),
		});
		expect(html).not.toContain("<img");
		expect(html).toContain("&lt;img src=x");
		expect(html).toContain("not a certification");
		expect(html).toContain("default-src 'none'");
	});

	it("rejects malformed triage counts", () => {
		for (const broken of [triage({ open: -1 }), triage({ total: 1.5 }), triage({ median_close_seconds: "fast" }), null]) {
			expect(() => parseTriageSummary(broken)).toThrow();
		}
	});
});
