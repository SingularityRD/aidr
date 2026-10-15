// Executive report and team rollup (E6).
//
// POST { action: "summary",  tenant_id, days: 7 | 30 | 90, language? }
//   Executive summary of one workspace: counts-only summary, incident triage
//   counts, headlines in English or Turkish and the scheduled-report options.
// POST { action: "rollup",   tenant_id, days }
//   One row of counts per workspace the caller administers (owner or admin of
//   an active workspace, at most 50). Each workspace's identity barrier is
//   checked against the caller's session; a workspace whose MFA/SSO policy the
//   session does not meet is listed by name only, without figures.
// POST { action: "document", tenant_id, days, language, include_teams }
//   The printable executive report (self-contained HTML, the same document the
//   scheduled summary attaches), returned for download.
// POST { action: "set_options", tenant_id, language, attachment }
//   Language and attachment choice of the scheduled summary. AAL2.
//
// Every request: session -> identity barrier -> active owner/admin membership
// in an active workspace -> tenant rate limit. Every read is counts, enums and
// workspace names only (see _shared/executive-report.ts). Every failure is
// closed: an unreadable summary is an error, never a page of zeros.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import {
	ExecutiveReportError,
	executiveReportDocument,
	executiveSummary,
	parseTriageSummary,
	type ReportLanguage,
	reportFileName,
	reportSections,
	type TeamRollupRow,
	teamRollupFigures,
	type TriageSummary,
} from "../_shared/executive-report.ts";
import { GovernanceDigestError, type GovernanceSummary, parseGovernanceSummary } from "../_shared/governance-digest.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const WINDOWS = [7, 30, 90] as const;
const DAY_MS = 86_400_000;
export const REPORT_RATE_LIMITS = Object.freeze({
	read: { perSubject: 30, perTenant: 120 },
	write: { perSubject: 10, perTenant: 30 },
});

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type Window = (typeof WINDOWS)[number];
type Command =
	| { action: "summary"; days: Window; language: ReportLanguage | null }
	| { action: "rollup"; days: Window }
	| { action: "document"; days: Window; language: ReportLanguage; includeTeams: boolean }
	| { action: "set_options"; language: ReportLanguage; attachment: boolean };

export interface ReportsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => SupabaseClient;
	now?: () => number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

const isWindow = (value: unknown): value is Window => WINDOWS.includes(value as Window);
const isLanguage = (value: unknown): value is ReportLanguage => value === "en" || value === "tr";

export function parseReportsRequest(
	value: unknown,
): { ok: true; tenantId: string; command: Command } | { ok: false; error: string } {
	if (!isRecord(value)) return { ok: false, error: "invalid_request" };
	if (typeof value.tenant_id !== "string" || !UUID.test(value.tenant_id)) return { ok: false, error: "invalid_tenant_id" };
	const tenantId = value.tenant_id.toLowerCase();
	switch (value.action) {
		case "summary":
			if (!onlyKeys(value, ["action", "tenant_id", "days"], ["language"])) return { ok: false, error: "invalid_request" };
			if (!isWindow(value.days)) return { ok: false, error: "invalid_window" };
			if (value.language !== undefined && !isLanguage(value.language)) return { ok: false, error: "invalid_language" };
			return { ok: true, tenantId, command: { action: "summary", days: value.days, language: value.language ?? null } };
		case "rollup":
			if (!onlyKeys(value, ["action", "tenant_id", "days"])) return { ok: false, error: "invalid_request" };
			if (!isWindow(value.days)) return { ok: false, error: "invalid_window" };
			return { ok: true, tenantId, command: { action: "rollup", days: value.days } };
		case "document":
			if (!onlyKeys(value, ["action", "tenant_id", "days", "language", "include_teams"])) {
				return { ok: false, error: "invalid_request" };
			}
			if (!isWindow(value.days)) return { ok: false, error: "invalid_window" };
			if (!isLanguage(value.language)) return { ok: false, error: "invalid_language" };
			if (typeof value.include_teams !== "boolean") return { ok: false, error: "invalid_request" };
			return {
				ok: true,
				tenantId,
				command: { action: "document", days: value.days, language: value.language, includeTeams: value.include_teams },
			};
		case "set_options":
			if (!onlyKeys(value, ["action", "tenant_id", "language", "attachment"])) return { ok: false, error: "invalid_request" };
			if (!isLanguage(value.language)) return { ok: false, error: "invalid_language" };
			if (typeof value.attachment !== "boolean") return { ok: false, error: "invalid_request" };
			return { ok: true, tenantId, command: { action: "set_options", language: value.language, attachment: value.attachment } };
		default:
			return { ok: false, error: "invalid_action" };
	}
}

/** Whole UTC days ending now, like the governance scorecard window. */
export function reportWindow(days: Window, nowMs: number): { from: string; to: string } {
	const today = Math.floor(nowMs / DAY_MS) * DAY_MS;
	return { from: new Date(today - (days - 1) * DAY_MS).toISOString(), to: new Date(nowMs).toISOString() };
}

class ReadFailure extends Error {}

/** Summary and triage counts of one workspace; throws ReadFailure when unreadable. */
async function workspaceFigures(
	db: SupabaseClient,
	tenantId: string,
	window: { from: string; to: string },
): Promise<{ summary: GovernanceSummary; triage: TriageSummary }> {
	const [summaryRead, triageRead] = await Promise.all([
		db.rpc("governance_digest_summary", { p_tenant_id: tenantId, p_from: window.from, p_to: window.to }),
		db.rpc("incident_triage_summary", { p_tenant_id: tenantId, p_from: window.from, p_to: window.to }),
	]);
	if (summaryRead.error || triageRead.error) throw new ReadFailure("report_unavailable");
	try {
		return { summary: parseGovernanceSummary(summaryRead.data), triage: parseTriageSummary(triageRead.data) };
	} catch (cause) {
		if (cause instanceof GovernanceDigestError || cause instanceof ExecutiveReportError) {
			console.error("[reports] summary rejected", JSON.stringify({ path: cause.path }));
			throw new ReadFailure("report_invalid");
		}
		throw cause;
	}
}

async function teamRollup(
	db: SupabaseClient,
	token: string,
	userId: string,
	window: { from: string; to: string },
): Promise<TeamRollupRow[]> {
	const { data, error } = await db.rpc("executive_report_teams", { p_actor_user_id: userId });
	if (error || !Array.isArray(data) || data.length > 50) throw new ReadFailure("report_unavailable");
	const rows: TeamRollupRow[] = [];
	for (const item of data) {
		if (
			!isRecord(item) || typeof item.tenant_id !== "string" || !UUID.test(item.tenant_id) ||
			typeof item.name !== "string" || (item.role !== "owner" && item.role !== "admin")
		) {
			throw new ReadFailure("report_invalid");
		}
		const tenantId = item.tenant_id.toLowerCase();
		const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
		if (!barrier.ok && barrier.status === 503) throw new ReadFailure("report_unavailable");
		if (!barrier.ok) {
			rows.push({ tenantId, name: item.name, role: item.role, figures: null });
			continue;
		}
		const { summary, triage } = await workspaceFigures(db, tenantId, window);
		rows.push({ tenantId, name: item.name, role: item.role, figures: teamRollupFigures(summary, triage) });
	}
	return rows;
}

async function reportOptions(
	db: SupabaseClient,
	tenantId: string,
): Promise<{ language: ReportLanguage; attachment: boolean; digestEnabled: boolean; digestCadence: string }> {
	const { data, error } = await db
		.from("tenant_governance_settings")
		.select("digest_language,digest_attachment,digest_enabled,digest_cadence")
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (error) throw new ReadFailure("report_unavailable");
	const row = (data ?? {}) as Record<string, unknown>;
	return {
		language: isLanguage(row.digest_language) ? row.digest_language : "en",
		attachment: typeof row.digest_attachment === "boolean" ? row.digest_attachment : true,
		digestEnabled: row.digest_enabled === true,
		digestCadence: row.digest_cadence === "monthly" ? "monthly" : "weekly",
	};
}

export function createReportsHandler(deps: ReportsDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("reports", config.error, (status, body) => corsJson(req, status, body));
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const request = parseReportsRequest(parsed.value);
		if (!request.ok) return corsJson(req, 400, { error: request.error });
		const { tenantId, command } = request;

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
				db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
				db.from("tenants").select("id,name,status").eq("id", tenantId).maybeSingle(),
			]);
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (
				!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
				!["owner", "admin", "member", "viewer"].includes(role) || !tenant
			) {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			if (role !== "owner" && role !== "admin") return corsJson(req, 403, { error: "report_role_insufficient" });
			if ((tenant as { status?: unknown }).status !== "active") return corsJson(req, 409, { error: "workspace_not_active" });
			if (command.action === "set_options") {
				const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
				if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
				if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });
			}

			const bucket = command.action === "set_options" ? "write" : "read";
			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: `reports:${bucket}`,
				...REPORT_RATE_LIMITS[bucket],
				now: now(),
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			const headers = rateLimitHeaders(rate);
			const workspaceName = String((tenant as { name?: unknown }).name ?? "");

			try {
				if (command.action === "set_options") {
					const { data, error } = await db.rpc("set_governance_report_options", {
						p_tenant_id: tenantId,
						p_actor_user_id: userId,
						p_language: command.language,
						p_attachment: command.attachment,
					});
					if (error) {
						const status = error.code === "42501" ? 403 : error.code === "22023" ? 400 : 503;
						return corsJson(req, status, { error: status === 503 ? "report_unavailable" : "report_options_refused" }, headers);
					}
					if (!isRecord(data)) return corsJson(req, 503, { error: "report_unavailable" }, headers);
					return corsJson(req, 200, {
						ok: true,
						options: { language: data.digest_language, attachment: data.digest_attachment },
					}, headers);
				}

				const window = reportWindow(command.days, now());
				if (command.action === "rollup") {
					const teams = await teamRollup(db, token, userId, window);
					return corsJson(req, 200, { ok: true, period: window, teams }, headers);
				}

				const { summary, triage } = await workspaceFigures(db, tenantId, window);
				if (command.action === "document") {
					const teams = command.includeTeams ? await teamRollup(db, token, userId, window) : undefined;
					const html = executiveReportDocument({
						language: command.language,
						workspaceName,
						periodFrom: window.from,
						periodTo: window.to,
						generatedAt: new Date(now()).toISOString(),
						summary,
						triage,
						teams,
					});
					return corsJson(req, 200, {
						ok: true,
						filename: reportFileName(command.language, window.to),
						content_type: "text/html; charset=utf-8",
						html,
					}, headers);
				}

				const options = await reportOptions(db, tenantId);
				const language = command.language ?? options.language;
				return corsJson(req, 200, {
					ok: true,
					period: window,
					language,
					options,
					executive: executiveSummary(summary, triage, language),
					sections: reportSections(summary, triage, language),
					triage,
				}, headers);
			} catch (cause) {
				if (cause instanceof ReadFailure) return corsJson(req, 503, { error: cause.message }, headers);
				throw cause;
			}
		} catch {
			return corsJson(req, 503, { error: "report_unavailable" });
		}
	};
}

const reports = createReportsHandler();
Deno.serve(reports);
