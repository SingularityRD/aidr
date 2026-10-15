// Incident triage for the dashboard's Security incidents page (E1).
//
// POST /incidents { action: "list" | "history" | "update", tenant_id, ... }
// Supabase session only.
//
// Every request: session -> identity barrier (tenant MFA/SSO policy, global
// revocation) -> live membership in an active tenant -> tenant rate limit.
// Reading (list, history) is open to every active member, viewers included,
// because the incidents themselves are. Changing triage (update) additionally
// needs owner/admin and AAL2, and goes through one service-role RPC that
// re-checks role and input under a tenant lock, applies optimistic
// concurrency and writes the history and admin audit rows in the same
// transaction. There is no API-key path, so no agent can triage, close or
// hide an incident. Triage never changes enforcement.
//
// Every failure is closed.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import {
	INCIDENT_TRIAGE_MAX_BODY_BYTES,
	incidentTriageErrorCode,
	incidentTriageRpcStatus,
	parseIncidentTriageRequest,
} from "../_shared/incident-triage.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const TRIAGE_COLUMNS = "event_id,status,owner_user_id,resolution_note,snoozed_until,version,updated_by,updated_at";
const HISTORY_COLUMNS =
	"id,event_id,actor_user_id,from_status,to_status,from_owner_user_id,to_owner_user_id,note,snoozed_until,version,self_closure,created_at";
const RATE_LIMITS = {
	read: { perSubject: 120, perTenant: 2_000 },
	write: { perSubject: 60, perTenant: 600 },
} as const;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type RpcError = { code?: string; message?: string } | null;

export interface IncidentsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => SupabaseClient;
	now?: () => number;
}

export function createIncidentsHandler(deps: IncidentsDeps = {}) {
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
		if (!config.ok) return configFailure("incidents", config.error, (status, body) => corsJson(req, status, body));
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, INCIDENT_TRIAGE_MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const request = parseIncidentTriageRequest(parsed.value, now());
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
				db.from("tenants").select("id,status").eq("id", tenantId).maybeSingle(),
			]);
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (
				!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
				!["owner", "admin", "member", "viewer"].includes(role) || !tenant
			) {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			if ((tenant as { status?: unknown }).status !== "active") {
				return corsJson(req, 409, { error: "workspace_not_active" });
			}
			if (command.action === "update") {
				if (role !== "owner" && role !== "admin") return corsJson(req, 403, { error: "incident_role_insufficient" });
				const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
				if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
				if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });
			}

			const bucket = command.action === "update" ? "write" : "read";
			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: `incidents:${bucket}`,
				...RATE_LIMITS[bucket],
				now: now(),
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			const headers = rateLimitHeaders(rate);

			if (command.action === "list") {
				const { data, error } = await db
					.from("incident_triage")
					.select(TRIAGE_COLUMNS)
					.eq("tenant_id", tenantId)
					.order("updated_at", { ascending: false })
					.limit(2000);
				if (error || !Array.isArray(data)) return corsJson(req, 503, { error: "incidents_unavailable" }, headers);
				return corsJson(req, 200, {
					ok: true,
					role,
					can_triage: role === "owner" || role === "admin",
					triage: data,
					now: new Date(now()).toISOString(),
				}, headers);
			}

			if (command.action === "history") {
				const { data, error } = await db
					.from("incident_triage_history")
					.select(HISTORY_COLUMNS)
					.eq("tenant_id", tenantId)
					.eq("event_id", command.eventId)
					.order("id", { ascending: false })
					.limit(200);
				if (error || !Array.isArray(data)) return corsJson(req, 503, { error: "incidents_unavailable" }, headers);
				return corsJson(req, 200, { ok: true, history: data }, headers);
			}

			const { data, error } = await db.rpc("update_incident_triage", {
				p_tenant_id: tenantId,
				p_actor_user_id: userId,
				p_event_id: command.eventId,
				p_expected_version: command.expectedVersion,
				p_fields: command.fields,
			});
			if (error) {
				const rpcError = error as RpcError;
				return corsJson(req, incidentTriageRpcStatus(rpcError?.code), {
					error: incidentTriageErrorCode(rpcError?.message) ?? "incidents_unavailable",
				}, headers);
			}
			if (typeof data !== "object" || data === null || Array.isArray(data)) {
				return corsJson(req, 503, { error: "incidents_unavailable" }, headers);
			}
			return corsJson(req, 200, { ok: true, triage: data }, headers);
		} catch {
			return corsJson(req, 503, { error: "incidents_unavailable" });
		}
	};
}

const incidents = createIncidentsHandler();
Deno.serve(incidents);
