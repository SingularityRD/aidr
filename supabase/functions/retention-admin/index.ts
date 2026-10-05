// Supabase Edge Function: GET|POST /v1/retention-admin
//
// Auth: Authorization: Bearer <supabase_access_token> + X-AIDR-Tenant-ID
//
// Tenant legal-hold management and per-tenant retention periods.
//   GET   active tenant owner or admin: hold history and retention policies with bounds.
//   POST  active tenant owner only: place_hold | release_hold | set_retention.
//
// Every write goes through a service-role RPC that re-verifies the active owner,
// validates the input, takes the shared tenant lock (seed 2606) and writes the
// change plus its admin_audit_logs row in one transaction. A hold REFUSED because
// a Storage deletion authorization is pending is reported as 409 and is NOT an
// active hold (see docs/production-readiness/retention-holds.md).

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CASE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/ #-]*$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const HOLD_PAGE = 50;
const DATA_CLASSES = new Set([
	"temporary_exports", "access_credentials", "telemetry", "endpoint_identity",
	"security_intelligence", "policy_configuration", "identity_membership",
	"commercial_records", "security_audit", "operational_ephemera",
]);

type Row = Record<string, unknown>;
// deno-lint-ignore no-explicit-any
type Db = SupabaseClient<any>;

export interface RetentionAdminDeps {
	/** Overrides the service-role client for the contract suite. */
	db?: Db;
}

type Command =
	| { action: "place_hold"; tenantId: string; caseId: string; owner: string; reason: string; reference: string | null }
	| { action: "release_hold"; tenantId: string; holdId: string; reason: string }
	| { action: "set_retention"; tenantId: string; dataClass: string; days: number; reason: string };

const noStore = (): Record<string, string> => ({ "Cache-Control": "no-store", Pragma: "no-cache" });

function uuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

function exactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
	const keys = Object.keys(value);
	return required.every((key) => keys.includes(key)) && keys.every((key) => required.includes(key) || optional.includes(key));
}

function text(value: unknown, max: number): string | null {
	if (typeof value !== "string" || value.length < 1 || value.length > max || value !== value.trim() || CONTROL.test(value)) return null;
	return value;
}

function parseCommand(value: unknown): Command | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const body = value as Record<string, unknown>;
	if (!uuid(body.tenant_id) || typeof body.action !== "string") return null;
	const tenantId = body.tenant_id;
	switch (body.action) {
		case "place_hold": {
			if (!exactKeys(body, ["action", "tenant_id", "case_id", "owner", "reason"], ["reference"])) return null;
			const caseId = text(body.case_id, 100);
			const owner = text(body.owner, 200);
			const reason = text(body.reason, 2000);
			const reference = body.reference === undefined ? null : text(body.reference, 200);
			if (!caseId || !CASE_ID.test(caseId) || !owner || !reason || (body.reference !== undefined && !reference)) return null;
			return { action: "place_hold", tenantId, caseId, owner, reason, reference };
		}
		case "release_hold": {
			if (!exactKeys(body, ["action", "tenant_id", "hold_id", "reason"])) return null;
			const reason = text(body.reason, 2000);
			return uuid(body.hold_id) && reason ? { action: "release_hold", tenantId, holdId: body.hold_id, reason } : null;
		}
		case "set_retention": {
			if (!exactKeys(body, ["action", "tenant_id", "data_class", "retention_days", "reason"])) return null;
			const reason = text(body.reason, 500);
			if (typeof body.data_class !== "string" || !DATA_CLASSES.has(body.data_class) || !reason) return null;
			if (typeof body.retention_days !== "number" || !Number.isSafeInteger(body.retention_days) || body.retention_days < 0 || body.retention_days > 3650) return null;
			return { action: "set_retention", tenantId, dataClass: body.data_class, days: body.retention_days, reason };
		}
		default:
			return null;
	}
}

function rpcFailure(req: Request, error: unknown): Response {
	const result = error && typeof error === "object" ? error as { code?: unknown; message?: unknown } : {};
	const message = typeof result.message === "string" ? result.message : "";
	const code = typeof result.code === "string" ? result.code : "";
	if (message.includes("retention_admin_owner_required")) return corsJson(req, 403, { error: "owner_required" }, noStore());
	if (message.includes("legal_hold_invalid_request") || message.includes("retention_invalid_request")) {
		return corsJson(req, 400, { error: "invalid_request" }, noStore());
	}
	if (message.includes("retention_days_out_of_bounds")) return corsJson(req, 400, { error: "retention_days_out_of_bounds" }, noStore());
	if (message.includes("retention_class_not_configurable")) return corsJson(req, 400, { error: "retention_class_not_configurable" }, noStore());
	if (message.includes("legal_hold_already_active") || (code === "23505" && message.includes("legal_hold"))) {
		return corsJson(req, 409, { error: "hold_already_active" }, noStore());
	}
	if (message.includes("legal_hold_refused_pending_")) {
		// Not an active hold: operators must treat this as an urgent unresolved request.
		return corsJson(req, 409, { error: "hold_refused_pending_deletion", hold_active: false }, noStore());
	}
	if (message.includes("retention_change_refused_offboarding")) return corsJson(req, 409, { error: "retention_change_refused_offboarding" }, noStore());
	return corsJson(req, 503, { error: "retention_management_unavailable" }, noStore());
}

function holdCursor(url: URL): { placedAt: string; id: string } | null | undefined {
	const placedAt = url.searchParams.getAll("hold_after_placed_at");
	const id = url.searchParams.getAll("hold_after_id");
	if (placedAt.length > 1 || id.length > 1) return undefined;
	if (placedAt.length === 0 && id.length === 0) return null;
	if (placedAt.length !== 1 || id.length !== 1 || !uuid(id[0])
		|| !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(placedAt[0])
		|| !Number.isFinite(Date.parse(placedAt[0]))) return undefined;
	return { placedAt: placedAt[0], id: id[0] };
}

function activeMember(value: unknown, roles: string[]): boolean {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as Row;
	if (typeof row.role !== "string" || !roles.includes(row.role)) return false;
	if (row.expires_at !== null && (typeof row.expires_at !== "string" || !Number.isFinite(Date.parse(row.expires_at)))) return false;
	return membershipActive({ role: row.role, expires_at: row.expires_at as string | null });
}

export function createRetentionAdminHandler(deps: RetentionAdminDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") {
			return corsJson(req, 405, { error: "method_not_allowed" }, { ...noStore(), Allow: "GET, POST" });
		}
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("retention-admin", config.error, (status, body) => corsJson(req, status, body, noStore()));

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" }, noStore());
		try {
			const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" }, noStore());
			const userId = auth.user.id;
			const globalIdentity = await checkIdentityBarrier(db, token, userId);
			if (!globalIdentity.ok) return corsJson(req, globalIdentity.status, { error: globalIdentity.error }, noStore());

			const rawHeaderTenant = req.headers.get("X-AIDR-Tenant-ID");
			const headerTenant = rawHeaderTenant?.trim();
			let command: Command | null = null;
			let tenantId: string;
			if (req.method === "GET") {
				if (!uuid(headerTenant) || headerTenant !== rawHeaderTenant) return corsJson(req, 400, { error: "invalid_tenant" }, noStore());
				tenantId = headerTenant;
			} else {
				const parsed = await readBoundedJson(req, 16_384);
				if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error }, noStore());
				command = parseCommand(parsed.value);
				if (!command) return corsJson(req, 400, { error: "invalid_request" }, noStore());
				tenantId = command.tenantId;
				if (rawHeaderTenant && (headerTenant !== rawHeaderTenant || headerTenant !== tenantId)) {
					return corsJson(req, 400, { error: "tenant_mismatch" }, noStore());
				}
			}

			const tenantIdentity = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error }, noStore());
			const { data: member, error: memberError } = await db.from("tenant_members")
				.select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
			const { data: tenant, error: tenantError } = await db.from("tenants")
				.select("status").eq("id", tenantId).maybeSingle();
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" }, noStore());
			const allowed = activeMember(member, req.method === "GET" ? ["owner", "admin"] : ["owner"]);
			if (!allowed || (tenant as Row | null)?.status !== "active") {
				return corsJson(req, 403, { error: req.method === "GET" ? "admin_required" : "owner_required" }, noStore());
			}
			const quota = await consumeTenantRateLimit(db, {
				tenantId, subject: userId, endpoint: "retention-admin", perSubject: 30, perTenant: 120,
			});
			if (!quota.ok) return corsJson(req, quota.status, { error: quota.error }, { ...noStore(), ...rateLimitHeaders(quota) });

			if (req.method === "GET") {
				const cursor = holdCursor(new URL(req.url));
				if (cursor === undefined) return corsJson(req, 400, { error: "invalid_pagination" }, noStore());
				let holdQuery = db.from("tenant_legal_holds")
					.select("id,hold_reference,case_id,hold_owner,reason,placed_by,placed_at,released_by,released_at,release_reason")
					.eq("tenant_id", tenantId);
				if (cursor) holdQuery = holdQuery.or(`placed_at.lt.${cursor.placedAt},and(placed_at.eq.${cursor.placedAt},id.gt.${cursor.id})`);
				const [holds, policies, bounds] = await Promise.all([
					holdQuery.order("placed_at", { ascending: false }).order("id", { ascending: true }).limit(HOLD_PAGE + 1),
					db.from("tenant_data_retention_policies").select("data_class,retention_days,updated_at,updated_by").eq("tenant_id", tenantId),
					db.from("retention_policy_bounds").select("data_class,min_days,max_days,tenant_configurable"),
				]);
				if (holds.error || policies.error || bounds.error) return corsJson(req, 503, { error: "retention_management_unavailable" }, noStore());
				const holdRows = (holds.data ?? []) as Row[];
				const boundsByClass = new Map(((bounds.data ?? []) as Row[]).map((row) => [String(row.data_class), row]));
				const retention = ((policies.data ?? []) as Row[]).map((row) => {
					const bound = boundsByClass.get(String(row.data_class));
					return {
						data_class: row.data_class,
						retention_days: row.retention_days,
						min_days: bound?.min_days ?? null,
						max_days: bound?.max_days ?? null,
						configurable: bound?.tenant_configurable === true,
						updated_at: row.updated_at ?? null,
						updated_by: row.updated_by ?? null,
					};
				}).sort((a, b) => String(a.data_class).localeCompare(String(b.data_class)));
				const page = holdRows.slice(0, HOLD_PAGE);
				return corsJson(req, 200, {
					ok: true,
					holds: page,
					active_hold: page.find((row) => row.released_at === null) ?? null,
					next_hold_cursor: holdRows.length > HOLD_PAGE
						? { placed_at: page[HOLD_PAGE - 1].placed_at, id: page[HOLD_PAGE - 1].id } : null,
					retention_policies: retention,
				}, noStore());
			}

			if (command?.action === "place_hold") {
				const { data, error } = await db.rpc("admin_place_tenant_legal_hold", {
					p_tenant_id: tenantId, p_actor_user_id: userId, p_case_id: command.caseId,
					p_hold_owner: command.owner, p_reason: command.reason, p_hold_reference: command.reference,
				});
				if (error) return rpcFailure(req, error);
				if (!uuid(data)) return corsJson(req, 503, { error: "retention_management_unavailable" }, noStore());
				return corsJson(req, 201, { ok: true, hold_id: data }, noStore());
			}
			if (command?.action === "release_hold") {
				const { data, error } = await db.rpc("admin_release_tenant_legal_hold", {
					p_tenant_id: tenantId, p_actor_user_id: userId, p_hold_id: command.holdId, p_release_reason: command.reason,
				});
				if (error) return rpcFailure(req, error);
				if (data !== true) return corsJson(req, 404, { error: "hold_not_found_or_released" }, noStore());
				return corsJson(req, 200, { ok: true }, noStore());
			}
			if (command?.action === "set_retention") {
				const { data, error } = await db.rpc("admin_set_tenant_retention", {
					p_tenant_id: tenantId, p_actor_user_id: userId, p_data_class: command.dataClass,
					p_retention_days: command.days, p_reason: command.reason,
				});
				if (error) return rpcFailure(req, error);
				const result = data && typeof data === "object" && !Array.isArray(data) ? data as Row : null;
				if (!result || typeof result.changed !== "boolean" || !Number.isSafeInteger(result.retention_days)) {
					return corsJson(req, 503, { error: "retention_management_unavailable" }, noStore());
				}
				return corsJson(req, 200, {
					ok: true,
					data_class: result.data_class,
					retention_days: result.retention_days,
					previous_retention_days: result.previous_retention_days,
					changed: result.changed,
				}, noStore());
			}
			return corsJson(req, 400, { error: "invalid_request" }, noStore());
		} catch {
			return corsJson(req, 503, { error: "retention_management_unavailable" }, noStore());
		}
	};
}

Deno.serve(createRetentionAdminHandler());
