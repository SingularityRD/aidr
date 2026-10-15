// Supabase Edge Function: /v1/fleet-keys
//
// Auth: Authorization: Bearer <supabase_access_token>; X-AIDR-Tenant-ID selects
// the team. Only active owners/admins of an active tenant may list, create or
// revoke fleet enrollment keys.
//
//   GET                                   -> { ok, keys: [...] } (no secrets)
//   POST { action: "create", label?, seat_cap, ttl_days? }
//                                         -> { ok, fleet_key, id, expires_at } (plaintext shown once)
//   POST { action: "revoke", id }         -> { ok, id, revoked_at }
//
// Issue and revoke run in one RPC with their admin_audit_logs row; the
// plaintext is never stored (SHA-256 hash plus a 4-character hint only).

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { fleetKeyHint, randomFleetKey, validateFleetKeyCreate } from "../_shared/fleet-keys.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeRateLimit, type RateLimitDb, validRateLimit } from "../_shared/rate-limit.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 8 * 1024;
const RECORD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CREATE_RL_PER_MIN = Number(Deno.env.get("AIDR_FLEETKEY_CREATE_RL_PER_MIN") ?? "10");
const LIST_COLUMNS =
	"id,label,key_hint,seat_cap,enrolled_count,use_count,expires_at,created_at,created_by,last_used_at,revoked_at";

type Client = ReturnType<typeof createClient<any, "public">>;
type RpcResult = { data: unknown; error: unknown | null };

function getBearerToken(req: Request): string | null {
	const m = (req.headers.get("Authorization") ?? "").match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

async function resolveAdminTenant(supabase: Client, userId: string, req: Request): Promise<string | null> {
	const requested = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim() || userId;
	if (!TENANT_ID.test(requested)) return null;
	const { data, error } = await supabase
		.from("tenant_members")
		.select("tenant_id,expires_at,role")
		.eq("tenant_id", requested)
		.eq("user_id", userId)
		.maybeSingle();
	if (error || !data?.tenant_id || !membershipActive(data)) return null;
	if (!["owner", "admin"].includes(String(data.role))) return null;
	const state = await supabase.from("tenants").select("status").eq("id", requested).maybeSingle();
	if (state.error || state.data?.status !== "active") return null;
	return String(data.tenant_id);
}

// Fail closed: an unavailable or misconfigured counter refuses issuance.
async function createBudget(supabase: Client, tenantId: string, userId: string): Promise<"allowed" | "limited" | "unavailable"> {
	if (!validRateLimit(CREATE_RL_PER_MIN, 1_000)) return "unavailable";
	const result = await consumeRateLimit(supabase as unknown as RateLimitDb, `fleetkey_create:${tenantId}:${userId}`, CREATE_RL_PER_MIN);
	return result.status;
}

async function rpcOnceRetried(supabase: Client, name: string, args: Record<string, unknown>): Promise<RpcResult> {
	let result: RpcResult = { data: null, error: { message: "not_called" } };
	for (let attempt = 0; attempt < 2; attempt++) {
		result = await supabase.rpc(name, args);
		if (!result.error) break;
	}
	return result;
}

function errorCode(error: unknown): string | null {
	return error && typeof error === "object" && "code" in error ? String((error as { code: unknown }).code) : null;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("fleet-keys", config.error, (status, body) => corsJson(req, status, body));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const accessToken = getBearerToken(req);
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = userData.user.id;
	const tenantId = await resolveAdminTenant(supabase, userId, req);
	if (!tenantId) return corsJson(req, 403, { error: "tenant_admin_required" });
	const identity = await checkIdentityBarrier(supabase, accessToken, userId, tenantId);
	if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });

	if (req.method === "GET") {
		const { data, error } = await supabase
			.from("fleet_enrollment_keys")
			.select(LIST_COLUMNS)
			.eq("tenant_id", tenantId)
			.order("created_at", { ascending: false })
			.limit(200);
		if (error) return corsJson(req, 500, { error: "db_error" });
		return corsJson(req, 200, { ok: true, keys: data ?? [] });
	}

	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

	const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
	if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
		return corsJson(req, 400, { error: "invalid_json" });
	}
	const body = parsed.value as Record<string, unknown>;
	const action = typeof body.action === "string" ? body.action : "create";

	if (action === "revoke") {
		const id = typeof body.id === "string" ? body.id.trim() : "";
		if (!RECORD_ID.test(id)) return corsJson(req, 400, { error: "invalid_id" });
		const mutation = await rpcOnceRetried(supabase, "revoke_fleet_enrollment_key_with_audit", {
			p_actor_user_id: userId,
			p_tenant_id: tenantId,
			p_id: id,
		});
		if (mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
		const result = mutation.data as { status?: string; revoked_at?: string };
		if (result?.status === "not_found") return corsJson(req, 404, { error: "fleet_key_not_found" });
		if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_admin_required" });
		if (result?.status !== "revoked") return corsJson(req, 409, { error: "fleet_key_revoke_conflict" });
		return corsJson(req, 200, { ok: true, id, revoked_at: result.revoked_at ?? null });
	}

	if (action !== "create") return corsJson(req, 400, { error: "invalid_action" });

	const request = validateFleetKeyCreate(body);
	if (!request.ok) return corsJson(req, 400, { error: request.error });
	const budget = await createBudget(supabase, tenantId, userId);
	if (budget === "limited") return corsJson(req, 429, { error: "rate_limited" });
	if (budget !== "allowed") return corsJson(req, 503, { error: "rate_limit_unavailable" });

	for (let i = 0; i < 5; i++) {
		const fleetKey = randomFleetKey();
		const mutation = await rpcOnceRetried(supabase, "issue_fleet_enrollment_key_with_audit", {
			p_actor_user_id: userId,
			p_tenant_id: tenantId,
			p_label: request.value.label,
			p_seat_cap: request.value.seatCap,
			p_ttl_days: request.value.ttlDays,
			p_key_hash: await sha256(fleetKey),
			p_key_hint: fleetKeyHint(fleetKey),
		});
		if (errorCode(mutation.error) === "42501") return corsJson(req, 403, { error: "tenant_not_admitted" });
		if (mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
		const result = mutation.data as { status?: string; id?: string; expires_at?: string; active_keys?: number };
		if (result?.status === "hash_conflict") continue;
		if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_admin_required" });
		if (result?.status === "too_many_active_keys") {
			return corsJson(req, 409, { error: "too_many_active_fleet_keys", active_keys: result.active_keys ?? null });
		}
		if (result?.status !== "issued" || !result.id || !result.expires_at) break;
		return corsJson(req, 200, {
			ok: true,
			fleet_key: fleetKey,
			id: result.id,
			expires_at: result.expires_at,
			seat_cap: request.value.seatCap,
		});
	}
	return corsJson(req, 500, { error: "fleet_key_issue_failed" });
});
