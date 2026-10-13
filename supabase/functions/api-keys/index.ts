// Supabase Edge Function: /v1/api-keys
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Provides an auditable API key create/revoke surface for the dashboard.
//
// Two key types (supabase/migrations/20260925000061_browser_guard_ingest_keys.sql):
//   tenant                full tenant credential for endpoint connectors (default)
//   ingest:browser_guard  Browser Guard telemetry only; owners/admins issue it
//                         with an explicit installation limit.
//
// Hygiene (supabase/migrations/20261013000510_api_key_expiry_and_label_bounds.sql):
//   * Every key carries a prefix that matches its type (`aidr_live_` tenant,
//     `aidr_ingest_` Browser Guard), including after rotation.
//   * Keys expire: `expires_in_days` (1..730) sets the lifetime, an explicit
//     `null` asks for a non-expiring key, and omitting it applies
//     AIDR_APIKEY_DEFAULT_TTL_DAYS (default 365). Renewal applies the same rule
//     and refuses to revive an expired key.
//   * Labels are 1..100 characters with no control characters.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { ConfigurationError, configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { boundedOverlapHours } from "../_shared/key-rotation.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { apiKeyPrefix, DEFAULT_TTL_ENV, defaultKeyTtlDays, parseLabel, resolveExpiry } from "./hygiene.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

// Credential row ids are UUIDs; anything else is a client error, not a storage or audit outage.
const RECORD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const BROWSER_GUARD_INGEST_SCOPE = "ingest:browser_guard";
// Same bounds as the api_keys_scope_check constraint.
const MAX_INSTALL_LIMIT = 100_000;

type CreateRequest =
	| { scope: "tenant" }
	| { scope: typeof BROWSER_GUARD_INGEST_SCOPE; installLimit: number };

/** Validate the requested key type; an unknown type is refused, never widened. */
function parseCreateRequest(
	body: Record<string, unknown>,
): { ok: true; value: CreateRequest } | { ok: false; error: string } {
	const scope = body.scope ?? "tenant";
	if (scope === "tenant") {
		return body.install_limit === undefined || body.install_limit === null
			? { ok: true, value: { scope } }
			: { ok: false, error: "invalid_install_limit" };
	}
	if (scope !== BROWSER_GUARD_INGEST_SCOPE) return { ok: false, error: "invalid_scope" };
	const limit = body.install_limit;
	if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_INSTALL_LIMIT) {
		return { ok: false, error: "invalid_install_limit" };
	}
	return { ok: true, value: { scope, installLimit: limit } };
}

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 8 * 1024;

const CREATE_RL_PER_MIN = Number(Deno.env.get("AIDR_APIKEY_CREATE_RL_PER_MIN") ?? "10");

// How long the retired hash stays accepted after a renewal. Clamped to the
// reviewed 1 hour .. 7 day range (see _shared/key-rotation.ts) and enforced
// again by the `api_keys_rotation_window_check` database constraint.
const RENEW_OVERLAP_HOURS = Deno.env.get("AIDR_APIKEY_RENEW_OVERLAP_HOURS") ?? "24";

// Default lifetime of a dashboard-issued key; validated per request (fail closed).
const DEFAULT_TTL_DAYS_RAW = Deno.env.get(DEFAULT_TTL_ENV);

type RateLimitRow = { count: number | null };

async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const bytes = new Uint8Array(digest);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function bytesToBase64(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}

function base64Url(bytes: Uint8Array): string {
	const b64 = bytesToBase64(bytes);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function randomApiKey(scope: CreateRequest["scope"]): string {
	const raw = new Uint8Array(32);
	crypto.getRandomValues(raw);
	// The prefix makes an ingest key recognisable where it is deployed (browser policy).
	return `${apiKeyPrefix(scope)}${base64Url(raw)}`;
}

async function resolveTenant(
	supabase: ReturnType<typeof createClient<any, "public">>,
	userId: string,
	req: Request,
): Promise<{ id: string; role: string } | null> {
	const requested = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim() || userId;
	if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requested)) return null;
	const { data } = await supabase
		.from("tenant_members")
		.select("tenant_id,expires_at,role")
		.eq("tenant_id", requested)
		.eq("user_id", userId)
		.maybeSingle();
	if (!data?.tenant_id || !membershipActive(data)) return null;
	const state = await supabase.from("tenants").select("status").eq("id", requested).maybeSingle();
	if (state.error || state.data?.status !== "active") return null;
	return { id: String(data.tenant_id), role: String(data.role ?? "viewer") };
}

async function rateLimitCreate(
	supabase: ReturnType<typeof createClient<any, "public">>,
	userId: string,
): Promise<boolean> {
	const nowMin = Math.floor(Date.now() / 60000);
	const key = `apikey_create:${userId}`;
	const { error } = await supabase.rpc("increment_rate_limit", {
		p_key: key,
		p_window_start: nowMin,
		p_delta: 1,
	});
	if (error) return false;
	const { data, error: countError } = await supabase
		.from("rate_limits")
		.select("count")
		.eq("key", key)
		.eq("window_start", nowMin)
		.maybeSingle();
	if (countError) return false;
	const row = data as RateLimitRow | null;
	const count = row?.count;
	return Number.isSafeInteger(CREATE_RL_PER_MIN) && CREATE_RL_PER_MIN > 0
		&& typeof count === "number" && Number.isSafeInteger(count) && count > 0 && count <= CREATE_RL_PER_MIN;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("api-keys", config.error, (status, body) => corsJson(req, status, body));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;
	const defaultTtlDays = defaultKeyTtlDays(DEFAULT_TTL_DAYS_RAW);
	if (defaultTtlDays === null) {
		return configFailure("api-keys", new ConfigurationError({ invalid: [DEFAULT_TTL_ENV] }), (status, body) =>
			corsJson(req, status, body));
	}

	const accessToken = getBearerToken(req.headers.get("Authorization"));
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = userData.user.id;
	const tenant = await resolveTenant(supabase, userId, req);
	if (!tenant) return corsJson(req, 403, { error: "tenant_not_authorized" });
	const identity = await checkIdentityBarrier(supabase, accessToken, userId, tenant.id);
	if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
	const canWrite = ["owner", "admin", "member"].includes(tenant.role);

	if (req.method === "GET") {
		let query = supabase
			.from("api_keys")
			.select("id,label,revoked,created_at,scope,install_limit,expires_at,rotated_at")
			.eq("tenant_id", tenant.id);
		if (!["owner", "admin"].includes(tenant.role)) query = query.eq("user_id", userId);
		const { data, error } = await query.order("created_at", { ascending: false }).limit(200);
		if (error) return corsJson(req, 500, { error: "db_error" });
		return corsJson(req, 200, { ok: true, keys: data ?? [] });
	}

	if (req.method === "POST") {
		if (!canWrite) return corsJson(req, 403, { error: "tenant_role_insufficient" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value))
			return corsJson(req, 400, { error: "invalid_json" });
		const body = parsed.value as Record<string, unknown>;
		const action = typeof body.action === "string" ? body.action : "create";
		if (!["create", "revoke", "renew"].includes(action)) return corsJson(req, 400, { error: "invalid_action" });

		if (action === "revoke") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return corsJson(req, 400, { error: "missing_id" });
			if (!RECORD_ID.test(id)) return corsJson(req, 400, { error: "invalid_id" });
			let mutation: { data: unknown; error: unknown | null } | null = null;
			for (let attempt = 0; attempt < 2; attempt++) {
				mutation = await supabase.rpc("revoke_api_key_with_audit", {
					p_actor_user_id: userId,
					p_tenant_id: tenant.id,
					p_id: id,
				});
				if (!mutation.error) break;
			}
			if (!mutation || mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
			const result = mutation.data as { status?: string };
			if (result?.status === "not_found") return corsJson(req, 404, { error: "key_not_found_or_not_owned" });
			if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_not_authorized" });
			if (result?.status !== "revoked") return corsJson(req, 409, { error: "key_revoke_conflict" });
			return corsJson(req, 200, { ok: true });
		}

		// renew
		if (action === "renew") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return corsJson(req, 400, { error: "missing_id" });
			if (!RECORD_ID.test(id)) return corsJson(req, 400, { error: "invalid_id" });
			const expiry = resolveExpiry(body, defaultTtlDays);
			if (!expiry.ok) return corsJson(req, 400, { error: "invalid_expiry" });
			const ok = await rateLimitCreate(supabase, `${tenant.id}:${userId}`);
			if (!ok) return corsJson(req, 429, { error: "rate_limited" });

			let read = supabase
				.from("api_keys")
				.select("id,key_hash,revoked,scope,expires_at")
				.eq("id", id)
				.eq("tenant_id", tenant.id);
			if (tenant.role === "member") read = read.eq("user_id", userId);
			const { data: current, error: readError } = await read.maybeSingle();
			if (readError) return corsJson(req, 500, { error: "db_error" });
			if (!current?.id) return corsJson(req, 404, { error: "key_not_found_or_not_owned" });
			// A revoked key must never come back through a rotation.
			if (current.revoked === true) return corsJson(req, 409, { error: "key_revoked" });
			// The renewed secret keeps the row's type, so it must carry that type's prefix.
			const scope = current.scope;
			if (scope !== "tenant" && scope !== BROWSER_GUARD_INGEST_SCOPE) {
				return corsJson(req, 500, { error: "key_scope_unavailable" });
			}
			if (typeof current.expires_at === "string" && Date.parse(current.expires_at) <= Date.now()) {
				return corsJson(req, 409, { error: "key_expired" });
			}
			const currentHash = typeof current.key_hash === "string" ? current.key_hash : "";
			if (!/^[a-f0-9]{64}$/.test(currentHash)) return corsJson(req, 500, { error: "key_hash_unavailable" });

			const overlapHours = boundedOverlapHours(RENEW_OVERLAP_HOURS);
			let apiKey = "";
			let rotated = false;
			let previousSecretValidUntil: string | null = null;
			let expiresAt: string | null = null;
			for (let i = 0; i < 5; i++) {
				apiKey = randomApiKey(scope);
				const keyHash = await sha256Hex(apiKey);
				let mutation: { data: unknown; error: unknown | null } | null = null;
				for (let attempt = 0; attempt < 2; attempt++) {
					mutation = await supabase.rpc("renew_api_key_with_audit", {
						p_actor_user_id: userId,
						p_tenant_id: tenant.id,
						p_id: id,
						p_expected_hash: currentHash,
						p_new_hash: keyHash,
						p_overlap_hours: overlapHours,
						p_set_expiry: true,
						p_expires_at: expiry.expiresAt,
					});
					if (!mutation.error) break;
				}
				if (mutation?.error && typeof mutation.error === "object" && "code" in mutation.error && mutation.error.code === "42501") {
					return corsJson(req, 403, { error: "tenant_not_admitted" });
				}
				if (!mutation || mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
				const result = mutation.data as {
					status?: string;
					previous_secret_valid_until?: string | null;
					expires_at?: string | null;
				};
				if (result?.status === "hash_conflict") continue;
				if (result?.status === "not_found") return corsJson(req, 404, { error: "key_not_found_or_not_owned" });
				if (result?.status === "revoked") return corsJson(req, 409, { error: "key_revoked" });
				if (result?.status === "expired") return corsJson(req, 409, { error: "key_expired" });
				if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_not_authorized" });
				if (result?.status !== "rotated") return corsJson(req, 409, { error: "key_rotation_conflict" });
				rotated = true;
				previousSecretValidUntil = result.previous_secret_valid_until ?? null;
				expiresAt = result.expires_at ?? null;
				break;
			}
			if (!rotated) return corsJson(req, 500, { error: "key_rotation_failed" });
			return corsJson(req, 200, {
				ok: true,
				api_key: apiKey,
				scope,
				previous_secret_valid_until: previousSecretValidUntil,
				expires_at: expiresAt,
			});
		}

		// create
		const request = parseCreateRequest(body);
		if (!request.ok) return corsJson(req, 400, { error: request.error });
		const createRequest = request.value;
		const parsedLabel = parseLabel(body.label);
		if (!parsedLabel.ok) return corsJson(req, 400, { error: "invalid_label" });
		const label = parsedLabel.value;
		const expiry = resolveExpiry(body, defaultTtlDays);
		if (!expiry.ok) return corsJson(req, 400, { error: "invalid_expiry" });
		// An ingest key is an organisation deployment credential.
		if (createRequest.scope !== "tenant" && !["owner", "admin"].includes(tenant.role)) {
			return corsJson(req, 403, { error: "tenant_role_insufficient" });
		}
		const ok = await rateLimitCreate(supabase, `${tenant.id}:${userId}`);
		if (!ok) return corsJson(req, 429, { error: "rate_limited" });

		let apiKey = "";
		let inserted = false;
		for (let i = 0; i < 5; i++) {
			apiKey = randomApiKey(createRequest.scope);
			const keyHash = await sha256Hex(apiKey);
			let mutation: { data: unknown; error: unknown | null } | null = null;
			for (let attempt = 0; attempt < 2; attempt++) {
				mutation = createRequest.scope === "tenant"
					? await supabase.rpc("issue_api_key_with_audit", {
						p_actor_user_id: userId,
						p_tenant_id: tenant.id,
						p_label: label,
						p_key_hash: keyHash,
						p_expires_at: expiry.expiresAt,
					})
					: await supabase.rpc("issue_scoped_api_key_with_audit", {
						p_actor_user_id: userId,
						p_tenant_id: tenant.id,
						p_label: label,
						p_key_hash: keyHash,
						p_scope: createRequest.scope,
						p_install_limit: createRequest.installLimit,
						p_expires_at: expiry.expiresAt,
					});
				if (!mutation.error) break;
			}
			if (mutation?.error && typeof mutation.error === "object" && "code" in mutation.error && mutation.error.code === "42501") {
				return corsJson(req, 403, { error: "tenant_not_admitted" });
			}
			if (!mutation || mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
			const result = mutation.data as { status?: string };
			if (result?.status === "hash_conflict") continue;
			if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_not_authorized" });
			if (result?.status !== "issued") return corsJson(req, 500, { error: "api_key_issue_failed" });
			inserted = true;
			break;
		}
		if (!inserted) return corsJson(req, 500, { error: "api_key_issue_failed" });
		return corsJson(req, 200, {
			ok: true,
			api_key: apiKey,
			scope: createRequest.scope,
			expires_at: expiry.expiresAt,
			...(createRequest.scope === "tenant" ? {} : { install_limit: createRequest.installLimit }),
		});
	}

	return corsJson(req, 405, { error: "method_not_allowed" });
});
