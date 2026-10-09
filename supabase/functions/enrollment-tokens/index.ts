// Supabase Edge Function: /v1/enrollment-tokens
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Creates/list/deletes enrollment tokens (plaintext shown once; hash-only at rest).

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { boundedOverlapHours } from "../_shared/key-rotation.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

// Credential row ids are UUIDs; anything else is a client error, not a storage or audit outage.
const RECORD_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 8 * 1024;

const CREATE_RL_PER_MIN = Number(Deno.env.get("AIDR_ENROLLTOKEN_CREATE_RL_PER_MIN") ?? "20");
const DEFAULT_TTL_HOURS = Number(Deno.env.get("AIDR_ENROLLTOKEN_DEFAULT_TTL_HOURS") ?? "24");

// How long the retired hash stays exchangeable after a renewal. Clamped to the
// reviewed 1 hour .. 7 day range (see _shared/key-rotation.ts), never longer
// than the retired token's own remaining validity, and enforced again by the
// `enrollment_tokens_rotation_window_check` database constraint.
const RENEW_OVERLAP_HOURS = Deno.env.get("AIDR_ENROLLTOKEN_RENEW_OVERLAP_HOURS") ?? "24";

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

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

function randomEnrollmentToken(): string {
	const raw = new Uint8Array(32);
	crypto.getRandomValues(raw);
	return `aidr_enroll_${base64Url(raw)}`;
}

async function resolveTenantId(
	supabase: ReturnType<typeof createClient>,
	userId: string,
	req: Request,
): Promise<{ id: string; role: string } | null> {
	const requested = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim() || userId;
	if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requested)) {
		return null;
	}
	const { data } = await supabase
		.from("tenant_members")
		.select("tenant_id,expires_at,role")
		.eq("tenant_id", requested)
		.eq("user_id", userId)
		.maybeSingle();
	if (!data?.tenant_id) return null;
	if (!membershipActive(data)) return null;
	const state = await supabase.from("tenants").select("status").eq("id", requested).maybeSingle();
	if (state.error || state.data?.status !== "active") return null;
	return { id: String(data.tenant_id), role: String(data.role) };
}

async function rateLimitCreate(
	supabase: ReturnType<typeof createClient>,
	userId: string,
): Promise<boolean> {
	const nowMin = Math.floor(Date.now() / 60000);
	const key = `enrolltoken_create:${userId}`;
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
	const count = (data as { count?: unknown } | null)?.count;
	return Number.isSafeInteger(CREATE_RL_PER_MIN) && CREATE_RL_PER_MIN > 0
		&& typeof count === "number" && Number.isSafeInteger(count) && count > 0 && count <= CREATE_RL_PER_MIN;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("enrollment-tokens", config.error, (status, body) =>
			corsJson(req, status, body),
		);
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const accessToken = getBearerToken(req);
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = userData.user.id;
	const tenant = await resolveTenantId(supabase, userId, req);
	if (!tenant) return corsJson(req, 403, { error: "tenant_not_authorized" });
	const tenantId = tenant.id;
	const identity = await checkIdentityBarrier(supabase, accessToken, userId, tenantId);
	if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });

	if (req.method === "GET") {
		let query = supabase
			.from("enrollment_tokens")
			.select("id,label,expires_at,consumed_at,created_at")
			.eq("tenant_id", tenantId);
		if (!["owner", "admin"].includes(tenant.role)) query = query.eq("user_id", userId);
		const { data, error } = await query.order("created_at", { ascending: false }).limit(200);
		if (error) return corsJson(req, 500, { error: "db_error" });
		return corsJson(req, 200, { ok: true, tokens: data ?? [] });
	}

	if (req.method === "POST") {
		if (!["owner", "admin", "member"].includes(tenant.role)) return corsJson(req, 403, { error: "tenant_role_insufficient" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value))
			return corsJson(req, 400, { error: "invalid_json" });
		const body = parsed.value as Record<string, unknown>;

		const action = typeof body.action === "string" ? body.action : "create";
		if (!["create", "delete", "renew"].includes(action)) return corsJson(req, 400, { error: "invalid_action" });

		if (action === "delete") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return corsJson(req, 400, { error: "missing_id" });
			if (!RECORD_ID.test(id)) return corsJson(req, 400, { error: "invalid_id" });
			let mutation: { data: unknown; error: unknown | null } | null = null;
			for (let attempt = 0; attempt < 2; attempt++) {
				mutation = await supabase.rpc("delete_enrollment_token_with_audit", {
					p_actor_user_id: userId,
					p_tenant_id: tenantId,
					p_id: id,
				});
				if (!mutation.error) break;
			}
			if (!mutation || mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
			const result = mutation.data as { status?: string };
			if (result?.status === "not_found") return corsJson(req, 404, { error: "token_not_found_or_not_owned" });
			if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_not_authorized" });
			if (result?.status !== "deleted") return corsJson(req, 409, { error: "token_delete_conflict" });
			return corsJson(req, 200, { ok: true });
		}

		// renew
		if (action === "renew") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return corsJson(req, 400, { error: "missing_id" });
			if (!RECORD_ID.test(id)) return corsJson(req, 400, { error: "invalid_id" });
			const ok = await rateLimitCreate(supabase, `${tenantId}:${userId}`);
			if (!ok) return corsJson(req, 429, { error: "rate_limited" });

			let read = supabase
				.from("enrollment_tokens")
				.select("id,token_hash,expires_at,consumed_at")
				.eq("id", id)
				.eq("tenant_id", tenantId);
			if (tenant.role === "member") read = read.eq("user_id", userId);
			const { data: current, error: readError } = await read.maybeSingle();
			if (readError) return corsJson(req, 500, { error: "db_error" });
			if (!current?.id) return corsJson(req, 404, { error: "token_not_found_or_not_owned" });
			// A consumed one-time token must never come back through a rotation.
			if (current.consumed_at) return corsJson(req, 409, { error: "token_already_consumed" });
			const currentHash = typeof current.token_hash === "string" ? current.token_hash : "";
			if (!/^[a-f0-9]{64}$/.test(currentHash)) return corsJson(req, 500, { error: "token_hash_unavailable" });

			const ttlHoursRaw = Number(body.ttl_hours ?? DEFAULT_TTL_HOURS);
			const ttlHours = Number.isFinite(ttlHoursRaw) ? Math.max(1, Math.min(24 * 30, Math.floor(ttlHoursRaw))) : DEFAULT_TTL_HOURS;
			const overlapHours = boundedOverlapHours(RENEW_OVERLAP_HOURS);

			let token = "";
			let rotated = false;
			let expiresAt: string | null = null;
			let previousSecretValidUntil: string | null = null;
			for (let i = 0; i < 5; i++) {
				token = randomEnrollmentToken();
				const tokenHash = await sha256Hex(token);
				let mutation: { data: unknown; error: unknown | null } | null = null;
				for (let attempt = 0; attempt < 2; attempt++) {
					mutation = await supabase.rpc("renew_enrollment_token_with_audit", {
						p_actor_user_id: userId,
						p_tenant_id: tenantId,
						p_id: id,
						p_expected_hash: currentHash,
						p_new_hash: tokenHash,
						p_ttl_hours: ttlHours,
						p_overlap_hours: overlapHours,
					});
					if (!mutation.error) break;
				}
				if (mutation?.error && typeof mutation.error === "object" && "code" in mutation.error && mutation.error.code === "42501") {
					return corsJson(req, 403, { error: "tenant_not_admitted" });
				}
				if (!mutation || mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
				const result = mutation.data as {
					status?: string;
					expires_at?: string;
					previous_secret_valid_until?: string | null;
				};
				if (result?.status === "hash_conflict") continue;
				if (result?.status === "not_found") return corsJson(req, 404, { error: "token_not_found_or_not_owned" });
				if (result?.status === "consumed") return corsJson(req, 409, { error: "token_already_consumed" });
				if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_not_authorized" });
				if (result?.status !== "rotated" || !result.expires_at) {
					return corsJson(req, 409, { error: "token_rotation_conflict" });
				}
				rotated = true;
				expiresAt = result.expires_at;
				previousSecretValidUntil = result.previous_secret_valid_until ?? null;
				break;
			}

			if (!rotated) return corsJson(req, 500, { error: "token_rotation_failed" });

			return corsJson(req, 200, {
				ok: true,
				enrollment_token: token,
				expires_at: expiresAt,
				previous_secret_valid_until: previousSecretValidUntil,
			});
		}

		// create
		const ok = await rateLimitCreate(supabase, `${tenantId}:${userId}`);
		if (!ok) return corsJson(req, 429, { error: "rate_limited" });

		const label = typeof body.label === "string" ? body.label.trim() : null;
		const ttlHoursRaw = Number(body.ttl_hours ?? DEFAULT_TTL_HOURS);
		const ttlHours = Number.isFinite(ttlHoursRaw) ? Math.max(1, Math.min(24 * 30, Math.floor(ttlHoursRaw))) : DEFAULT_TTL_HOURS;
		let token = "";
		let inserted = false;
		let expiresAt: string | null = null;
		for (let i = 0; i < 5; i++) {
			token = randomEnrollmentToken();
			const tokenHash = await sha256Hex(token);
			let mutation: { data: unknown; error: unknown | null } | null = null;
			for (let attempt = 0; attempt < 2; attempt++) {
				mutation = await supabase.rpc("issue_enrollment_token_with_audit", {
					p_actor_user_id: userId,
					p_tenant_id: tenantId,
					p_label: label,
					p_ttl_hours: ttlHours,
					p_token_hash: tokenHash,
				});
				if (!mutation.error) break;
			}
			if (mutation?.error && typeof mutation.error === "object" && "code" in mutation.error && mutation.error.code === "42501") {
				return corsJson(req, 403, { error: "tenant_not_admitted" });
			}
			if (!mutation || mutation.error) return corsJson(req, 503, { error: "audit_unavailable" });
			const result = mutation.data as { status?: string; expires_at?: string };
			if (result?.status === "hash_conflict") continue;
			if (result?.status === "forbidden") return corsJson(req, 403, { error: "tenant_not_authorized" });
			if (result?.status !== "issued" || !result.expires_at) {
				return corsJson(req, 500, { error: "token_issue_failed" });
			}
			inserted = true;
			expiresAt = result.expires_at;
			break;
		}

		if (!inserted) return corsJson(req, 500, { error: "token_issue_failed" });

		return corsJson(req, 200, { ok: true, enrollment_token: token, expires_at: expiresAt });
	}

	return corsJson(req, 405, { error: "method_not_allowed" });
});
