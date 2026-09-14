// Supabase Edge Function: /v1/enrollment-tokens
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Creates/list/deletes enrollment tokens (plaintext shown once; hash-only at rest).

import { createClient } from "npm:@supabase/supabase-js@2";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { boundedOverlapHours, rotationPlan } from "../_shared/key-rotation.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

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

function addHoursIso(hours: number): string {
	const safe = Number.isFinite(hours) ? Math.max(0, hours) : 0;
	return new Date(Date.now() + safe * 60 * 60 * 1000).toISOString();
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
	const count = Number((data as any)?.count ?? 0);
	return Number.isFinite(CREATE_RL_PER_MIN) && CREATE_RL_PER_MIN > 0 ? count <= CREATE_RL_PER_MIN : true;
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
		const { data, error } = await supabase
			.from("enrollment_tokens")
			.select("id,label,expires_at,consumed_at,created_at")
			.eq("tenant_id", tenantId)
			.order("created_at", { ascending: false })
			.limit(200);
		if (error) return corsJson(req, 500, { error: "db_error" });
		return corsJson(req, 200, { ok: true, tokens: data ?? [] });
	}

	if (req.method === "POST") {
		if (!["owner", "admin", "member"].includes(tenant.role)) return corsJson(req, 403, { error: "tenant_role_insufficient" });
		let body: Record<string, unknown> = {};
		try {
			body = (await req.json()) as Record<string, unknown>;
		} catch {
			body = {};
		}

		const action = typeof body.action === "string" ? body.action : "create";
		if (!["create", "delete", "renew"].includes(action)) return corsJson(req, 400, { error: "invalid_action" });

		if (action === "delete") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return corsJson(req, 400, { error: "missing_id" });
			let query = supabase
				.from("enrollment_tokens")
				.delete()
				.eq("id", id)
				.eq("tenant_id", tenantId);
			if (tenant.role === "member") query = query.eq("user_id", userId);
			const { data: changed, error } = await query.select("id");
			if (error) return corsJson(req, 500, { error: "db_error" });
			if (!changed?.length) return corsJson(req, 404, { error: "token_not_found_or_not_owned" });
			await supabase.from("admin_audit_logs").insert({
				actor_user_id: userId,
				tenant_id: tenantId,
				action: "enrollment_token.delete",
				target_user_id: userId,
				detail: { id },
			});
			return corsJson(req, 200, { ok: true });
		}

		// renew
		if (action === "renew") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return corsJson(req, 400, { error: "missing_id" });
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
			const expiresAt = addHoursIso(ttlHours);
			const plan = rotationPlan(
				Date.now(),
				boundedOverlapHours(RENEW_OVERLAP_HOURS),
				typeof current.expires_at === "string" ? current.expires_at : null,
			);

			let token = "";
			let rotated = false;
			for (let i = 0; i < 5; i++) {
				token = randomEnrollmentToken();
				const tokenHash = await sha256Hex(token);
				// Compare-and-swap on the hash that was read: a concurrent renewal
				// loses the race instead of silently discarding a rotation.
				const { data: changed, error } = await supabase
					.from("enrollment_tokens")
					.update({
						token_hash: tokenHash,
						expires_at: expiresAt,
						previous_hash: plan.previousHashExpiresAt === null ? null : currentHash,
						previous_hash_expires_at: plan.previousHashExpiresAt,
						rotated_at: plan.rotatedAt,
					})
					.eq("id", id)
					.eq("tenant_id", tenantId)
					.eq("token_hash", currentHash)
					.select("id");
				if (error) continue;
				if (!changed?.length) return corsJson(req, 409, { error: "token_rotation_conflict" });
				rotated = true;
				break;
			}

			if (!rotated) return corsJson(req, 500, { error: "token_rotation_failed" });

			await supabase.from("admin_audit_logs").insert({
				actor_user_id: userId,
				tenant_id: tenantId,
				action: "enrollment_token.renew",
				target_user_id: userId,
				detail: { id, ttl_hours: ttlHours, previous_secret_valid_until: plan.previousHashExpiresAt },
			});

			return corsJson(req, 200, {
				ok: true,
				enrollment_token: token,
				expires_at: expiresAt,
				previous_secret_valid_until: plan.previousHashExpiresAt,
			});
		}

		// create
		const ok = await rateLimitCreate(supabase, `${tenantId}:${userId}`);
		if (!ok) return corsJson(req, 429, { error: "rate_limited" });

		const label = typeof body.label === "string" ? body.label.trim() : null;
		const ttlHoursRaw = Number(body.ttl_hours ?? DEFAULT_TTL_HOURS);
		const ttlHours = Number.isFinite(ttlHoursRaw) ? Math.max(1, Math.min(24 * 30, Math.floor(ttlHoursRaw))) : DEFAULT_TTL_HOURS;
		const expiresAt = addHoursIso(ttlHours);

		let token = "";
		let inserted = false;
		for (let i = 0; i < 5; i++) {
			token = randomEnrollmentToken();
			const tokenHash = await sha256Hex(token);
			const { error } = await supabase.from("enrollment_tokens").insert({
				user_id: userId,
				tenant_id: tenantId,
				label,
				token_hash: tokenHash,
				expires_at: expiresAt,
			});
			if (!error) {
				inserted = true;
				break;
			}
		}

		if (!inserted) return corsJson(req, 500, { error: "token_issue_failed" });

		await supabase.from("admin_audit_logs").insert({
			actor_user_id: userId,
			tenant_id: tenantId,
			action: "enrollment_token.create",
			target_user_id: userId,
			detail: { label, ttl_hours: ttlHours },
		});

		return corsJson(req, 200, { ok: true, enrollment_token: token, expires_at: expiresAt });
	}

	return corsJson(req, 405, { error: "method_not_allowed" });
});
