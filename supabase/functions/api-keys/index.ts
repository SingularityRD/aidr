// Supabase Edge Function: /v1/api-keys
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Provides an auditable API key create/revoke surface for the dashboard.

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const CREATE_RL_PER_MIN = Number(Deno.env.get("AIDR_APIKEY_CREATE_RL_PER_MIN") ?? "10");

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

function randomApiKey(): string {
	const raw = new Uint8Array(32);
	crypto.getRandomValues(raw);
	return `aidr_live_${base64Url(raw)}`;
}

async function resolveTenant(
	supabase: ReturnType<typeof createClient>,
	userId: string,
	req: Request,
): Promise<{ id: string; role: string } | null> {
	const requested = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim();
	if (!requested) return { id: userId, role: "owner" };
	if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requested)) return null;
	const { data } = await supabase
		.from("tenant_members")
		.select("tenant_id,expires_at,role")
		.eq("tenant_id", requested)
		.eq("user_id", userId)
		.maybeSingle();
	if (!data?.tenant_id || (data.expires_at && new Date(String(data.expires_at)).getTime() <= Date.now())) return null;
	return { id: String(data.tenant_id), role: String(data.role ?? "viewer") };
}

async function rateLimitCreate(
	supabase: ReturnType<typeof createClient>,
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
	const count = typeof row?.count === "number" ? row.count : 0;
	return Number.isFinite(CREATE_RL_PER_MIN) && CREATE_RL_PER_MIN > 0 ? count <= CREATE_RL_PER_MIN : true;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return corsJson(req, 500, { error: "misconfigured_supabase_env" });

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
	const canWrite = ["owner", "admin", "member"].includes(tenant.role);

	if (req.method === "GET") {
		const { data, error } = await supabase
			.from("api_keys")
			.select("id,label,revoked,created_at")
			.eq("tenant_id", tenant.id)
			.order("created_at", { ascending: false })
			.limit(200);
		if (error) return corsJson(req, 500, { error: "db_error" });
		return corsJson(req, 200, { ok: true, keys: data ?? [] });
	}

	if (req.method === "POST") {
		if (!canWrite) return corsJson(req, 403, { error: "tenant_role_insufficient" });
		let body: Record<string, unknown> = {};
		try {
			body = (await req.json()) as Record<string, unknown>;
		} catch {
			body = {};
		}
		const action = typeof body.action === "string" ? body.action : "create";

		if (action === "revoke") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return corsJson(req, 400, { error: "missing_id" });
			const { error } = await supabase
				.from("api_keys")
				.update({ revoked: true })
				.eq("id", id)
				.eq("tenant_id", tenant.id);
			if (error) return corsJson(req, 500, { error: "db_error" });
			await supabase.from("admin_audit_logs").insert({
				actor_user_id: userId,
				tenant_id: tenant.id,
				action: "api_key.revoke",
				target_user_id: userId,
				detail: { id },
			});
			return corsJson(req, 200, { ok: true });
		}

		// create
		const ok = await rateLimitCreate(supabase, `${tenant.id}:${userId}`);
		if (!ok) return corsJson(req, 429, { error: "rate_limited" });

		const label = typeof body.label === "string" ? body.label.trim() : null;
		let apiKey = "";
		let inserted = false;
		for (let i = 0; i < 5; i++) {
			apiKey = randomApiKey();
			const keyHash = await sha256Hex(apiKey);
			const { error } = await supabase.from("api_keys").insert({
				user_id: userId,
				tenant_id: tenant.id,
				label,
				key_hash: keyHash,
			});
			if (!error) {
				inserted = true;
				break;
			}
		}
		if (!inserted) return corsJson(req, 500, { error: "api_key_issue_failed" });

		await supabase.from("admin_audit_logs").insert({
			actor_user_id: userId,
			tenant_id: tenant.id,
			action: "api_key.create",
			target_user_id: userId,
			detail: { label },
		});
		return corsJson(req, 200, { ok: true, api_key: apiKey });
	}

	return corsJson(req, 405, { error: "method_not_allowed" });
});
