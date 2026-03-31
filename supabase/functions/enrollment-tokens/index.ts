// Supabase Edge Function: /v1/enrollment-tokens
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Creates/list/deletes enrollment tokens (plaintext shown once; hash-only at rest).

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const CREATE_RL_PER_MIN = Number(Deno.env.get("AIDR_ENROLLTOKEN_CREATE_RL_PER_MIN") ?? "20");
const DEFAULT_TTL_HOURS = Number(Deno.env.get("AIDR_ENROLLTOKEN_DEFAULT_TTL_HOURS") ?? "24");

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\\s+(.+)$/i);
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
	return b64.replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
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
	// Fail open if rate limiting isn't configured yet.
	if (error) return true;
	const { data } = await supabase
		.from("rate_limits")
		.select("count")
		.eq("key", key)
		.eq("window_start", nowMin)
		.maybeSingle();
	const count = Number((data as any)?.count ?? 0);
	return Number.isFinite(CREATE_RL_PER_MIN) && CREATE_RL_PER_MIN > 0 ? count <= CREATE_RL_PER_MIN : true;
}

Deno.serve(async (req) => {
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "misconfigured_supabase_env" });

	const accessToken = getBearerToken(req);
	if (!accessToken) return json(401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });
	const userId = userData.user.id;

	if (req.method === "GET") {
		const { data, error } = await supabase
			.from("enrollment_tokens")
			.select("id,label,expires_at,consumed_at,created_at")
			.eq("user_id", userId)
			.order("created_at", { ascending: false })
			.limit(200);
		if (error) return json(500, { error: "db_error" });
		return json(200, { ok: true, tokens: data ?? [] });
	}

	if (req.method === "POST") {
		let body: Record<string, unknown> = {};
		try {
			body = (await req.json()) as Record<string, unknown>;
		} catch {
			body = {};
		}

		const action = typeof body.action === "string" ? body.action : "create";

		if (action === "delete") {
			const id = typeof body.id === "string" ? body.id.trim() : "";
			if (!id) return json(400, { error: "missing_id" });
			const { error } = await supabase
				.from("enrollment_tokens")
				.delete()
				.eq("id", id)
				.eq("user_id", userId);
			if (error) return json(500, { error: "db_error" });
			await supabase.from("admin_audit_logs").insert({
				actor_user_id: userId,
				action: "enrollment_token.delete",
				target_user_id: userId,
				detail: { id },
			});
			return json(200, { ok: true });
		}

		// create
		const ok = await rateLimitCreate(supabase, userId);
		if (!ok) return json(429, { error: "rate_limited" });

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
				label,
				token_hash: tokenHash,
				expires_at: expiresAt,
			});
			if (!error) {
				inserted = true;
				break;
			}
		}

		if (!inserted) return json(500, { error: "token_issue_failed" });

		await supabase.from("admin_audit_logs").insert({
			actor_user_id: userId,
			action: "enrollment_token.create",
			target_user_id: userId,
			detail: { label, ttl_hours: ttlHours },
		});

		return json(200, { ok: true, enrollment_token: token, expires_at: expiresAt });
	}

	return json(405, { error: "method_not_allowed" });
});

