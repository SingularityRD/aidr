// Supabase Edge Function: POST /v1/waitlist/signup
//
// Auth: none
//
// Public waitlist intake. Best-effort rate limiting by IP.

import { createClient } from "npm:@supabase/supabase-js@2";
import { buildCorsHeaders, parseAllowedOrigins, resolveAllowedOrigin } from "../_shared/origin.ts";
import { getRequestId } from "../_shared/response.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const WAITLIST_RL_PER_MIN = Number(Deno.env.get("AIDR_WAITLIST_RL_PER_MIN") ?? "10");
const ALLOWED_ORIGINS = parseAllowedOrigins(Deno.env.get("AIDR_ALLOWED_ORIGINS"));

function json(status: number, body: Record<string, unknown>, req: Request) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			...buildCorsHeaders(req.headers.get("Origin"), ALLOWED_ORIGINS),
			"X-Request-ID": getRequestId(req),
		},
	});
}

function getClientIp(req: Request): string {
	const h =
		req.headers.get("x-forwarded-for") ??
		req.headers.get("cf-connecting-ip") ??
		req.headers.get("x-real-ip") ??
		"";
	const first = h.split(",")[0]?.trim() ?? "";
	return first || "unknown";
}

async function sha256Hex(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest("SHA-256", data);
	const bytes = new Uint8Array(digest);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

async function rateLimitWaitlist(
	supabase: ReturnType<typeof createClient>,
	ip: string,
): Promise<boolean> {
	const nowMin = Math.floor(Date.now() / 60000);
	const ipHash = await sha256Hex(ip);
	const key = `waitlist:${ipHash.slice(0, 16)}`;
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
	const count =
		data && typeof data === "object" && "count" in data && typeof data.count === "number"
			? data.count
			: 0;
	return Number.isFinite(WAITLIST_RL_PER_MIN) && WAITLIST_RL_PER_MIN > 0
		? count <= WAITLIST_RL_PER_MIN
		: true;
}

Deno.serve(async (req) => {
	const origin = req.headers.get("Origin");
	const allowedOrigin = resolveAllowedOrigin(origin, ALLOWED_ORIGINS);
	if (origin && !allowedOrigin) return json(403, { error: "origin_not_allowed" }, req);

	if (req.method === "OPTIONS") return json(200, { ok: true }, req);
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" }, req);
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY)
		return json(500, { error: "misconfigured_supabase_env" }, req);

	let body: Record<string, unknown> = {};
	try {
		body = (await req.json()) as Record<string, unknown>;
	} catch {
		body = {};
	}

	const email = typeof body.email === "string" ? body.email.trim() : "";
	const name = typeof body.name === "string" ? body.name.trim() : null;
	const company = typeof body.company === "string" ? body.company.trim() : null;
	const message = typeof body.message === "string" ? body.message.trim() : null;

	if (!email || !email.includes("@") || email.length > 320)
		return json(400, { error: "invalid_email" }, req);

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const ip = getClientIp(req);
	const ok = await rateLimitWaitlist(supabase, ip);
	if (!ok) return json(429, { error: "rate_limited" }, req);

	const { error } = await supabase
		.from("waitlist_signups")
		.upsert({ email, name, company, message }, { onConflict: "email_lower" });
	if (error) return json(500, { error: "db_error" }, req);

	return json(200, { ok: true }, req);
});
