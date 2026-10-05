// Supabase Edge Function: POST /v1/waitlist/signup
//
// Auth: none
//
// Public waitlist intake. Fail-closed aggregate rate limiting.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { ConfigurationError, configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { buildCorsHeaders, parseAllowedOrigins, resolveAllowedOrigin } from "../_shared/origin.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { getRequestId } from "../_shared/response.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const MAX_WAITLIST_BODY_BYTES = 8 * 1024;
// Use one fixed deployment-wide bucket. Proxy IP headers are caller-controlled
// at this Edge Function boundary, and per-IP keys let attackers evade limits
// while creating unbounded counter rows. This intentionally trades per-client
// fairness for a hard aggregate cap; tune upward for legitimate launch traffic.
const WAITLIST_RL_PER_MIN = Number(Deno.env.get("AIDR_WAITLIST_RL_PER_MIN") ?? "1000");
const WAITLIST_RATE_LIMIT_ERROR = Number.isSafeInteger(WAITLIST_RL_PER_MIN) && WAITLIST_RL_PER_MIN > 0 && WAITLIST_RL_PER_MIN <= 100_000
	? null
	: new ConfigurationError({ invalid: ["AIDR_WAITLIST_RL_PER_MIN"] });
const ALLOWED_ORIGINS = parseAllowedOrigins(
	Deno.env.get("AIDR_ALLOWED_ORIGINS"),
	Deno.env.get("AIDR_DEVELOPMENT_MODE") === "true",
);

function json(status: number, body: Record<string, unknown>, req: Request) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			...buildCorsHeaders(req.headers.get("Origin"), ALLOWED_ORIGINS),
			"X-Request-ID": getRequestId(req),
		},
	});
}

async function rateLimitWaitlist(
	supabase: ReturnType<typeof createClient<any>>,
): Promise<boolean> {
	const nowMin = Math.floor(Date.now() / 60000);
	const key = "waitlist:global:v1";
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
	const count = data && typeof data === "object" && "count" in data ? data.count : null;
	return typeof count === "number" && Number.isSafeInteger(count) && count > 0 && count <= WAITLIST_RL_PER_MIN;
}

export async function handleWaitlistSignup(req: Request): Promise<Response> {
	const origin = req.headers.get("Origin");
	const allowedOrigin = resolveAllowedOrigin(origin, ALLOWED_ORIGINS);
	if (origin && !allowedOrigin) return json(403, { error: "origin_not_allowed" }, req);

	if (req.method === "OPTIONS") return json(200, { ok: true }, req);
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" }, req);

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("waitlist-signup", config.error, (status, body) => json(status, body, req));
	}
	if (WAITLIST_RATE_LIMIT_ERROR) {
		return configFailure("waitlist-signup", WAITLIST_RATE_LIMIT_ERROR, (status, body) => json(status, body, req));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const parsed = await readBoundedJson(req, MAX_WAITLIST_BODY_BYTES);
	if (!parsed.ok) return json(parsed.status, { error: parsed.error }, req);
	if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) {
		return json(400, { error: "invalid_json" }, req);
	}
	const body = parsed.value as Record<string, unknown>;

	const email = typeof body.email === "string" ? body.email.trim() : "";
	const name = typeof body.name === "string" ? body.name.trim() : null;
	const company = typeof body.company === "string" ? body.company.trim() : null;
	const message = typeof body.message === "string" ? body.message.trim() : null;

	if (!email || !email.includes("@") || email.length > 320)
		return json(400, { error: "invalid_email" }, req);

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const ok = await rateLimitWaitlist(supabase);
	if (!ok) return json(429, { error: "rate_limited" }, req);

	// Insert-only. An unauthenticated caller who knows an address must not be
	// able to overwrite the name/company/message of the existing row, so there is
	// no upsert. A duplicate address (unique email_lower, SQLSTATE 23505) leaves
	// the original row untouched and answers exactly like a first signup, so the
	// response does not reveal whether an email is already on the waitlist.
	const { error } = await supabase
		.from("waitlist_signups")
		.insert({ email, name, company, message });
	if (error && (error as { code?: string }).code !== "23505") return json(500, { error: "db_error" }, req);

	return json(200, { ok: true }, req);
}

Deno.serve(handleWaitlistSignup);
