// Supabase Edge Function: POST /v1/device/verify
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Attaches an authenticated user to a device session (by user_code).
// Requires an active tenant admission (licensed, trial, or explicit pilot).

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { evaluateDeviceVerifyState } from "../_shared/device-auth.ts";
import { jwtIssuedAtMs } from "../identity-security/logic.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 16 * 1024;
const VERIFY_RATE_LIMIT_PER_MIN = Number(Deno.env.get("AIDR_DEVICE_VERIFY_RL_PER_MIN") ?? "30");
const VERIFY_RATE_LIMIT_PREFIX = "device_start:verify:v1:user:";

type DeviceSessionRow = {
	id: string;
	authorized_at: string | null;
	expires_at: string;
	user_id: string | null;
	tenant_id: string | null;
};

type VerifyRateLimitResult =
	| { status: "allowed" }
	| { status: "limited"; retryAfterSeconds: number }
	| { status: "unavailable" };

const makeClient = (url: string, key: string) => createClient(url, key, { auth: { persistSession: false } });

async function rateLimitVerify(
	supabase: ReturnType<typeof makeClient>,
	userId: string,
	now = Date.now(),
): Promise<VerifyRateLimitResult> {
	if (!Number.isSafeInteger(VERIFY_RATE_LIMIT_PER_MIN) || VERIFY_RATE_LIMIT_PER_MIN < 1 || VERIFY_RATE_LIMIT_PER_MIN > 10_000 || !Number.isFinite(now)) {
		return { status: "unavailable" };
	}
	const windowStart = Math.floor(now / 60_000);
	const key = `${VERIFY_RATE_LIMIT_PREFIX}${userId}`;
	try {
		const { error: incrementError } = await supabase.rpc("increment_rate_limit", {
			p_key: key,
			p_window_start: windowStart,
			p_delta: 1,
		});
		if (incrementError) return { status: "unavailable" };
		const { data, error } = await supabase.from("rate_limits")
			.select("count")
			.eq("key", key)
			.eq("window_start", windowStart)
			.maybeSingle();
		if (error || !data || !Number.isSafeInteger(data.count) || data.count < 1) {
			return { status: "unavailable" };
		}
		if (data.count > VERIFY_RATE_LIMIT_PER_MIN) {
			return { status: "limited", retryAfterSeconds: Math.max(1, 60 - Math.floor((now % 60_000) / 1000)) };
		}
		return { status: "allowed" };
	} catch {
		return { status: "unavailable" };
	}
}

async function tenantAdmitted(
	supabase: ReturnType<typeof makeClient>,
	tenantId: string,
): Promise<"active" | "forbidden" | "unknown"> {
	const { data, error } = await supabase.rpc("tenant_admission_capacity", { p_tenant_id: tenantId });
	if (error || !Number.isSafeInteger(data) || Number(data) < 0) return "unknown";
	return Number(data) > 0 ? "active" : "forbidden";
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("device-verify", config.error, (status, body) => corsJson(req, status, body));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;
	if (!Number.isSafeInteger(VERIFY_RATE_LIMIT_PER_MIN) || VERIFY_RATE_LIMIT_PER_MIN < 1 || VERIFY_RATE_LIMIT_PER_MIN > 10_000) {
		return corsJson(req, 500, { error: "server_misconfigured", invalid: ["AIDR_DEVICE_VERIFY_RL_PER_MIN"] });
	}

	const accessToken = getBearerToken(req.headers.get("Authorization"));
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = makeClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = userData.user.id;
	// Bound authenticated code-guessing and database work before any user-code
	// lookup. The stable Auth user ID prevents fresh access tokens from resetting
	// this bucket; the limiter fails closed if its backing store is unavailable.
	const rate = await rateLimitVerify(supabase, userId);
	if (rate.status === "unavailable") return corsJson(req, 503, { error: "rate_limit_unavailable" });
	if (rate.status === "limited") return corsJson(req, 429, { error: "rate_limited" }, { "Retry-After": String(rate.retryAfterSeconds) });
	// Auth verified the token above. Carry its issuance time into the atomic
	// authorization RPC so a concurrent global revocation can reject this exact
	// session before the device row is bound to the user.
	const accessTokenIssuedAtMs = jwtIssuedAtMs(accessToken);
	if (accessTokenIssuedAtMs === null) {
		return corsJson(req, 401, { error: "invalid_access_token" });
	}

	const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
	if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) return corsJson(req, 400, { error: "invalid_json" });
	const body = parsed.value as Record<string, unknown>;
	const userCode = typeof body.user_code === "string" ? body.user_code.trim().toUpperCase() : "";
	if (!userCode) return corsJson(req, 400, { error: "missing_user_code" });

	const { data: row, error } = await supabase
		.from("device_sessions")
		.select("id,authorized_at,expires_at,user_id,tenant_id")
		.eq("user_code", userCode)
		.maybeSingle();
	if (error || !row) return corsJson(req, 404, { error: "device_code_invalid" });
	const session = row as DeviceSessionRow;
	const requested = req.headers.get("X-AIDR-Tenant-ID")?.trim();
	if (requested && !/^[a-f0-9-]{36}$/i.test(requested)) return corsJson(req, 400, { error: "invalid_tenant" });
	if (session.tenant_id && requested && session.tenant_id !== requested) return corsJson(req, 403, { error: "device_tenant_mismatch" });
	const tenantId = session.tenant_id ?? requested ?? userId;
	const admission = await tenantAdmitted(supabase, tenantId);
	if (admission !== "active") return admission === "unknown"
		? corsJson(req, 503, { error: "tenant_admission_unavailable" })
		: corsJson(req, 403, { error: "tenant_not_admitted" });
	const identity = await checkIdentityBarrier(supabase, accessToken, userId, tenantId);
	if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
	const { data: tenant, error: tenantError } = await supabase.from("tenants").select("status").eq("id", tenantId).maybeSingle();
	const { data: member, error: memberError } = await supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
	if (tenantError || memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
	if (tenant?.status !== "active" || !member || !["owner", "admin", "member"].includes(member.role)
		|| (member.expires_at && !(Date.parse(member.expires_at) > Date.now()))) {
		return corsJson(req, 403, { error: "tenant_enrollment_forbidden" });
	}
	const state = evaluateDeviceVerifyState({
		nowMs: Date.now(),
		expiresAtIso: session.expires_at,
		authorizedAt: session.authorized_at,
		pilotApproved: true,
	});
	if (state.status !== "ok") return corsJson(req, state.httpStatus, { error: state.error });

	const { data: authorizedRows, error: authorizeErr } = await supabase.rpc(
		"authorize_device_session",
		{
			p_user_code: userCode,
			p_user_id: userId,
			p_tenant_id: tenantId,
			p_access_token_issued_at: new Date(accessTokenIssuedAtMs).toISOString(),
		},
	);
	if (authorizeErr) return corsJson(req, 500, { error: "device_authorization_unavailable" });
	if (!Array.isArray(authorizedRows) || authorizedRows.length === 0) {
		return corsJson(req, 409, { error: "device_code_race" });
	}

	// The browser must be able to show when this authorization window closes:
	// once it does, the agent can no longer complete enrollment with this code.
	return corsJson(req, 200, { ok: true, expires_at: session.expires_at });
});
