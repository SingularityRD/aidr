// Supabase Edge Function: POST /v1/device/poll
//
// Auth: none (device-code bootstrap)
//
// Polls the device session. Once authorized and tenant-admitted, returns an enrollment token
// that can be exchanged via POST /v1/enroll.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { readDeviceCode } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { evaluateDevicePollState } from "../_shared/device-auth.ts";
import { consumeRateLimit, validRateLimit } from "../_shared/rate-limit.ts";
import { INGRESS_SECRET_ENV, ingressIpBucket, validIngressSecret, verifiedIngressIp } from "../_shared/trusted-ingress.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const DEVICE_POLL_INTERVAL_SECONDS = Number(Deno.env.get("AIDR_DEVICE_POLL_INTERVAL_SECONDS") ?? "3");
const ENROLLMENT_TOKEN_TTL_HOURS = Number(Deno.env.get("AIDR_DEVICE_ENROLLTOKEN_TTL_HOURS") ?? "24");
// Poll rate limits (per minute). Raw caller IP headers are never used as a key
// (they are caller-controlled and would let an attacker mint unbounded counter
// rows). When the trusted ingress attests the client IP (HMAC proof, shared
// with device-start), that client gets its own bucket checked first, so one
// caller cannot drain the shared budget after reaching its quota; signed callers
// then share a signed aggregate as a backstop. Unsigned callers (no ingress, or
// a forged/stale proof) consume only the unsigned aggregate, so a direct caller
// can no longer exhaust polling for clients that arrive through the ingress.
// One bucket per existing device session (keyed by the code hash, created only
// after the lookup finds a real session) bounds each device. Defaults allow the
// 3s poll interval.
const POLL_DEVICE_RL_PER_MIN = Number(Deno.env.get("AIDR_DEVICE_POLL_RL_PER_MIN") ?? "60");
const POLL_CLIENT_RL_PER_MIN = Number(Deno.env.get("AIDR_DEVICE_POLL_CLIENT_RL_PER_MIN") ?? "120");
const POLL_AGGREGATE_RL_PER_MIN = Number(Deno.env.get("AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN") ?? "6000");
const INGRESS_CONTEXT = "device-poll:v1";
const makeClient = (url: string, key: string) => createClient(url, key, { auth: { persistSession: false } });

type DeviceSessionRow = {
	id: string;
	user_id: string | null;
	tenant_id: string | null;
	authorized_at: string | null;
	exchanged_at: string | null;
	expires_at: string;
	user_code: string | null;
};
type EnrollmentTokenRow = { expires_at: string; consumed_at: string | null };

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

async function enrollmentTokenForDeviceCode(deviceCode: string): Promise<string> {
	// The device code already carries 256 random bits. Domain separation gives
	// this exchange its own bearer secret while allowing a lost response to be
	// recovered without storing plaintext or introducing a second database write.
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(`aidr:device-enrollment:v1:${deviceCode}`),
	);
	return `aidr_enroll_${base64Url(new Uint8Array(digest))}`;
}

function addHoursIso(hours: number): string {
	const safe = Number.isFinite(hours) ? Math.max(1, Math.min(24 * 30, Math.floor(hours))) : 24;
	return new Date(Date.now() + safe * 60 * 60 * 1000).toISOString();
}

async function ensureTenantAdmitted(
	supabase: ReturnType<typeof makeClient>,
	userId: string,
	tenantId: string,
): Promise<"active" | "forbidden" | "unknown"> {
	const { data: capacity, error } = await supabase.rpc("tenant_admission_capacity", { p_tenant_id: tenantId });
	if (error || !Number.isSafeInteger(capacity) || Number(capacity) < 0) return "unknown";
	if (Number(capacity) === 0) return "forbidden";
	const membership = await supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
	const tenant = await supabase.from("tenants").select("status").eq("id", tenantId).maybeSingle();
	if (membership.error || tenant.error) return "unknown";
	return tenant.data?.status === "active" && membership.data && ["owner", "admin", "member"].includes(membership.data.role) && (!membership.data.expires_at || Date.parse(membership.data.expires_at) > Date.now())
		? "active" : "forbidden";
}

async function recoverIssuedToken(
	supabase: ReturnType<typeof makeClient>,
	tokenHash: string,
	userId: string,
	tenantId: string,
): Promise<{ status: "available"; expiresAt: string } | { status: "missing" | "unknown" }> {
	const { data, error } = await supabase.from("enrollment_tokens")
		.select("expires_at,consumed_at")
		.eq("token_hash", tokenHash).eq("user_id", userId).eq("tenant_id", tenantId)
		.maybeSingle();
	if (error) return { status: "unknown" };
	const row = data as EnrollmentTokenRow | null;
	if (!row || row.consumed_at || !Number.isFinite(Date.parse(row.expires_at)) || Date.parse(row.expires_at) <= Date.now()) {
		return { status: "missing" };
	}
	return { status: "available", expiresAt: row.expires_at };
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("device-poll", config.error, (status, body) => corsJson(req, status, body));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const deviceCode = await readDeviceCode(req);

	if (!deviceCode) return corsJson(req, 401, { error: "missing_device_code" });

	const supabase = makeClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

	if (!validRateLimit(POLL_DEVICE_RL_PER_MIN, 10_000) || !validRateLimit(POLL_CLIENT_RL_PER_MIN, 100_000)
		|| !validRateLimit(POLL_AGGREGATE_RL_PER_MIN, 1_000_000) || POLL_AGGREGATE_RL_PER_MIN < POLL_DEVICE_RL_PER_MIN) {
		return corsJson(req, 500, { error: "server_misconfigured", invalid: ["AIDR_DEVICE_POLL_RL_PER_MIN", "AIDR_DEVICE_POLL_CLIENT_RL_PER_MIN", "AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN"] });
	}
	// Optional: without it every caller shares the unsigned aggregate.
	const ingressSecret = Deno.env.get(INGRESS_SECRET_ENV) ?? "";
	if (ingressSecret && !validIngressSecret(ingressSecret)) {
		return corsJson(req, 500, { error: "server_misconfigured", invalid: [INGRESS_SECRET_ENV] });
	}
	const limited = (result: { status: "limited" | "unavailable"; retryAfterSeconds: number }) =>
		result.status === "limited"
			? corsJson(req, 429, { error: "rate_limited", retry_after_seconds: result.retryAfterSeconds }, { "Retry-After": String(result.retryAfterSeconds) })
			: corsJson(req, 503, { error: "rate_limit_unavailable", enrollment_outcome: "unknown" }, { "Retry-After": String(result.retryAfterSeconds) });

	const clientIp = ingressSecret ? await verifiedIngressIp(req, ingressSecret, INGRESS_CONTEXT) : null;
	if (clientIp) {
		const perClient = await consumeRateLimit(supabase, `device_poll:v2:client:${await ingressIpBucket(clientIp)}`, POLL_CLIENT_RL_PER_MIN);
		if (perClient.status !== "allowed") return limited(perClient);
	}
	const aggregate = await consumeRateLimit(
		supabase, clientIp ? "device_poll:v2:signed-aggregate" : "device_poll:v1:aggregate", POLL_AGGREGATE_RL_PER_MIN,
	);
	if (aggregate.status !== "allowed") return limited(aggregate);

	const deviceHash = await sha256Hex(deviceCode);
	const { data: row, error } = await supabase
		.from("device_sessions")
		.select("id,user_id,tenant_id,authorized_at,exchanged_at,expires_at,user_code")
		.eq("device_code_hash", deviceHash)
		.maybeSingle();

	if (error) return corsJson(req, 503, { error: "device_session_lookup_failed", enrollment_outcome: "unknown" });
	if (!row) return corsJson(req, 401, { error: "device_code_invalid" });
	const session = row as DeviceSessionRow;
	const perDevice = await consumeRateLimit(supabase, `device_poll:v1:device:${deviceHash}`, POLL_DEVICE_RL_PER_MIN);
	if (perDevice.status !== "allowed") return limited(perDevice);
	const precheck = evaluateDevicePollState({
		nowMs: Date.now(),
		expiresAtIso: session.expires_at,
		authorizedAt: session.authorized_at,
		userId: session.user_id,
		pilotApproved: true,
		exchangedAt: session.exchanged_at,
	});
	// An issued token can outlive its device session. Allow recovery while that
	// token is still valid; an unexchanged expired code cannot issue anything.
	if (precheck.status === "expired" && !session.exchanged_at) {
		return corsJson(req, precheck.httpStatus, { error: precheck.error });
	}
	if (precheck.status === "pending") {
		return corsJson(req, 200, {
			ok: true,
			status: "pending",
			error: "authorization_pending",
			interval_seconds: Math.max(1, Math.floor(DEVICE_POLL_INTERVAL_SECONDS || 3)),
		});
	}
	if (!session.authorized_at || !session.user_id) return corsJson(req, 401, { error: "device_code_invalid" });

	const userId = String(session.user_id);
	const tenantId = session.tenant_id ?? userId;
	const admission = await ensureTenantAdmitted(supabase, userId, tenantId);
	if (admission === "unknown") return corsJson(req, 503, { error: "tenant_admission_unavailable", enrollment_outcome: "unknown" });
	if (admission === "forbidden") return corsJson(req, 403, { error: "tenant_not_admitted" });

	const token = await enrollmentTokenForDeviceCode(deviceCode);
	const tokenHash = await sha256Hex(token);
	const recover = async (): Promise<Response> => {
		const recovered = await recoverIssuedToken(supabase, tokenHash, userId, tenantId);
		if (recovered.status === "unknown") {
			return corsJson(req, 503, { error: "device_exchange_recovery_failed", enrollment_outcome: "unknown" });
		}
		if (recovered.status === "missing") return corsJson(req, 409, { error: "already_exchanged" });
		if (recovered.status !== "available") return corsJson(req, 503, { error: "device_exchange_recovery_failed", enrollment_outcome: "unknown" });
		return corsJson(req, 200, {
			ok: true, status: "approved", enrollment_token: token, expires_at: recovered.expiresAt,
		});
	};

	if (precheck.status === "already_exchanged" || session.exchanged_at) return await recover();

	// The RPC persists the hash-only token and consumes the device session in
	// one transaction. Every retry submits the same hash, and a lost response can
	// be recovered by checking the committed token row.
	const expiresAt = addHoursIso(ENROLLMENT_TOKEN_TTL_HOURS);
	const { data: issuedData, error: issueErr } = await supabase.rpc("issue_device_enrollment_token", {
		p_device_code_hash: deviceHash,
		p_token_hash: tokenHash,
		p_expires_at: expiresAt,
	});
	if (issueErr) return corsJson(req, 503, { error: "device_exchange_failed", enrollment_outcome: "unknown" });
	const issued = issuedData && typeof issuedData === "object" && !Array.isArray(issuedData)
		? issuedData as Record<string, unknown> : null;
	if (issued?.status === "tenant_not_admitted") return corsJson(req, 403, { error: "tenant_not_admitted" });
	if (issued?.status === "already_exchanged_or_invalid") return await recover();
	if (issued?.status !== "issued") return corsJson(req, 503, { error: "device_exchange_result_invalid", enrollment_outcome: "unknown" });

	return corsJson(req, 200, {
		ok: true,
		status: "approved",
		enrollment_token: token,
		expires_at: expiresAt,
	});
});
