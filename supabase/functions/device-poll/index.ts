// Supabase Edge Function: POST /v1/device/poll
//
// Auth: none (device-code bootstrap)
//
// Polls the device session. Once authorized and tenant-admitted, returns an enrollment token
// that can be exchanged via POST /v1/enroll.
//
// Abuse controls: every poll of a live device code consumes a per-device-code
// budget in the same reviewed `increment_rate_limit` RPC that device-start uses.
// A client that polls faster than the advertised interval receives the RFC 8628
// `slow_down` error with an interval raised by five seconds. Rate-limit storage
// failures fail closed (no token is issued while the budget cannot be read).
//
// The device poll has no trusted ingress proof, so caller IP headers are not
// used as a key (they are caller-controlled and would let an attacker mint
// unbounded counter rows). One aggregate bucket therefore bounds every lookup,
// including invalid codes, before the per-device-code budget applies.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { readDeviceCode } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { evaluateDevicePollState } from "../_shared/device-auth.ts";
import { consumeRateLimit, type RateLimitDb, validRateLimit } from "../_shared/rate-limit.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

/** RFC 8628 section 3.5: a `slow_down` response raises the interval by 5 seconds. */
export const DEVICE_POLL_SLOW_DOWN_INCREMENT_SECONDS = 5;
// Poll budget keys stay inside the reviewed `device_start` scope of the
// `increment_rate_limit` allowlist (20260913000005). One key per device-code
// hash, so the counter rows are bounded by the device-start issue rate.
const DEVICE_POLL_RATE_LIMIT_PREFIX = "device_start:v2:poll:";
const makeClient = (url: string, key: string) => createClient(url, key, { auth: { persistSession: false } });
type DevicePollClient = ReturnType<typeof makeClient>;

export interface DevicePollDeps {
	/** Service-role client factory; the contract suite injects a fake database. */
	createDb?: (url: string, serviceRoleKey: string) => DevicePollClient;
	/** Clock in epoch milliseconds. */
	now?: () => number;
}

type DevicePollSettings = {
	intervalSeconds: number;
	enrollmentTokenTtlHours: number;
	pollsPerMinute: number;
	aggregatePerMinute: number;
	invalid: string[];
};

const DEVICE_POLL_AGGREGATE_KEY = "device_poll:v1:aggregate";

function readSettings(env: EnvReader): DevicePollSettings {
	const intervalRaw = Number(env("AIDR_DEVICE_POLL_INTERVAL_SECONDS") ?? "3");
	const intervalSeconds = Math.max(1, Math.floor(intervalRaw || 3));
	const enrollmentTokenTtlHours = Number(env("AIDR_DEVICE_ENROLLTOKEN_TTL_HOURS") ?? "24");
	// A compliant client polls ceil(60 / interval) times per minute. The slack
	// absorbs a dashboard tab and a native hook polling the same code together,
	// and the fixed one-minute window boundary.
	const rawLimit = env("AIDR_DEVICE_POLL_RL_PER_MIN");
	const pollsPerMinute = rawLimit === undefined || rawLimit === null || rawLimit === ""
		? Math.ceil(60 / intervalSeconds) + 10
		: Number(rawLimit);
	const invalid: string[] = [];
	if (!Number.isSafeInteger(pollsPerMinute) || pollsPerMinute < 1 || pollsPerMinute > 600) {
		invalid.push("AIDR_DEVICE_POLL_RL_PER_MIN");
	}
	const aggregatePerMinute = Number(env("AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN") ?? "6000");
	if (!validRateLimit(aggregatePerMinute, 1_000_000) || aggregatePerMinute < pollsPerMinute) {
		invalid.push("AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN");
	}
	return { intervalSeconds, enrollmentTokenTtlHours, pollsPerMinute, aggregatePerMinute, invalid };
}

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

function addHoursIso(nowMs: number, hours: number): string {
	const safe = Number.isFinite(hours) ? Math.max(1, Math.min(24 * 30, Math.floor(hours))) : 24;
	return new Date(nowMs + safe * 60 * 60 * 1000).toISOString();
}

type PollBudget = "within" | "exceeded" | "unavailable";

/**
 * Consumes one poll from the per-device-code budget of the current minute.
 * Storage failures are reported as `unavailable` and never as an allowance.
 */
async function consumePollBudget(
	supabase: DevicePollClient,
	deviceHash: string,
	nowMs: number,
	limit: number,
): Promise<PollBudget> {
	const key = `${DEVICE_POLL_RATE_LIMIT_PREFIX}${deviceHash}`;
	const windowStart = Math.floor(nowMs / 60_000);
	try {
		const { error } = await supabase.rpc("increment_rate_limit", {
			p_key: key,
			p_window_start: windowStart,
			p_delta: 1,
		});
		if (error) return "unavailable";
		const { data, error: countError } = await supabase
			.from("rate_limits")
			.select("count")
			.eq("key", key)
			.eq("window_start", windowStart)
			.maybeSingle();
		if (countError) return "unavailable";
		const count = data && typeof data === "object" && "count" in data ? Number(data.count) : Number.NaN;
		if (!Number.isSafeInteger(count) || count < 1) return "unavailable";
		return count <= limit ? "within" : "exceeded";
	} catch {
		return "unavailable";
	}
}

async function ensureTenantAdmitted(
	supabase: DevicePollClient,
	userId: string,
	tenantId: string,
	nowMs: number,
): Promise<"active" | "forbidden" | "unknown"> {
	const { data: capacity, error } = await supabase.rpc("tenant_admission_capacity", { p_tenant_id: tenantId });
	if (error || !Number.isSafeInteger(capacity) || Number(capacity) < 0) return "unknown";
	if (Number(capacity) === 0) return "forbidden";
	const membership = await supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
	const tenant = await supabase.from("tenants").select("status").eq("id", tenantId).maybeSingle();
	if (membership.error || tenant.error) return "unknown";
	return tenant.data?.status === "active" && membership.data && ["owner", "admin", "member"].includes(membership.data.role) && (!membership.data.expires_at || Date.parse(membership.data.expires_at) > nowMs)
		? "active" : "forbidden";
}

async function recoverIssuedToken(
	supabase: DevicePollClient,
	tokenHash: string,
	userId: string,
	tenantId: string,
	nowMs: number,
): Promise<{ status: "available"; expiresAt: string } | { status: "missing" | "unknown" }> {
	const { data, error } = await supabase.from("enrollment_tokens")
		.select("expires_at,consumed_at")
		.eq("token_hash", tokenHash).eq("user_id", userId).eq("tenant_id", tenantId)
		.maybeSingle();
	if (error) return { status: "unknown" };
	const row = data as EnrollmentTokenRow | null;
	if (!row || row.consumed_at || !Number.isFinite(Date.parse(row.expires_at)) || Date.parse(row.expires_at) <= nowMs) {
		return { status: "missing" };
	}
	return { status: "available", expiresAt: row.expires_at };
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createDevicePollHandler(deps: DevicePollDeps = {}) {
	const now = deps.now ?? Date.now;
	const connect = deps.createDb ?? makeClient;

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("device-poll", config.error, (status, body) => corsJson(req, status, body));
		}
		const settings = readSettings(runtimeEnv);
		if (settings.invalid.length > 0) {
			return corsJson(req, 500, { error: "server_misconfigured", invalid: settings.invalid });
		}
		const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

		const deviceCode = await readDeviceCode(req);

		if (!deviceCode) return corsJson(req, 401, { error: "missing_device_code" });

		const supabase = connect(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

		// Aggregate bound on all lookups (invalid codes included); fails closed.
		const aggregate = await consumeRateLimit(
			supabase as unknown as RateLimitDb,
			DEVICE_POLL_AGGREGATE_KEY,
			settings.aggregatePerMinute,
			now(),
		);
		if (aggregate.status === "limited") {
			return corsJson(req, 429, { error: "rate_limited", retry_after_seconds: aggregate.retryAfterSeconds }, {
				"Retry-After": String(aggregate.retryAfterSeconds),
			});
		}
		if (aggregate.status === "unavailable") {
			return corsJson(req, 503, { error: "rate_limit_unavailable", enrollment_outcome: "unknown" }, {
				"Retry-After": String(aggregate.retryAfterSeconds),
			});
		}

		const deviceHash = await sha256Hex(deviceCode);
		const { data: row, error } = await supabase
			.from("device_sessions")
			.select("id,user_id,tenant_id,authorized_at,exchanged_at,expires_at,user_code")
			.eq("device_code_hash", deviceHash)
			.maybeSingle();

		if (error) return corsJson(req, 503, { error: "device_session_lookup_failed", enrollment_outcome: "unknown" });
		if (!row) return corsJson(req, 401, { error: "device_code_invalid" });
		const session = row as DeviceSessionRow;
		const precheck = evaluateDevicePollState({
			nowMs: now(),
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

		// Budget every poll of a live code before any admission or issue work. The
		// key is the device-code hash, so it exists only for codes device-start
		// minted, and its window counter is shared by every client polling it.
		const budget = await consumePollBudget(supabase, deviceHash, now(), settings.pollsPerMinute);
		if (budget === "unavailable") {
			return corsJson(req, 503, { error: "rate_limit_unavailable", enrollment_outcome: "unknown" }, {
				"Retry-After": String(settings.intervalSeconds),
			});
		}
		if (budget === "exceeded") {
			const slowerInterval = settings.intervalSeconds + DEVICE_POLL_SLOW_DOWN_INCREMENT_SECONDS;
			return corsJson(req, 400, { error: "slow_down", interval_seconds: slowerInterval }, {
				"Retry-After": String(slowerInterval),
			});
		}

		if (precheck.status === "pending") {
			return corsJson(req, 200, {
				ok: true,
				status: "pending",
				error: "authorization_pending",
				interval_seconds: settings.intervalSeconds,
			});
		}
		if (!session.authorized_at || !session.user_id) return corsJson(req, 401, { error: "device_code_invalid" });

		const userId = String(session.user_id);
		const tenantId = session.tenant_id ?? userId;
		const admission = await ensureTenantAdmitted(supabase, userId, tenantId, now());
		if (admission === "unknown") return corsJson(req, 503, { error: "tenant_admission_unavailable", enrollment_outcome: "unknown" });
		if (admission === "forbidden") return corsJson(req, 403, { error: "tenant_not_admitted" });

		const token = await enrollmentTokenForDeviceCode(deviceCode);
		const tokenHash = await sha256Hex(token);
		const recover = async (): Promise<Response> => {
			const recovered = await recoverIssuedToken(supabase, tokenHash, userId, tenantId, now());
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
		const expiresAt = addHoursIso(now(), settings.enrollmentTokenTtlHours);
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
	};
}

Deno.serve(createDevicePollHandler());
