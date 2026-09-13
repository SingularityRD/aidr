// Supabase Edge Function: POST /v1/device/poll
//
// Auth: none (device-code bootstrap)
//
// Polls the device session. Once authorized (and pilot-approved), returns an enrollment token
// that can be exchanged via POST /v1/enroll.

import { createClient } from "npm:@supabase/supabase-js@2";
import { readDeviceCode } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { evaluateDevicePollState } from "../_shared/device-auth.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

const DEVICE_POLL_INTERVAL_SECONDS = Number(Deno.env.get("AIDR_DEVICE_POLL_INTERVAL_SECONDS") ?? "3");
const ENROLLMENT_TOKEN_TTL_HOURS = Number(Deno.env.get("AIDR_DEVICE_ENROLLTOKEN_TTL_HOURS") ?? "24");

type PilotApplicationRow = { status: string | null };
type PilotApproval = "approved" | "forbidden" | "unknown";
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

async function ensurePilotApproved(
	supabase: ReturnType<typeof createClient>,
	userId: string,
	tenantId: string,
): Promise<PilotApproval> {
	const { data, error } = await supabase
		.from("pilot_applications")
		.select("status")
		.eq("tenant_id", tenantId).eq("status", "approved")
		.limit(1).maybeSingle();
	if (error) return "unknown";
	const row = data as PilotApplicationRow | null;
	if (row?.status !== "approved") return "forbidden";
	const membership = await supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
	const tenant = await supabase.from("tenants").select("status").eq("id", tenantId).maybeSingle();
	if (membership.error || tenant.error) return "unknown";
	return tenant.data?.status === "active" && membership.data && ["owner", "admin", "member"].includes(membership.data.role) && (!membership.data.expires_at || Date.parse(membership.data.expires_at) > Date.now())
		? "approved" : "forbidden";
}

async function recoverIssuedToken(
	supabase: ReturnType<typeof createClient>,
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

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

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
	const approval = await ensurePilotApproved(supabase, userId, tenantId);
	if (approval === "unknown") return corsJson(req, 503, { error: "pilot_approval_lookup_failed", enrollment_outcome: "unknown" });
	if (approval === "forbidden") return corsJson(req, 403, { error: "pilot_not_approved" });

	const token = await enrollmentTokenForDeviceCode(deviceCode);
	const tokenHash = await sha256Hex(token);
	const recover = async (): Promise<Response> => {
		const recovered = await recoverIssuedToken(supabase, tokenHash, userId, tenantId);
		if (recovered.status === "unknown") {
			return corsJson(req, 503, { error: "device_exchange_recovery_failed", enrollment_outcome: "unknown" });
		}
		if (recovered.status === "missing") return corsJson(req, 409, { error: "already_exchanged" });
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
	if (issued?.status === "pilot_not_approved") return corsJson(req, 403, { error: "pilot_not_approved" });
	if (issued?.status === "already_exchanged_or_invalid") return await recover();
	if (issued?.status !== "issued") return corsJson(req, 503, { error: "device_exchange_result_invalid", enrollment_outcome: "unknown" });

	return corsJson(req, 200, {
		ok: true,
		status: "approved",
		enrollment_token: token,
		expires_at: expiresAt,
	});
});
