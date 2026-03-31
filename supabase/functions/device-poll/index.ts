// Supabase Edge Function: POST /v1/device/poll
//
// Auth: none (device-code bootstrap)
//
// Polls the device session. Once authorized (and pilot-approved), returns an enrollment token
// that can be exchanged via POST /v1/enroll.

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { evaluateDevicePollState } from "../_shared/device-auth.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const DEVICE_POLL_INTERVAL_SECONDS = Number(Deno.env.get("AIDR_DEVICE_POLL_INTERVAL_SECONDS") ?? "3");
const ENROLLMENT_TOKEN_TTL_HOURS = Number(Deno.env.get("AIDR_DEVICE_ENROLLTOKEN_TTL_HOURS") ?? "24");

type PilotApplicationRow = { status: string | null };
type DeviceSessionRow = {
	id: string;
	user_id: string | null;
	authorized_at: string | null;
	exchanged_at: string | null;
	expires_at: string;
	user_code: string | null;
};

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
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
	const safe = Number.isFinite(hours) ? Math.max(1, Math.min(24 * 30, Math.floor(hours))) : 24;
	return new Date(Date.now() + safe * 60 * 60 * 1000).toISOString();
}

async function ensurePilotApproved(
	supabase: ReturnType<typeof createClient>,
	userId: string,
): Promise<boolean> {
	const { data } = await supabase
		.from("pilot_applications")
		.select("status")
		.eq("user_id", userId)
		.maybeSingle();
	const row = data as PilotApplicationRow | null;
	return row?.status === "approved";
}

Deno.serve(async (req) => {
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "misconfigured_supabase_env" });

	let deviceCode = getBearerToken(req.headers.get("Authorization"));
	if (!deviceCode) {
		try {
			const body = (await req.json()) as Record<string, unknown>;
			deviceCode = typeof body.device_code === "string" ? body.device_code.trim() : null;
		} catch {
			deviceCode = null;
		}
	}

	if (!deviceCode) return json(401, { error: "missing_device_code" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const deviceHash = await sha256Hex(deviceCode);
	const { data: row, error } = await supabase
		.from("device_sessions")
		.select("id,user_id,authorized_at,exchanged_at,expires_at,user_code")
		.eq("device_code_hash", deviceHash)
		.maybeSingle();

	if (error || !row) return json(401, { error: "device_code_invalid" });
	const session = row as DeviceSessionRow;
	const precheck = evaluateDevicePollState({
		nowMs: Date.now(),
		expiresAtIso: session.expires_at,
		authorizedAt: session.authorized_at,
		userId: session.user_id,
		pilotApproved: true,
		exchangedAt: session.exchanged_at,
	});
	if (precheck.status === "expired") return json(precheck.httpStatus, { error: precheck.error });
	if (precheck.status === "pending") {
		return json(200, {
			ok: true,
			status: "pending",
			error: "authorization_pending",
			interval_seconds: Math.max(1, Math.floor(DEVICE_POLL_INTERVAL_SECONDS || 3)),
		});
	}

	const userId = String(session.user_id);
	const approved = await ensurePilotApproved(supabase, userId);
	if (!approved) return json(403, { error: "pilot_not_approved" });

	if (precheck.status === "already_exchanged") {
		return json(409, { error: "already_exchanged" });
	}

	// Issue a one-time enrollment token (hash-only at rest).
	const expiresAt = addHoursIso(ENROLLMENT_TOKEN_TTL_HOURS);
	let token = "";
	let inserted = false;
	for (let i = 0; i < 5; i++) {
		token = randomEnrollmentToken();
		const tokenHash = await sha256Hex(token);
		const { error: insErr } = await supabase.from("enrollment_tokens").insert({
			user_id: userId,
			label: `device:${String(session.user_code ?? "").slice(0, 16)}`,
			token_hash: tokenHash,
			expires_at: expiresAt,
		});
		if (!insErr) {
			inserted = true;
			break;
		}
	}
	if (!inserted) return json(500, { error: "token_issue_failed" });

	await supabase
		.from("device_sessions")
		.update({ exchanged_at: new Date().toISOString(), status: "exchanged" })
		.eq("id", session.id);

	return json(200, {
		ok: true,
		status: "approved",
		enrollment_token: token,
		expires_at: expiresAt,
	});
});
