// Supabase Edge Function: POST /v1/device/verify
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Attaches an authenticated user to a device session (by user_code).
// Requires the user to be pilot-approved.

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { evaluateDeviceVerifyState } from "../_shared/device-auth.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

type PilotApplicationRow = { status: string | null };
type DeviceSessionRow = {
	id: string;
	authorized_at: string | null;
	expires_at: string;
	user_id: string | null;
	tenant_id: string | null;
};

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
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return corsJson(req, 500, { error: "misconfigured_supabase_env" });

	const accessToken = getBearerToken(req.headers.get("Authorization"));
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = userData.user.id;

	let body: Record<string, unknown> = {};
	try {
		body = (await req.json()) as Record<string, unknown>;
	} catch {
		body = {};
	}
	const userCode = typeof body.user_code === "string" ? body.user_code.trim().toUpperCase() : "";
	if (!userCode) return corsJson(req, 400, { error: "missing_user_code" });

	const approved = await ensurePilotApproved(supabase, userId);
	if (!approved) return corsJson(req, 403, { error: "pilot_not_approved" });

	const { data: row, error } = await supabase
		.from("device_sessions")
		.select("id,authorized_at,expires_at,user_id,tenant_id")
		.eq("user_code", userCode)
		.maybeSingle();
	if (error || !row) return corsJson(req, 404, { error: "device_code_invalid" });
	const session = row as DeviceSessionRow;
	const state = evaluateDeviceVerifyState({
		nowMs: Date.now(),
		expiresAtIso: session.expires_at,
		authorizedAt: session.authorized_at,
		pilotApproved: approved,
	});
	if (state.status !== "ok") return corsJson(req, state.httpStatus, { error: state.error });

	const { data: authorizedRows, error: authorizeErr } = await supabase.rpc(
		"authorize_device_session",
		{
			p_user_code: userCode,
			p_user_id: userId,
			p_tenant_id: session.tenant_id ?? userId,
		},
	);
	if (authorizeErr) return corsJson(req, 500, { error: "device_authorization_unavailable" });
	if (!Array.isArray(authorizedRows) || authorizedRows.length === 0) {
		return corsJson(req, 409, { error: "device_code_race" });
	}

	const { error: auditError } = await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		tenant_id: session.tenant_id ?? userId,
		action: "device.verify",
		target_user_id: userId,
		detail: { user_code: userCode },
	});
	if (auditError) return corsJson(req, 500, { error: "device_audit_unavailable" });

	return corsJson(req, 200, { ok: true });
});
