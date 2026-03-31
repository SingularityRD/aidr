// Supabase Edge Function: POST /v1/device/verify
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Attaches an authenticated user to a device session (by user_code).
// Requires the user to be pilot-approved.

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { evaluateDeviceVerifyState } from "../_shared/device-auth.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

type PilotApplicationRow = { status: string | null };
type DeviceSessionRow = {
	id: string;
	authorized_at: string | null;
	expires_at: string;
	user_id: string | null;
};

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
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

	const accessToken = getBearerToken(req.headers.get("Authorization"));
	if (!accessToken) return json(401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });
	const userId = userData.user.id;

	let body: Record<string, unknown> = {};
	try {
		body = (await req.json()) as Record<string, unknown>;
	} catch {
		body = {};
	}
	const userCode = typeof body.user_code === "string" ? body.user_code.trim().toUpperCase() : "";
	if (!userCode) return json(400, { error: "missing_user_code" });

	const approved = await ensurePilotApproved(supabase, userId);
	if (!approved) return json(403, { error: "pilot_not_approved" });

	const { data: row, error } = await supabase
		.from("device_sessions")
		.select("id,authorized_at,expires_at,user_id")
		.eq("user_code", userCode)
		.maybeSingle();
	if (error || !row) return json(404, { error: "device_code_invalid" });
	const session = row as DeviceSessionRow;
	const state = evaluateDeviceVerifyState({
		nowMs: Date.now(),
		expiresAtIso: session.expires_at,
		authorizedAt: session.authorized_at,
		pilotApproved: approved,
	});
	if (state.status !== "ok") return json(state.httpStatus, { error: state.error });

	const { error: updErr } = await supabase
		.from("device_sessions")
		.update({
			user_id: userId,
			authorized_at: new Date().toISOString(),
			status: "authorized",
		})
		.eq("id", session.id)
		.is("authorized_at", null);

	if (updErr) return json(409, { error: "device_code_race" });

	await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		action: "device.verify",
		target_user_id: userId,
		detail: { user_code: userCode },
	});

	return json(200, { ok: true });
});
