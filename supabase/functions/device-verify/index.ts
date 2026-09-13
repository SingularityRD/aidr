// Supabase Edge Function: POST /v1/device/verify
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Attaches an authenticated user to a device session (by user_code).
// Requires the user to be pilot-approved.

import { createClient } from "npm:@supabase/supabase-js@2";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { evaluateDeviceVerifyState } from "../_shared/device-auth.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

type PilotApplicationRow = { status: string | null; tenant_id: string };
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
	tenantId?: string,
): Promise<PilotApplicationRow | null> {
	let query = supabase
		.from("pilot_applications")
		.select("status,tenant_id").eq("status", "approved");
	query = tenantId ? query.eq("tenant_id", tenantId) : query.eq("user_id", userId);
	const { data } = await query.limit(1).maybeSingle();
	const row = data as PilotApplicationRow | null;
	return row?.status === "approved" ? row : null;
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
	const approved = await ensurePilotApproved(supabase, userId, session.tenant_id ?? requested);
	if (!approved) return corsJson(req, 403, { error: "pilot_not_approved" });
	const tenantId = session.tenant_id ?? requested ?? approved.tenant_id;
	const identity = await checkIdentityBarrier(supabase, accessToken, userId, tenantId);
	if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
	const { data: tenant } = await supabase.from("tenants").select("status").eq("id", tenantId).maybeSingle();
	const { data: member } = await supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
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
		},
	);
	if (authorizeErr) return corsJson(req, 500, { error: "device_authorization_unavailable" });
	if (!Array.isArray(authorizedRows) || authorizedRows.length === 0) {
		return corsJson(req, 409, { error: "device_code_race" });
	}

	const { error: auditError } = await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		tenant_id: tenantId,
		action: "device.verify",
		target_user_id: userId,
		detail: { user_code: userCode },
	});
	if (auditError) return corsJson(req, 500, { error: "device_audit_unavailable" });

	return corsJson(req, 200, { ok: true });
});
