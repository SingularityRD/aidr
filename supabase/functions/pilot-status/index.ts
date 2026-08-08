// Supabase Edge Function: GET /v1/pilot/status
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Returns current pilot application status for the authenticated user.

import { createClient } from "npm:@supabase/supabase-js@2";
import { corsJson, handleCors } from "../_shared/cors.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "GET") return corsJson(req, 405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return corsJson(req, 500, { error: "misconfigured_supabase_env" });

	const accessToken = getBearerToken(req);
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = userData.user.id;

	const { data, error: statusError } = await supabase
		.from("pilot_applications")
		.select("status,cohort,created_at,updated_at")
		.eq("user_id", userId)
		.eq("tenant_id", userId)
		.maybeSingle();

	if (statusError) return corsJson(req, 500, { error: "pilot_status_unavailable" });
	if (!data) return corsJson(req, 200, { ok: true, status: "none" });
	return corsJson(req, 200, { ok: true, ...data });
});
