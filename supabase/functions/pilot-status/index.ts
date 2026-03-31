// Supabase Edge Function: GET /v1/pilot/status
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Returns current pilot application status for the authenticated user.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

Deno.serve(async (req) => {
	if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "misconfigured_supabase_env" });

	const accessToken = getBearerToken(req);
	if (!accessToken) return json(401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });
	const userId = userData.user.id;

	const { data } = await supabase
		.from("pilot_applications")
		.select("status,cohort,created_at,updated_at")
		.eq("user_id", userId)
		.maybeSingle();

	if (!data) return json(200, { ok: true, status: "none" });
	return json(200, { ok: true, ...data });
});

