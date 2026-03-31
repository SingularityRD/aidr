// Supabase Edge Function: POST /v1/pilot/apply
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Creates or resets a pilot application for the authenticated user.

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
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "misconfigured_supabase_env" });

	const accessToken = getBearerToken(req);
	if (!accessToken) return json(401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });
	const userId = userData.user.id;

	const { data: existing } = await supabase
		.from("pilot_applications")
		.select("status")
		.eq("user_id", userId)
		.maybeSingle();

	const status = (existing as any)?.status === "approved" ? "approved" : "pending";

	await supabase.from("pilot_applications").upsert(
		{
			user_id: userId,
			status,
		},
		{ onConflict: "user_id" },
	);

	await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		action: "pilot.apply",
		target_user_id: userId,
		detail: {},
	});

	return json(200, { ok: true, status });
});

