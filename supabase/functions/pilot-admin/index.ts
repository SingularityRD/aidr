// Supabase Edge Function: POST /v1/pilot/admin
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Admin-only pilot approvals. The caller must be listed in public.pilot_admins.

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

function isUuid(s: string): boolean {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
		s.trim(),
	);
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
	const actorId = userData.user.id;

	const { data: adminRow } = await supabase
		.from("pilot_admins")
		.select("user_id")
		.eq("user_id", actorId)
		.maybeSingle();
	if (!adminRow) return json(403, { error: "forbidden" });

	let body: Record<string, unknown> = {};
	try {
		body = (await req.json()) as Record<string, unknown>;
	} catch {
		body = {};
	}

	const action = typeof body.action === "string" ? body.action.trim() : "";
	if (action !== "approve" && action !== "deny") return json(400, { error: "invalid_action" });

	let targetUserId =
		typeof body.user_id === "string" && isUuid(body.user_id) ? body.user_id.trim() : "";

	if (!targetUserId) {
		const email = typeof body.email === "string" ? body.email.trim() : "";
		if (!email || !email.includes("@")) return json(400, { error: "missing_target" });
		const { data: mapped } = await supabase.rpc("user_id_by_email", { p_email: email });
		if (typeof mapped === "string" && isUuid(mapped)) targetUserId = mapped;
	}

	if (!targetUserId) return json(404, { error: "user_not_found" });

	const cohort = typeof body.cohort === "string" ? body.cohort.trim() : null;
	const notes = typeof body.notes === "string" ? body.notes.trim() : null;
	const status = action === "approve" ? "approved" : "denied";

	await supabase.from("pilot_applications").upsert(
		{
			user_id: targetUserId,
			status,
			cohort,
			notes,
		},
		{ onConflict: "user_id" },
	);

	await supabase.from("admin_audit_logs").insert({
		actor_user_id: actorId,
		action: `pilot.${action}`,
		target_user_id: targetUserId,
		detail: { cohort, notes },
	});

	return json(200, { ok: true, user_id: targetUserId, status });
});

