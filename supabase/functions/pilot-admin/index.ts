// Supabase Edge Function: POST /v1/pilot/admin
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Admin-only pilot approvals. The caller must be listed in public.pilot_admins.

import { createClient } from "npm:@supabase/supabase-js@2";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

function isUuid(s: string): boolean {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
		s.trim(),
	);
}

Deno.serve(async (req) => {
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("pilot-admin", config.error, json);
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const accessToken = getBearerToken(req);
	if (!accessToken) return json(401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });
	const actorId = userData.user.id;
	const identity = await checkIdentityBarrier(supabase, accessToken, actorId);
	if (!identity.ok) return json(identity.status, { error: identity.error });

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
			tenant_id: targetUserId,
			status,
			cohort,
			notes,
		},
		{ onConflict: "user_id" },
	);

	await supabase.from("admin_audit_logs").insert({
		actor_user_id: actorId,
		tenant_id: targetUserId,
		action: `pilot.${action}`,
		target_user_id: targetUserId,
		detail: { cohort, notes },
	});

	return json(200, { ok: true, user_id: targetUserId, status });
});
