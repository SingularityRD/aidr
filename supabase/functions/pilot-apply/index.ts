// Supabase Edge Function: POST /v1/pilot/apply
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Creates or resets a pilot application for the authenticated user.

import { createClient } from "npm:@supabase/supabase-js@2";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("pilot-apply", config.error, (status, body) => corsJson(req, status, body));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	const accessToken = getBearerToken(req);
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	const userId = userData.user.id;
	const identity = await checkIdentityBarrier(supabase, accessToken, userId);
	if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });

	let body: Record<string, unknown> = {};
	try {
		body = (await req.json()) as Record<string, unknown>;
	} catch {
		body = {};
	}
	const notes = typeof body.useCase === "string" ? body.useCase.trim().slice(0, 4000) : null;

	const { data: existing, error: existingError } = await supabase
		.from("pilot_applications")
		.select("status,tenant_id")
		.eq("user_id", userId)
		.maybeSingle();

	if (existingError) return corsJson(req, 503, { error: "pilot_application_unavailable" });
	const status = existing?.status === "approved" ? "approved" : "pending";
	const tenantId = existing?.tenant_id ?? userId;
	const tenantIdentity = await checkIdentityBarrier(supabase, accessToken, userId, tenantId);
	if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error });

	const { error: upsertError } = await supabase.from("pilot_applications").upsert(
		{
			user_id: userId,
			tenant_id: tenantId,
			status,
			notes,
		},
		{ onConflict: "user_id" },
	);
	if (upsertError) return corsJson(req, 500, { error: "pilot_application_unavailable" });

	const { error: auditError } = await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		tenant_id: tenantId,
		action: "pilot.apply",
		target_user_id: userId,
		detail: { has_use_case: Boolean(notes) },
	});
	if (auditError) return corsJson(req, 500, { error: "pilot_audit_unavailable" });

	return corsJson(req, 200, { ok: true, status });
});
