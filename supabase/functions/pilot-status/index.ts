// Supabase Edge Function: GET /v1/pilot/status
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Returns current pilot application status for the authenticated user.

import { createClient } from "npm:@supabase/supabase-js@2";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

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
	if (req.method !== "GET") return corsJson(req, 405, { error: "method_not_allowed" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("pilot-status", config.error, (status, body) => corsJson(req, status, body));
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
	const requested = req.headers.get("X-AIDR-Tenant-ID")?.trim();
	if (requested) {
		if (!/^[a-f0-9-]{36}$/i.test(requested)) return corsJson(req, 400, { error: "invalid_tenant" });
		const tenantIdentity = await checkIdentityBarrier(supabase, accessToken, userId, requested);
		if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error });
		const membership = await supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", requested).eq("user_id", userId).maybeSingle();
		const state = await supabase.from("tenants").select("status").eq("id", requested).maybeSingle();
		if (membership.error || state.error) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (!membershipActive(membership.data) || state.data?.status !== "active") return corsJson(req, 403, { error: "tenant_access_denied" });
		const approval = await supabase.from("pilot_applications").select("status,cohort,tenant_id,created_at,updated_at").eq("tenant_id", requested).eq("status", "approved").limit(1).maybeSingle();
		if (approval.error) return corsJson(req, 503, { error: "pilot_status_unavailable" });
		return corsJson(req, 200, { ok: true, status: "none", tenant_id: requested, ...approval.data });
	}

	const { data, error: statusError } = await supabase
		.from("pilot_applications")
		.select("status,cohort,tenant_id,created_at,updated_at")
		.eq("user_id", userId)
		.maybeSingle();

	if (statusError) return corsJson(req, 500, { error: "pilot_status_unavailable" });
	if (!data) return corsJson(req, 200, { ok: true, status: "none" });
	const tenantIdentity = await checkIdentityBarrier(supabase, accessToken, userId, data.tenant_id);
	if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error });
	return corsJson(req, 200, { ok: true, ...data });
});
