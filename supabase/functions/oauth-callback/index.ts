import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { sha256 } from "../_shared/runtime-policy.ts";

// Historical UI route name: this accepts an invitation for an ALREADY verified session.
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("oauth-callback", config.error, (status, body) => corsJson(req, status, body));
	try {
		const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const { data: auth, error } = await db.auth.getUser(token);
		if (error || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
		const identity = await checkIdentityBarrier(db, token, auth.user.id);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
		let body: Record<string, unknown>;
		try { body = await req.json(); } catch { return corsJson(req, 400, { error: "invalid_json" }); }
		if (!body || typeof body.invite_token !== "string" || !/^[a-f0-9]{64}$/.test(body.invite_token)) return corsJson(req, 400, { error: "invalid_invitation" });
		const inviteHash = await sha256(body.invite_token);
		const { data: invitation, error: invitationError } = await db.from("team_invitations").select("tenant_id").eq("token_hash", inviteHash).maybeSingle();
		if (invitationError) return corsJson(req, 503, { error: "invitation_unavailable" });
		if (!invitation?.tenant_id) return corsJson(req, 403, { error: "invitation_not_accepted" });
		const tenantIdentity = await checkIdentityBarrier(db, token, auth.user.id, invitation.tenant_id);
		if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error });
		const { data, error: acceptError } = await db.rpc("accept_team_invitation", { p_hash: inviteHash, p_user_id: auth.user.id });
		if (acceptError) return corsJson(req, acceptError.code === "42501" ? 403 : 503, { error: "invitation_not_accepted" });
		return corsJson(req, 200, { ok: true, team_id: data });
	} catch { return corsJson(req, 503, { error: "invitation_unavailable" }); }
});
