import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { sha256 } from "../_shared/runtime-policy.ts";

// Historical UI route name: this accepts an invitation for an ALREADY verified session.
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 16 * 1024;

export interface OAuthCallbackDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: ReturnType<typeof createClient<any, "public">>;
	/** Overrides the client transport; used by the contract suite. */
	fetch?: typeof fetch;
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createOAuthCallbackHandler(deps: OAuthCallbackDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("oauth-callback", config.error, (status, body) => corsJson(req, status, body));
		try {
			const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false }, global: { fetch: deps.fetch } });
			const token = getBearerToken(req.headers.get("Authorization"));
			if (!token) return corsJson(req, 401, { error: "missing_access_token" });
			const { data: auth, error } = await db.auth.getUser(token);
			if (error || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
			const identity = await checkIdentityBarrier(db, token, auth.user.id);
			if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok && parsed.status === 413) return corsJson(req, 413, { error: "request_too_large" });
			if (!parsed.ok) return corsJson(req, 400, { error: "invalid_json" });
			const body = parsed.value as Record<string, unknown>;
			if (!body || typeof body.invite_token !== "string" || !/^[a-f0-9]{64}$/.test(body.invite_token)) return corsJson(req, 400, { error: "invalid_invitation" });
			const inviteHash = await sha256(body.invite_token);
			const { data: invitation, error: invitationError } = await db.from("team_invitations").select("tenant_id").eq("token_hash", inviteHash).maybeSingle();
			if (invitationError) return corsJson(req, 503, { error: "invitation_unavailable" });
			if (!invitation?.tenant_id) return corsJson(req, 403, { error: "invitation_not_accepted" });
			const tenantIdentity = await checkIdentityBarrier(db, token, auth.user.id, invitation.tenant_id);
			if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error });
			const { data, error: acceptError } = await db.rpc("accept_team_invitation", { p_hash: inviteHash, p_user_id: auth.user.id });
			if (acceptError) return corsJson(req, acceptError.code === "42501" ? 403 : 503, { error: "invitation_not_accepted" });
			// Fail closed on an unconfirmed or foreign redemption result: only the
			// invitation's own tenant, named by the privileged RPC, is an acceptance.
			if (typeof data !== "string" || data !== invitation.tenant_id) return corsJson(req, 503, { error: "invitation_unavailable" });
			return corsJson(req, 200, { ok: true, team_id: data });
		} catch { return corsJson(req, 503, { error: "invitation_unavailable" }); }
	};
}

Deno.serve(createOAuthCallbackHandler());
