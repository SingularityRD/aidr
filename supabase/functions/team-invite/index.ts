import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import {
	invitationExpiry,
	invitationSecret,
	invitationUrl,
	parseInvitationCommand,
	resendPendingInvitation,
	revokePendingInvitation,
} from "./lifecycle.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_DASHBOARD_URL"] as const;

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("team-invite", config.error, (status, body) => corsJson(req, status, body));
	try {
		const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const { data: auth, error } = await db.auth.getUser(token);
		if (error || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
		let body: unknown;
		try { body = await req.json(); } catch { return corsJson(req, 400, { error: "invalid_json" }); }
		const command = parseInvitationCommand(body);
		if (!command) return corsJson(req, 400, { error: "invalid_invitation" });
		const identity = await checkIdentityBarrier(db, token, auth.user.id, command.teamId);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
		const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", command.teamId).eq("user_id", auth.user.id).maybeSingle();
		if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (!membershipActive(member) || !["owner", "admin"].includes(member?.role)) return corsJson(req, 403, { error: "team_forbidden" });
		const { data: tenant, error: tenantError } = await db.from("tenants").select("status").eq("id", command.teamId).maybeSingle();
		if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (tenant?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });
		if (command.action === "list") {
			const { data, error: listError } = await db.from("team_invitations")
				.select("id,email,role,expires_at,created_at,created_by")
				.eq("tenant_id", command.teamId).is("accepted_at", null)
				.order("created_at", { ascending: false }).limit(100);
			if (listError) return corsJson(req, 503, { error: "invitation_list_failed" });
			return corsJson(req, 200, { ok: true, invitations: data ?? [] }, { "Cache-Control": "no-store" });
		}
		if (command.action === "revoke") {
			const { data, error: revokeError } = await revokePendingInvitation(db, command.teamId, command.invitationId, new Date().toISOString());
			if (revokeError) return corsJson(req, 503, { error: "invitation_revoke_failed" });
			if (!data) return corsJson(req, 404, { error: "invitation_not_pending" });
			return corsJson(req, 200, { ok: true, invitation_id: data.id });
		}

		const minute = Math.floor(Date.now() / 60000);
		const limitKey = `team-invite:${auth.user.id}`;
		const { error: limitError } = await db.rpc("increment_rate_limit", { p_key: limitKey, p_window_start: minute, p_delta: 1 });
		const { data: count, error: countError } = await db.from("rate_limits").select("count").eq("key", limitKey).eq("window_start", minute).maybeSingle();
		if (limitError || countError || !count) return corsJson(req, 503, { error: "rate_limit_unavailable" });
		if (count.count > 10) return corsJson(req, 429, { error: "rate_limited" });
		const secret = invitationSecret();
		const inviteUrl = invitationUrl(config.values.AIDR_DASHBOARD_URL, secret);
		const tokenHash = await sha256(secret);
		if (command.action === "resend") {
			const { data, error: resendError } = await resendPendingInvitation(db, command.teamId, command.invitationId, tokenHash, auth.user.id, new Date());
			if (resendError) return corsJson(req, 503, { error: "invitation_resend_failed" });
			if (!data) return corsJson(req, 404, { error: "invitation_not_pending" });
			return corsJson(req, 200, { ok: true, delivery: "manual", invitation_id: data.id, email: data.email, role: data.role, expires_at: data.expires_at, invite_url: inviteUrl }, { "Cache-Control": "no-store" });
		}
		const { data, error: insertError } = await db.from("team_invitations")
			.insert({ tenant_id: command.teamId, email: command.email, role: command.role, token_hash: tokenHash, created_by: auth.user.id, expires_at: invitationExpiry() })
			.select("id,expires_at").maybeSingle();
		if (insertError || !data) return corsJson(req, 503, { error: "invitation_create_failed" });
		return corsJson(req, 200, { ok: true, delivery: "manual", invitation_id: data.id, expires_at: data.expires_at, invite_url: inviteUrl }, { "Cache-Control": "no-store" });
	} catch { return corsJson(req, 503, { error: "invitation_unavailable" }); }
});
