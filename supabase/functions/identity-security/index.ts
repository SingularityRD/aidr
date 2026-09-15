// Supabase Edge Function: /identity-security
//
// Server-side identity recovery and tenant MFA administration. Public recovery
// actions are rate-limited and never reveal whether an email address exists.
// Authenticated actions verify the Supabase access token themselves because
// this function also exposes the public reset and break-glass entry points.

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { getRequestId } from "../_shared/response.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import {
	dashboardRecoveryUrl,
	generateRecoveryCodes,
	jwtHasAuthenticationMethod,
	normalizeEmail,
	normalizeRecoveryCode,
	normalizeUuid,
	policyAllowsAssurance,
	validateNewPassword,
} from "./logic.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_DASHBOARD_URL"] as const;
const MAX_BODY_BYTES = 8192;

type DatabaseClient = ReturnType<typeof createClient>;
type Assurance = "aal1" | "aal2" | null;
type AuthContext = {
	token: string;
	user: { id: string; email?: string };
	currentLevel: Assurance;
	nextLevel: Assurance;
};

async function readBody(req: Request): Promise<Record<string, unknown> | null> {
	const declared = Number(req.headers.get("content-length") ?? "0");
	if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;
	try {
		const raw = await req.text();
		if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) return null;
		const parsed: unknown = JSON.parse(raw);
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

async function rateLimit(
	db: DatabaseClient,
	key: string,
	windowMs: number,
	maximum: number,
): Promise<"allowed" | "limited" | "unavailable"> {
	const windowStart = Math.floor(Date.now() / windowMs);
	const { error: incrementError } = await db.rpc("increment_rate_limit", {
		p_key: key,
		p_window_start: windowStart,
		p_delta: 1,
	});
	if (incrementError) return "unavailable";
	const { data, error } = await db
		.from("rate_limits")
		.select("count")
		.eq("key", key)
		.eq("window_start", windowStart)
		.maybeSingle();
	if (error || typeof data?.count !== "number") return "unavailable";
	return data.count <= maximum ? "allowed" : "limited";
}

async function authenticate(db: DatabaseClient, req: Request): Promise<AuthContext | Response> {
	const token = getBearerToken(req.headers.get("Authorization"));
	if (!token) return corsJson(req, 401, { error: "missing_access_token" });
	const { data, error } = await db.auth.getUser(token);
	if (error || !data.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
	// The shared barrier owns the session-revocation check, so this mixed route
	// (public recovery + authenticated administration) uses the same rule the
	// tenant routes use instead of a second copy of it.
	const barrier = await checkIdentityBarrier(db, token, data.user.id);
	if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });
	const { data: assurance, error: assuranceError } =
		await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
	if (assuranceError || !assurance) {
		return corsJson(req, 503, { error: "assurance_unavailable" });
	}
	return {
		token,
		user: data.user as AuthContext["user"],
		currentLevel: assurance.currentLevel ?? null,
		nextLevel: assurance.nextLevel ?? null,
	};
}

async function memberContext(
	db: DatabaseClient,
	userId: string,
	tenantId: string,
): Promise<{ role: string; requireMfa: boolean; breakGlassEnabled: boolean } | null> {
	const { data: member, error: memberError } = await db
		.from("tenant_members")
		.select("role,expires_at")
		.eq("tenant_id", tenantId)
		.eq("user_id", userId)
		.maybeSingle();
	if (memberError || !membershipActive(member)) return null;
	const { data: tenant, error: tenantError } = await db
		.from("tenants")
		.select("status")
		.eq("id", tenantId)
		.maybeSingle();
	if (tenantError || tenant?.status !== "active") return null;
	const { data: policy, error: policyError } = await db
		.from("tenant_identity_policies")
		.select("require_mfa,break_glass_enabled")
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (policyError) return null;
	return {
		role: String(member?.role ?? "viewer"),
		requireMfa: policy?.require_mfa === true,
		breakGlassEnabled: policy?.break_glass_enabled === true,
	};
}

async function audit(
	db: DatabaseClient,
	values: Record<string, unknown>,
): Promise<boolean> {
	const { error } = await db.from("admin_audit_logs").insert(values);
	return !error;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("identity-security", config.error, (status, body) =>
			corsJson(req, status, body),
		);
	}
	const body = await readBody(req);
	if (!body || typeof body.action !== "string") {
		return corsJson(req, 400, { error: "invalid_request" });
	}
	let recoveryBase: URL;
	try {
		recoveryBase = dashboardRecoveryUrl(config.values.AIDR_DASHBOARD_URL);
	} catch {
		return corsJson(req, 500, { error: "server_misconfigured" });
	}
	const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	});
	const requestId = getRequestId(req);

	try {
		if (body.action === "request_password_reset") {
			const email = normalizeEmail(body.email);
			const subjectHash = await sha256(email ?? "invalid-email");
			const limit = await rateLimit(db, `identity-reset:${subjectHash}`, 10 * 60_000, 5);
			if (limit === "unavailable") return corsJson(req, 503, { error: "recovery_unavailable" });
			if (limit === "limited") return corsJson(req, 429, { error: "rate_limited" });
			const logged = await audit(db, {
				actor_user_id: null,
				tenant_id: null,
				target_user_id: null,
				action: "identity.password_reset.requested",
				detail: { subject_hash: subjectHash, request_id: requestId },
			});
			if (!logged) return corsJson(req, 503, { error: "recovery_unavailable" });
			if (email) {
				// Supabase deliberately returns the same result for unknown accounts.
				// Delivery still depends on the deployment's Auth/SMTP configuration.
				await db.auth.resetPasswordForEmail(email, { redirectTo: recoveryBase.toString() });
			}
			return corsJson(req, 202, {
				ok: true,
				message: "If this account is enabled, the configured auth provider will send recovery instructions.",
				delivery: "auth_provider_if_configured",
			});
		}

		if (body.action === "break_glass_recover") {
			const email = normalizeEmail(body.email);
			const recoveryCode = normalizeRecoveryCode(body.recovery_code);
			const subjectHash = await sha256(email ?? "invalid-email");
			const limit = await rateLimit(db, `identity-break-glass:${subjectHash}`, 10 * 60_000, 5);
			if (limit === "unavailable") return corsJson(req, 503, { error: "recovery_unavailable" });
			if (limit === "limited") return corsJson(req, 429, { error: "rate_limited" });
			if (!email || !recoveryCode) {
				return corsJson(req, 401, { error: "invalid_or_expired_recovery_code" });
			}
			const { data: consumed, error: consumeError } = await db.rpc("consume_identity_recovery_code", {
				p_email: email,
				p_code_hash: await sha256(recoveryCode),
				p_request_id: requestId,
			});
			if (consumeError) return corsJson(req, 503, { error: "recovery_unavailable" });
			const userId = normalizeUuid(consumed?.user_id);
			const tenantId = normalizeUuid(consumed?.tenant_id);
			if (!userId || !tenantId) {
				return corsJson(req, 401, { error: "invalid_or_expired_recovery_code" });
			}

			// A valid pre-provisioned break-glass code is the authorization to clear
			// factors. The Auth admin API removes each factor and revokes sessions
			// when a verified factor is deleted.
			const { data: factorData, error: factorError } = await db.auth.admin.mfa.listFactors({ userId });
			if (factorError || !factorData) return corsJson(req, 503, { error: "factor_reset_failed" });
			for (const factor of factorData.factors ?? []) {
				if (!normalizeUuid(factor.id)) return corsJson(req, 503, { error: "factor_reset_failed" });
				const { error } = await db.auth.admin.mfa.deleteFactor({ userId, id: factor.id });
				if (error) return corsJson(req, 503, { error: "factor_reset_failed" });
			}

			const grantId = crypto.randomUUID();
			const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
			const { error: grantError } = await db.from("identity_password_recovery_grants").insert({
				id: grantId,
				tenant_id: tenantId,
				user_id: userId,
				source: "break_glass",
				expires_at: expiresAt,
			});
			if (grantError) return corsJson(req, 503, { error: "recovery_unavailable" });
			const redirectTo = dashboardRecoveryUrl(config.values.AIDR_DASHBOARD_URL, grantId).toString();
			const { data: linkData, error: linkError } = await db.auth.admin.generateLink({
				type: "recovery",
				email,
				options: { redirectTo },
			});
			const actionLink = linkData?.properties?.action_link;
			if (linkError || typeof actionLink !== "string" || !actionLink) {
				return corsJson(req, 503, { error: "recovery_link_failed" });
			}
			await audit(db, {
				actor_user_id: null,
				tenant_id: tenantId,
				target_user_id: userId,
				action: "identity.break_glass.link_generated",
				detail: { grant_id: grantId, request_id: requestId, delivery: "manual" },
			});
			return corsJson(req, 200, {
				ok: true,
				delivery: "manual",
				recovery_link: actionLink,
				expires_at: expiresAt,
				reauthentication_required: true,
			});
		}

		const identity = await authenticate(db, req);
		if (identity instanceof Response) return identity;

		if (body.action === "bootstrap") {
			// AAL1 callers cannot read MFA-protected tenant/team rows through RLS.
			// Discover only their active identifiers and step-up requirements here;
			// this is not authorization to return names, roles, or business data.
			const now = Date.now();
			const { data: memberships, error: membershipError } = await db
				.from("tenant_members")
				.select("tenant_id,expires_at")
				.eq("user_id", identity.user.id)
				.or(`expires_at.is.null,expires_at.gt.${new Date(now).toISOString()}`);
			if (membershipError || !memberships) {
				return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
			}
			const memberTenantIds = memberships
				.filter((membership) => membershipActive(membership, now))
				.map((membership) => membership.tenant_id);
			if (!memberTenantIds.length) return corsJson(req, 200, { ok: true, memberships: [] });

			const { data: tenants, error: tenantError } = await db
				.from("tenants")
				.select("id")
				.in("id", memberTenantIds)
				.eq("status", "active")
				.order("id");
			if (tenantError || !tenants) {
				return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
			}
			const tenantIds = tenants.map((tenant) => tenant.id);
			if (!tenantIds.length) return corsJson(req, 200, { ok: true, memberships: [] });

			const { data: teamMembers, error: teamMemberError } = await db
				.from("team_members")
				.select("team_id,tenant_id")
				.eq("user_id", identity.user.id)
				.in("tenant_id", tenantIds)
				.order("joined_at", { ascending: false });
			if (teamMemberError || !teamMembers) {
				return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
			}
			const teamByTenant = new Map<string, string>();
			if (teamMembers.length) {
				const { data: teams, error: teamError } = await db
					.from("teams")
					.select("id,tenant_id")
					.in("id", teamMembers.map((membership) => membership.team_id))
					.in("tenant_id", tenantIds);
				if (teamError || !teams) {
					return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
				}
				// Preserve the dashboard's newest-team-first default without exposing
				// joined_at or trusting the independent teams query's row order.
				for (const membership of teamMembers) {
					if (teams.some((team) =>
						membership.team_id === team.id && membership.tenant_id === team.tenant_id
					)) teamByTenant.set(membership.tenant_id, membership.team_id);
				}
			}

			const { data: policies, error: policyError } = await db
				.from("tenant_identity_policies")
				.select("tenant_id,require_mfa")
				.in("tenant_id", tenantIds);
			if (policyError || !policies) {
				return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
			}
			const orderedTenantIds = [
				...teamByTenant.keys(),
				...tenantIds.filter((tenantId) => !teamByTenant.has(tenantId)),
			];
			return corsJson(req, 200, {
				ok: true,
				memberships: orderedTenantIds.map((tenantId) => {
					const requireMfa = policies.some((policy) =>
						policy.tenant_id === tenantId && policy.require_mfa === true
					);
					return {
						team_id: teamByTenant.get(tenantId) ?? null,
						tenant_id: tenantId,
						require_mfa: requireMfa,
						current_assurance: identity.currentLevel,
						next_assurance: identity.nextLevel,
						access_allowed: policyAllowsAssurance(requireMfa, identity.currentLevel),
					};
				}),
			});
		}

		if (body.action === "complete_password_recovery") {
			const newPassword = validateNewPassword(body.new_password);
			if (!newPassword) return corsJson(req, 400, { error: "password_does_not_meet_policy" });
			if (!jwtHasAuthenticationMethod(identity.token, "recovery")) {
				return corsJson(req, 401, { error: "password_recovery_session_required" });
			}
			let recoveryTenantId: string | null = null;
			const grantId = normalizeUuid(body.grant_id);
			if (grantId) {
				const { data, error } = await db.rpc("consume_identity_password_recovery_grant", {
					p_grant_id: grantId,
					p_user_id: identity.user.id,
				});
				if (error || !normalizeUuid(data)) {
					return corsJson(req, 401, { error: "invalid_or_expired_recovery_grant" });
				}
				recoveryTenantId = normalizeUuid(data);
			}
			// A password change must never succeed while older sessions remain usable.
			const { error: barrierError } = await db.rpc("mark_identity_session_revoked", {
				p_user_id: identity.user.id,
				p_tenant_id: recoveryTenantId,
				p_actor_user_id: identity.user.id,
				p_reason: "password_recovery",
			});
			if (barrierError) return corsJson(req, 503, { error: "session_revoke_failed" });
			const { error: signOutError } = await db.auth.admin.signOut(identity.token, "global");
			if (signOutError) return corsJson(req, 503, { error: "session_revoke_failed" });
			const { error: passwordError } = await db.auth.admin.updateUserById(identity.user.id, {
				password: newPassword,
			});
			if (passwordError) return corsJson(req, 503, { error: "password_update_failed" });
			return corsJson(req, 200, { ok: true, reauthentication_required: true });
		}

		const requestedTenant = normalizeUuid(body.tenant_id ?? req.headers.get("X-AIDR-Tenant-ID"));
		const tenantId = requestedTenant ?? identity.user.id;
		const member = await memberContext(db, identity.user.id, tenantId);
		if (!member) return corsJson(req, 403, { error: "tenant_not_authorized" });

		if (body.action === "status") {
			return corsJson(req, 200, {
				ok: true,
				tenant_id: tenantId,
				role: member.role,
				require_mfa: member.requireMfa,
				break_glass_enabled: member.breakGlassEnabled,
				current_assurance: identity.currentLevel,
				next_assurance: identity.nextLevel,
				access_allowed: policyAllowsAssurance(member.requireMfa, identity.currentLevel),
			});
		}

		if (body.action === "set_policy") {
			if (member.role !== "owner") return corsJson(req, 403, { error: "tenant_role_insufficient" });
			if (identity.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });
			if (typeof body.require_mfa !== "boolean" || typeof body.break_glass_enabled !== "boolean") {
				return corsJson(req, 400, { error: "invalid_identity_policy" });
			}
			const { data, error } = await db.rpc("set_tenant_identity_policy", {
				p_tenant_id: tenantId,
				p_actor_user_id: identity.user.id,
				p_require_mfa: body.require_mfa,
				p_break_glass_enabled: body.break_glass_enabled,
			});
			if (error) return corsJson(req, 503, { error: "identity_policy_update_failed" });
			return corsJson(req, 200, { ok: true, policy: data });
		}

		if (body.action === "rotate_recovery_codes") {
			if (!member.breakGlassEnabled) return corsJson(req, 409, { error: "break_glass_disabled" });
			if (!['owner', 'admin'].includes(member.role)) {
				return corsJson(req, 403, { error: "tenant_role_insufficient" });
			}
			if (identity.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });
			const targetUserId = normalizeUuid(body.target_user_id) ?? identity.user.id;
			const codes = generateRecoveryCodes();
			const hashes = await Promise.all(
				codes.map((code) => sha256(normalizeRecoveryCode(code) ?? "invalid")),
			);
			const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60_000).toISOString();
			const { data, error } = await db.rpc("issue_identity_recovery_codes", {
				p_tenant_id: tenantId,
				p_actor_user_id: identity.user.id,
				p_target_user_id: targetUserId,
				p_code_hashes: hashes,
				p_expires_at: expiresAt,
			});
			if (error) return corsJson(req, 403, { error: "recovery_code_issue_forbidden" });
			return corsJson(req, 200, {
				ok: true,
				target_user_id: targetUserId,
				codes,
				expires_at: expiresAt,
				retrievable_again: false,
				batch: data,
			});
		}

		if (body.action === "revoke_sessions") {
			if (!policyAllowsAssurance(member.requireMfa, identity.currentLevel)) {
				return corsJson(req, 403, { error: "mfa_required" });
			}
			const scope = body.scope === "others" ? "others" : body.scope === "global" ? "global" : null;
			if (!scope) return corsJson(req, 400, { error: "invalid_session_scope" });
			if (scope === "global") {
				const { error } = await db.rpc("mark_identity_session_revoked", {
					p_user_id: identity.user.id,
					p_tenant_id: tenantId,
					p_actor_user_id: identity.user.id,
					p_reason: "user_global_signout",
				});
				if (error) return corsJson(req, 503, { error: "session_revoke_failed" });
			}
			const { error } = await db.auth.admin.signOut(identity.token, scope);
			if (error) return corsJson(req, 503, { error: "session_revoke_failed" });
			if (scope === "others") {
				await audit(db, {
					actor_user_id: identity.user.id,
					tenant_id: tenantId,
					target_user_id: identity.user.id,
					action: "identity.sessions.other_refresh_tokens_revoked",
					detail: { request_id: requestId },
				});
			}
			return corsJson(req, 200, {
				ok: true,
				scope,
				reauthentication_required: scope === "global",
				access_token_note:
					scope === "others"
						? "Other access tokens remain valid until their configured JWT expiry."
						: "AIDR tenant RLS rejects tokens issued before this revocation barrier.",
			});
		}

		return corsJson(req, 400, { error: "invalid_action" });
	} catch {
		return corsJson(req, 503, { error: "identity_operation_unavailable" });
	}
});
