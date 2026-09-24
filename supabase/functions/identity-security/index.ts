// Supabase Edge Function: /identity-security
//
// Server-side identity recovery and tenant MFA administration. Public recovery
// actions are rate-limited and never reveal whether an email address exists.
// Authenticated actions verify the Supabase access token themselves because
// this function also exposes the public reset and break-glass entry points.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { getRequestId } from "../_shared/response.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import {
	dashboardRecoveryUrl,
	generateRecoveryCodes,
	jwtHasAuthenticationMethod,
	jwtHasSamlProvider,
	jwtSamlProviderId,
	jwtIssuedAtMs,
	jwtSessionId,
	normalizeEmail,
	normalizeRecoveryCode,
	normalizeRecoveryTokenHash,
	normalizeUuid,
	policyAllowsAssurance,
	recoveryCodeIssueError,
	validateNewPassword,
} from "./logic.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_DASHBOARD_URL"] as const;
const MAX_BODY_BYTES = 8192;

type ReadTable<Row extends Record<string, unknown>> = { Row: Row; Insert: never; Update: never; Relationships: [] };
type AuditValues = { actor_user_id: string | null; tenant_id: string | null; target_user_id: string | null; action: string; detail: Record<string, unknown> };
// Keep the route's schema aligned with its reads and the RPC signatures in the migrations.
type IdentityDatabase = {
	public: {
		Tables: {
			rate_limits: ReadTable<{ key: string; window_start: number; count: number }>;
			tenant_members: ReadTable<{ tenant_id: string; user_id: string; role: string; expires_at: string | null }>;
			tenants: ReadTable<{ id: string; status: string }>;
			tenant_identity_policies: ReadTable<{ tenant_id: string; require_mfa: boolean; break_glass_enabled: boolean; required_saml_provider_id: string | null }>;
			admin_audit_logs: { Row: AuditValues; Insert: AuditValues; Update: never; Relationships: [] };
			team_members: ReadTable<{ team_id: string; tenant_id: string; user_id: string; joined_at: string }>;
			teams: ReadTable<{ id: string; tenant_id: string }>;
		};
		Views: Record<string, never>;
		Functions: {
			increment_rate_limit: { Args: { p_key: string; p_window_start: number; p_delta: number }; Returns: undefined };
			issue_identity_password_recovery_grant: { Args: { p_email: string; p_grant_id: string; p_expires_at: string; p_proof_challenge_hash: string; p_recovery_requested_after: string }; Returns: boolean };
			begin_identity_break_glass_recovery: { Args: { p_email: string; p_code_hash: string; p_proof_challenge_hash: string; p_request_id: string }; Returns: Record<string, unknown> | null };
			issue_identity_break_glass_password_recovery_grant: { Args: { p_user_id: string; p_tenant_id: string; p_grant_id: string; p_expires_at: string; p_proof_challenge_hash: string; p_recovery_requested_after: string }; Returns: boolean };
			complete_identity_break_glass_recovery: { Args: { p_code_hash: string; p_proof_challenge_hash: string }; Returns: boolean };
			bind_identity_password_recovery_grant: { Args: { p_proof_verifier: string; p_user_id: string; p_session_id: string; p_access_token_issued_at: string }; Returns: boolean };
			begin_identity_password_recovery_completion: { Args: { p_proof_verifier: string; p_user_id: string; p_session_id: string; p_access_token_issued_at: string }; Returns: Record<string, unknown> | null };
			mark_identity_session_revoked: { Args: { p_user_id: string; p_tenant_id: string | null; p_actor_user_id: string; p_reason: string }; Returns: string };
			complete_identity_password_recovery_completion: { Args: { p_proof_verifier: string; p_user_id: string; p_session_id: string }; Returns: boolean };
			begin_identity_global_revocation: { Args: { p_user_id: string; p_actor_user_id: string; p_session_id: string; p_access_token_issued_at: string }; Returns: boolean };
			complete_identity_global_revocation: { Args: { p_user_id: string; p_actor_user_id: string; p_session_id: string }; Returns: boolean };
			set_tenant_identity_policy: { Args: { p_tenant_id: string; p_actor_user_id: string; p_require_mfa: boolean; p_break_glass_enabled: boolean }; Returns: Record<string, unknown> };
			scim_bind_saml_identity: { Args: { p_auth_user_id: string; p_provider_id: string }; Returns: string | null };
			issue_identity_recovery_codes: { Args: { p_tenant_id: string; p_actor_user_id: string; p_target_user_id: string; p_code_hashes: string[]; p_expires_at: string }; Returns: Record<string, unknown> };
		};
		Enums: Record<string, never>;
		CompositeTypes: Record<string, never>;
	};
};
type DatabaseClient = SupabaseClient<IdentityDatabase>;
type Assurance = string | null;
type VerifiedAuthContext = {
	token: string;
	user: { id: string; email?: string };
	sessionId: string;
	issuedAt: string;
};
type AuthContext = {
	token: string;
	user: { id: string; email?: string };
	currentLevel: Assurance;
	nextLevel: Assurance;
};

async function authenticateVerifiedUser(
	db: DatabaseClient,
	req: Request,
): Promise<VerifiedAuthContext | Response> {
	const token = getBearerToken(req.headers.get("Authorization"));
	if (!token) return corsJson(req, 401, { error: "missing_access_token" });
	const { data, error } = await db.auth.getUser(token);
	const sessionId = jwtSessionId(token);
	const issuedAtMs = jwtIssuedAtMs(token);
	if (error || !data.user?.id || !sessionId || issuedAtMs === null) {
		return corsJson(req, 401, { error: "invalid_access_token" });
	}
	return {
		token,
		user: data.user as VerifiedAuthContext["user"],
		sessionId,
		issuedAt: new Date(issuedAtMs).toISOString(),
	};
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
	const verified = await authenticateVerifiedUser(db, req);
	if (verified instanceof Response) return verified;
	// The shared barrier owns the session-revocation check, so this mixed route
	// (public recovery + authenticated administration) uses the same rule the
	// tenant routes use instead of a second copy of it.
	const barrier = await checkIdentityBarrier(db, verified.token, verified.user.id);
	if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });
	const { data: assurance, error: assuranceError } =
		await db.auth.mfa.getAuthenticatorAssuranceLevel(verified.token);
	if (assuranceError || !assurance) {
		return corsJson(req, 503, { error: "assurance_unavailable" });
	}
	return {
		token: verified.token,
		user: verified.user,
		currentLevel: assurance.currentLevel ?? null,
		nextLevel: assurance.nextLevel ?? null,
	};
}

async function memberContext(
	db: DatabaseClient,
	userId: string,
	tenantId: string,
): Promise<{ role: string; requireMfa: boolean; breakGlassEnabled: boolean; requiredSamlProviderId: string | null } | null> {
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
		.select("require_mfa,break_glass_enabled,required_saml_provider_id")
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (policyError) return null;
	return {
		role: String(member?.role ?? "viewer"),
		requireMfa: policy?.require_mfa === true,
		breakGlassEnabled: policy?.break_glass_enabled === true,
		requiredSamlProviderId: policy?.required_saml_provider_id ?? null,
	};
}

async function audit(
	db: DatabaseClient,
	values: AuditValues,
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
	const parsedBody = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!parsedBody.ok) {
		return corsJson(req, parsedBody.status, {
			error: parsedBody.error === "request_too_large" ? parsedBody.error : "invalid_request",
		});
	}
	if (!parsedBody.value || typeof parsedBody.value !== "object" || Array.isArray(parsedBody.value)) {
		return corsJson(req, 400, { error: "invalid_request" });
	}
	const body = parsedBody.value as Record<string, unknown>;
	if (typeof body.action !== "string") return corsJson(req, 400, { error: "invalid_request" });
	let recoveryBase: URL;
	try {
		recoveryBase = dashboardRecoveryUrl(config.values.AIDR_DASHBOARD_URL);
	} catch {
		return corsJson(req, 500, { error: "server_misconfigured" });
	}
	const db = createClient<IdentityDatabase>(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	});
	const requestId = getRequestId(req);

	try {
		if (body.action === "request_password_reset") {
			const email = normalizeEmail(body.email);
			const recoveryChallenge =
				typeof body.recovery_challenge === "string" &&
				/^[0-9a-f]{64}$/.test(body.recovery_challenge)
					? body.recovery_challenge
					: null;
			if (!recoveryChallenge) return corsJson(req, 400, { error: "invalid_request" });
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
				const recoveryRequestedAfter = new Date().toISOString();
				const { error: resetError } = await db.auth.resetPasswordForEmail(email, {
					redirectTo: recoveryBase.toString(),
				});
				if (resetError) return corsJson(req, 503, { error: "recovery_unavailable" });
				const { error: grantError } = await db.rpc("issue_identity_password_recovery_grant", {
					p_email: email,
					p_grant_id: crypto.randomUUID(),
					p_expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
					p_proof_challenge_hash: recoveryChallenge,
					p_recovery_requested_after: recoveryRequestedAfter,
				});
				if (grantError) return corsJson(req, 503, { error: "recovery_unavailable" });
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
			const recoveryChallenge =
				typeof body.recovery_challenge === "string" &&
				/^[0-9a-f]{64}$/.test(body.recovery_challenge)
					? body.recovery_challenge
					: null;
			const subjectHash = await sha256(email ?? "invalid-email");
			const limit = await rateLimit(db, `identity-break-glass:${subjectHash}`, 10 * 60_000, 5);
			if (limit === "unavailable") return corsJson(req, 503, { error: "recovery_unavailable" });
			if (limit === "limited") return corsJson(req, 429, { error: "rate_limited" });
			if (!email || !recoveryCode || !recoveryChallenge) {
				return corsJson(req, 401, { error: "invalid_or_expired_recovery_code" });
			}
			const codeHash = await sha256(recoveryCode);
			const { data: recovery, error: recoveryError } = await db.rpc(
				"begin_identity_break_glass_recovery",
				{
				p_email: email,
				p_code_hash: codeHash,
				p_proof_challenge_hash: recoveryChallenge,
				p_request_id: requestId,
				},
			);
			if (recoveryError) return corsJson(req, 503, { error: "recovery_unavailable" });
			const recoveryState = recovery && typeof recovery === "object"
				? recovery as Record<string, unknown>
				: null;
			const userId = normalizeUuid(recoveryState?.user_id);
			const tenantId = normalizeUuid(recoveryState?.tenant_id);
			if (
				!userId ||
				!tenantId ||
				(recoveryState?.status !== "pending" && recoveryState?.status !== "completed")
			) {
				return corsJson(req, 401, { error: "invalid_or_expired_recovery_code" });
			}

			const redirectTo = dashboardRecoveryUrl(config.values.AIDR_DASHBOARD_URL).toString();
			const recoveryRequestedAfter = new Date().toISOString();
			const { data: linkData, error: linkError } = await db.auth.admin.generateLink({
				type: "recovery",
				email,
				options: { redirectTo },
			});
			const tokenHash = normalizeRecoveryTokenHash(linkData?.properties?.hashed_token);
			if (
				linkError ||
				!tokenHash ||
				linkData?.user?.id !== userId ||
				linkData?.properties?.verification_type !== "recovery" ||
				linkData?.properties?.redirect_to !== redirectTo
			) {
				return corsJson(req, 503, { error: "recovery_token_failed" });
			}
			const grantId = crypto.randomUUID();
			const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
			const { data: issued, error: grantError } = await db.rpc(
				"issue_identity_break_glass_password_recovery_grant",
				{
					p_user_id: userId,
					p_tenant_id: tenantId,
					p_grant_id: grantId,
					p_expires_at: expiresAt,
					p_proof_challenge_hash: recoveryChallenge,
					p_recovery_requested_after: recoveryRequestedAfter,
				},
			);
			if (grantError || issued !== true) {
				return corsJson(req, 503, { error: "recovery_unavailable" });
			}
			// Defer factor removal until token generation and grant persistence have
			// succeeded. Deletes are idempotent on retry because each attempt lists
			// only the factors that still exist.
			const { data: factorData, error: factorError } = await db.auth.admin.mfa.listFactors({ userId });
			if (factorError || !factorData) return corsJson(req, 503, { error: "factor_reset_failed" });
			for (const factor of factorData.factors ?? []) {
				if (!normalizeUuid(factor.id)) return corsJson(req, 503, { error: "factor_reset_failed" });
				const { error } = await db.auth.admin.mfa.deleteFactor({ userId, id: factor.id });
				if (error) return corsJson(req, 503, { error: "factor_reset_failed" });
			}
			const logged = await audit(db, {
				actor_user_id: null,
				tenant_id: tenantId,
				target_user_id: userId,
				action: "identity.break_glass.token_issued",
				detail: { request_id: requestId, delivery: "in_app" },
			});
			if (!logged) return corsJson(req, 503, { error: "recovery_unavailable" });
			const { data: completed, error: completeError } = await db.rpc(
				"complete_identity_break_glass_recovery",
				{
					p_code_hash: codeHash,
					p_proof_challenge_hash: recoveryChallenge,
				},
			);
			if (completeError || completed !== true) {
				return corsJson(req, 503, { error: "recovery_unavailable" });
			}
			return corsJson(req, 200, {
				ok: true,
				delivery: "in_app",
				recovery_token_hash: tokenHash,
				recovery_type: "recovery",
				reauthentication_required: true,
			});
		}

		if (
			body.action === "bind_password_recovery_grant" ||
			body.action === "complete_password_recovery"
		) {
			const recoveryIdentity = await authenticateVerifiedUser(db, req);
			if (recoveryIdentity instanceof Response) return recoveryIdentity;
			if (!jwtHasAuthenticationMethod(recoveryIdentity.token, "otp")) {
				return corsJson(req, 401, { error: "password_recovery_otp_session_required" });
			}
			const recoveryVerifier =
				typeof body.recovery_verifier === "string" &&
				/^[A-Za-z0-9_-]{43}$/.test(body.recovery_verifier)
					? body.recovery_verifier
					: null;
			if (!recoveryVerifier) {
				return corsJson(req, 401, { error: "invalid_or_expired_recovery_grant" });
			}

			if (body.action === "bind_password_recovery_grant") {
				const { data, error } = await db.rpc("bind_identity_password_recovery_grant", {
					p_proof_verifier: recoveryVerifier,
					p_user_id: recoveryIdentity.user.id,
					p_session_id: recoveryIdentity.sessionId,
					p_access_token_issued_at: recoveryIdentity.issuedAt,
				});
				if (error || data !== true) {
					return corsJson(req, 401, { error: "invalid_or_expired_recovery_grant" });
				}
				return corsJson(req, 200, { ok: true });
			}

			const newPassword = validateNewPassword(body.new_password);
			if (!newPassword) return corsJson(req, 400, { error: "password_does_not_meet_policy" });
			const { data, error } = await db.rpc("begin_identity_password_recovery_completion", {
				p_proof_verifier: recoveryVerifier,
				p_user_id: recoveryIdentity.user.id,
				p_session_id: recoveryIdentity.sessionId,
				p_access_token_issued_at: recoveryIdentity.issuedAt,
			});
			const grant = data && typeof data === "object" ? data as Record<string, unknown> : null;
			const completionStatus = grant?.status;
			const source = grant?.source;
			const recoveryTenantId = normalizeUuid(grant?.tenant_id);
			if (
				error ||
				(completionStatus !== "pending" && completionStatus !== "completed") ||
				(source !== "email" && source !== "break_glass") ||
				(source === "break_glass" && !recoveryTenantId)
			) {
				return corsJson(req, 401, { error: "invalid_or_expired_recovery_grant" });
			}
			if (completionStatus === "completed") {
				return corsJson(req, 200, { ok: true, reauthentication_required: true });
			}
			// The one-time grant authorizes this verified OTP session even when a
			// break-glass barrier has fractional-second precision and the new JWT's
			// `iat` is rounded to the same second. Older sessions never possess it.
			const { error: barrierError } = await db.rpc("mark_identity_session_revoked", {
				p_user_id: recoveryIdentity.user.id,
				p_tenant_id: recoveryTenantId,
				p_actor_user_id: recoveryIdentity.user.id,
				p_reason: "password_recovery",
			});
			if (barrierError) return corsJson(req, 503, { error: "session_revoke_failed" });
			const { error: signOutError } = await db.auth.admin.signOut(recoveryIdentity.token, "global");
			if (signOutError) return corsJson(req, 503, { error: "session_revoke_failed" });
			const { error: passwordError } = await db.auth.admin.updateUserById(
				recoveryIdentity.user.id,
				{ password: newPassword },
			);
			if (passwordError) return corsJson(req, 503, { error: "password_update_failed" });
			const { data: completed, error: completeError } = await db.rpc(
				"complete_identity_password_recovery_completion",
				{
					p_proof_verifier: recoveryVerifier,
					p_user_id: recoveryIdentity.user.id,
					p_session_id: recoveryIdentity.sessionId,
				},
			);
			if (completeError || completed !== true) {
				return corsJson(req, 503, { error: "recovery_unavailable" });
			}
			return corsJson(req, 200, { ok: true, reauthentication_required: true });
		}

		if (body.action === "revoke_sessions" && body.scope === "global") {
			const identity = await authenticateVerifiedUser(db, req);
			if (identity instanceof Response) return identity;
			const { data: began, error: beginError } = await db.rpc(
				"begin_identity_global_revocation",
				{
					p_user_id: identity.user.id,
					p_actor_user_id: identity.user.id,
					p_session_id: identity.sessionId,
					p_access_token_issued_at: identity.issuedAt,
				},
			);
			if (beginError) return corsJson(req, 503, { error: "session_revoke_failed" });
			if (began !== true) return corsJson(req, 401, { error: "session_revoked" });
			const { error: signOutError } = await db.auth.admin.signOut(identity.token, "global");
			if (signOutError) return corsJson(req, 503, { error: "session_revoke_failed" });
			const { data: completed, error: completeError } = await db.rpc(
				"complete_identity_global_revocation",
				{
					p_user_id: identity.user.id,
					p_actor_user_id: identity.user.id,
					p_session_id: identity.sessionId,
				},
			);
			if (completeError || completed !== true) {
				return corsJson(req, 503, { error: "session_revoke_failed" });
			}
			return corsJson(req, 200, {
				ok: true,
				scope: "global",
				reauthentication_required: true,
				access_token_note: "AIDR tenant RLS rejects tokens issued before this revocation barrier.",
			});
		}

		const identity = await authenticate(db, req);
		if (identity instanceof Response) return identity;

		if (body.action === "bootstrap") {
			const samlProviderId = jwtSamlProviderId(identity.token);
			if (samlProviderId) {
				const { error: bindError } = await db.rpc("scim_bind_saml_identity", {
					p_auth_user_id: identity.user.id,
					p_provider_id: samlProviderId,
				});
				if (bindError) return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
			}
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
				.select("tenant_id,require_mfa,required_saml_provider_id")
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
					const samlProvider = policies.find((policy) => policy.tenant_id === tenantId)?.required_saml_provider_id;
					return {
						team_id: teamByTenant.get(tenantId) ?? null,
						tenant_id: tenantId,
						require_mfa: requireMfa,
						current_assurance: identity.currentLevel,
						next_assurance: identity.nextLevel,
						access_allowed: (!samlProvider || jwtHasSamlProvider(identity.token, samlProvider)) &&
							policyAllowsAssurance(requireMfa, identity.currentLevel),
					};
				}),
			});
		}

		const requestedTenant = normalizeUuid(body.tenant_id ?? req.headers.get("X-AIDR-Tenant-ID"));
		const tenantId = requestedTenant ?? identity.user.id;
		const member = await memberContext(db, identity.user.id, tenantId);
		if (!member) return corsJson(req, 403, { error: "tenant_not_authorized" });
		if (member.requiredSamlProviderId && !jwtHasSamlProvider(identity.token, member.requiredSamlProviderId)) {
			return corsJson(req, 403, { error: "sso_required" });
		}

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
			if (identity.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });
			const targetUserId = body.target_user_id === undefined
				? identity.user.id
				: normalizeUuid(body.target_user_id);
			if (!targetUserId) return corsJson(req, 403, { error: "recovery_code_issue_forbidden" });
			const issueError = recoveryCodeIssueError(identity.user.id, targetUserId);
			if (issueError) return corsJson(req, 403, { error: issueError });
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
			if (body.scope !== "others") return corsJson(req, 400, { error: "invalid_session_scope" });
			const { error } = await db.auth.admin.signOut(identity.token, "others");
			if (error) return corsJson(req, 503, { error: "session_revoke_failed" });
			await audit(db, {
				actor_user_id: identity.user.id,
				tenant_id: tenantId,
				target_user_id: identity.user.id,
				action: "identity.sessions.other_refresh_tokens_revoked",
				detail: { request_id: requestId },
			});
			return corsJson(req, 200, {
				ok: true,
				scope: "others",
				reauthentication_required: false,
				access_token_note: "Other access tokens remain valid until their configured JWT expiry.",
			});
		}

		return corsJson(req, 400, { error: "invalid_action" });
	} catch {
		return corsJson(req, 503, { error: "identity_operation_unavailable" });
	}
});
