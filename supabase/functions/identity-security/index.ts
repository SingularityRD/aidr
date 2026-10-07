// Supabase Edge Function: /identity-security
//
// Server-side identity recovery and tenant MFA administration. Public recovery
// actions are rate-limited and never reveal whether an email address exists.
// Authenticated actions verify the Supabase access token themselves because
// this function also exposes the public reset and break-glass entry points.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier, sessionHasOidcProvider } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { getRequestId } from "../_shared/response.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { INGRESS_SECRET_ENV, ingressIpBucket, validIngressSecret, verifiedIngressIp } from "../_shared/trusted-ingress.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import {
	dashboardRecoveryUrl,
	generateRecoveryCodes,
	jwtHasAuthenticationMethod,
	jwtHasSamlProvider,
	jwtSamlProviderId,
	jwtIssuedAtMs,
	jwtExpiresAtMs,
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
// Domain-separated trusted-ingress proof for the public recovery actions.
const INGRESS_CONTEXT = "identity-security:v1";
const SAML_POLICY_ACTIONS = ["request_saml_policy_change", "get_saml_policy_change", "approve_saml_policy_change"];

type ReadTable<Row extends Record<string, unknown>> = { Row: Row; Insert: never; Update: never; Relationships: [] };
type AuditValues = { actor_user_id: string | null; tenant_id: string | null; target_user_id: string | null; action: string; detail: Record<string, unknown> };
type SamlSessionProof = { session_id: string; issued_at: string; expires_at: string; aal: "aal2"; saml_provider_id: string };
// Keep the route's schema aligned with its reads and the RPC signatures in the migrations.
type IdentityDatabase = {
	public: {
		Tables: {
			rate_limits: ReadTable<{ key: string; window_start: number; count: number }>;
			tenant_members: ReadTable<{ tenant_id: string; user_id: string; role: string; expires_at: string | null }>;
			tenants: ReadTable<{ id: string; status: string }>;
			tenant_identity_policies: ReadTable<{ tenant_id: string; require_mfa: boolean; break_glass_enabled: boolean; required_saml_provider_id: string | null; required_oidc_provider_id: string | null }>;
			oidc_sso_sessions: ReadTable<{ session_id: string; user_id: string; provider_id: string; tenant_id: string; expires_at: string; revoked_at: string | null }>;
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
			request_tenant_saml_policy_change: { Args: { p_tenant_id: string; p_actor_user_id: string; p_new_provider_id: string | null; p_reason: string; p_change_ref: string; p_validated_session: SamlSessionProof }; Returns: Record<string, unknown> };
			approve_tenant_saml_policy_change: { Args: { p_tenant_id: string; p_actor_user_id: string; p_request_id: string; p_validated_session: SamlSessionProof }; Returns: Record<string, unknown> };
			get_tenant_saml_policy_change: { Args: { p_tenant_id: string; p_actor_user_id: string; p_request_id: string }; Returns: Record<string, unknown> };
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
	if (error || typeof data?.count !== "number" || !Number.isSafeInteger(data.count) || data.count < 1) return "unavailable";
	return data.count <= maximum ? "allowed" : "limited";
}

const RECOVERY_WINDOW_MS = 10 * 60_000;
// Per signed client IP, per public recovery action, per 10-minute window.
const RECOVERY_CLIENT_LIMIT = 20;

// Public recovery throttling. A caller whose IP the trusted ingress attested
// is checked against its own bucket first, so one client cannot drain the
// shared budget after reaching its quota; signed callers then share a signed
// aggregate as a backstop. Unsigned callers (no ingress, or a forged/stale
// proof) only ever consume the legacy unsigned aggregate, so a direct caller
// can no longer exhaust recovery for clients that arrive through the ingress.
async function publicRecoveryLimit(
	db: DatabaseClient,
	req: Request,
	scope: "identity-reset" | "identity-break-glass",
	aggregateLimit: number,
	ingressSecret: string,
): Promise<"allowed" | "limited" | "unavailable"> {
	const clientIp = ingressSecret ? await verifiedIngressIp(req, ingressSecret, INGRESS_CONTEXT) : null;
	if (!clientIp) return rateLimit(db, `${scope}:aggregate`, RECOVERY_WINDOW_MS, aggregateLimit);
	const client = await rateLimit(db, `${scope}:v2:client:${await ingressIpBucket(clientIp)}`, RECOVERY_WINDOW_MS, RECOVERY_CLIENT_LIMIT);
	if (client !== "allowed") return client;
	return rateLimit(db, `${scope}:v2:signed-aggregate`, RECOVERY_WINDOW_MS, aggregateLimit);
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
): Promise<{ role: string; requireMfa: boolean; breakGlassEnabled: boolean; requiredSamlProviderId: string | null; requiredOidcProviderId: string | null } | null> {
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
		.select("require_mfa,break_glass_enabled,required_saml_provider_id,required_oidc_provider_id")
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (policyError) return null;
	return {
		role: String(member?.role ?? "viewer"),
		requireMfa: policy?.require_mfa === true,
		breakGlassEnabled: policy?.break_glass_enabled === true,
		requiredSamlProviderId: policy?.required_saml_provider_id ?? null,
		requiredOidcProviderId: policy?.required_oidc_provider_id ?? null,
	};
}

async function audit(
	db: DatabaseClient,
	values: AuditValues,
): Promise<boolean> {
	const { error } = await db.from("admin_audit_logs").insert(values);
	return !error;
}

function samlPolicyError(req: Request, error: { message?: string }): Response {
	const statuses: Record<string, number> = {
		saml_policy_invalid_request: 400,
		saml_policy_owner_required: 403,
		saml_policy_aal2_required: 403,
		saml_policy_session_invalid: 401,
		saml_policy_session_revoked: 401,
		saml_policy_provider_session_required: 403,
		saml_policy_provider_unavailable: 409,
		saml_policy_owners_not_verified: 409,
		saml_policy_scim_identity_conflict: 409,
		saml_policy_unsupported_transition: 409,
		saml_policy_policy_conflict: 409,
		saml_policy_request_expired: 409,
		saml_policy_request_consumed: 409,
		saml_policy_distinct_owner_required: 403,
		saml_policy_request_not_found: 404,
		saml_policy_request_pending_limit: 429,
	};
	const reason = error.message ?? "";
	return Object.hasOwn(statuses, reason)
		? corsJson(req, statuses[reason], { error: reason })
		: corsJson(req, 503, { error: "saml_policy_unavailable" });
}

function samlPolicyResponse(req: Request, tenantId: string, data: unknown, notFound = false): Response {
	if (data === null && notFound) return corsJson(req, 404, { error: "saml_policy_request_not_found" });
	if (!data || typeof data !== "object" || Array.isArray(data)) return corsJson(req, 503, { error: "saml_policy_unavailable" });
	const row = data as Record<string, unknown>;
	if (!normalizeUuid(row.request_id) || normalizeUuid(row.tenant_id) !== tenantId) {
		return corsJson(req, 503, { error: "saml_policy_unavailable" });
	}
	const keys = ["request_id", "tenant_id", "requested_by", "old_provider_id", "new_provider_id", "reason", "change_ref", "created_at", "expires_at", "approved_by", "approved_at"];
	if (keys.some((key) => !Object.hasOwn(row, key))) return corsJson(req, 503, { error: "saml_policy_unavailable" });
	return corsJson(req, 200, { ok: true, request: Object.fromEntries(keys.map((key) => [key, row[key]])) }, { "Cache-Control": "no-store" });
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
	// Optional: without it every public recovery caller shares the unsigned aggregate.
	const ingressSecret = Deno.env.get(INGRESS_SECRET_ENV) ?? "";
	if (ingressSecret && !validIngressSecret(ingressSecret)) {
		return corsJson(req, 500, { error: "server_misconfigured", invalid: [INGRESS_SECRET_ENV] });
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
			// Caller-selected emails must not mint unlimited independent counter and audit rows.
			const aggregate = await publicRecoveryLimit(db, req, "identity-reset", 1000, ingressSecret);
			if (aggregate === "unavailable") return corsJson(req, 503, { error: "recovery_unavailable" });
			if (aggregate === "limited") return corsJson(req, 429, { error: "rate_limited" });
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
			const aggregate = await publicRecoveryLimit(db, req, "identity-break-glass", 300, ingressSecret);
			if (aggregate === "unavailable") return corsJson(req, 503, { error: "recovery_unavailable" });
			if (aggregate === "limited") return corsJson(req, 429, { error: "rate_limited" });
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
				.select("tenant_id,require_mfa,required_saml_provider_id,required_oidc_provider_id")
				.in("tenant_id", tenantIds);
			if (policyError || !policies) {
				return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
			}
			// OIDC sessions carry no AMR proof; resolve the server-side binding for each enforcing tenant.
			const oidcSatisfied = new Map<string, boolean>();
			for (const policy of policies) {
				if (!policy.required_oidc_provider_id) continue;
				const bound = await sessionHasOidcProvider(
					db, identity.token, identity.user.id, policy.required_oidc_provider_id, policy.tenant_id,
				);
				if (bound === "unavailable") return corsJson(req, 503, { error: "identity_bootstrap_unavailable" });
				oidcSatisfied.set(policy.tenant_id, bound);
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
					const oidcAllowed = oidcSatisfied.get(tenantId) ?? true;
					return {
						team_id: teamByTenant.get(tenantId) ?? null,
						tenant_id: tenantId,
						require_mfa: requireMfa,
						current_assurance: identity.currentLevel,
						next_assurance: identity.nextLevel,
						access_allowed: (!samlProvider || jwtHasSamlProvider(identity.token, samlProvider)) &&
							oidcAllowed &&
							policyAllowsAssurance(requireMfa, identity.currentLevel),
					};
				}),
			});
		}

		const samlAction = SAML_POLICY_ACTIONS.includes(body.action);
		if (samlAction) {
			const required = body.action === "request_saml_policy_change"
				? ["action", "tenant_id", "new_provider_id", "reason", "change_ref"]
				: ["action", "tenant_id", "request_id"];
			const tenant = normalizeUuid(body.tenant_id);
			const header = req.headers.get("X-AIDR-Tenant-ID");
			if (!required.every((key) => Object.hasOwn(body, key)) || Object.keys(body).some((key) => !required.includes(key)) ||
				!tenant || (header !== null && normalizeUuid(header) !== tenant)) {
				return corsJson(req, 400, { error: "saml_policy_invalid_request" });
			}
			if (body.action === "request_saml_policy_change") {
				if ((body.new_provider_id !== null && !normalizeUuid(body.new_provider_id)) ||
					typeof body.reason !== "string" || body.reason.trim().length < 12 || body.reason.trim().length > 500 ||
					typeof body.change_ref !== "string" || body.change_ref.trim().length < 1 || body.change_ref.trim().length > 200 ||
					/[\u0000-\u001f\u007f]/.test(body.reason + body.change_ref)) {
					return corsJson(req, 400, { error: "saml_policy_invalid_request" });
				}
			} else if (!normalizeUuid(body.request_id)) {
				return corsJson(req, 400, { error: "saml_policy_invalid_request" });
			}
		}

		const requestedTenant = normalizeUuid(body.tenant_id ?? req.headers.get("X-AIDR-Tenant-ID"));
		const tenantId = requestedTenant ?? identity.user.id;
		const member = await memberContext(db, identity.user.id, tenantId);
		if (!member) return corsJson(req, 403, { error: "tenant_not_authorized" });
		if (member.requiredSamlProviderId && !jwtHasSamlProvider(identity.token, member.requiredSamlProviderId)) {
			return corsJson(req, 403, { error: "sso_required" });
		}
		if (member.requiredOidcProviderId) {
			const oidcBound = await sessionHasOidcProvider(
				db, identity.token, identity.user.id, member.requiredOidcProviderId, tenantId,
			);
			if (oidcBound === "unavailable") return corsJson(req, 503, { error: "identity_policy_unavailable" });
			if (!oidcBound) return corsJson(req, 403, { error: "sso_required" });
		}

		if (samlAction) {
			const barrier = await checkIdentityBarrier(db, identity.token, identity.user.id, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });
			if (member.role !== "owner") return corsJson(req, 403, { error: "saml_policy_owner_required" });
			const sessionId = jwtSessionId(identity.token);
			const issuedAt = jwtIssuedAtMs(identity.token);
			const expiresAt = jwtExpiresAtMs(identity.token);
			if (!sessionId || issuedAt === null || !Number.isSafeInteger(issuedAt) || issuedAt % 1000 !== 0 ||
				!Number.isFinite(new Date(issuedAt).getTime()) || expiresAt === null || expiresAt <= Date.now() || expiresAt <= issuedAt) {
				return corsJson(req, 401, { error: "saml_policy_session_invalid" });
			}
			if (body.action === "get_saml_policy_change") {
				const { data, error } = await db.rpc("get_tenant_saml_policy_change", {
					p_tenant_id: tenantId, p_actor_user_id: identity.user.id, p_request_id: normalizeUuid(body.request_id)!,
				});
				return error ? samlPolicyError(req, error) : samlPolicyResponse(req, tenantId, data, true);
			}
			if (identity.currentLevel !== "aal2") return corsJson(req, 403, { error: "saml_policy_aal2_required" });
			const samlProviderId = jwtSamlProviderId(identity.token);
			const newProviderId = body.new_provider_id === null ? null : normalizeUuid(body.new_provider_id);
			if (!samlProviderId || (body.action === "request_saml_policy_change" && newProviderId !== null && newProviderId !== samlProviderId)) {
				return corsJson(req, 403, { error: "saml_policy_provider_session_required" });
			}
			const proof: SamlSessionProof = {
				session_id: sessionId, issued_at: new Date(issuedAt).toISOString(), expires_at: new Date(expiresAt).toISOString(),
				aal: "aal2", saml_provider_id: samlProviderId,
			};
			const result = body.action === "request_saml_policy_change"
				? await db.rpc("request_tenant_saml_policy_change", {
					p_tenant_id: tenantId, p_actor_user_id: identity.user.id, p_new_provider_id: newProviderId,
					p_reason: (body.reason as string).trim(), p_change_ref: (body.change_ref as string).trim(), p_validated_session: proof,
				})
				: await db.rpc("approve_tenant_saml_policy_change", {
					p_tenant_id: tenantId, p_actor_user_id: identity.user.id, p_request_id: normalizeUuid(body.request_id)!, p_validated_session: proof,
				});
			return result.error ? samlPolicyError(req, result.error) : samlPolicyResponse(req, tenantId, result.data);
		}

		if (body.action === "status") {
			return corsJson(req, 200, {
				ok: true,
				tenant_id: tenantId,
				role: member.role,
				require_mfa: member.requireMfa,
				required_saml_provider_id: member.requiredSamlProviderId,
				required_oidc_provider_id: member.requiredOidcProviderId,
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
		return corsJson(req, 503, { error: SAML_POLICY_ACTIONS.includes(body.action) ? "saml_policy_unavailable" : "identity_operation_unavailable" });
	}
});
