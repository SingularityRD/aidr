import type { SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import {
	jwtHasSamlProvider,
	jwtSessionId,
	policyAllowsAssurance,
	sessionPassesRevocationBarrier,
} from "../identity-security/logic.ts";

export type IdentityBarrierResult =
	| { ok: true }
	| { ok: false; status: 401 | 403 | 503; error: string };

/**
 * Does this access token's session carry a live, unrevoked OIDC SSO binding for
 * the tenant's enforced provider? OIDC sessions are minted by the `oidc-sso`
 * function, so (unlike SAML) the proof is a server-side row keyed by the JWT
 * `session_id`, not an AMR entry. Mirrors the RLS predicate in
 * `tenant_identity_access_allowed`. `"unavailable"` must be treated as denial.
 */
export async function sessionHasOidcProvider(
	db: Pick<SupabaseClient, "from">,
	token: string,
	userId: string,
	providerId: string,
	tenantId: string,
	now = Date.now(),
): Promise<boolean | "unavailable"> {
	const sessionId = jwtSessionId(token);
	if (!sessionId) return false;
	const { data, error } = await db
		.from("oidc_sso_sessions")
		.select("expires_at,revoked_at")
		.eq("session_id", sessionId)
		.eq("user_id", userId)
		.eq("provider_id", providerId)
		.eq("tenant_id", tenantId)
		.maybeSingle();
	if (error) return "unavailable";
	if (!data || (data as { revoked_at?: string | null }).revoked_at) return false;
	const expiresAt = Date.parse(String((data as { expires_at?: string }).expires_at));
	return Number.isFinite(expiresAt) && expiresAt > now;
}

/**
 * Service-role Edge functions bypass tenant RLS. Check the user-session barrier
 * explicitly before any privileged tenant read or mutation. A missing policy row
 * means MFA/SSO are optional; an unreadable row never does.
 */
export async function checkIdentityBarrier(
	db: Pick<SupabaseClient, "from" | "auth">,
	token: string,
	userId: string,
	tenantId?: string,
): Promise<IdentityBarrierResult> {
	try {
		const { data: state, error: stateError } = await db
			.from("identity_user_session_state")
			.select("revoked_before,global_revoke_pending_session_id")
			.eq("user_id", userId)
			.maybeSingle();
		if (stateError) return { ok: false, status: 503, error: "identity_state_unavailable" };
		if (
			state?.global_revoke_pending_session_id ||
			!sessionPassesRevocationBarrier(token, state?.revoked_before)
		) {
			return { ok: false, status: 401, error: "session_revoked" };
		}
		if (!tenantId) return { ok: true };

		const { data: policy, error: policyError } = await db
			.from("tenant_identity_policies")
			.select("require_mfa,required_saml_provider_id,required_oidc_provider_id")
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (policyError) return { ok: false, status: 503, error: "identity_policy_unavailable" };
		if (policy?.required_saml_provider_id !== null && policy?.required_saml_provider_id !== undefined &&
			(typeof policy.required_saml_provider_id !== "string" ||
				!jwtHasSamlProvider(token, policy.required_saml_provider_id))) {
			return { ok: false, status: 403, error: "sso_required" };
		}
		const requiredOidc = policy?.required_oidc_provider_id;
		if (requiredOidc !== null && requiredOidc !== undefined) {
			if (typeof requiredOidc !== "string") return { ok: false, status: 403, error: "sso_required" };
			const bound = await sessionHasOidcProvider(db, token, userId, requiredOidc, tenantId);
			if (bound === "unavailable") return { ok: false, status: 503, error: "identity_policy_unavailable" };
			if (!bound) return { ok: false, status: 403, error: "sso_required" };
		}
		if (policy?.require_mfa !== true) return { ok: true };

		const { data: assurance, error: assuranceError } =
			await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
		if (assuranceError || !assurance) {
			return { ok: false, status: 503, error: "assurance_unavailable" };
		}
		return policyAllowsAssurance(true, assurance.currentLevel ?? null)
			? { ok: true }
			: { ok: false, status: 403, error: "mfa_required" };
	} catch {
		return { ok: false, status: 503, error: "identity_barrier_unavailable" };
	}
}
