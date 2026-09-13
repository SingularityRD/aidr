import type { SupabaseClient } from "npm:@supabase/supabase-js@2";
import {
	policyAllowsAssurance,
	sessionPassesRevocationBarrier,
} from "../identity-security/logic.ts";

export type IdentityBarrierResult =
	| { ok: true }
	| { ok: false; status: 401 | 403 | 503; error: string };

/**
 * Service-role Edge functions bypass tenant RLS. Check the user-session barrier
 * explicitly before any privileged tenant read or mutation. A missing policy row
 * means MFA is optional; an unreadable row never does.
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
			.select("revoked_before")
			.eq("user_id", userId)
			.maybeSingle();
		if (stateError) return { ok: false, status: 503, error: "identity_state_unavailable" };
		if (!sessionPassesRevocationBarrier(token, state?.revoked_before)) {
			return { ok: false, status: 401, error: "session_revoked" };
		}
		if (!tenantId) return { ok: true };

		const { data: policy, error: policyError } = await db
			.from("tenant_identity_policies")
			.select("require_mfa")
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (policyError) return { ok: false, status: 503, error: "identity_policy_unavailable" };
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
