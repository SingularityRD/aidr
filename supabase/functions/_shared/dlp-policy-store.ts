import type { SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
// Generated, byte-parity-checked artifact of the engine schema, packaged with
// functions/ for self-hosted deployments; never the dashboard validation mirror.
import { DlpPolicySchema } from "./dlp-policy-schema.ts";
import { corsJson } from "./cors.ts";
import { isFourEyesRefusal, readPolicyFourEyes, submitPolicyChange } from "./policy-change-control.ts";

const DELIVERY = {
	delivered: false,
	delivery_status: "not_delivered",
	delivery_detail: "Saved policy is not signed runtime distribution; the signed provisioning path must consume it separately.",
} as const;

/** Called only after verified identity, live tenant membership/status and quota checks. */
export async function handleDlpPolicyAction(
	req: Request,
	db: SupabaseClient,
	body: Record<string, unknown>,
	context: { tenant: string; userId: string; role: string; token: string },
): Promise<Response> {
	const { tenant, userId, role, token } = context;
	const publishing = body.action === "publish_dlp_policy";
	if (publishing && !["owner", "admin"].includes(role)) {
		return corsJson(req, 403, { error: "policy_forbidden" });
	}
	// DLP documents contain sensitive matchers and exceptions. Require step-up
	// for both reads and writes, even when the tenant's general MFA is optional.
	const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
	if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
	if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

	if (!publishing) {
		const { data, error } = await db.from("tenant_dlp_policies")
			.select("version,policy,updated_at").eq("tenant_id", tenant).maybeSingle();
		if (error) return corsJson(req, 503, { error: "dlp_policy_unavailable" });
		// PostgREST's maybeSingle contract is `row | null`. Do not turn a malformed
		// response with missing `data` into `saved: true` (`undefined !== null`).
		if (data === undefined) return corsJson(req, 503, { error: "dlp_policy_unavailable" });
		// Do not revalidate time-sensitive exception expiry on reload: a saved
		// document can age, and must remain readable so an operator can repair it.
		if (data && (!Number.isSafeInteger(data.version) || data.version < 1 ||
			data.policy?.tenantId !== tenant || data.policy?.version !== data.version ||
			typeof data.updated_at !== "string" || !Number.isFinite(Date.parse(data.updated_at)))) {
			return corsJson(req, 503, { error: "dlp_policy_unavailable" });
		}
		return corsJson(req, 200, {
			ok: true, version: data?.version ?? 0, policy: data?.policy ?? null,
			updated_at: data?.updated_at ?? null, saved: data !== null, ...DELIVERY,
		});
	}

	const expected = body.expected_version;
	if (!Number.isSafeInteger(expected) || Number(expected) < 0 || Number(expected) >= Number.MAX_SAFE_INTEGER) {
		return corsJson(req, 400, { error: "invalid_version" });
	}
	const validated = DlpPolicySchema.safeParse(body.policy);
	if (!validated.success) {
		return corsJson(req, 400, {
			error: "invalid_dlp_policy",
			issues: validated.error.issues.map(({ path, message }) => ({ path, message })),
		});
	}
	if (validated.data.tenantId !== tenant) return corsJson(req, 400, { error: "dlp_tenant_mismatch" });
	// The editor keeps its document version independent of its CAS precondition.
	// Storage owns the revision counter; never allow client-chosen version jumps.
	const policy = { ...validated.data, version: Number(expected) + 1 };
	// Four-eyes change control: the saved revision waits for a second owner/admin.
	const fourEyes = await readPolicyFourEyes(db, tenant);
	if (!fourEyes.ok) return corsJson(req, 503, { error: "dlp_policy_publish_failed" });
	if (fourEyes.enabled) {
		return await submitPolicyChange(req, db, {
			tenantId: tenant, userId, kind: "dlp_publish", baseVersion: Number(expected), payload: { policy },
		});
	}
	const { data, error } = await db.rpc("publish_dlp_policy", {
		p_tenant_id: tenant, p_user_id: userId, p_expected_version: expected, p_policy: policy,
	});
	if (error) {
		if (isFourEyesRefusal(error)) return corsJson(req, 409, { error: "policy_four_eyes_required" });
		return corsJson(req, error.code === "PT409" ? 409 : error.code === "42501" ? 403 : error.code === "22023" ? 400 : 503, {
			error: error.code === "PT409" ? "policy_version_conflict" : "dlp_policy_publish_failed",
		});
	}
	// A successful RPC must confirm the committed row, not just a truthy payload.
	if (!data || data.version !== policy.version || data.policy?.version !== policy.version ||
		data.policy?.tenantId !== tenant || typeof data.updated_at !== "string" ||
		!Number.isFinite(Date.parse(data.updated_at))) {
		return corsJson(req, 503, { error: "dlp_policy_publish_failed" });
	}
	return corsJson(req, 200, {
		ok: true, version: data.version, policy: data.policy, updated_at: data.updated_at,
		saved: true, ...DELIVERY,
	});
}
