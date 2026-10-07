import { supabase } from "./supabase";

/**
 * Thin client for `policy-management` actions that need the service's
 * machine-readable error code and details (for example validation issues),
 * not only a generic failure.
 */
export type PolicyManagementResult =
	| { ok: true; data: Record<string, unknown> }
	| { ok: false; code: string; body: Record<string, unknown> | null };

const CODE = /^[a-z][a-z0-9_]{0,63}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function errorBody(error: unknown): Promise<Record<string, unknown> | null> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response)) return null;
	try {
		const body: unknown = await context.clone().json();
		return isRecord(body) ? body : null;
	} catch {
		return null;
	}
}

export async function invokePolicyManagement(
	body: Record<string, unknown>,
	fallback: string,
): Promise<PolicyManagementResult> {
	try {
		const { data, error } = await supabase.functions.invoke("policy-management", { body });
		if (error) {
			const details = await errorBody(error);
			const code =
				typeof details?.error === "string" && CODE.test(details.error) ? details.error : fallback;
			return { ok: false, code, body: details };
		}
		return isRecord(data) && data.ok === true
			? { ok: true, data }
			: { ok: false, code: fallback, body: null };
	} catch {
		return { ok: false, code: fallback, body: null };
	}
}

/** Operator copy for the policy-management error codes these views surface. */
export function policyManagementMessage(code: string): string {
	switch (code) {
		case "mfa_required":
			return "Multi-factor verification (AAL2) is required. Verify with your authenticator, then try again.";
		case "policy_forbidden":
			return "Only workspace owners and administrators can make this change.";
		case "policy_version_conflict":
			return "Someone else changed this policy in the meantime. Reload and try again.";
		case "policy_four_eyes_required":
			return "Four-eyes change control is on: the change needs a second owner or administrator.";
		case "policy_change_request_quota":
			return "Too many change requests are pending. Resolve some under AI governance → Change control.";
		case "revision_not_found":
			return "That revision no longer exists.";
		case "restore_target_not_older":
			return "Only an earlier revision can be restored.";
		case "invalid_dlp_policy":
			return "That revision is no longer valid under today's rules (for example an exception has expired), so it cannot be restored as is.";
		case "invalid_agent_profiles":
			return "The profile document is not valid.";
		case "rate_limited":
			return "Too many requests. Wait a minute and try again.";
		case "tenant_access_denied":
			return "You no longer have access to this workspace.";
		default:
			return "The policy service did not confirm the request.";
	}
}
