import { englishT, type Translate } from "../i18n/I18nProvider";
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
export function policyManagementMessage(code: string, t: Translate = englishT): string {
	switch (code) {
		case "mfa_required":
			return t("pm.err.mfa");
		case "policy_forbidden":
			return t("pm.err.forbidden");
		case "policy_version_conflict":
			return t("pm.err.conflict");
		case "policy_four_eyes_required":
			return t("pm.err.fourEyes");
		case "policy_change_request_quota":
			return t("pm.err.quota");
		case "revision_not_found":
			return t("pm.err.revisionMissing");
		case "restore_target_not_older":
			return t("pm.err.notOlder");
		case "invalid_dlp_policy":
			return t("pm.err.invalidDlp");
		case "invalid_agent_profiles":
			return t("pm.err.invalidProfiles");
		case "rate_limited":
			return t("gov.err.rateLimited");
		case "tenant_access_denied":
			return t("pm.err.noAccess");
		default:
			return t("pm.err.generic");
	}
}
