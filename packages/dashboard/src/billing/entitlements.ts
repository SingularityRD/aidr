/**
 * Plan entitlements for dashboard gating.
 *
 * Reads the member-only `get_tenant_plan_entitlements` RPC, which returns the
 * same server resolver the Edge Functions enforce with `requireFeature`
 * (supabase/functions/_shared/plan-entitlements.ts). The dashboard only hides
 * or disables what the server would refuse; it never grants anything, and an
 * unreadable answer is treated as "not available" rather than guessed.
 */
import { supabase } from "../lib/supabase";
import { type PlanFeature, type PlanId, planById } from "./plans";

export type GatedPlanFeature = Extract<
	PlanFeature,
	| "browser_privacy_guard"
	| "entra_sso"
	| "siem_export"
	| "scim"
	| "ai_security_posture"
	| "air_gapped_deployment"
>;

/** Cheapest edition that includes each gated feature (mirrors the catalog seed). */
export const FEATURE_MINIMUM_PLAN: Readonly<Record<GatedPlanFeature, PlanId>> = {
	browser_privacy_guard: "team",
	entra_sso: "team",
	siem_export: "business",
	scim: "business",
	ai_security_posture: "business",
	air_gapped_deployment: "enterprise",
};

export interface TenantEntitlements {
	planId: PlanId;
	source: string;
	trialActive: boolean;
	features: ReadonlySet<string>;
	retentionDaysMax: number | null;
}

const PLAN_IDS: readonly string[] = ["free", "team", "business", "enterprise"];
const SOURCES: readonly string[] = [
	"stripe_subscription",
	"team_record",
	"trial",
	"default",
	"admission_inactive",
];

/** Strict parse; anything unexpected is null. */
export function readTenantEntitlements(
	value: unknown,
	tenantId: string,
): TenantEntitlements | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const row = value as Record<string, unknown>;
	if (
		row.tenant_id !== tenantId ||
		typeof row.plan_id !== "string" ||
		!PLAN_IDS.includes(row.plan_id) ||
		typeof row.plan_source !== "string" ||
		!SOURCES.includes(row.plan_source) ||
		typeof row.trial_active !== "boolean" ||
		!Array.isArray(row.features) ||
		!row.features.every((feature) => typeof feature === "string") ||
		!(
			row.retention_days_max === null ||
			(typeof row.retention_days_max === "number" && Number.isSafeInteger(row.retention_days_max))
		)
	)
		return null;
	return {
		planId: row.plan_id as PlanId,
		source: row.plan_source,
		trialActive: row.trial_active,
		features: new Set(row.features as string[]),
		retentionDaysMax: row.retention_days_max as number | null,
	};
}

export async function loadTenantEntitlements(tenantId: string): Promise<TenantEntitlements> {
	const { data, error } = await supabase.rpc("get_tenant_plan_entitlements", {
		p_tenant_id: tenantId,
	});
	if (error) throw new Error("Plan information is unavailable");
	const entitlements = readTenantEntitlements(data, tenantId);
	if (!entitlements) throw new Error("Plan information is unavailable");
	return entitlements;
}

export function requiredPlanName(feature: GatedPlanFeature): string {
	return planById(FEATURE_MINIMUM_PLAN[feature])?.displayName ?? FEATURE_MINIMUM_PLAN[feature];
}
