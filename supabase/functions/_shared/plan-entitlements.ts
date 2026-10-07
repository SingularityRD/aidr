// Server-side plan entitlements: the one resolver every gated Edge Function uses.
//
// The plan catalog (`public.plans`, 20260925000010_plan_catalog.sql) lists the
// features of each edition, but until now those features were display-only.
// This module turns them into an authorization decision:
//
//   * `resolveTenantPlan(db, tenantId)` calls the service-role-only
//     `public.tenant_plan_entitlements` RPC (20261007130000_plan_retention_and_
//     feature_gating.sql). The database resolves the plan exactly once, from the
//     audited sources only: a granted Stripe subscription bound to the active
//     admission, otherwise the billing-managed team label, honoured only while
//     the tenant holds an active admission (or an approved pilot); an active
//     verified trial evaluates the Team edition. Anything else is Free.
//   * `requireFeature(db, tenantId, feature)` fails CLOSED: a missing feature
//     answers 402 `plan_feature_required`, and an unreadable or malformed
//     entitlement answers 503 `plan_entitlement_unavailable` — never "allow".
//
// Scope (CLAUDE.md): this gates managed, paid control-plane features (SCIM,
// SSO administration, Entra group sync, SIEM/audit export, AI security posture,
// Browser Guard telemetry, air-gapped deployment). It is never wired into local
// detection or into the connector's ingest of verdicts: detection does not
// depend on a plan or an account.
//
// The tier table mirrors the catalog seed and the dashboard mirror
// (packages/dashboard/src/billing/plans.ts): TEAM adds Browser Guard and Entra
// SSO, BUSINESS adds SIEM export, SCIM and AI Security Posture, ENTERPRISE adds
// air-gapped deployment. The database row is authoritative; the table below is
// used only to name the cheapest plan in the upgrade message.

export const PLAN_IDS = ["free", "team", "business", "enterprise"] as const;
export type PlanId = (typeof PLAN_IDS)[number];

export const GATED_FEATURES = [
	"browser_privacy_guard",
	"entra_sso",
	"siem_export",
	"scim",
	"ai_security_posture",
	"air_gapped_deployment",
] as const;
export type GatedFeature = (typeof GATED_FEATURES)[number];

/** Cheapest catalog edition that includes each gated feature. */
export const FEATURE_MINIMUM_PLAN: Readonly<Record<GatedFeature, PlanId>> = Object.freeze({
	browser_privacy_guard: "team",
	entra_sso: "team",
	siem_export: "business",
	scim: "business",
	ai_security_posture: "business",
	air_gapped_deployment: "enterprise",
});

export const PLAN_FEATURE_REQUIRED = "plan_feature_required";
export const PLAN_ENTITLEMENT_UNAVAILABLE = "plan_entitlement_unavailable";

export interface TenantPlanEntitlement {
	tenantId: string;
	planId: PlanId;
	/** Where the plan came from: stripe_subscription | team_record | trial | default | admission_inactive. */
	source: string;
	trialActive: boolean;
	features: ReadonlySet<string>;
	/** Maximum event (telemetry) retention the plan allows; null = contractual, no catalog cap. */
	retentionDaysMax: number | null;
}

/** Structural subset of the service-role Supabase client. */
export interface PlanEntitlementDb {
	rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }>;
}

const FEATURE_ID = /^[a-z][a-z0-9_]{0,63}$/;
const SOURCES = new Set(["stripe_subscription", "team_record", "trial", "default", "admission_inactive"]);

function record(value: unknown): Record<string, unknown> | null {
	const row = Array.isArray(value) && value.length === 1 ? value[0] : value;
	return row && typeof row === "object" && !Array.isArray(row) ? (row as Record<string, unknown>) : null;
}

/** Strictly parse the RPC result; anything unexpected is null (and callers fail closed). */
export function parseTenantPlanEntitlement(value: unknown, tenantId: string): TenantPlanEntitlement | null {
	const row = record(value);
	if (!row) return null;
	if (row.tenant_id !== tenantId) return null;
	if (typeof row.plan_id !== "string" || !(PLAN_IDS as readonly string[]).includes(row.plan_id)) return null;
	if (typeof row.plan_source !== "string" || !SOURCES.has(row.plan_source)) return null;
	if (typeof row.trial_active !== "boolean") return null;
	if (!Array.isArray(row.features) || row.features.length > 64 || !row.features.every((f) => typeof f === "string" && FEATURE_ID.test(f))) {
		return null;
	}
	const max = row.retention_days_max;
	if (max !== null && (typeof max !== "number" || !Number.isSafeInteger(max) || max < 1 || max > 3650)) return null;
	return {
		tenantId,
		planId: row.plan_id as PlanId,
		source: row.plan_source,
		trialActive: row.trial_active,
		features: new Set(row.features as string[]),
		retentionDaysMax: max as number | null,
	};
}

/** The tenant's effective plan, or null when it cannot be read (callers fail closed). */
export async function resolveTenantPlan(db: PlanEntitlementDb, tenantId: string): Promise<TenantPlanEntitlement | null> {
	try {
		const { data, error } = await db.rpc("tenant_plan_entitlements", { p_tenant_id: tenantId });
		if (error) return null;
		return parseTenantPlanEntitlement(data, tenantId);
	} catch {
		return null;
	}
}

export type FeatureDecision =
	| { ok: true; entitlement: TenantPlanEntitlement }
	| { ok: false; status: 402 | 503; body: Record<string, unknown> };

/** Decide `feature` for an already resolved (or unavailable) entitlement. */
export function decideFeature(entitlement: TenantPlanEntitlement | null, feature: GatedFeature): FeatureDecision {
	if (!entitlement) return { ok: false, status: 503, body: { error: PLAN_ENTITLEMENT_UNAVAILABLE } };
	if (entitlement.features.has(feature)) return { ok: true, entitlement };
	return {
		ok: false,
		status: 402,
		body: {
			error: PLAN_FEATURE_REQUIRED,
			feature,
			plan_id: entitlement.planId,
			required_plan: FEATURE_MINIMUM_PLAN[feature],
		},
	};
}

/**
 * Fail-closed feature check for one tenant. Call it only after the caller has
 * been authenticated and bound to `tenantId`, and before any feature data is
 * read or written.
 */
export async function requireFeature(db: PlanEntitlementDb, tenantId: string, feature: GatedFeature): Promise<FeatureDecision> {
	return decideFeature(await resolveTenantPlan(db, tenantId), feature);
}

/**
 * Effective event retention: the tenant setting capped by the plan maximum. A
 * tenant that never chose a value (seeded row) gets the plan's term.
 * Mirrors `app.tenant_effective_retention_days` used by the reaper.
 */
export function effectiveRetentionDays(
	configuredDays: number,
	explicitlyConfigured: boolean,
	planMaxDays: number | null,
): number {
	if (planMaxDays === null) return configuredDays;
	return explicitlyConfigured ? Math.min(configuredDays, planMaxDays) : planMaxDays;
}
