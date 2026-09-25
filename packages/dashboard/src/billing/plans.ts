/**
 * Static mirror of the public.plans catalog seed
 * (supabase/migrations/20260925000010_plan_catalog.sql), without prices.
 *
 * Prices are not published: every paid edition is sold by written quote. The
 * seed's price columns stay server-side reference data and are deliberately
 * absent from this browser bundle; only whether a billing interval is offered
 * is mirrored. The public /pricing (Editions) page renders from this mirror so
 * it needs no database access; plan-catalog-drift.test.ts parses the migration
 * seed and fails when the two disagree. Nothing here grants a plan. The
 * tenant's actual plan comes from the member-only get_tenant_plan RPC, and a
 * card checkout's amount comes from the payment provider's price at checkout.
 */
import { supabase } from "../lib/supabase";

export type PlanId = "free" | "team" | "business" | "enterprise";
export type PlanDeployment = "cloud" | "onprem" | "air-gapped";
export type BillingInterval = "monthly" | "yearly";
export type PlanFeature =
	| "local_detection"
	| "dashboard"
	| "browser_privacy_guard"
	| "entra_sso"
	| "siem_export"
	| "scim"
	| "ai_security_posture"
	| "air_gapped_deployment"
	| "dedicated_support";

export interface PlanDefinition {
	id: PlanId;
	displayName: string;
	/** Protected agents admitted per purchased seat. */
	includedAgents: number;
	minSeats: number;
	/** Billing intervals the catalog offers (seed price column is non-null); empty = quote only. */
	billingIntervals: readonly BillingInterval[];
	features: PlanFeature[];
	selfServe: boolean;
	deployment: PlanDeployment[];
	/** List retention term in days; null = contractual. */
	retentionDays: number | null;
	active: boolean;
	sortOrder: number;
}

export const PLAN_CATALOG: readonly PlanDefinition[] = [
	{
		id: "free",
		displayName: "Free",
		includedAgents: 1,
		minSeats: 1,
		billingIntervals: ["monthly", "yearly"],
		features: ["local_detection", "dashboard"],
		selfServe: true,
		deployment: ["cloud"],
		retentionDays: 7,
		active: true,
		sortOrder: 10,
	},
	{
		id: "team",
		displayName: "Team",
		includedAgents: 1,
		minSeats: 3,
		billingIntervals: ["monthly", "yearly"],
		features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"],
		selfServe: true,
		deployment: ["cloud"],
		retentionDays: 90,
		active: true,
		sortOrder: 20,
	},
	{
		id: "business",
		displayName: "Business",
		includedAgents: 1,
		minSeats: 25,
		billingIntervals: ["yearly"],
		features: [
			"local_detection",
			"dashboard",
			"browser_privacy_guard",
			"entra_sso",
			"siem_export",
			"scim",
			"ai_security_posture",
		],
		selfServe: false,
		deployment: ["cloud", "onprem"],
		retentionDays: 365,
		active: true,
		sortOrder: 30,
	},
	{
		id: "enterprise",
		displayName: "Enterprise",
		includedAgents: 1,
		minSeats: 1,
		billingIntervals: [],
		features: [
			"local_detection",
			"dashboard",
			"browser_privacy_guard",
			"entra_sso",
			"siem_export",
			"scim",
			"ai_security_posture",
			"air_gapped_deployment",
			"dedicated_support",
		],
		selfServe: false,
		deployment: ["onprem", "air-gapped"],
		retentionDays: null,
		active: true,
		sortOrder: 40,
	},
];

export const PLAN_FEATURE_LABELS: Record<PlanFeature, string> = {
	local_detection: "Local detection engine",
	dashboard: "Control-plane dashboard",
	browser_privacy_guard: "Browser Privacy Guard",
	entra_sso: "Microsoft Entra ID single sign-on",
	siem_export: "SIEM export",
	scim: "SCIM provisioning",
	ai_security_posture: "AI security posture",
	air_gapped_deployment: "Air-gapped deployment",
	dedicated_support: "Dedicated support",
};

export const DEPLOYMENT_LABELS: Record<PlanDeployment, string> = {
	cloud: "Cloud",
	onprem: "On-premises",
	"air-gapped": "Air-gapped",
};

/** Shown wherever a price slot used to be. Prices are never published. */
export const QUOTE_NOTICE =
	"Prices are not published. Paid editions are quoted for your seats and deployment; a written quote or order governs.";

export function planById(id: string): PlanDefinition | null {
	return PLAN_CATALOG.find((plan) => plan.id === id) ?? null;
}

export function seatTerms(plan: PlanDefinition): string {
	if (plan.id === "free") return `${plan.includedAgents} protected agent`;
	return plan.minSeats > 1 ? `Minimum ${plan.minSeats} developers` : "Scoped per agreement";
}

export function retentionTerms(plan: PlanDefinition): string {
	return plan.retentionDays === null
		? "Contractual retention"
		: `${plan.retentionDays}-day event retention`;
}

export interface TenantPlan {
	planId: PlanId;
	displayName: string;
	planSource: "stripe_subscription" | "team_record" | "default";
	includedAgentsPerSeat: number;
	minSeats: number;
	selfServe: boolean;
	retentionDays: number | null;
	allowedAgents: number;
	currentAgents: number;
	admission: {
		mode: string;
		status: string;
		kind: "trial" | "licensed" | null;
		expiresAt: string | null;
	};
	subscription: {
		planId: PlanId;
		billingInterval: "monthly" | "yearly";
		seats: number;
		status: string;
		admissionState: string;
		currentPeriodEnd: string | null;
	} | null;
}

const PLAN_IDS: readonly string[] = ["free", "team", "business", "enterprise"];
const NON_NEGATIVE = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const TIMESTAMP_OR_NULL = (value: unknown): value is string | null =>
	value === null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
const STATE = /^[a-z_]{1,40}$/;

function asRecord(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

/** Validate the get_tenant_plan payload. Anything unexpected is rejected, never guessed. */
export function readTenantPlan(value: unknown, tenantId: string): TenantPlan | null {
	const row = asRecord(value);
	const admission = asRecord(row?.admission);
	if (
		!row ||
		!admission ||
		row.tenant_id !== tenantId ||
		typeof row.plan_id !== "string" ||
		!PLAN_IDS.includes(row.plan_id) ||
		typeof row.display_name !== "string" ||
		!(["stripe_subscription", "team_record", "default"] as unknown[]).includes(row.plan_source) ||
		!NON_NEGATIVE(row.included_agents_per_seat) ||
		!NON_NEGATIVE(row.min_seats) ||
		typeof row.self_serve !== "boolean" ||
		!(row.retention_days === null || NON_NEGATIVE(row.retention_days)) ||
		!NON_NEGATIVE(row.allowed_agents) ||
		!NON_NEGATIVE(row.current_agents) ||
		typeof admission.mode !== "string" ||
		typeof admission.status !== "string" ||
		!STATE.test(admission.status) ||
		!(["trial", "licensed", null] as unknown[]).includes(admission.kind) ||
		!TIMESTAMP_OR_NULL(admission.expires_at)
	)
		return null;
	let subscription: TenantPlan["subscription"] = null;
	if (row.subscription !== null && row.subscription !== undefined) {
		const sub = asRecord(row.subscription);
		if (
			!sub ||
			typeof sub.plan_id !== "string" ||
			!PLAN_IDS.includes(sub.plan_id) ||
			(sub.billing_interval !== "monthly" && sub.billing_interval !== "yearly") ||
			!NON_NEGATIVE(sub.seats) ||
			typeof sub.status !== "string" ||
			!STATE.test(sub.status) ||
			typeof sub.admission_state !== "string" ||
			!STATE.test(sub.admission_state) ||
			!TIMESTAMP_OR_NULL(sub.current_period_end)
		)
			return null;
		subscription = {
			planId: sub.plan_id as PlanId,
			billingInterval: sub.billing_interval,
			seats: sub.seats,
			status: sub.status,
			admissionState: sub.admission_state,
			currentPeriodEnd: sub.current_period_end as string | null,
		};
	}
	return {
		planId: row.plan_id as PlanId,
		displayName: row.display_name,
		planSource: row.plan_source as TenantPlan["planSource"],
		includedAgentsPerSeat: row.included_agents_per_seat,
		minSeats: row.min_seats,
		selfServe: row.self_serve,
		retentionDays: row.retention_days as number | null,
		allowedAgents: row.allowed_agents,
		currentAgents: row.current_agents,
		admission: {
			mode: admission.mode,
			status: admission.status,
			kind: admission.kind as "trial" | "licensed" | null,
			expiresAt: admission.expires_at as string | null,
		},
		subscription,
	};
}

export async function loadTenantPlan(tenantId: string): Promise<TenantPlan> {
	const { data, error } = await supabase.rpc("get_tenant_plan", { p_tenant_id: tenantId });
	if (error) throw new Error("Plan information is unavailable");
	const plan = readTenantPlan(data, tenantId);
	if (!plan) throw new Error("Plan information is unavailable");
	return plan;
}
