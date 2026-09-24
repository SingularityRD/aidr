/**
 * Static mirror of the public.plans catalog seed
 * (supabase/migrations/20260925000010_plan_catalog.sql).
 *
 * The public /pricing page renders from this mirror so it needs no database
 * access; plan-catalog-drift.test.ts parses the migration seed and fails when
 * the two disagree. These are LIST PRICES: final SKU approval is COM-001, and
 * nothing here grants a plan. The tenant's actual plan comes from the
 * member-only get_tenant_plan RPC.
 */
import { supabase } from "../lib/supabase";

export type PlanId = "free" | "team" | "business" | "enterprise";
export type PlanDeployment = "cloud" | "onprem" | "air-gapped";
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
	/** Per-seat price for one month on monthly billing; null = not offered. */
	priceMonthlyCents: number | null;
	/** Per-seat price for one year on annual billing; null = custom quote. */
	priceYearlyCents: number | null;
	currency: "USD";
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
		priceMonthlyCents: 0,
		priceYearlyCents: 0,
		currency: "USD",
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
		priceMonthlyCents: 2400,
		priceYearlyCents: 24000,
		currency: "USD",
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
		priceMonthlyCents: null,
		priceYearlyCents: 54000,
		currency: "USD",
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
		priceMonthlyCents: null,
		priceYearlyCents: null,
		currency: "USD",
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

export const LIST_PRICE_NOTICE =
	"List prices in USD, per developer seat, before tax. Final SKU approval is pending (COM-001); a written quote or order governs.";

export function planById(id: string): PlanDefinition | null {
	return PLAN_CATALOG.find((plan) => plan.id === id) ?? null;
}

function dollars(cents: number): string {
	return cents % 100 === 0 ? `$${cents / 100}` : `$${(cents / 100).toFixed(2)}`;
}

/** Headline price, e.g. "$24", "$0", or "Custom". */
export function headlinePrice(plan: PlanDefinition): string {
	if (plan.priceMonthlyCents !== null) return dollars(plan.priceMonthlyCents);
	if (plan.priceYearlyCents !== null) return dollars(Math.round(plan.priceYearlyCents / 12));
	return "Custom";
}

/** Billing terms line under the headline price. */
export function priceTerms(plan: PlanDefinition): string {
	if (plan.priceMonthlyCents === 0 && plan.priceYearlyCents === 0) return "No charge";
	const parts: string[] = [];
	if (plan.priceMonthlyCents !== null) parts.push("per developer / month, billed monthly");
	if (plan.priceYearlyCents !== null) {
		const monthly = dollars(Math.round(plan.priceYearlyCents / 12));
		parts.push(
			plan.priceMonthlyCents !== null
				? `${monthly} per developer / month billed annually`
				: "per developer / month, billed annually",
		);
	}
	return parts.length > 0 ? parts.join(" · ") : "Quoted per deployment";
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
