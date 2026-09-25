// Pure Stripe price -> catalog plan evaluation (no Deno, Node, or SDK imports).
//
// AIDR_STRIPE_PRICE_MAP maps a Stripe price id to a paid catalog plan and a
// billing interval, e.g.
//
//   {"price_team_m":"team:monthly","price_team_y":"team:yearly","price_biz_y":"business:yearly"}
//
// The map is the only thing that turns a Stripe line item into a plan; the
// checkout metadata is never trusted for that. Only the paid, cloud-sellable
// catalog plans may appear: Free is never purchased and Enterprise is a custom
// quote handled through the invoice/operator path.
//
// The evaluation decides one of three actions, which the database function
// public.apply_stripe_plan_subscription applies atomically and audits:
//
//   grant  - an `active`, automatically collected subscription with exactly one
//            mapped plan item and a verifiable paid period end.
//   revoke - a terminal subscription (deleted, canceled, incomplete_expired).
//            Only the admission bound to `stripe:<subscription id>` is revoked.
//   hold   - any other state (trialing, past_due, unpaid, paused, incomplete,
//            or active with manual collection). Nothing new is granted; an
//            earlier grant keeps its fixed term, which ends at the paid period.

export const PAID_CATALOG_PLANS = ["team", "business"] as const;
type PaidCatalogPlan = (typeof PAID_CATALOG_PLANS)[number];
type BillingInterval = "monthly" | "yearly";

interface PlanPrice {
	planId: PaidCatalogPlan;
	interval: BillingInterval;
}

export type StripePriceMap = ReadonlyMap<string, PlanPrice>;

export type PriceMapResult = { ok: true; map: StripePriceMap } | { ok: false; error: string };

const PRICE_ID = /^price_[A-Za-z0-9]+$/;
const SUBSCRIPTION_ID = /^sub_[A-Za-z0-9_]{1,252}$/;
const MAPPING = /^(team|business):(monthly|yearly)$/;
const TERMINAL_STATUSES = new Set(["canceled", "cancelled", "incomplete_expired"]);
const MAX_MAP_ENTRIES = 32;

/**
 * Parse AIDR_STRIPE_PRICE_MAP. Absent or blank means "no plan prices" (a valid,
 * empty map). Anything malformed is an error: the caller must then refuse to
 * grant any plan rather than guess.
 */
export function parseStripePriceMap(raw: string | null | undefined): PriceMapResult {
	const text = (raw ?? "").trim();
	if (text === "") return { ok: true, map: new Map() };
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return { ok: false, error: "price_map_not_json" };
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		return { ok: false, error: "price_map_not_object" };
	}
	const entries = Object.entries(parsed as Record<string, unknown>);
	if (entries.length > MAX_MAP_ENTRIES) return { ok: false, error: "price_map_too_large" };
	const map = new Map<string, PlanPrice>();
	const seen = new Set<string>();
	for (const [priceId, value] of entries) {
		if (!PRICE_ID.test(priceId)) return { ok: false, error: "price_map_invalid_price_id" };
		const match = typeof value === "string" ? MAPPING.exec(value.trim()) : null;
		if (!match) return { ok: false, error: "price_map_invalid_plan" };
		const key = `${match[1]}:${match[2]}`;
		// One price per plan/interval keeps checkout price selection unambiguous.
		if (seen.has(key)) return { ok: false, error: "price_map_duplicate_plan_interval" };
		seen.add(key);
		map.set(priceId, { planId: match[1] as PaidCatalogPlan, interval: match[2] as BillingInterval });
	}
	return { ok: true, map };
}

/** The configured price for a plan and interval, or null when none is mapped. */
export function priceForPlan(
	map: StripePriceMap,
	planId: string,
	interval: string,
): string | null {
	for (const [priceId, price] of map) {
		if (price.planId === planId && price.interval === interval) return priceId;
	}
	return null;
}

type PlanSubscriptionAction = "grant" | "revoke" | "hold";

export interface PlanSubscriptionEvaluation {
	action: PlanSubscriptionAction;
	/** Machine-readable reason, recorded in the audit log. */
	reason: string;
	subscriptionId: string;
	/** Null only for a terminal event whose items no longer carry a mapped price. */
	planId: PaidCatalogPlan | null;
	interval: BillingInterval | null;
	seats: number;
	status: string;
	currentPeriodEnd: string | null;
}

export type PlanEventResult =
	| { kind: "not_applicable" }
	| { kind: "invalid"; reason: string; subscriptionId: string | null }
	| { kind: "plan"; evaluation: PlanSubscriptionEvaluation };

function asRecord(value: unknown): Record<string, unknown> | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	return value as Record<string, unknown>;
}

function idOf(value: unknown): string | null {
	if (typeof value === "string" && value.trim() !== "") return value.trim();
	const record = asRecord(value);
	return typeof record?.id === "string" && record.id.trim() !== "" ? record.id.trim() : null;
}

function toIso(value: unknown): string | null {
	const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
	if (!Number.isFinite(numeric) || numeric <= 0) return null;
	const date = new Date(Math.floor(numeric) * 1000);
	return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/**
 * Decide what a verified `customer.subscription.*` event may do to the
 * tenant's plan admission. Performs no I/O and never throws.
 */
export function evaluatePlanSubscriptionEvent(
	event: unknown,
	priceMap: StripePriceMap,
): PlanEventResult {
	const envelope = asRecord(event);
	const eventType = typeof envelope?.type === "string" ? envelope.type : "";
	if (!eventType.startsWith("customer.subscription.")) return { kind: "not_applicable" };
	const object = asRecord(asRecord(envelope?.data)?.object);
	if (!object) return { kind: "not_applicable" };
	const rawSubscriptionId = typeof object.id === "string" ? object.id.trim() : "";
	const subscriptionId = SUBSCRIPTION_ID.test(rawSubscriptionId) ? rawSubscriptionId : null;
	const status = typeof object.status === "string" && /^[a-z_]{1,40}$/.test(object.status.trim().toLowerCase())
		? object.status.trim().toLowerCase()
		: "unknown";
	const terminal = eventType === "customer.subscription.deleted" || TERMINAL_STATUSES.has(status);

	const items = asRecord(object.items);
	const data = items?.data;
	const itemsReadable = Array.isArray(data) && items?.has_more !== true;
	const mapped: Array<{ price: PlanPrice; quantity: unknown; periodEnd: unknown }> = [];
	if (itemsReadable) {
		for (const entry of data as unknown[]) {
			const item = asRecord(entry);
			const priceId = item ? idOf(item.price) : null;
			const price = priceId ? priceMap.get(priceId) : undefined;
			if (item && price) mapped.push({ price, quantity: item.quantity, periodEnd: item.current_period_end });
		}
	}

	if (terminal) {
		if (!subscriptionId) return { kind: "invalid", reason: "subscription_id_invalid", subscriptionId: null };
		// Revocation never depends on the price map: the database only revokes the
		// admission bound to this exact subscription id.
		const single = mapped.length === 1 ? mapped[0] : undefined;
		return {
			kind: "plan",
			evaluation: {
				action: "revoke",
				reason: eventType === "customer.subscription.deleted" ? "subscription_deleted" : `subscription_status_${status}`,
				subscriptionId,
				planId: single?.price.planId ?? null,
				interval: single?.price.interval ?? null,
				seats: 0,
				status: eventType === "customer.subscription.deleted" && status === "unknown" ? "canceled" : status,
				currentPeriodEnd: null,
			},
		};
	}

	if (!itemsReadable) {
		return priceMap.size > 0
			? { kind: "invalid", reason: "subscription_items_unavailable", subscriptionId }
			: { kind: "not_applicable" };
	}
	if (mapped.length === 0) return { kind: "not_applicable" };
	if (!subscriptionId) return { kind: "invalid", reason: "subscription_id_invalid", subscriptionId: null };
	if (mapped.length > 1) return { kind: "invalid", reason: "multiple_plan_items", subscriptionId };

	const [item] = mapped as [(typeof mapped)[number]];
	const quantity = typeof item.quantity === "number" ? item.quantity : Number(item.quantity);
	if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 100000) {
		return { kind: "invalid", reason: "plan_quantity_invalid", subscriptionId };
	}
	const periodEnd = toIso(item.periodEnd) ?? toIso(object.current_period_end);
	const base = {
		subscriptionId,
		planId: item.price.planId,
		interval: item.price.interval,
		seats: quantity,
		status,
		currentPeriodEnd: periodEnd,
	};
	if (status !== "active") {
		return { kind: "plan", evaluation: { ...base, action: "hold", reason: `subscription_status_${status}` } };
	}
	// `send_invoice` subscriptions are active before their invoice is paid; only
	// automatic collection proves the card was charged for this period.
	if (object.collection_method !== "charge_automatically") {
		return { kind: "plan", evaluation: { ...base, action: "hold", reason: "subscription_collection_unverified" } };
	}
	if (!periodEnd) {
		return { kind: "plan", evaluation: { ...base, action: "hold", reason: "subscription_period_unavailable" } };
	}
	return { kind: "plan", evaluation: { ...base, action: "grant", reason: "subscription_active" } };
}
