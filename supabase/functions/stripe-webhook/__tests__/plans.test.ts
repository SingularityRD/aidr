import { describe, expect, it } from "vitest";
import {
	evaluatePlanSubscriptionEvent,
	parseStripePriceMap,
	priceForPlan,
	type StripePriceMap,
} from "../plans.ts";

const MAP_JSON = JSON.stringify({
	price_teamMonthly: "team:monthly",
	price_teamYearly: "team:yearly",
	price_businessYearly: "business:yearly",
});

function map(): StripePriceMap {
	const parsed = parseStripePriceMap(MAP_JSON);
	if (!parsed.ok) throw new Error(parsed.error);
	return parsed.map;
}

function subscriptionEvent(
	type: string,
	object: Record<string, unknown>,
): Record<string, unknown> {
	return {
		id: "evt_plan_1",
		created: 1_800_000_000,
		type,
		data: {
			object: {
				id: "sub_plan_1",
				customer: "cus_1",
				status: "active",
				collection_method: "charge_automatically",
				items: {
					has_more: false,
					data: [{ price: { id: "price_teamMonthly" }, quantity: 5, current_period_end: 1_802_592_000 }],
				},
				...object,
			},
		},
	};
}

describe("AIDR_STRIPE_PRICE_MAP parsing", () => {
	it("treats an absent map as empty and valid", () => {
		for (const raw of [undefined, null, "", "   "]) {
			const parsed = parseStripePriceMap(raw);
			expect(parsed.ok).toBe(true);
			if (parsed.ok) expect(parsed.map.size).toBe(0);
		}
	});

	it("parses price to plan/interval entries", () => {
		const parsed = map();
		expect(parsed.get("price_teamMonthly")).toEqual({ planId: "team", interval: "monthly" });
		expect(parsed.get("price_businessYearly")).toEqual({ planId: "business", interval: "yearly" });
		expect(priceForPlan(parsed, "team", "yearly")).toBe("price_teamYearly");
		expect(priceForPlan(parsed, "business", "monthly")).toBeNull();
	});

	it.each([
		["not json", "price_map_not_json"],
		["[]", "price_map_not_object"],
		[JSON.stringify({ "not-a-price": "team:monthly" }), "price_map_invalid_price_id"],
		[JSON.stringify({ price_a: "free:monthly" }), "price_map_invalid_plan"],
		[JSON.stringify({ price_a: "enterprise:yearly" }), "price_map_invalid_plan"],
		[JSON.stringify({ price_a: "team:weekly" }), "price_map_invalid_plan"],
		[JSON.stringify({ price_a: 3 }), "price_map_invalid_plan"],
		[JSON.stringify({ price_a: "team:monthly", price_b: "team:monthly" }), "price_map_duplicate_plan_interval"],
	])("rejects malformed map %s", (raw, error) => {
		expect(parseStripePriceMap(raw)).toEqual({ ok: false, error });
	});
});

describe("plan subscription evaluation", () => {
	it("ignores non-subscription events and unmapped prices", () => {
		expect(evaluatePlanSubscriptionEvent({ type: "invoice.paid", data: { object: {} } }, map())).toEqual({
			kind: "not_applicable",
		});
		const extraOnly = subscriptionEvent("customer.subscription.updated", {
			items: { has_more: false, data: [{ price: "price_extra", quantity: 4 }] },
		});
		expect(evaluatePlanSubscriptionEvent(extraOnly, map())).toEqual({ kind: "not_applicable" });
	});

	it("grants only an active, automatically collected, single mapped plan item", () => {
		const result = evaluatePlanSubscriptionEvent(subscriptionEvent("customer.subscription.created", {}), map());
		expect(result).toEqual({
			kind: "plan",
			evaluation: {
				action: "grant",
				reason: "subscription_active",
				subscriptionId: "sub_plan_1",
				planId: "team",
				interval: "monthly",
				seats: 5,
				status: "active",
				currentPeriodEnd: new Date(1_802_592_000 * 1000).toISOString(),
			},
		});
	});

	it("falls back to the subscription period end for legacy payloads", () => {
		const result = evaluatePlanSubscriptionEvent(
			subscriptionEvent("customer.subscription.updated", {
				current_period_end: 1_803_000_000,
				items: { data: [{ price: "price_businessYearly", quantity: 30 }] },
			}),
			map(),
		);
		expect(result.kind === "plan" && result.evaluation).toMatchObject({
			action: "grant",
			planId: "business",
			interval: "yearly",
			seats: 30,
			currentPeriodEnd: new Date(1_803_000_000 * 1000).toISOString(),
		});
	});

	it.each([
		["trialing", {}, "subscription_status_trialing"],
		["past_due", {}, "subscription_status_past_due"],
		["unpaid", {}, "subscription_status_unpaid"],
		["paused", {}, "subscription_status_paused"],
		["incomplete", {}, "subscription_status_incomplete"],
		["active", { collection_method: "send_invoice" }, "subscription_collection_unverified"],
		[
			"active",
			{ items: { data: [{ price: "price_teamMonthly", quantity: 3 }] } },
			"subscription_period_unavailable",
		],
	])("never grants a %s subscription (%j)", (status, extra, reason) => {
		const result = evaluatePlanSubscriptionEvent(
			subscriptionEvent("customer.subscription.updated", { status, ...extra }),
			map(),
		);
		expect(result.kind).toBe("plan");
		if (result.kind === "plan") {
			expect(result.evaluation.action).toBe("hold");
			expect(result.evaluation.reason).toBe(reason);
		}
	});

	it.each([
		["customer.subscription.deleted", "active", "subscription_deleted"],
		["customer.subscription.updated", "canceled", "subscription_status_canceled"],
		["customer.subscription.updated", "incomplete_expired", "subscription_status_incomplete_expired"],
	])("revokes on terminal %s/%s", (type, status, reason) => {
		const result = evaluatePlanSubscriptionEvent(subscriptionEvent(type, { status }), map());
		expect(result.kind === "plan" && result.evaluation).toMatchObject({
			action: "revoke",
			reason,
			subscriptionId: "sub_plan_1",
			planId: "team",
			seats: 0,
		});
	});

	it("revokes a terminal subscription even when the price map is empty or the price is gone", () => {
		const result = evaluatePlanSubscriptionEvent(
			subscriptionEvent("customer.subscription.deleted", { status: "canceled", items: undefined }),
			new Map(),
		);
		expect(result.kind === "plan" && result.evaluation).toMatchObject({
			action: "revoke",
			planId: null,
			interval: null,
			subscriptionId: "sub_plan_1",
		});
	});

	it.each([
		[{ items: { has_more: true, data: [] } }, "subscription_items_unavailable"],
		[
			{
				items: {
					data: [
						{ price: "price_teamMonthly", quantity: 3, current_period_end: 1_802_592_000 },
						{ price: "price_businessYearly", quantity: 25, current_period_end: 1_802_592_000 },
					],
				},
			},
			"multiple_plan_items",
		],
		[{ items: { data: [{ price: "price_teamMonthly", quantity: 0 }] } }, "plan_quantity_invalid"],
		[{ items: { data: [{ price: "price_teamMonthly", quantity: 1.5 }] } }, "plan_quantity_invalid"],
		[{ id: "not-a-subscription" }, "subscription_id_invalid"],
	])("refuses ambiguous plan evidence %j", (object, reason) => {
		const result = evaluatePlanSubscriptionEvent(
			subscriptionEvent("customer.subscription.updated", object),
			map(),
		);
		expect(result).toMatchObject({ kind: "invalid", reason });
	});
});
