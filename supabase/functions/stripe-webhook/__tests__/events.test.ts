import { describe, expect, it } from "vitest";
import {
	evaluateStripeEvent,
	extractCheckoutIdentifiers,
	extractCheckoutIntentMetadata,
	invoicePaymentReferenceFromList,
	isEntitledSubscriptionStatus,
	isStripeEventId,
	isUuid,
	STRIPE_HANDLED_EVENT_TYPES,
	sumExtraAgentQuantity,
} from "../events.ts";

const PRICE_ID = "price_extra_agent_placeholder";
const USER_ID = "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const TENANT_ID = "1f2e3d4c-5b6a-4c7d-9e8f-0a1b2c3d4e5f";
const CUSTOMER_ID = "cus_test_placeholder";
const SUBSCRIPTION_ID = "sub_test_placeholder";

function subscriptionEvent(type: string, object: Record<string, unknown>) {
	return {
		id: `evt_${type.replace(/\./g, "_")}`,
		created: 1_700_000_000,
		type,
		data: { object: {
			id: SUBSCRIPTION_ID, customer: CUSTOMER_ID,
			collection_method: "charge_automatically", ...object,
		} },
	};
}

function itemsFor(priceId: string, quantity: number) {
	return { data: [{ quantity, price: { id: priceId }, current_period_end: 1_760_086_400 }] };
}

describe("stripe event allow-list and entitlement gates", () => {
	it("exposes exactly the documented allow-listed event types", () => {
		expect([...STRIPE_HANDLED_EVENT_TYPES].sort()).toEqual(
			[
				"checkout.session.completed",
				"customer.subscription.created",
				"customer.subscription.deleted",
				"customer.subscription.updated",
				"invoice.paid",
				"invoice.payment_failed",
			].sort(),
		);
	});

	it("grants the matching line item quantity for an active subscription", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active",
				items: itemsFor(PRICE_ID, 3),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.action).toBe("reconcile");
		expect(decision.status).toBe("active");
		expect(decision.entitled).toBe(true);
		expect(decision.writeEntitlement).toBe(true);
		expect(decision.extraAgents).toBe(3);
	});

	it("treats trialing as entitled", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.created", {
				status: "trialing",
				items: itemsFor(PRICE_ID, 1),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.entitled).toBe(true);
		expect(decision.extraAgents).toBe(1);
	});

	it("revokes paid seats on customer.subscription.deleted", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.deleted", {
				status: "canceled",
				items: itemsFor(PRICE_ID, 5),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.action).toBe("reconcile");
		expect(decision.entitled).toBe(false);
		expect(decision.writeEntitlement).toBe(true);
		expect(decision.extraAgents).toBe(0);
		expect(decision.reason).toBe("subscription_deleted");
	});

	it("revokes even when a deleted event still reports an active status", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.deleted", {
				status: "active",
				items: itemsFor(PRICE_ID, 5),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.entitled).toBe(false);
		expect(decision.extraAgents).toBe(0);
	});

	it.each(["past_due", "unpaid", "canceled", "incomplete", "incomplete_expired", "paused"])(
		"does not grant paid entitlement for status %s",
		(status) => {
			const decision = evaluateStripeEvent(
				subscriptionEvent("customer.subscription.updated", {
					status,
					items: itemsFor(PRICE_ID, 4),
				}),
				{ extraAgentPriceId: PRICE_ID },
			);

			expect(decision.entitled).toBe(false);
			expect(decision.writeEntitlement).toBe(true);
			expect(decision.extraAgents).toBe(0);
		},
	);

	it("does not grant when the line item price is not the configured extra-agent price", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active",
				items: itemsFor("price_something_else", 9),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.entitled).toBe(true);
		expect(decision.extraAgents).toBe(0);
	});

	it("ignores an entitled subscription when no extra-agent price is configured", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active",
				items: itemsFor(PRICE_ID, 4),
			}),
			{ extraAgentPriceId: "" },
		);

		expect(decision.action).toBe("ignore");
		expect(decision.reason).toBe("extra_agent_price_not_configured");
		expect(decision.writeEntitlement).toBe(false);
		expect(decision.extraAgents).toBe(0);
	});

	it("still revokes a deleted subscription when no price is configured", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.deleted", {
				status: "canceled",
				items: itemsFor(PRICE_ID, 4),
			}),
			{ extraAgentPriceId: "" },
		);

		expect(decision.action).toBe("reconcile");
		expect(decision.writeEntitlement).toBe(true);
		expect(decision.extraAgents).toBe(0);
	});

	it("ignores an entitled subscription whose items cannot be inspected", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", { status: "active" }),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.action).toBe("ignore");
		expect(decision.reason).toBe("subscription_items_unavailable");
		expect(decision.writeEntitlement).toBe(false);
	});

	it("never applies invoice.paid to entitlements", () => {
		const decision = evaluateStripeEvent(
			{
				id: "evt_invoice_paid",
				created: 1_700_000_000,
				type: "invoice.paid",
				data: {
					object: {
						id: "in_test_1",
						number: "AIDR-0001",
						status: "paid",
						currency: "usd",
						amount_paid: 2000,
						amount_due: 0,
						hosted_invoice_url: "https://invoice.stripe.com/i/test",
						customer: CUSTOMER_ID,
						subscription: SUBSCRIPTION_ID,
						metadata: { user_id: USER_ID },
					},
				},
			},
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.action).toBe("record");
		expect(decision.writeEntitlement).toBe(false);
		expect(decision.extraAgents).toBe(0);
		expect(decision.userId).toBe(USER_ID);
		expect(decision.subscriptionId).toBe(SUBSCRIPTION_ID);
		expect(decision.invoice?.id).toBe("in_test_1");
		expect(decision.invoice?.amountPaidCents).toBe(2000);
	});

	it("never applies invoice.payment_failed to entitlements", () => {
		const decision = evaluateStripeEvent(
			{
				id: "evt_invoice_failed",
				created: 1_700_000_000,
				type: "invoice.payment_failed",
				data: {
					object: {
						id: "in_test_2",
						status: "open",
						currency: "usd",
						amount_paid: 0,
						amount_due: 2000,
						customer: CUSTOMER_ID,
						subscription: SUBSCRIPTION_ID,
						metadata: { user_id: USER_ID },
					},
				},
			},
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.action).toBe("record");
		expect(decision.writeEntitlement).toBe(false);
		expect(decision.extraAgents).toBe(0);
	});

	it("reads the subscription metadata an invoice carries in its parent object", () => {
		const decision = evaluateStripeEvent(
			{
				id: "evt_invoice_parent",
				created: 1_700_000_000,
				type: "invoice.paid",
				data: {
					object: {
						id: "in_test_3",
						status: "paid",
						currency: "usd",
						customer: CUSTOMER_ID,
						parent: {
							subscription_details: {
								subscription: SUBSCRIPTION_ID,
								metadata: { user_id: USER_ID, tenant_id: TENANT_ID },
							},
						},
					},
				},
			},
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.userId).toBe(USER_ID);
		expect(decision.tenantId).toBe(TENANT_ID);
		expect(decision.subscriptionId).toBe(SUBSCRIPTION_ID);
	});

	it("records checkout.session.completed linkage without granting seats", () => {
		const decision = evaluateStripeEvent(
			{
				id: "evt_checkout",
				created: 1_700_000_000,
				type: "checkout.session.completed",
				data: {
					object: {
						id: "cs_test_1",
						customer: CUSTOMER_ID,
						subscription: SUBSCRIPTION_ID,
						client_reference_id: USER_ID,
						metadata: { user_id: USER_ID, tenant_id: TENANT_ID },
						customer_details: { email: "buyer@example.invalid" },
					},
				},
			},
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.action).toBe("record");
		expect(decision.reason).toBe("checkout_completed_linkage_only");
		expect(decision.writeEntitlement).toBe(false);
		expect(decision.extraAgents).toBe(0);
		expect(decision.userId).toBe(USER_ID);
		expect(decision.tenantId).toBe(TENANT_ID);
		expect(decision.subscriptionId).toBe(SUBSCRIPTION_ID);
	});

	it("ignores event types that are not allow-listed", () => {
		for (const type of ["charge.refunded", "customer.created", "payment_intent.succeeded", ""]) {
			const decision = evaluateStripeEvent(
				{ id: "evt_x", type, data: { object: { id: "obj_1" } } },
				{ extraAgentPriceId: PRICE_ID },
			);
			expect(decision.action).toBe("ignore");
			expect(decision.reason).toBe("event_type_not_allowlisted");
			expect(decision.writeEntitlement).toBe(false);
		}
	});

	it("ignores an allow-listed event with no object", () => {
		const decision = evaluateStripeEvent(
			{ id: "evt_x", type: "customer.subscription.updated", data: {} },
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.action).toBe("ignore");
		expect(decision.reason).toBe("missing_event_object");
	});

	it("fails closed when a handled event has no provider creation time", () => {
		const decision = evaluateStripeEvent({
			id: "evt_missing_created",
			type: "customer.subscription.updated",
			data: { object: { id: SUBSCRIPTION_ID, status: "active", items: itemsFor(PRICE_ID, 9) } },
		}, { extraAgentPriceId: PRICE_ID });
		expect(decision).toMatchObject({
			action: "ignore",
			reason: "missing_event_created_at",
			writeEntitlement: false,
		});
	});

	it("ignores an out-of-range provider time without throwing", () => {
		const decision = evaluateStripeEvent({
			...subscriptionEvent("customer.subscription.updated", {
				status: "active", items: itemsFor(PRICE_ID, 9),
			}),
			created: Number.MAX_VALUE,
		}, { extraAgentPriceId: PRICE_ID });
		expect(decision).toMatchObject({ action: "ignore", reason: "missing_event_created_at" });
	});

	it("never trusts a client-chosen user id", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active",
				items: itemsFor(PRICE_ID, 1),
				metadata: { user_id: "attacker-chosen" },
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.userId).toBeNull();
	});

	it("never trusts a non-uuid tenant id", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active",
				items: itemsFor(PRICE_ID, 1),
				metadata: { user_id: USER_ID, tenant_id: "../../etc/passwd" },
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.userId).toBe(USER_ID);
		expect(decision.tenantId).toBeNull();
	});

	it("captures the billing period end and cancellation flag", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active",
				items: itemsFor(PRICE_ID, 1),
				current_period_end: 1_760_086_400,
				cancel_at_period_end: true,
			}),
			{ extraAgentPriceId: PRICE_ID },
		);

		expect(decision.currentPeriodEnd).toBe(new Date(1_760_086_400 * 1000).toISOString());
		expect(decision.cancelAtPeriodEnd).toBe(true);
	});

	it("reads the Basil item period when the subscription has no top-level period", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active", items: itemsFor(PRICE_ID, 2),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);
		expect(decision).toMatchObject({
			action: "reconcile", extraAgents: 2,
			currentPeriodEnd: new Date(1_760_086_400 * 1000).toISOString(),
		});
	});

	it("uses the earliest period of purchased monthly and yearly items", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active", current_period_end: 1_900_000_000,
				items: { data: [
					{ quantity: 1, price: PRICE_ID, current_period_end: 1_800_000_000 },
					{ quantity: 2, price: "price_yearly", current_period_end: 1_760_086_400 },
					{ quantity: 1, price: "price_other", current_period_end: 1_700_000_000 },
					{ quantity: 0, price: PRICE_ID, current_period_end: 1_700_000_000 },
				] },
			}),
			{ extraAgentPriceId: PRICE_ID, extraAgentYearlyPriceId: "price_yearly" },
		);
		expect(decision.extraAgents).toBe(3);
		expect(decision.currentPeriodEnd).toBe(new Date(1_760_086_400 * 1000).toISOString());
	});

	it("supports a complete legacy subscription period when item periods are absent", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active", current_period_end: 1_760_086_400,
				items: { data: [{ quantity: 1, price: PRICE_ID }] },
			}),
			{ extraAgentPriceId: PRICE_ID },
		);
		expect(decision).toMatchObject({
			action: "reconcile", extraAgents: 1,
			currentPeriodEnd: new Date(1_760_086_400 * 1000).toISOString(),
		});
	});

	it.each([
		{ label: "missing", items: { data: [{ quantity: 1, price: PRICE_ID }] } },
		{ label: "mixed", items: { data: [
			{ quantity: 1, price: PRICE_ID, current_period_end: 1_760_086_400 },
			{ quantity: 1, price: PRICE_ID },
		] } },
		{ label: "invalid", items: { data: [{ quantity: 1, price: PRICE_ID, current_period_end: "bad" }] } },
	])("does not grant seats with $label purchased item periods", ({ items }) => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", { status: "active", items }),
			{ extraAgentPriceId: PRICE_ID },
		);
		expect(decision).toMatchObject({
			action: "ignore", reason: "subscription_period_unavailable", writeEntitlement: false,
		});
	});

	it("caps a trialing item period at the trial end", () => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.created", {
				status: "trialing", trial_end: 1_750_000_000, items: itemsFor(PRICE_ID, 1),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);
		expect(decision.currentPeriodEnd).toBe(new Date(1_750_000_000 * 1000).toISOString());
	});

	it.each(["send_invoice", null])("never grants active send-invoice or unknown collection mode %s", (collection_method) => {
		const decision = evaluateStripeEvent(
			subscriptionEvent("customer.subscription.updated", {
				status: "active", collection_method, items: itemsFor(PRICE_ID, 3),
			}),
			{ extraAgentPriceId: PRICE_ID },
		);
		expect(decision).toMatchObject({
			action: "ignore", reason: "subscription_collection_unverified", entitled: false,
			writeEntitlement: false, extraAgents: 0,
		});
	});
});

describe("stripe helpers", () => {
	it("attributes only one exact paid invoice payment", () => {
		const payment = {
			invoice: "in_test_1", status: "paid", amount_paid: 2000, currency: "usd",
			payment: { type: "payment_intent", payment_intent: "pi_test_1" },
		};
		const list = { data: [payment], has_more: false };
		expect(invoicePaymentReferenceFromList(list, "in_test_1", 2000, "usd"))
			.toEqual({ kind: "payment_intent", id: "pi_test_1" });
		for (const invalid of [
			{ ...list, has_more: true },
			{ ...list, data: [payment, payment] },
			{ ...list, data: [{ ...payment, invoice: "in_other" }] },
			{ ...list, data: [{ ...payment, status: "open" }] },
			{ ...list, data: [{ ...payment, amount_paid: 1000 }] },
			{ ...list, data: [{ ...payment, currency: "eur" }] },
		]) {
			expect(invoicePaymentReferenceFromList(invalid, "in_test_1", 2000, "usd")).toBeNull();
		}
	});

	it("validates uuids", () => {
		expect(isUuid(USER_ID)).toBe(true);
		expect(isUuid("not-a-uuid")).toBe(false);
		expect(isUuid(undefined)).toBe(false);
		expect(isUuid(42)).toBe(false);
	});

	it("validates stripe event ids", () => {
		expect(isStripeEventId("evt_1AbCDefGhI")).toBe(true);
		expect(isStripeEventId("")).toBe(false);
		expect(isStripeEventId("evt_x; drop table")).toBe(false);
		expect(isStripeEventId("a".repeat(260))).toBe(false);
	});

	it("treats only active and trialing as entitled", () => {
		expect(isEntitledSubscriptionStatus("active")).toBe(true);
		expect(isEntitledSubscriptionStatus("ACTIVE")).toBe(true);
		expect(isEntitledSubscriptionStatus("trialing")).toBe(true);
		for (const status of ["past_due", "canceled", "unpaid", "paused", "incomplete", "unknown", ""]) {
			expect(isEntitledSubscriptionStatus(status)).toBe(false);
		}
	});

	it("extracts identifiers only from well-formed metadata", () => {
		expect(extractCheckoutIdentifiers(null)).toEqual({
			userId: null,
			tenantId: null,
			clientReferenceId: null,
		});
		expect(
			extractCheckoutIdentifiers({ client_reference_id: USER_ID, metadata: { tenant_id: TENANT_ID } }),
		).toEqual({ userId: USER_ID, tenantId: TENANT_ID, clientReferenceId: USER_ID });
	});

	it("extracts the exact checkout intent binding from signed Stripe metadata", () => {
		expect(extractCheckoutIntentMetadata({
			metadata: {
				user_id: USER_ID,
				tenant_id: TENANT_ID,
				settlement_id: "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
				request_id: "request_1234567890",
			},
		})).toEqual({
			userId: USER_ID,
			tenantId: TENANT_ID,
			settlementId: "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
			requestId: "request_1234567890",
		});
		expect(extractCheckoutIntentMetadata({
			metadata: { user_id: USER_ID, tenant_id: TENANT_ID, settlement_id: "bad", request_id: "bad" },
		})).toEqual({ userId: USER_ID, tenantId: TENANT_ID, settlementId: null, requestId: null });
		expect(extractCheckoutIntentMetadata(null)).toEqual({
			userId: null, tenantId: null, settlementId: null, requestId: null,
		});
	});

	it("sums only the configured extra-agent price", () => {
		expect(
			sumExtraAgentQuantity(
				{
					data: [
						{ quantity: 2, price: { id: PRICE_ID } },
						{ quantity: 7, price: { id: "price_other" } },
						{ quantity: 1, price: { id: PRICE_ID } },
					],
				},
				PRICE_ID,
			),
		).toBe(3);
		expect(sumExtraAgentQuantity({ data: [] }, PRICE_ID)).toBe(0);
		expect(sumExtraAgentQuantity({ data: [{ quantity: 1, price: PRICE_ID }], has_more: true }, PRICE_ID)).toBeNull();
		expect(sumExtraAgentQuantity(undefined, PRICE_ID)).toBeNull();
		expect(sumExtraAgentQuantity({ data: "nope" }, PRICE_ID)).toBeNull();
		expect(sumExtraAgentQuantity({ data: [{ quantity: 1.5, price: { id: PRICE_ID } }] }, PRICE_ID)).toBeNull();
	});
});
