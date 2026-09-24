import { describe, expect, it } from "vitest";
import { checkoutParameters } from "../billing-checkout/checkout.ts";
import { evaluateStripeEvent, sumExtraAgentQuantity } from "../stripe-webhook/events.ts";

describe("server-side Stripe checkout linkage", () => {
	const input = { userId: "12345678-1234-4123-8123-123456789012", tenantId: "22345678-1234-4123-8123-123456789012", settlementId: "32345678-1234-4123-8123-123456789012", requestId: "checkout_request_123456", seats: 3, plan: "monthly", monthlyPrice: "price_monthly", dashboardUrl: "https://aidr.example" };
	it("binds checkout and subscription metadata to the server-authorized tenant", () => {
		const form = checkoutParameters(input);
		expect(form.get("subscription_data[metadata][tenant_id]")).toBe(input.tenantId);
		expect(form.get("metadata[user_id]")).toBe(input.userId);
		expect(form.get("metadata[settlement_id]")).toBe(input.settlementId);
		expect(form.get("subscription_data[metadata][request_id]")).toBe(input.requestId);
		const event = evaluateStripeEvent({ created: 1_700_000_000, type: "customer.subscription.created", data: { object: { id: "sub_1", customer: "cus_1", status: "active", collection_method: "charge_automatically", metadata: { user_id: form.get("subscription_data[metadata][user_id]"), tenant_id: form.get("subscription_data[metadata][tenant_id]") }, items: { data: [{ price: { id: form.get("line_items[0][price]") }, quantity: Number(form.get("line_items[0][quantity]")), current_period_end: 1_702_592_000 }] } } } }, { extraAgentPriceId: input.monthlyPrice });
		expect(event.tenantId).toBe(input.tenantId);
		expect(event.extraAgents).toBe(3);
		expect(event.writeEntitlement).toBe(true);
	});
	it("extracts an exact payment reference from signed invoice evidence", () => {
		const event = evaluateStripeEvent({
			created: 1_700_000_000,
			type: "invoice.paid",
			data: { object: {
				id: "in_paid_1",
				customer: "cus_1",
				subscription: "sub_1",
				payment_intent: "pi_exact_1",
				amount_paid: 3000,
				amount_due: 3000,
				currency: "usd",
				status: "paid",
				parent: { subscription_details: { subscription: "sub_1", metadata: {
					user_id: input.userId,
					tenant_id: input.tenantId,
					settlement_id: input.settlementId,
					request_id: input.requestId,
				} } },
			} },
		});
		expect(event.invoice).toMatchObject({
			settlementId: input.settlementId,
			requestId: input.requestId,
			paymentReference: { kind: "payment_intent", id: "pi_exact_1" },
			amountPaidCents: 3000,
		});
	});
	it("keeps renewal payments distinct under one checkout settlement", () => {
		const invoice = (id: string, paymentIntent: string) => evaluateStripeEvent({
			created: 1_700_000_000,
			type: "invoice.paid",
			data: { object: {
				id,
				customer: "cus_1",
				subscription: "sub_1",
				payment_intent: paymentIntent,
				amount_paid: 3000,
				amount_due: 3000,
				currency: "usd",
				parent: { subscription_details: { subscription: "sub_1", metadata: {
					user_id: input.userId,
					tenant_id: input.tenantId,
					settlement_id: input.settlementId,
					request_id: input.requestId,
				} } },
			} },
		});
		const first = invoice("in_renewal_1", "pi_renewal_1");
		const second = invoice("in_renewal_2", "pi_renewal_2");
		expect(first.invoice?.settlementId).toBe(second.invoice?.settlementId);
		expect(first.invoice?.paymentReference).toEqual({ kind: "payment_intent", id: "pi_renewal_1" });
		expect(second.invoice?.paymentReference).toEqual({ kind: "payment_intent", id: "pi_renewal_2" });
	});
	it.each([0, -1, 1.5, 10001, Number.NaN])("rejects invalid quantity %s", (seats) => expect(() => checkoutParameters({ ...input, seats })).toThrow());
	it("refuses an unconfigured yearly plan", () => expect(() => checkoutParameters({ ...input, plan: "yearly" })).toThrow("billing_price_not_configured"));
	it("reconciles a yearly price without counting unknown items", () => expect(sumExtraAgentQuantity({ data: [{ price: "price_yearly", quantity: 4 }, { price: "price_other", quantity: 900 }] }, "price_monthly", "price_yearly")).toBe(4));
});
