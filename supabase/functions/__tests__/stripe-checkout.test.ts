import { describe, expect, it } from "vitest";
import { checkoutParameters } from "../billing-checkout/checkout.ts";
import { evaluateStripeEvent, sumExtraAgentQuantity } from "../stripe-webhook/events.ts";

describe("server-side Stripe checkout linkage", () => {
	const input = { userId: "12345678-1234-4123-8123-123456789012", tenantId: "22345678-1234-4123-8123-123456789012", seats: 3, plan: "monthly", monthlyPrice: "price_monthly", dashboardUrl: "https://aidr.example" };
	it("binds checkout and subscription metadata to the server-authorized tenant", () => {
		const form = checkoutParameters(input);
		expect(form.get("subscription_data[metadata][tenant_id]")).toBe(input.tenantId);
		expect(form.get("metadata[user_id]")).toBe(input.userId);
		const event = evaluateStripeEvent({ type: "customer.subscription.created", data: { object: { id: "sub_1", customer: "cus_1", status: "active", metadata: { user_id: form.get("subscription_data[metadata][user_id]"), tenant_id: form.get("subscription_data[metadata][tenant_id]") }, items: { data: [{ price: { id: form.get("line_items[0][price]") }, quantity: Number(form.get("line_items[0][quantity]")) }] } } } }, { extraAgentPriceId: input.monthlyPrice });
		expect(event.tenantId).toBe(input.tenantId);
		expect(event.extraAgents).toBe(3);
		expect(event.writeEntitlement).toBe(true);
	});
	it.each([0, -1, 1.5, 10001, Number.NaN])("rejects invalid quantity %s", (seats) => expect(() => checkoutParameters({ ...input, seats })).toThrow());
	it("refuses an unconfigured yearly plan", () => expect(() => checkoutParameters({ ...input, plan: "yearly" })).toThrow("billing_price_not_configured"));
	it("reconciles a yearly price without counting unknown items", () => expect(sumExtraAgentQuantity({ data: [{ price: "price_yearly", quantity: 4 }, { price: "price_other", quantity: 900 }] }, "price_monthly", "price_yearly")).toBe(4));
});
