import { describe, expect, it } from "vitest";
import { evaluateStripeEvent } from "../events.ts";
import { isBoundZeroSeatTransition, selectStripeCustomerLinkage } from "../customer-linkage.ts";

const CUSTOMER_ID = "cus_shared_customer";
const USER_A = "12345678-1234-4123-8123-123456789012";
const TENANT_A = "22345678-1234-4123-8123-123456789012";
const USER_B = "32345678-1234-4123-8123-123456789012";
const TENANT_B = "42345678-1234-4123-8123-123456789012";

const mappings = [
	{ user_id: USER_A, tenant_id: TENANT_A },
	{ user_id: USER_A, tenant_id: TENANT_B },
];

describe("Stripe customer tenant linkage", () => {
	it("revokes a bound subscription after buyer offboarding, but cannot grant or cross tenants", () => {
		const evaluation = evaluateStripeEvent({
			id: "evt_cancelled",
			created: 1_700_000_030,
			type: "customer.subscription.deleted",
			data: { object: {
				id: "sub_offboarded",
				customer: CUSTOMER_ID,
				status: "canceled",
				metadata: { user_id: USER_A, tenant_id: TENANT_A },
			} },
		});
		const bound = { provider: "stripe", provider_subscription_id: "sub_offboarded", user_id: USER_A, tenant_id: TENANT_A };
		expect(isBoundZeroSeatTransition(evaluation, bound, USER_A, TENANT_A)).toBe(true);
		expect(isBoundZeroSeatTransition({ ...evaluation, userId: null, tenantId: null }, bound, USER_A, TENANT_A)).toBe(true);
		expect(isBoundZeroSeatTransition(evaluation, { ...bound, tenant_id: TENANT_B }, USER_A, TENANT_A)).toBe(false);
		expect(isBoundZeroSeatTransition(evaluation, { ...bound, user_id: USER_B }, USER_A, TENANT_A)).toBe(false);
		expect(isBoundZeroSeatTransition(evaluation, { ...bound, provider_subscription_id: "sub_other" }, USER_A, TENANT_A)).toBe(false);
		expect(isBoundZeroSeatTransition(evaluation, { ...bound, provider: "paddle" }, USER_A, TENANT_A)).toBe(false);
		expect(isBoundZeroSeatTransition({ ...evaluation, extraAgents: 1 }, bound, USER_A, TENANT_A)).toBe(false);
	});

	it("resolves one Stripe customer to either tenant using signed metadata", () => {
		expect(selectStripeCustomerLinkage(mappings, { userId: USER_A, tenantId: TENANT_A }).linkage)
			.toEqual({ userId: USER_A, tenantId: TENANT_A });
		expect(selectStripeCustomerLinkage(mappings, { userId: USER_A, tenantId: TENANT_B }).linkage)
			.toEqual({ userId: USER_A, tenantId: TENANT_B });
	});

	it("keeps tenant resolution stable when events arrive out of order", () => {
		const events = [
			{ id: "evt_b_new", created: 1_700_000_020, userId: USER_A, tenantId: TENANT_B },
			{ id: "evt_a_new", created: 1_700_000_010, userId: USER_A, tenantId: TENANT_A },
			{ id: "evt_a_old", created: 1_700_000_001, userId: USER_A, tenantId: TENANT_A },
		];
		const routed = events.map((event) => {
			const evaluation = evaluateStripeEvent({
				id: event.id,
				created: event.created,
				type: "customer.subscription.updated",
				data: { object: {
					id: `sub_${event.tenantId}`,
					customer: CUSTOMER_ID,
					status: "active",
					metadata: { user_id: event.userId, tenant_id: event.tenantId },
					items: { data: [] },
				} },
			});
			return {
				eventId: event.id,
				eventCreatedAt: evaluation.eventCreatedAt,
				linkage: selectStripeCustomerLinkage(mappings, {
					userId: evaluation.userId,
					tenantId: evaluation.tenantId,
				}).linkage,
			};
		});

		expect(routed.map(({ linkage }) => linkage?.tenantId)).toEqual([TENANT_B, TENANT_A, TENANT_A]);
		expect(Date.parse(routed[2].eventCreatedAt!)).toBeLessThan(Date.parse(routed[1].eventCreatedAt!));
	});

	it("does not guess when a shared customer has no tenant metadata", () => {
		expect(selectStripeCustomerLinkage(mappings).linkage).toBeNull();
		expect(selectStripeCustomerLinkage(mappings).ambiguous).toBe(true);
	});

	it("flags metadata that conflicts with every stored tenant binding", () => {
		expect(selectStripeCustomerLinkage(mappings, { userId: USER_B, tenantId: TENANT_B })).toMatchObject({
			linkage: null,
			conflict: true,
		});
	});

	it("allows a tenant binding to be created when the customer is only linked elsewhere", () => {
		expect(selectStripeCustomerLinkage([mappings[0]], { userId: USER_A, tenantId: TENANT_B })).toEqual({
			linkage: null,
			conflict: false,
			ambiguous: false,
		});
	});
});
