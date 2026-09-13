import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: { functions: { invoke: vi.fn() } },
}));

import {
	listEnterpriseOrders,
	newBillingRequestId,
	requestEnterpriseOrder,
} from "../billing/enterprise-orders";
import { convertCurrency, getPaymentProvider, getRegionConfig } from "../billing/payment-router";
import { buildProviderList } from "../billing/provider-selector";
import { supabase } from "../lib/supabase";

const tenantId = "11111111-1111-4111-8111-111111111111";
const order = {
	id: "22222222-2222-4222-8222-222222222222",
	tenant_id: tenantId,
	request_id: "request_1234567890",
	requested_agents: 25,
	quote_reference: "Q-2026-001",
	status: "pending_finance",
	created_at: "2026-09-13T10:00:00.000Z",
	updated_at: "2026-09-13T10:00:00.000Z",
};
const invoke = supabase.functions.invoke as ReturnType<typeof vi.fn>;

beforeEach(() => invoke.mockReset());

describe("enterprise order client contract", () => {
	it("creates an idempotency key without relying only on randomUUID", () => {
		expect(newBillingRequestId()).toMatch(/^[a-zA-Z0-9_-]{16,80}$/);
	});

	it("submits a tenant-bound, retry-stable request without claiming payment or entitlement", async () => {
		invoke.mockResolvedValue({ data: { ok: true, order }, error: null });
		const request = {
			request_id: order.request_id,
			requested_agents: 25,
			quote_reference: " Q-2026-001 ",
		};
		expect(await requestEnterpriseOrder(tenantId, request)).toEqual(order);
		expect(await requestEnterpriseOrder(tenantId, request)).toEqual(order);
		expect(invoke).toHaveBeenNthCalledWith(1, "invoice-entitlement", {
			method: "POST",
			headers: { "X-AIDR-Tenant-ID": tenantId },
			body: { request_id: order.request_id, requested_agents: 25, quote_reference: "Q-2026-001" },
		});
		expect(invoke.mock.calls[1]?.[1]?.body.request_id).toBe(order.request_id);
	});

	it("rejects invalid quantity and conflicting tenant response before showing an order", async () => {
		await expect(
			requestEnterpriseOrder(tenantId, { request_id: order.request_id, requested_agents: 0 }),
		).rejects.toThrow(/agent count/i);
		expect(invoke).not.toHaveBeenCalled();
		invoke.mockResolvedValue({
			data: { ok: true, order: { ...order, tenant_id: "33333333-3333-4333-8333-333333333333" } },
			error: null,
		});
		await expect(
			requestEnterpriseOrder(tenantId, { request_id: order.request_id, requested_agents: 25 }),
		).rejects.toThrow(/invalid enterprise order response/i);
	});

	it("rejects a create response that claims a verified payment", async () => {
		invoke.mockResolvedValue({
			data: { ok: true, order: { ...order, status: "paid_verified" } },
			error: null,
		});
		await expect(
			requestEnterpriseOrder(tenantId, { request_id: order.request_id, requested_agents: 25 }),
		).rejects.toThrow(/unexpected enterprise order status/i);
	});

	it("loads only tenant-bound, well-formed records and fails closed on unavailable ledger", async () => {
		invoke.mockResolvedValueOnce({ data: { ok: true, orders: [order] }, error: null });
		expect(await listEnterpriseOrders(tenantId)).toEqual([order]);
		expect(invoke).toHaveBeenCalledWith("invoice-entitlement", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": tenantId },
		});
		invoke.mockResolvedValueOnce({ data: {}, error: null });
		await expect(listEnterpriseOrders(tenantId)).rejects.toThrow(/unavailable/i);
		invoke.mockResolvedValueOnce({
			data: { ok: true, orders: [{ ...order, requested_agents: -1 }] },
			error: null,
		});
		await expect(listEnterpriseOrders(tenantId)).rejects.toThrow(
			/invalid enterprise order response/i,
		);
	});
});

describe("browser billing safety", () => {
	it("never fabricates an empty invoice ledger or an exchange-rate quote", async () => {
		await expect(getPaymentProvider().getInvoices("user")).rejects.toThrow(
			/server-side finance reconciliation/i,
		);
		await expect(convertCurrency(10, "USD", "EUR")).rejects.toThrow(/approved enterprise quote/i);
		await expect(convertCurrency(Number.NaN, "USD", "USD")).rejects.toThrow(
			/invalid commercial amount/i,
		);
		expect(await convertCurrency(10, "USD", "USD")).toBe(10);
		expect(invoke).not.toHaveBeenCalled();
	});

	it("does not advertise the unimplemented Stripe customer portal", () => {
		expect(getRegionConfig().features).not.toContain("Customer Portal");
		expect(JSON.stringify(buildProviderList("US"))).not.toContain("Customer Portal");
	});
});
