import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));

import { cancelSettlement, loadBillingPortal, projectedSeats } from "../billing/billing-portal";
import { supabase } from "../lib/supabase";

const tenantId = "11111111-1111-4111-8111-111111111111";
const settlementId = "22222222-2222-4222-8222-222222222222";

function response(overrides: Record<string, unknown> = {}) {
	return {
		ok: true,
		tenant_id: tenantId,
		settlements: [
			{
				settlementId,
				tenantId,
				requestId: "portal_request_123456",
				provider: "provider_fixture",
				status: "settled",
				currency: "USD",
				lines: [{ sku: "aidr.agent.seat", quantity: 2, unitAmountMinor: 1000 }],
				totalAmountMinor: 2000,
				settledAmountMinor: 2000,
				refundedAmountMinor: 0,
				quoteReference: "QUOTE-1",
				occurredAt: "2026-09-23T08:00:00.000Z",
				sequence: 1,
				receiptHash: "a".repeat(64),
				externalValidation: false,
			},
		],
		projection: [{ sku: "aidr.agent.seat", seats: 2, sources: [settlementId] }],
		self_service: true,
		...overrides,
	};
}

function setPortalResponse(body: unknown) {
	vi.mocked(supabase.functions.invoke).mockResolvedValue({ data: body, error: null } as never);
}

afterEach(() => vi.clearAllMocks());

describe("billing portal dashboard contract", () => {
	it("accepts a complete tenant-bound settlement response", async () => {
		setPortalResponse(response());

		const snapshot = await loadBillingPortal(tenantId);

		expect(snapshot.tenantId).toBe(tenantId);
		expect(snapshot.settlements[0]).toMatchObject({
			settlementId,
			settledAmountMinor: 2000,
			lines: [{ sku: "aidr.agent.seat", quantity: 2 }],
		});
		expect(projectedSeats(snapshot)).toBe(2);
	});

	it("rejects malformed settlement amounts instead of coercing them", async () => {
		setPortalResponse(
			response({
				settlements: [
					{
						...(response().settlements as Array<Record<string, unknown>>)[0],
						settledAmountMinor: "unknown",
					},
				],
			}),
		);

		await expect(loadBillingPortal(tenantId)).rejects.toThrow(
			"Invalid billing settlement response",
		);
	});

	it("keeps cancellation reconciliation pending explicit to the caller", async () => {
		vi.mocked(supabase.functions.invoke).mockResolvedValue({
			data: { error: "billing_reconciliation_pending", recovery_action: "cancel" },
			error: new Error("Function returned an error"),
		} as never);

		await expect(cancelSettlement(tenantId, "cancel_request_123456", settlementId)).rejects.toThrow(
			"Cancellation reconciliation is pending",
		);
	});

	it("rejects an invalid projection and leaves seats unknown when no settled projection exists", async () => {
		setPortalResponse(
			response({ projection: [{ sku: "aidr.agent.seat", seats: -1, sources: [] }] }),
		);
		await expect(loadBillingPortal(tenantId)).rejects.toThrow(
			"Invalid billing projection response",
		);

		setPortalResponse(
			response({
				settlements: [
					{
						...(response().settlements as Array<Record<string, unknown>>)[0],
						status: "quote_issued",
						settledAmountMinor: 0,
						sequence: 2,
					},
				],
				projection: [],
			}),
		);
		const snapshot = await loadBillingPortal(tenantId);
		expect(projectedSeats(snapshot)).toBeNull();
	});
});
