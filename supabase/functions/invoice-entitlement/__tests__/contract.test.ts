import { describe, expect, it } from "vitest";
import { parseInvoiceOrderRequest, parseTenantId, projectInvoiceOrder, projectRequestedInvoiceOrder } from "../contract.ts";

const request = {
	request_id: "order_request_12345",
	requested_agents: 125,
	quote_reference: "Q-2026-99",
};
const tenantId = "12345678-1234-1234-1234-123456789abc";
const row = {
	id: "87654321-4321-4321-4321-cba987654321",
	tenant_id: tenantId,
	request_id: request.request_id,
	requested_agents: request.requested_agents,
	quote_reference: request.quote_reference,
	status: "pending_finance",
	created_at: "2026-09-13T00:00:00.000Z",
	updated_at: "2026-09-13T00:00:00.000Z",
};

describe("invoice-only order intake contract", () => {
	it("requires an explicit tenant identifier", () => {
		expect(parseTenantId("12345678-1234-1234-1234-123456789abc")).toBe("12345678-1234-1234-1234-123456789abc");
		for (const tenant of [null, "", "alice", "12345678-1234-1234-1234-123456789abc/other"] as const) {
			expect(() => parseTenantId(tenant)).toThrow("invalid_tenant_id");
		}
	});

	it("accepts only quantity, idempotency key and optional quote reference", () => {
		expect(parseInvoiceOrderRequest(request)).toEqual({
			requestId: request.request_id,
			requestedAgents: 125,
			quoteReference: "Q-2026-99",
		});
		expect(parseInvoiceOrderRequest({ ...request, quote_reference: "  Q-2026-99  " }).quoteReference).toBe("Q-2026-99");
		expect(parseInvoiceOrderRequest({ ...request, quote_reference: "  " }).quoteReference).toBeNull();
	});

	it("rejects caller supplied payment, status and entitlement fields", () => {
		for (const extra of [
			{ status: "paid_verified" }, { invoice_reference: "INV-1" },
			{ paid: true }, { entitlement: { included_agents: 5000 } },
		]) {
			expect(() => parseInvoiceOrderRequest({ ...request, ...extra })).toThrow("unsupported_invoice_order_field");
		}
	});

	it("rejects invalid quantities, request ids, control characters and overlong references", () => {
		for (const agents of [0, -1, 100001, 1.5, "125", Number.NaN]) {
			expect(() => parseInvoiceOrderRequest({ ...request, requested_agents: agents })).toThrow("invalid_requested_agents");
		}
		for (const id of ["short", "a".repeat(81), "order/1234567890123456"]) {
			expect(() => parseInvoiceOrderRequest({ ...request, request_id: id })).toThrow("invalid_request_id");
		}
		for (const quote of ["Q-1\nX", "\tQ-1", "x".repeat(121), 1]) {
			expect(() => parseInvoiceOrderRequest({ ...request, quote_reference: quote })).toThrow("invalid_quote_reference");
		}
	});

	it("projects only a well-formed pending order for the authenticated tenant", () => {
		expect(projectInvoiceOrder({ ...row, secret_internal_note: "never return" }, tenantId)).toEqual(row);
		for (const invalid of [
			{ ...row, tenant_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
			{ ...row, status: "paid_verified" },
			{ ...row, requested_agents: "125" },
			{ ...row, created_at: "nonsense" },
		]) expect(projectInvoiceOrder(invalid, tenantId)).toBeNull();
	});

	it("accepts a POST result only when it matches the requested order", () => {
		const parsed = parseInvoiceOrderRequest(request);
		expect(projectRequestedInvoiceOrder(row, tenantId, parsed)).toEqual(row);
		for (const mismatch of [
			{ ...row, request_id: "different_request_12345" },
			{ ...row, requested_agents: 126 },
			{ ...row, quote_reference: "Q-2026-100" },
			{ ...row, quote_reference: null },
			{ ...row, tenant_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
			{ ...row, status: "paid_verified" },
		]) expect(projectRequestedInvoiceOrder(mismatch, tenantId, parsed)).toBeNull();
	});
});
