// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn(), functions: { invoke: vi.fn() } } }));
vi.mock("../billing/enterprise-orders", () => ({
	listEnterpriseOrders: vi.fn(),
	requestEnterpriseOrder: vi.fn(),
	newBillingRequestId: vi.fn(() => "request_1234567890abcdef"),
}));
vi.mock("../billing/invoice-approvals", () => ({ listInvoiceApprovals: vi.fn() }));
vi.mock("../billing/billing-portal", () => ({
	loadBillingPortal: vi.fn(),
	projectedSeats: vi.fn((snapshot) => snapshot.projection[0]?.seats ?? null),
	requestSeats: vi.fn(),
	cancelSettlement: vi.fn(),
}));

import { loadBillingPortal, type PortalSnapshot, requestSeats } from "../billing/billing-portal";
import { listEnterpriseOrders } from "../billing/enterprise-orders";
import { listInvoiceApprovals } from "../billing/invoice-approvals";
import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { BillingPage } from "../ui/pages/BillingPage";

const tenantA = "11111111-1111-4111-8111-111111111111";
const tenantB = "22222222-2222-4222-8222-222222222222";

function snapshot(
	tenantId: string,
	settlements: PortalSnapshot["settlements"] = [],
): PortalSnapshot {
	return { tenantId, settlements, projection: [], selfService: true };
}

function settledRow(
	settlementId: string,
	quoteReference: string,
): PortalSnapshot["settlements"][number] {
	return {
		settlementId,
		requestId: "portal_request_123456",
		provider: "provider_fixture",
		status: "settled",
		currency: "USD",
		lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
		totalAmountMinor: 1000,
		settledAmountMinor: 1000,
		refundedAmountMinor: 0,
		quoteReference,
		occurredAt: "2026-09-23T08:00:00.000Z",
		sequence: 1,
		receiptHash: "a".repeat(64),
		externalValidation: false,
	};
}

function query() {
	const chain = {
		select: vi.fn(),
		eq: vi.fn(),
		order: vi.fn(),
		limit: vi.fn(),
		maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
	};
	for (const method of ["select", "eq", "order", "limit"] as const)
		chain[method].mockReturnValue(chain);
	return chain;
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

beforeEach(() => {
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: tenantA },
		currentRole: "owner",
	} as never);
	vi.mocked(supabase.from).mockImplementation(() => query() as never);
	vi.mocked(listEnterpriseOrders).mockResolvedValue([]);
	vi.mocked(listInvoiceApprovals).mockResolvedValue([]);
	vi.mocked(requestSeats).mockResolvedValue({ providerQuantity: 1, action: "grant", delta: 1 });
	vi.mocked(loadBillingPortal).mockReset();
});

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
});

describe("billing portal tenant isolation", () => {
	it("does not render a prior tenant snapshot when an action refresh resolves after a team switch", async () => {
		const lateRefresh = deferred<PortalSnapshot>();
		vi.mocked(loadBillingPortal)
			.mockResolvedValueOnce(snapshot(tenantA))
			.mockImplementationOnce(() => lateRefresh.promise)
			.mockResolvedValueOnce(
				snapshot(tenantB, [settledRow("33333333-3333-4333-8333-333333333333", "TENANT-B-QUOTE")]),
			);

		const page = render(<BillingPage />);
		await screen.findByLabelText("Requested seats");
		fireEvent.click(screen.getByRole("button", { name: "Apply seat change" }));
		await waitFor(() => expect(loadBillingPortal).toHaveBeenCalledTimes(2));

		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantB },
			currentRole: "owner",
		} as never);
		page.rerender(<BillingPage />);
		await screen.findByText("TENANT-B-QUOTE");

		await act(async () => {
			lateRefresh.resolve(
				snapshot(tenantA, [
					settledRow("44444444-4444-4444-8444-444444444444", "TENANT-A-PRIVATE-QUOTE"),
				]),
			);
		});

		expect(screen.getByText("TENANT-B-QUOTE")).toBeInTheDocument();
		expect(screen.queryByText("TENANT-A-PRIVATE-QUOTE")).not.toBeInTheDocument();
	});
});
