// @vitest-environment jsdom

// Reconciliation contract for approved enterprise orders (BIL-03 follow-through).
//
// The settlement ledger and the recorded finance approvals only mean something
// when they are read together: a settled settlement that matches no approved
// order must be marked unmatched, and a settlement that exceeds what Finance
// approved must be marked over limit. No price and no tax figure may be
// invented to fill a gap — an unrecorded figure is rendered as absent.

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn() } }));
vi.mock("../billing/enterprise-orders", () => ({
	listEnterpriseOrders: vi.fn(),
	requestEnterpriseOrder: vi.fn(),
	newBillingRequestId: vi.fn(() => "request_1234567890"),
}));
vi.mock("../billing/invoice-approvals", () => ({ listInvoiceApprovals: vi.fn() }));
vi.mock("../billing/billing-portal", () => ({
	loadBillingPortal: vi.fn(),
	projectedSeats: vi.fn(),
	requestSeats: vi.fn(),
	cancelSettlement: vi.fn(),
}));

import {
	loadBillingPortal,
	type PortalSettlement,
	projectedSeats,
	requestSeats,
} from "../billing/billing-portal";
import { listEnterpriseOrders } from "../billing/enterprise-orders";
import { type InvoiceApproval, listInvoiceApprovals } from "../billing/invoice-approvals";
import { type ReconciliationApproval, reconcileApprovedOrders } from "../billing/reconciliation";
import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { BillingPage } from "../ui/pages/BillingPage";

const tenantId = "11111111-1111-4111-8111-111111111111";
const ORDER_ID = "22222222-2222-4222-8222-222222222222";
const OVER_ORDER_ID = "33333333-3333-4333-8333-333333333333";
const SETTLEMENT = "44444444-4444-4444-8444-444444444444";
const OVER_SETTLEMENT = "55555555-5555-4555-8555-555555555555";
const ORPHAN_SETTLEMENT = "66666666-6666-4666-8666-666666666666";

/** An operator-recorded approval, exactly as the dashboard client returns it. */
function approval(overrides: Partial<InvoiceApproval> = {}): InvoiceApproval {
	return {
		orderId: ORDER_ID,
		tenantId,
		requestId: "order_request_1234567890ab",
		quoteReference: "QUOTE-2026-0001",
		status: "paid",
		approver: "finance.operator@example.invalid",
		amountMinor: 25000,
		currency: "USD",
		evidenceSha256: "a".repeat(64),
		agentsGranted: 25,
		approvedAt: "2026-09-13T02:00:00.000Z",
		...overrides,
	};
}

/** A settlement ledger row, exactly as the billing portal returns it. */
function settlement(overrides: Partial<PortalSettlement> = {}): PortalSettlement {
	return {
		settlementId: SETTLEMENT,
		requestId: "request_1234567890abcdef",
		provider: "provider_fixture",
		status: "settled",
		currency: "USD",
		lines: [{ sku: "aidr.agent.seat", quantity: 25, unitAmountMinor: 1000 }],
		totalAmountMinor: 25000,
		settledAmountMinor: 25000,
		refundedAmountMinor: 0,
		quoteReference: "QUOTE-2026-0001",
		occurredAt: "2026-09-13T00:00:00.000Z",
		sequence: 3,
		receiptHash: "b".repeat(64),
		externalValidation: false,
		...overrides,
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

beforeEach(() => {
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: tenantId },
		currentRole: "owner",
	} as ReturnType<typeof useTeam>);
	vi.mocked(supabase.from).mockImplementation(() => query() as never);
	vi.mocked(listEnterpriseOrders).mockResolvedValue([]);
	vi.mocked(listInvoiceApprovals).mockResolvedValue([]);
	vi.mocked(projectedSeats).mockReturnValue(null);
	vi.mocked(loadBillingPortal).mockResolvedValue({
		tenantId,
		settlements: [],
		projection: [],
		selfService: false,
	});
});

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
});

describe("approved-order reconciliation", () => {
	it("marks a settled settlement that matches no approved order as unmatched", () => {
		const rows = reconcileApprovedOrders({
			approvals: [approval()],
			settlements: [
				settlement(),
				settlement({ settlementId: ORPHAN_SETTLEMENT, quoteReference: "QUOTE-2026-9999" }),
			],
		});

		const matched = rows.find((row) => row.orderId === ORDER_ID);
		expect(matched).toMatchObject({
			kind: "approved_order",
			status: "matched",
			reason: "settled_settlement_matches_approved_order",
			settlementIds: [SETTLEMENT],
			settledSeats: 25,
			settledAmountMinor: 25000,
		});

		const orphan = rows.find((row) => row.settlementIds.includes(ORPHAN_SETTLEMENT));
		expect(orphan).toMatchObject({
			kind: "settlement",
			orderId: null,
			status: "unmatched",
			reason: "no_approved_order",
			approvedAgents: null,
			// Absent, not zero: no approval recorded an amount for this settlement.
			approvedAmountMinor: null,
			currency: "USD",
			settledSeats: 25,
		});
	});

	it("marks a settled settlement over the approved agent count or amount as over limit", () => {
		const overSeats = reconcileApprovedOrders({
			approvals: [approval()],
			settlements: [
				settlement({
					lines: [{ sku: "aidr.agent.seat", quantity: 30, unitAmountMinor: 1000 }],
					settledAmountMinor: 30000,
				}),
			],
		});
		expect(overSeats[0]).toMatchObject({
			status: "over_limit",
			reason: "settled_seats_exceed_approved_agents",
			settledSeats: 30,
		});

		const overAmount = reconcileApprovedOrders({
			approvals: [approval()],
			settlements: [settlement({ settledAmountMinor: 200000 })],
		});
		expect(overAmount[0]).toMatchObject({
			status: "over_limit",
			reason: "settled_amount_exceeds_approved_amount",
			settledAmountMinor: 200000,
		});
	});

	it("does not label under-settled approvals matched or double-claim duplicate quote references", () => {
		const partial = reconcileApprovedOrders({
			approvals: [approval()],
			settlements: [
				settlement({
					settledAmountMinor: 10000,
					lines: [{ sku: "aidr.agent.seat", quantity: 10, unitAmountMinor: 1000 }],
				}),
			],
		});
		expect(partial[0]).toMatchObject({
			status: "partial",
			reason: "settlement_below_approved_amount_or_agents",
		});

		const unrecordedSeats = reconcileApprovedOrders({
			approvals: [approval()],
			settlements: [
				settlement({
					lines: [{ sku: "aidr.audit.export", quantity: 1, unitAmountMinor: 25000 }],
				}),
			],
		});
		expect(unrecordedSeats[0]).toMatchObject({
			status: "partial",
			reason: "settled_seats_not_recorded",
			settledSeats: null,
		});

		const duplicate = reconcileApprovedOrders({
			approvals: [
				approval(),
				approval({ orderId: OVER_ORDER_ID, requestId: "order_request_0987654321ab" }),
			],
			settlements: [settlement()],
		});
		const approvalRows = duplicate.filter((row) => row.kind === "approved_order");
		expect(approvalRows).toHaveLength(2);
		expect(approvalRows.every((row) => row.status === "ambiguous")).toBe(true);
		expect(approvalRows.every((row) => row.settlementIds.length === 0)).toBe(true);
		expect(duplicate.find((row) => row.kind === "settlement")).toMatchObject({
			status: "unmatched",
			reason: "ambiguous_approved_order_quote_reference",
		});
	});

	it("never turns an unrecorded approved figure into zero", () => {
		// A partial record is representable in the type even though the Edge
		// route refuses to write one; it must stay absent rather than become 0.
		const incomplete: ReconciliationApproval = {
			orderId: ORDER_ID,
			requestId: "order_request_1234567890ab",
			quoteReference: null,
			status: "paid",
			approver: "finance.operator@example.invalid",
			amountMinor: null,
			currency: null,
			evidenceSha256: null,
			agentsGranted: null,
			approvedAt: "2026-09-13T02:00:00.000Z",
		};
		const rows = reconcileApprovedOrders({
			approvals: [incomplete],
			settlements: [settlement()],
		});
		expect(rows[0]).toMatchObject({
			approvedAmountMinor: null,
			approvedAgents: null,
			status: "unmatched",
			reason: "approved_order_without_quote_reference",
		});
	});

	it("ignores settlements that are not settled and keeps the latest settled row", () => {
		const rows = reconcileApprovedOrders({
			approvals: [approval()],
			settlements: [
				settlement({ sequence: 2, settledAmountMinor: 1000 }),
				settlement({ sequence: 3, settledAmountMinor: 25000 }),
				settlement({
					settlementId: ORPHAN_SETTLEMENT,
					quoteReference: "QUOTE-2026-9999",
					status: "refunded",
				}),
			],
		});
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({ status: "matched", settledAmountMinor: 25000 });
	});

	it.each(["cancelled", "refunded"] as const)("does not match an approval to a later %s receipt", (status) => {
		const rows = reconcileApprovedOrders({
			approvals: [approval()],
			settlements: [
				settlement({ sequence: 3, status: "settled" }),
				settlement({ sequence: 4, status }),
			],
		});
		expect(rows).toHaveLength(1);
		expect(rows[0]).toMatchObject({
			status: "unmatched",
			reason: "no_settled_settlement",
			settlementIds: [],
		});
	});
});

describe("billing reconciliation table", () => {
	it("offers only the persisted exact retry when provider read-back is indeterminate", async () => {
		vi.mocked(loadBillingPortal).mockResolvedValue({
			tenantId,
			settlements: [],
			projection: [],
			selfService: true,
		});
		const recovery = Object.assign(new Error("recovery required"), {
			name: "BillingRecoveryError",
			requestId: "original_1234567890",
			action: "request_seats",
			detail: {
				recovery_payload: {
					provider: "stripe",
					subscription_id: "sub_live_1",
					seats: 5,
					sku: "aidr.agent.seat",
				},
			},
		});
		vi.mocked(requestSeats)
			.mockRejectedValueOnce(recovery)
			.mockResolvedValueOnce({ providerQuantity: 5, action: "noop", delta: 0 });

		render(<BillingPage />);
		const input = await screen.findByLabelText("Requested seats");
		fireEvent.change(input, { target: { value: "6" } });
		fireEvent.click(screen.getByRole("button", { name: "Apply seat change" }));

		const retry = await screen.findByRole("button", {
			name: "Retry original request: 5 seats",
		});
		expect(
			screen.getByText(/Only its exact persisted request can be retried safely/),
		).toBeInTheDocument();
		fireEvent.click(retry);

		await waitFor(() => expect(requestSeats).toHaveBeenCalledTimes(2));
		expect(vi.mocked(requestSeats).mock.calls[1]).toEqual([
			tenantId,
			"original_1234567890",
			5,
			"aidr.agent.seat",
		]);
		await waitFor(() =>
			expect(
				screen.queryByRole("button", { name: /Retry original request/ }),
			).not.toBeInTheDocument(),
		);
	});

	it("renders matched, over-limit and unmatched rows and shows absent figures as not recorded", async () => {
		vi.mocked(listInvoiceApprovals).mockResolvedValue([
			approval(),
			approval({
				orderId: OVER_ORDER_ID,
				quoteReference: "QUOTE-2026-0002",
				agentsGranted: 10,
				requestId: "order_request_0987654321ab",
			}),
		]);
		vi.mocked(loadBillingPortal).mockResolvedValue({
			tenantId,
			settlements: [
				settlement(),
				settlement({
					settlementId: OVER_SETTLEMENT,
					quoteReference: "QUOTE-2026-0002",
					lines: [{ sku: "aidr.agent.seat", quantity: 12, unitAmountMinor: 1000 }],
					settledAmountMinor: 12000,
				}),
				settlement({ settlementId: ORPHAN_SETTLEMENT, quoteReference: "QUOTE-2026-9999" }),
			],
			projection: [],
			selfService: false,
		});

		render(<BillingPage />);

		const table = await screen.findByRole("table", { name: "Approved order reconciliation" });
		expect(table).toBeInTheDocument();
		await waitFor(() => expect(screen.getAllByText("Matched").length).toBe(1));
		expect(screen.getAllByText("Over limit").length).toBe(1);
		expect(screen.getAllByText("Unmatched").length).toBe(1);
		expect(screen.getByText("settled_seats_exceed_approved_agents")).toBeInTheDocument();
		expect(screen.getByText("no_approved_order")).toBeInTheDocument();
		expect(screen.getByText("No approved order")).toBeInTheDocument();
		expect(screen.getByText("QUOTE-2026-9999")).toBeInTheDocument();

		// The orphan row has no recorded approved amount and no recorded tax
		// figure. Both are rendered as explicitly absent, never as zero.
		expect(screen.getAllByText("Not recorded").length).toBeGreaterThanOrEqual(4);
		expect(screen.queryByText("USD 0.00")).not.toBeInTheDocument();
		expect(screen.getByText(/No tax rate and no catalogue price/)).toBeInTheDocument();
	});

	it("renders unavailable, never an empty reconciliation, when approvals cannot be read", async () => {
		vi.mocked(listInvoiceApprovals).mockRejectedValue(new Error("unavailable"));
		vi.mocked(loadBillingPortal).mockResolvedValue({
			tenantId,
			settlements: [settlement()],
			projection: [],
			selfService: false,
		});

		render(<BillingPage />);

		await waitFor(() =>
			expect(
				screen.getByText(/Reconciliation is unavailable: the recorded finance approvals/),
			).toBeInTheDocument(),
		);
		expect(
			screen.queryByRole("table", { name: "Approved order reconciliation" }),
		).not.toBeInTheDocument();
	});
});
