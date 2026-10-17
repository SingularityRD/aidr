// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn() } }));
vi.mock("../billing/enterprise-orders", () => ({
	listEnterpriseOrders: vi.fn(),
	requestEnterpriseOrder: vi.fn(),
	newBillingRequestId: vi.fn(() => "request_1234567890abcdef"),
}));
vi.mock("../billing/invoice-approvals", () => ({ listInvoiceApprovals: vi.fn() }));
vi.mock("../billing/billing-portal", () => ({
	loadBillingPortal: vi.fn(),
	projectedSeats: vi.fn(() => 1),
	requestSeats: vi.fn(),
	cancelSettlement: vi.fn(),
}));

import {
	cancelSettlement,
	loadBillingPortal,
	type PortalSnapshot,
	requestSeats,
} from "../billing/billing-portal";
import { listEnterpriseOrders } from "../billing/enterprise-orders";
import { listInvoiceApprovals } from "../billing/invoice-approvals";
import { useTeam } from "../enterprise/team-provider";
import { I18nProvider } from "../i18n/I18nProvider";
import { supabase } from "../lib/supabase";
import { BillingPage } from "../ui/pages/BillingPage";

const tenantId = "11111111-1111-4111-8111-111111111111";
const settlementId = "22222222-2222-4222-8222-222222222222";
const settled: PortalSnapshot["settlements"][number] = {
	settlementId,
	requestId: "original_1234567890",
	provider: "stripe",
	status: "settled",
	currency: "USD",
	lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
	totalAmountMinor: 1000,
	settledAmountMinor: 1000,
	refundedAmountMinor: 0,
	quoteReference: null,
	occurredAt: "2026-09-23T08:00:00.000Z",
	sequence: 1,
	receiptHash: "a".repeat(64),
	externalValidation: false,
};

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
	} as never);
	vi.mocked(supabase.from).mockImplementation(() => query() as never);
	vi.mocked(listEnterpriseOrders).mockResolvedValue([]);
	vi.mocked(listInvoiceApprovals).mockResolvedValue([]);
	vi.mocked(loadBillingPortal).mockResolvedValue({
		tenantId,
		settlements: [settled],
		projection: [],
		selfService: true,
	});
});
afterEach(() => {
	cleanup();
	vi.clearAllMocks();
	vi.unstubAllEnvs();
});

describe("billing portal actions", () => {
	it.each([
		{ name: "missing", row: null },
		{
			name: "malformed",
			row: { included_agents: 1, extra_agents: "2", allowed_agents: 3, current_agents: 0 },
		},
		{
			name: "inconsistent",
			row: { included_agents: 1, extra_agents: 2, allowed_agents: 4, current_agents: 0 },
		},
	])("shows unavailable instead of invented seat counts for a $name view row", async ({ row }) => {
		vi.mocked(supabase.from).mockImplementation((table) => {
			const chain = query();
			if (String(table) === "seat_usage")
				chain.maybeSingle.mockResolvedValue({ data: row, error: null });
			return chain as never;
		});
		render(<BillingPage />);
		for (const label of ["Included", "Extra", "Allowed", "Connected"])
			expect(screen.getByText(label).parentElement).toHaveTextContent("Unavailable");
		await screen.findByText(/Seat usage is unavailable for this tenant/);
		for (const label of ["Included", "Extra", "Allowed", "Connected"])
			expect(screen.getByText(label).parentElement).toHaveTextContent("Unavailable");
	});

	it("does not invent a legacy entitlement if the seat view is absent", async () => {
		vi.mocked(supabase.from).mockImplementation((table) => {
			const chain = query();
			if (String(table) === "seat_usage")
				chain.maybeSingle.mockResolvedValue({
					data: null,
					error: { code: "42P01", message: "seat_usage missing" },
				});
			return chain as never;
		});
		render(<BillingPage />);
		await screen.findByText(/Failed to load seat usage/);
		for (const label of ["Included", "Extra", "Allowed", "Connected"])
			expect(screen.getByText(label).parentElement).toHaveTextContent("Unavailable");
		expect(supabase.from).not.toHaveBeenCalledWith("entitlements");
		expect(supabase.from).not.toHaveBeenCalledWith("agents");
	});

	it.each([
		["expired", "2020-01-01T00:00:00Z"],
		["missing", null],
	])(
		"labels %s provider quantity separately from the effective seat allowance",
		async (_case, periodEnd) => {
			vi.mocked(supabase.from).mockImplementation((table) => {
				const chain = query();
				if (String(table) === "seat_usage")
					chain.maybeSingle.mockResolvedValue({
						data: { included_agents: 1, extra_agents: 0, allowed_agents: 1, current_agents: 1 },
						error: null,
					});
				if (String(table) === "subscriptions")
					chain.maybeSingle.mockResolvedValue({
						data: {
							provider: "stripe",
							provider_subscription_id: "sub_expired",
							status: "active",
							extra_agents: 5,
							current_period_end: periodEnd,
							cancel_at_period_end: false,
							updated_at: "2026-09-23T00:00:00Z",
						},
						error: null,
					});
				return chain as never;
			});
			render(<BillingPage />);
			await waitFor(() =>
				expect(screen.getByText("Recorded extra agents").parentElement).toHaveTextContent("5"),
			);
			expect(screen.getByText("Extra").parentElement).toHaveTextContent("0");
			expect(screen.getByText("Allowed").parentElement).toHaveTextContent("1");
			expect(screen.getByText("Term expired or unverified")).toBeInTheDocument();
			expect(screen.getByText(/not included in the effective allowance/)).toBeInTheDocument();
			expect(screen.getByText(/not the current effective seat allowance/)).toBeInTheDocument();
		},
	);

	it("waits for the order ledger before allowing a Finance request", async () => {
		vi.stubEnv("VITE_SALES_EMAIL", "sales@example.com");
		let finishRead: ((orders: []) => void) | undefined;
		vi.mocked(listEnterpriseOrders).mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					finishRead = resolve;
				}),
		);
		render(<BillingPage />);
		const submit = screen.getByRole("button", { name: "Submit for Finance review" });
		expect(submit).toBeDisabled();
		await act(async () => finishRead?.([]));
		expect(submit).toBeEnabled();
	});

	it("keeps Finance submission closed when existing orders cannot be read", async () => {
		vi.stubEnv("VITE_SALES_EMAIL", "sales@example.com");
		vi.mocked(listEnterpriseOrders).mockRejectedValueOnce(new Error("ledger unavailable"));
		render(<BillingPage />);
		await screen.findByText(/Enterprise order status is unavailable/);
		expect(screen.getByRole("button", { name: "Submit for Finance review" })).toBeDisabled();
	});

	it("allows only the exact retry while a provider write needs recovery", async () => {
		const recovery = Object.assign(new Error("recovery required"), {
			name: "BillingRecoveryError",
			requestId: "original_1234567890",
			action: "request_seats",
			detail: { recovery_payload: { seats: 5, sku: "aidr.agent.seat" } },
		});
		vi.mocked(requestSeats).mockRejectedValueOnce(recovery);
		render(<BillingPage />);
		fireEvent.click(await screen.findByRole("button", { name: "Apply seat change" }));
		const retry = await screen.findByRole("button", { name: "Retry original request: 5 seats" });
		expect(retry).toBeEnabled();
		expect(screen.getByRole("button", { name: "Apply seat change" })).toBeDisabled();
		expect(screen.getByRole("button", { name: "Cancel subscription" })).toBeDisabled();
		fireEvent.click(screen.getByRole("button", { name: "Apply seat change" }));
		fireEvent.click(screen.getByRole("button", { name: "Cancel subscription" }));
		expect(requestSeats).toHaveBeenCalledTimes(1);
		expect(cancelSettlement).not.toHaveBeenCalled();
	});

	it("does not offer cancellation when the server disables self-service billing", async () => {
		vi.mocked(loadBillingPortal).mockResolvedValue({
			tenantId,
			settlements: [settled],
			projection: [],
			selfService: false,
		});
		render(<BillingPage />);
		await waitFor(() => expect(loadBillingPortal).toHaveBeenCalled());
		await screen.findByText(/Self-service billing is not enabled/);
		expect(screen.queryByRole("button", { name: "Cancel subscription" })).not.toBeInTheDocument();
	});

	it("retries the original cancellation without permitting a new seat change", async () => {
		const recovery = Object.assign(new Error("recovery required"), {
			name: "BillingRecoveryError",
			requestId: "original_cancel_123456",
			action: "cancel",
			detail: { recovery_payload: { settlement_id: settlementId } },
		});
		vi.mocked(cancelSettlement).mockRejectedValueOnce(recovery).mockResolvedValueOnce(undefined);
		render(<BillingPage />);
		fireEvent.click(await screen.findByRole("button", { name: "Cancel subscription" }));
		const retry = await screen.findByRole("button", { name: "Retry original cancellation" });
		expect(screen.getByRole("button", { name: "Apply seat change" })).toBeDisabled();
		fireEvent.click(retry);
		await waitFor(() => expect(cancelSettlement).toHaveBeenCalledTimes(2));
		expect(vi.mocked(cancelSettlement).mock.calls[1]).toEqual([
			tenantId,
			"original_cancel_123456",
			settlementId,
		]);
		expect(requestSeats).not.toHaveBeenCalled();
	});

	it("keeps the provider result but closes actions if the ledger refresh fails", async () => {
		vi.mocked(loadBillingPortal)
			.mockResolvedValueOnce({
				tenantId,
				settlements: [settled],
				projection: [],
				selfService: true,
			})
			.mockRejectedValueOnce(new Error("ledger unavailable"));
		vi.mocked(requestSeats).mockResolvedValue({ providerQuantity: 5, action: "grant", delta: 4 });
		render(<BillingPage />);
		fireEvent.click(await screen.findByRole("button", { name: "Apply seat change" }));
		await waitFor(() => expect(loadBillingPortal).toHaveBeenCalledTimes(2));
		expect(screen.getByText(/Provider now reports 5 seats/)).toBeInTheDocument();
		expect(screen.getByLabelText("Subscription portal error")).toHaveTextContent(
			/settlement ledger could not be refreshed/i,
		);
		expect(screen.queryByRole("button", { name: "Apply seat change" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Cancel subscription" })).not.toBeInTheDocument();
		expect(screen.queryByText(/No settlement is on record/)).not.toBeInTheDocument();
	});
});

describe("billing portal errors follow the console language", () => {
	it("shows the Turkish unavailable notice instead of the client's English error", async () => {
		vi.mocked(loadBillingPortal).mockRejectedValue(
			new Error("The billing portal is unavailable for this tenant"),
		);
		render(
			<I18nProvider initialLocale="tr">
				<BillingPage />
			</I18nProvider>,
		);
		await screen.findByText("Faturalandırma portalı kullanılamıyor");
		expect(screen.queryByText(/unavailable for this tenant/)).not.toBeInTheDocument();
	});
});
