// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn() } }));
vi.mock("../billing/enterprise-orders", () => ({
	listEnterpriseOrders: vi.fn(),
	requestEnterpriseOrder: vi.fn(),
	newBillingRequestId: vi.fn(() => "request_1234567890"),
}));

import { listEnterpriseOrders, requestEnterpriseOrder } from "../billing/enterprise-orders";
import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { BillingPage } from "../ui/pages/BillingPage";

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
	vi.stubEnv("VITE_SALES_EMAIL", "sales@example.com");
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: tenantId },
		currentRole: "owner",
	} as ReturnType<typeof useTeam>);
	vi.mocked(supabase.from).mockImplementation(() => query() as never);
	vi.mocked(listEnterpriseOrders).mockResolvedValue([]);
	vi.mocked(requestEnterpriseOrder).mockResolvedValue(order);
});
afterEach(() => {
	cleanup();
	vi.clearAllMocks();
	vi.unstubAllEnvs();
	vi.useRealTimers();
});

describe("enterprise billing page", () => {
	it.each(["PGRST205", "42P01"])(
		"does not use stale entitlements when the seat view is unavailable (%s)",
		async (code) => {
			vi.mocked(supabase.from).mockImplementation((table) => {
				const tableName = String(table);
				const chain = query();
				if (tableName === "seat_usage")
					chain.maybeSingle.mockResolvedValue({
						data: null,
						error: { code, message: "seat_usage missing" },
					});
				return chain as never;
			});
			render(<BillingPage />);
			await waitFor(() =>
				expect(screen.getByRole("alert")).toHaveTextContent("Failed to load seat usage"),
			);
			for (const label of ["Included", "Extra", "Allowed", "Connected"])
				expect(screen.getByText(label).parentElement).toHaveTextContent("Unavailable");
			expect(supabase.from).not.toHaveBeenCalledWith("entitlements");
			expect(supabase.from).not.toHaveBeenCalledWith("agents");
		},
	);

	it("submits a pending Finance request without changing the displayed entitlement", async () => {
		render(<BillingPage />);
		await waitFor(() => expect(listEnterpriseOrders).toHaveBeenCalledWith(tenantId));
		fireEvent.change(screen.getByLabelText("Requested protected agents"), {
			target: { value: "25" },
		});
		fireEvent.change(screen.getByLabelText("Quote reference (optional)"), {
			target: { value: "Q-2026-001" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Submit for Finance review" }));
		await waitFor(() =>
			expect(requestEnterpriseOrder).toHaveBeenCalledWith(tenantId, {
				request_id: "request_1234567890",
				requested_agents: 25,
				quote_reference: "Q-2026-001",
			}),
		);
		await waitFor(() => expect(screen.getByText(/25 protected agents/)).toBeInTheDocument());
		expect(screen.getByText(/A request enters Finance review/)).toBeInTheDocument();
		expect(screen.getByText("Request pending Finance review")).toBeDisabled();
		expect(screen.getByText("Allowed").parentElement).toHaveTextContent("Unavailable");
	});

	it("reuses the request ID after a failed submission", async () => {
		vi.mocked(requestEnterpriseOrder).mockRejectedValueOnce(new Error("network"));
		render(<BillingPage />);
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Submit for Finance review" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Submit for Finance review" }));
		await screen.findByText(/Enterprise order request was not accepted/i);
		fireEvent.click(screen.getByRole("button", { name: "Submit for Finance review" }));
		await waitFor(() => expect(requestEnterpriseOrder).toHaveBeenCalledTimes(2));
		expect(vi.mocked(requestEnterpriseOrder).mock.calls[0]?.[1]?.request_id).toBe(
			vi.mocked(requestEnterpriseOrder).mock.calls[1]?.[1]?.request_id,
		);
	});

	it("keeps a newly submitted order when an older list response arrives late", async () => {
		vi.useFakeTimers();
		let finishOldRead: ((rows: (typeof order)[]) => void) | undefined;
		vi.mocked(listEnterpriseOrders)
			.mockResolvedValueOnce([])
			.mockImplementationOnce(
				() =>
					new Promise((resolve) => {
						finishOldRead = resolve;
					}),
			);
		await act(async () => {
			render(<BillingPage />);
		});
		expect(screen.getByRole("button", { name: "Submit for Finance review" })).toBeEnabled();
		await act(async () => {
			vi.advanceTimersByTime(30_000);
		});
		expect(listEnterpriseOrders).toHaveBeenCalledTimes(2);
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Submit for Finance review" }));
		});
		expect(screen.getByText(/25 protected agents/)).toBeInTheDocument();
		await act(async () => finishOldRead?.([]));
		expect(screen.getByText(/25 protected agents/)).toBeInTheDocument();
	});

	it("does not let a poll started during submission erase the accepted request", async () => {
		vi.useFakeTimers();
		let finishOrder: ((row: typeof order) => void) | undefined;
		let finishPoll: ((rows: (typeof order)[]) => void) | undefined;
		vi.mocked(requestEnterpriseOrder).mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					finishOrder = resolve;
				}),
		);
		vi.mocked(listEnterpriseOrders)
			.mockResolvedValueOnce([])
			.mockImplementationOnce(
				() =>
					new Promise((resolve) => {
						finishPoll = resolve;
					}),
			);
		await act(async () => {
			render(<BillingPage />);
		});
		expect(listEnterpriseOrders).toHaveBeenCalledTimes(1);
		expect(screen.getByRole("button", { name: "Submit for Finance review" })).toBeEnabled();
		fireEvent.click(screen.getByRole("button", { name: "Submit for Finance review" }));
		await act(async () => {
			vi.advanceTimersByTime(30_000);
		});
		expect(listEnterpriseOrders).toHaveBeenCalledTimes(2);
		await act(async () => finishOrder?.(order));
		expect(screen.getByText(/25 protected agents/)).toBeInTheDocument();
		await act(async () => finishPoll?.([]));
		expect(screen.getByText(/25 protected agents/)).toBeInTheDocument();
	});

	it("shows a loading state until the first order read resolves", async () => {
		let finishRead: ((rows: (typeof order)[]) => void) | undefined;
		vi.mocked(listEnterpriseOrders).mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					finishRead = resolve;
				}),
		);
		render(<BillingPage />);
		expect(screen.getByText("Loading enterprise order requests…")).toBeInTheDocument();
		expect(
			screen.queryByText("No enterprise order requests recorded for this tenant."),
		).not.toBeInTheDocument();
		await act(async () => finishRead?.([]));
		expect(
			screen.getByText("No enterprise order requests recorded for this tenant."),
		).toBeInTheDocument();
	});

	it("clears order details when the active tenant changes", async () => {
		vi.mocked(listEnterpriseOrders).mockResolvedValueOnce([order]).mockResolvedValueOnce([]);
		const view = render(<BillingPage />);
		await waitFor(() => expect(screen.getByText(/25 protected agents/)).toBeInTheDocument());
		fireEvent.change(screen.getByLabelText("Requested protected agents"), {
			target: { value: "42" },
		});
		fireEvent.change(screen.getByLabelText("Quote reference (optional)"), {
			target: { value: "Q-private" },
		});
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: "33333333-3333-4333-8333-333333333333" },
			currentRole: "owner",
		} as ReturnType<typeof useTeam>);
		view.rerender(<BillingPage />);
		await waitFor(() => expect(screen.queryByText(/25 protected agents/)).not.toBeInTheDocument());
		expect(screen.getByLabelText("Requested protected agents")).toHaveValue(1);
		expect(screen.getByLabelText("Quote reference (optional)")).toHaveValue("");
	});

	it("describes invoice reconciliation without promising a webhook or manual grant", () => {
		render(<BillingPage />);
		expect(screen.getByText(/Finance must confirm payment and reconcile/)).toBeInTheDocument();
		expect(screen.queryByText(/manual entitlement grants/i)).not.toBeInTheDocument();
		expect(screen.queryByText(/billing webhook/i)).not.toBeInTheDocument();
	});

	it("does not expose order data or submission to a non-admin member", async () => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantId },
			currentRole: "member",
		} as ReturnType<typeof useTeam>);
		render(<BillingPage />);
		expect(screen.getByText(/Only a tenant owner or admin/)).toBeInTheDocument();
		expect(
			screen.queryByRole("button", { name: "Submit for Finance review" }),
		).not.toBeInTheDocument();
		expect(listEnterpriseOrders).not.toHaveBeenCalled();
	});
});
