// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ nextId: 0, seatUnavailable: false }));
const tenantId = "11111111-1111-4111-8111-111111111111";

vi.mock("../enterprise/team-provider", () => ({
	useTeam: () => ({ currentTeam: { id: tenantId }, currentRole: "owner" }),
}));
vi.mock("../lib/supabase", () => ({
	supabase: {
		from: (table: string) => {
			const query = {
				select: () => query,
				eq: () => query,
				order: () => query,
				limit: () => query,
				maybeSingle: async () => ({
					data:
						table === "seat_usage" && !state.seatUnavailable
							? {
									included_agents: 1,
									extra_agents: 0,
									allowed_agents: 1,
									current_agents: 0,
								}
							: null,
					error: null,
				}),
			};
			return query;
		},
	},
}));
vi.mock("../billing/commercial", async (importOriginal) => ({
	...(await importOriginal<typeof import("../billing/commercial")>()),
	selfServiceCheckoutEnabled: true,
	safeCommercialLink: (value: string | null) => value,
	getSalesContactHref: () => "mailto:sales@example.com",
}));
vi.mock("../billing/enterprise-orders", () => ({
	listEnterpriseOrders: vi.fn(async () => []),
	requestEnterpriseOrder: vi.fn(),
	newBillingRequestId: () => `request_${String(++state.nextId).padStart(16, "0")}`,
}));
vi.mock("../billing/invoice-approvals", () => ({ listInvoiceApprovals: vi.fn(async () => []) }));
vi.mock("../billing/billing-portal", () => ({
	loadBillingPortal: vi.fn(async () => ({
		tenantId,
		settlements: [],
		projection: [],
		selfService: false,
	})),
	projectedSeats: () => null,
	requestSeats: vi.fn(),
	cancelSettlement: vi.fn(),
}));
vi.mock("../billing/stripe-client", () => ({
	CheckoutSessionExpiredError: class CheckoutSessionExpiredError extends Error {
		constructor() {
			super("The checkout session expired. Start a new checkout request.");
		}
	},
	createCheckout: vi.fn(),
}));

import { CheckoutSessionExpiredError, createCheckout } from "../billing/stripe-client";
import { BillingPage } from "../ui/pages/BillingPage";

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
	state.seatUnavailable = false;
});

it("does not begin a checkout when effective seat state cannot be read", async () => {
	state.seatUnavailable = true;
	render(<BillingPage />);
	await screen.findByText(/Seat usage is unavailable for this tenant/);
	const begin = screen.getByRole("button", { name: "Review monthly subscription" });
	expect(begin).toBeDisabled();
	fireEvent.click(begin);
	expect(createCheckout).not.toHaveBeenCalled();
});

it("uses a new checkout request only after the provider confirms the old session expired", async () => {
	vi.mocked(createCheckout)
		.mockRejectedValueOnce(new CheckoutSessionExpiredError())
		.mockResolvedValueOnce({
			checkoutId: "cs_new",
			checkoutUrl: "https://checkout.stripe.com/c/pay/cs_new",
		});
	render(<BillingPage />);
	await waitFor(() => expect(screen.getByText("Included").parentElement).toHaveTextContent("1"));
	const begin = screen.getByRole("button", { name: "Review monthly subscription" });
	fireEvent.click(begin);
	await screen.findByText("The checkout session expired. Start a new checkout request.");
	fireEvent.click(begin);
	await waitFor(() => expect(createCheckout).toHaveBeenCalledTimes(2));
	const first = vi.mocked(createCheckout).mock.calls[0]?.[6];
	const second = vi.mocked(createCheckout).mock.calls[1]?.[6];
	expect(first).toMatch(/^request_/);
	expect(second).toMatch(/^request_/);
	expect(second).not.toBe(first);
});
