// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const commercial = vi.hoisted(() => ({ selfService: false }));
vi.mock("../lib/supabase", () => ({ supabase: { rpc: vi.fn() } }));
vi.mock("../billing/commercial", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../billing/commercial")>();
	return {
		...actual,
		get selfServiceCheckoutEnabled() {
			return commercial.selfService;
		},
	};
});
vi.mock("../billing/enterprise-orders", () => ({
	requestEnterpriseOrder: vi.fn(),
	newBillingRequestId: vi.fn(() => "plan_request_1234567890"),
}));
vi.mock("../billing/stripe-client", () => ({ createCheckout: vi.fn() }));

import { requestEnterpriseOrder } from "../billing/enterprise-orders";
import { PlanCard } from "../billing/plan-card";
import { readTenantPlan } from "../billing/plans";
import { createCheckout } from "../billing/stripe-client";
import { supabase } from "../lib/supabase";
import { CURRENCY_OR_PRICE } from "./helpers/public-price-patterns";

const TENANT = "11111111-1111-4111-8111-111111111111";
const rpc = supabase.rpc as unknown as ReturnType<typeof vi.fn>;

function planPayload(overrides: Record<string, unknown> = {}) {
	return {
		tenant_id: TENANT,
		plan_id: "free",
		display_name: "Free",
		plan_source: "default",
		included_agents_per_seat: 1,
		min_seats: 1,
		self_serve: true,
		retention_days: 7,
		allowed_agents: 1,
		current_agents: 1,
		admission: {
			mode: "cloud",
			status: "active",
			kind: "trial",
			expires_at: "2026-10-08T00:00:00+00:00",
		},
		subscription: null,
		...overrides,
	};
}

beforeEach(() => {
	commercial.selfService = false;
	rpc.mockResolvedValue({ data: planPayload(), error: null });
	vi.mocked(requestEnterpriseOrder).mockResolvedValue({
		id: "22222222-2222-4222-8222-222222222222",
		tenant_id: TENANT,
		request_id: "plan_request_1234567890",
		requested_agents: 3,
		quote_reference: "plan-request:team:yearly",
		status: "pending_finance",
		created_at: "2026-09-24T00:00:00.000Z",
		updated_at: "2026-09-24T00:00:00.000Z",
	});
	vi.mocked(createCheckout).mockResolvedValue({
		checkoutUrl: "https://checkout.stripe.com/c/pay/cs_plan",
		checkoutId: "cs_plan",
	});
});

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
});

describe("billing plan card", () => {
	it("shows the current plan and usage against admitted capacity from the member RPC", async () => {
		rpc.mockResolvedValue({
			data: planPayload({
				plan_id: "team",
				display_name: "Team",
				plan_source: "stripe_subscription",
				allowed_agents: 5,
				current_agents: 4,
				admission: {
					mode: "cloud",
					status: "active",
					kind: "licensed",
					expires_at: "2026-10-24T00:00:00+00:00",
				},
				subscription: {
					plan_id: "team",
					billing_interval: "monthly",
					seats: 5,
					status: "active",
					admission_state: "granted",
					current_period_end: "2026-10-24T00:00:00+00:00",
				},
			}),
			error: null,
		});
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		expect(await screen.findByText("4 / 5")).toBeInTheDocument();
		expect(rpc).toHaveBeenCalledWith("get_tenant_plan", { p_tenant_id: TENANT });
		const card = within(screen.getByLabelText("Current plan"));
		expect(card.getByText("Verified card subscription")).toBeInTheDocument();
		expect(card.getByText("licensed · active")).toBeInTheDocument();
		expect(card.getByRole("progressbar", { name: "Protected agent usage" })).toHaveAttribute(
			"aria-valuenow",
			"4",
		);
		expect(
			card.getByText(/Card subscription: Team · 5 seats · monthly · active/),
		).toBeInTheDocument();
	});

	it("warns when the tenant has no admitted capacity", async () => {
		rpc.mockResolvedValue({
			data: planPayload({
				allowed_agents: 0,
				current_agents: 0,
				admission: { mode: "cloud", status: "none", kind: null, expires_at: null },
			}),
			error: null,
		});
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		expect(await screen.findByText(/no admitted protected-agent capacity/)).toBeInTheDocument();
	});

	it.each([
		[{ data: null, error: { message: "permission denied" } }],
		[{ data: planPayload({ tenant_id: "33333333-3333-4333-8333-333333333333" }), error: null }],
		[{ data: planPayload({ allowed_agents: -1 }), error: null }],
	])("shows no plan figures when the projection is unusable (%#)", async (result) => {
		rpc.mockResolvedValue(result);
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		expect(await screen.findByText(/Plan information could not be loaded/)).toBeInTheDocument();
		expect(screen.queryByText("Current plan")).not.toBeInTheDocument();
	});

	it("limits plan changes to owners and admins", async () => {
		render(<PlanCard tenantId={TENANT} canManageBilling={false} />);
		expect(
			await screen.findByText("Plan changes are limited to tenant owners and admins."),
		).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Request upgrade" })).not.toBeInTheDocument();
	});

	it("files an invoice-flow upgrade request when self-service checkout is off", async () => {
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		const button = await screen.findByRole("button", { name: "Request upgrade" });
		await waitFor(() => expect(button).toBeEnabled());
		fireEvent.click(button);
		await waitFor(() =>
			expect(requestEnterpriseOrder).toHaveBeenCalledWith(TENANT, {
				request_id: "plan_request_1234567890",
				requested_agents: 3,
				quote_reference: "plan-request:team:yearly",
			}),
		);
		expect(
			await screen.findByText(/sent to Finance review as pending finance/),
		).toBeInTheDocument();
		expect(createCheckout).not.toHaveBeenCalled();
	});

	it("enforces the plan seat minimum before any request", async () => {
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		fireEvent.click(await screen.findByRole("radio", { name: /Business/ }));
		const seats = screen.getByLabelText("Developer seats");
		expect(seats).toHaveValue(25);
		fireEvent.change(seats, { target: { value: "10" } });
		expect(screen.getByText("Business requires at least 25 developer seats.")).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Request upgrade" })).toBeDisabled();
	});

	it("uses server-side checkout only for a self-serve plan when the build and tenant allow it", async () => {
		commercial.selfService = true;
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		const button = await screen.findByRole("button", { name: "Continue to checkout" });
		fireEvent.change(screen.getByLabelText("Developer seats"), { target: { value: "4" } });
		fireEvent.change(screen.getByLabelText("Billing"), { target: { value: "monthly" } });
		await waitFor(() => expect(button).toBeEnabled());
		fireEvent.click(button);
		await waitFor(() =>
			expect(createCheckout).toHaveBeenCalledWith(
				"",
				"",
				4,
				"monthly",
				undefined,
				TENANT,
				"plan_request_1234567890",
				"team",
			),
		);
		expect(await screen.findByRole("link", { name: "Open secure checkout" })).toHaveAttribute(
			"href",
			"https://checkout.stripe.com/c/pay/cs_plan",
		);
		expect(requestEnterpriseOrder).not.toHaveBeenCalled();

		// A sales-assisted plan never goes to card checkout, even in self-service builds.
		fireEvent.click(screen.getByRole("radio", { name: /Business/ }));
		expect(screen.getByRole("button", { name: "Request upgrade" })).toBeInTheDocument();
	});

	it.each([false, true])(
		"shows plan names and terms but never a list price in the picker (self-service %s)",
		async (selfService) => {
			commercial.selfService = selfService;
			render(<PlanCard tenantId={TENANT} canManageBilling />);
			const picker = await screen.findByRole("group", { name: "Plan picker" });
			await screen.findByText("1 / 1");
			expect(
				within(picker).getByText(/Minimum 3 developers · 90-day event retention/),
			).toBeTruthy();
			for (const name of ["Team", "Business", "Enterprise"]) {
				expect(within(picker).getByRole("radio", { name: new RegExp(name) })).toBeInTheDocument();
			}
			const card = screen.getByLabelText("Current plan");
			expect(card.textContent ?? "").not.toMatch(CURRENCY_OR_PRICE);
			expect(card).toHaveTextContent("Prices are not published.");
			expect(within(card).getByRole("link", { name: "anil@singularityrd.com" })).toHaveAttribute(
				"href",
				expect.stringMatching(/^mailto:anil@singularityrd\.com\?/),
			);
			if (selfService) {
				expect(card).toHaveTextContent(/shows the amount on the payment provider's page/);
			}
		},
	);

	it("offers only the billing intervals the catalog carries", async () => {
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		const billing = await screen.findByLabelText("Billing");
		expect(
			within(billing)
				.getAllByRole("option")
				.map((option) => option.textContent),
		).toEqual(["Monthly", "Annual"]);
		fireEvent.click(screen.getByRole("radio", { name: /Business/ }));
		expect(
			within(screen.getByLabelText("Billing"))
				.getAllByRole("option")
				.map((option) => option.textContent),
		).toEqual(["Annual"]);
		fireEvent.click(screen.getByRole("radio", { name: /Enterprise/ }));
		expect(screen.queryByLabelText("Billing")).not.toBeInTheDocument();
	});

	it("keeps checkout off for a tenant outside the cloud admission mode", async () => {
		commercial.selfService = true;
		rpc.mockResolvedValue({
			data: planPayload({
				admission: { mode: "onprem", status: "active", kind: "licensed", expires_at: null },
			}),
			error: null,
		});
		render(<PlanCard tenantId={TENANT} canManageBilling />);
		expect(await screen.findByRole("button", { name: "Request upgrade" })).toBeInTheDocument();
	});
});

describe("readTenantPlan", () => {
	it("accepts the documented projection and rejects anything else", () => {
		expect(readTenantPlan(planPayload(), TENANT)).toMatchObject({
			planId: "free",
			allowedAgents: 1,
		});
		expect(readTenantPlan(planPayload({ plan_id: "pro" }), TENANT)).toBeNull();
		expect(readTenantPlan(planPayload({ plan_source: "browser" }), TENANT)).toBeNull();
		expect(readTenantPlan(planPayload({ subscription: { plan_id: "team" } }), TENANT)).toBeNull();
		expect(readTenantPlan([], TENANT)).toBeNull();
	});
});
