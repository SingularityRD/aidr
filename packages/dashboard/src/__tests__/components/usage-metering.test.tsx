// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/supabase", () => ({
	supabase: { from: vi.fn() },
	supabaseEnvError: null,
}));

import { UsageMetering } from "../../components/usage-metering";
import { supabase } from "../../lib/supabase";

const mockedSupabase = supabase as unknown as { from: ReturnType<typeof vi.fn> };

type Scenario = {
	seat: { data: unknown; error: unknown };
	entitlements: { data: unknown; error: unknown };
	agents: unknown[];
	count: number;
	subscription: { data: unknown; error: unknown };
};

const defaultScenario: Scenario = {
	seat: {
		data: { included_agents: 1, extra_agents: 0, allowed_agents: 1, current_agents: 0 },
		error: null,
	},
	entitlements: { data: { included_agents: 1, extra_agents: 0 }, error: null },
	agents: [],
	count: 0,
	subscription: { data: null, error: null },
};

function queryChain(result: unknown) {
	const chain = {
		select: vi.fn(),
		order: vi.fn(),
		limit: vi.fn(),
		gte: vi.fn(),
		maybeSingle: vi.fn(),
		then: (resolve: (value: unknown) => unknown) => Promise.resolve(result).then(resolve),
	};
	chain.select.mockReturnValue(chain);
	chain.order.mockReturnValue(chain);
	chain.limit.mockReturnValue(chain);
	chain.gte.mockReturnValue(chain);
	chain.maybeSingle.mockResolvedValue(result);
	return chain;
}

function configure(partial: Partial<Scenario> = {}) {
	const scenario = { ...defaultScenario, ...partial };
	mockedSupabase.from.mockImplementation((table: string) => {
		if (table === "seat_usage") return queryChain(scenario.seat);
		if (table === "entitlements") return queryChain(scenario.entitlements);
		if (table === "subscriptions") return queryChain(scenario.subscription);
		if (table === "agents") {
			const query = queryChain({ data: scenario.agents, error: null });
			query.select.mockImplementation((_fields: string, options?: { count?: string }) => {
				if (options?.count === "exact")
					return Promise.resolve({ data: null, error: null, count: scenario.count });
				return query;
			});
			return query;
		}
		return queryChain({ data: [], error: null });
	});
}

describe("UsageMetering", () => {
	beforeEach(() => {
		vi.resetAllMocks();
		configure();
	});
	afterEach(cleanup);

	it("renders a loading card immediately", () => {
		const { container } = render(<UsageMetering />);
		expect(container.querySelector(".card")).toBeInTheDocument();
	});

	it("renders seat usage and active billing state", async () => {
		configure({
			seat: {
				data: { included_agents: 2, extra_agents: 3, allowed_agents: 5, current_agents: 2 },
				error: null,
			},
			count: 2,
			subscription: {
				data: {
					status: "active",
					provider: "invoice",
					extra_agents: 3,
					current_period_end: "2026-06-28T00:00:00Z",
					cancel_at_period_end: false,
				},
				error: null,
			},
		});

		render(<UsageMetering />);
		await waitFor(() =>
			expect(screen.getByRole("progressbar")).toHaveAttribute("aria-label", "2 of 5 agents used"),
		);
		expect(screen.getByText("Active")).toBeInTheDocument();
		expect(screen.getByText("invoice")).toBeInTheDocument();
	});

	it("falls back to entitlements when seat_usage is unavailable", async () => {
		configure({
			seat: { data: null, error: { message: "seat_usage missing" } },
			entitlements: { data: { included_agents: 1, extra_agents: 0 }, error: null },
			count: 1,
		});

		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByText("Free tier")).toBeInTheDocument());
		expect(screen.getByRole("progressbar")).toHaveAttribute("aria-label", "1 of 1 agents used");
	});

	it("shows a warning at the entitlement threshold", async () => {
		configure({
			seat: {
				data: { included_agents: 4, extra_agents: 1, allowed_agents: 5, current_agents: 4 },
				error: null,
			},
			count: 4,
		});

		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByText("Approaching limit.")).toBeInTheDocument());
	});

	it("shows a visible error when entitlement fallback also fails", async () => {
		configure({
			seat: { data: null, error: { message: "seat_usage missing" } },
			entitlements: { data: null, error: new Error("Database connection failed") },
		});

		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByText("Database connection failed")).toBeInTheDocument());
	});
});
