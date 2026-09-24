// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../lib/supabase", () => ({
	supabase: { from: vi.fn() },
	supabaseEnvError: null,
}));

const team = vi.hoisted(() => ({ id: "tenant-a" }));
vi.mock("../../enterprise/team-provider", () => ({
	useTeam: () => ({ currentTeam: team.id ? { id: team.id } : null }),
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
	let resolvedResult = result;
	const chain = {
		select: vi.fn(),
		eq: vi.fn(),
		order: vi.fn(),
		limit: vi.fn(),
		gte: vi.fn(),
		maybeSingle: vi.fn(),
		then: (resolve: (value: unknown) => unknown) => Promise.resolve(resolvedResult).then(resolve),
		setResult: (next: unknown) => {
			resolvedResult = next;
		},
	};
	chain.select.mockReturnValue(chain);
	chain.eq.mockReturnValue(chain);
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
					query.setResult({ data: null, error: null, count: scenario.count });
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
		team.id = "tenant-a";
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

	it("does not label an expired provider term as an active entitlement", async () => {
		configure({
			seat: { data: { included_agents: 1, extra_agents: 0, allowed_agents: 1, current_agents: 1 }, error: null },
			subscription: {
				data: { status: "active", provider: "stripe", extra_agents: 4,
					current_period_end: "2020-01-01T00:00:00Z", cancel_at_period_end: false },
				error: null,
			},
		});
		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByText("Term expired or unverified")).toBeInTheDocument());
		expect(screen.queryByText("Active")).not.toBeInTheDocument();
		expect(screen.getByRole("progressbar")).toHaveAttribute("aria-label", "1 of 1 agents used");
	});

	it("does not display stale persisted seats when the effective seat view is unavailable", async () => {
		configure({
			seat: { data: null, error: { message: "seat_usage missing" } },
			entitlements: { data: { included_agents: 1, extra_agents: 9 }, error: null },
			count: 1,
		});

		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByText("Failed to load usage data")).toBeInTheDocument());
		expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
		expect(mockedSupabase.from.mock.calls.some(([table]) => table === "entitlements")).toBe(false);
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

	it("rejects malformed effective seat rows without guessing an allowance", async () => {
		configure({
			seat: { data: { included_agents: 1, extra_agents: "9", allowed_agents: 10, current_agents: 1 }, error: null },
		});

		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByText("Seat entitlement data is unavailable.")).toBeInTheDocument());
		expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
	});

	it("uses expired-provider effective seats instead of the persisted billing projection", async () => {
		configure({
			seat: { data: { included_agents: 1, extra_agents: 0, allowed_agents: 1, current_agents: 1 }, error: null },
			entitlements: { data: { included_agents: 1, extra_agents: 9 }, error: null },
		});
		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByRole("progressbar")).toHaveAttribute("aria-label", "1 of 1 agents used"));
		expect(mockedSupabase.from.mock.calls.some(([table]) => table === "entitlements")).toBe(false);
	});

	it("does not invent a free allowance when the selected team's seat row is absent", async () => {
		configure({ seat: { data: null, error: null } });
		render(<UsageMetering />);
		await waitFor(() =>
			expect(screen.getByText("Seat entitlement data is unavailable.")).toBeInTheDocument(),
		);
		expect(screen.queryByText("No subscription record")).not.toBeInTheDocument();
		expect(mockedSupabase.from.mock.calls.some(([table]) => table === "entitlements")).toBe(false);
	});

	it("does not hide a seat query failure behind legacy fallback", async () => {
		configure({
			seat: { data: null, error: { code: "42501", message: "permission denied for seat_usage" } },
		});
		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByText("Failed to load usage data")).toBeInTheDocument());
		expect(mockedSupabase.from.mock.calls.some(([table]) => table === "entitlements")).toBe(false);
	});

	it("filters every usage, trend and billing query to the selected team", async () => {
		render(<UsageMetering />);
		await waitFor(() => expect(screen.getByRole("progressbar")).toBeInTheDocument());
		const tables = mockedSupabase.from.mock.calls.map(([table]) => table);
		for (const table of ["seat_usage", "subscriptions"]) {
			const index = tables.indexOf(table);
			expect(index).toBeGreaterThanOrEqual(0);
			expect(mockedSupabase.from.mock.results[index]?.value?.eq).toHaveBeenCalledWith(
				"tenant_id",
				"tenant-a",
			);
		}
		for (const [index, table] of tables.entries()) {
			if (table === "agents")
				expect(mockedSupabase.from.mock.results[index]?.value?.eq).toHaveBeenCalledWith(
					"tenant_id",
					"tenant-a",
				);
		}
	});

	it("clears the prior team's usage synchronously when switching teams", async () => {
		configure({
			seat: {
				data: { included_agents: 2, extra_agents: 0, allowed_agents: 2, current_agents: 2 },
				error: null,
			},
		});
		const view = render(<UsageMetering />);
		await waitFor(() =>
			expect(screen.getByRole("progressbar")).toHaveAttribute("aria-label", "2 of 2 agents used"),
		);
		team.id = "tenant-b";
		configure({
			seat: {
				data: { included_agents: 4, extra_agents: 0, allowed_agents: 4, current_agents: 1 },
				error: null,
			},
		});
		view.rerender(<UsageMetering />);
		expect(
			screen.queryByRole("progressbar", { name: "2 of 2 agents used" }),
		).not.toBeInTheDocument();
		await waitFor(() =>
			expect(screen.getByRole("progressbar")).toHaveAttribute("aria-label", "1 of 4 agents used"),
		);
	});
});
