// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn() } }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { AgentsPage } from "../ui/pages/AgentsPage";

const tenantId = "11111111-1111-4111-8111-111111111111";
const agent = {
	id: "agent-1",
	iid: "installation-1",
	display_name: "Customer workstation",
	agent_runtime: "claude-code",
	agent_runtime_version: "1.0.0",
	first_seen: "2026-09-23T00:00:00Z",
	last_seen: "2026-09-23T00:01:00Z",
};

function configureQueries(
	agentResults: Array<unknown | Promise<unknown>>,
	seatResults: Array<unknown | Promise<unknown>> = [],
) {
	const order = vi.fn(() => Promise.resolve(agentResults.shift()));
	const eq = vi.fn();
	const maybeSingle = vi.fn(() =>
		Promise.resolve(
			seatResults.shift() ?? {
				data: { included_agents: 1, extra_agents: 0, allowed_agents: 1 },
				error: null,
			},
		),
	);
	vi.mocked(supabase.from).mockImplementation((table: string) => {
		if (table !== "agents" && table !== "seat_usage") throw new Error(`Unexpected table: ${table}`);
		const query = {
			select: vi.fn(),
			eq,
			order,
			maybeSingle,
		};
		query.select.mockReturnValue(query);
		query.eq.mockReturnValue(query);
		return query as unknown as ReturnType<typeof supabase.from>;
	});
	return { order, maybeSingle, eq };
}

async function renderPage() {
	let page!: ReturnType<typeof render>;
	await act(async () => {
		page = render(
			<MemoryRouter>
				<AgentsPage />
			</MemoryRouter>,
		);
	});
	return page;
}

describe("Agents availability", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantId, name: "Customer" },
		} as never);
		vi.mocked(supabase.from).mockReset();
	});

	afterEach(() => {
		cleanup();
		vi.useRealTimers();
	});

	it("clears a previously listed agent when the next poll fails", async () => {
		const { eq } = configureQueries([
			{ data: [agent], error: null },
			{ data: null, error: { message: "Agent service unavailable" } },
		]);
		await renderPage();
		expect(eq).toHaveBeenCalledWith("tenant_id", tenantId);
		expect(screen.getByText("Customer workstation")).toBeInTheDocument();
		expect(screen.getByText("agents recorded")).toBeInTheDocument();
		await act(async () => {
			await vi.advanceTimersByTimeAsync(5000);
		});
		expect(screen.queryByText("Customer workstation")).not.toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent("Failed to load agents");
		expect(screen.getAllByText("Agent data is unavailable.")).toHaveLength(1);
		expect(screen.queryByText("no agents")).not.toBeInTheDocument();
	});

	it("clears a previously listed agent when a refresh request rejects", async () => {
		const { order } = configureQueries([{ data: [agent], error: null }]);
		await renderPage();
		expect(screen.getByText("Customer workstation")).toBeInTheDocument();
		order.mockRejectedValueOnce(new Error("request https://internal.test?token=secret failed"));
		await act(async () => {
			await vi.advanceTimersByTimeAsync(5000);
		});
		expect(screen.queryByText("Customer workstation")).not.toBeInTheDocument();
		expect(screen.getAllByRole("alert")[0]).toHaveTextContent("Failed to load agents");
		expect(document.body.textContent).not.toContain("internal.test");
	});

	it("rejects a malformed success response instead of claiming an empty or reporting fleet", async () => {
		configureQueries([{ data: [{ ...agent, iid: null }], error: null }]);
		await renderPage();
		expect(screen.getByRole("alert")).toHaveTextContent("Agent data is unavailable.");
		expect(screen.queryByText("Customer workstation")).not.toBeInTheDocument();
		expect(screen.queryByText("no agents")).not.toBeInTheDocument();
	});

	it("ignores an older poll response after a newer agent list arrives", async () => {
		let resolveOld: (value: unknown) => void = () => {};
		const oldRequest = new Promise((resolve) => {
			resolveOld = resolve;
		});
		configureQueries([oldRequest, { data: [agent], error: null }]);
		await renderPage();
		await act(async () => {
			await vi.advanceTimersByTimeAsync(5000);
		});
		expect(screen.getByText("Customer workstation")).toBeInTheDocument();
		await act(async () => {
			resolveOld({ data: [], error: null });
		});
		expect(screen.getByText("Customer workstation")).toBeInTheDocument();
	});

	it("hides the former team's agents and seat count while the new team loads", async () => {
		const nextTenantId = "22222222-2222-4222-8222-222222222222";
		let selectedTenantId = tenantId;
		vi.mocked(useTeam).mockImplementation(
			() => ({ currentTeam: { id: selectedTenantId, name: "Customer" } }) as never,
		);
		let resolveNext: (value: unknown) => void = () => {};
		const nextRequest = new Promise((resolve) => {
			resolveNext = resolve;
		});
		const { eq } = configureQueries([{ data: [agent], error: null }, nextRequest]);
		const page = await renderPage();
		expect(screen.getByText("Customer workstation")).toBeInTheDocument();
		expect(screen.getByText("agents recorded")).toBeInTheDocument();
		selectedTenantId = nextTenantId;
		await act(async () => {
			page.rerender(
				<MemoryRouter>
					<AgentsPage />
				</MemoryRouter>,
			);
		});
		expect(eq).toHaveBeenCalledWith("tenant_id", nextTenantId);
		expect(screen.queryByText("Customer workstation")).not.toBeInTheDocument();
		expect(screen.getByText("unavailable", { selector: "span" })).toBeInTheDocument();
		await act(async () => {
			resolveNext({ data: [], error: null });
		});
		expect(screen.getByText("no agents")).toBeInTheDocument();
	});

	it("keeps no selected tenant unavailable and sends no fleet request", async () => {
		vi.mocked(useTeam).mockReturnValue({ currentTeam: null } as never);
		await renderPage();
		expect(supabase.from).not.toHaveBeenCalled();
		expect(screen.getByText("Select a team to view its agents.")).toBeInTheDocument();
		expect(screen.queryByText("no agents")).not.toBeInTheDocument();
	});

	it("reads the effective limit from seat_usage without querying raw entitlements", async () => {
		configureQueries(
			[{ data: [agent], error: null }],
			[{ data: { included_agents: 1, extra_agents: 0, allowed_agents: 1 }, error: null }],
		);
		await renderPage();
		expect(supabase.from).toHaveBeenCalledWith("seat_usage");
		expect(supabase.from).not.toHaveBeenCalledWith("entitlements");
		expect(screen.getByText(/Allowed:/)).toHaveTextContent("Allowed: 1");
	});

	it.each([
		["missing", { data: null, error: null }],
		["query failure", { data: null, error: { message: "seat_usage failed" } }],
		[
			"malformed",
			{ data: { included_agents: 1, extra_agents: 0, allowed_agents: "9" }, error: null },
		],
		[
			"inconsistent",
			{ data: { included_agents: 1, extra_agents: 0, allowed_agents: 9 }, error: null },
		],
	])("keeps the allowed limit unavailable on %s seat_usage", async (_case, seatResult) => {
		configureQueries([{ data: [agent], error: null }], [seatResult]);
		await renderPage();
		expect(screen.getByText(/Allowed:/)).toHaveTextContent("Allowed: unavailable");
		expect(screen.getByText(/do not infer the allowed-agent limit/)).toBeInTheDocument();
		expect(supabase.from).not.toHaveBeenCalledWith("entitlements");
	});
});
