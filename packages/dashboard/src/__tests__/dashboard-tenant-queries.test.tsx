// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({
	supabase: { from: vi.fn(), functions: { invoke: vi.fn() } },
}));
vi.mock("../ui/session", () => ({ getSession: vi.fn().mockResolvedValue(null) }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { DashboardPage } from "../ui/pages/DashboardPage";

const tenantId = "11111111-1111-4111-8111-111111111111";

function renderPage() {
	return act(async () => {
		render(
			<MemoryRouter>
				<DashboardPage />
			</MemoryRouter>,
		);
	});
}

describe("selected tenant dashboard queries", () => {
	beforeEach(() => {
		vi.mocked(supabase.from).mockReset();
		vi.mocked(supabase.functions.invoke)
			.mockReset()
			.mockResolvedValue({
				data: { ok: true, tokens: [] },
				error: null,
			});
		vi.mocked(useTeam).mockReturnValue({ currentTeam: { id: tenantId } } as never);
	});

	afterEach(cleanup);

	it("scopes fleet, events, and pending tokens to the selected tenant", async () => {
		const queries = new Map<string, { eq: ReturnType<typeof vi.fn> }>();
		vi.mocked(supabase.from).mockImplementation((table: string) => {
			const query = {
				select: vi.fn(),
				eq: vi.fn(),
				order: vi.fn(),
				limit: vi.fn(),
				then(resolve: (value: unknown) => unknown) {
					return Promise.resolve({ data: [], error: null }).then(resolve);
				},
			};
			for (const method of ["select", "eq", "order", "limit"] as const) {
				query[method].mockReturnValue(query);
			}
			queries.set(table, query);
			return query as unknown as ReturnType<typeof supabase.from>;
		});

		await renderPage();
		expect(screen.getByText("No events recorded yet.")).toBeInTheDocument();
		expect(queries.get("agents")?.eq).toHaveBeenCalledWith("tenant_id", tenantId);
		expect(queries.get("events")?.eq).toHaveBeenCalledWith("tenant_id", tenantId);
		expect(supabase.functions.invoke).toHaveBeenCalledWith("enrollment-tokens", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": tenantId },
		});
	});

	it("does not query another tenant when no selected team exists", async () => {
		vi.mocked(useTeam).mockReturnValue({ currentTeam: null } as never);
		await renderPage();
		expect(supabase.from).not.toHaveBeenCalled();
		expect(supabase.functions.invoke).not.toHaveBeenCalled();
		expect(screen.getByRole("alert")).toHaveTextContent("Select a team to view dashboard.");
	});

	it("removes the previous team's dashboard before the next query settles", async () => {
		const nextTenantId = "22222222-2222-4222-8222-222222222222";
		let selected = tenantId;
		vi.mocked(useTeam).mockImplementation(() => ({ currentTeam: { id: selected } }) as never);
		vi.mocked(supabase.from).mockImplementation((table: string) => {
			let scope = "";
			const query = {
				select: vi.fn(), eq: vi.fn(), order: vi.fn(), limit: vi.fn(),
				then(resolve: (value: unknown) => unknown) {
					const data = table === "agents" && scope === tenantId ? [{
						id: "first-agent", iid: "first-installation", display_name: "First agent",
						agent_runtime: "codex", last_seen: null,
					}] : [];
					return Promise.resolve({ data, error: null, count: data.length }).then(resolve);
				},
			};
			for (const method of ["select", "order", "limit"] as const) query[method].mockReturnValue(query);
			query.eq.mockImplementation((_column: string, value: string) => { scope = value; return query; });
			return query as unknown as ReturnType<typeof supabase.from>;
		});
		let page!: ReturnType<typeof render>;
		await act(async () => {
			page = render(<MemoryRouter><DashboardPage /></MemoryRouter>);
		});
		expect(screen.getByText("First agent")).toBeInTheDocument();
		selected = nextTenantId;
		await act(async () => {
			page.rerender(<MemoryRouter><DashboardPage /></MemoryRouter>);
		});
		expect(screen.queryByText("First agent")).not.toBeInTheDocument();
		expect(screen.getByText("No agents yet.", { exact: false })).toBeInTheDocument();
	});
});
