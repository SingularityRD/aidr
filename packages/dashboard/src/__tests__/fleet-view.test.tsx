// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn(), rpc: vi.fn() } }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import {
	agentHealth,
	agentsCsv,
	applyEventFilters,
	eventsCsv,
	readAgentFilters,
	readEventFilters,
	STALE_AFTER_MS,
	writeEventFilters,
} from "../ui/fleet-view";
import { AgentDetailPage } from "../ui/pages/AgentDetailPage";
import { AgentsPage } from "../ui/pages/AgentsPage";
import { EventsPage } from "../ui/pages/EventsPage";

const tenantId = "11111111-1111-4111-8111-111111111111";
const agentId = "22222222-2222-4222-8222-222222222222";
const NOW = Date.parse("2026-10-15T12:00:00Z");

type Result = { data: unknown; error: unknown };
type Call = { table: string; method: string; args: unknown[] };

/** Chainable, thenable PostgREST stand-in that records every filter call. */
function backend(results: Record<string, Result | (() => Result)>) {
	const calls: Call[] = [];
	vi.mocked(supabase.from).mockImplementation((table: string) => {
		const pick = () => {
			const entry = results[table] ?? { data: [], error: null };
			return typeof entry === "function" ? entry() : entry;
		};
		const query: Record<string, unknown> = {};
		for (const method of ["select", "eq", "gte", "or", "order", "limit"]) {
			query[method] = (...args: unknown[]) => {
				calls.push({ table, method, args });
				return query;
			};
		}
		query.maybeSingle = () => Promise.resolve(pick());
		query.then = (resolve: (value: Result) => unknown, reject?: (reason: unknown) => unknown) =>
			Promise.resolve().then(pick).then(resolve, reject);
		return query as never;
	});
	return calls;
}

function LocationProbe() {
	const location = useLocation();
	return <output data-testid="location">{location.search}</output>;
}

async function renderAt(path: string, element: React.ReactNode, route = "*") {
	await act(async () => {
		render(
			<MemoryRouter initialEntries={[path]}>
				<Routes>
					<Route
						path={route}
						element={
							<>
								{element}
								<LocationProbe />
							</>
						}
					/>
				</Routes>
			</MemoryRouter>,
		);
	});
}

function agent(id: string, name: string, lastSeen: number, extra: Record<string, unknown> = {}) {
	return {
		id,
		iid: `iid-${id}`,
		display_name: name,
		agent_runtime: "claude-code",
		agent_runtime_version: "1.2.3",
		first_seen: "2026-09-01T00:00:00Z",
		last_seen: new Date(lastSeen).toISOString(),
		retired_at: null,
		retired_reason: null,
		...extra,
	};
}

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
	vi.setSystemTime(NOW);
	vi.mocked(supabase.from).mockReset();
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: tenantId, name: "Customer" },
		isLoading: false,
		canManageTeam: false,
	} as never);
});

afterEach(() => {
	cleanup();
	vi.useRealTimers();
});

describe("fleet-view helpers", () => {
	it("classifies stale agents by the alert-channel default (4 hours)", () => {
		expect(agentHealth({ last_seen: new Date(NOW - 60_000).toISOString() }, NOW)).toBe("active");
		expect(agentHealth({ last_seen: new Date(NOW - STALE_AFTER_MS - 1).toISOString() }, NOW)).toBe(
			"stale",
		);
		expect(agentHealth({ last_seen: "not a date" }, NOW)).toBe("stale");
		expect(
			agentHealth(
				{ last_seen: new Date(NOW).toISOString(), retired_at: "2026-10-01T00:00:00Z" },
				NOW,
			),
		).toBe("retired");
	});

	it("drops URL filter values that could smuggle a PostgREST expression", () => {
		const filters = readEventFilters(
			new URLSearchParams({
				decision: "deny,payload->>x.eq.y",
				severity: "high)",
				type: "runtime_verdict;drop",
				agent: "not-a-uuid",
				rule: "AIDR-1,or(id.gt.0)",
				range: "forever",
			}),
		);
		expect(filters).toEqual({
			range: "all",
			type: "",
			decision: "",
			severity: "",
			agent: "",
			rule: "",
		});
		expect(
			readAgentFilters(new URLSearchParams({ status: "bogus", runtime: "a b" })),
		).toMatchObject({ status: "all", runtime: "" });
	});

	it("applies validated event filters server-side", () => {
		const calls: Array<[string, ...unknown[]]> = [];
		const query = {
			eq: (...args: unknown[]) => (calls.push(["eq", ...args]), query),
			gte: (...args: unknown[]) => (calls.push(["gte", ...args]), query),
			or: (...args: unknown[]) => (calls.push(["or", ...args]), query),
		};
		const filters = readEventFilters(
			new URLSearchParams({
				range: "24h",
				type: "runtime_verdict",
				decision: "deny",
				severity: "critical",
				agent: agentId,
				rule: "AIDR-SHELL-001",
			}),
		);
		applyEventFilters(query, filters, NOW);
		expect(calls).toEqual([
			["gte", "created_at", new Date(NOW - 24 * 3600_000).toISOString()],
			["eq", "type", "runtime_verdict"],
			["eq", "agent_id", agentId],
			["or", "payload->>verdict.eq.deny,payload->>decision.eq.deny"],
			["eq", "payload->>severity", "critical"],
			["eq", "payload->>matched_threat_id", "AIDR-SHELL-001"],
		]);
		expect(writeEventFilters(filters).toString()).toBe(
			`range=24h&type=runtime_verdict&decision=deny&severity=critical&agent=${agentId}&rule=AIDR-SHELL-001`,
		);
	});

	it("neutralises spreadsheet formulas in CSV exports", () => {
		const csv = agentsCsv([agent("a1", '=HYPERLINK("http://x")', NOW)], NOW);
		expect(csv.split("\r\n")[0]).toBe(
			"id,iid,display_name,runtime,runtime_version,status,first_seen,last_seen,retired_at,retired_reason",
		);
		expect(csv).toContain(`"'=HYPERLINK(""http://x"")"`);
		const events = eventsCsv(
			[
				{
					id: 7,
					type: "runtime_verdict",
					created_at: "2026-10-15T11:00:00Z",
					agent_id: "a1",
					payload: {
						verdict: "deny",
						severity: "high",
						tool_name: "@cmd",
						matched_threat_id: "R-1",
					},
				},
			],
			new Map([["a1", { display_name: "laptop", iid: "i", agent_runtime: "cursor" }]]),
		);
		expect(events.split("\r\n")[1]).toBe(
			"7,2026-10-15T11:00:00Z,runtime_verdict,deny,high,'@cmd,R-1,a1,laptop,cursor",
		);
	});
});

describe("Agents page fleet tracking", () => {
	const fresh = agent("a-fresh", "fresh-laptop", NOW - 60_000);
	const stale = agent("a-stale", "stale-desktop", NOW - STALE_AFTER_MS - 60_000, {
		agent_runtime: "cursor",
	});
	const retired = agent("a-retired", "old-vm", NOW - 30 * 86400_000, {
		retired_at: "2026-10-01T00:00:00Z",
		retired_reason: "manual",
	});

	function fleet() {
		return backend({
			agents: { data: [fresh, stale, retired], error: null },
			seat_usage: {
				data: { included_agents: 5, extra_agents: 0, allowed_agents: 5 },
				error: null,
			},
		});
	}

	it("badges stale agents and counts them", async () => {
		fleet();
		await renderAt("/agents", <AgentsPage />);
		const row = screen.getByText("stale-desktop").closest("tr") as HTMLElement;
		expect(row).toHaveAttribute("data-agent-status", "stale");
		expect(within(row).getByText("Stale")).toBeInTheDocument();
		expect(screen.getByText("fresh-laptop").closest("tr")).toHaveAttribute(
			"data-agent-status",
			"active",
		);
		expect(screen.getByText("1 active agent(s) not seen for more than 4 hours.")).toHaveAttribute(
			"data-stale-count",
			"1",
		);
	});

	it("restores status and runtime filters from a deep link", async () => {
		fleet();
		await renderAt("/agents?status=stale&runtime=cursor", <AgentsPage />);
		expect(screen.getByText("stale-desktop")).toBeInTheDocument();
		expect(screen.queryByText("fresh-laptop")).not.toBeInTheDocument();
		expect(screen.queryByText("old-vm")).not.toBeInTheDocument();
		expect(screen.getByText("Showing 1 of 3.")).toBeInTheDocument();
	});

	it("writes search to the URL and shows a filtered-empty state, not the onboarding empty state", async () => {
		fleet();
		await renderAt("/agents", <AgentsPage />);
		await act(async () => {
			fireEvent.change(screen.getByRole("searchbox"), { target: { value: "nothing-matches" } });
		});
		expect(screen.getByTestId("location")).toHaveTextContent("?q=nothing-matches");
		expect(screen.getByText("No agents match these filters.")).toBeInTheDocument();
		expect(screen.queryByText(/No agents yet/)).not.toBeInTheDocument();
	});

	it("exports exactly the filtered list as CSV", async () => {
		fleet();
		const blobs: Blob[] = [];
		const createObjectURL = vi.fn((blob: Blob) => {
			blobs.push(blob);
			return "blob:agents";
		});
		Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
		const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
		await renderAt("/agents?status=active", <AgentsPage />);
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
		});
		expect(click).toHaveBeenCalledTimes(1);
		const csv = await (blobs[0] as Blob).text();
		expect(csv).toContain("fresh-laptop");
		expect(csv).not.toContain("stale-desktop");
		expect(csv).not.toContain("old-vm");
		click.mockRestore();
	});

	it("disables export and shows no counts when the agent query fails", async () => {
		backend({
			agents: { data: null, error: { message: "agents down" } },
			seat_usage: { data: null, error: { message: "seat down" } },
		});
		await renderAt("/agents", <AgentsPage />);
		expect(screen.getByRole("button", { name: "Export CSV" })).toBeDisabled();
		expect(screen.queryByText(/Showing \d+ of/)).not.toBeInTheDocument();
		expect(screen.queryByText(/not seen for more than 4 hours/)).not.toBeInTheDocument();
		expect(screen.getAllByText("Agent data is unavailable.").length).toBeGreaterThan(0);
	});

	it("hides Retire from members who cannot manage the team", async () => {
		fleet();
		await renderAt("/agents", <AgentsPage />);
		expect(screen.queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
	});
});

describe("Events page filters", () => {
	const events = [
		{
			id: 1,
			type: "runtime_verdict",
			created_at: "2026-10-15T11:00:00Z",
			agent_id: agentId,
			payload: { verdict: "deny", severity: "high", tool_name: "shell", matched_threat_id: "R-1" },
		},
	];

	it("sends deep-linked filters to the server and keeps them in the URL", async () => {
		const calls = backend({
			events: { data: events, error: null },
			agents: {
				data: [{ id: agentId, iid: "iid-1", display_name: "laptop", agent_runtime: "cursor" }],
				error: null,
			},
		});
		await renderAt(`/events?decision=deny&agent=${agentId}&range=7d&rule=R-1`, <EventsPage />);
		const eventCalls = calls.filter((call) => call.table === "events");
		expect(eventCalls).toContainEqual({
			table: "events",
			method: "eq",
			args: ["tenant_id", tenantId],
		});
		expect(eventCalls).toContainEqual({
			table: "events",
			method: "eq",
			args: ["agent_id", agentId],
		});
		expect(eventCalls).toContainEqual({
			table: "events",
			method: "or",
			args: ["payload->>verdict.eq.deny,payload->>decision.eq.deny"],
		});
		expect(eventCalls).toContainEqual({
			table: "events",
			method: "gte",
			args: ["created_at", new Date(NOW - 7 * 86400_000).toISOString()],
		});
		expect(eventCalls).toContainEqual({
			table: "events",
			method: "eq",
			args: ["payload->>matched_threat_id", "R-1"],
		});
		expect(screen.getByText("shell (high)")).toBeInTheDocument();

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
		});
		expect(screen.getByTestId("location")).toHaveTextContent(/^$/);
	});

	it("shows an error and no invented counts when the events query fails", async () => {
		backend({ events: { data: null, error: { message: "events down" } } });
		await renderAt("/events?decision=deny", <EventsPage />);
		expect(screen.getByRole("alert")).toHaveTextContent("Failed to load events");
		expect(screen.queryByText(/\d+ blocked/)).not.toBeInTheDocument();
		expect(screen.getByText("Event data is unavailable right now.")).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Export CSV" })).toBeDisabled();
		expect(screen.getByRole("button", { name: "Export JSON" })).toBeDisabled();
	});

	it("says no events match the filters instead of claiming the tenant has none", async () => {
		backend({ events: { data: [], error: null } });
		await renderAt("/events?type=plugin_scan", <EventsPage />);
		expect(screen.getByText("No events match these filters.")).toBeInTheDocument();
		expect(screen.queryByText(/No events received yet/)).not.toBeInTheDocument();
	});
});

describe("Agent detail health", () => {
	const detail = { ...agent(agentId, "laptop", NOW - 60_000), tenant_id: tenantId };

	it("shows connector protection states and links to the agent's events", async () => {
		backend({
			agents: { data: detail, error: null },
			entitlement_snapshots: { data: null, error: null },
			events: { data: [], error: null },
			connector_heartbeats: {
				data: [
					{
						connector: "claude-code",
						state: "protected",
						enforcement: "machine_policy",
						protection_locked: true,
						host_version: "2.0.1",
						reported_at: "2026-10-15T11:30:00Z",
						state_since: "2026-10-01T00:00:00Z",
					},
					{
						connector: "codex",
						state: "hook_untrusted",
						enforcement: "user_config",
						protection_locked: false,
						host_version: null,
						reported_at: "2026-10-15T11:30:00Z",
						state_since: "2026-10-14T00:00:00Z",
					},
				],
				error: null,
			},
		});
		await renderAt(`/agents/${agentId}`, <AgentDetailPage />, "/agents/:agentId");
		expect(screen.getByText("Protected")).toBeInTheDocument();
		expect(screen.getByText("Hook not trusted")).toBeInTheDocument();
		expect(screen.getByText("locked")).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "View all events from this agent" })).toHaveAttribute(
			"href",
			`/events?agent=${agentId}`,
		);
		expect(screen.queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
	});

	it("fails closed when connector heartbeats cannot be read", async () => {
		backend({
			agents: { data: detail, error: null },
			entitlement_snapshots: { data: null, error: null },
			events: { data: [], error: null },
			connector_heartbeats: { data: null, error: { message: "denied" } },
		});
		await renderAt(`/agents/${agentId}`, <AgentDetailPage />, "/agents/:agentId");
		expect(
			screen.getByText("Connector protection data is unavailable right now."),
		).toBeInTheDocument();
		expect(screen.queryByText("Protected")).not.toBeInTheDocument();
	});

	it("never prints an invented seat limit from a malformed entitlement snapshot", async () => {
		backend({
			agents: { data: detail, error: null },
			entitlement_snapshots: {
				data: { updated_at: "2026-10-15T00:00:00Z", entitlement: { subscription_tier: "team" } },
				error: null,
			},
			events: { data: [], error: null },
			connector_heartbeats: { data: [], error: null },
		});
		await renderAt(`/agents/${agentId}`, <AgentDetailPage />, "/agents/:agentId");
		const line = screen.getByText(/team/, { selector: ".mono" });
		expect(line.textContent).not.toMatch(/\b0\b/);
		expect(line).toHaveTextContent("unknown");
	});
});
