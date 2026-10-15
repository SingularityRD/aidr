// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: { from: vi.fn(), functions: { invoke: vi.fn() } },
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { AgentDetailPage } from "../ui/pages/AgentDetailPage";
import { AutoSecOpsPage } from "../ui/pages/AutoSecOpsPage";
import { EventsPage } from "../ui/pages/EventsPage";
import { IncidentsPage } from "../ui/pages/IncidentsPage";

const from = supabase.from as ReturnType<typeof vi.fn>;
const invoke = supabase.functions.invoke as ReturnType<typeof vi.fn>;
const mockedUseTeam = useTeam as ReturnType<typeof vi.fn>;
const selectedTeamId = "11111111-1111-4111-8111-111111111111";

type QueryResult = { data: unknown; error: { message: string; code?: string } | null };

function query(result: () => QueryResult | Promise<QueryResult>) {
	const chain = {
		select: vi.fn(),
		order: vi.fn(),
		limit: vi.fn(),
		eq: vi.fn(),
		maybeSingle: vi.fn(() => Promise.resolve(result())),
		then: (resolve: (value: QueryResult) => unknown, reject?: (reason: unknown) => unknown) =>
			Promise.resolve().then(result).then(resolve, reject),
	};
	for (const method of ["select", "order", "limit", "eq"] as const) {
		chain[method].mockReturnValue(chain);
	}
	return chain;
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((accept) => {
		resolve = accept;
	});
	return { promise, resolve };
}

beforeEach(() => {
	vi.resetAllMocks();
	mockedUseTeam.mockReturnValue({
		currentTeam: { id: selectedTeamId },
		teams: [{ id: selectedTeamId, name: "Selected" }],
		isLoading: false,
		switchTeam: vi.fn(),
	});
});
afterEach(() => {
	cleanup();
	vi.useRealTimers();
});

describe("customer response pages", () => {
	it("does not query event or incident data without a selected team", () => {
		mockedUseTeam.mockReturnValue({
			currentTeam: null,
			teams: [],
			isLoading: false,
			switchTeam: vi.fn(),
		});
		render(
			<MemoryRouter>
				<EventsPage />
				<IncidentsPage />
			</MemoryRouter>,
		);
		expect(screen.getByText("Select a team to view events.")).toBeInTheDocument();
		expect(screen.getByText("Select a team to view incidents.")).toBeInTheDocument();
		expect(from).not.toHaveBeenCalled();
	});

	it("scopes both feeds and clears the former team's rows on selection change", async () => {
		const otherTeamId = "22222222-2222-4222-8222-222222222222";
		let selected = selectedTeamId;
		const scopes: string[] = [];
		mockedUseTeam.mockImplementation(() => ({ currentTeam: { id: selected }, isLoading: false }));
		from.mockImplementation((table: string) => {
			let scope = "";
			const chain = query(() =>
				table === "events" || table === "incident_events"
					? {
							data: [
								{
									id: table === "events" ? 11 : 12,
									type: "runtime_verdict",
									created_at: "2026-09-23T12:00:00Z",
									agent_id: "agent-1",
									payload: {
										tool_name: `${scope === selectedTeamId ? "first" : "second"}-${table}`,
										verdict: table === "events" ? "allow" : "deny",
									},
								},
							],
							error: null,
						}
					: { data: [], error: null },
			);
			chain.eq.mockImplementation((column: string, value: string) => {
				if (column === "tenant_id") {
					scope = value;
					scopes.push(`${table}:${value}`);
				}
				return chain;
			});
			return chain;
		});

		const page = render(
			<MemoryRouter>
				<EventsPage />
				<IncidentsPage />
			</MemoryRouter>,
		);
		expect(await screen.findByText("first-events")).toBeInTheDocument();
		expect(screen.getByText("first-incident_events: blocked")).toBeInTheDocument();
		selected = otherTeamId;
		page.rerender(
			<MemoryRouter>
				<EventsPage />
				<IncidentsPage />
			</MemoryRouter>,
		);
		expect(screen.queryByText("first-events")).not.toBeInTheDocument();
		expect(screen.queryByText("first-incident_events: blocked")).not.toBeInTheDocument();
		expect(await screen.findByText("second-events")).toBeInTheDocument();
		expect(screen.getByText("second-incident_events: blocked")).toBeInTheDocument();
		for (const table of ["events", "incident_events", "agents"]) {
			expect(scopes).toContain(`${table}:${selectedTeamId}`);
			expect(scopes).toContain(`${table}:${otherTeamId}`);
		}
	});

	it("keeps the incident fallback query inside the selected team", async () => {
		const fallbackQuery = query(() => ({ data: [], error: null }));
		from.mockImplementation((table: string) =>
			table === "incident_events"
				? query(() => ({ data: null, error: { code: "PGRST205", message: "view missing" } }))
				: table === "events"
					? fallbackQuery
					: query(() => ({ data: [], error: null })),
		);
		render(
			<MemoryRouter>
				<IncidentsPage />
			</MemoryRouter>,
		);
		await waitFor(() => expect(from).toHaveBeenCalledWith("events"));
		expect(fallbackQuery.eq).toHaveBeenCalledWith("tenant_id", selectedTeamId);
	});

	it("removes stale event decisions when the next poll fails", async () => {
		vi.useFakeTimers();
		let reads = 0;
		from.mockImplementation((table: string) =>
			query(() =>
				table === "events"
					? ++reads === 1
						? {
								data: [
									{
										id: 1,
										type: "runtime_verdict",
										created_at: "2026-09-23T12:00:00Z",
										agent_id: "agent-1",
										payload: { tool_name: "bash", verdict: "deny" },
									},
								],
								error: null,
							}
						: { data: null, error: { message: "private backend detail" } }
					: { data: [], error: null },
			),
		);

		render(
			<MemoryRouter>
				<EventsPage />
			</MemoryRouter>,
		);
		await act(async () => {
			await Promise.resolve();
		});
		expect(screen.getByText("1 blocked")).toBeInTheDocument();
		await act(async () => {
			await vi.advanceTimersByTimeAsync(6000);
		});
		expect(screen.getByText("Event data is unavailable right now.")).toBeInTheDocument();
		expect(screen.queryByText("1 blocked")).not.toBeInTheDocument();
		expect(screen.queryByText("bash")).not.toBeInTheDocument();
	});

	it("removes stale incidents and counts when the next poll fails", async () => {
		vi.useFakeTimers();
		let reads = 0;
		from.mockImplementation((table: string) =>
			query(() =>
				table === "incident_events"
					? ++reads === 1
						? {
								data: [
									{
										id: 2,
										type: "runtime_verdict",
										created_at: "2026-09-23T12:00:00Z",
										agent_id: "agent-1",
										payload: { tool_name: "bash", verdict: "deny", severity: "critical" },
									},
								],
								error: null,
							}
						: { data: null, error: { message: "private backend detail" } }
					: { data: [], error: null },
			),
		);

		render(
			<MemoryRouter>
				<IncidentsPage />
			</MemoryRouter>,
		);
		await act(async () => {
			await Promise.resolve();
		});
		expect(screen.getByText("1 blocked")).toBeInTheDocument();
		await act(async () => {
			await vi.advanceTimersByTimeAsync(6000);
		});
		expect(screen.getByText("Incident data is unavailable right now.")).toBeInTheDocument();
		expect(screen.queryByText("1 blocked")).not.toBeInTheDocument();
		expect(screen.queryByText("bash: blocked (critical)")).not.toBeInTheDocument();
	});

	it.each([
		["events", EventsPage, "Event data is unavailable right now."],
		["incidents", IncidentsPage, "Incident data is unavailable right now."],
	] as const)(
		"treats a null %s feed as unavailable, not empty",
		async (_name, Page, unavailable) => {
			from.mockImplementation((table: string) =>
				query(() => ({ data: table === "agents" ? [] : null, error: null })),
			);
			render(
				<MemoryRouter>
					<Page />
				</MemoryRouter>,
			);
			expect(await screen.findByText(unavailable)).toBeInTheDocument();
			expect(screen.queryByText("No incidents yet.")).not.toBeInTheDocument();
			expect(
				screen.queryByText(
					"No events received yet. Check agent enrollment and telemetry delivery.",
				),
			).not.toBeInTheDocument();
		},
	);

	it("distinguishes a missing agent from loading", async () => {
		from.mockImplementation((table: string) =>
			query(() => (table === "agents" ? { data: null, error: null } : { data: [], error: null })),
		);
		render(
			<MemoryRouter initialEntries={["/agents/missing"]}>
				<Routes>
					<Route path="/agents/:agentId" element={<AgentDetailPage />} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Agent not found.")).toBeInTheDocument();
		expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
	});

	it("does not turn a malformed event response for an existing agent into no events", async () => {
		from.mockImplementation((table: string) =>
			query(() =>
				table === "agents"
					? {
							data: {
								id: "agent-1",
								tenant_id: selectedTeamId,
								iid: "iid-1",
								display_name: "Agent one",
							},
							error: null,
						}
					: { data: null, error: null },
			),
		);
		render(
			<MemoryRouter initialEntries={["/agents/agent-1"]}>
				<Routes>
					<Route path="/agents/:agentId" element={<AgentDetailPage />} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Event data is unavailable right now.")).toBeInTheDocument();
		expect(screen.queryByText("No events yet.")).not.toBeInTheDocument();
	});

	it("does not print arbitrary agent event payloads", async () => {
		const canary = "private-payload-canary-4c08";
		const tenantId = selectedTeamId;
		const snapshotQuery = query(() => ({ data: null, error: null }));
		from.mockImplementation((table: string) =>
			table === "entitlement_snapshots"
				? snapshotQuery
				: query(() =>
						table === "agents"
							? {
									data: {
										id: "agent-1",
										tenant_id: tenantId,
										iid: "iid-1",
										display_name: "Agent one",
										agent_runtime: "codex",
										agent_runtime_version: "1",
										last_seen: "2026-09-23T12:00:00Z",
									},
									error: null,
								}
							: table === "events"
								? {
										data: [
											{
												id: 5,
												type: "future_event",
												created_at: "2026-09-23T12:00:00Z",
												payload: { nested: { secret: canary } },
											},
										],
										error: null,
									}
								: { data: null, error: null },
					),
		);
		render(
			<MemoryRouter initialEntries={["/agents/agent-1"]}>
				<Routes>
					<Route path="/agents/:agentId" element={<AgentDetailPage />} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Agent one")).toBeInTheDocument();
		await waitFor(() => expect(snapshotQuery.eq).toHaveBeenCalledWith("tenant_id", tenantId));
		expect(snapshotQuery.eq).toHaveBeenCalledWith("iid", "iid-1");
		expect(screen.getByText("Additional event details are not shown.")).toBeInTheDocument();
		expect(document.body.textContent).not.toContain(canary);
	});

	it("does not show a manually addressed agent from another selected team", async () => {
		const foreignTenantId = "22222222-2222-4222-8222-222222222222";
		const agentQuery = query(() => ({
			data: {
				id: "foreign-agent",
				tenant_id: foreignTenantId,
				iid: "shared-iid",
				display_name: "Foreign agent",
			},
			error: null,
		}));
		const eventsQuery = query(() => ({
			data: [
				{
					id: 99,
					type: "runtime_verdict",
					created_at: "2026-09-23T12:00:00Z",
					payload: { tool_name: "foreign-tool", verdict: "deny" },
				},
			],
			error: null,
		}));
		from.mockImplementation((table: string) =>
			table === "agents"
				? agentQuery
				: table === "events"
					? eventsQuery
					: query(() => ({ data: null, error: null })),
		);
		render(
			<MemoryRouter initialEntries={["/agents/foreign-agent"]}>
				<Routes>
					<Route path="/agents/:agentId" element={<AgentDetailPage />} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Agent not found.")).toBeInTheDocument();
		expect(agentQuery.eq).toHaveBeenCalledWith("tenant_id", selectedTeamId);
		expect(eventsQuery.eq).toHaveBeenCalledWith("tenant_id", selectedTeamId);
		expect(from).not.toHaveBeenCalledWith("entitlement_snapshots");
		expect(document.body.textContent).not.toContain("Foreign agent");
		expect(document.body.textContent).not.toContain("foreign-tool");
	});

	it("finishes agent loading with an unavailable state after a network rejection", async () => {
		from.mockImplementation((table: string) =>
			query(() =>
				table === "events"
					? Promise.reject(new Error("private connection detail"))
					: { data: null, error: null },
			),
		);
		render(
			<MemoryRouter initialEntries={["/agents/agent-1"]}>
				<Routes>
					<Route path="/agents/:agentId" element={<AgentDetailPage />} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Agent data is unavailable right now.")).toBeInTheDocument();
		expect(screen.getByText("Event data is unavailable right now.")).toBeInTheDocument();
		expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
		expect(document.body.textContent).not.toContain("private connection detail");
	});

	it("does not display AutoSecOps data for a different team", async () => {
		const otherTeamId = "22222222-2222-4222-8222-222222222222";
		invoke.mockImplementation(async (_name: string, request: { body: { action: string } }) => ({
			data:
				request.body.action === "health"
					? {
							ok: true,
							provider: "autosecops",
							action: "health",
							team_id: otherTeamId,
							data: { snapshot: { state: "healthy", active_agents: 9 } },
						}
					: {
							ok: true,
							provider: "autosecops",
							action: "fleet",
							team_id: otherTeamId,
							data: { response: { items: [{ agent_id: "foreign", agent_name: "foreign-agent" }] } },
						},
			error: null,
		}));

		render(<AutoSecOpsPage />);
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("AutoSecOps health response is invalid."),
		);
		expect(screen.getByText("Fleet data is unavailable.")).toBeInTheDocument();
		expect(screen.queryByText("foreign-agent")).not.toBeInTheDocument();
		expect(screen.getAllByText("unknown").length).toBeGreaterThan(0);
	});

	it("hides the previous team's AutoSecOps result and ignores its late refresh", async () => {
		const firstTeam = "11111111-1111-4111-8111-111111111111";
		const secondTeam = "22222222-2222-4222-8222-222222222222";
		const oldHealth = deferred<unknown>();
		const oldFleet = deferred<unknown>();
		const newHealth = deferred<unknown>();
		const newFleet = deferred<unknown>();
		let firstTeamRequests = 0;
		let selectedTeam = firstTeam;
		mockedUseTeam.mockImplementation(() => ({
			currentTeam: { id: selectedTeam },
			teams: [
				{ id: firstTeam, name: "First" },
				{ id: secondTeam, name: "Second" },
			],
			isLoading: false,
			switchTeam: vi.fn(),
		}));
		invoke.mockImplementation(
			(_name: string, request: { body: { team_id: string; action: string } }) => {
				if (request.body.team_id === firstTeam) {
					if (++firstTeamRequests <= 2) {
						return Promise.resolve(
							request.body.action === "health"
								? {
										data: {
											ok: true,
											provider: "autosecops",
											action: "health",
											team_id: firstTeam,
											data: { snapshot: { state: "healthy", active_agents: 1 } },
										},
										error: null,
									}
								: {
										data: {
											ok: true,
											provider: "autosecops",
											action: "fleet",
											team_id: firstTeam,
											data: {
												response: { items: [{ agent_id: "agent-1", agent_name: "first-agent" }] },
											},
										},
										error: null,
									},
						);
					}
					return request.body.action === "health" ? oldHealth.promise : oldFleet.promise;
				}
				return request.body.action === "health" ? newHealth.promise : newFleet.promise;
			},
		);

		const page = render(<AutoSecOpsPage />);
		expect(await screen.findByText("first-agent")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
		await waitFor(() => expect(invoke).toHaveBeenCalledTimes(4));
		selectedTeam = secondTeam;
		page.rerender(<AutoSecOpsPage />);
		await waitFor(() => expect(invoke).toHaveBeenCalledTimes(6));
		expect(screen.queryByText("first-agent")).not.toBeInTheDocument();
		await act(async () => {
			oldHealth.resolve({
				data: {
					ok: true,
					provider: "autosecops",
					action: "health",
					team_id: firstTeam,
					data: { snapshot: { state: "healthy", active_agents: 1 } },
				},
				error: null,
			});
			oldFleet.resolve({
				data: {
					ok: true,
					provider: "autosecops",
					action: "fleet",
					team_id: firstTeam,
					data: { response: { items: [{ agent_id: "agent-1", agent_name: "first-agent" }] } },
				},
				error: null,
			});
		});
		expect(screen.queryByText("first-agent")).not.toBeInTheDocument();
		await act(async () => {
			newHealth.resolve({
				data: {
					ok: true,
					provider: "autosecops",
					action: "health",
					team_id: secondTeam,
					data: { snapshot: { state: "healthy", active_agents: 2 } },
				},
				error: null,
			});
			newFleet.resolve({
				data: {
					ok: true,
					provider: "autosecops",
					action: "fleet",
					team_id: secondTeam,
					data: { response: { items: [{ agent_id: "agent-2", agent_name: "second-agent" }] } },
				},
				error: null,
			});
		});
		expect(screen.getByText("second-agent")).toBeInTheDocument();
	});
});
