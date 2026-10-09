// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: { from: vi.fn(), functions: { invoke: vi.fn() } },
}));
vi.mock("../ui/session", () => ({ getSession: vi.fn().mockResolvedValue(null) }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => ({ currentTeam: { id: "tenant-1" } }) }));

import { supabase } from "../lib/supabase";
import { DASHBOARD_CONNECTED_WINDOW_MS } from "../ui/dashboard-freshness";
import { DashboardPage } from "../ui/pages/DashboardPage";

const now = Date.parse("2026-05-01T12:00:00.000Z");
const responses = vi.fn<(table: string) => unknown>();
const agent = (last_seen: string | null = new Date(now).toISOString()) => ({
	id: "agent-1",
	iid: "installation-1",
	display_name: "Test agent",
	agent_runtime: "codex",
	last_seen,
});
const event = {
	id: 1,
	type: "runtime_verdict",
	created_at: new Date(now).toISOString(),
	agent_id: "agent-1",
	payload: { tool_name: "bash", verdict: "deny" },
};
// The agent list is read with an exact count; a plain list needs count = its length.
const success = (data: unknown[], count = data.length) => ({ data, error: null, count });
const chains: Array<{ table: string; select: ReturnType<typeof vi.fn>; order: ReturnType<typeof vi.fn>; limit: ReturnType<typeof vi.fn> }> = [];

function counter(label: string) {
	const counters = screen.getByRole("region", { name: "Fleet counters" });
	return within(counters).getByText(label).parentElement?.querySelector(".stat-value");
}

function heartbeat() {
	return screen.getByText("Latest heartbeat").nextElementSibling;
}

async function showDashboard() {
	await act(async () => {
		render(<MemoryRouter><DashboardPage /></MemoryRouter>);
	});
}

async function advance(ms: number) {
	await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
}

describe("Dashboard freshness and availability", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(now);
		responses.mockReset().mockImplementation(() => success([]));
		vi.mocked(supabase.functions.invoke).mockReset().mockResolvedValue({
			data: { ok: true, tokens: [] }, error: null,
		});
		chains.length = 0;
		vi.mocked(supabase.from).mockReset().mockImplementation((table: string) => {
			const chain = {
				table,
				select: vi.fn(), eq: vi.fn(), order: vi.fn(), limit: vi.fn(),
				then(resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) {
					return Promise.resolve().then(() => responses(table)).then(resolve, reject);
				},
			};
			for (const method of ["select", "eq", "order", "limit"] as const) chain[method].mockReturnValue(chain);
			chains.push(chain);
			return chain as unknown as ReturnType<typeof supabase.from>;
		});
	});

	afterEach(() => {
		cleanup();
		expect(vi.getTimerCount()).toBe(0);
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	it("shows zero and empty messages only for successful empty results", async () => {
		await showDashboard();
		for (const label of ["Agents", "Connected", "Pending", "Events", "Deny", "Ask"]) {
			expect(counter(label)).toHaveTextContent(/^0$/);
		}
		expect(heartbeat()).toHaveTextContent("no agents yet");
		expect(screen.getByText(/No agents yet\. Use/)).toBeInTheDocument();
		expect(screen.getByText("No events recorded yet.")).toBeInTheDocument();
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
	});

	it("does not expose arbitrary event payloads in the dashboard summary", async () => {
		const canary = "private-payload-canary-4c08";
		responses.mockImplementation((table) => success(table === "events" ? [{
			...event, type: "future_event", payload: { nested: { secret: canary } },
		}] : []));
		await showDashboard();
		expect(screen.getByText("Additional event details are not shown.")).toBeInTheDocument();
		expect(document.body.textContent).not.toContain(canary);
	});

	it("does not show empty or healthy counts before queries settle", async () => {
		responses.mockImplementation(() => new Promise(() => {}));
		await showDashboard();
		for (const label of ["Agents", "Connected", "Events", "Deny", "Ask"]) {
			expect(counter(label)).toHaveTextContent("—");
		}
		expect(heartbeat()).toHaveTextContent("unavailable");
		expect(screen.queryByText(/No agents yet\. Use/)).not.toBeInTheDocument();
		expect(screen.queryByText("No events recorded yet.")).not.toBeInTheDocument();
	});

	it.each([
		["null data", { data: null, error: null }],
		["missing data", { error: null }],
		["object data", { data: {}, error: null }],
		["malformed rows", { data: [null], error: null }],
		["missing row fields", { data: [{}], error: null }],
		["missing error acknowledgement", { data: [] }],
		["missing response", undefined],
		["failure with data", { data: [], error: { message: "Query failed" } }],
	])("treats %s as unavailable rather than an empty fleet", async (_label, result) => {
		responses.mockReturnValue(result);
		await showDashboard();
		for (const label of ["Agents", "Connected", "Events", "Deny", "Ask"]) {
			expect(counter(label)).toHaveTextContent("—");
		}
		expect(screen.getByRole("alert")).toBeInTheDocument();
		expect(screen.getByText("Agent data is unavailable right now.")).toBeInTheDocument();
		expect(screen.getByText("Event data is unavailable right now.")).toBeInTheDocument();
		expect(heartbeat()).toHaveTextContent("unavailable");
	});

	it("ages count and row together across the inclusive boundary without new data", async () => {
		const rows = [agent(new Date(now - DASHBOARD_CONNECTED_WINDOW_MS).toISOString())];
		responses.mockImplementation((table) => success(table === "agents" ? rows : []));
		await showDashboard();
		expect(counter("Connected")).toHaveTextContent(/^1$/);
		expect(screen.getByText("connected")).toHaveClass("badge-success");

		await advance(1000); // The next data poll is not due yet.
		expect(responses).toHaveBeenCalledTimes(2);
		expect(counter("Connected")).toHaveTextContent(/^0$/);
		expect(screen.getByText("stale")).toHaveClass("badge-neutral");
		expect(screen.queryByText("connected")).not.toBeInTheDocument();

		await advance(5000); // Poll returns the exact same array reference.
		expect(counter("Connected")).toHaveTextContent(/^0$/);
		expect(screen.getByText("stale")).toBeInTheDocument();
	});

	it("keeps aging while a poll hangs and does not overlap that source's requests", async () => {
		responses.mockImplementation((table) => success(table === "agents"
			? [agent(new Date(now - DASHBOARD_CONNECTED_WINDOW_MS + 6500).toISOString())] : []));
		await showDashboard();
		responses.mockImplementation((table) => table === "agents" ? new Promise(() => {}) : success([]));
		await advance(6000);
		expect(counter("Connected")).toHaveTextContent(/^1$/);
		await advance(1000);
		expect(counter("Connected")).toHaveTextContent(/^0$/);
		expect(screen.getByText("stale")).toBeInTheDocument();
		await advance(12000);
		expect(responses.mock.calls.filter(([table]) => table === "agents")).toHaveLength(2);
	});

	it("times out hanging sources, retries, and ignores their late healthy responses", async () => {
		responses.mockImplementation((table) => success(table === "agents" ? [agent()] : [event]));
		await showDashboard();
		let resolveLate: (value: unknown) => void = () => {};
		const hanging = new Promise((resolve) => { resolveLate = resolve; });
		responses.mockReturnValue(hanging);
		vi.mocked(supabase.functions.invoke).mockImplementation(() => hanging as ReturnType<typeof supabase.functions.invoke>);
		await advance(21_000); // A poll starts at 6s and reaches its 15s deadline.
		for (const label of ["Agents", "Connected", "Events", "Deny", "Ask", "Pending"]) {
			expect(counter(label)).toHaveTextContent("—");
		}
		expect(screen.getByRole("alert")).toHaveTextContent("Dashboard query timed out.");
		responses.mockReturnValue(success([]));
		vi.mocked(supabase.functions.invoke).mockResolvedValue({ data: { ok: true, tokens: [] }, error: null });
		await advance(3000); // Next regular poll recovers without waiting for the old read.
		expect(counter("Connected")).toHaveTextContent(/^0$/);
		expect(counter("Events")).toHaveTextContent(/^0$/);
		expect(counter("Pending")).toHaveTextContent(/^0$/);
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
		await act(async () => { resolveLate(success([agent()])); });
		expect(counter("Connected")).toHaveTextContent(/^0$/);
		expect(counter("Events")).toHaveTextContent(/^0$/);
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
	});

	it.each(["not-a-timestamp", null, new Date(now + 60_000).toISOString()])(
		"keeps an existing agent with heartbeat %s distinct from no agents",
		async (stamp) => {
			responses.mockImplementation((table) => success(table === "agents" ? [agent(stamp)] : []));
			await showDashboard();
			expect(counter("Agents")).toHaveTextContent(/^1$/);
			expect(counter("Connected")).toHaveTextContent(/^0$/);
			expect(screen.getByText("Test agent")).toBeInTheDocument();
			const row = screen.getByRole("row", { name: /Test agent/ });
			expect(within(row).getByText(stamp?.startsWith("2026") ? "stale" : "unknown")).toHaveClass("badge-neutral");
			expect(heartbeat()).toHaveTextContent("unavailable");
			expect(screen.queryByText("no agents yet")).not.toBeInTheDocument();
		},
	);

	it("uses the newest valid nonfuture heartbeat even if the first row is invalid", async () => {
		const validStamp = new Date(now - 1000).toISOString();
		responses.mockImplementation((table) => success(table === "agents" ? [
			{ ...agent(new Date(now + 60_000).toISOString()), id: "future" },
			{ ...agent("invalid"), id: "invalid" },
			agent(validStamp),
		] : []));
		await showDashboard();
		expect(counter("Agents")).toHaveTextContent(/^3$/);
		expect(counter("Connected")).toHaveTextContent(/^1$/);
		expect(heartbeat()).toHaveTextContent(new Date(validStamp).toLocaleString());
	});

	it.each(["rejection", "malformed response", "failed response"])(
		"clears previously healthy data on %s and recovers on the next success", async (failure) => {
		responses.mockImplementation((table) => success(table === "agents" ? [agent()] : [event]));
		await showDashboard();
		expect(counter("Connected")).toHaveTextContent(/^1$/);
		expect(counter("Deny")).toHaveTextContent(/^1$/);
		if (failure === "rejection") {
			responses.mockRejectedValue(new Error("Network unavailable"));
		} else if (failure === "malformed response") {
			responses.mockReturnValue({ data: null, error: null });
		} else {
			responses.mockImplementation((table) => ({
				data: table === "agents" ? [agent()] : [event],
				error: { message: "Network unavailable" },
			}));
		}
		await advance(6000);
		for (const label of ["Agents", "Connected", "Events", "Deny", "Ask"]) {
			expect(counter(label)).toHaveTextContent("—");
		}
		expect(screen.queryByText("connected")).not.toBeInTheDocument();
		expect(screen.queryByText("bash: deny")).not.toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent(
			failure === "malformed response"
				? "Malformed dashboard query response."
				: failure === "rejection"
					? "Network unavailable"
					: "Dashboard query failed.",
		);

		responses.mockReturnValue(success([]));
		await advance(6000);
		expect(counter("Connected")).toHaveTextContent(/^0$/);
		expect(counter("Deny")).toHaveTextContent(/^0$/);
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
	});

	it("clears a failed source even when the other source is hanging", async () => {
		responses.mockImplementation((table) => success(table === "agents" ? [agent()] : [event]));
		await showDashboard();
		responses.mockImplementation((table) => table === "agents"
			? Promise.reject(new Error("Agents offline")) : new Promise(() => {}));
		await advance(6000);
		expect(counter("Connected")).toHaveTextContent("—");
		expect(screen.getByRole("alert")).toHaveTextContent("Agents offline");
		expect(counter("Events")).toHaveTextContent(/^1$/);
	});

	it("plugin scans without a finding count do not read as clean", async () => {
		responses.mockImplementation((table) => success(table === "events" ? [
			{ ...event, id: 2, type: "plugin_scan", payload: { plugin_key: "acme-plugin" } },
			{ ...event, id: 3, type: "plugin_scan", payload: { plugin_key: "clean-plugin", findings_count: 0 } },
		] : []));
		await showDashboard();
		expect(screen.getByText("acme-plugin: finding count unavailable")).toBeInTheDocument();
		expect(screen.getByText("clean-plugin: 0 finding(s)")).toBeInTheDocument();
		expect(screen.queryByText("acme-plugin: 0 finding(s)")).not.toBeInTheDocument();
	});

	it("reads agents as an explicit, exactly counted page newest heartbeat first", async () => {
		await showDashboard();
		const agentChain = chains.find((chain) => chain.table === "agents");
		expect(agentChain?.select).toHaveBeenCalledWith(expect.any(String), { count: "exact" });
		expect(agentChain?.order).toHaveBeenCalledWith("last_seen", { ascending: false, nullsFirst: false });
		expect(agentChain?.limit).toHaveBeenCalledWith(1000);
	});

	it("shows the exact agent total beyond the 1000-row page", async () => {
		const staleTail = agent(new Date(now - DASHBOARD_CONNECTED_WINDOW_MS - 1).toISOString());
		responses.mockImplementation((table) => table === "agents"
			? success([agent(), { ...staleTail, id: "agent-2" }], 1500) : success([]));
		await showDashboard();
		expect(counter("Agents")).toHaveTextContent(/^1500$/);
		// The page ends with a stale heartbeat, so no connected agent lies beyond it.
		expect(counter("Connected")).toHaveTextContent(/^1$/);
		expect(screen.queryByText(/at least; latest 1000 heartbeats/)).not.toBeInTheDocument();
	});

	it("marks the connected count as a lower bound when the page may cut off connected agents", async () => {
		responses.mockImplementation((table) => table === "agents"
			? success([agent(), { ...agent(), id: "agent-2" }], 1500) : success([]));
		await showDashboard();
		expect(counter("Agents")).toHaveTextContent(/^1500$/);
		expect(counter("Connected")).toHaveTextContent(/^2\+$/);
		expect(screen.getByText("at least; latest 1000 heartbeats")).toBeInTheDocument();
	});

	it.each([
		["a missing count", { data: [], error: null }],
		["a count below the returned rows", { data: [agent()], error: null, count: 0 }],
		["a non-numeric count", { data: [], error: null, count: "12" }],
	])("treats an agent page with %s as unavailable", async (_label, result) => {
		responses.mockImplementation((table) => table === "agents" ? result : success([]));
		await showDashboard();
		expect(counter("Agents")).toHaveTextContent("—");
		expect(counter("Connected")).toHaveTextContent("—");
		expect(screen.getByRole("alert")).toHaveTextContent("Malformed dashboard query response.");
		expect(counter("Events")).toHaveTextContent(/^0$/);
	});

	it.each([
		{ expires_at: "invalid" },
		{ consumed_at: "invalid", expires_at: new Date(now + 60_000).toISOString() },
		{ consumed_at: "", expires_at: new Date(now + 60_000).toISOString() },
	])("does not turn malformed enrollment token %j into zero pending approvals", async (token) => {
		vi.mocked(supabase.functions.invoke).mockResolvedValue({
			data: { ok: true, tokens: [token] }, error: null,
		});
		await showDashboard();
		expect(counter("Pending")).toHaveTextContent("—");
		expect(counter("Agents")).toHaveTextContent(/^0$/);
	});

	it("reports when pending enrollment data is unavailable instead of leaving an unexplained dash", async () => {
		vi.mocked(supabase.functions.invoke).mockRejectedValue(new Error("Dashboard query failed."));
		await showDashboard();
		expect(counter("Pending")).toHaveTextContent("—");
		expect(screen.getByRole("alert")).toHaveTextContent("Dashboard query failed.");
	});
});
