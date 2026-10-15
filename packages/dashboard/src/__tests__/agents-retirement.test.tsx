// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn(), functions: { invoke: vi.fn() } } }));

import { useTeam } from "../enterprise/team-provider";
import { lifecycleErrorKey, setAutoRetire, validAutoRetireDays } from "../lib/agent-lifecycle";
import { supabase } from "../lib/supabase";
import { AgentsPage } from "../ui/pages/AgentsPage";

const tenantId = "11111111-1111-4111-8111-111111111111";
const activeAgent = {
	id: "22222222-2222-4222-8222-222222222222",
	iid: "installation-1",
	display_name: "Active workstation",
	agent_runtime: "claude-code",
	agent_runtime_version: "1.0.0",
	first_seen: "2026-09-23T00:00:00Z",
	last_seen: "2026-09-23T00:01:00Z",
	retired_at: null,
	retired_reason: null,
};
const retiredAgent = {
	...activeAgent,
	id: "33333333-3333-4333-8333-333333333333",
	iid: "installation-2",
	display_name: "Reimaged laptop",
	retired_at: "2026-10-01T00:00:00Z",
	retired_reason: "offline",
};

function configure({ autoRetire = 30 as number | null } = {}) {
	vi.mocked(supabase.from).mockImplementation((table: string) => {
		const select = vi.fn();
		const eq = vi.fn();
		const query = {
			select,
			eq,
			order: vi.fn(() => Promise.resolve({ data: [activeAgent, retiredAgent], error: null })),
			maybeSingle: vi.fn(() =>
				Promise.resolve(
					table === "seat_usage"
						? {
								data: { included_agents: 2, extra_agents: 0, allowed_agents: 2, retired_agents: 1 },
								error: null,
							}
						: { data: { auto_retire_offline_days: autoRetire }, error: null },
				),
			),
		};
		select.mockReturnValue(query);
		eq.mockReturnValue(query);
		return query as unknown as ReturnType<typeof supabase.from>;
	});
}

async function renderPage() {
	await act(async () => {
		render(
			<MemoryRouter>
				<AgentsPage />
			</MemoryRouter>,
		);
	});
}

describe("agent retirement in the Agents page", () => {
	beforeEach(() => {
		vi.mocked(supabase.from).mockReset();
		vi.mocked(supabase.functions.invoke).mockReset();
	});
	afterEach(() => cleanup());

	it("shows active and retired agents, counts only active ones and offers Retire to admins", async () => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantId, name: "Customer" },
			canManageTeam: true,
		} as never);
		configure();
		await renderPage();
		const active = screen.getByText("Active workstation").closest("tr") as HTMLElement;
		const retired = screen.getByText("Reimaged laptop").closest("tr") as HTMLElement;
		expect(within(active).getByText("Active")).toBeInTheDocument();
		expect(within(retired).getByText("Retired (offline)")).toBeInTheDocument();
		expect(within(active).getByRole("button", { name: "Retire" })).toBeInTheDocument();
		expect(within(retired).queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
		expect(document.body.textContent).toContain("Recorded: 1.");
		expect(document.body.textContent).toContain("Retired (no seat): 1.");
		expect(document.querySelector("[data-auto-retire]")).toHaveTextContent(
			"Current setting: 30 days",
		);
	});

	it("retires only after confirmation and reports the revoked device keys", async () => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantId, name: "Customer" },
			canManageTeam: true,
		} as never);
		configure();
		vi.mocked(supabase.functions.invoke).mockResolvedValue({
			data: { ok: true, status: "retired", agent_id: activeAgent.id, revoked_keys: 1 },
			error: null,
		} as never);
		await renderPage();
		const row = screen.getByText("Active workstation").closest("tr") as HTMLElement;
		fireEvent.click(within(row).getByRole("button", { name: "Retire" }));
		expect(supabase.functions.invoke).not.toHaveBeenCalled();
		expect(
			within(row).getByText(/Its seat is freed and its device key is revoked/),
		).toBeInTheDocument();
		await act(async () => {
			fireEvent.click(within(row).getByRole("button", { name: "Retire device" }));
		});
		expect(supabase.functions.invoke).toHaveBeenCalledWith("agent-lifecycle", {
			body: { action: "retire", tenant_id: tenantId, agent_id: activeAgent.id },
		});
	});

	it("hides Retire and the auto-retirement form from members", async () => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantId, name: "Customer" },
			canManageTeam: false,
		} as never);
		configure({ autoRetire: null });
		await renderPage();
		expect(screen.queryByRole("button", { name: "Retire" })).not.toBeInTheDocument();
		expect(
			screen.getByText("Only workspace owners and admins can change this."),
		).toBeInTheDocument();
		expect(document.querySelector("[data-auto-retire]")).toHaveTextContent("Current setting: Off");
	});

	it("rejects out-of-range auto-retirement before calling the server", async () => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: tenantId, name: "Customer" },
			canManageTeam: true,
		} as never);
		configure();
		await renderPage();
		const input = screen.getByRole("spinbutton");
		fireEvent.change(input, { target: { value: "3" } });
		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Save" }));
		});
		expect(screen.getByRole("alert")).toHaveTextContent("Enter a whole number between 7 and 365");
		expect(supabase.functions.invoke).not.toHaveBeenCalled();
		expect(validAutoRetireDays(null)).toBe(true);
		expect(validAutoRetireDays(366)).toBe(false);
		expect(await setAutoRetire(tenantId, 6)).toEqual({ ok: false, code: "invalid_days" });
		expect(lifecycleErrorKey("mfa_required")).toBe("agents.retire.err.mfa");
		expect(lifecycleErrorKey("something_new")).toBe("agents.retire.err.unavailable");
	});
});
