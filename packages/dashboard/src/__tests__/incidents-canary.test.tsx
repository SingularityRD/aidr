// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: { from: vi.fn(), functions: { invoke: vi.fn() } },
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { IncidentsPage, isCanaryTrigger } from "../ui/pages/IncidentsPage";

const from = supabase.from as ReturnType<typeof vi.fn>;

function query(data: unknown) {
	const chain = {
		select: vi.fn(),
		order: vi.fn(),
		limit: vi.fn(),
		eq: vi.fn(),
		then: (resolve: (value: unknown) => unknown) =>
			Promise.resolve({ data, error: null }).then(resolve),
	};
	for (const method of ["select", "order", "limit", "eq"] as const) {
		chain[method].mockReturnValue(chain);
	}
	return chain;
}

beforeEach(() => {
	vi.resetAllMocks();
	(useTeam as ReturnType<typeof vi.fn>).mockReturnValue({
		currentTeam: { id: "11111111-1111-4111-8111-111111111111" },
		isLoading: false,
	});
});
afterEach(() => cleanup());

describe("canary incidents", () => {
	it("recognises canary triggers by source or rule id only", () => {
		expect(isCanaryTrigger({ payload: { source: "canary" } })).toBe(true);
		expect(isCanaryTrigger({ payload: { matched_threat_id: "AIDR-CANARY-002" } })).toBe(true);
		expect(isCanaryTrigger({ payload: { matched_threat_id: "OUT-CANARY-001" } })).toBe(true);
		expect(
			isCanaryTrigger({ payload: { source: "heuristic", matched_threat_id: "CLT-SELF-008" } }),
		).toBe(false);
		expect(isCanaryTrigger({ payload: { matched_threat_id: "AIDR-CANARY-001x" } })).toBe(false);
	});

	it("labels canary incidents in the incident table", async () => {
		from.mockImplementation((table: string) =>
			query(
				table === "incident_events"
					? [
							{
								id: 1,
								type: "runtime_verdict",
								created_at: "2026-09-25T10:00:00Z",
								agent_id: "agent-1",
								payload: {
									tool_name: "Read",
									verdict: "deny",
									severity: "critical",
									source: "canary",
									matched_threat_id: "AIDR-CANARY-002",
								},
							},
							{
								id: 2,
								type: "runtime_verdict",
								created_at: "2026-09-25T10:01:00Z",
								agent_id: "agent-1",
								payload: { tool_name: "Bash", verdict: "deny", source: "heuristic" },
							},
						]
					: [],
			),
		);
		render(
			<MemoryRouter>
				<IncidentsPage />
			</MemoryRouter>,
		);
		expect(await screen.findByText("Read: blocked (critical)")).toBeInTheDocument();
		expect(screen.getAllByText("Canary triggered")).toHaveLength(1);
	});
});
