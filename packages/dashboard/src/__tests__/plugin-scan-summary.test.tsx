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
import { EventsPage } from "../ui/pages/EventsPage";
import { IncidentsPage } from "../ui/pages/IncidentsPage";
import { pluginScanFindingsCount, pluginScanSummary } from "../ui/plugin-scan";

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

const scan = (id: number, payload: Record<string, unknown>) => ({
	id,
	type: "plugin_scan",
	created_at: "2026-09-25T10:00:00Z",
	agent_id: "agent-1",
	payload,
});

beforeEach(() => {
	vi.resetAllMocks();
	(useTeam as ReturnType<typeof vi.fn>).mockReturnValue({
		currentTeam: { id: "11111111-1111-4111-8111-111111111111" },
		isLoading: false,
	});
});
afterEach(() => cleanup());

describe("plugin scan finding counts", () => {
	it.each([
		[{ findings_count: 0 }, 0],
		[{ findings_count: 3 }, 3],
		[{}, null],
		[{ findings_count: null }, null],
		[{ findings_count: "3" }, null],
		[{ findings_count: -1 }, null],
		[{ findings_count: 1.5 }, null],
		[{ findings_count: Number.NaN }, null],
		[{ findings_count: Number.POSITIVE_INFINITY }, null],
	])("reads %j as %s", (payload, expected) => {
		expect(pluginScanFindingsCount(payload)).toBe(expected);
	});

	it("never turns a missing count into a clean-looking zero", () => {
		expect(pluginScanSummary({ plugin_key: "acme" })).toBe("acme: finding count unavailable");
		expect(pluginScanSummary(null)).toBe("plugin: finding count unavailable");
		expect(pluginScanSummary({ plugin_key: "acme", findings_count: 0 })).toBe("acme: 0 finding(s)");
		expect(pluginScanSummary({ plugin_key: "acme", findings_count: 2 })).toBe("acme: 2 finding(s)");
	});

	it("labels an unknown count in the events feed", async () => {
		from.mockImplementation((table: string) =>
			query(
				table === "events"
					? [
							scan(1, { plugin_key: "unknown-count" }),
							scan(2, { plugin_key: "clean", findings_count: 0 }),
						]
					: [],
			),
		);
		render(
			<MemoryRouter>
				<EventsPage />
			</MemoryRouter>,
		);
		expect(await screen.findByText("unknown-count: finding count unavailable")).toBeInTheDocument();
		expect(screen.getByText("clean: 0 finding(s)")).toBeInTheDocument();
	});

	it("keeps a plugin scan with an unknown count in the incident list for review", async () => {
		from.mockImplementation((table: string) =>
			query(
				table === "incident_events"
					? [
							scan(1, { plugin_key: "unknown-count" }),
							scan(2, { plugin_key: "clean", findings_count: 0 }),
							scan(3, { plugin_key: "risky", findings_count: 4 }),
						]
					: [],
			),
		);
		render(
			<MemoryRouter>
				<IncidentsPage />
			</MemoryRouter>,
		);
		expect(await screen.findByText("unknown-count: finding count unavailable")).toBeInTheDocument();
		expect(screen.getByText("risky: 4 finding(s)")).toBeInTheDocument();
		expect(screen.queryByText("clean: 0 finding(s)")).not.toBeInTheDocument();
	});
});
