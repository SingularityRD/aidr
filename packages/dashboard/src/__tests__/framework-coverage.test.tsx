// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn() } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import artifact from "../generated/framework-coverage.json";
import { supabase } from "../lib/supabase";
import {
	FrameworkCoverageSection,
	FrameworkTags,
	frameworksForRule,
} from "../ui/framework-coverage";
import { EventsPage } from "../ui/pages/EventsPage";
import { IncidentsPage } from "../ui/pages/IncidentsPage";

afterEach(cleanup);

function query(data: unknown) {
	const result = { data, error: null };
	const chain: Record<string, unknown> = {
		then: (resolve: (value: unknown) => unknown) => Promise.resolve(result).then(resolve),
	};
	for (const method of ["select", "order", "limit", "eq"]) chain[method] = vi.fn(() => chain);
	return chain;
}

describe("event and incident views", () => {
	it("show the framework IDs of the rule an event matched, resolved from the bundled mapping", async () => {
		(useTeam as ReturnType<typeof vi.fn>).mockReturnValue({
			currentTeam: { id: "11111111-1111-4111-8111-111111111111" },
			isLoading: false,
		});
		const event = {
			id: 1,
			type: "runtime_verdict",
			created_at: "2026-09-25T10:00:00Z",
			agent_id: "agent-1",
			// A client-supplied frameworks field is ignored; only the rule id is used.
			payload: {
				tool_name: "Bash",
				verdict: "deny",
				matched_threat_id: "CLT-CMD-003",
				frameworks: { owasp_llm: ["LLM99-FAKE"] },
			},
		};
		(supabase.from as ReturnType<typeof vi.fn>).mockImplementation((table: string) =>
			query(table === "events" || table === "incident_events" ? [event] : []),
		);
		render(
			<MemoryRouter>
				<EventsPage />
				<IncidentsPage />
			</MemoryRouter>,
		);
		expect(await screen.findAllByText("AML.T0072")).toHaveLength(2);
		expect(screen.getAllByText("ASI05:2026")).toHaveLength(2);
		expect(screen.queryByText("LLM99-FAKE")).not.toBeInTheDocument();
	});
});

describe("Framework coverage view", () => {
	it("renders all three frameworks from the bundled artifact", () => {
		render(<FrameworkCoverageSection />);
		const region = screen.getByRole("region", { name: "Framework coverage" });
		expect(within(region).getByRole("heading", { name: "Framework coverage" })).toBeInTheDocument();
		expect(
			within(region).getByRole("region", { name: "OWASP Top 10 for LLM Applications 2025" }),
		).toBeInTheDocument();
		expect(
			within(region).getByRole("region", { name: "OWASP Top 10 for Agentic Applications 2026" }),
		).toBeInTheDocument();
		expect(within(region).getByRole("region", { name: "MITRE ATLAS 2026.09" })).toBeInTheDocument();
		expect(
			within(region).getByText(`${artifact.matrix.rule_count}`, { exact: false }),
		).toBeTruthy();
	});

	it("shows every OWASP item with its honest status and rationale", () => {
		render(<FrameworkCoverageSection />);
		const llm = screen.getByRole("region", { name: "OWASP Top 10 for LLM Applications 2025" });
		const rows = within(llm).getAllByRole("row").slice(1);
		expect(rows).toHaveLength(10);
		const llm08 = rows.find((row) => within(row).queryByText("LLM08:2025"));
		expect(llm08).toBeDefined();
		expect(within(llm08 as HTMLElement).getByText("not applicable")).toBeInTheDocument();
		const agentic = screen.getByRole("region", {
			name: "OWASP Top 10 for Agentic Applications 2026",
		});
		const asi07 = within(agentic)
			.getAllByRole("row")
			.find((row) => within(row).queryByText("ASI07:2026"));
		expect(within(asi07 as HTMLElement).getByText("not covered")).toBeInTheDocument();
	});
});

describe("FrameworkTags", () => {
	it("resolves a shipped rule id to its OWASP and ATLAS IDs", () => {
		const refs = frameworksForRule("CLT-CMD-003");
		expect(refs?.mitre_atlas).toContain("AML.T0072");
		render(<FrameworkTags ruleId="CLT-CMD-003" />);
		expect(screen.getByText("ASI05:2026")).toHaveAttribute(
			"title",
			"Unexpected Code Execution (RCE)",
		);
		expect(screen.getByText("AML.T0072")).toBeInTheDocument();
	});

	it("renders nothing for unknown, missing or prototype rule ids", () => {
		for (const ruleId of ["NOT-A-RULE", undefined, null, 42, "__proto__", "constructor"]) {
			expect(frameworksForRule(ruleId)).toBeNull();
			const { container } = render(<FrameworkTags ruleId={ruleId} />);
			expect(container).toBeEmptyDOMElement();
			cleanup();
		}
	});
});
