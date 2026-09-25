// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({ supabase: { from: vi.fn() } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import {
	latestFindings,
	type PostureFindingRow,
	PosturePage,
	postureTrend,
} from "../ui/pages/PosturePage";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const NOW = Date.parse("2026-09-24T12:00:00.000Z");
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;

function row(overrides: Partial<PostureFindingRow>): PostureFindingRow {
	return {
		id: 1,
		source: "infra_scan",
		finding_kind: "cve",
		severity: "critical",
		cvss: null,
		vuln_id: null,
		component: null,
		component_version: null,
		applicability: null,
		target_digest: null,
		mcp_server_name: null,
		mcp_transport: null,
		risk_categories: [],
		attestation_status: null,
		subject_digest: null,
		plugin_key: null,
		rule_id: null,
		skill_risk_type: null,
		observed_at: "2026-09-24T10:00:00.000Z",
		...overrides,
	};
}

const ROWS: PostureFindingRow[] = [
	row({
		id: 1,
		vuln_id: "CVE-2024-37032",
		component: "ollama",
		component_version: "0.1.30",
		cvss: "9.1",
		applicability: "confirmed",
		target_digest: DIGEST_A,
	}),
	row({
		id: 2,
		vuln_id: "CVE-2024-37032",
		component: "ollama",
		component_version: "0.1.30",
		cvss: "9.1",
		applicability: "confirmed",
		target_digest: DIGEST_B,
		observed_at: "2026-09-23T10:00:00.000Z",
	}),
	row({
		id: 3,
		vuln_id: "CVE-2024-0001",
		component: "gradio",
		severity: "high",
		cvss: 7.5,
		applicability: "unconfirmed",
		target_digest: DIGEST_A,
	}),
	row({
		id: 4,
		finding_kind: "exposed_component",
		severity: "info",
		component: "comfyui",
		target_digest: DIGEST_B,
	}),
	row({
		id: 5,
		source: "mcp_inventory",
		finding_kind: "mcp_server",
		severity: "critical",
		mcp_server_name: "shell-runner",
		mcp_transport: "stdio",
		risk_categories: ["shell_wrapper_command", "mcp-05"],
		attestation_status: "unverifiable",
		subject_digest: DIGEST_A,
	}),
	row({
		id: 6,
		source: "skill_scan",
		finding_kind: "skill_rule",
		severity: "critical",
		plugin_key: "acme-skill",
		rule_id: "SKILL-T03-001",
		skill_risk_type: "T03",
		subject_digest: DIGEST_B,
	}),
];

function mockRows(result: { data: unknown; error: { message: string } | null }) {
	const chain: Record<string, unknown> = {};
	for (const method of ["select", "eq", "gte", "order", "limit"]) {
		chain[method] = vi.fn(() => chain);
	}
	chain.then = (resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) =>
		Promise.resolve(result).then(resolve, reject);
	vi.mocked(supabase.from).mockReturnValue(chain as never);
	return chain;
}

function renderPage() {
	return render(
		<MemoryRouter>
			<PosturePage />
		</MemoryRouter>,
	);
}

describe("AI security posture page", () => {
	beforeEach(() => {
		vi.mocked(useTeam).mockReturnValue({
			currentTeam: { id: TENANT_ID, name: "Example tenant" },
			isLoading: false,
		} as never);
		vi.mocked(supabase.from).mockReset();
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("queries only the selected tenant's posture findings", async () => {
		const chain = mockRows({ data: ROWS, error: null });
		renderPage();
		await screen.findByRole("region", { name: "Infrastructure exposure" });
		expect(supabase.from).toHaveBeenCalledWith("posture_findings");
		expect(chain.eq).toHaveBeenCalledWith("tenant_id", TENANT_ID);
		expect(chain.gte).toHaveBeenCalledWith("observed_at", expect.any(String));
	});

	it("shows CVEs by severity and CVSS, MCP risks and skill findings", async () => {
		mockRows({ data: ROWS, error: null });
		renderPage();

		const infra = await screen.findByRole("region", { name: "Infrastructure exposure" });
		const infraRows = within(infra).getAllByRole("row").slice(1);
		expect(infraRows).toHaveLength(2);
		// Critical first; the same CVE on two targets is one row with two targets.
		expect(infraRows[0]).toHaveTextContent("CVE-2024-37032");
		expect(infraRows[0]).toHaveTextContent("ollama 0.1.30");
		expect(infraRows[0]).toHaveTextContent("9.1");
		expect(within(infraRows[0] as HTMLElement).getAllByRole("cell")[5]).toHaveTextContent("2");
		expect(infraRows[1]).toHaveTextContent("CVE-2024-0001");
		expect(infraRows[1]).toHaveTextContent("unconfirmed");
		expect(infra).toHaveTextContent("1 identified component(s) without a matched CVE");

		const mcp = screen.getByRole("region", { name: "MCP inventory risks" });
		expect(mcp).toHaveTextContent("shell-runner");
		expect(mcp).toHaveTextContent("Shell wrapper, Command injection & execution");
		expect(mcp).toHaveTextContent("unverifiable");

		const skills = screen.getByRole("region", { name: "Skill and plugin findings" });
		expect(skills).toHaveTextContent("acme-skill");
		expect(skills).toHaveTextContent("SKILL-T03-001");
		expect(skills).toHaveTextContent("T03 Remote payload retrieval and execution");

		const counters = screen.getByRole("region", { name: "Posture counters" });
		expect(counters).toHaveTextContent("Critical CVEs1");
		expect(counters).toHaveTextContent("High CVEs1");

		expect(screen.getByRole("region", { name: "Posture trend" })).toBeInTheDocument();
		expect(document.body.textContent).not.toMatch(/infra[- ]?guard|tencent|\baig\b/i);
	});

	it("explains how to upload when nothing has been reported", async () => {
		mockRows({ data: [], error: null });
		renderPage();
		const empty = await screen.findByRole("region", { name: "No posture data" });
		expect(empty).toHaveTextContent("not that the environment is clean");
		expect(empty).toHaveTextContent("aidr scan --target");
		expect(empty).toHaveTextContent("--upload");
		expect(empty).toHaveTextContent("aidr discover --upload");
		expect(document.body.textContent).not.toMatch(/infra[- ]?guard|tencent|\baig\b/i);
		expect(
			screen.queryByRole("region", { name: "Infrastructure exposure" }),
		).not.toBeInTheDocument();
	});

	it("fails closed when posture data cannot be read", async () => {
		mockRows({ data: null, error: { message: "permission denied for table posture_findings" } });
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("this is not a clean result"),
		);
		expect(screen.queryByRole("region", { name: "No posture data" })).not.toBeInTheDocument();
	});
});

describe("posture aggregation", () => {
	it("keeps the latest observation of each finding", () => {
		const current = latestFindings([
			row({
				id: 1,
				vuln_id: "CVE-1",
				target_digest: DIGEST_A,
				severity: "high",
				observed_at: "2026-09-20T00:00:00Z",
			}),
			row({
				id: 2,
				vuln_id: "CVE-1",
				target_digest: DIGEST_A,
				severity: "critical",
				observed_at: "2026-09-22T00:00:00Z",
			}),
		]);
		expect(current.map((entry) => entry.id)).toEqual([2]);
	});

	it("buckets the trend by UTC day and ignores informational rows", () => {
		const trend = postureTrend(
			[
				row({ id: 1, severity: "critical", observed_at: "2026-09-24T01:00:00Z" }),
				row({ id: 2, severity: "high", observed_at: "2026-09-24T02:00:00Z" }),
				row({ id: 3, severity: "medium", observed_at: "2026-09-23T02:00:00Z" }),
				row({ id: 4, severity: "info", observed_at: "2026-09-23T03:00:00Z" }),
				row({ id: 5, severity: "critical", observed_at: "2026-07-01T00:00:00Z" }),
			],
			NOW,
			7,
		);
		expect(trend).toHaveLength(7);
		expect(trend.at(-1)).toEqual({ day: "2026-09-24", critical: 1, high: 1, other: 0 });
		expect(trend.at(-2)).toEqual({ day: "2026-09-23", critical: 0, high: 0, other: 1 });
		expect(trend.reduce((sum, day) => sum + day.critical + day.high + day.other, 0)).toBe(3);
	});
});
