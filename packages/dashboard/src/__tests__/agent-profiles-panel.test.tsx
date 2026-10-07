// @vitest-environment jsdom

import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession: vi.fn(),
			getUser: vi.fn(),
			signOut: vi.fn(),
			signInWithOAuth: vi.fn(),
			signInWithOtp: vi.fn(),
			exchangeCodeForSession: vi.fn(),
			onAuthStateChange: vi.fn(),
		},
		functions: { invoke: vi.fn() },
		from: vi.fn(),
		rpc: vi.fn(),
	},
	supabaseEnvError: null,
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { PROFILE_TEMPLATE_SUMMARIES } from "../enterprise/agent-profile-templates";
import { AgentProfilesPanel, parseProfileDecisionRow } from "../enterprise/agent-profiles-panel";
import { useTeam } from "../enterprise/team-provider";
import { installDashboardMocks, mockedSupabase, TEAM_ID } from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const AGENT_ID = "a0000000-0000-4000-8000-000000000009";

function profileEvent(id: number, decision: "ask" | "deny", check: string, tool = "Bash") {
	return {
		id: `e${id}`,
		created_at: "2026-09-25T08:00:00.000Z",
		agent_id: AGENT_ID,
		payload: {
			type: "runtime_verdict",
			verdict: decision,
			source: "agent_profile",
			matched_threat_id: check,
			tool_name: tool,
		},
	};
}

function setup(events: unknown[] | { error: { message: string } }) {
	installDashboardMocks({
		tableResults: {
			events: Array.isArray(events)
				? { data: events, error: null }
				: { data: null, error: events.error },
			agents: {
				data: [{ id: AGENT_ID, iid: "iid-1", display_name: "build-runner-1" }],
				error: null,
			},
		},
	});
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TEAM_ID, name: "Runtime team" },
		canManageTeam: true,
		isLoading: false,
	} as never);
	// The editor reads the staged document and its history (policy-management).
	mockedSupabase().functions.invoke.mockImplementation(
		async (_name: string, request?: { body?: { action?: string } }) => {
			if (request?.body?.action === "read_agent_profiles") {
				return {
					data: {
						ok: true,
						staged: true,
						version: 2,
						policy: { version: 1, profiles: [{ name: "ci-agent", default: "deny" }] },
						policy_sha256: "a".repeat(64),
						profile_count: 1,
						updated_at: "2026-09-28T10:00:00.000Z",
						delivered: false,
						delivery_status: "staged_not_signed",
					},
					error: null,
				};
			}
			return { data: { ok: true, revisions: [], next_before_version: null }, error: null };
		},
	);
}

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe("agent permission profiles panel", () => {
	it("mirrors the shipped engine templates exactly", async () => {
		const specifier = pathToFileURL(
			resolve(REPO_ROOT, "packages", "core", "src", "agent-profile-templates.ts"),
		).href;
		const core = (await import(specifier)) as {
			AGENT_PROFILE_TEMPLATES: Record<
				string,
				{ name: string; description: string; default: string; tools: Record<string, string> }
			>;
		};
		const shipped = Object.values(core.AGENT_PROFILE_TEMPLATES).map((template) => ({
			name: template.name,
			description: template.description,
			default: template.default,
			tools: template.tools,
		}));
		expect(PROFILE_TEMPLATE_SUMMARIES).toEqual(shipped);
	});

	it("shows templates, publishing steps and the tenant's reported profile decisions", async () => {
		setup([
			profileEvent(1, "deny", "AGENT-PROFILE-COMMAND"),
			profileEvent(2, "deny", "AGENT-PROFILE-COMMAND"),
			profileEvent(3, "ask", "AGENT-PROFILE-MCP", "mcp__github__create_issue"),
			// Not a profile decision: must be ignored even if the filter lets it through.
			{
				...profileEvent(4, "deny", "CLT-CMD-001"),
				payload: { verdict: "deny", source: "heuristic" },
			},
		]);
		render(<AgentProfilesPanel />);

		const templates = screen.getByRole("table", { name: "Agent permission profile templates" });
		for (const name of ["read-only-reviewer", "standard-developer", "ci-agent", "locked-down"]) {
			expect(within(templates).getByText(name)).toBeInTheDocument();
		}
		const command = await screen.findByLabelText("Signed profile publishing commands");
		expect(command).toHaveTextContent("provision-agent-profiles.mjs");
		expect(command).toHaveTextContent(`--tenant ${TEAM_ID} --revision 2`);

		const recent = await screen.findByRole("table", { name: "Recent profile decisions" });
		expect(within(recent).getAllByText("build-runner-1")).toHaveLength(3);
		expect(within(recent).getByText("mcp__github__create_issue")).toBeInTheDocument();
		const summary = screen.getByRole("table", { name: "Profile decisions by rule family" });
		const commandRow = within(summary).getByText("Command prefix").closest("tr");
		expect(commandRow).toHaveTextContent("Command prefix20");
		expect(within(summary).getByText("MCP server / tool").closest("tr")).toHaveTextContent(
			"MCP server / tool01",
		);

		const from = mockedSupabase().from;
		expect(from).toHaveBeenCalledWith("events");
	});

	it("says so when no decisions have been reported and surfaces read errors", async () => {
		setup([]);
		render(<AgentProfilesPanel />);
		expect(
			await screen.findByText(/No agent has reported a profile decision yet/),
		).toBeInTheDocument();
		cleanup();

		setup({ error: { message: "permission denied for table events" } });
		render(<AgentProfilesPanel />);
		// Database detail stays out of the browser; the safe fallback is shown.
		const alert = await screen.findByRole("alert");
		expect(alert).toHaveTextContent("Recent profile decisions are unavailable.");
		expect(alert).not.toHaveTextContent("permission denied");
	});

	it("parses only well-formed profile decision rows", () => {
		expect(parseProfileDecisionRow(profileEvent(1, "deny", "AGENT-PROFILE-FILE"))).toMatchObject({
			decision: "deny",
			check: "AGENT-PROFILE-FILE",
		});
		expect(parseProfileDecisionRow({ ...profileEvent(1, "deny", "x"), id: 1 })).toBeNull();
		expect(parseProfileDecisionRow(null)).toBeNull();
		expect(
			parseProfileDecisionRow({
				...profileEvent(1, "deny", "AGENT-PROFILE-FILE"),
				payload: {
					source: "agent_profile",
					verdict: "allow",
					matched_threat_id: "AGENT-PROFILE-FILE",
				},
			}),
		).toBeNull();
	});
});
