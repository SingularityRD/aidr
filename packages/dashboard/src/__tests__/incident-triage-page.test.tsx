// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: { from: vi.fn(), functions: { invoke: vi.fn() } },
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import {
	exceptionPrefillPath,
	isSnoozed,
	type TriageDraft,
	triageDraftProblem,
} from "../lib/incidents";
import { supabase } from "../lib/supabase";
import { IncidentsPage } from "../ui/pages/IncidentsPage";

const TENANT = "11111111-1111-4111-8111-111111111111";
const OWNER = "22222222-2222-4222-8222-222222222222";
const ANALYST = "33333333-3333-4333-8333-333333333333";
const AGENT = "44444444-4444-4444-8444-444444444444";
const DAY = 86_400_000;

const from = supabase.from as ReturnType<typeof vi.fn>;
const invoke = supabase.functions.invoke as ReturnType<typeof vi.fn>;

function query(data: unknown) {
	const chain = {
		select: vi.fn(),
		order: vi.fn(),
		limit: vi.fn(),
		eq: vi.fn(),
		then: (resolve: (value: unknown) => unknown) =>
			Promise.resolve({ data, error: null }).then(resolve),
	};
	for (const method of ["select", "order", "limit", "eq"] as const)
		chain[method].mockReturnValue(chain);
	return chain;
}

const EVENTS = [
	{
		id: 7,
		type: "runtime_verdict",
		created_at: "2026-10-14T09:00:00Z",
		agent_id: AGENT,
		payload: {
			tool_name: "Bash",
			verdict: "deny",
			severity: "high",
			matched_threat_id: "CLT-CMD-011",
		},
	},
	{
		id: 8,
		type: "runtime_verdict",
		created_at: "2026-10-14T09:05:00Z",
		agent_id: AGENT,
		payload: {
			tool_name: "Read",
			verdict: "deny",
			severity: "critical",
			matched_threat_id: "AIDR-CANARY-002",
			source: "canary",
		},
	},
	{
		id: 9,
		type: "runtime_verdict",
		created_at: "2026-10-14T09:10:00Z",
		agent_id: AGENT,
		payload: { tool_name: "Write", verdict: "ask" },
	},
];

function team(role: "owner" | "viewer") {
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TENANT, name: "Acme" },
		currentRole: role,
		currentUserId: OWNER,
		isLoading: false,
		roleResolved: true,
		members: [
			{ id: "m1", user_id: OWNER, role: "owner", email: "owner@acme.test", joined_at: "" },
			{ id: "m2", user_id: ANALYST, role: "member", email: "analyst@acme.test", joined_at: "" },
			{
				id: "m3",
				user_id: "55555555-5555-4555-8555-555555555555",
				role: "viewer",
				email: "viewer@acme.test",
				joined_at: "",
			},
		],
	} as unknown as ReturnType<typeof useTeam>);
}

let triage: Array<Record<string, unknown>>;
let canTriage: boolean;

beforeEach(() => {
	vi.resetAllMocks();
	canTriage = true;
	triage = [
		{
			event_id: 9,
			status: "resolved",
			owner_user_id: ANALYST,
			resolution_note: "Expected write",
			snoozed_until: null,
			version: 2,
			updated_by: OWNER,
			updated_at: "2026-10-14T09:30:00Z",
		},
	];
	from.mockImplementation((table: string) => query(table === "incident_events" ? EVENTS : []));
	invoke.mockImplementation(async (_name: string, { body }: { body: Record<string, unknown> }) => {
		if (body.action === "list")
			return { data: { ok: true, can_triage: canTriage, triage }, error: null };
		if (body.action === "history") {
			return {
				data: {
					ok: true,
					history: [
						{
							id: 1,
							actor_user_id: OWNER,
							from_status: null,
							to_status: "acknowledged",
							to_owner_user_id: ANALYST,
							note: null,
							self_closure: false,
							created_at: "2026-10-14T09:20:00Z",
						},
					],
				},
				error: null,
			};
		}
		if (body.action === "update") {
			return {
				data: {
					ok: true,
					triage: {
						event_id: body.event_id,
						status: body.status,
						owner_user_id: body.owner_user_id,
						resolution_note: body.resolution_note,
						snoozed_until: body.snoozed_until,
						version: Number(body.expected_version) + 1,
						updated_by: OWNER,
						updated_at: "2026-10-14T10:00:00Z",
					},
				},
				error: null,
			};
		}
		return { data: null, error: new Error("unexpected") };
	});
});
afterEach(() => cleanup());

function renderPage() {
	render(
		<MemoryRouter>
			<IncidentsPage />
		</MemoryRouter>,
	);
}

describe("incident triage on the Security incidents page", () => {
	it("shows status and owner, and hides closed incidents from the default queue", async () => {
		team("owner");
		renderPage();
		expect(await screen.findByText("Bash: blocked (high)")).toBeInTheDocument();
		expect(screen.queryByText("Write: needs approval")).not.toBeInTheDocument();
		fireEvent.change(screen.getByLabelText("Show"), { target: { value: "closed" } });
		const row = (await screen.findByText(/^Write:/)).closest("tr") as HTMLElement;
		expect(within(row).getByText("Resolved")).toBeInTheDocument();
		expect(within(row).getByText("analyst@acme.test")).toBeInTheDocument();
	});

	it("closes an incident as a false positive with a note, then offers a pre-filled exception", async () => {
		team("owner");
		renderPage();
		await screen.findByText("Bash: blocked (high)");
		fireEvent.click(screen.getByRole("button", { name: "Manage incident 7" }));
		const form = await screen.findByRole("form", { name: "Change incident status" });
		expect(
			within(form).queryByRole("option", { name: "viewer@acme.test" }),
		).not.toBeInTheDocument();
		fireEvent.change(within(form).getByLabelText("Status"), {
			target: { value: "false_positive" },
		});
		fireEvent.change(within(form).getByLabelText("Owner"), { target: { value: ANALYST } });
		fireEvent.submit(form);
		// Closing without a note is refused in the browser before any request.
		expect(
			await screen.findByText("Write a resolution note before closing the incident."),
		).toBeInTheDocument();
		expect(invoke.mock.calls.some(([, init]) => init.body.action === "update")).toBe(false);

		fireEvent.change(within(form).getByLabelText("Resolution note (required)"), {
			target: { value: "Release script, reviewed" },
		});
		fireEvent.click(within(form).getByRole("button", { name: "Save" }));
		await screen.findByText("Saved. Status: False positive.");
		const update = invoke.mock.calls.find(([, init]) => init.body.action === "update");
		expect(update?.[0]).toBe("incidents");
		expect(update?.[1].body).toEqual({
			action: "update",
			tenant_id: TENANT,
			event_id: 7,
			expected_version: 0,
			status: "false_positive",
			owner_user_id: ANALYST,
			resolution_note: "Release script, reviewed",
			snoozed_until: null,
		});
		const link = await screen.findByRole("link", { name: "Create a detection exception…" });
		const href = new URL(link.getAttribute("href") ?? "", "https://console.test");
		expect(href.pathname).toBe("/governance/detection-exceptions");
		expect(Object.fromEntries(href.searchParams)).toEqual({
			rule: "CLT-CMD-011",
			subject_kind: "agent",
			subject: AGENT,
			reason: "Release script, reviewed",
		});
		expect(screen.getByRole("list", { name: "Audit trail" })).toHaveTextContent(
			"owner@acme.test: new → Acknowledged",
		);
	});

	it("never offers an exception for a canary rule", () => {
		expect(
			exceptionPrefillPath({ ruleId: "AIDR-CANARY-002", agentId: AGENT, note: "x" }),
		).toBeNull();
		expect(exceptionPrefillPath({ ruleId: "CLT-SELF-008", agentId: AGENT, note: "x" })).toBeNull();
		expect(
			exceptionPrefillPath({ ruleId: "clt-canary-001", agentId: AGENT, note: "x" }),
		).toBeNull();
		expect(exceptionPrefillPath({ ruleId: undefined, agentId: AGENT, note: "x" })).toBeNull();
		expect(exceptionPrefillPath({ ruleId: "CLT-CMD-011", agentId: "not-a-uuid", note: null })).toBe(
			"/governance/detection-exceptions?rule=CLT-CMD-011",
		);
	});

	it("is read-only, with the audit trail, for members who cannot triage", async () => {
		team("viewer");
		canTriage = false;
		renderPage();
		await screen.findByText("Bash: blocked (high)");
		fireEvent.click(screen.getByRole("button", { name: "Manage incident 7" }));
		expect(
			await screen.findByText(/Only workspace owners and admins can change incident status/),
		).toBeInTheDocument();
		expect(screen.queryByRole("form", { name: "Change incident status" })).not.toBeInTheDocument();
	});

	it("keeps showing incidents as open when triage cannot be loaded", async () => {
		team("owner");
		invoke.mockResolvedValue({ data: null, error: new Error("down") });
		renderPage();
		expect(await screen.findByText("Bash: blocked (high)")).toBeInTheDocument();
		expect(await screen.findByText(/Incident status could not be loaded/)).toBeInTheDocument();
		expect(screen.getByText("Write: needs approval")).toBeInTheDocument();
	});
});

describe("incident triage rules", () => {
	const draft: TriageDraft = { status: "acknowledged", ownerUserId: "", note: "", snoozeUntil: "" };
	const day = (offset: number) => new Date(Date.now() + offset).toISOString().slice(0, 10);

	it("bounds snoozes and requires a note to close", () => {
		const now = Date.now();
		expect(triageDraftProblem(draft, now)).toBeNull();
		expect(triageDraftProblem({ ...draft, snoozeUntil: day(3 * DAY) }, now)).toBeNull();
		expect(triageDraftProblem({ ...draft, snoozeUntil: day(40 * DAY) }, now)).toContain(
			"at most 30 days",
		);
		expect(triageDraftProblem({ ...draft, snoozeUntil: day(-DAY) }, now)).toContain("future");
		expect(triageDraftProblem({ ...draft, status: "resolved" }, now)).toContain("resolution note");
		expect(
			triageDraftProblem(
				{ ...draft, status: "resolved", note: "ok", snoozeUntil: day(DAY * 2) },
				now,
			),
		).toContain("cannot be snoozed");
	});

	it("treats a snooze as hiding only open or acknowledged incidents until it ends", () => {
		const row = {
			eventId: 1,
			status: "open" as const,
			ownerUserId: null,
			resolutionNote: null,
			snoozedUntil: new Date(Date.now() + DAY).toISOString(),
			version: 1,
			updatedBy: "",
			updatedAt: "",
		};
		expect(isSnoozed(row, Date.now())).toBe(true);
		expect(isSnoozed(row, Date.now() + 2 * DAY)).toBe(false);
		expect(isSnoozed({ ...row, status: "resolved" }, Date.now())).toBe(false);
	});
});
