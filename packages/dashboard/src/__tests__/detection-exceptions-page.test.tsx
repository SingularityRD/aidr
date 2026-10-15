// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: { getSession: vi.fn(), getUser: vi.fn(), onAuthStateChange: vi.fn() },
		functions: { invoke: vi.fn() },
		from: vi.fn(),
		rpc: vi.fn(),
	},
	supabaseEnvError: null,
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import {
	draftFromQuery,
	draftProblem,
	exceptionState,
	isProtectedRule,
} from "../lib/detection-exceptions";
import { supabase } from "../lib/supabase";
import { DetectionExceptionsPage } from "../ui/pages/DetectionExceptionsPage";

const TEAM_ID = "22222222-2222-4222-8222-222222222222";
const MEMBER = "13131313-1313-4131-8131-131313131313";
const DAY = 86_400_000;
const day = (offset: number) => new Date(Date.now() + offset).toISOString().slice(0, 10);

function team(role: string) {
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TEAM_ID, name: "Acme" },
		currentRole: role,
		isLoading: false,
		roleResolved: true,
		members: [{ id: "m1", user_id: MEMBER, role: "member", email: "dev@acme.test", joined_at: "" }],
	} as unknown as ReturnType<typeof useTeam>);
}

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
});

describe("detection exception rules in the dashboard", () => {
	const draft = {
		ruleId: "CLT-CMD-011",
		subjectKind: "user" as const,
		subject: MEMBER,
		endDate: day(7 * DAY),
		reason: "release scripts",
		artifactSha256: "",
	};

	it("requires a bounded end date, a reason and refuses self-defense rules", () => {
		const now = Date.now();
		expect(draftProblem(draft, now)).toBeNull();
		expect(draftProblem({ ...draft, ruleId: "CLT-SELF-007" }, now)).toContain("Self-defense");
		expect(draftProblem({ ...draft, endDate: day(40 * DAY) }, now)).toContain("at most 30 days");
		expect(draftProblem({ ...draft, endDate: day(-DAY) }, now)).toContain("future");
		expect(draftProblem({ ...draft, reason: " " }, now)).toContain("reason");
		expect(draftProblem({ ...draft, subject: "bob" }, now)).toContain("member");
		expect(isProtectedRule("clt-canary-001")).toBe(true);
	});

	it("derives the state from revocation and expiry", () => {
		const row = {
			id: "x",
			ruleId: "CLT-CMD-011",
			artifactSha256: null,
			subjectKind: "repo" as const,
			subject: "github.com/acme/app",
			reason: "r",
			createdBy: "",
			createdAt: "",
			expiresAt: new Date(Date.now() + DAY).toISOString(),
			revokedAt: null,
			revokeReason: null,
		};
		expect(exceptionState(row, Date.now())).toBe("active");
		expect(exceptionState(row, Date.now() + 2 * DAY)).toBe("expired");
		expect(exceptionState({ ...row, revokedAt: "2026-10-01T00:00:00Z" }, Date.now())).toBe(
			"revoked",
		);
	});
});

describe("DetectionExceptionsPage", () => {
	it("is limited to owners and admins", () => {
		team("member");
		render(
			<MemoryRouter>
				<DetectionExceptionsPage />
			</MemoryRouter>,
		);
		expect(screen.getByRole("alert")).toHaveTextContent("Only workspace owners and admins");
		expect(supabase.functions.invoke).not.toHaveBeenCalled();
	});

	it("lists exceptions and creates one through the Edge Function", async () => {
		team("admin");
		vi.mocked(supabase.functions.invoke).mockImplementation(async (_name, options) => {
			const body = (options as { body: Record<string, unknown> }).body;
			if (body.action === "list") {
				return {
					data: {
						ok: true,
						exceptions: [
							{
								id: "e1",
								rule_id: "CLT-CMD-001",
								artifact_sha256: null,
								subject_kind: "user",
								subject_user_id: MEMBER,
								reason: "pipeline",
								created_at: new Date().toISOString(),
								expires_at: new Date(Date.now() + DAY).toISOString(),
								revoked_at: null,
							},
						],
					},
					error: null,
				} as never;
			}
			return { data: { ok: true, exception_id: "e2" }, error: null } as never;
		});
		render(
			<MemoryRouter>
				<DetectionExceptionsPage />
			</MemoryRouter>,
		);
		expect(await screen.findByText("CLT-CMD-001")).toBeInTheDocument();
		expect(screen.getByRole("cell", { name: "Member: dev@acme.test" })).toBeInTheDocument();

		fireEvent.change(screen.getByLabelText("Rule id"), { target: { value: "CLT-CMD-011" } });
		fireEvent.change(screen.getByLabelText("Member"), { target: { value: MEMBER } });
		fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "release scripts" } });
		fireEvent.click(screen.getByRole("button", { name: "Add exception" }));

		await waitFor(() =>
			expect(supabase.functions.invoke).toHaveBeenCalledWith(
				"detection-exceptions",
				expect.objectContaining({
					body: expect.objectContaining({
						action: "create",
						tenant_id: TEAM_ID,
						rule_id: "CLT-CMD-011",
						subject_kind: "user",
						subject_value: MEMBER,
						reason: "release scripts",
					}),
				}),
			),
		);
	});

	it("is pre-filled from a false-positive incident but sends nothing until submitted", async () => {
		team("owner");
		vi.mocked(supabase.functions.invoke).mockResolvedValue({
			data: { ok: true, exceptions: [] },
			error: null,
		} as never);
		const agent = "44444444-4444-4444-8444-444444444444";
		render(
			<MemoryRouter
				initialEntries={[
					`/governance/detection-exceptions?rule=CLT-CMD-011&subject_kind=agent&subject=${agent}&reason=Release%20script%2C%20reviewed`,
				]}
			>
				<DetectionExceptionsPage />
			</MemoryRouter>,
		);
		await screen.findByText("No detection exceptions yet.");
		expect(screen.getByText(/Filled in from a false-positive incident/)).toBeInTheDocument();
		expect(screen.getByLabelText("Rule id")).toHaveValue("CLT-CMD-011");
		expect(screen.getByLabelText("Agent id")).toHaveValue(agent);
		expect(screen.getByLabelText("Reason")).toHaveValue("Release script, reviewed");
		expect(
			vi
				.mocked(supabase.functions.invoke)
				.mock.calls.every(([, o]) => (o as { body: { action: string } }).body.action === "list"),
		).toBe(true);
	});

	it("ignores a protected rule or a malformed subject in the query string", () => {
		const draft = draftFromQuery(
			"?rule=CLT-SELF-008&subject_kind=agent&subject=nope&reason=x",
			Date.now(),
		);
		expect(draft.ruleId).toBe("");
		expect(draft.subject).toBe("");
		expect(draft.subjectKind).toBe("agent");
		expect(draftFromQuery("?subject_kind=tenant", Date.now()).subjectKind).toBe("user");
	});

	it("never sends a self-defense rule", async () => {
		team("owner");
		vi.mocked(supabase.functions.invoke).mockResolvedValue({
			data: { ok: true, exceptions: [] },
			error: null,
		} as never);
		render(
			<MemoryRouter>
				<DetectionExceptionsPage />
			</MemoryRouter>,
		);
		await screen.findByText("No detection exceptions yet.");
		fireEvent.change(screen.getByLabelText("Rule id"), { target: { value: "CLT-SELF-007" } });
		fireEvent.change(screen.getByLabelText("Member"), { target: { value: MEMBER } });
		fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "x" } });
		fireEvent.click(screen.getByRole("button", { name: "Add exception" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Self-defense rules cannot be excepted",
		);
		expect(
			vi
				.mocked(supabase.functions.invoke)
				.mock.calls.every(([, o]) => (o as { body: { action: string } }).body.action === "list"),
		).toBe(true);
	});
});
