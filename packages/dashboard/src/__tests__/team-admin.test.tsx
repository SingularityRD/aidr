// @vitest-environment jsdom

// Regression guards for AIDR-008 (team administration unreachable).
//
// The capability existed in full — AdminPanel with create team, invite with
// role, change role, remove member and role gating — but nothing referenced it
// and no route rendered it, so no customer could manage a team. EnterpriseAuth
// even navigated to "/team", a route that did not exist.
//
// These tests assert the three things that were missing: the route exists and
// renders, the console navigation exposes it, and the role gate is real. They
// also pin the fail-closed behaviour for the parts of team administration whose
// backend does not exist in this repository (the `team-invite` Edge Function and
// the `public.users` relation the member query wants).

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
	},
	supabaseEnvError: null,
}));

import { AppLayout } from "../ui/AppLayout";
import { TeamPage } from "../ui/pages/TeamPage";
import {
	ADMIN_USER_ID,
	installDashboardMocks,
	MEMBER_USER_ID,
	mockedSupabase,
	TEAM_ID,
	VIEWER_USER_ID,
} from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const MAIN_TSX = readFileSync(resolve(REPO_ROOT, "packages/dashboard/src/main.tsx"), "utf8");

function routeBlock(path: string): string {
	const marker = `path: "${path}"`;
	const start = MAIN_TSX.indexOf(marker);
	expect(start, `${marker} is not registered in main.tsx`).toBeGreaterThan(-1);
	return MAIN_TSX.slice(start, start + 320);
}

function renderTeamRoute() {
	return render(
		<MemoryRouter initialEntries={["/team"]}>
			<Routes>
				<Route path="/*" element={<AppLayout />}>
					<Route path="team" element={<TeamPage />} />
				</Route>
			</Routes>
		</MemoryRouter>,
	);
}

async function inviteMember(email: string) {
	await waitFor(() =>
		expect(screen.getByPlaceholderText("colleague@company.com")).toBeInTheDocument(),
	);
	fireEvent.change(screen.getByPlaceholderText("colleague@company.com"), {
		target: { value: email },
	});
	fireEvent.click(screen.getByRole("button", { name: "Invite" }));
}

describe("Team administration is reachable (AIDR-008)", () => {
	afterEach(cleanup);

	it("registers /team through the console shell behind the session loader", () => {
		const block = routeBlock("/team");
		expect(block).toContain("<AppLayout />");
		expect(block).toContain("loader: requireSessionLoader");
		expect(block).toContain("<TeamPage />");
	});

	it("exposes the team surface from the console navigation", () => {
		const layout = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/ui/AppLayout.tsx"),
			"utf8",
		);
		expect(layout).toContain('<NavLink to="/team">Team</NavLink>');
	});

	it("never navigates to a route the router does not define", () => {
		// This is the regression that stranded invitees: EnterpriseAuth called
		// navigate("/team") while main.tsx registered no /team route.
		const enterpriseAuth = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/enterprise/auth.tsx"),
			"utf8",
		);
		const targets = [...enterpriseAuth.matchAll(/navigate\("([^"]+)"\)/g)].map((match) => match[1]);
		expect(targets.length).toBeGreaterThan(0);
		for (const target of targets) {
			expect(MAIN_TSX, `navigate("${target}") has no matching route`).toContain(
				`path: "${target}"`,
			);
		}
	});

	it("renders the team administration page for a team owner", async () => {
		installDashboardMocks({
			role: "owner",
			members: [
				{ id: "row-admin", user_id: ADMIN_USER_ID, role: "owner" },
				{ id: "row-member", user_id: MEMBER_USER_ID, role: "member" },
			],
		});

		renderTeamRoute();

		await waitFor(() => expect(screen.getByText("Runtime team")).toBeInTheDocument());
		expect(screen.getByRole("heading", { name: "Team", level: 1 })).toBeInTheDocument();
		await waitFor(() =>
			expect(screen.getByRole("heading", { name: "Team Members (2)" })).toBeInTheDocument(),
		);
		expect(screen.getByPlaceholderText("colleague@company.com")).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Invite" })).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "+ New Team" })).toBeInTheDocument();
		expect(screen.getAllByRole("button", { name: "Remove" })).toHaveLength(2);
	});

	it("shows an owner the policy navigation entry once the role is resolved", async () => {
		installDashboardMocks({ role: "owner" });

		renderTeamRoute();

		await waitFor(() =>
			expect(screen.getByRole("link", { name: "Policies" })).toBeInTheDocument(),
		);
		expect(screen.getByRole("link", { name: "Team" })).toHaveAttribute("href", "/team");
		expect(screen.getByRole("link", { name: "Policies" })).toHaveAttribute("href", "/policies");
	});

	it("hides the policy navigation entry from a viewer and keeps the member list read-only", async () => {
		installDashboardMocks({
			role: "viewer",
			members: [
				{ id: "row-viewer", user_id: VIEWER_USER_ID, role: "viewer" },
				{ id: "row-admin", user_id: ADMIN_USER_ID, role: "owner" },
			],
		});

		renderTeamRoute();

		await waitFor(() =>
			expect(screen.getByRole("heading", { name: "Team Members (2)" })).toBeInTheDocument(),
		);
		expect(screen.getByText(/read-only access to this team/)).toBeInTheDocument();
		expect(screen.queryByPlaceholderText("colleague@company.com")).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Invite" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "+ New Team" })).not.toBeInTheDocument();
		// The viewer sees roles as read-only pills, never as editable selects.
		const row = screen.getByText(`user ${ADMIN_USER_ID}`).closest("tr");
		expect(row).not.toBeNull();
		expect(within(row as HTMLElement).queryByRole("combobox")).not.toBeInTheDocument();
		expect(within(row as HTMLElement).getByText("Owner")).toBeInTheDocument();

		await waitFor(() =>
			expect(screen.queryByRole("link", { name: "Policies" })).not.toBeInTheDocument(),
		);
	});
});

describe("Team administration fails closed (AIDR-008, AIDR-019)", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});
	afterEach(cleanup);

	it("shows a visible error instead of a fabricated member count when the rows cannot be read", async () => {
		installDashboardMocks({
			memberEmailProjection: { message: "permission denied for table team_members" },
		});

		renderTeamRoute();

		await waitFor(() => expect(screen.getByText("Member list unavailable.")).toBeInTheDocument());
		expect(screen.getByRole("alert")).toHaveTextContent(
			"permission denied for table team_members",
		);
		expect(screen.getByRole("alert")).toHaveTextContent(
			"No member count is shown because the membership rows could not be read.",
		);
		expect(screen.queryByText(/Team Members \(/)).not.toBeInTheDocument();
	});

	it("lists members by user id and says emails are unavailable when no users relation exists", async () => {
		installDashboardMocks({
			members: [
				{ id: "row-admin", user_id: ADMIN_USER_ID, role: "admin" },
				{ id: "row-member", user_id: MEMBER_USER_ID, role: "member" },
			],
		});

		renderTeamRoute();

		await waitFor(() =>
			expect(screen.getByRole("heading", { name: "Team Members (2)" })).toBeInTheDocument(),
		);
		expect(screen.getByText(`user ${MEMBER_USER_ID}`)).toBeInTheDocument();
		expect(
			screen.getByText("Member email addresses are unavailable in this deployment."),
		).toBeInTheDocument();
		expect(screen.queryByText("Member list unavailable.")).not.toBeInTheDocument();
	});

	it("does not claim a member was invited when the team-invite function is missing", async () => {
		installDashboardMocks({
			invite: { data: null, error: { message: "Failed to send a request to the Edge Function" } },
		});

		renderTeamRoute();
		await inviteMember("colleague@company.com");

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/the "team-invite" Edge Function is unavailable/,
			),
		);
		expect(screen.getByRole("alert")).toHaveTextContent(/No invitation was sent/);
		expect(screen.queryByText(/Invitation sent/)).not.toBeInTheDocument();
	});

	it("does not claim success when the invite service answers without confirming", async () => {
		installDashboardMocks({ invite: { data: null, error: null } });

		renderTeamRoute();
		await inviteMember("colleague@company.com");

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/did not confirm the invitation/),
		);
		expect(screen.queryByText(/Invitation sent/)).not.toBeInTheDocument();
	});

	it("reports the invitation only when the service confirms it", async () => {
		installDashboardMocks({ invite: { data: { ok: true, invite_url: `${window.location.origin}/enterprise?invite=abc` }, error: null } });

		renderTeamRoute();
		await inviteMember("colleague@company.com");

		await waitFor(() =>
			expect(screen.getByText("Invitation created for colleague@company.com. Share the link below; no email was sent.")).toBeInTheDocument(),
		);
		expect(mockedSupabase().functions.invoke).toHaveBeenCalledWith(
			"team-invite",
			expect.objectContaining({
				body: expect.objectContaining({ team_id: TEAM_ID, email: "colleague@company.com" }),
			}),
		);
	});

	it("does not claim a member was removed when the database rejects the write", async () => {
		vi.restoreAllMocks();
		installDashboardMocks({ memberWriteRows: null });
		vi.spyOn(window, "confirm").mockReturnValue(true);

		renderTeamRoute();
		await waitFor(() => expect(screen.getByRole("button", { name: "Remove" })).toBeInTheDocument());
		fireEvent.click(screen.getByRole("button", { name: "Remove" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/No membership row was removed/),
		);
		expect(screen.queryByText(/removed from team/)).not.toBeInTheDocument();
	});

	it("does not claim a role change when the database rejects the write", async () => {
		installDashboardMocks({
			memberWriteRows: null,
			members: [
				{ id: "row-admin", user_id: ADMIN_USER_ID, role: "admin" },
				{ id: "row-member", user_id: MEMBER_USER_ID, role: "member" },
			],
		});
		vi.spyOn(window, "confirm").mockReturnValue(true);

		renderTeamRoute();
		await waitFor(() =>
			expect(screen.getByRole("heading", { name: "Team Members (2)" })).toBeInTheDocument(),
		);
		const row = screen.getByText(`user ${MEMBER_USER_ID}`).closest("tr");
		expect(row).not.toBeNull();
		fireEvent.change(within(row as HTMLElement).getByRole("combobox"), {
			target: { value: "admin" },
		});

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/No membership row was updated/),
		);
		expect(screen.queryByText(/Role updated to/)).not.toBeInTheDocument();
	});

	it("does not present a failed membership query as 'you have no team'", async () => {
		installDashboardMocks({
			membershipsError: { message: "permission denied for table teams" },
		});

		renderTeamRoute();

		await waitFor(() =>
			expect(screen.getByText("Your team membership could not be loaded.")).toBeInTheDocument(),
		);
		expect(screen.queryByText("You are not part of any team yet.")).not.toBeInTheDocument();
		expect(
			screen.queryByRole("button", { name: "Create Your First Team" }),
		).not.toBeInTheDocument();
	});
});
