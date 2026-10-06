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
// also pin fail-closed behaviour when `team-invite` is unavailable and when
// the tenant-scoped member directory RPC is absent.

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
		rpc: vi.fn(),
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
		expect(block).toContain("lazy: loadAppLayout");
		expect(block).toContain("loader: requireSessionLoader");
		expect(block).toContain('import("./ui/pages/TeamPage")');
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

	it("shows owner-visible member emails only from the tenant-scoped directory RPC", async () => {
		installDashboardMocks({
			role: "owner",
			memberDirectory: "present",
			members: [
				{ user_id: ADMIN_USER_ID, role: "owner", email: "owner@example.test" },
				{ user_id: MEMBER_USER_ID, role: "member", email: "member@example.test" },
			],
		});
		renderTeamRoute();
		await screen.findByText("member@example.test");
		expect(screen.getByText("owner@example.test")).toBeInTheDocument();
		expect(screen.queryByText(/Member email addresses are unavailable/)).not.toBeInTheDocument();
		expect(mockedSupabase().rpc).toHaveBeenCalledWith("list_team_members_with_email", {
			p_team_id: TEAM_ID,
		});
	});

	it("does not render tenant-controlled remote avatar URLs", async () => {
		const trackingPixel = "https://tracker.example/pixel?team-view=1";
		installDashboardMocks({
			role: "owner",
			memberDirectory: "present",
			members: [{ user_id: MEMBER_USER_ID, role: "member", avatar_url: trackingPixel }],
		});

		const { container } = renderTeamRoute();

		await screen.findByText(`${MEMBER_USER_ID}@company.invalid`);
		expect(container.querySelector(`img[src="${trackingPixel}"]`)).toBeNull();
		expect(container.querySelectorAll("img")).toHaveLength(0);
	});

	it("shows an owner the policy navigation entry once the role is resolved", async () => {
		installDashboardMocks({ role: "owner" });

		renderTeamRoute();

		await waitFor(() => expect(screen.getByRole("link", { name: "Policies" })).toBeInTheDocument());
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

	it("does not offer owner promotion or owner removal to an administrator", async () => {
		installDashboardMocks({
			role: "admin",
			members: [
				{ id: "row-admin", user_id: ADMIN_USER_ID, role: "admin" },
				{ id: "row-owner", user_id: VIEWER_USER_ID, role: "owner" },
			],
		});
		renderTeamRoute();
		await waitFor(() =>
			expect(screen.getByRole("heading", { name: "Team Members (2)" })).toBeInTheDocument(),
		);
		const ownerRow = screen.getByText(`user ${VIEWER_USER_ID}`).closest("tr");
		expect(ownerRow).not.toBeNull();
		expect(within(ownerRow as HTMLElement).queryByRole("combobox")).not.toBeInTheDocument();
		expect(
			within(ownerRow as HTMLElement).queryByRole("button", { name: "Remove" }),
		).not.toBeInTheDocument();
		const adminRow = screen.getByText(`user ${ADMIN_USER_ID}`).closest("tr");
		expect(adminRow).not.toBeNull();
		expect(within(adminRow as HTMLElement).getByRole("combobox")).toBeInTheDocument();
		expect(
			within(adminRow as HTMLElement).queryByRole("option", { name: "Owner" }),
		).not.toBeInTheDocument();
	});

	it("rechecks managed access after changing the signed-in member's role", async () => {
		installDashboardMocks({
			role: "owner",
			members: [{ user_id: ADMIN_USER_ID, role: "owner" }],
		});
		renderTeamRoute();
		const member = await screen.findByText(`user ${ADMIN_USER_ID}`);
		fireEvent.change(within(member.closest("tr") as HTMLElement).getByRole("combobox"), {
			target: { value: "viewer" },
		});
		await waitFor(() => {
			const bootstraps = mockedSupabase().functions.invoke.mock.calls.filter(
				([name, request]) => name === "identity-security" && request?.body?.action === "bootstrap",
			);
			expect(bootstraps).toHaveLength(2);
		});
	});

	it("rechecks managed access after removing the signed-in member", async () => {
		installDashboardMocks({
			role: "owner",
			members: [{ user_id: ADMIN_USER_ID, role: "owner" }],
		});
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderTeamRoute();
		fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
		await waitFor(() => {
			const bootstraps = mockedSupabase().functions.invoke.mock.calls.filter(
				([name, request]) => name === "identity-security" && request?.body?.action === "bootstrap",
			);
			expect(bootstraps).toHaveLength(2);
		});
		vi.restoreAllMocks();
	});
});

describe("Team administration fails closed (AIDR-008, AIDR-019)", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});
	afterEach(cleanup);

	it("shows a visible error instead of a fabricated member count when the rows cannot be read", async () => {
		installDashboardMocks({
			memberDirectory: { message: "permission denied for table team_members" },
		});

		renderTeamRoute();

		await waitFor(() => expect(screen.getByText("Member list unavailable.")).toBeInTheDocument());
		expect(screen.getByRole("alert")).toHaveTextContent("Failed to load members");
		expect(screen.getByRole("alert")).not.toHaveTextContent("team_members");
		expect(screen.getByRole("alert")).toHaveTextContent(
			"No member count is shown because the membership rows could not be read.",
		);
		expect(screen.queryByText(/Team Members \(/)).not.toBeInTheDocument();
	});

	it("lists members by user id when an older deployment lacks the directory RPC", async () => {
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
			expect(screen.getByRole("alert")).toHaveTextContent(/invitation service is unavailable/i),
		);
		expect(screen.getByRole("alert")).not.toHaveTextContent(/team-invite/);
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
		installDashboardMocks({
			invite: {
				data: { ok: true, invite_url: `${window.location.origin}/enterprise?invite=abc` },
				error: null,
			},
		});

		renderTeamRoute();
		await inviteMember("colleague@company.com");

		await waitFor(() =>
			expect(
				screen.getByText(
					"Invitation created for colleague@company.com. Share the link below; no email was sent.",
				),
			).toBeInTheDocument(),
		);
		expect(mockedSupabase().functions.invoke).toHaveBeenCalledWith(
			"team-invite",
			expect.objectContaining({
				body: expect.objectContaining({ team_id: TEAM_ID, email: "colleague@company.com" }),
			}),
		);
	});

	it("lists pending invitations and replaces or revokes them only after server confirmation", async () => {
		installDashboardMocks({ role: "owner" });
		const invoke = mockedSupabase().functions.invoke;
		const original = invoke.getMockImplementation() as (
			name: string,
			request?: unknown,
		) => Promise<unknown>;
		const invitationId = "77777777-7777-4777-8777-777777777777";
		const recipient = "colleague@company.com";
		let pending = true;
		invoke.mockImplementation(
			async (
				name: string,
				request?: { body?: { action?: string; team_id?: string; invitation_id?: string } },
			) => {
				if (name !== "team-invite") return original(name, request);
				if (request?.body?.action === "list")
					return {
						data: {
							ok: true,
							invitations: pending
								? [
										{
											id: invitationId,
											email: recipient,
											role: "member",
											expires_at: "2030-01-01T00:00:00.000Z",
										},
									]
								: [],
						},
						error: null,
					};
				if (request?.body?.action === "resend")
					return {
						data: {
							ok: true,
							invitation_id: invitationId,
							invite_url: `${window.location.origin}/enterprise?invite=replacement-secret`,
						},
						error: null,
					};
				if (request?.body?.action === "revoke") {
					pending = false;
					return { data: { ok: true, invitation_id: invitationId }, error: null };
				}
				return { data: null, error: { message: "unexpected action" } };
			},
		);
		vi.spyOn(window, "confirm").mockReturnValue(true);

		renderTeamRoute();
		await waitFor(() => expect(screen.getByText(recipient)).toBeInTheDocument());
		expect(screen.queryByDisplayValue(/seed-secret/)).not.toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Replace link" }));
		await waitFor(() =>
			expect(
				screen.getByText(
					`Link replaced for ${recipient}. Share the new link below; no email was sent.`,
				),
			).toBeInTheDocument(),
		);
		expect(
			screen.getByDisplayValue(`${window.location.origin}/enterprise?invite=replacement-secret`),
		).toBeInTheDocument();
		expect(invoke).toHaveBeenCalledWith("team-invite", {
			body: { team_id: TEAM_ID, action: "resend", invitation_id: invitationId },
		});

		fireEvent.click(screen.getByRole("button", { name: "Revoke invitation" }));
		await waitFor(() =>
			expect(screen.getByText(`Invitation revoked for ${recipient}.`)).toBeInTheDocument(),
		);
		await waitFor(() => expect(screen.getByText("No pending invitations.")).toBeInTheDocument());
		expect(screen.queryByDisplayValue(/replacement-secret/)).not.toBeInTheDocument();
		expect(invoke).toHaveBeenCalledWith("team-invite", {
			body: { team_id: TEAM_ID, action: "revoke", invitation_id: invitationId },
		});
	});

	it("does not show an empty pending list when the invitation service is unavailable", async () => {
		installDashboardMocks({ role: "owner" });
		const invoke = mockedSupabase().functions.invoke;
		const original = invoke.getMockImplementation() as (
			name: string,
			request?: unknown,
		) => Promise<unknown>;
		invoke.mockImplementation((name: string, request?: { body?: { action?: string } }) =>
			name === "team-invite" && request?.body?.action === "list"
				? Promise.resolve({ data: null, error: { message: "service unavailable" } })
				: original(name, request),
		);
		renderTeamRoute();
		await waitFor(() =>
			expect(screen.getByText(/Pending invitations could not be loaded/)).toBeInTheDocument(),
		);
		expect(screen.queryByText("No pending invitations.")).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Replace link" })).not.toBeInTheDocument();
	});

	it("refuses a replacement link outside this dashboard even when the service says ok", async () => {
		installDashboardMocks({ role: "owner" });
		const invoke = mockedSupabase().functions.invoke;
		const original = invoke.getMockImplementation() as (
			name: string,
			request?: unknown,
		) => Promise<unknown>;
		const invitationId = "77777777-7777-4777-8777-777777777777";
		invoke.mockImplementation((name: string, request?: { body?: { action?: string } }) => {
			if (name !== "team-invite") return original(name, request);
			if (request?.body?.action === "list")
				return Promise.resolve({
					data: {
						ok: true,
						invitations: [
							{
								id: invitationId,
								email: "colleague@company.com",
								role: "member",
								expires_at: "2030-01-01T00:00:00.000Z",
							},
						],
					},
					error: null,
				});
			return Promise.resolve({
				data: {
					ok: true,
					invitation_id: invitationId,
					invite_url: "https://outside.example/enterprise?invite=secret",
				},
				error: null,
			});
		});
		vi.spyOn(window, "confirm").mockReturnValue(true);
		renderTeamRoute();
		fireEvent.click(await screen.findByRole("button", { name: "Replace link" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("invalid link"));
		expect(screen.queryByDisplayValue(/outside\.example/)).not.toBeInTheDocument();
		expect(screen.queryByText(/Link replaced/)).not.toBeInTheDocument();
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
