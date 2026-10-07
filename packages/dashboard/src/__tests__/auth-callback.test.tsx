// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
	exchangeCodeForSession,
	from,
	getSession,
	getUser,
	membershipQuery,
	onAuthStateChange,
	setSession,
	signOut,
	verifyOtp,
} = vi.hoisted(() => ({
	exchangeCodeForSession: vi.fn(),
	from: vi.fn(),
	getSession: vi.fn(),
	getUser: vi.fn(),
	membershipQuery: vi.fn(),
	onAuthStateChange: vi.fn(),
	setSession: vi.fn(),
	signOut: vi.fn(),
	verifyOtp: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			exchangeCodeForSession,
			getSession,
			getUser,
			onAuthStateChange,
			setSession,
			signOut,
			verifyOtp,
		},
		from,
	},
}));

import { isInvitePending } from "../ui/invite-pending";
import { AuthCallbackPage } from "../ui/pages/AuthCallbackPage";
import { readSession } from "../ui/session";

const INVITE_HASH = "pkce_0123456789abcdef0123456789abcdef";

function renderInviteCallback(path = `/auth/callback?token_hash=${INVITE_HASH}&type=invite`) {
	window.history.replaceState({}, "", path);
	return render(
		<MemoryRouter initialEntries={["/auth/callback"]}>
			<Routes>
				<Route path="/auth/callback" element={<AuthCallbackPage />} />
				<Route path="/onboarding" element={<div>Onboarding destination</div>} />
				<Route path="/login" element={<div>Sign-in page</div>} />
			</Routes>
		</MemoryRouter>,
	);
}

describe("authentication callback ownership", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		localStorage.clear();
		window.history.replaceState({}, "", "/auth/callback?code=one-time-code");
		exchangeCodeForSession.mockResolvedValue({
			data: { session: { access_token: "session-token", user: { id: "user-id" } } },
			error: null,
		});
		setSession.mockResolvedValue({
			data: { session: { access_token: "header.payload.signature", user: { id: "user-id" } } },
			error: null,
		});
		getUser.mockResolvedValue({ data: { user: { id: "user-id" } }, error: null });
		signOut.mockImplementation(async () => {
			localStorage.removeItem("aidr.dashboard.auth.session.v1");
			return { error: null };
		});
		onAuthStateChange.mockReturnValue({
			data: { subscription: { unsubscribe: vi.fn() } },
		});
		verifyOtp.mockImplementation(async () => {
			localStorage.setItem("aidr.dashboard.auth.session.v1", "invite-session");
			const user = { id: "invitee-id", email: "invitee@example.com" };
			return { data: { session: { access_token: "a.b.c", user }, user }, error: null };
		});
		membershipQuery.mockResolvedValue({
			data: [{ role: "viewer", teams: { name: "Acme Security" } }],
			error: null,
		});
		const chain = {
			select: () => chain,
			eq: () => chain,
			order: () => chain,
			limit: membershipQuery,
		};
		from.mockReturnValue(chain);
	});

	afterEach(() => {
		cleanup();
		window.history.replaceState({}, "", "/");
	});

	it("explicitly exchanges the one-time PKCE code exactly once", async () => {
		render(
			<MemoryRouter initialEntries={["/auth/callback?code=one-time-code"]}>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
					<Route path="/onboarding" element={<div>Onboarding destination</div>} />
				</Routes>
			</MemoryRouter>,
		);

		expect(await screen.findByText("Onboarding destination")).toBeInTheDocument();
		expect(exchangeCodeForSession).toHaveBeenCalledOnce();
		expect(exchangeCodeForSession).toHaveBeenCalledWith("one-time-code");
		expect(getSession).not.toHaveBeenCalled();
		expect(onAuthStateChange).not.toHaveBeenCalled();
		expect(window.location.search).toBe("");
		expect(window.location.hash).toBe("");
	});

	it("does not consume the callback twice under StrictMode", async () => {
		render(
			<StrictMode>
				<MemoryRouter initialEntries={["/auth/callback?code=one-time-code"]}>
					<Routes>
						<Route path="/auth/callback" element={<AuthCallbackPage />} />
						<Route path="/onboarding" element={<div>Onboarding destination</div>} />
					</Routes>
				</MemoryRouter>
			</StrictMode>,
		);

		expect(await screen.findByText("Onboarding destination")).toBeInTheDocument();
		expect(exchangeCodeForSession).toHaveBeenCalledOnce();
		expect(signOut).not.toHaveBeenCalled();
		expect(screen.queryByText("Authentication could not be completed.")).not.toBeInTheDocument();
	});

	it("does not expose provider error details", async () => {
		exchangeCodeForSession.mockResolvedValue({
			data: { session: null },
			error: new Error("invalid grant: oauth-code=secret"),
		});

		render(
			<MemoryRouter initialEntries={["/auth/callback?code=one-time-code"]}>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
				</Routes>
			</MemoryRouter>,
		);

		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Authentication could not be completed.",
		);
		expect(screen.queryByText(/oauth-code=secret/)).not.toBeInTheDocument();
	});

	it("explains a missing browser-bound verifier without exposing tokens", async () => {
		exchangeCodeForSession.mockResolvedValue({
			data: { session: null },
			error: { code: "pkce_code_verifier_not_found", message: "private verifier detail" },
		});
		render(
			<MemoryRouter initialEntries={["/auth/callback?code=one-time-code"]}>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByRole("alert")).toHaveTextContent("browser where you requested it");
		expect(screen.queryByText("private verifier detail")).not.toBeInTheDocument();
		expect(window.location.search).toBe("");
	});

	it.each([
		"/auth/callback#access_token=header.payload.signature&refresh_token=refresh-token-longer-than-20-characters&type=invite",
		"/auth/callback#access_token=header.payload.signature&refresh_token=refresh-token-longer-than-20-characters&type=magiclink",
		"/auth/callback?code=one-time-code#access_token=header.payload.signature&refresh_token=r",
	])("never accepts session tokens from the URL fragment (%s)", async (path) => {
		window.history.replaceState({}, "", path);
		render(
			<MemoryRouter initialEntries={["/auth/callback"]}>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
					<Route path="/onboarding" element={<div>Protected destination</div>} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByRole("alert")).toHaveTextContent("link format is not accepted");
		expect(setSession).not.toHaveBeenCalled();
		expect(getUser).not.toHaveBeenCalled();
		expect(verifyOtp).not.toHaveBeenCalled();
		expect(exchangeCodeForSession).not.toHaveBeenCalled();
		expect(screen.queryByText("Protected destination")).not.toBeInTheDocument();
		expect(screen.queryByText(/header\.payload\.signature/)).not.toBeInTheDocument();
		expect(window.location.hash).toBe("");
		expect(window.location.search).toBe("");
	});

	it("verifies an invite token_hash server-side and asks for confirmation before proceeding", async () => {
		renderInviteCallback();
		expect(await screen.findByText("Confirm invitation")).toBeInTheDocument();
		expect(verifyOtp).toHaveBeenCalledOnce();
		expect(verifyOtp).toHaveBeenCalledWith({ type: "invite", token_hash: INVITE_HASH });
		expect(setSession).not.toHaveBeenCalled();
		expect(exchangeCodeForSession).not.toHaveBeenCalled();
		expect(window.location.search).toBe("");
		expect(screen.getByText("invitee@example.com")).toBeInTheDocument();
		expect(screen.getByRole("listitem")).toHaveTextContent(
			"You are joining workspace Acme Security as role viewer.",
		);
		// Not yet confirmed: the session is gated and the protected route is not reached.
		expect(isInvitePending("invitee-id")).toBe(true);
		expect(screen.queryByText("Onboarding destination")).not.toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Continue" }));
		expect(await screen.findByText("Onboarding destination")).toBeInTheDocument();
		expect(isInvitePending("invitee-id")).toBe(false);
		expect(signOut).not.toHaveBeenCalled();
	});

	it("keeps sanitizeReturnTo behaviour after an invite is confirmed", async () => {
		localStorage.setItem("aidr.postAuthReturnTo.v1", "//evil.example/steal");
		renderInviteCallback();
		fireEvent.click(await screen.findByRole("button", { name: "Continue" }));
		expect(await screen.findByText("Onboarding destination")).toBeInTheDocument();
	});

	it("signs out when the invitee cancels the confirmation", async () => {
		renderInviteCallback();
		fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
		expect(await screen.findByText("Sign-in page")).toBeInTheDocument();
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(localStorage.getItem("aidr.dashboard.auth.session.v1")).toBeNull();
		expect(isInvitePending("invitee-id")).toBe(false);
		expect(screen.queryByText("Onboarding destination")).not.toBeInTheDocument();
	});

	it("refuses an unconfirmed invite session anywhere else in the app", async () => {
		renderInviteCallback();
		expect(await screen.findByText("Confirm invitation")).toBeInTheDocument();
		getSession.mockResolvedValue({
			data: { session: { access_token: "a.b.c", user: { id: "invitee-id" } } },
			error: null,
		});
		const snapshot = await readSession();
		expect(snapshot.session).toBeNull();
		expect(snapshot.status.state).toBe("signed_out");
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(isInvitePending("invitee-id")).toBe(false);
	});

	it("fails closed and signs out when the invite token_hash is rejected", async () => {
		verifyOtp.mockResolvedValue({
			data: { session: null, user: null },
			error: new Error("Token has expired or is invalid"),
		});
		renderInviteCallback();
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Authentication could not be completed.",
		);
		expect(screen.queryByText(/expired or is invalid/)).not.toBeInTheDocument();
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		await waitFor(() => expect(isInvitePending("invitee-id")).toBe(false));
	});

	it("fails closed when the invite workspace cannot be shown", async () => {
		membershipQuery.mockResolvedValue({ data: null, error: new Error("rls") });
		renderInviteCallback();
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Authentication could not be completed.",
		);
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(localStorage.getItem("aidr.dashboard.auth.session.v1")).toBeNull();
		expect(screen.queryByText("Confirm invitation")).not.toBeInTheDocument();
	});

	it.each([
		`/auth/callback?token_hash=${INVITE_HASH}&type=recovery`,
		`/auth/callback?token_hash=${INVITE_HASH}&type=magiclink`,
		"/auth/callback?token_hash=bad%20hash&type=invite",
		`/auth/callback?code=one-time-code&token_hash=${INVITE_HASH}&type=invite`,
	])("rejects any other token_hash callback without verifying it (%s)", async (path) => {
		renderInviteCallback(path);
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Authentication could not be completed.",
		);
		expect(verifyOtp).not.toHaveBeenCalled();
		expect(exchangeCodeForSession).not.toHaveBeenCalled();
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
	});

	it("rejects and purges a legacy recovery hash without reaching a protected route", async () => {
		localStorage.setItem("aidr.dashboard.auth.session.v1", "callback-created-session");
		window.history.replaceState(
			{},
			"",
			"/auth/callback?type=recovery#access_token=recovery-access&refresh_token=recovery-refresh",
		);

		render(
			<MemoryRouter
				initialEntries={[
					"/auth/callback?type=recovery#access_token=recovery-access&refresh_token=recovery-refresh",
				]}
			>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
					<Route path="/dashboard" element={<div>Protected dashboard</div>} />
				</Routes>
			</MemoryRouter>,
		);

		expect(await screen.findByRole("alert")).toHaveTextContent("link format is not accepted");
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(exchangeCodeForSession).not.toHaveBeenCalled();
		expect(localStorage.getItem("aidr.dashboard.auth.session.v1")).toBeNull();
		expect(screen.queryByText("Protected dashboard")).not.toBeInTheDocument();
		expect(window.location.search).toBe("");
		expect(window.location.hash).toBe("");
	});
});
