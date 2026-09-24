// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { exchangeCodeForSession, getSession, getUser, onAuthStateChange, setSession, signOut } =
	vi.hoisted(() => ({
		exchangeCodeForSession: vi.fn(),
		getSession: vi.fn(),
		getUser: vi.fn(),
		onAuthStateChange: vi.fn(),
		setSession: vi.fn(),
		signOut: vi.fn(),
	}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: { exchangeCodeForSession, getSession, getUser, onAuthStateChange, setSession, signOut },
	},
}));

import { AuthCallbackPage } from "../ui/pages/AuthCallbackPage";

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

	it("accepts a provider invite fragment only after server-side user validation", async () => {
		window.history.replaceState(
			{},
			"",
			"/auth/callback#access_token=header.payload.signature&refresh_token=refresh-token-longer-than-20-characters&type=invite",
		);
		render(
			<MemoryRouter initialEntries={["/auth/callback"]}>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
					<Route path="/onboarding" element={<div>Onboarding destination</div>} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByText("Onboarding destination")).toBeInTheDocument();
		expect(setSession).toHaveBeenCalledOnce();
		expect(getUser).toHaveBeenCalledWith("header.payload.signature");
		expect(window.location.hash).toBe("");
		expect(exchangeCodeForSession).not.toHaveBeenCalled();
	});

	it("rejects an invite fragment when the server validates a different user", async () => {
		getUser.mockResolvedValue({ data: { user: { id: "different-user" } }, error: null });
		window.history.replaceState(
			{},
			"",
			"/auth/callback#access_token=header.payload.signature&refresh_token=refresh-token-longer-than-20-characters&type=invite",
		);
		render(
			<MemoryRouter initialEntries={["/auth/callback"]}>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
					<Route path="/onboarding" element={<div>Protected destination</div>} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Authentication could not be completed.",
		);
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(screen.queryByText("Protected destination")).not.toBeInTheDocument();
		expect(window.location.hash).toBe("");
	});

	it("clears an invite session when server-side user validation rejects", async () => {
		setSession.mockImplementationOnce(async () => {
			localStorage.setItem("aidr.dashboard.auth.session.v1", "unverified-invite-session");
			return {
				data: { session: { access_token: "header.payload.signature", user: { id: "user-id" } } },
				error: null,
			};
		});
		getUser.mockRejectedValueOnce(new Error("network failure after session persistence"));
		window.history.replaceState(
			{},
			"",
			"/auth/callback#access_token=header.payload.signature&refresh_token=refresh-token-longer-than-20-characters&type=invite",
		);
		render(
			<MemoryRouter initialEntries={["/auth/callback"]}>
				<Routes>
					<Route path="/auth/callback" element={<AuthCallbackPage />} />
					<Route path="/onboarding" element={<div>Protected destination</div>} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Authentication could not be completed.",
		);
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(localStorage.getItem("aidr.dashboard.auth.session.v1")).toBeNull();
		expect(screen.queryByText("Protected destination")).not.toBeInTheDocument();
		expect(window.location.hash).toBe("");
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

		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Authentication could not be completed.",
		);
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(exchangeCodeForSession).not.toHaveBeenCalled();
		expect(localStorage.getItem("aidr.dashboard.auth.session.v1")).toBeNull();
		expect(screen.queryByText("Protected dashboard")).not.toBeInTheDocument();
		expect(window.location.search).toBe("");
		expect(window.location.hash).toBe("");
	});
});
