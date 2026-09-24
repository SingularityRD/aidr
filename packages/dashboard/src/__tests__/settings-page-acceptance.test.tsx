// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SettingsPage } from "../ui/pages/SettingsPage";
import { ThemeProvider } from "../ui/ThemeProvider";

const session = vi.hoisted(() => ({ getSession: vi.fn(), signOut: vi.fn() }));
vi.mock("../ui/session", () => session);
vi.mock("../lib/supabase", () => ({ supabaseEnvError: null }));

beforeEach(() => {
	vi.clearAllMocks();
	localStorage.clear();
	session.getSession.mockResolvedValue({ user: { email: "operator@example.test" } });
	session.signOut.mockResolvedValue({ serverRevoked: true });
});
afterEach(cleanup);

it("shows the account, persists appearance, exposes legal links and completes sign-out", async () => {
	render(
		<MemoryRouter initialEntries={["/settings"]}>
			<ThemeProvider>
				<Routes>
					<Route path="/settings" element={<SettingsPage />} />
					<Route path="/login" element={<h1>Sign in</h1>} />
				</Routes>
			</ThemeProvider>
		</MemoryRouter>,
	);
	expect(await screen.findByText("operator@example.test")).toBeInTheDocument();
	fireEvent.click(screen.getByRole("button", { name: "Dark" }));
	await waitFor(() => expect(localStorage.getItem("theme")).toBe("dark"));
	expect(document.documentElement).toHaveAttribute("data-theme", "dark");
	expect(screen.getByRole("link", { name: "Privacy notice" })).toHaveAttribute("href", "/privacy");
	expect(screen.getByRole("link", { name: "Security" })).toHaveAttribute("href", "/security");
	expect(screen.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");
	expect(screen.getByRole("link", { name: "Support" })).toHaveAttribute("href", "/support");
	fireEvent.click(screen.getByRole("button", { name: "Sign out of this session" }));
	expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
	expect(session.signOut).toHaveBeenCalledOnce();
});

it("hides settings while ending the session and reports unconfirmed server revocation on login", async () => {
	let finish!: (value: { serverRevoked: boolean }) => void;
	session.signOut.mockImplementation(
		() =>
			new Promise((resolve) => {
				finish = resolve;
			}),
	);
	function LoginLocation() {
		const location = useLocation();
		return <div>Login destination: {location.search}</div>;
	}
	render(
		<MemoryRouter initialEntries={["/settings"]}>
			<ThemeProvider>
				<Routes>
					<Route path="/settings" element={<SettingsPage />} />
					<Route path="/login" element={<LoginLocation />} />
				</Routes>
			</ThemeProvider>
		</MemoryRouter>,
	);
	fireEvent.click(await screen.findByRole("button", { name: "Sign out of this session" }));
	expect(screen.getByRole("status")).toHaveTextContent("Ending this browser session");
	expect(screen.queryByRole("heading", { name: "Settings" })).not.toBeInTheDocument();
	finish({ serverRevoked: false });
	expect(
		await screen.findByText("Login destination: ?signout=revocation-unconfirmed"),
	).toBeInTheDocument();
});
