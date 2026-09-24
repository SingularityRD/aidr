// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../enterprise/team-provider", () => ({
	TeamProvider: ({ children }: { children: React.ReactNode }) => children,
	useTeam: () => ({
		canEditPolicy: true,
		roleResolved: true,
		isLoading: false,
		currentTeam: {},
		error: null,
	}),
}));
vi.mock("../lib/supabase", () => ({ supabaseEnvError: null }));
const signOut = vi.hoisted(() => vi.fn());
vi.mock("../ui/session", () => ({ signOut }));

import { AppLayout } from "../ui/AppLayout";
import { PublicLayout } from "../ui/PublicLayout";

afterEach(() => {
	cleanup();
	signOut.mockReset();
});

function expectWorkingSkipLink(navigationName: string) {
	const link = screen.getByRole("link", { name: "Skip to content" });
	const targetId = link.getAttribute("href")?.slice(1);
	const target = targetId ? document.getElementById(targetId) : null;

	expect(target).toHaveAttribute("tabindex", "-1");
	expect(target).not.toContainElement(screen.getByRole("navigation", { name: navigationName }));
	target?.focus();
	expect(target).toHaveFocus();
}

describe("layout keyboard access", () => {
	it("lets dashboard users skip its navigation and focus page content", () => {
		render(
			<MemoryRouter initialEntries={["/dashboard"]}>
				<Routes>
					<Route path="/" element={<AppLayout />}>
						<Route path="dashboard" element={<h1>Dashboard content</h1>} />
					</Route>
				</Routes>
			</MemoryRouter>,
		);

		expectWorkingSkipLink("Dashboard");
	});

	it("provides the same skip-to-content path on public pages", () => {
		render(
			<MemoryRouter initialEntries={["/"]}>
				<Routes>
					<Route path="/" element={<PublicLayout />}>
						<Route index element={<h1>Public content</h1>} />
					</Route>
				</Routes>
			</MemoryRouter>,
		);

		expectWorkingSkipLink("Public");
	});

	it("hides protected dashboard content while sign-out is pending", async () => {
		let finish!: (value: { serverRevoked: boolean }) => void;
		signOut.mockImplementation(
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
			<MemoryRouter initialEntries={["/dashboard"]}>
				<Routes>
					<Route path="/" element={<AppLayout />}>
						<Route path="dashboard" element={<h1>Protected dashboard</h1>} />
					</Route>
					<Route path="/login" element={<LoginLocation />} />
				</Routes>
			</MemoryRouter>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
		expect(screen.getByRole("status")).toHaveTextContent("Ending this browser session");
		expect(screen.queryByRole("heading", { name: "Protected dashboard" })).not.toBeInTheDocument();
		finish({ serverRevoked: false });
		expect(
			await screen.findByText("Login destination: ?signout=revocation-unconfirmed"),
		).toBeInTheDocument();
	});

	it("leaves the protected view after local sign-out fails", async () => {
		signOut.mockRejectedValue(new Error("local cleanup failed"));
		function LoginLocation() {
			return <div>Login destination: {useLocation().search}</div>;
		}
		render(
			<MemoryRouter initialEntries={["/dashboard"]}>
				<Routes>
					<Route path="/" element={<AppLayout />}>
						<Route path="dashboard" element={<h1>Protected dashboard</h1>} />
					</Route>
					<Route path="/login" element={<LoginLocation />} />
				</Routes>
			</MemoryRouter>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
		expect(await screen.findByText("Login destination: ?signout=local-failed")).toBeInTheDocument();
		expect(screen.queryByRole("heading", { name: "Protected dashboard" })).not.toBeInTheDocument();
	});
});
