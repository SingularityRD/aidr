// @vitest-environment jsdom

/**
 * Grouped console navigation: every console route stays reachable, each link
 * label is the heading of the page it opens, and the Turkish labels use the
 * plain names the usability audit asked for.
 */
import "@testing-library/jest-dom/vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const team = vi.hoisted(() => ({
	value: {
		canEditPolicy: true,
		roleResolved: true,
		currentRole: "owner" as string | null,
		isLoading: false,
		currentTeam: null,
		error: null,
	},
}));
vi.mock("../lib/supabase", () => ({ supabase: { auth: {} }, supabaseEnvError: null }));
vi.mock("../ui/session", () => ({ getSession: vi.fn(), signOut: vi.fn() }));
vi.mock("../enterprise/team-provider", () => ({
	TeamProvider: ({ children }: { children: React.ReactNode }) => children,
	useTeam: () => team.value,
}));

import { en } from "../i18n/en";
import { I18nProvider } from "../i18n/I18nProvider";
import { tr } from "../i18n/tr";
import { AppLayout, NAV_SECTIONS } from "../ui/AppLayout";

const MAIN = readFileSync(resolve(__dirname, "..", "main.tsx"), "utf8");

/** Console routes reached from a page rather than the menu. */
const REACHED_FROM_A_PAGE: Record<string, string> = {
	"/agents/:agentId": "each row on /agents links to its detail page",
	"/governance/requests": "the AI governance sub-navigation links to it",
	"/governance/change-control": "the AI governance sub-navigation links to it",
};

function consoleRoutes(): string[] {
	return [...MAIN.matchAll(/path: "(\/[^"]+)",\s+lazy: loadAppLayout/g)].map(
		(match) => match[1] as string,
	);
}

function renderNav(locale: "en" | "tr", role: string | null = "owner") {
	team.value = {
		...team.value,
		currentRole: role,
		canEditPolicy: role === "owner" || role === "admin" || role === "member",
	};
	render(
		<I18nProvider initialLocale={locale}>
			<MemoryRouter initialEntries={["/dashboard"]}>
				<Routes>
					<Route path="/" element={<AppLayout />}>
						<Route path="dashboard" element={<p>content</p>} />
					</Route>
				</Routes>
			</MemoryRouter>
		</I18nProvider>,
	);
}

afterEach(cleanup);

describe("console navigation", () => {
	const items = NAV_SECTIONS.flatMap((section) => section.items);

	it("keeps every console route reachable", () => {
		const routes = consoleRoutes();
		expect(routes.length).toBeGreaterThan(20);
		const linked = new Set(items.map((item) => item.to));
		const unreachable = routes.filter((route) => !linked.has(route) && !REACHED_FROM_A_PAGE[route]);
		expect(unreachable).toEqual([]);
		for (const item of items) expect(routes, item.to).toContain(item.to);
	});

	it("groups the menu into a few task areas", () => {
		expect(NAV_SECTIONS.map((section) => en[section.label])).toEqual([
			"Overview",
			"Protection",
			"Approvals & incidents",
			"Devices & downloads",
			"Governance & compliance",
			"Administration",
		]);
		renderNav("en");
		const nav = screen.getByRole("navigation", { name: "Dashboard" });
		const response = within(nav).getByRole("group", { name: "Approvals & incidents" });
		expect(within(response).getByRole("link", { name: "Approvals" })).toHaveAttribute(
			"href",
			"/approvals",
		);
		expect(within(response).getByRole("link", { name: "Security incidents" })).toHaveAttribute(
			"href",
			"/incidents",
		);
	});

	it("uses one name for the browser extension and plain Turkish labels", () => {
		expect(en["nav.browserGuard"]).toBe("Browser Guard");
		expect(tr["nav.browserGuard"]).toBe("Browser Guard");
		expect(tr["nav.events"]).toBe("Etkinlik akışı");
		expect(tr["nav.incidents"]).toBe("Güvenlik vakaları");
		renderNav("tr");
		const nav = screen.getByRole("navigation", { name: "Panel" });
		expect(within(nav).getByRole("group", { name: "Onaylar ve vakalar" })).toBeInTheDocument();
		expect(within(nav).getByRole("link", { name: "Etkinlik akışı" })).toHaveAttribute(
			"href",
			"/events",
		);
		expect(within(nav).getByRole("link", { name: "Browser Guard" })).toHaveAttribute(
			"href",
			"/privacy-guard",
		);
	});

	it("hides owner-only entries from a viewer and empty groups entirely", () => {
		renderNav("en", "viewer");
		const nav = screen.getByRole("navigation", { name: "Dashboard" });
		expect(within(nav).queryByRole("link", { name: "Single sign-on" })).not.toBeInTheDocument();
		expect(within(nav).queryByRole("link", { name: "Team policy" })).not.toBeInTheDocument();
		expect(within(nav).getByRole("link", { name: "Team" })).toBeInTheDocument();
		const governance = within(nav).getByRole("group", { name: "Governance & compliance" });
		expect(within(governance).getAllByRole("link")).toHaveLength(1);
	});

	it("shows the read-only auditor its audit pages and hides enrolment and editing", () => {
		renderNav("en", "auditor");
		const nav = screen.getByRole("navigation", { name: "Dashboard" });
		const governance = within(nav).getByRole("group", { name: "Governance & compliance" });
		expect(
			within(governance)
				.getAllByRole("link")
				.map((link) => link.getAttribute("href")),
		).toEqual(["/governance", "/compliance", "/reports"]);
		for (const href of ["/events", "/incidents", "/team"]) {
			expect(nav.querySelector(`a[href="${href}"]`), href).not.toBeNull();
		}
		for (const href of [
			"/policies",
			"/onboarding",
			"/downloads",
			"/siem",
			"/sso",
			"/scim",
			"/retention",
			"/governance/detection-exceptions",
			"/governance/register",
		]) {
			expect(nav.querySelector(`a[href="${href}"]`), href).toBeNull();
		}
		cleanup();
		renderNav("tr", "auditor");
		expect(screen.getByRole("link", { name: tr["nav.reports"] })).toHaveAttribute(
			"href",
			"/reports",
		);
	});
});
