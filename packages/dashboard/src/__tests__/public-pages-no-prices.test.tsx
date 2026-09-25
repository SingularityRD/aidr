// @vitest-environment jsdom
// Product-owner decision: prices are not published anywhere customer-facing.
// This renders every public route inside the public layout, in both commercial
// modes, and fails if any price, currency or per-seat price wording appears in
// the page text or the document head.
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const commercial = vi.hoisted(() => ({ selfService: false }));
vi.mock("../billing/commercial", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../billing/commercial")>();
	return {
		...actual,
		get selfServiceCheckoutEnabled() {
			return commercial.selfService;
		},
	};
});
vi.mock("../lib/supabase", () => ({
	supabase: {
		functions: {
			invoke: vi.fn().mockResolvedValue({ data: null, error: { message: "offline" } }),
		},
	},
	supabaseEnvError: null,
}));
vi.mock("../ui/session", () => ({ getSession: vi.fn().mockResolvedValue(null) }));

import { PublicLayout } from "../ui/PublicLayout";
import { LandingPage } from "../ui/pages/public/LandingPage";
import { PilotPage } from "../ui/pages/public/PilotPage";
import { PricingPage } from "../ui/pages/public/PricingPage";
import { PublicInfoPage } from "../ui/pages/public/PublicInfoPage";
import { VerifyPage } from "../ui/pages/public/VerifyPage";
import { CURRENCY_OR_PRICE } from "./helpers/public-price-patterns";

afterEach(() => {
	cleanup();
	commercial.selfService = false;
	vi.unstubAllEnvs();
});

const PUBLIC_ROUTES: Array<[string, ReactElement]> = [
	["/", <LandingPage key="landing" />],
	["/pricing", <PricingPage key="pricing" />],
	["/pilot", <PilotPage key="pilot" />],
	["/verify", <VerifyPage key="verify" />],
	["/support", <PublicInfoPage key="support" kind="support" />],
	["/status", <PublicInfoPage key="status" kind="status" />],
	["/privacy", <PublicInfoPage key="privacy" kind="privacy" />],
	["/security", <PublicInfoPage key="security" kind="security" />],
	["/terms", <PublicInfoPage key="terms" kind="terms" />],
];

async function renderedText(path: string, page: ReactElement): Promise<string> {
	const { container } = render(
		<MemoryRouter initialEntries={[path]}>
			<Routes>
				<Route path="/" element={<PublicLayout />}>
					<Route
						path={path === "/" ? undefined : path.slice(1)}
						index={path === "/"}
						element={page}
					/>
				</Route>
			</Routes>
		</MemoryRouter>,
	);
	await waitFor(() => expect(screen.getByRole("contentinfo")).toBeInTheDocument());
	// Let async effects (pilot/verify lookups) settle before reading the text.
	await new Promise((resolve) => setTimeout(resolve, 0));
	return `${document.title}\n${document.head.textContent ?? ""}\n${container.textContent ?? ""}`;
}

describe("public pages never publish prices", () => {
	it("keeps the pattern honest: it catches the copy that used to ship", () => {
		for (const sample of [
			"$24",
			"€20",
			"₺750",
			"20 USD",
			"$20 per developer / month billed annually",
			"per developer / month, billed monthly",
			"List prices, subject to COM-001 approval.",
			"geliştirici başına 20 USD / ay",
			"koltuk başına",
		]) {
			expect(sample).toMatch(CURRENCY_OR_PRICE);
		}
		for (const sample of [
			"Paid editions are licensed per developer seat",
			"Quote-based",
			"Contact sales",
			"Prices are not published.",
			"Minimum 25 developers",
		]) {
			expect(sample).not.toMatch(CURRENCY_OR_PRICE);
		}
	});

	for (const selfService of [false, true]) {
		describe(selfService ? "self-service build" : "invoice build", () => {
			for (const [path, page] of PUBLIC_ROUTES) {
				it(`renders ${path} without price or currency text`, async () => {
					commercial.selfService = selfService;
					vi.stubEnv("VITE_SALES_EMAIL", "sales@example.test");
					const text = await renderedText(path, page);
					expect(text.length).toBeGreaterThan(0);
					expect(text.match(CURRENCY_OR_PRICE)?.[0] ?? null).toBeNull();
				});
			}
		});
	}

	it("labels the /pricing navigation link Editions", async () => {
		await renderedText("/", <LandingPage />);
		expect(screen.getByRole("link", { name: "Editions" })).toHaveAttribute("href", "/pricing");
		expect(screen.getByRole("link", { name: /^View Editions/ })).toHaveAttribute(
			"href",
			"/pricing",
		);
	});
});
