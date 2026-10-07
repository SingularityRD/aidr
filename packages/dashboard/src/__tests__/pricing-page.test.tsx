// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
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

import { PLAN_CATALOG } from "../billing/plans";
import { PricingPage } from "../ui/pages/public/PricingPage";
import { CURRENCY_OR_PRICE } from "./helpers/public-price-patterns";

const QUOTE_EMAIL = "anil@singularityrd.com";

afterEach(() => {
	cleanup();
	commercial.selfService = false;
});

function renderEditions() {
	return render(
		<MemoryRouter>
			<PricingPage />
		</MemoryRouter>,
	);
}

function planSection(name: string): HTMLElement {
	const section = screen.getByRole("heading", { name }).closest("section");
	if (!section) throw new Error(`no section for ${name}`);
	return section;
}

describe("public editions page (/pricing)", () => {
	it("is titled Editions and compares every catalog edition without a price", () => {
		const { container } = renderEditions();
		expect(screen.getByRole("heading", { level: 1, name: "Editions" })).toBeInTheDocument();
		expect(screen.getByText("Paketler")).toBeInTheDocument();
		for (const plan of PLAN_CATALOG) {
			expect(planSection(plan.displayName)).toBeInTheDocument();
		}
		const team = within(planSection("Team"));
		expect(team.getByText("Quote-based")).toBeInTheDocument();
		expect(team.getByText("Minimum 3 developers")).toBeInTheDocument();
		expect(team.getByText("Browser Privacy Guard")).toBeInTheDocument();
		expect(team.getByText("90-day event retention")).toBeInTheDocument();
		const business = within(planSection("Business"));
		expect(business.getByText("Minimum 25 developers")).toBeInTheDocument();
		expect(business.getByText("Cloud or On-premises deployment")).toBeInTheDocument();
		expect(business.getByText("SIEM export")).toBeInTheDocument();
		const enterprise = within(planSection("Enterprise"));
		expect(enterprise.getByText("On-premises or Air-gapped deployment")).toBeInTheDocument();
		expect(enterprise.getByText("Dedicated support")).toBeInTheDocument();
		const free = within(planSection("Free"));
		expect(free.getByText("1 protected agent")).toBeInTheDocument();
		expect(free.getByText("7-day event retention")).toBeInTheDocument();
		expect(container.textContent ?? "").not.toMatch(CURRENCY_OR_PRICE);
		expect(container.querySelector(".price")).toBeNull();
	});

	it("states that prices are not published and offers the quote contact", () => {
		renderEditions();
		const note = screen.getByRole("note");
		expect(note).toHaveTextContent("Prices are not published.");
		expect(note).not.toHaveTextContent(/list price|COM-001/i);
		expect(within(note).getByRole("link", { name: QUOTE_EMAIL })).toHaveAttribute(
			"href",
			expect.stringMatching(new RegExp(`^mailto:${QUOTE_EMAIL}\\?`)),
		);
		expect(screen.getByText("Teklif alın")).toBeInTheDocument();
	});

	it("gives every paid edition a Contact sales CTA to anil@singularityrd.com", () => {
		renderEditions();
		for (const name of ["Team", "Business", "Enterprise"]) {
			const cta = within(planSection(name)).getByRole("link", {
				name: `Contact sales about ${name}`,
			});
			expect(cta).toHaveTextContent("Contact sales");
			expect(cta.getAttribute("href")).toBe(
				`mailto:${QUOTE_EMAIL}?subject=${encodeURIComponent(`Singularity AIDR ${name} quote request`)}`,
			);
		}
		expect(
			within(planSection("Free")).queryByRole("link", { name: /Contact sales/ }),
		).not.toBeInTheDocument();
	});

	it("routes every paid edition to scope review while online checkout is off (invoice mode)", () => {
		renderEditions();
		expect(screen.getByText(/self-service checkout is not offered/)).toBeInTheDocument();
		expect(
			within(planSection("Free")).getByRole("link", { name: "Start with Free" }),
		).toHaveAttribute("href", "/login?returnTo=%2Fonboarding");
		for (const name of ["Team", "Business", "Enterprise"]) {
			const section = within(planSection(name));
			expect(section.getByRole("link", { name: "Request scope review" })).toHaveAttribute(
				"href",
				"/pilot",
			);
			expect(section.getByText("Sales-assisted")).toBeInTheDocument();
		}
		expect(screen.queryByRole("link", { name: "Choose Team" })).not.toBeInTheDocument();
	});

	it("routes self-serve editions to sign-in and keeps the quote CTA, still without prices", () => {
		commercial.selfService = true;
		const { container } = renderEditions();
		expect(
			within(planSection("Free")).getByRole("link", { name: "Start with Free" }),
		).toHaveAttribute("href", "/login?returnTo=%2Fonboarding");
		const team = within(planSection("Team"));
		expect(team.getByRole("link", { name: "Choose Team" })).toHaveAttribute(
			"href",
			"/login?returnTo=%2Fbilling",
		);
		expect(team.getByRole("link", { name: "Contact sales about Team" })).toBeInTheDocument();
		expect(team.getByText("Self-serve")).toBeInTheDocument();
		for (const name of ["Business", "Enterprise"]) {
			expect(
				within(planSection(name)).getByRole("link", { name: "Request scope review" }),
			).toHaveAttribute("href", "/pilot");
		}
		expect(container.textContent ?? "").not.toMatch(CURRENCY_OR_PRICE);
	});
});
