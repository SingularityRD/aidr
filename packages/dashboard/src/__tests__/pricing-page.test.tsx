// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { headlinePrice, PLAN_CATALOG, priceTerms } from "../billing/plans";
import { PricingPage } from "../ui/pages/public/PricingPage";

afterEach(cleanup);

function renderPricing() {
	render(
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

describe("public pricing page", () => {
	it("renders every active catalog plan with its list price and terms", () => {
		renderPricing();
		for (const plan of PLAN_CATALOG) {
			const section = within(planSection(plan.displayName));
			expect(section.getByText(headlinePrice(plan))).toBeInTheDocument();
			expect(section.getByText(priceTerms(plan))).toBeInTheDocument();
		}
		const team = within(planSection("Team"));
		expect(team.getByText("$24")).toBeInTheDocument();
		expect(team.getByText(/\$20 per developer \/ month billed annually/)).toBeInTheDocument();
		expect(team.getByText("Minimum 3 developers")).toBeInTheDocument();
		expect(team.getByText("Browser Privacy Guard")).toBeInTheDocument();
		expect(team.getByText("90-day event retention")).toBeInTheDocument();
		const business = within(planSection("Business"));
		expect(business.getByText("$45")).toBeInTheDocument();
		expect(business.getByText("Minimum 25 developers")).toBeInTheDocument();
		expect(business.getByText("Cloud or On-premises deployment")).toBeInTheDocument();
		expect(business.getByText("SIEM export")).toBeInTheDocument();
		const enterprise = within(planSection("Enterprise"));
		expect(enterprise.getByText("Custom")).toBeInTheDocument();
		expect(enterprise.getByText("On-premises or Air-gapped deployment")).toBeInTheDocument();
		expect(enterprise.getByText("Dedicated support")).toBeInTheDocument();
		const free = within(planSection("Free"));
		expect(free.getByText("$0")).toBeInTheDocument();
		expect(free.getByText("1 protected agent")).toBeInTheDocument();
		expect(free.getByText("7-day event retention")).toBeInTheDocument();
	});

	it("labels the prices as list prices pending COM-001", () => {
		renderPricing();
		expect(screen.getByRole("note")).toHaveTextContent(
			"List prices in USD, per developer seat, before tax. Final SKU approval is pending (COM-001)",
		);
	});

	it("routes self-serve plans to sign-in and sales-assisted plans to scope review", () => {
		renderPricing();
		expect(
			within(planSection("Free")).getByRole("link", { name: "Start with Free" }),
		).toHaveAttribute("href", "/login?returnTo=%2Fonboarding");
		expect(within(planSection("Team")).getByRole("link", { name: "Choose Team" })).toHaveAttribute(
			"href",
			"/login?returnTo=%2Fbilling",
		);
		for (const name of ["Business", "Enterprise"]) {
			expect(
				within(planSection(name)).getByRole("link", { name: "Request scope review" }),
			).toHaveAttribute("href", "/pilot");
		}
	});
});
