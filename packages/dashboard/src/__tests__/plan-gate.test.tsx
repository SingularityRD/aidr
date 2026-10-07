// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const team = vi.hoisted(() => ({
	currentTeam: { tenant_id: "11111111-1111-4111-8111-111111111111" } as {
		tenant_id: string;
	} | null,
	isLoading: false,
}));
vi.mock("../lib/supabase", () => ({ supabase: { rpc: vi.fn() } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => team }));

import { FEATURE_MINIMUM_PLAN, readTenantEntitlements } from "../billing/entitlements";
import { PLAN_CATALOG } from "../billing/plans";
import { supabase } from "../lib/supabase";
import { PlanGate } from "../ui/PlanGate";

const TENANT = "11111111-1111-4111-8111-111111111111";
const rpc = supabase.rpc as unknown as ReturnType<typeof vi.fn>;

function entitlement(overrides: Record<string, unknown> = {}) {
	return {
		tenant_id: TENANT,
		plan_id: "team",
		plan_source: "stripe_subscription",
		trial_active: false,
		features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"],
		retention_days_max: 90,
		...overrides,
	};
}

function renderGate(feature: Parameters<typeof PlanGate>[0]["feature"]) {
	return render(
		<MemoryRouter>
			<PlanGate feature={feature}>
				<p>gated content</p>
			</PlanGate>
		</MemoryRouter>,
	);
}

beforeEach(() => {
	rpc.mockReset();
	team.currentTeam = { tenant_id: TENANT };
	team.isLoading = false;
});
afterEach(cleanup);

describe("PlanGate", () => {
	it("renders the page when the server-resolved plan includes the feature", async () => {
		rpc.mockResolvedValue({ data: entitlement(), error: null });
		renderGate("entra_sso");
		expect(await screen.findByText("gated content")).toBeInTheDocument();
		expect(rpc).toHaveBeenCalledWith("get_tenant_plan_entitlements", { p_tenant_id: TENANT });
	});

	it("shows an upgrade notice naming the required edition instead of the page", async () => {
		rpc.mockResolvedValue({ data: entitlement(), error: null });
		renderGate("scim");
		expect(await screen.findByText(/View plans and upgrade/)).toHaveAttribute("href", "/billing");
		expect(screen.getByText("Business")).toBeInTheDocument();
		expect(screen.queryByText("gated content")).not.toBeInTheDocument();
	});

	it("explains an inactive licence", async () => {
		rpc.mockResolvedValue({
			data: entitlement({ plan_id: "free", plan_source: "admission_inactive", features: [] }),
			error: null,
		});
		renderGate("siem_export");
		expect(await screen.findByText(/licence or admission is not active/)).toBeInTheDocument();
	});

	it("never shows the page when the plan cannot be read", async () => {
		rpc.mockResolvedValue({ data: null, error: { message: "denied" } });
		renderGate("ai_security_posture");
		expect(await screen.findByRole("alert")).toHaveTextContent("Plan information is unavailable");
		expect(screen.queryByText("gated content")).not.toBeInTheDocument();
	});

	it("rejects a payload for another tenant or an unknown plan", () => {
		expect(readTenantEntitlements(entitlement({ tenant_id: "x" }), TENANT)).toBeNull();
		expect(readTenantEntitlements(entitlement({ plan_id: "pro" }), TENANT)).toBeNull();
		expect(readTenantEntitlements(entitlement(), TENANT)?.features.has("entra_sso")).toBe(true);
	});

	it("names the cheapest catalog edition for each gated feature", () => {
		for (const [feature, plan] of Object.entries(FEATURE_MINIMUM_PLAN)) {
			const cheapest = [...PLAN_CATALOG]
				.sort((a, b) => a.sortOrder - b.sortOrder)
				.find((row) => (row.features as string[]).includes(feature));
			expect(cheapest?.id, feature).toBe(plan);
		}
	});
});
