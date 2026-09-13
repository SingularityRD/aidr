// @vitest-environment jsdom

// Regression guards for AIDR-010 (dead dashboard modules) and for the
// invite-acceptance half of AIDR-008.
//
// The reference scan that produced AIDR-010 counted eight modules with zero
// references. Two of them (billing/provider-selector.tsx and
// billing/payment-router.ts) are not actually dead: the invoice-first
// commercial contract in billing-stripe.test.ts and
// scripts/check-commercial-surface.mjs pins their contents. The other six are
// removed here, because every backend they need is absent from the repository,
// so wiring them would only have shipped a surface that cannot work. This file
// records that decision as an executable guard, plus the reachability check
// that would have caught AIDR-008/AIDR-009 in the first place.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

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
	},
	supabaseEnvError: null,
}));

import { EnterpriseAuth } from "../enterprise/auth";
import { installDashboardMocks } from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const DASHBOARD_SRC = resolve(REPO_ROOT, "packages/dashboard/src");

/** Modules deleted by the AIDR-010 triage, with the missing dependency that killed them. */
const DELETED_MODULES: Array<{ path: string; reason: string }> = [
	{
		path: "billing/agent-seat-manager.tsx",
		reason:
			"writes agent_seats (created by no migration) and invokes billing-portal (absent); duplicates the reachable BillingPage seat view",
	},
	{
		path: "billing/seat-manager.tsx",
		reason:
			"reads users, agent_seats and referral_credits (created by no migration) and subscriptions.plan_type/seats (absent columns)",
	},
	{
		path: "billing/referral-section.tsx",
		reason: "reads users and referral_credits (created by no migration)",
	},
	{
		path: "billing/index.ts",
		reason: "barrel that only re-exported the deleted agent seat manager",
	},
	{
		path: "auth/invite-system.tsx",
		reason:
			"reads referrals and users (created by no migration) and invokes send-invite-email, grant-referral-credits and claim-referral-credits (absent)",
	},
	{
		path: "ui/DarkModeToggle.tsx",
		reason: "byte-for-byte duplicate of the reachable ui/ThemeToggle.tsx",
	},
	{
		path: "billing/lemon-client.ts",
		reason: "Lemon Squeezy removal already required by billing-stripe.test.ts",
	},
];

/** Modules whose data layer exists, so they stay even though they are unreferenced today. */
const RETAINED_CONTRACT_MODULES = ["billing/provider-selector.tsx", "billing/payment-router.ts"];

function sourceFiles(dir: string): string[] {
	const found: string[] = [];
	for (const entry of readdirSync(dir)) {
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) found.push(...sourceFiles(full));
		else if (/\.(ts|tsx)$/.test(entry)) found.push(full);
	}
	return found;
}

/** Files reachable from the application entry (main.tsx) by following relative imports. */
function reachableFromEntry(entryName = "main.tsx"): Set<string> {
	const files = sourceFiles(DASHBOARD_SRC);
	const byPath = new Map(files.map((file) => [file, file]));
	const importPattern = /(?:from\s+|import\s*\(\s*)["']([^"']+)["']/g;

	const resolveSpecifier = (fromFile: string, specifier: string): string | null => {
		const base = resolve(dirname(fromFile), specifier);
		for (const candidate of [
			`${base}.ts`,
			`${base}.tsx`,
			join(base, "index.ts"),
			join(base, "index.tsx"),
		]) {
			if (byPath.has(candidate)) return candidate;
		}
		return null;
	};

	const entry = files.find((file) => relative(DASHBOARD_SRC, file) === entryName);
	expect(entry, `${entryName} not found`).toBeTruthy();

	const seen = new Set<string>();
	const queue = [entry as string];
	while (queue.length > 0) {
		const current = queue.pop() as string;
		if (seen.has(current)) continue;
		seen.add(current);
		const source = readFileSync(current, "utf8");
		for (const match of source.matchAll(importPattern)) {
			const specifier = match[1];
			if (!specifier || !specifier.startsWith(".")) continue;
			const resolved = resolveSpecifier(current, specifier);
			if (resolved) queue.push(resolved);
		}
	}
	return new Set([...seen].map((file) => relative(DASHBOARD_SRC, file).replaceAll("\\", "/")));
}

function renderInviteRoute(entry = "/enterprise?invite=invite-token-123") {
	return render(
		<MemoryRouter initialEntries={[entry]}>
			<Routes>
				<Route path="/enterprise" element={<EnterpriseAuth />} />
				<Route path="/team" element={<div>team-route-content</div>} />
			</Routes>
		</MemoryRouter>,
	);
}

describe("Dashboard module surface (AIDR-010)", () => {
	it("keeps the team administration and policy surfaces reachable from the app entry", () => {
		const reachable = reachableFromEntry();
		for (const module of [
			"enterprise/admin-panel.tsx",
			"enterprise/policy-editor.tsx",
			"enterprise/auth.tsx",
			"ui/pages/TeamPage.tsx",
			"ui/pages/PolicyPage.tsx",
			"ui/ThemeToggle.tsx",
		]) {
			expect(reachable, `${module} is not reachable from main.tsx`).toContain(module);
		}
	});

	it("deleted the modules whose entire backend is absent from the repository", () => {
		for (const module of DELETED_MODULES) {
			expect(
				existsSync(resolve(DASHBOARD_SRC, module.path)),
				`${module.path} should be deleted: ${module.reason}`,
			).toBe(false);
		}
	});

	it("keeps the Stripe/invoice contract modules that the commercial surface guard pins", () => {
		for (const module of RETAINED_CONTRACT_MODULES) {
			expect(existsSync(resolve(DASHBOARD_SRC, module))).toBe(true);
		}
		const guard = readFileSync(resolve(REPO_ROOT, "scripts/check-commercial-surface.mjs"), "utf8");
		expect(guard).toContain("provider-selector.tsx");
		expect(guard).toContain("payment-router.ts");
		const billingTest = readFileSync(
			resolve(DASHBOARD_SRC, "__tests__/billing-stripe.test.ts"),
			"utf8",
		);
		expect(billingTest).toContain("../billing/provider-selector");
		expect(billingTest).toContain("../billing/payment-router");
	});
});

describe("Team invitation acceptance (AIDR-008)", () => {
	afterEach(cleanup);

	it("renders the invitation panel for an invite link", () => {
		installDashboardMocks();

		renderInviteRoute();

		expect(screen.getByRole("heading", { name: "Team Invitation" })).toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Accept Invitation" })).toBeInTheDocument();
	});

	it("keeps the invitation token across the sign-in redirect", async () => {
		installDashboardMocks();
		localStorage.clear();

		renderInviteRoute();
		fireEvent.click(screen.getByText("Continue with GitHub"));

		await waitFor(() => expect(localStorage.getItem("aidr.postAuthReturnTo.v1")).not.toBeNull());
		// Dropping the token here meant an invitee came back from the provider
		// with no invitation to accept.
		expect(localStorage.getItem("aidr.postAuthReturnTo.v1")).toBe(
			"/enterprise?invite=invite-token-123",
		);
	});

	it("does not claim the invitation was accepted when oauth-callback is missing", async () => {
		installDashboardMocks({
			invite: { data: null, error: { message: "Failed to send a request to the Edge Function" } },
		});

		renderInviteRoute();
		fireEvent.click(screen.getByRole("button", { name: "Accept Invitation" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/the "oauth-callback" Edge Function is unavailable/,
			),
		);
		expect(screen.getByRole("alert")).toHaveTextContent(/invitation was not accepted/);
		expect(screen.queryByText(/invitation accepted!/i)).not.toBeInTheDocument();
	});

	it("does not claim acceptance when the function answers without confirming", async () => {
		installDashboardMocks({ invite: { data: null, error: null } });

		renderInviteRoute();
		fireEvent.click(screen.getByRole("button", { name: "Accept Invitation" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(/did not confirm the invitation/),
		);
		expect(screen.queryByText(/invitation accepted!/i)).not.toBeInTheDocument();
	});

	it("lands on the real team page after a confirmed acceptance", async () => {
		installDashboardMocks({ invite: { data: { ok: true }, error: null } });

		renderInviteRoute();
		fireEvent.click(screen.getByRole("button", { name: "Accept Invitation" }));

		await waitFor(() =>
			expect(screen.getByText("Team invitation accepted! Redirecting...")).toBeInTheDocument(),
		);
		// The redirect used to target "/team", a route main.tsx never registered.
		await waitFor(
			() => expect(screen.getByText("team-route-content")).toBeInTheDocument(),
			{ timeout: 4000 },
		);
	});
});
