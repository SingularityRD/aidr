// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession: vi.fn(),
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

import { TeamProvider } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { AppLayout } from "../ui/AppLayout";
import { PublicLayout } from "../ui/PublicLayout";
import { AgentsPage } from "../ui/pages/AgentsPage";
import { AutoSecOpsPage } from "../ui/pages/AutoSecOpsPage";
import { BillingPage } from "../ui/pages/BillingPage";
import { IncidentsPage } from "../ui/pages/IncidentsPage";
import { LoginPage } from "../ui/pages/LoginPage";
import { OnboardingPage } from "../ui/pages/OnboardingPage";
import { DemoPage } from "../ui/pages/public/DemoPage";
import { LandingPage } from "../ui/pages/public/LandingPage";
import { PricingPage } from "../ui/pages/public/PricingPage";
import { getSession, signOut } from "../ui/session";

const mockedSupabase = supabase as unknown as {
	auth: {
		getSession: ReturnType<typeof vi.fn>;
		signOut: ReturnType<typeof vi.fn>;
		signInWithOAuth: ReturnType<typeof vi.fn>;
		signInWithOtp: ReturnType<typeof vi.fn>;
		onAuthStateChange: ReturnType<typeof vi.fn>;
	};
	functions: { invoke: ReturnType<typeof vi.fn> };
	from: ReturnType<typeof vi.fn>;
};

function createQueryBuilder(defaultData: unknown[] = []) {
	const result = { data: defaultData, error: null, count: defaultData.length };
	const chain = {
		select: vi.fn(),
		order: vi.fn(),
		limit: vi.fn(),
		maybeSingle: vi.fn(),
		single: vi.fn(),
		eq: vi.fn(),
		neq: vi.fn(),
		in: vi.fn(),
		gte: vi.fn(),
		lte: vi.fn(),
		then: (resolve: (value: typeof result) => unknown) => Promise.resolve(result).then(resolve),
	};

	for (const method of ["select", "order", "limit", "eq", "neq", "in", "gte", "lte"] as const) {
		chain[method].mockReturnValue(chain);
	}
	chain.maybeSingle.mockResolvedValue({ data: null, error: null });
	chain.single.mockResolvedValue({ data: null, error: null });
	return chain;
}

function resetSupabaseMocks() {
	vi.resetAllMocks();
	mockedSupabase.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });
	mockedSupabase.auth.signOut.mockResolvedValue({ error: null });
	mockedSupabase.auth.signInWithOAuth.mockResolvedValue({ data: { url: null }, error: null });
	mockedSupabase.auth.signInWithOtp.mockResolvedValue({ data: {}, error: null });
	mockedSupabase.auth.onAuthStateChange.mockReturnValue({
		data: { subscription: { unsubscribe: vi.fn() } },
	});
	mockedSupabase.functions.invoke.mockResolvedValue({ data: {}, error: null });
	mockedSupabase.from.mockImplementation(() => createQueryBuilder());
}

describe("Dashboard integration", () => {
	beforeEach(resetSupabaseMocks);
	afterEach(cleanup);

	it("renders the authenticated navigation", () => {
		render(
			<MemoryRouter initialEntries={["/agents"]}>
				<Routes>
					<Route path="/*" element={<AppLayout />}>
						<Route path="agents" element={<div>Agents content</div>} />
					</Route>
				</Routes>
			</MemoryRouter>,
		);

		expect(screen.getByText("Singularity AIDR")).toBeInTheDocument();
		expect(screen.getByText("Agents")).toBeInTheDocument();
		expect(screen.getByText("Billing")).toBeInTheDocument();
		expect(screen.getByText("Sign out")).toBeInTheDocument();
	});

	it("renders the login form and submits OAuth", async () => {
		render(
			<MemoryRouter initialEntries={["/login"]}>
				<Routes>
					<Route path="/login" element={<LoginPage />} />
				</Routes>
			</MemoryRouter>,
		);

		expect(screen.getByText("Welcome to AIDR")).toBeInTheDocument();
		expect(screen.getByPlaceholderText("you@company.com")).toBeInTheDocument();
		fireEvent.click(screen.getByText("Continue with Google"));
		await waitFor(() => expect(mockedSupabase.auth.signInWithOAuth).toHaveBeenCalled());
	});

	it("renders agents and fail-closed entitlement status", async () => {
		render(
			<MemoryRouter>
				<AgentsPage />
			</MemoryRouter>,
		);

		await waitFor(() => expect(screen.getByText("Agents")).toBeInTheDocument());
		expect(screen.getByText(/Allowed:/)).toBeInTheDocument();
		expect(screen.getByText("unavailable")).toBeInTheDocument();
		expect(screen.getByText("Name")).toBeInTheDocument();
	});

	it("renders the AutoSecOps integration boundary without inventing runtime data", async () => {
		render(
			<MemoryRouter>
				<TeamProvider>
					<AutoSecOpsPage />
				</TeamProvider>
			</MemoryRouter>,
		);

		expect(screen.getByRole("heading", { name: "AutoSecOps" })).toBeInTheDocument();
		expect(screen.getByText("Not connected")).toBeInTheDocument();
		expect(screen.getByText("No AutoSecOps runtime agents reported yet.")).toBeInTheDocument();
	});

	it("renders the AutoSecOps health and fleet returned by the authenticated bridge", async () => {
		const teamId = "11111111-1111-4111-8111-111111111111";
		mockedSupabase.from.mockImplementation((table: string) =>
			createQueryBuilder(
				table === "team_members"
					? [
							{
								team_id: teamId,
								role: "admin",
								teams: {
									id: teamId,
									name: "Runtime team",
									plan: "pro",
									created_at: "2026-01-01T00:00:00.000Z",
									updated_at: "2026-01-01T00:00:00.000Z",
								},
							},
						]
					: [],
			),
		);
		mockedSupabase.functions.invoke.mockImplementation(
			async (_name: string, options: { body?: { action?: string } }) => {
				if (options.body?.action === "health") {
					return {
						data: {
							ok: true,
							provider: "autosecops",
							action: "health",
							data: { snapshot: { state: "healthy", active_agents: 1, open_degradations: 0 } },
						},
						error: null,
					};
				}
				return {
					data: {
						ok: true,
						provider: "autosecops",
						action: "fleet",
						data: {
							response: {
								items: [
									{
										agent_id: "agent-1",
										agent_name: "codex-agent",
										runtime: "codex",
										connector: "sdk",
										state: "active",
										health: "healthy",
									},
								],
							},
						},
					},
					error: null,
				};
			},
		);

		render(
			<MemoryRouter>
				<TeamProvider>
					<AutoSecOpsPage />
				</TeamProvider>
			</MemoryRouter>,
		);

		await waitFor(() => expect(screen.getByText("healthy")).toBeInTheDocument());
		expect(screen.getByText("codex-agent")).toBeInTheDocument();
		expect(mockedSupabase.functions.invoke).toHaveBeenCalledWith(
			"autosecops-runtime",
			expect.objectContaining({
				body: expect.objectContaining({ action: "fleet", team_id: teamId }),
			}),
		);
	});

	it("fails closed on a malformed successful AutoSecOps response", async () => {
		const teamId = "11111111-1111-4111-8111-111111111111";
		mockedSupabase.from.mockImplementation((table: string) =>
			createQueryBuilder(
				table === "team_members"
					? [{ team_id: teamId, role: "admin", teams: { id: teamId, name: "Runtime team" } }]
					: [],
			),
		);
		mockedSupabase.functions.invoke.mockResolvedValue({
			data: { ok: true, provider: "unexpected", data: {} },
			error: null,
		});

		render(
			<MemoryRouter>
				<TeamProvider>
					<AutoSecOpsPage />
				</TeamProvider>
			</MemoryRouter>,
		);

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("AutoSecOps health response is invalid."),
		);
		expect(screen.getByRole("alert")).toHaveTextContent(
			"No synthetic or cached AutoSecOps data is shown when the bridge is unavailable.",
		);
	});

	it("renders the invoice-only billing path without invoking checkout", async () => {
		render(
			<MemoryRouter>
				<BillingPage />
			</MemoryRouter>,
		);

		await waitFor(() =>
			expect(screen.getByText(/Self-service checkout is disabled/)).toBeInTheDocument(),
		);
		expect(mockedSupabase.functions.invoke).not.toHaveBeenCalledWith(
			"billing-checkout",
			expect.anything(),
		);
	});

	it("renders the public landing and pricing routes", () => {
		render(
			<MemoryRouter initialEntries={["/pricing"]}>
				<Routes>
					<Route path="/" element={<PublicLayout />}>
						<Route index element={<LandingPage />} />
						<Route path="pricing" element={<PricingPage />} />
					</Route>
				</Routes>
			</MemoryRouter>,
		);

		expect(screen.getByRole("heading", { name: "Pricing" })).toBeInTheDocument();
		expect(screen.getByText("Enterprise")).toBeInTheDocument();
	});

	it("runs the controlled synthetic demo without invoking Supabase", async () => {
		render(
			<MemoryRouter>
				<DemoPage />
			</MemoryRouter>,
		);

		expect(screen.getByRole("heading", { name: /See the security workflow/ })).toBeInTheDocument();
		expect(screen.getByText("demo-2026-08-04.1")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Run synthetic fixture" }));
		await waitFor(() => expect(screen.getByText(/No external command/)).toBeInTheDocument());
		expect(mockedSupabase.functions.invoke).not.toHaveBeenCalled();
	});

	it("propagates agent API errors to the visible UI", async () => {
		mockedSupabase.from.mockImplementation(() => {
			const query = createQueryBuilder();
			query.order.mockResolvedValue({ data: null, error: { message: "Database error" } });
			query.maybeSingle.mockResolvedValue({ data: null, error: { message: "Database error" } });
			return query;
		});

		render(
			<MemoryRouter>
				<AgentsPage />
			</MemoryRouter>,
		);

		await waitFor(() => expect(screen.getAllByText("Database error").length).toBeGreaterThan(0));
	});

	it("invokes sign-out and session reads through the Supabase client", async () => {
		await getSession();
		await signOut();
		expect(mockedSupabase.auth.getSession).toHaveBeenCalled();
		expect(mockedSupabase.auth.signOut).toHaveBeenCalled();
	});

	it("mounts onboarding and incidents without crashing", () => {
		const onboarding = render(
			<MemoryRouter>
				<OnboardingPage />
			</MemoryRouter>,
		);
		expect(onboarding.container).toBeTruthy();
		onboarding.unmount();

		const incidents = render(
			<MemoryRouter>
				<IncidentsPage />
			</MemoryRouter>,
		);
		expect(incidents.container).toBeTruthy();
	});
});
