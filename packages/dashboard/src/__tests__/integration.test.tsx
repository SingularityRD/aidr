// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession: vi.fn(),
			getUser: vi.fn(),
			signOut: vi.fn(),
			signInWithOAuth: vi.fn(),
			signInWithOtp: vi.fn(),
			signInWithPassword: vi.fn(),
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
import { DashboardPage } from "../ui/pages/DashboardPage";
import { EventsPage } from "../ui/pages/EventsPage";
import { IncidentsPage } from "../ui/pages/IncidentsPage";
import { LoginPage } from "../ui/pages/LoginPage";
import { OnboardingPage } from "../ui/pages/OnboardingPage";
import { DemoPage } from "../ui/pages/public/DemoPage";
import { LandingPage } from "../ui/pages/public/LandingPage";
import { PricingPage } from "../ui/pages/public/PricingPage";
import { SettingsPage } from "../ui/pages/SettingsPage";
import { getSession, signOut } from "../ui/session";
import { ThemeProvider } from "../ui/ThemeProvider";

const mockedSupabase = supabase as unknown as {
	auth: {
		getSession: ReturnType<typeof vi.fn>;
		getUser: ReturnType<typeof vi.fn>;
		signOut: ReturnType<typeof vi.fn>;
		signInWithOAuth: ReturnType<typeof vi.fn>;
		signInWithOtp: ReturnType<typeof vi.fn>;
		signInWithPassword: ReturnType<typeof vi.fn>;
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

const AUTHENTICATED_USER_ID = "22222222-2222-4222-8222-222222222222";
let bootstrapTeamId: string | null = null;

function identityFixture(request?: { body?: { action?: string; tenant_id?: string } }) {
	const assurance = {
		require_mfa: true,
		current_assurance: "aal2",
		next_assurance: "aal2",
		access_allowed: true,
	};
	if (request?.body?.action === "bootstrap") {
		return { data: { ok: true, memberships: [{
			team_id: bootstrapTeamId,
			tenant_id: bootstrapTeamId ?? AUTHENTICATED_USER_ID,
			...assurance,
		}] }, error: null };
	}
	return { data: { ok: true, tenant_id: request?.body?.tenant_id, ...assurance }, error: null };
}

function resetSupabaseMocks() {
	vi.resetAllMocks();
	delete window.__AIDR_CONFIG__;
	window.localStorage.clear();
	bootstrapTeamId = null;
	// These protected page fixtures represent a signed-in caller whose token
	// already satisfies the tenant's server-confirmed MFA policy.
	mockedSupabase.auth.getSession.mockResolvedValue({
		data: { session: { user: { id: AUTHENTICATED_USER_ID }, access_token: "integration-aal2-session" } },
		error: null,
	});
	mockedSupabase.auth.getUser.mockResolvedValue({ data: { user: { id: "22222222-2222-4222-8222-222222222222" } }, error: null });
	mockedSupabase.auth.signOut.mockResolvedValue({ error: null });
	mockedSupabase.auth.signInWithOAuth.mockResolvedValue({ data: { url: null }, error: null });
	mockedSupabase.auth.signInWithOtp.mockResolvedValue({ data: {}, error: null });
	mockedSupabase.auth.onAuthStateChange.mockReturnValue({
		data: { subscription: { unsubscribe: vi.fn() } },
	});
	mockedSupabase.functions.invoke.mockImplementation(async (name: string, request?: { body?: { action?: string; tenant_id?: string } }) =>
		name === "identity-security" ? identityFixture(request) : { data: {}, error: null },
	);
	mockedSupabase.from.mockImplementation(() => createQueryBuilder());
}

describe("Dashboard integration", () => {
	beforeEach(resetSupabaseMocks);
	afterEach(cleanup);

	it("renders the authenticated navigation", async () => {
		render(
			<MemoryRouter initialEntries={["/agents"]}>
				<Routes>
					<Route path="/*" element={<AppLayout />}>
						<Route path="agents" element={<div>Agents content</div>} />
					</Route>
				</Routes>
			</MemoryRouter>,
		);

		await waitFor(() => expect(screen.getByText("Singularity AIDR")).toBeInTheDocument());
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

	it("self-hosted login exposes configured password auth and preserves a safe return path", async () => {
		window.__AIDR_CONFIG__ = { authMethods: ["password"] };
		mockedSupabase.auth.signInWithPassword.mockResolvedValue({ data: {}, error: null });
		render(
			<MemoryRouter initialEntries={["/login?returnTo=%2Fenterprise"]}>
				<Routes>
					<Route path="/login" element={<LoginPage />} />
					<Route path="/enterprise" element={<div>Customer workspace</div>} />
				</Routes>
			</MemoryRouter>,
		);
		expect(screen.queryByText("Continue with Google")).not.toBeInTheDocument();
		expect(screen.queryByText("Send magic link")).not.toBeInTheDocument();
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "owner@example.test" },
		});
		fireEvent.change(screen.getByLabelText("Password"), {
			target: { value: "test-only-password-long" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
		await waitFor(() => expect(screen.getByText("Customer workspace")).toBeInTheDocument());
		expect(mockedSupabase.auth.signInWithPassword).toHaveBeenCalledWith(
			expect.objectContaining({ email: "owner@example.test", password: "test-only-password-long" }),
		);
	});

	it("failed password sign-in clears the password without exposing account details", async () => {
		window.__AIDR_CONFIG__ = { authMethods: ["password"] };
		mockedSupabase.auth.signInWithPassword.mockResolvedValue({
			error: { message: "private backend detail" },
		});
		render(
			<MemoryRouter>
				<LoginPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "owner@example.test" },
		});
		fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong-password" } });
		fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Sign-in failed"));
		expect(screen.getByLabelText("Password")).toHaveValue("");
		expect(screen.queryByText("private backend detail")).not.toBeInTheDocument();
	});

	it("renders agents and fail-closed entitlement status", async () => {
		render(
			<MemoryRouter>
				<TeamProvider>
					<AgentsPage />
				</TeamProvider>
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

		await waitFor(() => expect(screen.getByRole("heading", { name: "AutoSecOps" })).toBeInTheDocument());
		expect(screen.getByText("Not connected")).toBeInTheDocument();
		expect(screen.getByText("No AutoSecOps runtime agents reported yet.")).toBeInTheDocument();
	});

	it("renders the AutoSecOps health and fleet returned by the authenticated bridge", async () => {
		const teamId = "11111111-1111-4111-8111-111111111111";
		bootstrapTeamId = teamId;
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
			async (name: string, options: { body?: { action?: string; tenant_id?: string } }) => {
				if (name === "identity-security") return identityFixture(options);
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
		bootstrapTeamId = teamId;
		mockedSupabase.from.mockImplementation((table: string) =>
			createQueryBuilder(
				table === "team_members"
					? [{ team_id: teamId, role: "admin", teams: { id: teamId, name: "Runtime team" } }]
					: [],
			),
		);
		mockedSupabase.functions.invoke.mockImplementation(async (name: string, request?: { body?: { action?: string; tenant_id?: string } }) =>
			name === "identity-security" ? identityFixture(request) : {
				data: { ok: true, provider: "unexpected", data: {} },
				error: null,
			},
		);

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
				<TeamProvider>
					<BillingPage />
				</TeamProvider>
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

	it("renders blocked and approval-required AIDR events in the incidents dashboard", async () => {
		const agentId = "agent-demo-001";
		mockedSupabase.from.mockImplementation((table: string) =>
			createQueryBuilder(
				table === "incident_events"
					? [
							{
								id: 101,
								type: "runtime_verdict",
								created_at: "2026-08-11T09:30:00.000Z",
								agent_id: agentId,
								payload: {
									tool_name: "bash",
									verdict: "deny",
									severity: "critical",
								},
							},
							{
								id: 102,
								type: "runtime_verdict",
								created_at: "2026-08-11T09:31:00.000Z",
								agent_id: agentId,
								payload: {
									tool_name: "write",
									verdict: "ask",
									severity: "warning",
								},
							},
							{
								id: 103,
								type: "runtime_verdict",
								created_at: "2026-08-11T09:32:00.000Z",
								agent_id: agentId,
								payload: { tool_name: "git", verdict: "allow", severity: "info" },
							},
						]
					: table === "agents"
						? [
								{
									id: agentId,
									iid: "iid-demo-001",
									display_name: "Demo OpenCode agent",
									agent_runtime: "opencode",
								},
							]
						: [],
			),
		);

		render(
			<MemoryRouter>
				<IncidentsPage />
			</MemoryRouter>,
		);

		await waitFor(() => expect(screen.getByText("bash: deny (critical)")).toBeInTheDocument());
		expect(screen.getAllByText("Demo OpenCode agent")).toHaveLength(2);
		expect(screen.getByText("bash: deny (critical)")).toBeInTheDocument();
		expect(screen.getByText("write: ask (warning)")).toBeInTheDocument();
		expect(screen.queryByText("git: allow (info)")).not.toBeInTheDocument();
		expect(mockedSupabase.from).toHaveBeenCalledWith("incident_events");
	});

	it("propagates agent API errors to the visible UI", async () => {
		bootstrapTeamId = "11111111-1111-4111-8111-111111111111";
		mockedSupabase.from.mockImplementation((table: string) => {
			if (table === "team_members") return createQueryBuilder([{ team_id: "11111111-1111-4111-8111-111111111111", role: "owner", teams: { id: "11111111-1111-4111-8111-111111111111", name: "Customer", plan: "enterprise" } }]);
			const query = createQueryBuilder();
			query.order.mockResolvedValue({ data: null, error: { message: "Database error" } });
			query.maybeSingle.mockResolvedValue({ data: null, error: { message: "Database error" } });
			return query;
		});

		render(
			<MemoryRouter>
				<TeamProvider>
					<AgentsPage />
				</TeamProvider>
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

	it("renders the control-plane overview from real fleet queries", async () => {
		const now = new Date().toISOString();
		mockedSupabase.from.mockImplementation((table: string) =>
			createQueryBuilder(
				table === "agents"
					? [
							{
								id: "agent-1",
								iid: "iid-overview-1",
								display_name: "overview-agent",
								agent_runtime: "claude-code",
								last_seen: now,
							},
						]
					: table === "events"
						? [
								{
									id: 900,
									type: "runtime_verdict",
									created_at: now,
									agent_id: "agent-1",
									payload: { tool_name: "bash", verdict: "deny", severity: "critical" },
								},
							]
						: [],
			),
		);

		render(
			<MemoryRouter>
				<DashboardPage />
			</MemoryRouter>,
		);

		expect(
			screen.getByText("Observe every agent decision from one secure dashboard."),
		).toBeInTheDocument();
		await waitFor(() => expect(screen.getByText("overview-agent")).toBeInTheDocument());
		expect(screen.getByText("Live agents")).toBeInTheDocument();
		expect(screen.getByText("Recent events")).toBeInTheDocument();
		expect(screen.getByText("bash: deny")).toBeInTheDocument();
		expect(screen.getByText("connected")).toBeInTheDocument();
	});

	it("keeps overview counters fail-closed when fleet queries fail", async () => {
		mockedSupabase.from.mockImplementation((table: string) => {
			const query = createQueryBuilder();
			if (table === "agents") {
				query.order.mockResolvedValue({ data: null, error: { message: "Agents down" } });
			} else {
				query.limit.mockResolvedValue({ data: null, error: { message: "Events down" } });
			}
			return query;
		});

		render(
			<MemoryRouter>
				<DashboardPage />
			</MemoryRouter>,
		);

		await waitFor(() =>
			expect(screen.getByText("Agent data is unavailable right now.")).toBeInTheDocument(),
		);
		expect(screen.getByText("Event data is unavailable right now.")).toBeInTheDocument();
		// Agents / Connected / Events / Deny / Ask / Pending all render an
		// honest "—" because the mocked enrollment response has no acknowledgement.
		expect(screen.getAllByText("—")).toHaveLength(6);
		expect(screen.getByText("unavailable")).toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent("Agents down Events down");
	});

	it("keeps the events feed fail-closed when the events query fails", async () => {
		mockedSupabase.from.mockImplementation((table: string) => {
			const query = createQueryBuilder();
			if (table === "events") {
				query.limit.mockResolvedValue({ data: null, error: { message: "Events down" } });
			}
			return query;
		});

		render(
			<MemoryRouter>
				<EventsPage />
			</MemoryRouter>,
		);

		await waitFor(() =>
			expect(screen.getByText("Event data is unavailable right now.")).toBeInTheDocument(),
		);
		expect(screen.queryByText("0 deny")).not.toBeInTheDocument();
		expect(screen.getByRole("alert")).toHaveTextContent("Events down");
	});

	it("renders the raw events feed with verdict badges", async () => {
		const now = new Date().toISOString();
		mockedSupabase.from.mockImplementation((table: string) =>
			createQueryBuilder(
				table === "events"
					? [
							{
								id: 901,
								type: "runtime_verdict",
								created_at: now,
								agent_id: "agent-1",
								payload: { tool_name: "fetch", verdict: "deny", severity: "high" },
							},
							{
								id: 902,
								type: "runtime_verdict",
								created_at: now,
								agent_id: "agent-1",
								payload: { tool_name: "git", verdict: "allow", severity: "info" },
							},
						]
					: table === "agents"
						? [
								{
									id: "agent-1",
									iid: "iid-events-1",
									display_name: "events-agent",
									agent_runtime: "cursor",
								},
							]
						: [],
			),
		);

		render(
			<MemoryRouter>
				<EventsPage />
			</MemoryRouter>,
		);

		await waitFor(() => expect(screen.getByText("fetch (high)")).toBeInTheDocument());
		expect(screen.getByText("git (info)")).toBeInTheDocument();
		expect(screen.getByText("1 deny")).toBeInTheDocument();
		expect(screen.getByText("1 allow")).toBeInTheDocument();
		expect(mockedSupabase.from).toHaveBeenCalledWith("events");
	});

	it("renders settings and signs out through the Supabase client", async () => {
		render(
			<MemoryRouter>
				<ThemeProvider>
					<SettingsPage />
				</ThemeProvider>
			</MemoryRouter>,
		);

		expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();
		fireEvent.click(screen.getByText("Sign out of this session"));
		await waitFor(() => expect(mockedSupabase.auth.signOut).toHaveBeenCalled());
	});

	it("mounts onboarding and incidents without crashing", () => {
		const onboarding = render(
			<MemoryRouter>
				<TeamProvider><OnboardingPage /></TeamProvider>
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
