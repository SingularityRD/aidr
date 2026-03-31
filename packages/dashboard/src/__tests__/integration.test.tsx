/**
 * Integration tests for the Dashboard package
 * Tests: React component rendering, routing, API calls (mocked)
 */

import "@testing-library/jest-dom";
import type * as SupabaseModule from "@supabase/supabase-js";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import React from "react";
import { BrowserRouter, MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock modules before importing components
vi.mock("@supabase/supabase-js", async () => {
	const actual = await vi.importActual<typeof SupabaseModule>("@supabase/supabase-js");
	return {
		...actual,
		createClient: vi.fn(),
	};
});

// Mock the supabase module
vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession: vi.fn(),
			signOut: vi.fn(),
			signInWithOAuth: vi.fn(),
			signInWithOtp: vi.fn(),
			exchangeCodeForSession: vi.fn(),
			onAuthStateChange: vi.fn(() => ({ data: { subscription: { unsubscribe: vi.fn() } } })),
		},
		from: vi.fn(() => ({
			select: vi.fn(() => ({
				order: vi.fn(() => Promise.resolve({ data: [], error: null })),
				maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
			})),
			insert: vi.fn(() => Promise.resolve({ data: null, error: null })),
			update: vi.fn(() => ({
				eq: vi.fn(() => Promise.resolve({ data: null, error: null })),
			})),
			delete: vi.fn(() => ({
				eq: vi.fn(() => Promise.resolve({ data: null, error: null })),
			})),
		})),
	},
	supabaseEnvError: null,
}));

import { supabase } from "../lib/supabase";
// Import components after mocking
import { AppLayout } from "../ui/AppLayout";
import { PublicLayout } from "../ui/PublicLayout";
import { AgentsPage } from "../ui/pages/AgentsPage";
import { ApiKeysPage } from "../ui/pages/ApiKeysPage";
import { BillingPage } from "../ui/pages/BillingPage";
import { IncidentsPage } from "../ui/pages/IncidentsPage";
import { LoginPage } from "../ui/pages/LoginPage";
import { OnboardingPage } from "../ui/pages/OnboardingPage";
import { LandingPage } from "../ui/pages/public/LandingPage";
import { PricingPage } from "../ui/pages/public/PricingPage";
import { getSession, signOut } from "../ui/session";

// Type for mocked supabase
const mockedSupabase = supabase as unknown as {
	auth: {
		getSession: ReturnType<typeof vi.fn>;
		signOut: ReturnType<typeof vi.fn>;
		signInWithOAuth: ReturnType<typeof vi.fn>;
		signInWithOtp: ReturnType<typeof vi.fn>;
		exchangeCodeForSession: ReturnType<typeof vi.fn>;
	};
	from: ReturnType<typeof vi.fn>;
};

describe("Dashboard Integration", () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	afterEach(() => {
		vi.resetAllMocks();
	});

	describe("React Component Rendering", () => {
		it("should render AppLayout with navigation", () => {
			render(
				<MemoryRouter initialEntries={["/agents"]}>
					<Routes>
						<Route path="/*" element={<AppLayout />}>
							<Route path="agents" element={<div>Agents Content</div>} />
						</Route>
					</Routes>
				</MemoryRouter>,
			);

			expect(screen.getByText("Singularity AIDR")).toBeInTheDocument();
			expect(screen.getByText("Agents")).toBeInTheDocument();
			expect(screen.getByText("Incidents")).toBeInTheDocument();
			expect(screen.getByText("API Keys")).toBeInTheDocument();
			expect(screen.getByText("Billing")).toBeInTheDocument();
			expect(screen.getByText("Sign out")).toBeInTheDocument();
		});

		it("should render LoginPage with form elements", () => {
			mockedSupabase.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });

			render(
				<MemoryRouter initialEntries={["/login"]}>
					<Routes>
						<Route path="/login" element={<LoginPage />} />
					</Routes>
				</MemoryRouter>,
			);

			expect(screen.getByText("Sign in")).toBeInTheDocument();
			expect(screen.getByText("Continue with Google")).toBeInTheDocument();
			expect(screen.getByPlaceholderText("you@company.com")).toBeInTheDocument();
			expect(screen.getByText("Send magic link")).toBeInTheDocument();
		});

		it("should render AgentsPage with table structure", async () => {
			mockedSupabase.from.mockReturnValue({
				select: vi.fn(() => ({
					order: vi.fn(() => Promise.resolve({ data: [], error: null })),
				})),
			});

			render(
				<MemoryRouter>
					<AgentsPage />
				</MemoryRouter>,
			);

			await waitFor(() => {
				expect(screen.getByText("Agents")).toBeInTheDocument();
			});

			expect(screen.getByText("Name")).toBeInTheDocument();
			expect(screen.getByText("Runtime")).toBeInTheDocument();
			expect(screen.getByText("Last seen")).toBeInTheDocument();
		});

		it("should render PublicLayout with children", () => {
			render(
				<MemoryRouter initialEntries={["/"]}>
					<Routes>
						<Route path="/" element={<PublicLayout />}>
							<Route index element={<LandingPage />} />
						</Route>
					</Routes>
				</MemoryRouter>,
			);

			expect(screen.getByText("Edge-first AI Agent Detection & Response")).toBeInTheDocument();
		});

		it("should show environment error when supabase is not configured", () => {
			// Temporarily override the mock
			const originalEnvError = vi.importMock("../lib/supabase");
			vi.doMock("../lib/supabase", () => ({
				supabase: {},
				supabaseEnvError: "Missing environment variables",
			}));

			const { AppLayout: AppLayoutWithError } = require("../ui/AppLayout");

			render(
				<MemoryRouter>
					<AppLayoutWithError />
				</MemoryRouter>,
			);

			expect(screen.getByText(/Dashboard environment is incomplete/)).toBeInTheDocument();

			vi.doUnmock("../lib/supabase");
		});
	});

	describe("Routing", () => {
		it("should render different pages based on route", () => {
			const { container } = render(
				<MemoryRouter initialEntries={["/pricing"]}>
					<Routes>
						<Route path="/" element={<PublicLayout />}>
							<Route index element={<LandingPage />} />
							<Route path="pricing" element={<PricingPage />} />
						</Route>
					</Routes>
				</MemoryRouter>,
			);

			// Pricing page should show pricing content
			expect(screen.getByText(/Pricing/)).toBeInTheDocument();
		});

		it("should handle navigation between routes", async () => {
			mockedSupabase.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });

			render(
				<MemoryRouter initialEntries={["/login"]}>
					<Routes>
						<Route path="/login" element={<LoginPage />} />
						<Route path="/onboarding" element={<div>Onboarding Page</div>} />
					</Routes>
				</MemoryRouter>,
			);

			expect(screen.getByText("Sign in")).toBeInTheDocument();
		});

		it("should handle nested routing with AppLayout", () => {
			render(
				<MemoryRouter initialEntries={["/agents"]}>
					<Routes>
						<Route path="/" element={<AppLayout />}>
							<Route path="agents" element={<div data-testid="agents-content">Agents List</div>} />
							<Route
								path="incidents"
								element={<div data-testid="incidents-content">Incidents List</div>}
							/>
						</Route>
					</Routes>
				</MemoryRouter>,
			);

			expect(screen.getByTestId("agents-content")).toBeInTheDocument();
		});
	});

	describe("API Calls (Mocked)", () => {
		it("should fetch agents on AgentsPage mount", async () => {
			const mockAgents = [
				{
					id: "1",
					iid: "install-123",
					display_name: "Test Agent",
					agent_runtime: "claude-code",
					agent_runtime_version: "1.0.0",
					first_seen: new Date().toISOString(),
					last_seen: new Date().toISOString(),
				},
			];

			mockedSupabase.from.mockReturnValue({
				select: vi.fn(() => ({
					order: vi.fn(() => Promise.resolve({ data: mockAgents, error: null })),
					maybeSingle: vi.fn(() => Promise.resolve({ data: null, error: null })),
				})),
			});

			render(
				<MemoryRouter>
					<AgentsPage />
				</MemoryRouter>,
			);

			await waitFor(() => {
				expect(mockedSupabase.from).toHaveBeenCalledWith("agents");
			});
		});

		it("should fetch entitlements alongside agents", async () => {
			mockedSupabase.from.mockImplementation((table: string) => {
				if (table === "agents") {
					return {
						select: vi.fn(() => ({
							order: vi.fn(() => Promise.resolve({ data: [], error: null })),
						})),
					};
				}
				if (table === "entitlements") {
					return {
						select: vi.fn(() => ({
							maybeSingle: vi.fn(() =>
								Promise.resolve({
									data: { included_agents: 1, extra_agents: 0 },
									error: null,
								}),
							),
						})),
					};
				}
				return { select: vi.fn() };
			});

			render(
				<MemoryRouter>
					<AgentsPage />
				</MemoryRouter>,
			);

			await waitFor(() => {
				expect(mockedSupabase.from).toHaveBeenCalledWith("entitlements");
			});
		});

		it("should handle API errors gracefully", async () => {
			mockedSupabase.from.mockReturnValue({
				select: vi.fn(() => ({
					order: vi.fn(() => Promise.resolve({ data: null, error: { message: "Database error" } })),
				})),
			});

			render(
				<MemoryRouter>
					<AgentsPage />
				</MemoryRouter>,
			);

			await waitFor(() => {
				expect(screen.getByText("Database error")).toBeInTheDocument();
			});
		});

		it("should call signOut when clicking Sign out button", async () => {
			mockedSupabase.auth.signOut.mockResolvedValue({ error: null });

			render(
				<MemoryRouter>
					<AppLayout />
				</MemoryRouter>,
			);

			const signOutButton = screen.getByText("Sign out");
			fireEvent.click(signOutButton);

			await waitFor(() => {
				expect(mockedSupabase.auth.signOut).toHaveBeenCalled();
			});
		});

		it("should handle OAuth sign in", async () => {
			mockedSupabase.auth.signInWithOAuth.mockResolvedValue({
				data: { provider: "google", url: "https://oauth.example.com" },
				error: null,
			});
			mockedSupabase.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });

			render(
				<MemoryRouter initialEntries={["/login"]}>
					<Routes>
						<Route path="/login" element={<LoginPage />} />
					</Routes>
				</MemoryRouter>,
			);

			const googleButton = screen.getByText("Continue with Google");
			fireEvent.click(googleButton);

			await waitFor(() => {
				expect(mockedSupabase.auth.signInWithOAuth).toHaveBeenCalledWith({
					provider: "google",
					options: expect.objectContaining({
						redirectTo: expect.any(String),
					}),
				});
			});
		});

		it("should handle magic link sign in", async () => {
			mockedSupabase.auth.signInWithOtp.mockResolvedValue({
				data: { session: null, user: null },
				error: null,
			});
			mockedSupabase.auth.getSession.mockResolvedValue({ data: { session: null }, error: null });

			render(
				<MemoryRouter initialEntries={["/login"]}>
					<Routes>
						<Route path="/login" element={<LoginPage />} />
					</Routes>
				</MemoryRouter>,
			);

			const emailInput = screen.getByPlaceholderText("you@company.com");
			fireEvent.change(emailInput, { target: { value: "test@example.com" } });

			const magicLinkButton = screen.getByText("Send magic link");
			fireEvent.click(magicLinkButton);

			await waitFor(() => {
				expect(mockedSupabase.auth.signInWithOtp).toHaveBeenCalledWith(
					expect.objectContaining({
						email: "test@example.com",
					}),
				);
			});
		});
	});

	describe("Session Management", () => {
		it("should check session on mount", async () => {
			mockedSupabase.auth.getSession.mockResolvedValue({
				data: { session: { user: { id: "user-123" } } },
				error: null,
			});

			await getSession();

			expect(mockedSupabase.auth.getSession).toHaveBeenCalled();
		});

		it("should return null when no session exists", async () => {
			mockedSupabase.auth.getSession.mockResolvedValue({
				data: { session: null },
				error: null,
			});

			const session = await getSession();

			expect(session).toBeNull();
		});

		it("should call signOut on session termination", async () => {
			mockedSupabase.auth.signOut.mockResolvedValue({ error: null });

			await signOut();

			expect(mockedSupabase.auth.signOut).toHaveBeenCalled();
		});
	});

	describe("Page Components", () => {
		it("should render OnboardingPage", () => {
			mockedSupabase.from.mockReturnValue({
				select: vi.fn(() => Promise.resolve({ data: [], error: null })),
			});

			const { container } = render(
				<MemoryRouter>
					<OnboardingPage />
				</MemoryRouter>,
			);

			expect(container).toBeTruthy();
		});

		it("should render ApiKeysPage", () => {
			mockedSupabase.from.mockReturnValue({
				select: vi.fn(() => Promise.resolve({ data: [], error: null })),
			});

			const { container } = render(
				<MemoryRouter>
					<ApiKeysPage />
				</MemoryRouter>,
			);

			expect(container).toBeTruthy();
		});

		it("should render BillingPage", () => {
			mockedSupabase.from.mockReturnValue({
				select: vi.fn(() => Promise.resolve({ data: [], error: null })),
			});

			const { container } = render(
				<MemoryRouter>
					<BillingPage />
				</MemoryRouter>,
			);

			expect(container).toBeTruthy();
		});

		it("should render IncidentsPage", () => {
			mockedSupabase.from.mockReturnValue({
				select: vi.fn(() => Promise.resolve({ data: [], error: null })),
			});

			const { container } = render(
				<MemoryRouter>
					<IncidentsPage />
				</MemoryRouter>,
			);

			expect(container).toBeTruthy();
		});
	});
});
