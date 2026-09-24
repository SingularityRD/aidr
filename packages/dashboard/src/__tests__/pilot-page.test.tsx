// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));
vi.mock("../ui/session", () => ({ getSession: vi.fn().mockResolvedValue(null) }));

import { supabase } from "../lib/supabase";
import { PilotPage } from "../ui/pages/public/PilotPage";
import { getSession } from "../ui/session";

const invoke = vi.mocked(supabase.functions.invoke);
const session = vi.mocked(getSession);
const TEAM_TENANT = "33333333-3333-4333-8333-333333333333";
const OTHER_TEAM_TENANT = "44444444-4444-4444-8444-444444444444";
const PERSONAL_TENANT = "11111111-1111-4111-8111-111111111111";
const pilotAdmission = {
	mode: "pilot",
	status: "none",
	access_kind: null,
	allowed_agents: 0,
	expires_at: null,
	trial_available: false,
};
const configuredLegal = {
	configured: true,
	terms: { version: "2026-09", sha256: "a".repeat(64), url: "https://example.test/terms" },
	privacy: { version: "2026-09", sha256: "b".repeat(64), url: "https://example.test/privacy" },
};

beforeEach(() => {
	session.mockResolvedValue(null);
	invoke.mockImplementation(
		async (name) =>
			({
				data:
					name === "identity-security"
						? {
								ok: true,
								memberships: [
									{
										tenant_id: TEAM_TENANT,
										team_id: TEAM_TENANT,
										require_mfa: false,
										current_assurance: "aal1",
										next_assurance: null,
										access_allowed: true,
									},
								],
							}
						: { ok: true, status: "none", admission: pilotAdmission },
				error: null,
			}) as never,
	);
});

afterEach(() => {
	cleanup();
	vi.clearAllMocks();
	vi.unstubAllEnvs();
});

describe("pilot application access", () => {
	it("lets signed-out prospects contact sales without first completing sign-in", async () => {
		vi.stubEnv("VITE_SALES_URL", "");
		vi.stubEnv("VITE_SALES_EMAIL", "sales@example.test");
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);

		expect(await screen.findByRole("link", { name: "Sign in to check access" })).toHaveAttribute(
			"href",
			"/login?returnTo=/pilot",
		);
		expect(screen.getByRole("link", { name: "Contact sales" })).toHaveAttribute(
			"href",
			"mailto:sales@example.test",
		);
		expect(screen.getByText(/check your workspace access/)).toBeInTheDocument();
	});

	it("makes a missing sales route visible instead of rendering a dead link", async () => {
		vi.stubEnv("VITE_SALES_URL", "");
		vi.stubEnv("VITE_SALES_EMAIL", "");
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);

		expect(await screen.findByRole("status")).toHaveTextContent(
			"sales contact route is not configured",
		);
		expect(screen.queryByRole("link", { name: "Contact sales" })).not.toBeInTheDocument();
	});

	it("does not submit until safe HTTPS privacy and terms documents are configured", async () => {
		vi.stubEnv("VITE_PRIVACY_URL", "");
		vi.stubEnv("VITE_TERMS_URL", "javascript:alert(1)");
		session.mockResolvedValue({ user: { email: "pilot@example.test" } } as never);
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);

		fireEvent.change(await screen.findByLabelText("Use case"), {
			target: { value: "Protect our coding agents" },
		});
		expect(await screen.findByRole("alert")).toHaveTextContent("applications are disabled");
		expect(screen.getByRole("button", { name: "Submit application" })).toBeDisabled();
		expect(invoke).not.toHaveBeenCalledWith("pilot-apply", expect.anything());
	});

	it("submits only after safe legal documents are configured and reviewed", async () => {
		vi.stubEnv("VITE_PRIVACY_URL", "https://example.test/privacy");
		vi.stubEnv("VITE_TERMS_URL", "https://example.test/pilot-terms");
		session.mockResolvedValue({ user: { email: "pilot@example.test" } } as never);
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);

		fireEvent.change(await screen.findByLabelText("Use case"), {
			target: { value: "Protect our coding agents" },
		});
		const submit = screen.getByRole("button", { name: "Submit application" });
		expect(submit).toBeDisabled();
		fireEvent.click(screen.getByRole("checkbox"));
		expect(submit).toBeEnabled();
		fireEvent.click(submit);

		await waitFor(() => {
			expect(invoke).toHaveBeenCalledWith("pilot-apply", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": TEAM_TENANT },
				body: { email: "pilot@example.test", org: "", useCase: "Protect our coding agents" },
			});
		});
	});

	it("does not offer pilot application before workspace mode is resolved", async () => {
		vi.stubEnv("VITE_PRIVACY_URL", "https://example.test/privacy");
		vi.stubEnv("VITE_TERMS_URL", "https://example.test/pilot-terms");
		session.mockResolvedValue({ user: { email: "pilot@example.test" } } as never);
		let finishStatus!: (value: unknown) => void;
		invoke.mockImplementation((name) => {
			if (name === "identity-security")
				return Promise.resolve({
					data: { ok: true, memberships: [{ tenant_id: TEAM_TENANT, team_id: TEAM_TENANT }] },
					error: null,
				}) as never;
			if (name === "pilot-status")
				return new Promise((resolve) => {
					finishStatus = resolve;
				}) as never;
			return Promise.resolve({ data: { ok: true, status: "pending" }, error: null }) as never;
		});
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);
		await waitFor(() => expect(invoke).toHaveBeenCalledWith("pilot-status", expect.anything()));
		expect(screen.queryByRole("button", { name: "Submit application" })).not.toBeInTheDocument();
		await act(async () =>
			finishStatus({
				data: { ok: true, status: "pending", admission: pilotAdmission },
				error: null,
			}),
		);
		expect(await screen.findByRole("button", { name: "Submit application" })).toBeDisabled();
		expect(screen.queryByRole("button", { name: "Start onboarding" })).not.toBeInTheDocument();
	});

	it("uses the active default tenant for pilot status and submissions", async () => {
		vi.stubEnv("VITE_PRIVACY_URL", "https://example.test/privacy");
		vi.stubEnv("VITE_TERMS_URL", "https://example.test/pilot-terms");
		session.mockResolvedValue({ user: { email: "pilot@example.test" } } as never);
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);

		await waitFor(() => {
			expect(invoke).toHaveBeenCalledWith("pilot-status", {
				method: "GET",
				headers: { "X-AIDR-Tenant-ID": TEAM_TENANT },
			});
		});
	});

	it("lets a user select a workspace and submit an independent application there", async () => {
		vi.stubEnv("VITE_PRIVACY_URL", "https://example.test/privacy");
		vi.stubEnv("VITE_TERMS_URL", "https://example.test/pilot-terms");
		session.mockResolvedValue({ user: { email: "pilot@example.test" } } as never);
		invoke.mockImplementation(async (name, options) => {
			if (name === "identity-security") {
				return {
					data: {
						ok: true,
						memberships: [
							{
								tenant_id: TEAM_TENANT,
								team_id: TEAM_TENANT,
								require_mfa: false,
								current_assurance: "aal1",
								next_assurance: null,
								access_allowed: true,
							},
							{
								tenant_id: PERSONAL_TENANT,
								team_id: null,
								require_mfa: false,
								current_assurance: "aal1",
								next_assurance: null,
								access_allowed: true,
							},
						],
					},
					error: null,
				} as never;
			}
			if (name === "pilot-status" && options?.headers?.["X-AIDR-Tenant-ID"] === TEAM_TENANT) {
				return {
					data: { ok: true, status: "none", tenant_id: TEAM_TENANT, admission: pilotAdmission },
					error: null,
				} as never;
			}
			if (name === "pilot-status" && options?.headers?.["X-AIDR-Tenant-ID"] === PERSONAL_TENANT) {
				return {
					data: {
						ok: true,
						status: "pending",
						tenant_id: PERSONAL_TENANT,
						admission: pilotAdmission,
					},
					error: null,
				} as never;
			}
			return {
				data: { ok: true, status: "none", admission: pilotAdmission },
				error: null,
			} as never;
		});
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);

		fireEvent.change(await screen.findByLabelText("Workspace"), {
			target: { value: PERSONAL_TENANT },
		});
		await waitFor(() =>
			expect(invoke).toHaveBeenCalledWith("pilot-status", {
				method: "GET",
				headers: { "X-AIDR-Tenant-ID": PERSONAL_TENANT },
			}),
		);
		fireEvent.change(await screen.findByLabelText("Use case"), {
			target: { value: "Protect our coding agents" },
		});
		fireEvent.click(screen.getByRole("checkbox"));
		fireEvent.click(screen.getByRole("button", { name: "Submit application" }));

		await waitFor(() => {
			expect(invoke).toHaveBeenCalledWith("pilot-apply", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": PERSONAL_TENANT },
				body: { email: "pilot@example.test", org: "", useCase: "Protect our coding agents" },
			});
		});
	});

	it("opens onboarding for the selected approved team", async () => {
		session.mockResolvedValue({ user: { email: "pilot@example.test" } } as never);
		invoke.mockImplementation(async (name, options) => {
			if (name === "identity-security")
				return {
					data: {
						ok: true,
						memberships: [
							{ tenant_id: TEAM_TENANT, team_id: TEAM_TENANT },
							{ tenant_id: OTHER_TEAM_TENANT, team_id: OTHER_TEAM_TENANT },
						],
					},
					error: null,
				} as never;
			return {
				data: {
					ok: true,
					status:
						options?.headers?.["X-AIDR-Tenant-ID"] === OTHER_TEAM_TENANT ? "approved" : "none",
					admission:
						options?.headers?.["X-AIDR-Tenant-ID"] === OTHER_TEAM_TENANT
							? { ...pilotAdmission, status: "active", access_kind: "pilot", allowed_agents: 1 }
							: pilotAdmission,
				},
				error: null,
			} as never;
		});
		function Destination() {
			return <div>Selected onboarding {useLocation().search}</div>;
		}
		render(
			<MemoryRouter initialEntries={["/pilot"]}>
				<Routes>
					<Route path="/pilot" element={<PilotPage />} />
					<Route path="/onboarding" element={<Destination />} />
				</Routes>
			</MemoryRouter>,
		);
		fireEvent.change(await screen.findByLabelText("Workspace"), {
			target: { value: OTHER_TEAM_TENANT },
		});
		fireEvent.click(await screen.findByRole("button", { name: "Start onboarding" }));
		expect(
			await screen.findByText(`Selected onboarding ?tenant=${OTHER_TEAM_TENANT}`),
		).toBeInTheDocument();
	});

	it("routes a cloud customer to team trial setup without a pilot application", async () => {
		session.mockResolvedValue({ user: { email: "customer@example.test" } } as never);
		invoke.mockImplementation(
			async (name) =>
				({
					error: null,
					data:
						name === "identity-security"
							? { ok: true, memberships: [{ tenant_id: TEAM_TENANT, team_id: TEAM_TENANT }] }
							: {
									ok: true,
									status: "none",
									admission: { ...pilotAdmission, mode: "cloud", trial_available: true },
									legal: configuredLegal,
								},
				}) as never,
		);
		function Destination() {
			return <div>Selected onboarding {useLocation().search}</div>;
		}
		render(
			<MemoryRouter initialEntries={["/pilot"]}>
				<Routes>
					<Route path="/pilot" element={<PilotPage />} />
					<Route path="/onboarding" element={<Destination />} />
				</Routes>
			</MemoryRouter>,
		);
		expect(await screen.findByText("none")).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Submit application" })).not.toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Set up 14-day trial" }));
		expect(
			await screen.findByText(`Selected onboarding ?tenant=${TEAM_TENANT}`),
		).toBeInTheDocument();
		expect(invoke).not.toHaveBeenCalledWith("pilot-apply", expect.anything());
	});

	it("explains missing legal documents when the service disables trial availability", async () => {
		session.mockResolvedValue({ user: { email: "customer@example.test" } } as never);
		invoke.mockImplementation(
			async (name) =>
				({
					error: null,
					data:
						name === "identity-security"
							? { ok: true, memberships: [{ tenant_id: TEAM_TENANT, team_id: TEAM_TENANT }] }
							: {
									ok: true,
									status: "none",
									admission: { ...pilotAdmission, mode: "cloud", trial_available: false },
									legal: { configured: false, terms: null, privacy: null },
								},
				}) as never,
		);
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);
		expect(await screen.findByRole("status")).toHaveTextContent(
			"Trial setup awaits published Terms and Privacy",
		);
		expect(screen.queryByRole("button", { name: "Set up 14-day trial" })).not.toBeInTheDocument();
	});

	it("does not offer onboarding solely from an old approved pilot response", async () => {
		session.mockResolvedValue({ user: { email: "customer@example.test" } } as never);
		invoke.mockImplementation(
			async (name) =>
				({
					error: null,
					data:
						name === "identity-security"
							? { ok: true, memberships: [{ tenant_id: TEAM_TENANT, team_id: TEAM_TENANT }] }
							: { ok: true, status: "approved" },
				}) as never,
		);
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Workspace access response is invalid",
		);
		expect(screen.queryByRole("button", { name: "Start onboarding" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Submit application" })).not.toBeInTheDocument();
	});

	it("keeps applying disabled when identity bootstrap has no active tenant", async () => {
		vi.stubEnv("VITE_PRIVACY_URL", "https://example.test/privacy");
		vi.stubEnv("VITE_TERMS_URL", "https://example.test/pilot-terms");
		session.mockResolvedValue({ user: { email: "pilot@example.test" } } as never);
		invoke.mockImplementation(
			async (name) =>
				({
					data:
						name === "identity-security"
							? { ok: true, memberships: [] }
							: { ok: true, status: "none" },
					error: null,
				}) as never,
		);
		render(
			<MemoryRouter>
				<PilotPage />
			</MemoryRouter>,
		);

		expect(await screen.findByRole("alert")).toHaveTextContent("No active workspace");
		expect(screen.queryByRole("button", { name: "Submit application" })).not.toBeInTheDocument();
	});
});
