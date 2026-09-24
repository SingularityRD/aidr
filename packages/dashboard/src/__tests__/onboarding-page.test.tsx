// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { invoke, useTeam } = vi.hoisted(() => ({ invoke: vi.fn(), useTeam: vi.fn() }));

vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke } } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam }));

import { OnboardingPage } from "../ui/pages/OnboardingPage";

const firstTeam = { id: "team-one", name: "First team" };
const secondTeam = { id: "team-two", name: "Second team" };
const userId = "33333333-3333-4333-8333-333333333333";
const activeAdmission = {
	mode: "pilot",
	status: "active",
	access_kind: "pilot",
	allowed_agents: 1,
	expires_at: null,
	trial_available: false,
};
const configuredLegal = {
	configured: true,
	terms: { version: "2026-09", sha256: "a".repeat(64), url: "https://example.test/terms" },
	privacy: { version: "2026-09", sha256: "b".repeat(64), url: "https://example.test/privacy" },
};

function teamState(currentTeam = firstTeam, currentRole = "owner") {
	return { currentTeam, currentRole, isLoading: false, roleResolved: true, error: null };
}

function deviceResponse(code = "ABCD2345") {
	return {
		data: {
			ok: true,
			verification_url: `/verify?code=${code}`,
			user_code: code,
			device_code: `device-${code}`,
			expires_at: new Date(Date.now() + 60_000).toISOString(),
			interval_seconds: 2,
		},
		error: null,
	};
}

function renderPage() {
	return render(
		<MemoryRouter>
			<OnboardingPage />
		</MemoryRouter>,
	);
}

describe("operator onboarding", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		window.localStorage.clear();
		useTeam.mockReturnValue(teamState());
		invoke.mockImplementation(async (name: string) =>
			name === "pilot-status"
				? { data: { ok: true, status: "approved", admission: activeAdmission }, error: null }
				: name === "device-start"
					? deviceResponse()
					: { data: { ok: true, status: "pending" }, error: null },
		);
	});
	afterEach(() => {
		cleanup();
		delete window.__AIDR_CONFIG__;
	});

	it("shows a loading state and blocks enrollment until team permissions resolve", () => {
		useTeam.mockReturnValue({ ...teamState(), roleResolved: false });
		renderPage();
		expect(screen.getByRole("status")).toHaveTextContent("Checking team access");
		expect(invoke).not.toHaveBeenCalled();
	});

	it("offers explicit team creation only on cloud when no team workspace exists", async () => {
		const createTeam = vi.fn().mockResolvedValue(undefined);
		window.__AIDR_CONFIG__ = { signupMode: "cloud" };
		useTeam.mockReturnValue({
			currentTeam: null,
			currentUserId: userId,
			currentRole: null,
			isLoading: false,
			roleResolved: true,
			error: null,
			createTeam,
		});
		renderPage();
		fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
			target: { value: " Acme Security " },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create team" }));
		await waitFor(() => expect(createTeam).toHaveBeenCalledWith("Acme Security", expect.any(String)));
		expect(createTeam.mock.calls[0]?.[1]).toMatch(
			/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
		);
		expect(invoke).not.toHaveBeenCalled();
	});

	it("keeps team creation closed outside explicit cloud signup mode", () => {
		window.__AIDR_CONFIG__ = { signupMode: "closed" };
		useTeam.mockReturnValue({
			currentTeam: null,
			currentUserId: userId,
			currentRole: null,
			isLoading: false,
			roleResolved: true,
			error: null,
			createTeam: vi.fn(),
		});
		renderPage();
		expect(screen.getByRole("alert")).toHaveTextContent("Select a team");
		expect(screen.queryByRole("button", { name: "Create team" })).not.toBeInTheDocument();
	});

	it("retries an ambiguous creation with the same durable request ID", async () => {
		const createTeam = vi
			.fn()
			.mockRejectedValueOnce(new Error("response was lost"))
			.mockResolvedValueOnce(undefined);
		window.__AIDR_CONFIG__ = { signupMode: "cloud" };
		useTeam.mockReturnValue({
			currentTeam: null,
			currentUserId: userId,
			currentRole: null,
			isLoading: false,
			roleResolved: true,
			error: null,
			createTeam,
		});
		renderPage();
		fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
			target: { value: "Acme Security" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create team" }));
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				"Retry this saved request",
			),
		);
		expect(screen.getByRole("textbox", { name: "Team name" })).toHaveAttribute("readonly");
		const firstRequest = createTeam.mock.calls[0];
		expect(screen.getByRole("button", { name: "Retry workspace creation" })).toBeEnabled();
		fireEvent.click(screen.getByRole("button", { name: "Retry workspace creation" }));
		await waitFor(() => expect(createTeam).toHaveBeenCalledTimes(2));
		expect(createTeam.mock.calls[1]).toEqual(firstRequest);
		expect(window.localStorage.getItem(`aidr:onboarding-team-create:v1:${userId}`)).toBeNull();
	});

	it("restores an ambiguous request after reload and keeps it scoped to its user", async () => {
		const createTeam = vi.fn().mockRejectedValue(new Error("response was lost"));
		window.__AIDR_CONFIG__ = { signupMode: "cloud" };
		useTeam.mockReturnValue({
			currentTeam: null,
			currentUserId: userId,
			currentRole: null,
			isLoading: false,
			roleResolved: true,
			error: null,
			createTeam,
		});
		const firstPage = renderPage();
		fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
			target: { value: "Acme Security" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create team" }));
		await waitFor(() => expect(createTeam).toHaveBeenCalledOnce());
		const firstRequest = createTeam.mock.calls[0];
		firstPage.unmount();
		useTeam.mockReturnValue({
			currentTeam: null,
			currentUserId: "44444444-4444-4444-8444-444444444444",
			currentRole: null,
			isLoading: false,
			roleResolved: true,
			error: null,
			createTeam,
		});
		const otherUsersPage = renderPage();
		expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue("");
		expect(screen.getByRole("button", { name: "Create team" })).toBeDisabled();
		otherUsersPage.unmount();
		useTeam.mockReturnValue({
			currentTeam: null,
			currentUserId: userId,
			currentRole: null,
			isLoading: false,
			roleResolved: true,
			error: null,
			createTeam,
		});
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue("Acme Security"),
		);
		expect(screen.getByRole("button", { name: "Retry workspace creation" })).toBeEnabled();
		fireEvent.click(screen.getByRole("button", { name: "Retry workspace creation" }));
		await waitFor(() => expect(createTeam).toHaveBeenCalledTimes(2));
		expect(createTeam.mock.calls[1]).toEqual(firstRequest);
	});

	it("explains viewer permission and disables code generation", async () => {
		useTeam.mockReturnValue(teamState(firstTeam, "viewer"));
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled(),
		);
		expect(screen.getByRole("alert")).toHaveTextContent("cannot enroll agents");
	});

	it("retries a failed pilot lookup before enabling enrollment", async () => {
		let lookups = 0;
		invoke.mockImplementation(async (name: string) => {
			if (name === "pilot-status")
				return ++lookups === 1
					? { data: null, error: { message: "offline" } }
					: { data: { ok: true, status: "approved", admission: activeAdmission }, error: null };
			return deviceResponse();
		});
		renderPage();
		await screen.findByRole("button", { name: "Retry status" });
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
		fireEvent.click(screen.getByRole("button", { name: "Retry status" }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		expect(invoke).toHaveBeenCalledWith("pilot-status", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": firstTeam.id },
		});
	});

	it("starts a cloud trial only through the tenant-scoped authenticated edge action", async () => {
		const available = {
			...activeAdmission,
			mode: "cloud",
			status: "none",
			access_kind: null,
			allowed_agents: 0,
			trial_available: true,
		};
		const active = {
			...available,
			status: "active",
			access_kind: "trial",
			allowed_agents: 1,
			trial_available: false,
			expires_at: new Date(Date.now() + 14 * 86400_000).toISOString(),
		};
		invoke.mockImplementation(async (name: string, options?: { method?: string }) =>
			name === "pilot-status"
				? {
						data: {
							ok: true,
							status: "none",
							admission: options?.method === "POST" ? active : available,
							legal: configuredLegal,
						},
						error: null,
					}
				: deviceResponse(),
		);
		renderPage();
		const start = await screen.findByRole("button", { name: "Start 14-day trial · 1 agent" });
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
		expect(start).toBeDisabled();
		expect(screen.getByRole("link", { name: "Terms (2026-09)" })).toHaveAttribute(
			"href",
			"https://example.test/terms",
		);
		fireEvent.click(screen.getByRole("checkbox"));
		fireEvent.click(start);
		await waitFor(() =>
			expect(invoke).toHaveBeenCalledWith("pilot-status", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": firstTeam.id },
				body: {
					action: "start_trial",
					accepted: true,
					terms: { version: "2026-09", sha256: "a".repeat(64) },
					privacy: { version: "2026-09", sha256: "b".repeat(64) },
				},
			}),
		);
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		expect(screen.getByRole("status")).toHaveTextContent("Trial active · 1 agent");
	});

	it("does not enable enrollment when trial activation is rejected", async () => {
		const available = {
			...activeAdmission,
			mode: "cloud",
			status: "none",
			access_kind: null,
			allowed_agents: 0,
			trial_available: true,
		};
		invoke.mockImplementation(async (name: string, options?: { method?: string }) =>
			name === "pilot-status" && options?.method === "POST"
				? { data: null, error: { message: "trial_not_available" } }
				: {
						data: { ok: true, status: "none", admission: available, legal: configuredLegal },
						error: null,
					},
		);
		renderPage();
		fireEvent.click(await screen.findByRole("checkbox"));
		fireEvent.click(await screen.findByRole("button", { name: "Start 14-day trial · 1 agent" }));
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("Trial activation was not confirmed"),
		);
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
	});

	it("reloads legal documents and clears consent after a rejected trial", async () => {
		const available = { ...activeAdmission, mode: "cloud", status: "none", access_kind: null, allowed_agents: 0, trial_available: true };
		let gets = 0;
		invoke.mockImplementation(async (name: string, options?: { method?: string }) => {
			if (name !== "pilot-status") return deviceResponse();
			if (options?.method === "POST") return { data: null, error: { message: "legal_documents_changed", context: { status: 409 } } };
			gets++;
			const legal = gets === 1 ? configuredLegal : {
				...configuredLegal,
				terms: { ...configuredLegal.terms, version: "2026-10", sha256: "c".repeat(64) },
			};
			return { data: { ok: true, status: "none", admission: available, legal }, error: null };
		});
		renderPage();
		fireEvent.click(await screen.findByRole("checkbox"));
		fireEvent.click(screen.getByRole("button", { name: "Start 14-day trial · 1 agent" }));
		expect(await screen.findByRole("link", { name: "Terms (2026-10)" })).toBeInTheDocument();
		expect(screen.getByRole("checkbox")).not.toBeChecked();
		expect(screen.getByRole("button", { name: "Start 14-day trial · 1 agent" })).toBeDisabled();
		expect(gets).toBe(2);
	});

	it("does not offer a trial before published legal documents are configured", async () => {
		invoke.mockResolvedValue({
			data: {
				ok: true,
				status: "none",
				admission: {
					...activeAdmission,
					mode: "cloud",
					status: "none",
					access_kind: null,
					allowed_agents: 0,
					trial_available: false,
				},
				legal: { configured: false, terms: null, privacy: null },
			},
			error: null,
		});
		renderPage();
		expect(
			await screen.findByText(/Trial setup awaits published Terms and Privacy/),
		).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: /Start 14-day trial/ })).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
	});

	it("rejects an unsafe legal link even if the service marks documents configured", async () => {
		invoke.mockResolvedValue({
			data: {
				ok: true,
				status: "none",
				admission: {
					...activeAdmission,
					mode: "cloud",
					status: "none",
					access_kind: null,
					allowed_agents: 0,
					trial_available: true,
				},
				legal: {
					...configuredLegal,
					terms: { ...configuredLegal.terms, url: "javascript:alert(1)" },
				},
			},
			error: null,
		});
		renderPage();
		expect(await screen.findByRole("alert")).toHaveTextContent("Terms and Privacy are published");
		expect(screen.queryByRole("link", { name: /Terms/ })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: /Start 14-day trial/ })).not.toBeInTheDocument();
	});

	it("does not treat legacy pilot approval without admission as enrollment permission", async () => {
		invoke.mockResolvedValue({ data: { ok: true, status: "approved" }, error: null });
		renderPage();
		await screen.findByRole("button", { name: "Retry status" });
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
		expect(screen.queryByRole("button", { name: /Start 14-day trial/ })).not.toBeInTheDocument();
	});

	it("rejects an inconsistent active admission with zero agent capacity", async () => {
		invoke.mockResolvedValue({
			data: { ok: true, status: "approved", admission: { ...activeAdmission, allowed_agents: 0 } },
			error: null,
		});
		renderPage();
		await screen.findByRole("button", { name: "Retry status" });
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
	});

	it("does not offer trial activation to a non-owner", async () => {
		useTeam.mockReturnValue(teamState(firstTeam, "member"));
		invoke.mockResolvedValue({
			data: {
				ok: true,
				status: "none",
				admission: {
					...activeAdmission,
					mode: "cloud",
					status: "none",
					access_kind: null,
					allowed_agents: 0,
					trial_available: true,
				},
			},
			error: null,
		});
		renderPage();
		await waitFor(() => expect(screen.getByText("none")).toBeInTheDocument());
		expect(screen.queryByRole("button", { name: /Start 14-day trial/ })).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
	});

	it("preselects the current team and code on the browser verification link", async () => {
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		const href = screen.getByRole("link", { name: "Authorize in browser" }).getAttribute("href");
		const url = new URL(href ?? "", location.origin);
		expect(url.pathname).toBe("/verify");
		expect(url.searchParams.get("code")).toBe("ABCD2345");
		expect(url.searchParams.get("team")).toBe(firstTeam.id);
		expect(screen.getByRole("link", { name: "I already opened it" })).toHaveAttribute(
			"href",
			`/verify?code=ABCD2345&team=${firstTeam.id}`,
		);
	});

	it("copies the labeled runtime prompt and resets copy feedback when the runtime changes", async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
		renderPage();
		const prompt = screen.getByRole("textbox", { name: "Prompt to give your agent" });
		fireEvent.click(screen.getByRole("button", { name: "Copy prompt" }));
		await waitFor(() =>
			expect(writeText).toHaveBeenCalledWith((prompt as HTMLTextAreaElement).value),
		);
		expect(screen.getByRole("button", { name: "Prompt copied" })).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Cursor" }));
		expect(screen.getByRole("button", { name: "Copy prompt" })).toBeInTheDocument();
	});

	it("uses the approved private-registry OpenCode install path without inventing a download", () => {
		renderPage();
		fireEvent.click(screen.getByRole("button", { name: "OpenCode" }));
		const prompt = (
			screen.getByRole("textbox", { name: "Prompt to give your agent" }) as HTMLTextAreaElement
		).value;
		expect(prompt).toContain("approved exact version");
		expect(prompt).toContain("independently verified publisher-signed release record");
		expect(prompt).toContain("private @singularityrd registry access");
		expect(prompt).toContain("~/.config/opencode/package.json");
		expect(prompt).toContain("~/.config/opencode/opencode.json");
		expect(prompt).not.toContain("Link the plugin directory");
	});

	it("clears an old code before a replacement request completes or fails", async () => {
		let starts = 0;
		let resolveReplacement: (value: unknown) => void = () => undefined;
		invoke.mockImplementation((name: string) => {
			if (name === "pilot-status")
				return Promise.resolve({
					data: { ok: true, status: "approved", admission: activeAdmission },
					error: null,
				});
			if (name === "device-start")
				return ++starts === 1
					? Promise.resolve(deviceResponse())
					: new Promise((resolve) => {
							resolveReplacement = resolve;
						});
			return Promise.resolve({ data: { ok: true, status: "pending" }, error: null });
		});
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Generating code…" })).toBeDisabled();
		resolveReplacement({ data: { ok: false }, error: null });
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent("did not confirm a code"),
		);
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
	});

	it("does not retain a generated code after switching teams", async () => {
		const view = renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		useTeam.mockReturnValue(teamState(secondTeam));
		view.rerender(
			<MemoryRouter>
				<OnboardingPage />
			</MemoryRouter>,
		);
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Open verify page" })).toHaveAttribute(
			"href",
			"/verify?team=team-two",
		);
	});

	it.each([401, 409])("stops polling and removes the code after HTTP %i", async (status) => {
		invoke.mockImplementation(async (name: string) =>
			name === "pilot-status"
				? { data: { ok: true, status: "approved", admission: activeAdmission }, error: null }
				: name === "device-start"
					? deviceResponse()
					: { data: null, error: { message: "rejected", context: { status } } },
		);
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await waitFor(
			() => expect(screen.getByRole("alert")).toHaveTextContent("rejected or already used"),
			{ timeout: 3000 },
		);
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
		expect(invoke.mock.calls.filter(([name]) => name === "device-poll")).toHaveLength(1);
	});

	it("removes an expired code instead of leaving a usable authorization link", async () => {
		invoke.mockImplementation(async (name: string) => {
			if (name === "pilot-status")
				return { data: { ok: true, status: "approved", admission: activeAdmission }, error: null };
			if (name === "device-start") {
				const response = deviceResponse();
				response.data.expires_at = new Date(Date.now() + 750).toISOString();
				return response;
			}
			return { data: { ok: true, status: "pending" }, error: null };
		});
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("code expired"), {
			timeout: 3000,
		});
		expect(screen.queryByRole("link", { name: "Authorize in browser" })).not.toBeInTheDocument();
	});

	it("does not claim authorization for an approved response without a usable token", async () => {
		invoke.mockImplementation(async (name: string) =>
			name === "pilot-status"
				? { data: { ok: true, status: "approved", admission: activeAdmission }, error: null }
				: name === "device-start"
					? deviceResponse()
					: { data: { ok: true, status: "approved" }, error: null },
		);
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await waitFor(
			() => expect(screen.getByRole("alert")).toHaveTextContent("no usable enrollment token"),
			{ timeout: 3000 },
		);
		expect(screen.queryByText("Authorized.")).not.toBeInTheDocument();
	});

	it("treats an unrecognized successful poll response as an error", async () => {
		invoke.mockImplementation(async (name: string) =>
			name === "pilot-status"
				? { data: { ok: true, status: "approved", admission: activeAdmission }, error: null }
				: name === "device-start"
					? deviceResponse()
					: { data: { ok: true }, error: null },
		);
		renderPage();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled(),
		);
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("unknown state"), {
			timeout: 3000,
		});
		expect(screen.queryByRole("link", { name: "Authorize in browser" })).not.toBeInTheDocument();
	});
});
