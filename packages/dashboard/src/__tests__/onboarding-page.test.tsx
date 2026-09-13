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
	return render(<MemoryRouter><OnboardingPage /></MemoryRouter>);
}

describe("operator onboarding", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		useTeam.mockReturnValue(teamState());
		invoke.mockImplementation(async (name: string) =>
			name === "pilot-status"
				? { data: { ok: true, status: "approved" }, error: null }
				: name === "device-start"
					? deviceResponse()
					: { data: { ok: true, status: "pending" }, error: null },
		);
	});
	afterEach(cleanup);

	it("shows a loading state and blocks enrollment until team permissions resolve", () => {
		useTeam.mockReturnValue({ ...teamState(), roleResolved: false });
		renderPage();
		expect(screen.getByRole("status")).toHaveTextContent("Checking team access");
		expect(invoke).not.toHaveBeenCalled();
	});

	it("explains viewer permission and disables code generation", async () => {
		useTeam.mockReturnValue(teamState(firstTeam, "viewer"));
		renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled());
		expect(screen.getByRole("alert")).toHaveTextContent("cannot enroll agents");
	});

	it("retries a failed pilot lookup before enabling enrollment", async () => {
		let lookups = 0;
		invoke.mockImplementation(async (name: string) => {
			if (name === "pilot-status") return ++lookups === 1
				? { data: null, error: { message: "offline" } }
				: { data: { ok: true, status: "approved" }, error: null };
			return deviceResponse();
		});
		renderPage();
		await screen.findByRole("button", { name: "Retry status" });
		expect(screen.getByRole("button", { name: "Generate code" })).toBeDisabled();
		fireEvent.click(screen.getByRole("button", { name: "Retry status" }));
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		expect(invoke).toHaveBeenCalledWith("pilot-status", {
			method: "GET", headers: { "X-AIDR-Tenant-ID": firstTeam.id },
		});
	});

	it("preselects the current team and code on the browser verification link", async () => {
		renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		const href = screen.getByRole("link", { name: "Authorize in browser" }).getAttribute("href");
		const url = new URL(href ?? "", location.origin);
		expect(url.pathname).toBe("/verify");
		expect(url.searchParams.get("code")).toBe("ABCD2345");
		expect(url.searchParams.get("team")).toBe(firstTeam.id);
		expect(screen.getByRole("link", { name: "I already opened it" })).toHaveAttribute(
			"href", `/verify?code=ABCD2345&team=${firstTeam.id}`,
		);
	});

	it("copies the labeled runtime prompt and resets copy feedback when the runtime changes", async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
		renderPage();
		const prompt = screen.getByRole("textbox", { name: "Prompt to give your agent" });
		fireEvent.click(screen.getByRole("button", { name: "Copy prompt" }));
		await waitFor(() => expect(writeText).toHaveBeenCalledWith((prompt as HTMLTextAreaElement).value));
		expect(screen.getByRole("button", { name: "Prompt copied" })).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Cursor" }));
		expect(screen.getByRole("button", { name: "Copy prompt" })).toBeInTheDocument();
	});

	it("clears an old code before a replacement request completes or fails", async () => {
		let starts = 0;
		let resolveReplacement: (value: unknown) => void = () => undefined;
		invoke.mockImplementation((name: string) => {
			if (name === "pilot-status") return Promise.resolve({ data: { ok: true, status: "approved" }, error: null });
			if (name === "device-start") return ++starts === 1
				? Promise.resolve(deviceResponse())
				: new Promise((resolve) => { resolveReplacement = resolve; });
			return Promise.resolve({ data: { ok: true, status: "pending" }, error: null });
		});
		renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Generating code…" })).toBeDisabled();
		resolveReplacement({ data: { ok: false }, error: null });
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("did not confirm a code"));
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
	});

	it("does not retain a generated code after switching teams", async () => {
		const view = renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		useTeam.mockReturnValue(teamState(secondTeam));
		view.rerender(<MemoryRouter><OnboardingPage /></MemoryRouter>);
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Open verify page" })).toHaveAttribute("href", "/verify?team=team-two");
	});

	it.each([401, 409])("stops polling and removes the code after HTTP %i", async (status) => {
		invoke.mockImplementation(async (name: string) => name === "pilot-status"
			? { data: { ok: true, status: "approved" }, error: null }
			: name === "device-start"
				? deviceResponse()
				: { data: null, error: { message: "rejected", context: { status } } });
		renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("rejected or already used"), { timeout: 3000 });
		expect(screen.queryByText("ABCD2345")).not.toBeInTheDocument();
		expect(invoke.mock.calls.filter(([name]) => name === "device-poll")).toHaveLength(1);
	});

	it("removes an expired code instead of leaving a usable authorization link", async () => {
		invoke.mockImplementation(async (name: string) => {
			if (name === "pilot-status") return { data: { ok: true, status: "approved" }, error: null };
			if (name === "device-start") {
				const response = deviceResponse();
				response.data.expires_at = new Date(Date.now() + 750).toISOString();
				return response;
			}
			return { data: { ok: true, status: "pending" }, error: null };
		});
		renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await screen.findByText("ABCD2345");
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("code expired"), { timeout: 3000 });
		expect(screen.queryByRole("link", { name: "Authorize in browser" })).not.toBeInTheDocument();
	});

	it("does not claim authorization for an approved response without a usable token", async () => {
		invoke.mockImplementation(async (name: string) => name === "pilot-status"
			? { data: { ok: true, status: "approved" }, error: null }
			: name === "device-start"
				? deviceResponse()
				: { data: { ok: true, status: "approved" }, error: null });
		renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("no usable enrollment token"), { timeout: 3000 });
		expect(screen.queryByText("Authorized.")).not.toBeInTheDocument();
	});

	it("treats an unrecognized successful poll response as an error", async () => {
		invoke.mockImplementation(async (name: string) => name === "pilot-status"
			? { data: { ok: true, status: "approved" }, error: null }
			: name === "device-start"
				? deviceResponse()
				: { data: { ok: true }, error: null });
		renderPage();
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate code" })).toBeEnabled());
		fireEvent.click(screen.getByRole("button", { name: "Generate code" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("unknown state"), { timeout: 3000 });
		expect(screen.queryByRole("link", { name: "Authorize in browser" })).not.toBeInTheDocument();
	});
});
