// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSession, signUp, signOut } = vi.hoisted(() => ({
	getSession: vi.fn(),
	signUp: vi.fn(),
	signOut: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: { auth: { getSession, signUp, signOut } },
}));

import { LoginPage } from "../ui/pages/LoginPage";

function renderSignup() {
	render(
		<MemoryRouter initialEntries={["/login"]}>
			<LoginPage />
		</MemoryRouter>,
	);
	fireEvent.click(screen.getByRole("button", { name: "New to AIDR? Create an account" }));
	fireEvent.change(screen.getByLabelText("Email address"), {
		target: { value: "new-owner@example.test" },
	});
	fireEvent.change(screen.getByLabelText("Team or organization name"), {
		target: { value: " Acme Security " },
	});
	fireEvent.change(screen.getByLabelText("Password"), {
		target: { value: "example-password-123" },
	});
	fireEvent.change(screen.getByLabelText("Confirm password"), {
		target: { value: "example-password-123" },
	});
}

describe("cloud account registration", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		window.localStorage.clear();
		window.__AIDR_CONFIG__ = { authMethods: ["password", "magic-link"], signupMode: "cloud" };
		getSession.mockResolvedValue({ data: { session: null }, error: null });
		signOut.mockResolvedValue({ error: null });
	});
	afterEach(() => {
		cleanup();
		delete window.__AIDR_CONFIG__;
	});

	it("submits email confirmation and never treats an unconfirmed account as signed in", async () => {
		signUp.mockResolvedValue({
			data: { user: { id: "new-user" }, session: null },
			error: null,
		});
		renderSignup();
		fireEvent.click(screen.getByRole("button", { name: "Create account" }));
		await waitFor(() => expect(signUp).toHaveBeenCalledOnce());
		expect(signUp).toHaveBeenCalledWith({
			email: "new-owner@example.test",
			password: "example-password-123",
			options: {
				emailRedirectTo: `${location.origin}/auth/callback`,
				captchaToken: undefined,
				data: { workspace_name: "Acme Security" },
			},
		});
		expect(screen.getByRole("alert")).toHaveTextContent(
			"If this address is eligible, check your inbox",
		);
		expect(screen.getByLabelText("Password")).toHaveValue("");
		expect(signOut).not.toHaveBeenCalled();
		expect(window.localStorage.getItem("aidr.postAuthReturnTo.v1")).toBe("/onboarding");
	});

	it("keeps duplicate-account confirmation copy enumeration-safe", async () => {
		signUp.mockResolvedValue({
			data: { user: { id: "existing-user", identities: [] }, session: null },
			error: null,
		});
		renderSignup();
		fireEvent.click(screen.getByRole("button", { name: "Create account" }));
		const notice = await screen.findByRole("alert");
		expect(notice).toHaveTextContent("If this address is eligible");
		expect(notice).not.toHaveTextContent("A confirmation email has been sent");
	});

	it("does not submit mismatched passwords", () => {
		renderSignup();
		fireEvent.change(screen.getByLabelText("Confirm password"), {
			target: { value: "different-password" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create account" }));
		expect(screen.getByRole("alert")).toHaveTextContent("Passwords do not match");
		expect(signUp).not.toHaveBeenCalled();
	});

	it("requires a bounded nonblank organization name", () => {
		renderSignup();
		fireEvent.change(screen.getByLabelText("Team or organization name"), {
			target: { value: "   " },
		});
		expect(screen.getByRole("button", { name: "Create account" })).toBeDisabled();
		expect(signUp).not.toHaveBeenCalled();
	});

	it("rejects control characters in the organization name before signup", () => {
		renderSignup();
		fireEvent.change(screen.getByLabelText("Team or organization name"), {
			target: { value: "Acme\u007fSecurity" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create account" }));
		expect(screen.getByRole("alert")).toHaveTextContent("without control characters");
		expect(signUp).not.toHaveBeenCalled();
	});

	it("clears an unexpected immediate session instead of continuing without email confirmation", async () => {
		signUp.mockResolvedValue({
			data: { user: { id: "new-user" }, session: { access_token: "unexpected" } },
			error: null,
		});
		renderSignup();
		fireEvent.click(screen.getByRole("button", { name: "Create account" }));
		await waitFor(() => expect(signOut).toHaveBeenCalledWith({ scope: "local" }));
		expect(screen.getByRole("alert")).toHaveTextContent("Email confirmation is not enabled");
		expect(screen.queryByText(/Check your inbox/)).not.toBeInTheDocument();
	});

	it("reports email delivery limits without exposing provider details", async () => {
		signUp.mockResolvedValue({
			data: { user: null, session: null },
			error: { status: 429, message: "private SMTP quota" },
		});
		renderSignup();
		fireEvent.click(screen.getByRole("button", { name: "Create account" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("temporarily limited"));
		expect(screen.queryByText("private SMTP quota")).not.toBeInTheDocument();
	});

	it.each(["closed", "pilot", "onprem", "unconfigured"])(
		"keeps registration hidden unless the runtime mode is explicitly cloud (%s)",
		(mode) => {
			window.__AIDR_CONFIG__ = { authMethods: ["password"], signupMode: mode as "closed" };
			render(
				<MemoryRouter>
					<LoginPage />
				</MemoryRouter>,
			);
			expect(
				screen.queryByRole("button", { name: "New to AIDR? Create an account" }),
			).not.toBeInTheDocument();
			expect(signUp).not.toHaveBeenCalled();
		},
	);

	it("requires the configured password method even in cloud mode", () => {
		window.__AIDR_CONFIG__ = { authMethods: ["magic-link"], signupMode: "cloud" };
		render(
			<MemoryRouter>
				<LoginPage />
			</MemoryRouter>,
		);
		expect(
			screen.queryByRole("button", { name: "New to AIDR? Create an account" }),
		).not.toBeInTheDocument();
	});
});
