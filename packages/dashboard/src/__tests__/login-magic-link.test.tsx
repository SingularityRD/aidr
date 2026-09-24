// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useRef } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSession, signInWithOtp, widgetState } = vi.hoisted(() => ({
	getSession: vi.fn(),
	signInWithOtp: vi.fn(),
	widgetState: { mounts: 0 },
}));

vi.mock("../lib/supabase", () => ({ supabase: { auth: { signInWithOtp } } }));
vi.mock("../ui/session", () => ({ getSession }));
vi.mock("../components/Turnstile", () => ({
	Turnstile: ({ onVerify }: { onVerify: (token: string) => void }) => {
		const instance = useRef<number | null>(null);
		if (instance.current === null) instance.current = ++widgetState.mounts;
		return (
			<button type="button" onClick={() => onVerify(`challenge-${instance.current}`)}>
				Verify challenge {instance.current}
			</button>
		);
	},
}));

import { LoginPage } from "../ui/pages/LoginPage";

describe("magic-link login", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		widgetState.mounts = 0;
		localStorage.clear();
		window.__AIDR_CONFIG__ = { authMethods: ["magic-link"] };
		getSession.mockResolvedValue(null);
		signInWithOtp.mockResolvedValue({ data: {}, error: null });
	});

	afterEach(() => {
		cleanup();
		vi.unstubAllEnvs();
		delete window.__AIDR_CONFIG__;
	});

	it("requests a non-signup link and keeps the acknowledgement account-neutral", async () => {
		render(
			<MemoryRouter initialEntries={["/login?returnTo=%2Fdashboard"]}>
				<LoginPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "member@example.test" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Send magic link" }));

		await waitFor(() =>
			expect(signInWithOtp).toHaveBeenCalledWith({
				email: "member@example.test",
				options: {
					emailRedirectTo: `${location.origin}/auth/callback`,
					captchaToken: undefined,
					shouldCreateUser: false,
				},
			}),
		);
		const notice = await screen.findByRole("alert");
		expect(notice).toHaveTextContent("If this account is enabled");
		expect(notice).not.toHaveTextContent("has been sent");
		expect(localStorage.getItem("aidr.postAuthReturnTo.v1")).toBe("/dashboard");
	});

	it("requires a fresh single-use challenge before retrying a failed auth request", async () => {
		vi.stubEnv("VITE_TURNSTILE_SITE_KEY", "test-site-key");
		signInWithOtp
			.mockResolvedValueOnce({ data: null, error: { status: 429, message: "rate limited" } })
			.mockResolvedValueOnce({ data: {}, error: null });
		render(
			<MemoryRouter>
				<LoginPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "member@example.test" },
		});
		fireEvent.click(await screen.findByRole("button", { name: "Verify challenge 1" }));
		fireEvent.click(screen.getByRole("button", { name: "Send magic link" }));
		await screen.findByText("Email delivery is temporarily limited. Please try again later.");
		const secondChallenge = await screen.findByRole("button", { name: "Verify challenge 2" });
		expect(screen.getByRole("button", { name: "Send magic link" })).toBeDisabled();
		fireEvent.click(secondChallenge);
		fireEvent.click(screen.getByRole("button", { name: "Send magic link" }));

		await screen.findByText("If this account is enabled, check your inbox for a sign-in link.");
		expect(signInWithOtp).toHaveBeenNthCalledWith(
			1,
			expect.objectContaining({
				email: "member@example.test",
				options: expect.objectContaining({ captchaToken: "challenge-1" }),
			}),
		);
		expect(signInWithOtp).toHaveBeenNthCalledWith(
			2,
			expect.objectContaining({
				email: "member@example.test",
				options: expect.objectContaining({ captchaToken: "challenge-2" }),
			}),
		);
	});
});
