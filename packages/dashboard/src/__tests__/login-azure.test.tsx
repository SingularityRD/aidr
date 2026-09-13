// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSession, signInWithOAuth } = vi.hoisted(() => ({
	getSession: vi.fn(), signInWithOAuth: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: { auth: { getSession, signInWithOAuth } },
}));

import { LoginPage } from "../ui/pages/LoginPage";

describe("configured Microsoft Entra sign-in", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		window.__AIDR_CONFIG__ = { authMethods: ["azure"] };
		getSession.mockResolvedValue({ data: { session: null }, error: null });
		signInWithOAuth.mockResolvedValue({ data: { url: null }, error: null });
	});
	afterEach(() => {
		cleanup();
		delete window.__AIDR_CONFIG__;
	});

	it("offers only the configured provider and starts Azure OAuth", async () => {
		render(<MemoryRouter initialEntries={["/login?returnTo=%2Fenterprise"]}><LoginPage /></MemoryRouter>);
		const button = screen.getByRole("button", { name: "Continue with Microsoft Entra ID" });
		expect(screen.queryByRole("button", { name: "Continue with Google" })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Continue with GitHub" })).not.toBeInTheDocument();
		fireEvent.click(button);
		await waitFor(() => expect(signInWithOAuth).toHaveBeenCalledWith({
			provider: "azure", options: { redirectTo: `${location.origin}/auth/callback` },
		}));
	});

	it("shows a safe failure message if the configured provider rejects sign-in", async () => {
		signInWithOAuth.mockResolvedValue({ data: null, error: { message: "private provider detail" } });
		render(<MemoryRouter><LoginPage /></MemoryRouter>);
		fireEvent.click(screen.getByRole("button", { name: "Continue with Microsoft Entra ID" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("provider is unavailable"));
		expect(screen.queryByText("private provider detail")).not.toBeInTheDocument();
	});
});
