// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSession, signInWithSSO } = vi.hoisted(() => ({
	getSession: vi.fn(),
	signInWithSSO: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: { auth: { getSession, signInWithSSO } },
}));

import { LoginPage } from "../ui/pages/LoginPage";

describe("configured SAML sign-in", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		localStorage.clear();
		window.__AIDR_CONFIG__ = { authMethods: ["password"] };
		getSession.mockResolvedValue({ data: { session: null }, error: null });
		signInWithSSO.mockResolvedValue({ data: { url: null }, error: null });
	});
	afterEach(() => {
		cleanup();
		delete window.__AIDR_CONFIG__;
	});

	it("keeps SSO hidden by default and leaves password login available", () => {
		render(<MemoryRouter><LoginPage /></MemoryRouter>);
		expect(screen.queryByRole("button", { name: "Continue with company SSO" })).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
	});

	it("starts provider-bound SAML with the existing callback and safe return path", async () => {
		window.__AIDR_CONFIG__ = {
			authMethods: ["password"],
			samlProviderId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92",
		};
		render(<MemoryRouter initialEntries={["/login?returnTo=%2Fenterprise"]}><LoginPage /></MemoryRouter>);
		fireEvent.click(screen.getByRole("button", { name: "Continue with company SSO" }));
		await waitFor(() => expect(signInWithSSO).toHaveBeenCalledWith({
			providerId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92",
			options: { redirectTo: `${location.origin}/auth/callback` },
		}));
		expect(localStorage.getItem("aidr.postAuthReturnTo.v1")).toBe("/enterprise");
		expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
	});

	it("starts SAML discovery only for the explicitly configured domain", async () => {
		window.__AIDR_CONFIG__ = { authMethods: ["magic-link"], samlDomain: "company.example" };
		render(<MemoryRouter><LoginPage /></MemoryRouter>);
		fireEvent.click(screen.getByRole("button", { name: "Continue with company SSO" }));
		await waitFor(() => expect(signInWithSSO).toHaveBeenCalledWith({
			domain: "company.example",
			options: { redirectTo: `${location.origin}/auth/callback` },
		}));
		expect(screen.getByRole("button", { name: "Send magic link" })).toBeInTheDocument();
	});

	it("offers each explicitly configured provider and starts the selected SAML flow", async () => {
		window.__AIDR_CONFIG__ = {
			authMethods: ["password"],
			samlProviders: [
				{ providerId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92", label: "Microsoft Entra ID" },
				{ providerId: "33333333-3333-4333-8333-333333333333", label: "Okta" },
			],
		};
		render(<MemoryRouter><LoginPage /></MemoryRouter>);
		const entra = screen.getByRole("button", { name: "Continue with Microsoft Entra ID" });
		const okta = screen.getByRole("button", { name: "Continue with Okta" });
		fireEvent.click(entra);
		await waitFor(() => expect(signInWithSSO).toHaveBeenCalledWith({
			providerId: "21648a9d-8d5a-4555-a9d1-d6375dc14e92",
			options: { redirectTo: `${location.origin}/auth/callback` },
		}));
		signInWithSSO.mockClear();
		fireEvent.click(okta);
		await waitFor(() => expect(signInWithSSO).toHaveBeenCalledWith({
			providerId: "33333333-3333-4333-8333-333333333333",
			options: { redirectTo: `${location.origin}/auth/callback` },
		}));
	});

	it("does not expose provider errors or accept an insecure redirect URL", async () => {
		window.__AIDR_CONFIG__ = { authMethods: [], samlDomain: "company.example" };
		signInWithSSO.mockResolvedValue({ data: { url: "javascript:alert(1)" }, error: null });
		render(<MemoryRouter><LoginPage /></MemoryRouter>);
		fireEvent.click(screen.getByRole("button", { name: "Continue with company SSO" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("Company sign-in is unavailable");
		expect(screen.queryByText("Sign-in has not been configured")).not.toBeInTheDocument();
	});
});
