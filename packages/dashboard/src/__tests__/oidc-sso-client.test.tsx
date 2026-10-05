// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
	invoke: vi.fn(),
	verifyOtp: vi.fn(),
	signOut: vi.fn(),
	getSession: vi.fn(),
	role: "owner",
}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		functions: { invoke: fixture.invoke },
		auth: {
			verifyOtp: fixture.verifyOtp,
			signOut: fixture.signOut,
			getSession: fixture.getSession,
		},
	},
}));
vi.mock("../auth/oidc-sso", async (importOriginal) => ({
	...(await importOriginal<typeof import("../auth/oidc-sso")>()),
	redirectToIdp: vi.fn(),
}));
vi.mock("../enterprise/team-provider", () => ({
	useTeam: () => ({
		currentTeam: {
			id: "team-id",
			tenant_id: "11111111-1111-4111-8111-111111111111",
			name: "Contoso",
		},
		currentRole: fixture.role,
	}),
}));

import { completeOidcFlow, isSafeIdpUrl, redirectToIdp, startOidcFlow } from "../auth/oidc-sso";
import { LoginPage } from "../ui/pages/LoginPage";
import { OidcBreakGlassPage } from "../ui/pages/OidcBreakGlassPage";
import { OidcCallbackPage } from "../ui/pages/OidcCallbackPage";
import { OidcSsoPage } from "../ui/pages/OidcSsoPage";

const TOKEN_HASH = "a".repeat(64);
const TICKET = "T".repeat(43);
const BINDING_KEY = "aidr.oidc.binding.v1";

beforeEach(() => {
	vi.resetAllMocks();
	sessionStorage.clear();
	localStorage.clear();
	fixture.role = "owner";
	fixture.getSession.mockResolvedValue({ data: { session: null }, error: null });
	fixture.signOut.mockResolvedValue({ error: null });
	window.__AIDR_CONFIG__ = { authMethods: ["password"] };
});
afterEach(() => {
	cleanup();
	delete window.__AIDR_CONFIG__;
});

function storedBinding() {
	return JSON.parse(sessionStorage.getItem(BINDING_KEY) ?? "null") as {
		verifier: string;
		mode: string;
		returnTo: string;
	};
}

describe("startOidcFlow", () => {
	it("registers only the SHA-256 of a per-tab binding secret and returns a validated https URL", async () => {
		fixture.invoke.mockResolvedValue({
			data: { ok: true, authorization_url: "https://idp.example.com/authorize?x=1" },
			error: null,
		});
		const result = await startOidcFlow({ email: " Alice@Example.COM ", returnTo: "/dashboard" });
		expect(result).toEqual({ ok: true, url: "https://idp.example.com/authorize?x=1" });
		const body = fixture.invoke.mock.calls[0]?.[1].body as Record<string, string>;
		expect(body).toMatchObject({ action: "start", mode: "login", email: "alice@example.com" });
		const binding = storedBinding();
		const digest = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(binding.verifier),
		);
		expect(body.binding_challenge).toBe(
			Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""),
		);
		expect(JSON.stringify(body)).not.toContain(binding.verifier);
		expect(binding.returnTo).toBe("/dashboard");
	});

	it.each([
		["http://idp.example.com/a"],
		["javascript:alert(1)"],
		["https://user:pw@idp.example.com/a"],
		["not a url"],
		[undefined],
	])("refuses to redirect to %s and clears the binding", async (url) => {
		fixture.invoke.mockResolvedValue({ data: { ok: true, authorization_url: url }, error: null });
		const result = await startOidcFlow({ email: "a@b.example", returnTo: "/" });
		expect(result.ok).toBe(false);
		expect(sessionStorage.getItem(BINDING_KEY)).toBeNull();
		expect(isSafeIdpUrl(url)).toBe(false);
	});

	it("shows a fixed message for an unavailable provider and never raw server text", async () => {
		fixture.invoke.mockResolvedValue({
			data: { error: "sso_not_available" },
			error: { message: "relation oidc_providers does not exist" },
		});
		const result = await startOidcFlow({ email: "a@b.example", returnTo: "/" });
		expect(result).toMatchObject({ ok: false });
		expect(JSON.stringify(result)).not.toMatch(/relation|oidc_providers/);
	});
});

describe("completeOidcFlow", () => {
	const seedBinding = (mode = "login") =>
		sessionStorage.setItem(
			BINDING_KEY,
			JSON.stringify({ verifier: "v".repeat(43), mode, returnTo: "/team", startedAt: Date.now() }),
		);

	it("redeems the one-time token, binds the session with the ticket and consumes the binding", async () => {
		seedBinding();
		fixture.invoke
			.mockResolvedValueOnce({
				data: {
					ok: true,
					token_hash: TOKEN_HASH,
					login_ticket: TICKET,
					verification_type: "magiclink",
				},
				error: null,
			})
			.mockResolvedValueOnce({ data: { ok: true, tenant_id: "t" }, error: null });
		fixture.verifyOtp.mockResolvedValue({
			data: { session: { access_token: "jwt" } },
			error: null,
		});
		const result = await completeOidcFlow("?code=abc&state=xyz");
		expect(result).toEqual({ ok: true, mode: "login", returnTo: "/team" });
		expect(fixture.invoke.mock.calls[0]?.[1].body).toEqual({
			action: "callback",
			code: "abc",
			state: "xyz",
			binding_verifier: "v".repeat(43),
		});
		expect(fixture.verifyOtp).toHaveBeenCalledWith({ token_hash: TOKEN_HASH, type: "magiclink" });
		expect(fixture.invoke.mock.calls[1]?.[1].body).toEqual({
			action: "bind_session",
			login_ticket: TICKET,
		});
		expect(sessionStorage.getItem(BINDING_KEY)).toBeNull();
	});

	it("signs out again when the server refuses to bind the session", async () => {
		seedBinding();
		fixture.invoke
			.mockResolvedValueOnce({
				data: { ok: true, token_hash: TOKEN_HASH, login_ticket: TICKET },
				error: null,
			})
			.mockResolvedValueOnce({ data: null, error: { message: "401" } });
		fixture.verifyOtp.mockResolvedValue({
			data: { session: { access_token: "jwt" } },
			error: null,
		});
		const result = await completeOidcFlow("?code=abc&state=xyz");
		expect(result.ok).toBe(false);
		expect(fixture.signOut).toHaveBeenCalled();
	});

	it("does not call the server without a matching binding (a callback opened in another browser)", async () => {
		const result = await completeOidcFlow("?code=abc&state=xyz");
		expect(result).toMatchObject({ ok: false });
		expect(fixture.invoke).not.toHaveBeenCalled();
	});

	it("rejects expired bindings, IdP errors and missing parameters", async () => {
		sessionStorage.setItem(
			BINDING_KEY,
			JSON.stringify({
				verifier: "v".repeat(43),
				mode: "login",
				returnTo: "/",
				startedAt: Date.now() - 20 * 60_000,
			}),
		);
		expect((await completeOidcFlow("?code=abc&state=xyz")).ok).toBe(false);
		seedBinding();
		expect((await completeOidcFlow("?error=access_denied&state=xyz")).ok).toBe(false);
		seedBinding();
		expect((await completeOidcFlow("?code=abc")).ok).toBe(false);
		expect(fixture.invoke).not.toHaveBeenCalled();
	});

	it("maps documented failure reasons to fixed messages, including those in an HTTP error body", async () => {
		seedBinding();
		fixture.invoke.mockResolvedValue({
			data: null,
			error: {
				message: "Edge Function returned a non-2xx status code",
				context: new Response(
					JSON.stringify({ error: "sso_login_failed", reason: "domain_not_verified" }),
					{ status: 401 },
				),
			},
		});
		const result = await completeOidcFlow("?code=abc&state=xyz");
		expect(result).toMatchObject({
			ok: false,
			message: expect.stringMatching(/email domain is not verified/),
		});
	});

	it("returns a link result without creating a session", async () => {
		seedBinding("link");
		fixture.invoke.mockResolvedValue({ data: { ok: true, linked: true }, error: null });
		expect(await completeOidcFlow("?code=abc&state=xyz")).toEqual({
			ok: true,
			mode: "link",
			returnTo: "/team",
		});
		expect(fixture.verifyOtp).not.toHaveBeenCalled();
	});
});

describe("callback page", () => {
	function renderCallback(url = "/auth/oidc/callback?code=abc&state=xyz") {
		return render(
			<MemoryRouter initialEntries={[url]}>
				<Routes>
					<Route path="/auth/oidc/callback" element={<OidcCallbackPage />} />
					<Route path="/team" element={<div>team page</div>} />
					<Route path="/sso" element={<div>sso page</div>} />
					<Route path="/login" element={<div>login page</div>} />
				</Routes>
			</MemoryRouter>,
		);
	}

	it("navigates to the sanitised return path after a successful sign-in", async () => {
		sessionStorage.setItem(
			BINDING_KEY,
			JSON.stringify({
				verifier: "v".repeat(43),
				mode: "login",
				returnTo: "/team",
				startedAt: Date.now(),
			}),
		);
		fixture.invoke
			.mockResolvedValueOnce({
				data: { ok: true, token_hash: TOKEN_HASH, login_ticket: TICKET },
				error: null,
			})
			.mockResolvedValueOnce({ data: { ok: true }, error: null });
		fixture.verifyOtp.mockResolvedValue({
			data: { session: { access_token: "jwt" } },
			error: null,
		});
		renderCallback();
		expect(await screen.findByText("team page")).toBeInTheDocument();
	});

	it("shows a generic alert and a way back when verification fails", async () => {
		renderCallback();
		expect(await screen.findByRole("alert")).toHaveTextContent(/expired or was already used/);
		expect(screen.getByRole("link", { name: "Back to sign-in" })).toBeInTheDocument();
	});
});

describe("work-email SSO on the login page", () => {
	it("is hidden unless the deployment opts in", () => {
		render(
			<MemoryRouter>
				<LoginPage />
			</MemoryRouter>,
		);
		expect(
			screen.queryByRole("button", { name: "Continue with work email SSO" }),
		).not.toBeInTheDocument();
	});

	it("starts the flow and keeps password sign-in available", async () => {
		window.__AIDR_CONFIG__ = { authMethods: ["password"], oidcSso: true };
		fixture.invoke.mockResolvedValue({
			data: { ok: true, authorization_url: "https://idp.example.com/authorize" },
			error: null,
		});
		render(
			<MemoryRouter initialEntries={["/login?returnTo=%2Fteam"]}>
				<LoginPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Work email for single sign-on"), {
			target: { value: "alice@a-corp.test" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Continue with work email SSO" }));
		await waitFor(() =>
			expect(redirectToIdp).toHaveBeenCalledWith("https://idp.example.com/authorize"),
		);
		expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
	});
});

describe("owner SSO administration page", () => {
	const snapshot = (overrides: Record<string, unknown> = {}) => ({
		ok: true,
		redirect_uri: "https://app.aidr.test/auth/oidc/callback",
		provider: {
			id: "22222222-2222-4222-8222-222222222222",
			kind: "entra",
			display_name: "Contoso",
			issuer: "https://login.microsoftonline.com/11111111-2222-4333-8444-555555555555/v2.0",
			client_id: "client-a",
			token_auth_method: "client_secret_basic",
			client_secret_configured: true,
			subject_claim: "oid",
			groups_claim: null,
			groups_mode: "ignore",
			enabled: true,
			discovery_ready: true,
		},
		domains: [
			{ domain: "a-corp.test", verified: true, txt_name: "_aidr-sso.a-corp.test" },
			{
				domain: "new.test",
				verified: false,
				txt_name: "_aidr-sso.new.test",
				txt_value: "aidr-sso-verification=abc",
			},
		],
		enforced: false,
		saml_enforced: false,
		break_glass_enabled: true,
		...overrides,
	});

	beforeEach(() => {
		fixture.invoke.mockImplementation(
			async (_name: string, options: { body: Record<string, unknown> }) => {
				if (options.body.action === "get_config") return { data: snapshot(), error: null };
				return { data: { ok: true }, error: null };
			},
		);
	});

	it("is restricted to owners and never calls the function for anyone else", () => {
		fixture.role = "admin";
		render(<OidcSsoPage />);
		expect(screen.getByText(/available to active tenant owners only/)).toBeInTheDocument();
		expect(fixture.invoke).not.toHaveBeenCalled();
	});

	it("shows the redirect URI, pending DNS record and never a secret", async () => {
		render(<OidcSsoPage />);
		expect(await screen.findByText("https://app.aidr.test/auth/oidc/callback")).toBeInTheDocument();
		expect(
			screen.getByText(/_aidr-sso\.new\.test TXT aidr-sso-verification=abc/),
		).toBeInTheDocument();
		expect(document.body.textContent).not.toMatch(/s3cr3t/);
		expect(fixture.invoke.mock.calls[0]?.[1].body).toMatchObject({
			action: "get_config",
			tenant_id: "11111111-1111-4111-8111-111111111111",
		});
	});

	it("verifies a domain and surfaces a fixed message when verification fails", async () => {
		render(<OidcSsoPage />);
		fireEvent.click(await screen.findByRole("button", { name: "Verify new.test" }));
		await waitFor(() =>
			expect(
				fixture.invoke.mock.calls.some((call) => call[1].body.action === "verify_domain"),
			).toBe(true),
		);
		fixture.invoke.mockImplementation(
			async (_n: string, options: { body: Record<string, unknown> }) =>
				options.body.action === "get_config"
					? { data: snapshot(), error: null }
					: { data: { error: "verification_record_not_found" }, error: { message: "boom" } },
		);
		fireEvent.click(screen.getByRole("button", { name: "Verify new.test" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"The verification record was not found",
		);
	});

	it("requires a reason and change reference before enforcing and sends them to the audited operation", async () => {
		render(<OidcSsoPage />);
		const enforce = await screen.findByRole("button", { name: "Enforce single sign-on" });
		expect(enforce).toBeDisabled();
		fireEvent.change(screen.getByLabelText("Reason (recorded in the audit log)"), {
			target: { value: "Cut over to Entra SSO" },
		});
		fireEvent.change(screen.getByLabelText("Change reference"), { target: { value: "CHG-1042" } });
		expect(enforce).toBeEnabled();
		fireEvent.click(enforce);
		await waitFor(() =>
			expect(
				fixture.invoke.mock.calls.find((call) => call[1].body.action === "set_enforcement")?.[1]
					.body,
			).toMatchObject({
				provider_id: "22222222-2222-4222-8222-222222222222",
				reason: "Cut over to Entra SSO",
				change_ref: "CHG-1042",
			}),
		);
	});

	it("explains a refused enforcement without exposing server details", async () => {
		fixture.invoke.mockImplementation(
			async (_n: string, options: { body: Record<string, unknown> }) =>
				options.body.action === "get_config"
					? { data: snapshot(), error: null }
					: { data: { error: "oidc_verified_owners_required" }, error: { message: "relation x" } },
		);
		render(<OidcSsoPage />);
		fireEvent.change(await screen.findByLabelText("Reason (recorded in the audit log)"), {
			target: { value: "Cut over to Entra SSO" },
		});
		fireEvent.change(screen.getByLabelText("Change reference"), { target: { value: "CHG-1042" } });
		fireEvent.click(screen.getByRole("button", { name: "Enforce single sign-on" }));
		const alert = await screen.findByRole("alert");
		expect(alert).toHaveTextContent("at least two owners are required");
		expect(alert.textContent).not.toMatch(/relation/);
	});

	it("offers disabling when enforcement is on, and never offers enforcing", async () => {
		fixture.invoke.mockImplementation(
			async (_n: string, options: { body: Record<string, unknown> }) =>
				options.body.action === "get_config"
					? { data: snapshot({ enforced: true }), error: null }
					: { data: { ok: true }, error: null },
		);
		render(<OidcSsoPage />);
		expect(await screen.findByRole("button", { name: "Disable enforcement" })).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Enforce single sign-on" })).toBeNull();
	});

	it("saves provider settings with a secret reference, never a secret value", async () => {
		render(<OidcSsoPage />);
		await screen.findByLabelText("Issuer");
		fireEvent.change(screen.getByLabelText("Client secret reference"), {
			target: { value: "contoso" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save and validate" }));
		await waitFor(() =>
			expect(fixture.invoke.mock.calls.some((call) => call[1].body.action === "put_provider")).toBe(
				true,
			),
		);
		const body = fixture.invoke.mock.calls.find(
			(call) => call[1].body.action === "put_provider",
		)?.[1].body;
		expect(body).toMatchObject({ client_secret_ref: "CONTOSO", kind: "entra" });
		expect(JSON.stringify(body)).not.toMatch(/client_secret"|password/);
	});
});

describe("break-glass page", () => {
	it("submits the code once and reports success without any session", async () => {
		fixture.invoke.mockResolvedValue({
			data: { ok: true, enforcement_suspended: true },
			error: null,
		});
		render(
			<MemoryRouter>
				<OidcBreakGlassPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Owner email"), {
			target: { value: "owner@a-corp.test" },
		});
		fireEvent.change(screen.getByLabelText("Recovery code"), { target: { value: "ABCDE-12345" } });
		fireEvent.click(screen.getByRole("button", { name: "Suspend enforcement" }));
		expect(await screen.findByRole("status")).toHaveTextContent(/was suspended/);
		expect(fixture.invoke.mock.calls[0]?.[1].body).toEqual({
			action: "break_glass_suspend_enforcement",
			email: "owner@a-corp.test",
			recovery_code: "ABCDE-12345",
		});
		expect(fixture.verifyOtp).not.toHaveBeenCalled();
		expect(screen.getByLabelText("Recovery code")).toHaveValue("");
	});

	it("uses one message for every invalid code and a distinct one for throttling", async () => {
		fixture.invoke.mockResolvedValue({
			data: { error: "invalid_or_expired_recovery_code" },
			error: { message: "401" },
		});
		render(
			<MemoryRouter>
				<OidcBreakGlassPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Owner email"), {
			target: { value: "owner@a-corp.test" },
		});
		fireEvent.change(screen.getByLabelText("Recovery code"), { target: { value: "nope" } });
		fireEvent.click(screen.getByRole("button", { name: "Suspend enforcement" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"The recovery code is invalid or expired.",
		);
		fixture.invoke.mockResolvedValue({
			data: { error: "rate_limited" },
			error: { message: "429" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Suspend enforcement" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Too many attempts"));
	});
});
