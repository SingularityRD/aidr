// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getSession, invoke, signOut, verifyOtp } = vi.hoisted(() => ({
	getSession: vi.fn(),
	invoke: vi.fn(),
	signOut: vi.fn(),
	verifyOtp: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: { getSession, signOut, verifyOtp },
		functions: { invoke },
	},
}));

import {
	claimRecoveryHandoff,
	isRecoveryOtpSession,
	loadRecoveryTransaction,
	normalizeRecoveryTokenHash,
	RECOVERY_HANDOFF_STORAGE_KEY,
	RECOVERY_TRANSACTION_STORAGE_KEY,
	RecoveryPage,
} from "../ui/pages/RecoveryPage";

const TOKEN_HASH = "a".repeat(64);
const VERIFIER_RE = /^[A-Za-z0-9_-]{43}$/;
const CHALLENGE_RE = /^[0-9a-f]{64}$/;
const VERIFIER = "a".repeat(43);
const PROOF_ID = "33333333-3333-4333-8333-333333333333";

function session(method: string = "otp") {
	const payload = btoa(
		JSON.stringify({
			amr: [{ method, timestamp: 1 }],
			session_id: "22222222-2222-4222-8222-222222222222",
		}),
	)
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
	return { access_token: `header.${payload}.signature`, user: { id: "user-id" } };
}

describe("recovery credential boundaries", () => {
	it("accepts only a fixed-size token hash and a recovery-authenticated session", () => {
		expect(normalizeRecoveryTokenHash(TOKEN_HASH.toUpperCase())).toBe(TOKEN_HASH);
		expect(normalizeRecoveryTokenHash("a".repeat(63))).toBeNull();
		expect(normalizeRecoveryTokenHash(`${TOKEN_HASH}?next=/admin`)).toBeNull();
		expect(isRecoveryOtpSession(session())).toBe(true);
		expect(isRecoveryOtpSession(session("recovery"))).toBe(false);
		expect(isRecoveryOtpSession(session("password"))).toBe(false);
		expect(
			isRecoveryOtpSession({
				...session(),
				access_token: ["header.e", "30.signa", "ture"].join(""),
			}),
		).toBe(false);
		expect(isRecoveryOtpSession({ access_token: "not-a-jwt" })).toBe(false);
	});
});

describe("account recovery UI", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		window.history.replaceState({}, "", "/");
		window.localStorage.clear();
		window.sessionStorage.clear();
		invoke.mockResolvedValue({ data: { ok: true }, error: null });
		getSession.mockResolvedValue({ data: { session: null }, error: null });
		signOut.mockResolvedValue({ error: null });
		verifyOtp.mockResolvedValue({
			data: { session: session(), user: { id: "user-id" } },
			error: null,
		});
	});

	afterEach(() => {
		cleanup();
		window.localStorage.clear();
		window.sessionStorage.clear();
		window.history.replaceState({}, "", "/");
	});

	it("requests an opaque reset and verifies the emailed one-time code", async () => {
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "user@example.test" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Request recovery" }));
		await waitFor(() =>
			expect(invoke).toHaveBeenCalledWith("identity-security", {
				body: {
					action: "request_password_reset",
					email: "user@example.test",
					recovery_challenge: expect.stringMatching(CHALLENGE_RE),
				},
			}),
		);

		const code = await screen.findByLabelText("One-time recovery code");
		expect(screen.getByRole("alert")).toHaveTextContent("If this account is enabled");
		const transaction = loadRecoveryTransaction();
		expect(transaction).toMatchObject({
			email: "user@example.test",
			verifier: expect.stringMatching(VERIFIER_RE),
		});
		expect(JSON.parse(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY) ?? "null")).toMatchObject({
			email: "user@example.test",
			verifier: transaction?.verifier,
			proofId: expect.stringMatching(/^[0-9a-f-]{36}$/),
		});
		expect(window.location.href).not.toContain(transaction?.verifier ?? "not-present");
		expect(document.body).not.toHaveTextContent(transaction?.verifier ?? "not-present");
		fireEvent.change(code, { target: { value: "123456" } });
		fireEvent.click(screen.getByRole("button", { name: "Verify recovery code" }));

		expect(await screen.findByLabelText("New password")).toBeInTheDocument();
		expect(verifyOtp).toHaveBeenCalledWith({
			email: "user@example.test",
			token: "123456",
			type: "recovery",
		});
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: {
				action: "bind_password_recovery_grant",
				recovery_verifier: expect.stringMatching(VERIFIER_RE),
			},
			headers: { Authorization: `Bearer ${session().access_token}` },
		});
		const bindRequest = invoke.mock.calls.find(
			([, options]) => options.body.action === "bind_password_recovery_grant",
		)?.[1];

		fireEvent.change(screen.getByLabelText("New password"), {
			target: { value: "correct horse battery staple 42" },
		});
		fireEvent.change(screen.getByLabelText("Confirm new password"), {
			target: { value: "correct horse battery staple 42" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Update password and revoke sessions" }));
		await waitFor(() =>
			expect(invoke).toHaveBeenCalledWith("identity-security", {
				body: {
					action: "complete_password_recovery",
					new_password: "correct horse battery staple 42",
					recovery_verifier: bindRequest?.body.recovery_verifier,
				},
			}),
		);
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY)).toBeNull();
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).toBeNull();
	});

	it("claims a same-browser new-tab handoff once before showing the emailed code form", async () => {
		const now = Date.now();
		localStorage.setItem(
			RECOVERY_HANDOFF_STORAGE_KEY,
			JSON.stringify({
				proofId: PROOF_ID,
				email: "new-tab@example.test",
				verifier: VERIFIER,
				issuedAt: now,
				expiresAt: now + 60_000,
			}),
		);

		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);

		expect(await screen.findByLabelText("One-time recovery code")).toBeInTheDocument();
		expect(screen.getByLabelText("Email address")).toHaveValue("new-tab@example.test");
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).toBeNull();
		expect(loadRecoveryTransaction()).toMatchObject({
			email: "new-tab@example.test",
			verifier: VERIFIER,
		});
		expect(getSession).toHaveBeenCalledOnce();
		expect(claimRecoveryHandoff()).toBeNull();
		expect(invoke).not.toHaveBeenCalled();
	});

	it("retains and reuses the same proof after an uncertain reset response", async () => {
		invoke
			.mockResolvedValueOnce({ data: null, error: { context: { status: 503 } } })
			.mockResolvedValueOnce({ data: { ok: true }, error: null });
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "retry@example.test" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Request recovery" }));

		expect(await screen.findByRole("alert")).toHaveTextContent("temporarily unavailable");
		expect(sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY)).not.toBeNull();
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).not.toBeNull();
		fireEvent.click(screen.getByRole("button", { name: "Request recovery" }));
		expect(await screen.findByLabelText("One-time recovery code")).toBeInTheDocument();

		const resetRequests = invoke.mock.calls
			.map(([, options]) => options.body)
			.filter((body) => body.action === "request_password_reset");
		expect(resetRequests).toHaveLength(2);
		expect(resetRequests[1].recovery_challenge).toBe(resetRequests[0].recovery_challenge);
	});

	it.each([
		[
			"expired",
			{
				proofId: PROOF_ID,
				email: "user@example.test",
				verifier: VERIFIER,
				issuedAt: Date.now() - 120_000,
				expiresAt: Date.now() - 1,
			},
		],
		[
			"malformed",
			{
				proofId: PROOF_ID,
				email: "user@example.test",
				verifier: "stolen",
				issuedAt: Date.now(),
				expiresAt: Date.now() + 60_000,
			},
		],
	])("consumes and rejects a %s cross-tab handoff without session access", async (_name, value) => {
		localStorage.setItem(RECOVERY_HANDOFF_STORAGE_KEY, JSON.stringify(value));
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);

		expect(await screen.findByRole("button", { name: "Request recovery" })).toBeInTheDocument();
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).toBeNull();
		expect(sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY)).toBeNull();
		expect(getSession).not.toHaveBeenCalled();
	});

	it("restores and re-binds a short-lived same-browser recovery transaction after reload", async () => {
		sessionStorage.setItem(
			RECOVERY_TRANSACTION_STORAGE_KEY,
			JSON.stringify({
				email: "reload@example.test",
				verifier: VERIFIER,
				expiresAt: Date.now() + 60_000,
			}),
		);
		localStorage.setItem(
			RECOVERY_HANDOFF_STORAGE_KEY,
			JSON.stringify({
				proofId: PROOF_ID,
				email: "reload@example.test",
				verifier: VERIFIER,
				issuedAt: Date.now(),
				expiresAt: Date.now() + 60_000,
			}),
		);
		getSession.mockResolvedValue({ data: { session: session() }, error: null });

		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);

		expect(await screen.findByLabelText("New password")).toBeInTheDocument();
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: { action: "bind_password_recovery_grant", recovery_verifier: VERIFIER },
			headers: { Authorization: `Bearer ${session().access_token}` },
		});
		expect(screen.queryByText(VERIFIER)).not.toBeInTheDocument();
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).not.toBeNull();
	});

	it.each([
		["expired", { email: "user@example.test", verifier: VERIFIER, expiresAt: Date.now() - 1 }],
		[
			"malformed",
			{ email: "user@example.test", verifier: "stolen", expiresAt: Date.now() + 60_000 },
		],
	])("purges %s recovery transaction state before session access", async (_name, value) => {
		sessionStorage.setItem(RECOVERY_TRANSACTION_STORAGE_KEY, JSON.stringify(value));
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);

		expect(await screen.findByRole("button", { name: "Request recovery" })).toBeInTheDocument();
		expect(sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY)).toBeNull();
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).toBeNull();
		expect(getSession).not.toHaveBeenCalled();
	});

	it("purges a terminally rejected verifier so it cannot be replayed", async () => {
		sessionStorage.setItem(
			RECOVERY_TRANSACTION_STORAGE_KEY,
			JSON.stringify({
				email: "reload@example.test",
				verifier: VERIFIER,
				expiresAt: Date.now() + 60_000,
			}),
		);
		localStorage.setItem(
			RECOVERY_HANDOFF_STORAGE_KEY,
			JSON.stringify({
				proofId: PROOF_ID,
				email: "reload@example.test",
				verifier: VERIFIER,
				issuedAt: Date.now(),
				expiresAt: Date.now() + 60_000,
			}),
		);
		getSession.mockResolvedValue({ data: { session: session() }, error: null });
		invoke.mockResolvedValue({ data: null, error: { status: 401 } });

		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);

		expect(await screen.findByRole("alert")).toHaveTextContent("invalid or expired");
		expect(sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY)).toBeNull();
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).toBeNull();
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
	});

	it("keeps a bound recovery transaction across a transient completion failure", async () => {
		const now = Date.now();
		sessionStorage.setItem(
			RECOVERY_TRANSACTION_STORAGE_KEY,
			JSON.stringify({
				email: "retry@example.test",
				verifier: VERIFIER,
				expiresAt: now + 60_000,
			}),
		);
		localStorage.setItem(
			RECOVERY_HANDOFF_STORAGE_KEY,
			JSON.stringify({
				proofId: PROOF_ID,
				email: "retry@example.test",
				verifier: VERIFIER,
				issuedAt: now,
				expiresAt: now + 60_000,
			}),
		);
		getSession.mockResolvedValue({ data: { session: session() }, error: null });
		invoke
			.mockResolvedValueOnce({ data: { ok: true }, error: null })
			.mockResolvedValueOnce({ data: null, error: { context: { status: 503 } } })
			.mockResolvedValueOnce({ data: { ok: true }, error: null });

		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		const password = await screen.findByLabelText("New password");
		fireEvent.change(password, { target: { value: "correct horse battery staple 42" } });
		fireEvent.change(screen.getByLabelText("Confirm new password"), {
			target: { value: "correct horse battery staple 42" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Update password and revoke sessions" }));

		expect(await screen.findByRole("alert")).toHaveTextContent("temporarily unavailable");
		expect(password).toHaveValue("correct horse battery staple 42");
		expect(sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY)).not.toBeNull();
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).not.toBeNull();
		expect(signOut).not.toHaveBeenCalled();

		fireEvent.click(screen.getByRole("button", { name: "Update password and revoke sessions" }));
		await waitFor(() =>
			expect(sessionStorage.getItem(RECOVERY_TRANSACTION_STORAGE_KEY)).toBeNull(),
		);
		expect(localStorage.getItem(RECOVERY_HANDOFF_STORAGE_KEY)).toBeNull();
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
	});

	it("exchanges a break-glass response token in memory without rendering a link", async () => {
		invoke.mockResolvedValue({
			data: {
				ok: true,
				recovery_token_hash: TOKEN_HASH,
				recovery_type: "recovery",
			},
			error: null,
		});
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Break-glass code" }));
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "user@example.test" },
		});
		fireEvent.change(screen.getByLabelText("One-time recovery code"), {
			target: { value: "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-00000-11111" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Use one-time code" }));

		expect(await screen.findByLabelText("New password")).toBeInTheDocument();
		expect(verifyOtp).toHaveBeenCalledWith({ token_hash: TOKEN_HASH, type: "recovery" });
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: expect.objectContaining({
				action: "break_glass_recover",
				recovery_challenge: expect.stringMatching(CHALLENGE_RE),
			}),
		});
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: {
				action: "bind_password_recovery_grant",
				recovery_verifier: expect.stringMatching(VERIFIER_RE),
			},
			headers: { Authorization: `Bearer ${session().access_token}` },
		});
		expect(
			screen.queryByRole("link", { name: /continue password recovery/i }),
		).not.toBeInTheDocument();
		expect(document.body).not.toHaveTextContent(TOKEN_HASH);
	});

	it("rejects a malformed break-glass token without sending it to Auth", async () => {
		invoke.mockResolvedValue({
			data: {
				ok: true,
				recovery_token_hash: "not-a-token",
				recovery_type: "recovery",
			},
			error: null,
		});
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.click(screen.getByRole("button", { name: "Break-glass code" }));
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "u@example.test" },
		});
		fireEvent.change(screen.getByLabelText("One-time recovery code"), {
			target: { value: "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF-00000-11111" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Use one-time code" }));

		expect(await screen.findByRole("alert")).toHaveTextContent("invalid or expired");
		expect(verifyOtp).not.toHaveBeenCalled();
	});

	it("scrubs callback credentials without trusting an unbound URL token", async () => {
		window.history.replaceState(
			{},
			"",
			`/auth/recover?token_hash=${TOKEN_HASH}&type=recovery#access_token=never-log`,
		);
		render(
			<MemoryRouter initialEntries={[`/auth/recover?token_hash=${TOKEN_HASH}&type=recovery`]}>
				<RecoveryPage />
			</MemoryRouter>,
		);

		expect(window.location.search).not.toContain("token_hash");
		expect(window.location.hash).toBe("");
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Enter the one-time code from your recovery email",
		);
		expect(screen.queryByLabelText("New password")).not.toBeInTheDocument();
		expect(verifyOtp).not.toHaveBeenCalled();
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
	});

	it("does not claim recovery success for an empty reset response", async () => {
		invoke.mockResolvedValue({ data: {}, error: null });
		render(
			<MemoryRouter>
				<RecoveryPage />
			</MemoryRouter>,
		);
		fireEvent.change(screen.getByLabelText("Email address"), {
			target: { value: "user@example.test" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Request recovery" }));
		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				"Password recovery is temporarily unavailable",
			),
		);
	});
});
