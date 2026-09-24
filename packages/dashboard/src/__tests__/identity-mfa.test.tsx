// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useLayoutEffect } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
	invoke,
	getSession,
	signOut,
	onAuthStateChange,
	unsubscribe,
	enroll,
	listFactors,
	challenge,
	verify,
} = vi.hoisted(() => ({
	invoke: vi.fn(),
	getSession: vi.fn(),
	signOut: vi.fn(),
	onAuthStateChange: vi.fn(),
	unsubscribe: vi.fn(),
	enroll: vi.fn(),
	listFactors: vi.fn(),
	challenge: vi.fn(),
	verify: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession,
			signOut,
			onAuthStateChange,
			mfa: { enroll, listFactors, challenge, verify },
		},
		functions: { invoke },
	},
	supabaseEnvError: null,
}));

import { EnterpriseAuth } from "../enterprise/auth";
import { signOut as dashboardSignOut, INACTIVITY_TIMEOUT_MS, readSession } from "../ui/session";

const USER_ID = "22222222-2222-4222-8222-222222222222";
const FACTOR_ID = "33333333-3333-4333-8333-333333333333";
const CHALLENGE_ID = "44444444-4444-4444-8444-444444444444";

/** The status report the identity-security Edge Function returns at aal1. */
function aal1Report() {
	return {
		data: {
			ok: true,
			tenant_id: "11111111-1111-4111-8111-111111111111",
			role: "owner",
			require_mfa: true,
			break_glass_enabled: true,
			current_assurance: "aal1",
			next_assurance: "aal2",
			access_allowed: false,
		},
		error: null,
	};
}

/** The same report once the session has stepped up to aal2. */
function aal2Report() {
	return {
		data: {
			ok: true,
			tenant_id: "11111111-1111-4111-8111-111111111111",
			role: "owner",
			require_mfa: true,
			break_glass_enabled: true,
			current_assurance: "aal2",
			next_assurance: "aal2",
			access_allowed: true,
		},
		error: null,
	};
}

function renderManagedSurface() {
	return render(
		<MemoryRouter>
			<EnterpriseAuth>
				<div>Managed console</div>
			</EnterpriseAuth>
		</MemoryRouter>,
	);
}

describe("AAL2 step-up before managed screens", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		localStorage.clear();
		getSession.mockResolvedValue({
			data: { session: { access_token: "access-token-aal1", user: { id: USER_ID } } },
			error: null,
		});
		signOut.mockResolvedValue({ error: null });
		onAuthStateChange.mockReturnValue({ data: { subscription: { unsubscribe } } });
		listFactors.mockResolvedValue({
			data: {
				all: [{ id: FACTOR_ID, factor_type: "totp", status: "verified" }],
				totp: [{ id: FACTOR_ID, factor_type: "totp", status: "verified" }],
				phone: [],
				webauthn: [],
			},
			error: null,
		});
		challenge.mockResolvedValue({
			data: { id: CHALLENGE_ID, type: "totp", expires_at: 4_102_444_800 },
			error: null,
		});
		verify.mockImplementation(async () => {
			getSession.mockResolvedValue({
				data: { session: { access_token: "access-token-aal2", user: { id: USER_ID } } },
				error: null,
			});
			return { data: { access_token: "access-token-aal2" }, error: null };
		});
		enroll.mockResolvedValue({
			data: {
				id: FACTOR_ID,
				type: "totp",
				totp: {
					qr_code: "<svg></svg>",
					secret: "JBSWY3DPEHPK3PXP",
					uri: "otpauth://totp/AIDR?secret=JBSWY3DPEHPK3PXP",
				},
			},
			error: null,
		});
	});

	afterEach(() => {
		cleanup();
		delete window.__AIDR_CONFIG__;
	});

	it("offers a signed-in visitor a path out of the enterprise entry page", async () => {
		render(
			<MemoryRouter initialEntries={["/enterprise"]}>
				<EnterpriseAuth />
			</MemoryRouter>,
		);
		expect(await screen.findByRole("link", { name: "Open dashboard" })).toHaveAttribute(
			"href",
			"/dashboard",
		);
	});

	it("explains an explicitly unconfigured sign-in deployment without fake methods", async () => {
		getSession.mockResolvedValue({ data: { session: null }, error: null });
		window.__AIDR_CONFIG__ = { authMethods: [] };
		render(
			<MemoryRouter initialEntries={["/enterprise"]}>
				<EnterpriseAuth />
			</MemoryRouter>,
		);
		expect(await screen.findByRole("status")).toHaveTextContent(
			"Enterprise sign-in is not configured for this deployment",
		);
		expect(
			screen.queryByRole("button", { name: /Continue with GitHub|Continue with GitLab/ }),
		).not.toBeInTheDocument();
		expect(
			screen.queryByRole("link", { name: "Sign in with a configured method" }),
		).not.toBeInTheDocument();
	});

	it("challenges an aal1 session before rendering managed screens", async () => {
		let statusCalls = 0;
		invoke.mockImplementation(async () => {
			statusCalls += 1;
			return statusCalls === 1 ? aal1Report() : aal2Report();
		});

		renderManagedSurface();

		await waitFor(() =>
			expect(
				screen.getByRole("heading", { name: "Multi-factor authentication required" }),
			).toBeInTheDocument(),
		);
		// The pre-MFA session must not open the protected screen.
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: { action: "status" },
			headers: { Authorization: "Bearer access-token-aal1" },
		});

		fireEvent.change(screen.getByLabelText("Authenticator code"), {
			target: { value: "123456" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));

		await waitFor(() => expect(screen.getByText("Managed console")).toBeInTheDocument());
		expect(challenge).toHaveBeenCalledWith({ factorId: FACTOR_ID });
		expect(verify).toHaveBeenCalledWith({
			factorId: FACTOR_ID,
			challengeId: CHALLENGE_ID,
			code: "123456",
		});
		// Access is granted by the server's typed report, not by the client's
		// own verify response, so the control plane is asked again.
		expect(invoke).toHaveBeenCalledTimes(2);
		expect(signOut).not.toHaveBeenCalled();
	});

	it("forces AAL2 for DLP even when tenant-wide MFA is optional", async () => {
		let statusCalls = 0;
		invoke.mockImplementation(async () => {
			statusCalls += 1;
			const report = statusCalls === 1 ? aal1Report() : aal2Report();
			return {
				...report,
				data: { ...report.data, require_mfa: false, access_allowed: true },
			};
		});
		render(
			<MemoryRouter>
				<EnterpriseAuth tenantId="11111111-1111-4111-8111-111111111111" forceMfa>
					<div>DLP protected action</div>
				</EnterpriseAuth>
			</MemoryRouter>,
		);
		await screen.findByRole("heading", { name: "Multi-factor authentication required" });
		expect(screen.queryByText("DLP protected action")).not.toBeInTheDocument();
		fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
		fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));
		await screen.findByText("DLP protected action");
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: { action: "status", tenant_id: "11111111-1111-4111-8111-111111111111" },
			headers: expect.objectContaining({ Authorization: "Bearer access-token-aal2" }),
		});
	});

	it("does not degrade to the pre-MFA session when the challenge is cancelled", async () => {
		invoke.mockResolvedValue(aal1Report());

		renderManagedSurface();

		await waitFor(() =>
			expect(
				screen.getByRole("heading", { name: "Multi-factor authentication required" }),
			).toBeInTheDocument(),
		);
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Cancel and sign out" }));

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/Multi-factor authentication was cancelled/,
			),
		);
		// Cancelling ends the session instead of quietly continuing at aal1.
		expect(signOut).toHaveBeenCalled();
		expect(verify).not.toHaveBeenCalled();
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
		expect(screen.queryByLabelText("Authenticator code")).not.toBeInTheDocument();
		expect(invoke).toHaveBeenCalledTimes(1);
	});

	it("never mounts B with A's clear state and ignores a delayed A response", async () => {
		const a = "11111111-1111-4111-8111-111111111111";
		const b = "55555555-5555-4555-8555-555555555555";
		const mounts = vi.fn();
		function Child({ tenant }: { tenant: string }) {
			useLayoutEffect(() => {
				mounts(tenant);
			}, [tenant]);
			return <div>Protected {tenant}</div>;
		}
		const pending: Array<(value: ReturnType<typeof aal2Report>) => void> = [];
		invoke.mockImplementation(() => new Promise((resolve) => pending.push(resolve)));
		const view = (tenant: string) => (
			<MemoryRouter>
				<EnterpriseAuth tenantId={tenant}>
					<Child tenant={tenant} />
				</EnterpriseAuth>
			</MemoryRouter>
		);
		const { rerender } = render(view(a));
		await waitFor(() => expect(pending).toHaveLength(1));
		await act(async () => pending[0]!(aal2Report()));
		expect(mounts).toHaveBeenCalledExactlyOnceWith(a);
		rerender(view(b));
		expect(mounts).toHaveBeenCalledTimes(1); // Includes the render BEFORE effects.
		await waitFor(() => expect(pending).toHaveLength(2));
		rerender(view(a));
		await waitFor(() => expect(pending).toHaveLength(3));
		rerender(view(b));
		await waitFor(() => expect(pending).toHaveLength(4));
		await act(async () => pending[2]!(aal2Report())); // Old A completes after B starts.
		await act(async () =>
			pending[1]!({ ...aal2Report(), data: { ...aal2Report().data, tenant_id: b } }),
		); // Old B generation, too.
		expect(mounts).toHaveBeenCalledTimes(1);
		await act(async () =>
			pending[3]!({ ...aal2Report(), data: { ...aal2Report().data, tenant_id: b } }),
		);
		expect(mounts).toHaveBeenCalledTimes(2);
		expect(mounts).toHaveBeenLastCalledWith(b);
	});

	it("withholds a cleared tenant immediately on token downgrade and user change", async () => {
		invoke.mockResolvedValue(aal2Report());
		renderManagedSurface();
		await screen.findByText("Managed console");
		let resolveStatus!: (value: ReturnType<typeof aal1Report>) => void;
		invoke.mockImplementation(
			() =>
				new Promise((resolve) => {
					resolveStatus = resolve;
				}),
		);
		const callback = onAuthStateChange.mock.calls[0]![0];
		getSession.mockResolvedValue({
			data: { session: { access_token: "downgraded-token", user: { id: USER_ID } } },
			error: null,
		});
		act(() => callback("TOKEN_REFRESHED"));
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
		await waitFor(() => expect(invoke).toHaveBeenCalledTimes(2));
		expect(invoke.mock.calls[1]![1].headers.Authorization).toBe("Bearer downgraded-token");
		await act(async () => resolveStatus(aal1Report()));
		await screen.findByLabelText("Authenticator code");
		fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
		getSession.mockResolvedValue({
			data: { session: { access_token: "other-user-token", user: { id: FACTOR_ID } } },
			error: null,
		});
		act(() => callback("SIGNED_IN"));
		await waitFor(() => expect(invoke).toHaveBeenCalledTimes(3));
		await act(async () => resolveStatus(aal1Report()));
		expect(screen.getByLabelText("Authenticator code")).toHaveValue("");
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
	});

	it("discards enrollment secrets and delayed factor operations on tenant switch", async () => {
		const a = "11111111-1111-4111-8111-111111111111";
		const b = "55555555-5555-4555-8555-555555555555";
		invoke.mockImplementation(async (_name, options) => ({
			...aal1Report(),
			data: { ...aal1Report().data, tenant_id: options.body.tenant_id },
		}));
		let finishEnrollment!: (value: unknown) => void;
		enroll.mockImplementation(
			() =>
				new Promise((resolve) => {
					finishEnrollment = resolve;
				}),
		);
		const view = (tenant: string) => (
			<MemoryRouter>
				<EnterpriseAuth tenantId={tenant}>
					<div>Managed console</div>
				</EnterpriseAuth>
			</MemoryRouter>
		);
		const { rerender } = render(view(a));
		fireEvent.click(await screen.findByText("Enroll a new authenticator app"));
		rerender(view(b));
		await screen.findByLabelText("Authenticator code");
		await act(async () =>
			finishEnrollment({
				data: { id: FACTOR_ID, type: "totp", totp: { secret: "OLD-SECRET", uri: "old-uri" } },
				error: null,
			}),
		);
		expect(screen.queryByText("OLD-SECRET")).not.toBeInTheDocument();
		expect(screen.getByLabelText("Authenticator code")).toHaveValue("");
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
	});

	it("does not continue a factor operation after an auth event invalidates its generation", async () => {
		invoke.mockResolvedValue(aal1Report());
		let finishFactors!: (value: unknown) => void;
		listFactors.mockImplementation(
			() =>
				new Promise((resolve) => {
					finishFactors = resolve;
				}),
		);
		renderManagedSurface();
		await screen.findByLabelText("Authenticator code");
		fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
		fireEvent.click(screen.getByText("Verify and continue"));
		await waitFor(() => expect(listFactors).toHaveBeenCalledOnce());
		await act(async () => {
			onAuthStateChange.mock.calls[0]![0]("TOKEN_REFRESHED");
			finishFactors({ data: { totp: [{ id: FACTOR_ID, status: "verified" }] }, error: null });
			await Promise.resolve();
		});
		expect(challenge).not.toHaveBeenCalled();
		expect(verify).not.toHaveBeenCalled();
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
	});

	it("ignores an older session read that resolves after a new auth generation", async () => {
		let finishOldRead!: (value: unknown) => void;
		getSession.mockImplementationOnce(
			() =>
				new Promise((resolve) => {
					finishOldRead = resolve;
				}),
		);
		invoke.mockResolvedValue(aal1Report());
		renderManagedSurface();
		await waitFor(() => expect(getSession).toHaveBeenCalledOnce());
		act(() => onAuthStateChange.mock.calls[0]![0]("TOKEN_REFRESHED"));
		await screen.findByLabelText("Authenticator code");
		await act(async () =>
			finishOldRead({
				data: { session: { access_token: "stale-aal2", user: { id: USER_ID } } },
				error: null,
			}),
		);
		expect(invoke).toHaveBeenCalledOnce();
		expect(invoke.mock.calls[0]![1].headers.Authorization).toBe("Bearer access-token-aal1");
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
	});

	it("rejects revoked sessions and a mismatched tenant assurance response", async () => {
		invoke.mockResolvedValue({ data: null, error: new Error("session_revoked") });
		const { rerender } = render(
			<MemoryRouter>
				<EnterpriseAuth tenantId="tenant-a">
					<div>Managed console</div>
				</EnterpriseAuth>
			</MemoryRouter>,
		);
		await screen.findByText(/Session assurance could not be verified/);
		expect(screen.queryByText("session_revoked")).not.toBeInTheDocument();
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
		invoke.mockResolvedValue(aal2Report());
		rerender(
			<MemoryRouter>
				<EnterpriseAuth tenantId="tenant-b">
					<div>Managed console</div>
				</EnterpriseAuth>
			</MemoryRouter>,
		);
		await screen.findByText(/Session assurance could not be verified/);
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
	});

	it("withholds managed screens when the control plane report cannot be trusted", async () => {
		invoke.mockResolvedValue({ data: { ok: true }, error: null });

		renderManagedSurface();

		await waitFor(() =>
			expect(screen.getByRole("alert")).toHaveTextContent(
				/Session assurance could not be verified/,
			),
		);
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
		expect(challenge).not.toHaveBeenCalled();
	});
});

describe("Dashboard session lifetime", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		localStorage.clear();
		signOut.mockResolvedValue({ error: null });
		invoke.mockResolvedValue({
			data: { ok: true, scope: "global", reauthentication_required: true },
			error: null,
		});
		getSession.mockResolvedValue({
			data: { session: { access_token: "access-token-aal1", user: { id: USER_ID } } },
			error: null,
		});
	});

	afterEach(cleanup);

	it("ends an idle session instead of resuming it", async () => {
		localStorage.setItem(
			"aidr.session.activity.v1",
			JSON.stringify({ user_id: USER_ID, at: Date.now() - INACTIVITY_TIMEOUT_MS - 1_000 }),
		);

		const snapshot = await readSession();

		expect(snapshot.session).toBeNull();
		expect(snapshot.status.state).toBe("expired");
		expect(snapshot.status.reason).toBe("inactivity");
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: { action: "revoke_sessions", scope: "global" },
		});
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
	});

	it("globally revokes the authenticated session before clearing local state", async () => {
		await dashboardSignOut();

		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: { action: "revoke_sessions", scope: "global" },
		});
		const [revokeOrder] = invoke.mock.invocationCallOrder;
		const [localSignOutOrder] = signOut.mock.invocationCallOrder;
		if (revokeOrder === undefined || localSignOutOrder === undefined) {
			throw new Error("Expected both revocation and local sign-out calls");
		}
		expect(revokeOrder).toBeLessThan(localSignOutOrder);
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
	});

	it("purges local auth when global revocation is unconfirmed", async () => {
		invoke.mockResolvedValue({ data: { ok: true }, error: null });
		localStorage.setItem("aidr.session.activity.v1", JSON.stringify({ user_id: USER_ID, at: 1 }));

		await expect(dashboardSignOut()).resolves.toEqual({ serverRevoked: false });
		expect(signOut).toHaveBeenCalledWith({ scope: "local" });
		expect(localStorage.getItem("aidr.session.activity.v1")).toBeNull();
	});

	it("reports an unconfirmed local sign-out as a failure", async () => {
		signOut.mockResolvedValue({ error: new Error("local cleanup failed") });
		await expect(dashboardSignOut()).rejects.toThrow("local cleanup failed");
	});

	it("keeps a freshly used session active", async () => {
		localStorage.setItem(
			"aidr.session.activity.v1",
			JSON.stringify({ user_id: USER_ID, at: Date.now() }),
		);

		const snapshot = await readSession();

		expect(snapshot.session).not.toBeNull();
		expect(snapshot.status.state).toBe("active");
		expect(signOut).not.toHaveBeenCalled();
	});
});
