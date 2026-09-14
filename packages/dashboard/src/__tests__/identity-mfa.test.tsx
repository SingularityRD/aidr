// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
import { INACTIVITY_TIMEOUT_MS, readSession } from "../ui/session";

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
		verify.mockResolvedValue({ data: { access_token: "access-token-aal2" }, error: null });
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

	afterEach(cleanup);

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
		expect(invoke).toHaveBeenCalledWith("identity-security", { body: { action: "status" } });

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

	it("withholds managed screens when the control plane report cannot be trusted", async () => {
		invoke.mockResolvedValue({ data: { ok: true }, error: null });

		renderManagedSurface();

		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/Access is withheld/));
		expect(screen.queryByText("Managed console")).not.toBeInTheDocument();
		expect(challenge).not.toHaveBeenCalled();
	});
});

describe("Dashboard session lifetime", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		localStorage.clear();
		signOut.mockResolvedValue({ error: null });
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
		expect(signOut).toHaveBeenCalled();
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
