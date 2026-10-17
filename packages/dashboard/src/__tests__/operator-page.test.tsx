// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OperatorPage } from "../ui/pages/OperatorPage";
import { ThemeProvider } from "../ui/ThemeProvider";

const TOKEN = "operator-access-token";
const TENANT_A = "33333333-3333-4333-8333-333333333333";
const TENANT_B = "44444444-4444-4444-8444-444444444444";
const OWNER = "22222222-2222-4222-8222-222222222222";

const fixture = vi.hoisted(() => ({
	invoke: vi.fn(),
	listFactors: vi.fn(),
	challenge: vi.fn(),
	verify: vi.fn(),
	enroll: vi.fn(),
	refresh: vi.fn(async () => undefined),
	session: {
		access_token: "operator-access-token",
		user: { id: "11111111-1111-4111-8111-111111111111" },
	} as { access_token: string; user: { id: string } } | null,
}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		functions: { invoke: fixture.invoke },
		auth: {
			mfa: {
				listFactors: fixture.listFactors,
				challenge: fixture.challenge,
				verify: fixture.verify,
				enroll: fixture.enroll,
			},
		},
	},
}));
vi.mock("../ui/use-session", () => ({
	useSessionSnapshot: () => ({
		snapshot: {
			status: { state: fixture.session ? "active" : "signed_out" },
			session: fixture.session,
		},
		generation: 1,
		refresh: fixture.refresh,
		isCurrent: () => true,
	}),
}));

/** Mirrors supabase-js FunctionsHttpError: the Response is on `context`. */
function httpError(status: number, error: string) {
	return {
		data: null,
		error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
			context: new Response(JSON.stringify({ error }), { status }),
		}),
	};
}

const tenantA = {
	id: TENANT_A,
	name: "Acme Corp",
	kind: "organization",
	status: "active",
	created_at: "2026-01-01T00:00:00.000Z",
	admission: {
		kind: "licensed",
		plan_id: "business",
		seats: 30,
		expires_at: "2027-09-30T23:59:59.000Z",
		active: true,
	},
};
const tenantB = {
	id: TENANT_B,
	name: null,
	kind: "personal",
	status: "active",
	created_at: "2026-02-01T00:00:00.000Z",
	admission: null,
};
const ok = (action: string, result: unknown) => ({
	data: { ok: true, action, result },
	error: null,
});
const usage = (tenantId: string) =>
	ok("tenant_usage", {
		tenant: {
			id: tenantId,
			kind: "organization",
			status: "active",
			created_at: "2026-01-01T00:00:00.000Z",
		},
		admission_mode: "cloud",
		admission: {
			kind: "licensed",
			plan_id: "business",
			seats: 30,
			starts_at: "2026-01-01T00:00:00.000Z",
			expires_at: "2027-09-30T23:59:59.000Z",
			revoked_at: null,
			active: true,
		},
		allowed_agents: 30,
		agents: { enrolled: 12, active_7d: 9 },
		members: 4,
	});

type Body = Record<string, unknown>;
function serve(overrides: Partial<Record<string, (body: Body) => unknown>> = {}) {
	fixture.invoke.mockImplementation(async (_name: string, options: { body: Body }) => {
		const handler = overrides[options.body.action as string];
		if (handler) return handler(options.body);
		switch (options.body.action) {
			case "list_tenants":
				return options.body.after
					? ok("list_tenants", { tenants: [tenantB], next_cursor: null })
					: ok("list_tenants", { tenants: [tenantA], next_cursor: TENANT_A });
			case "tenant_usage":
				return usage(options.body.tenant_id as string);
			case "grant_license":
				return ok("grant_license", {
					status: "granted",
					tenant_id: options.body.tenant_id,
					plan_id: options.body.plan_id,
				});
			case "revoke_license":
				return ok("revoke_license", { status: "revoked", tenant_id: options.body.tenant_id });
		}
		throw new Error(`unexpected action ${String(options.body.action)}`);
	});
}

function bodies(action: string): Body[] {
	return fixture.invoke.mock.calls
		.map(([, options]) => (options as { body: Body }).body)
		.filter((body) => body.action === action);
}

function renderPage() {
	return render(
		<ThemeProvider>
			<MemoryRouter initialEntries={["/operator"]}>
				<OperatorPage />
			</MemoryRouter>
		</ThemeProvider>,
	);
}

async function openTenant() {
	fireEvent.click(await screen.findByRole("button", { name: "Manage Acme Corp" }));
	await screen.findByText("Agents enrolled");
}

beforeEach(() => {
	vi.clearAllMocks();
	fixture.session = { access_token: TOKEN, user: { id: "11111111-1111-4111-8111-111111111111" } };
	serve();
});
afterEach(cleanup);

describe("operator console access", () => {
	it("shows a 403 state to a non-operator and renders no tenant data", async () => {
		fixture.invoke.mockResolvedValue(httpError(403, "forbidden"));
		renderPage();
		expect(
			await screen.findByRole("heading", { name: "Operator access required" }),
		).toBeInTheDocument();
		expect(screen.getByText(/403/)).toBeInTheDocument();
		expect(screen.queryByRole("table")).not.toBeInTheDocument();
		expect(fixture.invoke).toHaveBeenCalledTimes(1);
		expect(fixture.listFactors).not.toHaveBeenCalled();
	});

	it("leaves the checking state under StrictMode's development remount", async () => {
		fixture.invoke.mockResolvedValue(httpError(403, "forbidden"));
		render(
			<StrictMode>
				<ThemeProvider>
					<MemoryRouter initialEntries={["/operator"]}>
						<OperatorPage />
					</MemoryRouter>
				</ThemeProvider>
			</StrictMode>,
		);
		expect(
			await screen.findByRole("heading", { name: "Operator access required" }),
		).toBeInTheDocument();
	});

	it("asks the server, with the session token, instead of trusting any client flag", async () => {
		renderPage();
		await screen.findByRole("table");
		expect(fixture.invoke).toHaveBeenCalledWith("operator-admin", {
			body: { action: "list_tenants", limit: 25 },
			headers: { Authorization: `Bearer ${TOKEN}` },
		});
	});

	it("prompts an AAL1 operator to step up and verifies against the enrolled TOTP factor", async () => {
		fixture.invoke.mockResolvedValue(httpError(403, "mfa_required"));
		fixture.listFactors.mockResolvedValue({
			data: { totp: [{ id: "factor-1", status: "verified", factor_type: "totp" }], all: [] },
			error: null,
		});
		fixture.challenge.mockResolvedValue({ data: { id: "challenge-1" }, error: null });
		fixture.verify.mockResolvedValue({ data: {}, error: null });
		renderPage();
		expect(
			await screen.findByRole("heading", { name: "Multi-factor authentication required" }),
		).toBeInTheDocument();
		expect(screen.queryByRole("table")).not.toBeInTheDocument();

		fireEvent.change(await screen.findByLabelText("Authenticator code"), {
			target: { value: "123456" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));
		await waitFor(() =>
			expect(fixture.verify).toHaveBeenCalledWith({
				factorId: "factor-1",
				challengeId: "challenge-1",
				code: "123456",
			}),
		);
		expect(fixture.challenge).toHaveBeenCalledWith({ factorId: "factor-1" });
		// The token rotation is picked up by refreshing the session; the console
		// is reopened only by a fresh server check, never by the verify result.
		await waitFor(() => expect(fixture.refresh).toHaveBeenCalledTimes(1));
	});

	it("offers enrollment when the operator has no verified factor", async () => {
		fixture.invoke.mockResolvedValue(httpError(403, "mfa_required"));
		fixture.listFactors.mockResolvedValue({ data: { totp: [], all: [] }, error: null });
		fixture.enroll.mockResolvedValue({
			data: { id: "new-factor", type: "totp", totp: { secret: "SECRET", uri: "otpauth://totp/x" } },
			error: null,
		});
		renderPage();
		fireEvent.click(await screen.findByRole("button", { name: "Set up authenticator app" }));
		expect(await screen.findByText("SECRET")).toBeInTheDocument();
		expect(fixture.enroll).toHaveBeenCalledWith({
			factorType: "totp",
			friendlyName: "AIDR operator console",
		});
		expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument();
	});

	it("shows an honest unavailable state on a service failure and a malformed list", async () => {
		fixture.invoke.mockResolvedValueOnce(httpError(503, "authorization_unavailable"));
		renderPage();
		expect(
			await screen.findByRole("heading", { name: "Operator service unavailable" }),
		).toBeInTheDocument();
		expect(screen.getByText(/Operator authorization could not be checked/)).toBeInTheDocument();

		fixture.invoke.mockResolvedValueOnce(
			ok("list_tenants", { tenants: [{ id: "not-a-uuid" }], next_cursor: null }),
		);
		fireEvent.click(screen.getByRole("button", { name: "Retry" }));
		expect(await screen.findByText(/unexpected tenant list/)).toBeInTheDocument();
		expect(screen.queryByRole("table")).not.toBeInTheDocument();
	});

	it("does not render the console for a signed-out visitor or call the service", async () => {
		fixture.session = null;
		renderPage();
		expect(screen.getByRole("heading", { name: "Sign in required" })).toBeInTheDocument();
		expect(fixture.invoke).not.toHaveBeenCalled();
	});
});

describe("operator console tenants and actions", () => {
	it("lists licences and pages with the server's keyset cursor", async () => {
		renderPage();
		const table = await screen.findByRole("table");
		expect(within(table).getByText("Acme Corp")).toBeInTheDocument();
		expect(within(table).getByText("business")).toBeInTheDocument();
		expect(within(table).getByText("Active")).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Next page" }));
		expect(await screen.findByText("Personal workspace (name withheld)")).toBeInTheDocument();
		expect(bodies("list_tenants").at(-1)).toEqual({
			action: "list_tenants",
			limit: 25,
			after: TENANT_A,
		});
		expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();

		fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
		expect(await screen.findByText("Acme Corp")).toBeInTheDocument();
		expect(bodies("list_tenants").at(-1)).toEqual({ action: "list_tenants", limit: 25 });
	});

	it("reads usage and seats for the selected tenant", async () => {
		renderPage();
		await openTenant();
		expect(bodies("tenant_usage")).toEqual([{ action: "tenant_usage", tenant_id: TENANT_A }]);
		expect(screen.getByText("12")).toBeInTheDocument();
		expect(screen.getByText("cloud")).toBeInTheDocument();
	});

	it("requires a review step, then grants with the exact payload", async () => {
		renderPage();
		await openTenant();
		fireEvent.change(screen.getByLabelText("Plan id"), { target: { value: "enterprise" } });
		fireEvent.change(screen.getByLabelText("Seats"), { target: { value: "50" } });
		fireEvent.change(screen.getByLabelText("Expiry date (ends 23:59:59 UTC)"), {
			target: { value: "2099-12-31" },
		});
		fireEvent.change(screen.getByLabelText("Contract reference"), { target: { value: " PO-77 " } });
		fireEvent.change(screen.getByLabelText("Owner user id (optional)"), {
			target: { value: OWNER },
		});
		fireEvent.click(screen.getByRole("button", { name: "Review grant" }));
		expect(bodies("grant_license")).toHaveLength(0);

		fireEvent.click(await screen.findByRole("button", { name: "Confirm grant" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("operator-admin", {
				body: {
					action: "grant_license",
					tenant_id: TENANT_A,
					plan_id: "enterprise",
					seats: 50,
					expires_at: "2099-12-31T23:59:59.000Z",
					reference: "PO-77",
					owner_user_id: OWNER,
				},
				headers: { Authorization: `Bearer ${TOKEN}` },
			}),
		);
		expect(await screen.findByText(/Licence granted: enterprise, 50 seats/)).toBeInTheDocument();
	});

	it("rejects invalid grant input locally without calling the service", async () => {
		renderPage();
		await openTenant();
		fireEvent.change(screen.getByLabelText("Seats"), { target: { value: "0" } });
		fireEvent.change(screen.getByLabelText("Expiry date (ends 23:59:59 UTC)"), {
			target: { value: "2099-12-31" },
		});
		fireEvent.change(screen.getByLabelText("Contract reference"), { target: { value: "PO-1" } });
		fireEvent.click(screen.getByRole("button", { name: "Review grant" }));
		expect(await screen.findByText(/Seats must be a whole number/)).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Confirm grant" })).not.toBeInTheDocument();
		expect(bodies("grant_license")).toHaveLength(0);
	});

	it("maps a refused grant to its documented message", async () => {
		serve({ grant_license: () => httpError(403, "admission_operator_required") });
		renderPage();
		await openTenant();
		fireEvent.change(screen.getByLabelText("Expiry date (ends 23:59:59 UTC)"), {
			target: { value: "2099-12-31" },
		});
		fireEvent.change(screen.getByLabelText("Contract reference"), { target: { value: "PO-1" } });
		fireEvent.click(screen.getByRole("button", { name: "Review grant" }));
		fireEvent.click(await screen.findByRole("button", { name: "Confirm grant" }));
		expect(
			await screen.findByText(/You are not an admission operator for this tenant/),
		).toBeInTheDocument();
	});

	it("requires a confirming click before revoking, then sends the reason", async () => {
		renderPage();
		await openTenant();
		fireEvent.change(screen.getByLabelText("Revocation reason"), {
			target: { value: "contract ended" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Revoke licence" }));
		expect(bodies("revoke_license")).toHaveLength(0);

		fireEvent.click(screen.getByRole("button", { name: "Confirm: revoke licence for Acme Corp" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("operator-admin", {
				body: { action: "revoke_license", tenant_id: TENANT_A, reason: "contract ended" },
				headers: { Authorization: `Bearer ${TOKEN}` },
			}),
		);
		expect(await screen.findByText("Licence revoked.")).toBeInTheDocument();
	});

	it("returns to the step-up prompt when an action reports mfa_required", async () => {
		serve({ revoke_license: () => httpError(403, "mfa_required") });
		fixture.listFactors.mockResolvedValue({ data: { totp: [], all: [] }, error: null });
		renderPage();
		await openTenant();
		fireEvent.change(screen.getByLabelText("Revocation reason"), {
			target: { value: "contract ended" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Revoke licence" }));
		fireEvent.click(screen.getByRole("button", { name: "Confirm: revoke licence for Acme Corp" }));
		expect(
			await screen.findByRole("heading", { name: "Multi-factor authentication required" }),
		).toBeInTheDocument();
		expect(screen.queryByRole("table")).not.toBeInTheDocument();
	});
});
