// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SettingsPage } from "../ui/pages/SettingsPage";
import { ThemeProvider } from "../ui/ThemeProvider";

const TENANT = "11111111-1111-4111-8111-111111111111";

const session = vi.hoisted(() => ({ getSession: vi.fn(), signOut: vi.fn() }));
const invoke = vi.hoisted(() => vi.fn());
const team = vi.hoisted(() => ({
	currentTeam: { id: "11111111-1111-4111-8111-111111111111", name: "Acme Security" } as {
		id: string;
		name: string;
	} | null,
	applyWorkspaceName: vi.fn(),
}));
vi.mock("../ui/session", () => session);
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke } }, supabaseEnvError: null }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => team }));

interface Fixture {
	role?: string;
	status?: string;
	retentionDays?: number;
	assurance?: "aal1" | "aal2";
	requireMfa?: boolean;
	loadError?: boolean;
	updateError?: string;
	closeError?: string;
}

function httpError(status: number, error: string) {
	return {
		data: null,
		error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
			context: new Response(JSON.stringify({ error }), { status }),
		}),
	};
}

interface InvokeOptions {
	method?: string;
	headers?: Record<string, string>;
	body?: Record<string, unknown>;
}

/** The tenant as the fake tenant-settings function currently stores it. */
interface FakeTenant {
	readonly role: string;
	readonly status: string;
	name: string;
	retentionDays: number;
}

function workspaceRow(tenant: FakeTenant) {
	return {
		id: TENANT,
		name: tenant.name,
		kind: "team",
		status: tenant.status,
		retention_days: tenant.retentionDays,
		created_at: "2026-01-01T00:00:00.000Z",
	};
}

function identitySecurityResponse(fixture: Fixture) {
	return {
		data: {
			ok: true,
			tenant_id: TENANT,
			current_assurance: fixture.assurance ?? "aal2",
			require_mfa: fixture.requireMfa ?? false,
		},
		error: null,
	};
}

function getSettingsResponse(fixture: Fixture, tenant: FakeTenant, options: InvokeOptions) {
	if (fixture.loadError) return httpError(503, "authorization_unavailable");
	expect(options.headers).toEqual({ "X-AIDR-Tenant-ID": TENANT });
	const active = tenant.status === "active";
	return {
		data: {
			ok: true,
			workspace: workspaceRow(tenant),
			role: tenant.role,
			permissions: {
				can_edit: active && (tenant.role === "owner" || tenant.role === "admin"),
				can_close: active && tenant.role === "owner",
				requires_aal2: true,
			},
			retention_bounds: { min: 1, max: 3650 },
		},
		error: null,
	};
}

function updateSettingsResponse(
	fixture: Fixture,
	tenant: FakeTenant,
	body: Record<string, unknown>,
) {
	if (fixture.updateError) return httpError(403, fixture.updateError);
	if (typeof body.name === "string") tenant.name = body.name;
	if (typeof body.retention_days === "number") tenant.retentionDays = body.retention_days;
	return { data: { ok: true, workspace: workspaceRow(tenant), changed: [] }, error: null };
}

function closeWorkspaceResponse(fixture: Fixture) {
	if (fixture.closeError) return httpError(400, fixture.closeError);
	return {
		data: {
			ok: true,
			closure: {
				run_id: "55555555-5555-4555-8555-555555555555",
				status: "requested",
				backup_scope: "excluded_external_retention",
				backup_exception: "Backup copies are excluded from this live-data receipt.",
			},
		},
		error: null,
	};
}

function tenantSettingsResponse(fixture: Fixture, tenant: FakeTenant, options: InvokeOptions) {
	if (options.method === "GET") return getSettingsResponse(fixture, tenant, options);
	if (options.body?.action === "update")
		return updateSettingsResponse(fixture, tenant, options.body);
	if (options.body?.action === "close") return closeWorkspaceResponse(fixture);
	throw new Error("unexpected tenant-settings request");
}

function install(fixture: Fixture = {}) {
	const tenant: FakeTenant = {
		role: fixture.role ?? "owner",
		status: fixture.status ?? "active",
		name: "Acme Security",
		retentionDays: fixture.retentionDays ?? 90,
	};
	invoke.mockImplementation(async (fn: string, options: InvokeOptions) => {
		if (fn === "identity-security") return identitySecurityResponse(fixture);
		if (fn !== "tenant-settings") throw new Error(`unexpected function ${fn}`);
		return tenantSettingsResponse(fixture, tenant, options);
	});
}

function patches() {
	return invoke.mock.calls
		.filter(([fn, options]) => fn === "tenant-settings" && options?.method === "PATCH")
		.map(([, options]) => options.body);
}

function renderSettings() {
	return render(
		<MemoryRouter initialEntries={["/settings"]}>
			<ThemeProvider>
				<Routes>
					<Route path="/settings" element={<SettingsPage />} />
					<Route path="/login" element={<h1>Sign in</h1>} />
				</Routes>
			</ThemeProvider>
		</MemoryRouter>,
	);
}

beforeEach(() => {
	vi.clearAllMocks();
	localStorage.clear();
	team.currentTeam = { id: TENANT, name: "Acme Security" };
	session.getSession.mockResolvedValue({ user: { email: "operator@example.test" } });
	session.signOut.mockResolvedValue({ serverRevoked: true });
	install();
});
afterEach(cleanup);

it("shows the account, persists appearance, exposes legal links and completes sign-out", async () => {
	renderSettings();
	expect(await screen.findByText("operator@example.test")).toBeInTheDocument();
	fireEvent.click(screen.getByRole("button", { name: "Dark" }));
	await waitFor(() => expect(localStorage.getItem("theme")).toBe("dark"));
	expect(document.documentElement).toHaveAttribute("data-theme", "dark");
	expect(screen.getByRole("link", { name: "Privacy notice" })).toHaveAttribute("href", "/privacy");
	expect(screen.getByRole("link", { name: "Security" })).toHaveAttribute("href", "/security");
	expect(screen.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");
	expect(screen.getByRole("link", { name: "Support" })).toHaveAttribute("href", "/support");
	fireEvent.click(screen.getByRole("button", { name: "Sign out of this session" }));
	expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
	expect(session.signOut).toHaveBeenCalledOnce();
});

it("hides settings while ending the session and reports unconfirmed server revocation on login", async () => {
	let finish!: (value: { serverRevoked: boolean }) => void;
	session.signOut.mockImplementation(
		() =>
			new Promise((resolve) => {
				finish = resolve;
			}),
	);
	function LoginLocation() {
		const location = useLocation();
		return <div>Login destination: {location.search}</div>;
	}
	render(
		<MemoryRouter initialEntries={["/settings"]}>
			<ThemeProvider>
				<Routes>
					<Route path="/settings" element={<SettingsPage />} />
					<Route path="/login" element={<LoginLocation />} />
				</Routes>
			</ThemeProvider>
		</MemoryRouter>,
	);
	fireEvent.click(await screen.findByRole("button", { name: "Sign out of this session" }));
	expect(screen.getByRole("status")).toHaveTextContent("Ending this browser session");
	expect(screen.queryByRole("heading", { name: "Settings" })).not.toBeInTheDocument();
	finish({ serverRevoked: false });
	expect(
		await screen.findByText("Login destination: ?signout=revocation-unconfirmed"),
	).toBeInTheDocument();
});

describe("workspace section", () => {
	it("renames the workspace only after the service confirms it", async () => {
		renderSettings();
		const input = await screen.findByLabelText("Workspace name");
		expect(input).toHaveValue("Acme Security");
		const save = screen.getByRole("button", { name: "Save workspace settings" });
		expect(save).toBeDisabled();
		fireEvent.change(input, { target: { value: "  Acme Platform " } });
		fireEvent.click(save);
		expect(await screen.findByText("Workspace settings saved.")).toBeInTheDocument();
		expect(patches()).toEqual([{ tenant_id: TENANT, action: "update", name: "Acme Platform" }]);
		expect(screen.getByTestId("workspace-name")).toHaveTextContent("Acme Platform");
		expect(team.applyWorkspaceName).toHaveBeenCalledWith(TENANT, "Acme Platform");
	});

	it("requires explicit confirmation before shortening retention", async () => {
		renderSettings();
		const retention = await screen.findByLabelText("Telemetry retention (days)");
		fireEvent.change(retention, { target: { value: "30" } });
		const save = screen.getByRole("button", { name: "Save workspace settings" });
		expect(save).toBeDisabled();
		const confirm = screen.getByRole("checkbox");
		expect(confirm.closest("label")).toHaveTextContent("from 90 to 30 days");
		fireEvent.click(confirm);
		fireEvent.click(save);
		expect(await screen.findByText("Workspace settings saved.")).toBeInTheDocument();
		expect(patches()).toEqual([
			{
				tenant_id: TENANT,
				action: "update",
				retention_days: 30,
				confirm_retention_reduction: true,
			},
		]);
		expect(screen.getByText("30 days")).toBeInTheDocument();
		expect(team.applyWorkspaceName).not.toHaveBeenCalled();
	});

	it("extends retention without a reduction prompt and rejects out-of-range values", async () => {
		renderSettings();
		const retention = await screen.findByLabelText("Telemetry retention (days)");
		const save = screen.getByRole("button", { name: "Save workspace settings" });
		for (const invalid of ["0", "3651", "12.5"]) {
			fireEvent.change(retention, { target: { value: invalid } });
			expect(save, invalid).toBeDisabled();
		}
		fireEvent.change(retention, { target: { value: "365" } });
		expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
		fireEvent.click(save);
		await screen.findByText("Workspace settings saved.");
		expect(patches()).toEqual([{ tenant_id: TENANT, action: "update", retention_days: 365 }]);
	});

	it("routes an AAL1 session to MFA verification when a change needs step-up", async () => {
		install({ updateError: "mfa_required" });
		renderSettings();
		fireEvent.change(await screen.findByLabelText("Workspace name"), {
			target: { value: "Renamed" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save workspace settings" }));
		const alert = await screen.findByRole("alert");
		expect(alert).toHaveTextContent("Multi-factor verification is required");
		expect(within(alert).getByRole("link", { name: "Verify with authenticator" })).toHaveAttribute(
			"href",
			`/auth/dlp-step-up?tenant=${TENANT}&return=settings`,
		);
		expect(screen.getByTestId("workspace-name")).toHaveTextContent("Acme Security");
		expect(team.applyWorkspaceName).not.toHaveBeenCalled();
	});

	it("is read-only for members and viewers", async () => {
		for (const role of ["member", "viewer"]) {
			install({ role });
			const view = renderSettings();
			expect(await screen.findByTestId("workspace-name")).toHaveTextContent("Acme Security");
			expect(
				screen.getByText("Only an owner or administrator can change workspace settings."),
			).toBeInTheDocument();
			expect(screen.queryByLabelText("Workspace name")).not.toBeInTheDocument();
			expect(screen.queryByRole("button", { name: "Close workspace" })).not.toBeInTheDocument();
			view.unmount();
		}
	});

	it("lets administrators edit but not close the workspace", async () => {
		install({ role: "admin" });
		renderSettings();
		expect(await screen.findByLabelText("Workspace name")).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Close workspace" })).not.toBeInTheDocument();
	});

	it("closes the workspace only after the owner types its exact name", async () => {
		renderSettings();
		const confirm = await screen.findByLabelText(/to confirm/);
		const close = screen.getByRole("button", { name: "Close workspace" });
		expect(close).toBeDisabled();
		fireEvent.change(confirm, { target: { value: "acme security" } });
		expect(close).toBeDisabled();
		fireEvent.change(confirm, { target: { value: "Acme Security" } });
		expect(close).toBeEnabled();
		fireEvent.click(close);
		expect(
			await screen.findByText(/Workspace closure requested \(offboarding status: requested\)/),
		).toBeInTheDocument();
		expect(patches()).toEqual([
			{ tenant_id: TENANT, action: "close", confirm_name: "Acme Security" },
		]);
		expect(screen.getByText("Closing (offboarding in progress)")).toBeInTheDocument();
		expect(screen.queryByLabelText("Workspace name")).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Close workspace" })).not.toBeInTheDocument();
	});

	it("reports a refused closure without claiming it happened", async () => {
		install({ closeError: "confirmation_mismatch" });
		renderSettings();
		fireEvent.change(await screen.findByLabelText(/to confirm/), {
			target: { value: "Acme Security" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Close workspace" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("does not match the workspace name");
		expect(screen.queryByText(/closure requested/)).not.toBeInTheDocument();
		expect(screen.getByText("Active")).toBeInTheDocument();
	});

	it("shows an unreadable workspace as an error, not as empty settings", async () => {
		install({ loadError: true });
		renderSettings();
		expect(await screen.findByRole("alert")).toHaveTextContent("did not confirm the request");
		expect(screen.queryByTestId("workspace-name")).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
	});

	it("omits the workspace section when no workspace is selected", async () => {
		team.currentTeam = null;
		renderSettings();
		expect(await screen.findByText("operator@example.test")).toBeInTheDocument();
		expect(screen.queryByRole("heading", { name: "Workspace" })).not.toBeInTheDocument();
		expect(invoke).not.toHaveBeenCalled();
	});
});

describe("profile section", () => {
	it("reports a verified AAL2 session", async () => {
		renderSettings();
		expect(await screen.findByTestId("mfa-status")).toHaveTextContent(
			"Verified for this session (AAL2).",
		);
		expect(invoke).toHaveBeenCalledWith("identity-security", {
			body: { action: "status", tenant_id: TENANT },
		});
	});

	it("links an AAL1 session to MFA setup and verification", async () => {
		install({ assurance: "aal1", requireMfa: true });
		renderSettings();
		const status = await screen.findByTestId("mfa-status");
		expect(status).toHaveTextContent(
			"Not verified for this session (AAL1). This workspace requires MFA.",
		);
		expect(within(status).getByRole("link", { name: "Set up or verify MFA" })).toHaveAttribute(
			"href",
			`/auth/dlp-step-up?tenant=${TENANT}&return=settings`,
		);
	});
});
