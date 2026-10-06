// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SamlPolicyPanel } from "../ui/pages/SamlPolicyPanel";

const fixture = vi.hoisted(() => ({ invoke: vi.fn(), gate: vi.fn() }));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: fixture.invoke } } }));
vi.mock("../enterprise/auth", () => ({
	EnterpriseAuth: ({ children, ...props }: { children: ReactNode }) => {
		fixture.gate(props);
		return children;
	},
}));

const TENANT = "11111111-1111-4111-8111-111111111111";
const REQUESTER = "22222222-2222-4222-8222-222222222222";
const APPROVER = "33333333-3333-4333-8333-333333333333";
const PROVIDER = "44444444-4444-4444-8444-444444444444";
const REQUEST = "55555555-5555-4555-8555-555555555555";
const CREATED = "2026-10-05T20:00:00.000Z";
const EXPIRES = "2026-10-05T20:05:00.000Z";

function status(providerId: string | null = null) {
	return {
		ok: true,
		tenant_id: TENANT,
		role: "owner",
		current_assurance: "aal2",
		access_allowed: true,
		required_saml_provider_id: providerId,
	};
}
function request(overrides: Record<string, unknown> = {}) {
	return {
		request_id: REQUEST,
		tenant_id: TENANT,
		requested_by: REQUESTER,
		old_provider_id: null,
		new_provider_id: PROVIDER,
		reason: "Approved SAML cutover",
		change_ref: "CHG-123",
		created_at: CREATED,
		expires_at: EXPIRES,
		approved_by: null,
		approved_at: null,
		...overrides,
	};
}
function renderPanel(userId = REQUESTER) {
	return render(<SamlPolicyPanel tenantId={TENANT} currentUserId={userId} />);
}
function fillChange() {
	fireEvent.change(screen.getByLabelText("SAML provider ID"), { target: { value: PROVIDER } });
	fireEvent.change(screen.getByLabelText("Change reason"), {
		target: { value: "Approved SAML cutover" },
	});
	fireEvent.change(screen.getByLabelText("Change reference"), { target: { value: "CHG-123" } });
}
async function review() {
	fireEvent.change(screen.getByLabelText("Change request ID"), { target: { value: REQUEST } });
	fireEvent.click(screen.getByRole("button", { name: "Review request" }));
	return screen.findByRole("region", { name: "SAML change review" });
}
beforeEach(() => {
	vi.clearAllMocks();
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(new Date(CREATED));
	fixture.invoke.mockImplementation(
		async (_name: string, options: { body: { action: string } }) => ({
			data: options.body.action === "status" ? status() : { ok: true, request: request() },
			error: null,
		}),
	);
});
afterEach(() => {
	cleanup();
	vi.useRealTimers();
});

describe("SAML two-owner policy change", () => {
	it("uses the existing tenant MFA gate and creates an immutable request without applying the policy", async () => {
		renderPanel();
		await screen.findByText("Off", { selector: "strong" });
		expect(fixture.gate).toHaveBeenCalledWith({ tenantId: TENANT, forceMfa: true });
		fillChange();
		fireEvent.click(screen.getByRole("button", { name: "Request enabling SAML" }));
		const region = await screen.findByRole("region", { name: "SAML change review" });
		expect(fixture.invoke).toHaveBeenCalledWith("identity-security", {
			method: "POST",
			body: {
				action: "request_saml_policy_change",
				tenant_id: TENANT,
				new_provider_id: PROVIDER,
				reason: "Approved SAML cutover",
				change_ref: "CHG-123",
			},
		});
		expect(
			within(region).getByRole("button", { name: "Approve as a second owner" }),
		).toBeDisabled();
		expect(screen.getByText(/Request created. SAML enforcement is unchanged/)).toBeInTheDocument();
		expect(screen.getByLabelText("Change request ID")).toHaveValue(REQUEST);
	});

	it("lets a different owner review exact metadata and approve only the request ID", async () => {
		let applied = false;
		fixture.invoke.mockImplementation(
			async (_name: string, options: { body: { action: string } }) => {
				if (options.body.action === "status")
					return { data: status(applied ? PROVIDER : null), error: null };
				if (options.body.action === "approve_saml_policy_change") {
					applied = true;
					return {
						data: { ok: true, request: request({ approved_by: APPROVER, approved_at: CREATED }) },
						error: null,
					};
				}
				return { data: { ok: true, request: request() }, error: null };
			},
		);
		renderPanel(APPROVER);
		const region = await review();
		expect(within(region).getByText("Approved SAML cutover")).toBeInTheDocument();
		expect(within(region).getByText("CHG-123")).toBeInTheDocument();
		fireEvent.click(within(region).getByRole("button", { name: "Approve as a second owner" }));
		await screen.findByText(`Approved by ${APPROVER}. The policy change was applied.`);
		expect(fixture.invoke).toHaveBeenCalledWith("identity-security", {
			method: "POST",
			body: { action: "approve_saml_policy_change", tenant_id: TENANT, request_id: REQUEST },
		});
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Request disabling SAML" })).toBeEnabled(),
		);
	});

	it("requests a two-owner rollback to Off and explains that direct provider replacement is unsupported", async () => {
		fixture.invoke.mockImplementation(
			async (_name: string, options: { body: { action: string } }) => ({
				data:
					options.body.action === "status"
						? status(PROVIDER)
						: {
								ok: true,
								request: request({
									old_provider_id: PROVIDER,
									new_provider_id: null,
									reason: "Approved SAML rollback",
									change_ref: "CHG-124",
								}),
							},
				error: null,
			}),
		);
		renderPanel();
		await waitFor(() =>
			expect(screen.getByRole("button", { name: "Request disabling SAML" })).toBeEnabled(),
		);
		expect(screen.queryByLabelText("SAML provider ID")).not.toBeInTheDocument();
		expect(screen.getByText(/To replace a provider, first disable/)).toBeInTheDocument();
		fireEvent.change(screen.getByLabelText("Change reason"), {
			target: { value: "Approved SAML rollback" },
		});
		fireEvent.change(screen.getByLabelText("Change reference"), { target: { value: "CHG-124" } });
		fireEvent.click(screen.getByRole("button", { name: "Request disabling SAML" }));
		await screen.findByRole("region", { name: "SAML change review" });
		expect(fixture.invoke).toHaveBeenCalledWith("identity-security", {
			method: "POST",
			body: {
				action: "request_saml_policy_change",
				tenant_id: TENANT,
				new_provider_id: null,
				reason: "Approved SAML rollback",
				change_ref: "CHG-124",
			},
		});
	});

	it("does not report an applied policy when approval is outside the immutable request lifetime", async () => {
		for (const approvedAt of ["2026-10-05T19:59:59.999Z", EXPIRES]) {
			fixture.invoke.mockImplementation(
				async (_name: string, options: { body: { action: string } }) => ({
					data:
						options.body.action === "status"
							? status()
							: {
									ok: true,
									request: request(
										options.body.action === "approve_saml_policy_change"
											? { approved_by: APPROVER, approved_at: approvedAt }
											: {},
									),
								},
					error: null,
				}),
			);
			const view = renderPanel(APPROVER);
			const region = await review();
			fireEvent.click(within(region).getByRole("button", { name: "Approve as a second owner" }));
			expect(await screen.findByRole("alert")).toHaveTextContent("invalid change request");
			expect(screen.queryByText(/The policy change was applied/)).not.toBeInTheDocument();
			expect(screen.queryByText(/SAML enforcement was updated/)).not.toBeInTheDocument();
			view.unmount();
		}
	});

	it("withholds approval for another tenant, malformed metadata, and an expired request", async () => {
		for (const overrides of [
			{ tenant_id: APPROVER },
			{ expires_at: "2026-10-05T20:10:00.000Z" },
			{ approved_by: REQUESTER, approved_at: CREATED },
		]) {
			fixture.invoke.mockImplementation(
				async (_name: string, options: { body: { action: string } }) => ({
					data:
						options.body.action === "status" ? status() : { ok: true, request: request(overrides) },
					error: null,
				}),
			);
			const view = renderPanel(APPROVER);
			fireEvent.change(screen.getByLabelText("Change request ID"), { target: { value: REQUEST } });
			fireEvent.click(screen.getByRole("button", { name: "Review request" }));
			expect(await screen.findByRole("alert")).toHaveTextContent("invalid change request");
			expect(
				screen.queryByRole("button", { name: "Approve as a second owner" }),
			).not.toBeInTheDocument();
			view.unmount();
		}
		vi.setSystemTime(new Date(EXPIRES));
		fixture.invoke.mockImplementation(
			async (_name: string, options: { body: { action: string } }) => ({
				data: options.body.action === "status" ? status() : { ok: true, request: request() },
				error: null,
			}),
		);
		renderPanel(APPROVER);
		const region = await review();
		expect(
			within(region).getByRole("button", { name: "Approve as a second owner" }),
		).toBeDisabled();
		expect(region).toHaveTextContent("This request expired");
	});

	it("disables approval at the deadline without refreshing and clears reviewed metadata when the ID changes", async () => {
		const shortlyExpires = new Date(Date.parse(CREATED) + 100).toISOString();
		fixture.invoke.mockImplementation(
			async (_name: string, options: { body: { action: string } }) => ({
				data:
					options.body.action === "status"
						? status()
						: { ok: true, request: request({ expires_at: shortlyExpires }) },
				error: null,
			}),
		);
		renderPanel(APPROVER);
		const region = await review();
		expect(within(region).getByRole("button", { name: "Approve as a second owner" })).toBeEnabled();
		vi.setSystemTime(new Date(Date.parse(shortlyExpires) + 1));
		await waitFor(() =>
			expect(
				within(region).getByRole("button", { name: "Approve as a second owner" }),
			).toBeDisabled(),
		);
		fireEvent.click(within(region).getByRole("button", { name: "Approve as a second owner" }));
		expect(
			within(region).getByRole("button", { name: "Approve as a second owner" }),
		).toBeDisabled();
		expect(
			fixture.invoke.mock.calls.some(
				([, options]) => options.body.action === "approve_saml_policy_change",
			),
		).toBe(false);
		fireEvent.change(screen.getByLabelText("Change request ID"), { target: { value: PROVIDER } });
		expect(screen.queryByRole("region", { name: "SAML change review" })).not.toBeInTheDocument();
	});

	it("fails closed for old status responses and safely explains provider-session rejection", async () => {
		fixture.invoke.mockResolvedValue({
			data: { ...status(), required_saml_provider_id: undefined },
			error: null,
		});
		const view = renderPanel();
		expect(await screen.findByRole("alert")).toHaveTextContent("Changes are disabled");
		expect(screen.getByRole("button", { name: "Request enabling SAML" })).toBeDisabled();
		view.unmount();
		fixture.invoke.mockImplementation(
			async (_name: string, options: { body: { action: string } }) =>
				options.body.action === "status"
					? { data: status(), error: null }
					: {
							data: null,
							error: {
								context: new Response(
									JSON.stringify({
										error: "saml_policy_provider_session_required",
										message: "private implementation detail",
									}),
									{ status: 403 },
								),
							},
						},
		);
		renderPanel();
		await screen.findByText("Off", { selector: "strong" });
		fillChange();
		fireEvent.click(screen.getByRole("button", { name: "Request enabling SAML" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("Sign in through the SAML provider");
		expect(screen.queryByText("private implementation detail")).not.toBeInTheDocument();
	});
});
