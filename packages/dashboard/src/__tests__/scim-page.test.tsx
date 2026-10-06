// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScimPage } from "../ui/pages/ScimPage";

const fixture = vi.hoisted(() => ({ role: "owner", invoke: vi.fn() }));
vi.mock("../enterprise/team-provider", () => ({
	useTeam: () => ({
		currentTeam: { id: "team-id", tenant_id: "tenant-id", name: "Finance" },
		currentRole: fixture.role,
	}),
}));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: fixture.invoke } } }));
vi.mock("../ui/pages/SamlPolicyPanel", () => ({ SamlPolicyPanel: () => null }));

const TOKEN_ID = "11111111-1111-4111-8111-111111111111";
const OLD_TOKEN_ID = "22222222-2222-4222-8222-222222222222";
const CREATED_AT = "2026-09-24T00:00:00.000Z";
const EXPIRY = "2026-12-23T00:00:00.000Z";
const SECRET = `aidr_scim_${"A".repeat(43)}`;

function snapshot(overrides: Record<string, unknown> = {}) {
	return {
		ok: true,
		tokens: [],
		group_role_mappings: [],
		next_token_cursor: null,
		next_mapping_cursor: null,
		...overrides,
	};
}

beforeEach(() => {
	vi.clearAllMocks();
	fixture.role = "owner";
	fixture.invoke.mockResolvedValue({ data: snapshot(), error: null });
});
afterEach(cleanup);

describe("SCIM dashboard customer workflow", () => {
	it("creates, masks, reveals and clears a one-time secret and sends the canonical tenant ID", async () => {
		fixture.invoke.mockImplementation(
			async (name: string, options?: { method?: string; body?: Record<string, unknown> }) => {
				if (name === "scim-admin" && options?.method === "POST")
					return {
						data: { ok: true, token_id: TOKEN_ID, scim_token: SECRET, expires_at: EXPIRY },
						error: null,
					};
				return { data: snapshot(), error: null };
			},
		);
		render(<ScimPage />);
		await screen.findByText("No SCIM credentials have been issued.");
		expect(fixture.invoke).toHaveBeenCalledWith("scim-admin", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": "tenant-id" },
		});
		fireEvent.change(screen.getByLabelText("Credential label"), {
			target: { value: "Entra production" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create credential" }));
		const secretInput = await screen.findByLabelText("New SCIM credential");
		expect(secretInput).toHaveAttribute("type", "password");
		expect(secretInput).not.toHaveValue(SECRET);
		expect(screen.getByText(/Shown once/)).toBeInTheDocument();
		expect(fixture.invoke).toHaveBeenCalledWith("scim-admin", {
			method: "POST",
			headers: { "X-AIDR-Tenant-ID": "tenant-id" },
			body: { action: "create_token", label: "Entra production", tenant_id: "tenant-id" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Reveal" }));
		expect(secretInput).toHaveValue(SECRET);
		fireEvent.click(screen.getByRole("button", { name: "Clear secret" }));
		expect(screen.queryByLabelText("New SCIM credential")).not.toBeInTheDocument();
	});

	it("rotates with overlap and requires confirmation before permanent revocation", async () => {
		fixture.invoke.mockImplementation(
			async (name: string, options?: { method?: string; body?: Record<string, unknown> }) => {
				if (name === "scim-admin" && options?.method === "POST")
					return options.body?.action === "revoke_token"
						? { data: { ok: true }, error: null }
						: {
								data: { ok: true, token_id: TOKEN_ID, scim_token: SECRET, expires_at: EXPIRY },
								error: null,
							};
				return {
					data: snapshot({
						tokens: [
							{
								id: OLD_TOKEN_ID,
								label: "Entra",
								rotated_from: null,
								created_at: CREATED_AT,
								expires_at: EXPIRY,
								revoked_at: null,
								last_used_at: null,
							},
						],
					}),
					error: null,
				};
			},
		);
		render(<ScimPage />);
		const row = await screen.findByRole("row", { name: /Entra Active/ });
		fireEvent.click(within(row).getByRole("button", { name: "Rotate" }));
		await screen.findByLabelText("New SCIM credential");
		expect(fixture.invoke).toHaveBeenCalledWith("scim-admin", {
			method: "POST",
			headers: { "X-AIDR-Tenant-ID": "tenant-id" },
			body: {
				action: "rotate_token",
				token_id: OLD_TOKEN_ID,
				label: "Entra rotation",
				tenant_id: "tenant-id",
			},
		});
		fireEvent.click(within(row).getByRole("button", { name: "Revoke" }));
		expect(within(row).getByText("Revoke permanently?")).toBeInTheDocument();
		expect(
			fixture.invoke.mock.calls.filter(
				([name, options]) => name === "scim-admin" && options?.method === "POST",
			),
		).toHaveLength(1);
		fireEvent.click(within(row).getByRole("button", { name: "Confirm revoke" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("scim-admin", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": "tenant-id" },
				body: { action: "revoke_token", token_id: OLD_TOKEN_ID, tenant_id: "tenant-id" },
			}),
		);
	});

	it("refreshes and warns before retrying when credential creation has an ambiguous network result", async () => {
		let reads = 0;
		fixture.invoke.mockImplementation(async (name: string, options?: { method?: string }) => {
			if (name === "scim-admin" && options?.method === "POST")
				return { data: null, error: new Error("network disconnected") };
			reads += 1;
			return {
				data: snapshot({
					tokens:
						reads > 1
							? [
									{
										id: TOKEN_ID,
										label: "Entra uncertain",
										rotated_from: null,
										created_at: CREATED_AT,
										expires_at: EXPIRY,
										revoked_at: null,
										last_used_at: null,
									},
								]
							: [],
				}),
				error: null,
			};
		});
		render(<ScimPage />);
		await screen.findByText("No SCIM credentials have been issued.");
		fireEvent.change(screen.getByLabelText("Credential label"), {
			target: { value: "Entra uncertain" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create credential" }));

		await screen.findByRole("row", { name: /Entra uncertain Active/ });
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"If a new active credential is listed but its secret was not shown, revoke it before retrying.",
		);
		expect(screen.getByLabelText("Credential label")).toHaveValue("");
	});

	it("does not label a definite rejection as an ambiguous credential write", async () => {
		fixture.invoke.mockImplementation(async (name: string, options?: { method?: string }) => {
			if (name === "scim-admin" && options?.method === "POST")
				return {
					data: null,
					error: Object.assign(new Error("request rejected"), {
						context: new Response(JSON.stringify({ error: "invalid_request" }), { status: 400 }),
					}),
				};
			return { data: snapshot(), error: null };
		});
		render(<ScimPage />);
		await screen.findByText("No SCIM credentials have been issued.");
		fireEvent.change(screen.getByLabelText("Credential label"), {
			target: { value: "Entra production" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create credential" }));

		const alert = await screen.findByRole("alert");
		expect(alert).toHaveTextContent("The request was rejected.");
		expect(alert).not.toHaveTextContent("may have reached AIDR");
		expect(
			fixture.invoke.mock.calls.filter(
				([name, options]) => name === "scim-admin" && options?.method === "GET",
			),
		).toHaveLength(1);
	});

	it("maps the exact external ID, rejects whitespace locally, edits and confirms removal", async () => {
		const externalId = "directory-group-immutable-id";
		fixture.invoke.mockImplementation(
			async (name: string, options?: { method?: string; body?: Record<string, unknown> }) => {
				if (name === "scim-admin" && options?.method === "POST")
					return { data: { ok: true, changed: true }, error: null };
				return {
					data: snapshot({
						group_role_mappings: [
							{
								external_group_id: externalId,
								role: "viewer",
								created_by: null,
								created_at: CREATED_AT,
							},
						],
					}),
					error: null,
				};
			},
		);
		render(<ScimPage />);
		await screen.findByRole("row", { name: /directory-group-immutable-id viewer/ });
		fireEvent.change(screen.getByLabelText("Exact external group ID"), {
			target: { value: " directory-group-immutable-id " },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save mapping" }));
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"exact immutable SCIM Group.externalId",
		);
		expect(
			fixture.invoke.mock.calls.some(
				([name, options]) => name === "scim-admin" && options?.method === "POST",
			),
		).toBe(false);
		fireEvent.click(screen.getByRole("button", { name: "Clear" }));
		fireEvent.change(screen.getByLabelText("Exact external group ID"), {
			target: { value: externalId },
		});
		fireEvent.change(screen.getByLabelText("AIDR role"), { target: { value: "admin" } });
		fireEvent.click(screen.getByRole("button", { name: "Save mapping" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("scim-admin", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": "tenant-id" },
				body: {
					action: "set_group_mapping",
					external_group_id: externalId,
					role: "admin",
					tenant_id: "tenant-id",
				},
			}),
		);
		const row = screen.getByRole("row", { name: /directory-group-immutable-id viewer/ });
		fireEvent.click(within(row).getByRole("button", { name: "Edit" }));
		expect(screen.getByLabelText("Exact external group ID")).toHaveValue(externalId);
		expect(screen.getByLabelText("AIDR role")).toHaveValue("viewer");
		fireEvent.click(within(row).getByRole("button", { name: "Remove" }));
		fireEvent.click(within(row).getByRole("button", { name: "Confirm remove" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("scim-admin", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": "tenant-id" },
				body: {
					action: "remove_group_mapping",
					external_group_id: externalId,
					tenant_id: "tenant-id",
				},
			}),
		);
	});

	it("uses each independent keyset cursor and hides the API for non-owner roles", async () => {
		fixture.invoke.mockImplementation(async (name: string) => {
			if (name.includes("token_after_created_at")) return { data: snapshot(), error: null };
			return {
				data: snapshot({
					next_token_cursor: { id: TOKEN_ID, created_at: CREATED_AT },
					next_mapping_cursor: "external-group-1",
				}),
				error: null,
			};
		});
		const view = render(<ScimPage />);
		await screen.findByRole("button", { name: "Load more" });
		fireEvent.click(screen.getByRole("button", { name: "Load more" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith(
				`scim-admin?token_after_created_at=${encodeURIComponent(CREATED_AT)}&token_after_id=${TOKEN_ID}&mapping_after_external_group_id=external-group-1`,
				{ method: "GET", headers: { "X-AIDR-Tenant-ID": "tenant-id" } },
			),
		);
		view.unmount();
		fixture.invoke.mockClear();
		fixture.role = "admin";
		render(<ScimPage />);
		expect(screen.getByRole("heading", { name: "Directory provisioning" })).toBeInTheDocument();
		expect(screen.getByText(/active tenant owners only/)).toBeInTheDocument();
		expect(fixture.invoke).not.toHaveBeenCalled();
	});

	it("clears a one-time secret and directory data when owner access is lost", async () => {
		fixture.invoke.mockImplementation(async (name: string, options?: { method?: string }) =>
			name === "scim-admin" && options?.method === "POST"
				? {
						data: { ok: true, token_id: TOKEN_ID, scim_token: SECRET, expires_at: EXPIRY },
						error: null,
					}
				: { data: snapshot(), error: null },
		);
		const view = render(<ScimPage />);
		await screen.findByText("No SCIM credentials have been issued.");
		fireEvent.change(screen.getByLabelText("Credential label"), {
			target: { value: "Temporary owner secret" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create credential" }));
		await screen.findByLabelText("New SCIM credential");

		fixture.role = "admin";
		view.rerender(<ScimPage />);
		await waitFor(() =>
			expect(screen.queryByLabelText("New SCIM credential")).not.toBeInTheDocument(),
		);
		expect(screen.getByText(/active tenant owners only/)).toBeInTheDocument();

		fixture.role = "owner";
		view.rerender(<ScimPage />);
		await screen.findByText("No SCIM credentials have been issued.");
		expect(screen.queryByLabelText("New SCIM credential")).not.toBeInTheDocument();
	});
});
