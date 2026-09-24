// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { supabase } from "../lib/supabase";
import { ApiKeysPage } from "../ui/pages/ApiKeysPage";

const team = vi.hoisted(() => ({ role: "owner" }));
vi.mock("../enterprise/team-provider", () => ({
	useTeam: () => ({ currentTeam: { id: "team-a", name: "Finance" }, currentRole: team.role }),
}));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));

const invoke = vi.mocked(supabase.functions.invoke);
const activeAdmission = {
	mode: "cloud",
	status: "active",
	access_kind: "trial",
	allowed_agents: 1,
	expires_at: "2099-01-01T00:00:00Z",
	trial_available: false,
};

beforeEach(() => {
	vi.clearAllMocks();
	team.role = "owner";
	window.history.replaceState({}, "", "/api-keys");
});
afterEach(cleanup);

describe("API key customer journey", () => {
	it("can refresh a workspace without admission into an active trial without reloading the page", async () => {
		let approved = false;
		invoke.mockImplementation(async (name) => ({
			error: null,
			data:
				name === "pilot-status"
					? {
							ok: true,
							status: "none",
							admission: approved
								? activeAdmission
								: { ...activeAdmission, status: "none", allowed_agents: 0 },
						}
					: name === "api-keys"
						? { ok: true, keys: [] }
						: { ok: true, tokens: [] },
		}));
		render(<ApiKeysPage />);
		await screen.findByText("none");
		expect(screen.getByRole("button", { name: "Generate key" })).toBeDisabled();
		approved = true;
		fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate key" })).toBeEnabled());
		expect(invoke.mock.calls.filter(([name]) => name === "pilot-status")).toHaveLength(2);
	});

	it("never enables credential creation from a legacy approval without admission", async () => {
		invoke.mockImplementation(async (name) => ({
			error: null,
			data:
				name === "pilot-status"
					? { ok: true, status: "approved" }
					: name === "api-keys"
						? { ok: true, keys: [] }
						: { ok: true, tokens: [] },
		}));
		render(<ApiKeysPage />);
		await screen.findByText("unknown");
		expect(screen.getByRole("button", { name: "Generate key" })).toBeDisabled();
		expect(screen.getByRole("button", { name: "Generate enrollment token" })).toBeDisabled();
	});

	it("rotates a tenant-scoped key and shows the replacement secret once with its overlap deadline", async () => {
		const replacement = "aidr_live_replacement_secret";
		const validUntil = "2026-09-24T02:00:00.000Z";
		invoke.mockImplementation(async (name, options) => {
			if (name === "pilot-status")
				return { error: null, data: { ok: true, admission: activeAdmission } };
			if (name === "api-keys" && options?.method === "POST") {
				expect(options.body).toEqual({ action: "renew", id: "key-1" });
				return {
					error: null,
					data: { ok: true, api_key: replacement, previous_secret_valid_until: validUntil },
				};
			}
			return {
				error: null,
				data:
					name === "api-keys"
						? {
								ok: true,
								keys: [{ id: "key-1", label: "server", revoked: false, created_at: validUntil }],
							}
						: { ok: true, tokens: [] },
			};
		});

		render(<ApiKeysPage />);
		fireEvent.click(await screen.findByRole("button", { name: "Rotate" }));
		const secret = await screen.findByLabelText("New API key");
		expect((secret as HTMLInputElement).value).toMatch(/^•+/);
		expect(screen.getByText(/previous key remains valid until/i)).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Reveal" }));
		expect(secret).toHaveValue(replacement);
		expect(screen.getByRole("button", { name: "Rotate" })).toBeDisabled();
		expect(invoke).toHaveBeenCalledWith("api-keys", {
			method: "POST",
			headers: { "X-AIDR-Tenant-ID": "team-a" },
			body: { action: "renew", id: "key-1" },
		});
	});

	it("issues, reveals and clears one-time credentials, then revokes or deletes them", async () => {
		const exampleKey = ["sample", "only", "key"].join("-");
		const exampleToken = ["sample", "only", "token"].join("-");
		let key: { id: string; label: string; revoked: boolean; created_at: string } | null = null;
		let token: {
			id: string;
			label: string;
			consumed_at: null;
			created_at: string;
			expires_at: string;
		} | null = null;
		function keyResponse(action?: string, label?: string) {
			if (action === "create") {
				key = {
					id: "key-1",
					label: label ?? "",
					revoked: false,
					created_at: "2026-09-23T00:00:00Z",
				};
				return { ok: true, api_key: exampleKey };
			}
			if (action === "revoke") {
				if (key) key.revoked = true;
				return { ok: true };
			}
			return { ok: true, keys: key ? [{ ...key }] : [] };
		}
		function tokenResponse(action?: string, label?: string) {
			if (action === "create") {
				token = {
					id: "token-1",
					label: label ?? "",
					consumed_at: null,
					created_at: "2026-09-23T00:00:00Z",
					expires_at: "2099-01-01T00:00:00Z",
				};
				return { ok: true, enrollment_token: exampleToken };
			}
			if (action === "delete") {
				token = null;
				return { ok: true };
			}
			return { ok: true, tokens: token ? [{ ...token }] : [] };
		}
		invoke.mockImplementation(async (name, options) => {
			const body = options?.body as { action?: string; label?: string } | undefined;
			return {
				error: null,
				data:
					name === "pilot-status"
						? { ok: true, status: "none", admission: activeAdmission }
						: name === "api-keys"
							? keyResponse(body?.action, body?.label)
							: tokenResponse(body?.action, body?.label),
			};
		});
		render(<ApiKeysPage />);
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate key" })).toBeEnabled());
		fireEvent.change(screen.getByPlaceholderText("work-laptop, build-server, etc."), {
			target: { value: " analyst " },
		});
		fireEvent.click(screen.getByRole("button", { name: "Generate key" }));
		const secret = await screen.findByLabelText("New API key");
		expect((secret as HTMLInputElement).value).toMatch(/^•+/);
		expect((secret as HTMLInputElement).value.endsWith(exampleKey.slice(-4))).toBe(true);
		expect(screen.getByRole("button", { name: "Generate key" })).toBeDisabled();
		fireEvent.click(screen.getByRole("button", { name: "Reveal" }));
		expect(secret).toHaveValue(exampleKey);
		await screen.findByText("analyst");
		fireEvent.click(screen.getByRole("button", { name: "Clear" }));
		expect(screen.getByRole("button", { name: "Generate key" })).toBeEnabled();
		fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
		await screen.findByText("revoked");

		fireEvent.change(screen.getByPlaceholderText("workstation-1, ci-runner, etc."), {
			target: { value: " workstation " },
		});
		fireEvent.click(screen.getByRole("button", { name: "Generate enrollment token" }));
		await screen.findByLabelText("New enrollment token");
		expect(screen.getByRole("button", { name: "Generate enrollment token" })).toBeDisabled();
		await screen.findByText("workstation");
		fireEvent.click(screen.getByRole("button", { name: "Delete" }));
		await waitFor(() => expect(screen.queryByText("workstation")).not.toBeInTheDocument());
	});
});

describe("Browser Guard ingest-only keys", () => {
	function install(onCreate: (body: Record<string, unknown>) => Record<string, unknown>) {
		const keys: Array<Record<string, unknown>> = [];
		invoke.mockImplementation(async (name, options) => {
			if (name === "pilot-status")
				return { error: null, data: { ok: true, admission: activeAdmission } };
			if (name === "api-keys" && options?.method === "POST") {
				const body = options.body as Record<string, unknown>;
				const result = onCreate(body);
				keys.push({
					id: `key-${keys.length + 1}`,
					label: body.label,
					revoked: false,
					created_at: "2026-09-24T00:00:00Z",
					scope: body.scope ?? "tenant",
					install_limit: body.install_limit ?? null,
				});
				return { error: null, data: result };
			}
			return {
				error: null,
				data: name === "api-keys" ? { ok: true, keys: [...keys] } : { ok: true, tokens: [] },
			};
		});
	}

	it("issues an ingest-only key with an installation limit and labels it in the key list", async () => {
		const secret = ["aidr", "ingest", "sample"].join("_");
		const bodies: Array<Record<string, unknown>> = [];
		install((body) => {
			bodies.push(body);
			return { ok: true, api_key: secret, scope: body.scope, install_limit: body.install_limit };
		});
		render(<ApiKeysPage />);
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate key" })).toBeEnabled());
		fireEvent.change(screen.getByLabelText("Key type"), {
			target: { value: "ingest:browser_guard" },
		});
		expect(screen.getByText(/Users of a managed browser can read this key/)).toBeInTheDocument();
		fireEvent.change(screen.getByLabelText("Installation limit"), { target: { value: "250" } });
		fireEvent.change(screen.getByPlaceholderText("work-laptop, build-server, etc."), {
			target: { value: " managed browsers " },
		});
		fireEvent.click(screen.getByRole("button", { name: "Generate key" }));
		await screen.findByLabelText("New API key");
		expect(bodies).toEqual([
			{
				action: "create",
				label: "managed browsers",
				scope: "ingest:browser_guard",
				install_limit: 250,
			},
		]);
		expect(
			screen.getByText(/paste it into the managed policy's telemetry\.apiKey/),
		).toBeInTheDocument();
		expect(
			await screen.findByText("Browser Guard ingest · up to 250 installs"),
		).toBeInTheDocument();
	});

	it("preselects the ingest-only type from the Privacy Guard link and validates the limit", async () => {
		window.history.replaceState({}, "", "/api-keys?type=browser_guard");
		install(() => ({ ok: true, api_key: "unused" }));
		render(<ApiKeysPage />);
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate key" })).toBeEnabled());
		expect(screen.getByLabelText("Key type")).toHaveValue("ingest:browser_guard");
		for (const value of ["0", "100001", "2.5", "", "ten"]) {
			fireEvent.change(screen.getByLabelText("Installation limit"), { target: { value } });
			expect(screen.getByRole("button", { name: "Generate key" })).toBeDisabled();
		}
		fireEvent.change(screen.getByLabelText("Installation limit"), { target: { value: "100000" } });
		expect(screen.getByRole("button", { name: "Generate key" })).toBeEnabled();
	});

	it("lets a member create tenant keys but not ingest-only keys", async () => {
		team.role = "member";
		install(() => ({ ok: true, api_key: "unused" }));
		render(<ApiKeysPage />);
		await waitFor(() => expect(screen.getByRole("button", { name: "Generate key" })).toBeEnabled());
		fireEvent.change(screen.getByLabelText("Key type"), {
			target: { value: "ingest:browser_guard" },
		});
		expect(screen.getByRole("button", { name: "Generate key" })).toBeDisabled();
		expect(
			screen.getByText("Ask a workspace owner or admin to create this key."),
		).toBeInTheDocument();
	});
});
