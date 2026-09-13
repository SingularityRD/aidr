// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiKeysPage } from "../ui/pages/ApiKeysPage";
import { supabase } from "../lib/supabase";
const state = vi.hoisted(() => ({ currentTeam: { id: "team-a", name: "Finance" }, currentRole: "owner" }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => state }));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));
const invoke = vi.mocked(supabase.functions.invoke);
beforeEach(() => {
  state.currentTeam = { id: "team-a", name: "Finance" }; state.currentRole = "owner"; vi.clearAllMocks();
  invoke.mockImplementation(async (name, options) => ({ error: null, data: name === "pilot-status" ? { ok: true, status: "approved" } : (options?.body as { action?: string })?.action === "create" ? { ok: true, api_key: "fixture-secret-once", enrollment_token: "fixture-token-once" } : { ok: true, keys: [], tokens: [] } }));
});
afterEach(cleanup);
describe("selected-team credentials", () => {
  it("binds reads and writes to the selected tenant and clears the one-time secret on team switch", async () => {
    const result = render(<ApiKeysPage />);
    const button = await screen.findByRole("button", { name: "Generate key" });
    await waitFor(() => expect(button).toBeEnabled()); fireEvent.click(button);
    await screen.findByLabelText("New API key");
    for (const [,options] of invoke.mock.calls) expect(options?.headers).toEqual({ "X-AIDR-Tenant-ID": "team-a" });
    state.currentTeam = { id: "team-b", name: "Engineering" }; result.rerender(<ApiKeysPage />);
    expect(screen.queryByLabelText("New API key")).not.toBeInTheDocument();
    await waitFor(() => expect(invoke).toHaveBeenCalledWith("api-keys", { method: "GET", headers: { "X-AIDR-Tenant-ID": "team-b" } }));
  });
  it("keeps credential creation disabled for a viewer even when admission is approved", async () => {
    state.currentRole = "viewer"; render(<ApiKeysPage />);
    await waitFor(() => expect(screen.queryByText("loading")).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Generate key" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Generate enrollment token" })).toBeDisabled();
  });
	it("keeps a key active and shows the error when the revoke Edge call is missing", async () => {
		invoke.mockImplementation(async (name, options) => {
			if (name === "pilot-status") return { error: null, data: { ok: true, status: "approved" } };
			if (name === "api-keys" && options?.method === "POST") {
				return { error: { message: "Function not found" }, data: null };
			}
			if (name === "api-keys") return { error: null, data: { ok: true, keys: [{ id: "key-1", label: "pilot", revoked: false, created_at: "2026-09-13T00:00:00Z" }] } };
			return { error: null, data: { ok: true, tokens: [] } };
		});
		render(<ApiKeysPage />);
		const revoke = await screen.findByRole("button", { name: "Revoke" });
		fireEvent.click(revoke);
		expect(await screen.findByRole("alert")).toHaveTextContent("Function not found");
		expect(screen.getByText("active")).toBeInTheDocument();
		expect(invoke.mock.calls.filter(([name, options]) => name === "api-keys" && options?.method === "GET")).toHaveLength(1);
	});
});
