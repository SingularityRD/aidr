// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { supabase } from "../lib/supabase";
import { ApiKeysPage } from "../ui/pages/ApiKeysPage";
import { fleetKeyState, parseSeatCap } from "../ui/pages/FleetEnrollmentKeys";

const state = vi.hoisted(() => ({
	currentTeam: { id: "team-a", name: "Finance" },
	currentRole: "admin",
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: () => state }));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: vi.fn() } } }));
const invoke = vi.mocked(supabase.functions.invoke);

const activeAdmission = {
	mode: "onprem",
	status: "active",
	access_kind: "licensed",
	allowed_agents: 500,
	expires_at: null,
	trial_available: false,
};
const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
const listed = {
	id: "fleet-1",
	label: "laptops",
	key_hint: "Wxyz",
	seat_cap: 500,
	enrolled_count: 12,
	use_count: 14,
	expires_at: future,
	created_at: "2026-10-01T00:00:00Z",
	last_used_at: null,
	revoked_at: null as string | null,
};
// Synthetic one-time secret, assembled at runtime.
const SECRET = ["aidr", "fleet", "synthetic-fixture"].join("_");

beforeEach(() => {
	state.currentRole = "admin";
	listed.revoked_at = null;
	vi.clearAllMocks();
	invoke.mockImplementation(async (name, options) => {
		const body = options?.body as { action?: string } | undefined;
		if (name === "pilot-status")
			return { error: null, data: { ok: true, admission: activeAdmission } };
		if (name === "fleet-keys" && body?.action === "create")
			return {
				error: null,
				data: { ok: true, fleet_key: SECRET, id: "fleet-2", expires_at: future },
			};
		if (name === "fleet-keys" && body?.action === "revoke") {
			listed.revoked_at = new Date().toISOString();
			return { error: null, data: { ok: true, id: "fleet-1", revoked_at: listed.revoked_at } };
		}
		if (name === "fleet-keys") return { error: null, data: { ok: true, keys: [listed] } };
		return { error: null, data: { ok: true, keys: [], tokens: [] } };
	});
});
afterEach(cleanup);

describe("fleet enrollment keys card", () => {
	it("is shown to owners/admins only", async () => {
		state.currentRole = "member";
		render(<ApiKeysPage />);
		await screen.findByRole("button", { name: "Generate key" });
		await waitFor(() => expect(invoke).toHaveBeenCalledWith("pilot-status", expect.anything()));
		expect(
			screen.queryByRole("heading", { name: "Fleet enrollment keys" }),
		).not.toBeInTheDocument();
		expect(invoke).not.toHaveBeenCalledWith("fleet-keys", expect.anything());
	});

	it("creates a seat-capped key for the selected team and shows the secret once", async () => {
		render(<ApiKeysPage />);
		await screen.findByRole("heading", { name: "Fleet enrollment keys" });
		expect(await screen.findByText("12 / 500")).toBeInTheDocument();
		expect(screen.getByText("…Wxyz")).toBeInTheDocument();

		fireEvent.change(screen.getByLabelText("Maximum new machines"), { target: { value: "750" } });
		fireEvent.click(screen.getByRole("button", { name: "Create fleet key" }));
		const secret = await screen.findByLabelText("New fleet enrollment key");
		expect(secret).toHaveAttribute("type", "password");
		expect(invoke).toHaveBeenCalledWith("fleet-keys", {
			method: "POST",
			headers: { "X-AIDR-Tenant-ID": "team-a" },
			body: { action: "create", label: null, seat_cap: 750, ttl_days: 90 },
		});
		expect(screen.getByRole("button", { name: "Create fleet key" })).toBeDisabled();
		fireEvent.click(screen.getByRole("button", { name: "Clear" }));
		expect(screen.queryByLabelText("New fleet enrollment key")).not.toBeInTheDocument();
	});

	it("blocks an out-of-range seat cap before calling the server", async () => {
		render(<ApiKeysPage />);
		await screen.findByRole("heading", { name: "Fleet enrollment keys" });
		fireEvent.change(screen.getByLabelText("Maximum new machines"), { target: { value: "0" } });
		expect(screen.getByRole("button", { name: "Create fleet key" })).toBeDisabled();
	});

	it("revokes only after a second confirmation", async () => {
		render(<ApiKeysPage />);
		await screen.findByText("12 / 500");
		fireEvent.click(screen.getAllByRole("button", { name: "Revoke" }).at(-1) as HTMLElement);
		expect(invoke).not.toHaveBeenCalledWith(
			"fleet-keys",
			expect.objectContaining({ body: { action: "revoke", id: "fleet-1" } }),
		);
		fireEvent.click(await screen.findByRole("button", { name: "Confirm revoke" }));
		await waitFor(() =>
			expect(invoke).toHaveBeenCalledWith("fleet-keys", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": "team-a" },
				body: { action: "revoke", id: "fleet-1" },
			}),
		);
		expect(await screen.findByText("revoked")).toBeInTheDocument();
	});

	it("derives the key state from revocation, expiry and the cap", () => {
		const now = Date.parse("2026-10-14T00:00:00Z");
		const base = { ...listed, expires_at: "2026-11-01T00:00:00Z" };
		expect(fleetKeyState(base, now)).toBe("active");
		expect(fleetKeyState({ ...base, enrolled_count: 500 }, now)).toBe("exhausted");
		expect(fleetKeyState({ ...base, expires_at: "2026-10-01T00:00:00Z" }, now)).toBe("expired");
		expect(fleetKeyState({ ...base, revoked_at: "2026-10-02T00:00:00Z" }, now)).toBe("revoked");
		expect(parseSeatCap("500")).toBe(500);
		for (const value of ["0", "100001", "1.5", "", "abc"]) expect(parseSeatCap(value)).toBeNull();
	});
});
