// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RetentionPage } from "../ui/pages/RetentionPage";

const fixture = vi.hoisted(() => ({ role: "owner", invoke: vi.fn() }));
vi.mock("../enterprise/team-provider", () => ({
	useTeam: () => ({
		currentTeam: { id: "team-id", tenant_id: "tenant-id", name: "Finance" },
		currentRole: fixture.role,
	}),
}));
vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke: fixture.invoke } } }));

const HOLD_ID = "11111111-1111-4111-8111-111111111111";
const policies = [
	{
		data_class: "telemetry",
		retention_days: 30,
		min_days: 7,
		max_days: 3650,
		configurable: true,
		updated_at: null,
	},
	{
		data_class: "access_credentials",
		retention_days: 0,
		min_days: 0,
		max_days: 0,
		configurable: false,
		updated_at: null,
	},
];
const activeHold = {
	id: HOLD_ID,
	hold_reference: "CASE-1",
	case_id: "CASE-1",
	hold_owner: "Counsel A",
	reason: "Litigation",
	placed_at: "2026-10-01T00:00:00.000Z",
	released_at: null,
	release_reason: null,
};
const snapshot = (holds: unknown[] = []) => ({
	ok: true,
	holds,
	retention_policies: policies,
	next_hold_cursor: null,
});

beforeEach(() => {
	vi.clearAllMocks();
	fixture.role = "owner";
	fixture.invoke.mockResolvedValue({ data: snapshot(), error: null });
});
afterEach(cleanup);

describe("legal hold and retention dashboard", () => {
	it("loads with the canonical tenant header and shows bounds and platform-controlled classes", async () => {
		render(<RetentionPage />);
		await screen.findByText(
			"No active legal hold. Retention and offboarding follow the periods below.",
		);
		expect(fixture.invoke).toHaveBeenCalledWith("retention-admin", {
			method: "GET",
			headers: { "X-AIDR-Tenant-ID": "tenant-id" },
		});
		expect(screen.getByText("7–3650")).toBeInTheDocument();
		expect(screen.getByText("Platform controlled")).toBeInTheDocument();
	});

	it("requires a confirming second click before placing a hold, then sends case, owner and reason", async () => {
		fixture.invoke.mockImplementation(async (_name: string, options?: { method?: string }) =>
			options?.method === "POST"
				? { data: { ok: true, hold_id: HOLD_ID }, error: null }
				: { data: snapshot(), error: null },
		);
		render(<RetentionPage />);
		await screen.findByLabelText("Case ID");
		fireEvent.change(screen.getByLabelText("Case ID"), { target: { value: "CASE-2026-001" } });
		fireEvent.change(screen.getByLabelText("Hold owner"), { target: { value: "Counsel A" } });
		fireEvent.change(screen.getByLabelText("Reason"), {
			target: { value: "Litigation preservation" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Place legal hold" }));
		expect(fixture.invoke.mock.calls.some(([, options]) => options?.method === "POST")).toBe(false);
		fireEvent.click(screen.getByRole("button", { name: "Confirm: place legal hold" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("retention-admin", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": "tenant-id" },
				body: {
					action: "place_hold",
					case_id: "CASE-2026-001",
					owner: "Counsel A",
					reason: "Litigation preservation",
					tenant_id: "tenant-id",
				},
			}),
		);
		await screen.findByText(/Legal hold placed/);
	});

	it("rejects an invalid case id locally without calling the service", async () => {
		render(<RetentionPage />);
		await screen.findByLabelText("Case ID");
		fireEvent.change(screen.getByLabelText("Case ID"), { target: { value: "bad;case" } });
		fireEvent.change(screen.getByLabelText("Hold owner"), { target: { value: "Counsel A" } });
		fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "x" } });
		fireEvent.click(screen.getByRole("button", { name: "Place legal hold" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("Enter the case ID");
		expect(fixture.invoke).toHaveBeenCalledTimes(1);
	});

	it("shows an urgent not-protected message when placement is refused for a pending deletion", async () => {
		fixture.invoke.mockImplementation(async (_name: string, options?: { method?: string }) =>
			options?.method === "POST"
				? { data: { error: "hold_refused_pending_deletion", hold_active: false }, error: null }
				: { data: snapshot(), error: null },
		);
		render(<RetentionPage />);
		await screen.findByLabelText("Case ID");
		fireEvent.change(screen.getByLabelText("Case ID"), { target: { value: "CASE-1" } });
		fireEvent.change(screen.getByLabelText("Hold owner"), { target: { value: "Counsel A" } });
		fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Preserve" } });
		fireEvent.click(screen.getByRole("button", { name: "Place legal hold" }));
		fireEvent.click(await screen.findByRole("button", { name: "Confirm: place legal hold" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("NOT placed");
	});

	it("releases an active hold only with a reason and a confirmation", async () => {
		fixture.invoke.mockImplementation(async (_name: string, options?: { method?: string }) =>
			options?.method === "POST"
				? { data: { ok: true }, error: null }
				: { data: snapshot([activeHold]), error: null },
		);
		render(<RetentionPage />);
		await screen.findByRole("region", { name: "Active legal hold" });
		expect(screen.getByRole("button", { name: "Release hold" })).toBeDisabled();
		fireEvent.change(screen.getByLabelText("Release reason"), {
			target: { value: "Matter closed" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Release hold" }));
		fireEvent.click(screen.getByRole("button", { name: "Confirm release" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("retention-admin", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": "tenant-id" },
				body: {
					action: "release_hold",
					hold_id: HOLD_ID,
					reason: "Matter closed",
					tenant_id: "tenant-id",
				},
			}),
		);
	});

	it("changes a retention period within bounds and rejects out-of-range values locally", async () => {
		fixture.invoke.mockImplementation(async (_name: string, options?: { method?: string }) =>
			options?.method === "POST"
				? {
						data: {
							ok: true,
							data_class: "telemetry",
							retention_days: 90,
							previous_retention_days: 30,
							changed: true,
						},
						error: null,
					}
				: { data: snapshot(), error: null },
		);
		render(<RetentionPage />);
		await screen.findByText("7–3650");
		fireEvent.click(screen.getByRole("button", { name: "Change" }));
		fireEvent.change(screen.getByLabelText("Retention days for Agent telemetry and incidents"), {
			target: { value: "3" },
		});
		fireEvent.change(screen.getByLabelText("Reason for change"), {
			target: { value: "Policy review" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		expect(await screen.findByRole("alert")).toHaveTextContent("between 7 and 3650");
		fireEvent.change(screen.getByLabelText("Retention days for Agent telemetry and incidents"), {
			target: { value: "90" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Save" }));
		await waitFor(() =>
			expect(fixture.invoke).toHaveBeenCalledWith("retention-admin", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": "tenant-id" },
				body: {
					action: "set_retention",
					data_class: "telemetry",
					retention_days: 90,
					reason: "Policy review",
					tenant_id: "tenant-id",
				},
			}),
		);
		await screen.findByText("Retention period saved and audited.");
	});

	it("is read-only for admins and blocked for other roles", async () => {
		fixture.role = "admin";
		render(<RetentionPage />);
		await screen.findByText("7–3650");
		expect(screen.queryByRole("button", { name: "Change" })).not.toBeInTheDocument();
		expect(screen.queryByLabelText("Case ID")).not.toBeInTheDocument();
		cleanup();
		fixture.invoke.mockClear();
		fixture.role = "member";
		render(<RetentionPage />);
		expect(screen.getByText(/owners and admins only/)).toBeInTheDocument();
		expect(fixture.invoke).not.toHaveBeenCalled();
	});

	it("never renders raw backend error details", async () => {
		fixture.invoke.mockResolvedValue({
			data: null,
			error: Object.assign(new Error("relation tenant_legal_holds permission denied for table x"), {
				context: { status: 500 },
			}),
		});
		render(<RetentionPage />);
		const alert = await screen.findByRole("alert");
		expect(alert).not.toHaveTextContent("tenant_legal_holds");
	});
});
