// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { invoke, useTeam } = vi.hoisted(() => ({ invoke: vi.fn(), useTeam: vi.fn() }));

vi.mock("../lib/supabase", () => ({ supabase: { functions: { invoke } } }));
vi.mock("../enterprise/team-provider", () => ({ useTeam }));

import { AdminPanel } from "../enterprise/admin-panel";

function renderPanel(createTeam: ReturnType<typeof vi.fn>) {
	useTeam.mockReturnValue({
		currentTeam: {
			id: "11111111-1111-4111-8111-111111111111",
			name: "Primary workspace",
			plan: "pro",
			created_at: "2026-09-23T00:00:00.000Z",
			updated_at: "2026-09-23T00:00:00.000Z",
		},
		currentRole: "owner",
		members: [],
		isLoading: false,
		error: null,
		membersError: null,
		memberEmailsAvailable: true,
		canManageTeam: true,
		inviteMember: vi.fn(),
		removeMember: vi.fn(),
		updateMemberRole: vi.fn(),
		createTeam,
	});
	return render(<AdminPanel />);
}

describe("admin workspace creation request IDs", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		invoke.mockResolvedValue({ data: { ok: true, invitations: [] }, error: null });
	});
	afterEach(cleanup);

	it("reuses the same ID for an ambiguous retry and rotates it for the next intentional workspace", async () => {
		const createTeam = vi
			.fn()
			.mockRejectedValueOnce(new Error("gateway timeout"))
			.mockResolvedValue(undefined);
		renderPanel(createTeam);

		fireEvent.click(screen.getByRole("button", { name: "+ New Team" }));
		fireEvent.change(screen.getByRole("textbox", { name: "New Team Name" }), {
			target: { value: "Acme Security" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create Team" }));
		await waitFor(() => expect(createTeam).toHaveBeenCalledTimes(1));
		await screen.findByRole("alert");
		const firstAttempt = createTeam.mock.calls[0];
		if (!firstAttempt) throw new Error("first team creation was not recorded");
		expect(screen.getByRole("textbox", { name: "New Team Name" })).toHaveAttribute("readonly");
		fireEvent.click(screen.getByRole("button", { name: "Retry Team Creation" }));
		await waitFor(() => expect(createTeam).toHaveBeenCalledTimes(2));
		expect(createTeam.mock.calls[1]).toEqual(firstAttempt);

		fireEvent.click(screen.getByRole("button", { name: "+ New Team" }));
		fireEvent.change(screen.getByRole("textbox", { name: "New Team Name" }), {
			target: { value: "Second workspace" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Create Team" }));
		await waitFor(() => expect(createTeam).toHaveBeenCalledTimes(3));
		const secondIntent = createTeam.mock.calls[2];
		if (!secondIntent) throw new Error("second intentional workspace was not recorded");
		expect(secondIntent[0]).toBe("Second workspace");
		expect(secondIntent[1]).not.toBe(firstAttempt[1]);
	});
});
