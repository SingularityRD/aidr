// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { useTeamMock } = vi.hoisted(() => ({ useTeamMock: vi.fn() }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: useTeamMock }));
vi.mock("../enterprise/admin-panel", () => ({ AdminPanel: () => null }));

import { TeamAuditPanel } from "../enterprise/team-audit-panel";
import type { useTeam } from "../enterprise/team-provider";
import { TeamPage } from "../ui/pages/TeamPage";

const TEAM_A = "11111111-1111-4111-8111-111111111111";
const TEAM_B = "22222222-2222-4222-8222-222222222222";
const makeRow = (teamId: string, index: number) => ({
	id: `audit-${index}`,
	team_id: teamId,
	user_id: `actor-${index}`,
	action: `action-${index}`,
	timestamp: Date.parse("2026-09-23T00:00:00.000Z") - index * 1000,
	created_at: new Date(Date.parse("2026-09-23T00:00:00.000Z") - index * 1000).toISOString(),
});

function teamState(overrides: Record<string, unknown> = {}): ReturnType<typeof useTeam> {
	return {
		currentTeam: {
			id: TEAM_A,
			name: "Team A",
			plan: "pro",
			created_at: "2026-09-23T00:00:00.000Z",
			updated_at: "2026-09-23T00:00:00.000Z",
		},
		canViewAudit: true,
		canManageTeam: true,
		canReadAuditTrail: true,
		auditLogs: [],
		auditLoaded: true,
		auditError: null,
		refreshAuditLogs: vi.fn().mockResolvedValue(undefined),
		exportAuditLogs: vi.fn().mockResolvedValue("blob:export"),
		...overrides,
	} as unknown as ReturnType<typeof useTeam>;
}

describe("Team audit customer UI", () => {
	beforeEach(() => {
		vi.resetAllMocks();
		useTeamMock.mockReturnValue(teamState());
	});
	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
	});

	it("is reachable from the Team page", () => {
		render(<TeamPage />);
		expect(screen.getByRole("heading", { name: "Team audit" })).toBeInTheDocument();
	});

	it("does not confuse loading, read failure, and an empty team", () => {
		useTeamMock.mockReturnValue(teamState({ auditLoaded: false }));
		const { rerender } = render(<TeamAuditPanel />);
		expect(screen.getByText("Loading audit records…")).toBeInTheDocument();
		expect(screen.queryByText("No audit records for this team.")).not.toBeInTheDocument();

		const refreshAuditLogs = vi.fn().mockResolvedValue(undefined);
		useTeamMock.mockReturnValue(teamState({ auditError: "storage unavailable", refreshAuditLogs }));
		rerender(<TeamAuditPanel />);
		expect(screen.getByRole("alert")).toHaveTextContent("Audit records are unavailable.");
		expect(screen.queryByText("No audit records for this team.")).not.toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Refresh audit" }));
		expect(refreshAuditLogs).toHaveBeenCalledOnce();

		useTeamMock.mockReturnValue(teamState());
		rerender(<TeamAuditPanel />);
		expect(screen.getByText("No audit records for this team.")).toBeInTheDocument();
		expect(screen.queryByRole("alert")).not.toBeInTheDocument();
	});

	it("renders only the selected team's audit rows, including during a team switch", () => {
		const auditLogs = [
			{ ...makeRow(TEAM_A, 1), verdict: { input: "private prompt content" } },
			makeRow(TEAM_B, 2),
		];
		useTeamMock.mockReturnValue(teamState({ auditLogs }));
		const { rerender } = render(<TeamAuditPanel />);
		expect(screen.getByText("action-1")).toBeInTheDocument();
		expect(screen.queryByText("action-2")).not.toBeInTheDocument();
		expect(screen.queryByText("private prompt content")).not.toBeInTheDocument();

		useTeamMock.mockReturnValue(
			teamState({ currentTeam: { id: TEAM_B, name: "Team B" }, auditLogs }),
		);
		rerender(<TeamAuditPanel />);
		expect(screen.getByText("action-2")).toBeInTheDocument();
		expect(screen.queryByText("action-1")).not.toBeInTheDocument();
	});

	it("labels an audit actor that the server did not record", () => {
		useTeamMock.mockReturnValue(
			teamState({ auditLogs: [{ ...makeRow(TEAM_A, 1), user_id: null }] }),
		);
		render(<TeamAuditPanel />);
		expect(screen.getByText("Not recorded")).toBeInTheDocument();
	});

	it("pages the latest 25 rows without claiming that all history is loaded", () => {
		useTeamMock.mockReturnValue(
			teamState({ auditLogs: Array.from({ length: 26 }, (_, index) => makeRow(TEAM_A, index)) }),
		);
		render(<TeamAuditPanel />);
		expect(screen.getByText("action-0")).toBeInTheDocument();
		expect(screen.queryByText("action-25")).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Previous audit page" })).toBeDisabled();
		fireEvent.click(screen.getByRole("button", { name: "Next audit page" }));
		expect(screen.getByText("action-25")).toBeInTheDocument();
		expect(screen.queryByText("action-0")).not.toBeInTheDocument();
		expect(screen.getByRole("button", { name: "Next audit page" })).toBeDisabled();
		fireEvent.click(screen.getByRole("button", { name: "Previous audit page" }));
		expect(screen.getByText("action-0")).toBeInTheDocument();
	});

	it("shows audit rows but no export controls to members and viewers", () => {
		const exportAuditLogs = vi.fn();
		useTeamMock.mockReturnValue(
			teamState({
				canManageTeam: false,
				canReadAuditTrail: false,
				exportAuditLogs,
				auditLogs: [makeRow(TEAM_A, 0)],
			}),
		);
		render(<TeamAuditPanel />);
		expect(screen.getByText("action-0")).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Prepare CSV export" })).toBeNull();
		expect(screen.queryByRole("button", { name: "Prepare JSON export" })).toBeNull();
		expect(
			screen.getByText("Audit export is available to team owners, admins and auditors."),
		).toBeInTheDocument();
		expect(exportAuditLogs).not.toHaveBeenCalled();
	});

	it("exports a chosen date range and blocks an inverted one", async () => {
		const exportAuditLogs = vi.fn().mockResolvedValue("blob:ranged");
		useTeamMock.mockReturnValue(teamState({ exportAuditLogs }));
		render(<TeamAuditPanel />);
		fireEvent.change(screen.getByLabelText("From (UTC date)"), { target: { value: "2026-09-01" } });
		fireEvent.change(screen.getByLabelText("To (UTC date, inclusive)"), {
			target: { value: "2026-09-30" },
		});
		fireEvent.click(screen.getByRole("button", { name: "Prepare CSV export" }));
		await screen.findByRole("link", { name: "Save audit export" });
		expect(exportAuditLogs).toHaveBeenCalledWith("csv", "audit", {
			from: "2026-09-01T00:00:00.000Z",
			to: "2026-10-01T00:00:00.000Z",
		});

		fireEvent.change(screen.getByLabelText("From (UTC date)"), { target: { value: "2026-10-05" } });
		expect(screen.getByRole("alert")).toHaveTextContent(
			"The start date must not be after the end date.",
		);
		expect(screen.getByRole("button", { name: "Prepare CSV export" })).toBeDisabled();
		expect(screen.getByRole("button", { name: "Prepare JSON export" })).toBeDisabled();
	});

	it("gives the read-only auditor the export controls without team management", () => {
		useTeamMock.mockReturnValue(teamState({ canManageTeam: false, canReadAuditTrail: true }));
		render(<TeamAuditPanel />);
		expect(screen.getByRole("button", { name: "Prepare CSV export" })).toBeEnabled();
		expect(
			screen.queryByText("Audit export is available to team owners, admins and auditors."),
		).toBeNull();
	});

	it("offers a save link only for a completed tenant-scoped export", async () => {
		const exportAuditLogs = vi
			.fn()
			.mockResolvedValueOnce("blob:csv-export")
			.mockResolvedValueOnce("blob:json-export");
		useTeamMock.mockReturnValue(teamState({ exportAuditLogs }));
		render(<TeamAuditPanel />);

		fireEvent.click(screen.getByRole("button", { name: "Prepare CSV export" }));
		const csvLink = await screen.findByRole("link", { name: "Save audit export" });
		expect(exportAuditLogs).toHaveBeenCalledWith("csv", "audit", {});
		expect(csvLink).toHaveAttribute("href", "blob:csv-export");
		expect(csvLink.getAttribute("download")).toContain(TEAM_A);
		expect(csvLink.getAttribute("download")).toMatch(/\.csv$/);
		expect(screen.getByText("Audit export is ready to download.")).toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: "Prepare JSON export" }));
		await waitFor(() =>
			expect(screen.getByRole("link", { name: "Save audit export" })).toHaveAttribute(
				"href",
				"blob:json-export",
			),
		);
		expect(exportAuditLogs).toHaveBeenLastCalledWith("json", "audit", {});
		expect(
			screen.getByRole("link", { name: "Save audit export" }).getAttribute("download"),
		).toMatch(/\.json$/);
	});

	it("never exposes a stale export after the selected team changes", async () => {
		let completeExport: (url: string) => void = () => undefined;
		const exportAuditLogs = vi.fn().mockReturnValue(
			new Promise<string>((resolve) => {
				completeExport = resolve;
			}),
		);
		const revokeObjectURL = vi.fn();
		vi.stubGlobal("URL", Object.assign(class extends URL {}, { revokeObjectURL }));
		useTeamMock.mockReturnValue(teamState({ exportAuditLogs }));
		const { rerender } = render(<TeamAuditPanel />);
		fireEvent.click(screen.getByRole("button", { name: "Prepare CSV export" }));
		expect(exportAuditLogs).toHaveBeenCalledWith("csv", "audit", {});

		useTeamMock.mockReturnValue(teamState({ currentTeam: { id: TEAM_B, name: "Team B" } }));
		rerender(<TeamAuditPanel />);
		await act(async () => completeExport("blob:old-team-export"));
		expect(screen.queryByRole("link", { name: "Save audit export" })).not.toBeInTheDocument();
		expect(screen.queryByText("Audit export is ready to download.")).not.toBeInTheDocument();
		expect(revokeObjectURL).toHaveBeenCalledWith("blob:old-team-export");
	});

	it("does not claim success or offer a file when export fails", async () => {
		useTeamMock.mockReturnValue(
			teamState({ exportAuditLogs: vi.fn().mockRejectedValue(new Error("export unavailable")) }),
		);
		render(<TeamAuditPanel />);
		fireEvent.click(screen.getByRole("button", { name: "Prepare JSON export" }));
		await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/export/i));
		expect(screen.queryByRole("link", { name: "Save audit export" })).not.toBeInTheDocument();
		expect(screen.queryByText("Audit export is ready to download.")).not.toBeInTheDocument();
	});
});
