// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: { from: vi.fn(), rpc: vi.fn(), functions: { invoke: vi.fn() } },
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import { supabase } from "../lib/supabase";
import { ReportsPage } from "../ui/pages/ReportsPage";

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const invoke = supabase.functions.invoke as ReturnType<typeof vi.fn>;

function team(role: string) {
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TENANT, name: "Acme" },
		currentRole: role,
		isLoading: false,
		roleResolved: true,
		members: [],
	} as unknown as ReturnType<typeof useTeam>);
}

function figures(overrides: Record<string, number> = {}) {
	return {
		agentsActive: 9,
		agentsEnrolled: 12,
		browserActive: 31,
		allow: 1200,
		ask: 40,
		deny: 25,
		masked: 60,
		blocked: 3,
		incidentsActive: 5,
		incidentsCritical: 1,
		incidentsUnassigned: 2,
		approvalsPending: 1,
		...overrides,
	};
}

beforeEach(() => {
	vi.resetAllMocks();
	invoke.mockImplementation(async (name: string, { body }: { body: Record<string, unknown> }) => {
		if (name === "governance-digest")
			return { data: { ok: true, status: "sent", recipients: 2, delivered: 2 }, error: null };
		switch (body.action) {
			case "summary":
				return {
					data: {
						ok: true,
						language: body.language,
						period: { from: "2026-09-15T00:00:00.000Z", to: "2026-10-14T10:00:00.000Z" },
						options: {
							language: "tr",
							attachment: true,
							digestEnabled: true,
							digestCadence: "weekly",
						},
						executive: {
							status: "attention",
							headlines: [
								{
									level: "attention",
									text:
										body.language === "tr"
											? "2 açık vakanın sorumlusu yok."
											: "2 open incident(s) have no owner.",
								},
								{
									level: "info",
									text: "25 risky agent action(s) were blocked and 40 held for human approval.",
								},
							],
						},
						sections: [{ title: "AI usage", lines: ["Coding agents active: 9 of 12 enrolled"] }],
					},
					error: null,
				};
			case "rollup":
				return {
					data: {
						ok: true,
						teams: [
							{ tenantId: TENANT, name: "Acme", role: "owner", figures: figures() },
							{ tenantId: OTHER, name: "Treasury", role: "admin", figures: null },
						],
					},
					error: null,
				};
			case "set_options":
				return {
					data: { ok: true, options: { language: body.language, attachment: body.attachment } },
					error: null,
				};
			case "document":
				return {
					data: {
						ok: true,
						filename: "aidr-executive-report-2026-10-14.html",
						html: "<!doctype html><p>r</p>",
					},
					error: null,
				};
			default:
				return { data: null, error: new Error("unexpected") };
		}
	});
});
afterEach(() => cleanup());

function renderPage() {
	render(
		<MemoryRouter>
			<ReportsPage />
		</MemoryRouter>,
	);
}

describe("ReportsPage", () => {
	it("is limited to owners and admins", () => {
		team("member");
		renderPage();
		expect(screen.getByRole("alert")).toHaveTextContent("Only workspace owners and admins");
		expect(invoke).not.toHaveBeenCalled();
	});

	it("shows the executive summary and a team rollup that withholds restricted workspaces", async () => {
		team("owner");
		renderPage();
		expect(await screen.findByText("Needs attention")).toBeInTheDocument();
		expect(
			within(screen.getByTestId("executive-headlines")).getByText(
				"2 open incident(s) have no owner.",
			),
		).toBeInTheDocument();
		const rollup = screen.getByRole("region", { name: "Team rollup" });
		const treasury = (await within(rollup).findByText("Treasury")).closest("tr") as HTMLElement;
		expect(treasury).toHaveTextContent(
			"Not shown: this session does not meet the workspace's sign-in policy.",
		);
		const acme = within(rollup).getByText("Acme").closest("tr") as HTMLElement;
		expect(acme).toHaveTextContent("9 / 12");

		fireEvent.change(screen.getByLabelText("Report language"), { target: { value: "tr" } });
		expect(await screen.findByText("2 açık vakanın sorumlusu yok.")).toBeInTheDocument();
		expect(invoke).toHaveBeenCalledWith("reports", {
			method: "POST",
			body: { action: "summary", tenant_id: TENANT, days: 30, language: "tr" },
		});
	});

	it("saves the scheduled e-mail language and attachment, and sends a test", async () => {
		team("admin");
		renderPage();
		const schedule = await screen.findByRole("region", { name: "Scheduled e-mail" });
		expect(await within(schedule).findByText("Sent every week.")).toBeInTheDocument();
		expect(within(schedule).getByLabelText("E-mail language")).toHaveValue("tr");
		fireEvent.click(within(schedule).getByLabelText("Attach the printable report"));
		fireEvent.click(within(schedule).getByRole("button", { name: "Save e-mail settings" }));
		await screen.findByText("E-mail settings saved.");
		expect(invoke).toHaveBeenCalledWith("reports", {
			method: "POST",
			body: { action: "set_options", tenant_id: TENANT, language: "tr", attachment: false },
		});
		fireEvent.click(within(schedule).getByRole("button", { name: "Send a test now" }));
		await screen.findByText("Test sent to 2 of 2 recipient(s).");
	});

	it("downloads the printable report from the server", async () => {
		team("owner");
		const create = vi.fn(() => "blob:report");
		Object.assign(URL, { createObjectURL: create, revokeObjectURL: vi.fn() });
		renderPage();
		await screen.findByText("Needs attention");
		fireEvent.click(screen.getByLabelText("Include the team rollup"));
		fireEvent.click(screen.getByRole("button", { name: "Download report" }));
		await screen.findByText("Downloaded aidr-executive-report-2026-10-14.html.");
		expect(invoke).toHaveBeenCalledWith("reports", {
			method: "POST",
			body: {
				action: "document",
				tenant_id: TENANT,
				days: 30,
				language: "en",
				include_teams: true,
			},
		});
		await waitFor(() => expect(create).toHaveBeenCalled());
	});

	it("shows a closed error instead of figures when the service refuses", async () => {
		team("owner");
		invoke.mockResolvedValue({ data: null, error: new Error("down") });
		renderPage();
		const errors = await screen.findAllByText("The report service is not available right now.");
		expect(errors.length).toBeGreaterThanOrEqual(2);
		expect(screen.queryByText("Needs attention")).not.toBeInTheDocument();
	});
});
