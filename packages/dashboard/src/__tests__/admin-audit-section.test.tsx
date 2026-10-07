// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { useTeamMock } = vi.hoisted(() => ({ useTeamMock: vi.fn() }));
vi.mock("../enterprise/team-provider", () => ({ useTeam: useTeamMock }));
vi.mock("../lib/supabase", () => ({ supabase: { rpc: vi.fn() } }));

import {
	ADMIN_AUDIT_PAGE_SIZE,
	AdminAuditSection,
	readAdminAuditPage,
} from "../enterprise/admin-audit-section";
import { supabase } from "../lib/supabase";

const TENANT = "11111111-1111-4111-8111-111111111111";
const rpc = supabase.rpc as unknown as ReturnType<typeof vi.fn>;

function row(id: number) {
	return {
		id,
		created_at: new Date(Date.parse("2026-10-01T00:00:00.000Z") - id * 1000).toISOString(),
		actor_user_id: "22222222-2222-4222-8222-222222222222",
		target_user_id: null,
		action: `policy.action-${id}`,
		detail: { version: id },
	};
}

function team(overrides: Record<string, unknown> = {}) {
	return {
		currentTeam: { id: TENANT, tenant_id: TENANT, name: "Team" },
		canManageTeam: true,
		exportAuditLogs: vi.fn().mockResolvedValue("blob:admin"),
		...overrides,
	};
}

beforeEach(() => {
	rpc.mockReset();
	useTeamMock.mockReturnValue(team());
});
afterEach(cleanup);

describe("Administrative actions (admin_audit_logs)", () => {
	it("pages tenant-scoped rows through the owner/admin RPC with a keyset cursor", async () => {
		const first = Array.from({ length: ADMIN_AUDIT_PAGE_SIZE + 1 }, (_, index) => row(index + 1));
		rpc
			.mockResolvedValueOnce({ data: first, error: null })
			.mockResolvedValueOnce({ data: [row(99)], error: null });
		render(<AdminAuditSection />);
		expect(await screen.findByText("policy.action-1")).toBeInTheDocument();
		expect(
			screen.queryByText(`policy.action-${ADMIN_AUDIT_PAGE_SIZE + 1}`),
		).not.toBeInTheDocument();
		expect(rpc).toHaveBeenCalledWith("list_tenant_admin_audit_logs", {
			p_tenant_id: TENANT,
			p_limit: ADMIN_AUDIT_PAGE_SIZE + 1,
		});

		fireEvent.click(screen.getByRole("button", { name: "Older administrative actions" }));
		expect(await screen.findByText("policy.action-99")).toBeInTheDocument();
		const last = first[ADMIN_AUDIT_PAGE_SIZE - 1];
		expect(rpc).toHaveBeenLastCalledWith("list_tenant_admin_audit_logs", {
			p_tenant_id: TENANT,
			p_limit: ADMIN_AUDIT_PAGE_SIZE + 1,
			p_before_created_at: last?.created_at,
			p_before_id: last?.id,
		});
		expect(screen.getByRole("button", { name: "Older administrative actions" })).toBeDisabled();
	});

	it("is not rendered, and never queried, for members and viewers", () => {
		useTeamMock.mockReturnValue(team({ canManageTeam: false }));
		const { container } = render(<AdminAuditSection />);
		expect(container).toBeEmptyDOMElement();
		expect(rpc).not.toHaveBeenCalled();
	});

	it("shows an error rather than an empty trail when the RPC is refused", async () => {
		rpc.mockResolvedValue({ data: null, error: { message: "admin_audit_access_denied" } });
		render(<AdminAuditSection />);
		expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
		expect(
			screen.queryByText("No administrative actions recorded for this team."),
		).not.toBeInTheDocument();
	});

	it("exports the administrative trail through audit-export source admin", async () => {
		rpc.mockResolvedValue({ data: [], error: null });
		const state = team();
		useTeamMock.mockReturnValue(state);
		render(<AdminAuditSection />);
		fireEvent.click(await screen.findByRole("button", { name: "Export administrative CSV" }));
		await waitFor(() => expect(state.exportAuditLogs).toHaveBeenCalledWith("csv", "admin"));
		expect(await screen.findByText("Save administrative audit export")).toHaveAttribute(
			"href",
			"blob:admin",
		);
	});

	it("rejects malformed pages", () => {
		expect(readAdminAuditPage([{ ...row(1), id: "1" }])).toBeNull();
		expect(readAdminAuditPage({})).toBeNull();
		expect(readAdminAuditPage([row(1)])?.[0]?.action).toBe("policy.action-1");
	});
});
