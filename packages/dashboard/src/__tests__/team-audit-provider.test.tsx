// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const A = "11111111-1111-4111-8111-111111111111";
const B = "22222222-2222-4222-8222-222222222222";
const USER = "33333333-3333-4333-8333-333333333333";
const mocks = vi.hoisted(() => ({
	selectedTeam: "",
	from: vi.fn(),
	getUser: vi.fn(),
	rpc: vi.fn(),
	invoke: vi.fn(),
	collectAuditExport: vi.fn(),
	createObjectURL: vi.fn(),
}));

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: { getUser: mocks.getUser },
		from: mocks.from,
		rpc: mocks.rpc,
		functions: { invoke: mocks.invoke },
	},
	supabaseEnvError: null,
}));
vi.mock("../enterprise/audit-export", () => ({ collectAuditExport: mocks.collectAuditExport }));
vi.mock("../enterprise/identity-bootstrap", () => ({
	IdentityBootstrap: ({
		children,
	}: {
		children: (
			teamId: string,
			switchTeam: (teamId: string) => void,
			refreshMemberships: (teamId: string) => Promise<void>,
			isCurrent: () => boolean,
			userId: string,
		) => ReactNode;
	}) => {
		const selected = mocks.selectedTeam;
		return children(
			selected,
			() => undefined,
			async () => undefined,
			() => mocks.selectedTeam === selected,
			USER,
		);
	},
}));

import { TeamProvider, useTeam } from "../enterprise/team-provider";

const memberships = [A, B].map((id) => ({
	team_id: id,
	role: "owner",
	teams: {
		id,
		name: `Team ${id}`,
		plan: "pro",
		github_org: null,
		gitlab_group: null,
		created_at: "2026-09-23T00:00:00.000Z",
		updated_at: "2026-09-23T00:00:00.000Z",
	},
}));
const auditRow = (teamId: string, action: string) => ({
	id: `${teamId}-${action}`,
	team_id: teamId,
	user_id: USER,
	action,
	created_at: "2026-09-23T00:00:00.000Z",
	verdict: { input: "secret prompt that must not be selected" },
});

interface AuditRead {
	columns: string;
	tenantFilter: string;
}
let auditReads: AuditRead[];
let resolveAuditA: ((value: { data: unknown[]; error: null }) => void) | null;
let resolveExportA: ((value: { data: unknown; error: null }) => void) | null;
let delayARead: boolean;
let delayAExport: boolean;
const contexts = new Map<string, ReturnType<typeof useTeam>>();

function query(table: string) {
	let columns = "";
	let tenantFilter = "";
	const chain = {
		select(value: string) {
			columns = value;
			return chain;
		},
		eq(key: string, value: string) {
			if (key === "tenant_id") tenantFilter = value;
			return chain;
		},
		order() {
			return chain;
		},
		limit() {
			return chain;
		},
		then(resolve: (value: { data: unknown[]; error: null }) => unknown) {
			if (table === "team_members")
				return Promise.resolve({ data: memberships, error: null }).then(resolve);
			auditReads.push({ columns, tenantFilter });
			if (tenantFilter === A && delayARead) {
				return new Promise<{ data: unknown[]; error: null }>((finish) => {
					resolveAuditA = finish;
				}).then(resolve);
			}
			const action = tenantFilter === B ? "B-only-action" : "A-only-action";
			return Promise.resolve({ data: [auditRow(tenantFilter, action)], error: null }).then(resolve);
		},
	};
	return chain;
}

function Probe() {
	const context = useTeam();
	if (context.currentTeam) contexts.set(context.currentTeam.id, context);
	return (
		<div data-testid="audit-probe">
			{context.currentTeam?.id ?? "loading"}: {context.auditLogs.map((row) => row.action).join(",")}
		</div>
	);
}

function CreateTeamProbe() {
	const { createTeam } = useTeam();
	return (
		<button
			onClick={() => void createTeam("Retry workspace", "55555555-5555-4555-8555-555555555555")}
		>
			Create workspace
		</button>
	);
}

function renderProvider() {
	return render(
		<TeamProvider>
			<Probe />
		</TeamProvider>,
	);
}

beforeEach(() => {
	vi.resetAllMocks();
	contexts.clear();
	auditReads = [];
	resolveAuditA = null;
	resolveExportA = null;
	delayARead = false;
	delayAExport = false;
	mocks.selectedTeam = A;
	mocks.from.mockImplementation(query);
	mocks.getUser.mockResolvedValue({ data: { user: { id: USER } }, error: null });
	mocks.rpc.mockResolvedValue({ data: [], error: null });
	mocks.invoke.mockImplementation((_name: string, request: { body: { team_id: string } }) => {
		if (request.body.team_id === A && delayAExport) {
			return new Promise((finish) => {
				resolveExportA = finish;
			});
		}
		return Promise.resolve({ data: { ok: true }, error: null });
	});
	mocks.collectAuditExport.mockImplementation(
		async (_format: string, getPage: () => Promise<unknown>) => {
			await getPage();
			return new Blob(["fixture"]);
		},
	);
	mocks.createObjectURL.mockReturnValue("blob:current-team");
	vi.stubGlobal(
		"URL",
		Object.assign(class extends URL {}, { createObjectURL: mocks.createObjectURL }),
	);
});
afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

describe("team audit provider boundaries", () => {
	it("selects safe columns under the selected tenant and discards a late previous-team read", async () => {
		delayARead = true;
		const { rerender } = renderProvider();
		await waitFor(() => expect(resolveAuditA).not.toBeNull());
		expect(auditReads).toContainEqual({
			columns: "id,team_id,user_id,action,created_at",
			tenantFilter: A,
		});
		mocks.selectedTeam = B;
		rerender(
			<TeamProvider>
				<Probe />
			</TeamProvider>,
		);
		await waitFor(() =>
			expect(screen.getByTestId("audit-probe")).toHaveTextContent("B-only-action"),
		);
		await act(async () => {
			resolveAuditA?.({ data: [auditRow(A, "late-A-action")], error: null });
		});
		expect(screen.getByTestId("audit-probe")).toHaveTextContent("B-only-action");
		expect(screen.getByTestId("audit-probe")).not.toHaveTextContent("late-A-action");
		expect(auditReads).toContainEqual({
			columns: "id,team_id,user_id,action,created_at",
			tenantFilter: B,
		});
		expect(auditReads.every((read) => !read.columns.includes("verdict"))).toBe(true);
	});

	it("binds each export to its original team and rejects a late A export after B is selected", async () => {
		delayAExport = true;
		const { rerender } = renderProvider();
		await waitFor(() => expect(contexts.has(A)).toBe(true));
		const oldExport = contexts.get(A)?.exportAuditLogs;
		expect(oldExport).toBeDefined();
		const stale = expect(oldExport?.("json")).rejects.toThrow(/selected team changed/i);
		await waitFor(() => expect(resolveExportA).not.toBeNull());

		mocks.selectedTeam = B;
		rerender(
			<TeamProvider>
				<Probe />
			</TeamProvider>,
		);
		await waitFor(() => expect(contexts.has(B)).toBe(true));
		await expect(contexts.get(B)?.exportAuditLogs("csv")).resolves.toBe("blob:current-team");
		await act(async () => resolveExportA?.({ data: { ok: true }, error: null }));
		await stale;
		expect(mocks.invoke).toHaveBeenCalledWith("audit-export", {
			body: { team_id: A, format: "json" },
		});
		expect(mocks.invoke).toHaveBeenCalledWith("audit-export", {
			body: { team_id: B, format: "csv" },
		});
		expect(mocks.createObjectURL).toHaveBeenCalledOnce();
		expect(screen.getByTestId("audit-probe")).toHaveTextContent(B);
	});

	it("explains a legal-hold refusal instead of reporting an unexplained export failure", async () => {
		mocks.invoke.mockResolvedValue({
			data: null,
			error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
				context: new Response(JSON.stringify({ error: "legal_hold_active" }), { status: 409 }),
			}),
		});
		renderProvider();
		await waitFor(() => expect(contexts.has(A)).toBe(true));
		await expect(contexts.get(A)?.exportAuditLogs("csv")).rejects.toThrow(
			/paused while a legal hold is active/,
		);
		mocks.invoke.mockResolvedValue({ data: { error: "export_unavailable" }, error: null });
		await expect(contexts.get(A)?.exportAuditLogs("csv")).rejects.toThrow(
			"Audit export failed. No partial file was produced.",
		);
		expect(mocks.createObjectURL).not.toHaveBeenCalled();
	});

	it("forwards the stable request ID through the team-creation RPC contract", async () => {
		mocks.rpc.mockResolvedValue({
			data: {
				id: "66666666-6666-4666-8666-666666666666",
				tenant_id: "66666666-6666-4666-8666-666666666666",
			},
			error: null,
		});
		render(
			<TeamProvider>
				<CreateTeamProbe />
			</TeamProvider>,
		);
		await act(async () => screen.getByRole("button", { name: "Create workspace" }).click());
		await waitFor(() =>
			expect(mocks.rpc).toHaveBeenCalledWith("create_team_tenant", {
				p_name: "Retry workspace",
				p_request_id: "55555555-5555-4555-8555-555555555555",
				p_plan: "free",
			}),
		);
	});
});
