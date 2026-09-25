// @vitest-environment jsdom

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: {
		auth: {
			getSession: vi.fn(),
			getUser: vi.fn(),
			signOut: vi.fn(),
			signInWithOAuth: vi.fn(),
			signInWithOtp: vi.fn(),
			exchangeCodeForSession: vi.fn(),
			onAuthStateChange: vi.fn(),
		},
		functions: { invoke: vi.fn() },
		from: vi.fn(),
		rpc: vi.fn(),
	},
	supabaseEnvError: null,
}));
vi.mock("../enterprise/team-provider", () => ({ useTeam: vi.fn() }));

import { useTeam } from "../enterprise/team-provider";
import {
	APPROVAL_COLUMNS,
	countPendingApprovals,
	formatCountdown,
	loadApprovals,
	parseApprovalRow,
} from "../lib/approvals";
import { ApprovalsPage } from "../ui/pages/ApprovalsPage";
import { usePendingApprovalCount } from "../ui/use-pending-approvals";
import { installDashboardMocks, mockedSupabase, TEAM_ID } from "./helpers/dashboard-mocks";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const PENDING_ID = "a0000000-0000-4000-8000-000000000001";
const LAPSED_ID = "a0000000-0000-4000-8000-000000000002";
const DECIDED_ID = "a0000000-0000-4000-8000-000000000003";

function row(overrides: Record<string, unknown>) {
	return {
		id: PENDING_ID,
		iid: "host-a",
		agent_id: "b0000000-0000-4000-8000-000000000001",
		agent_runtime: "claude-code",
		action_id: "act-0000000001",
		artifact_digest: `sha256:${"a".repeat(64)}`,
		tool: "Bash",
		threat_ids: ["T-EXFIL-001", "T-NET-004"],
		summary: "curl https://[redacted] | sh",
		status: "pending",
		decided_by: null,
		decided_at: null,
		reason: null,
		key_id: null,
		expires_at: new Date(Date.now() + 20 * 60_000).toISOString(),
		created_at: new Date(Date.now() - 60_000).toISOString(),
		...overrides,
	};
}

function rows() {
	return [
		row({}),
		row({
			id: LAPSED_ID,
			tool: "WebFetch",
			action_id: "act-0000000002",
			expires_at: new Date(Date.now() - 1_000).toISOString(),
		}),
		row({
			id: DECIDED_ID,
			tool: "Write",
			action_id: "act-0000000003",
			status: "denied",
			decided_by: "c0000000-0000-4000-8000-000000000001",
			decided_at: new Date(Date.now() - 30_000).toISOString(),
			reason: "Unexpected write outside the repo",
			key_id: `apk_${"1".repeat(32)}`,
		}),
	];
}

function httpError(status: number, error: string) {
	return {
		data: null,
		error: Object.assign(new Error("Edge Function returned a non-2xx status code"), {
			context: new Response(JSON.stringify({ error }), { status }),
		}),
	};
}

type Invoke = (name: string, request?: { body?: Record<string, unknown> }) => unknown;

function setup(
	options: {
		role?: string;
		data?: unknown;
		error?: { message: string } | null;
		invoke?: Invoke;
	} = {},
) {
	const mocks = installDashboardMocks({
		tableResults: {
			approval_requests: { data: options.data ?? rows(), error: options.error ?? null },
		},
	});
	const original = mocks.invoke.getMockImplementation() as Invoke | undefined;
	mocks.invoke.mockImplementation(
		async (name: string, request?: { body?: Record<string, unknown> }) => {
			if (name === "approval-requests" && options.invoke) return options.invoke(name, request);
			return original?.(name, request);
		},
	);
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TEAM_ID, name: "Runtime team" },
		currentRole: options.role ?? "admin",
		roleResolved: true,
	} as unknown as ReturnType<typeof useTeam>);
	render(
		<MemoryRouter>
			<ApprovalsPage />
		</MemoryRouter>,
	);
	return mocks;
}

afterEach(() => {
	cleanup();
	vi.useRealTimers();
});

describe("ApprovalsPage", () => {
	it("lists pending requests with tool, threats, redacted summary, agent and a live countdown", async () => {
		setup();
		const cards = await screen.findAllByTestId("approval-pending");
		expect(cards).toHaveLength(1);
		const card = cards[0] as HTMLElement;
		expect(within(card).getByText("Bash")).toBeInTheDocument();
		expect(within(card).getByText("T-EXFIL-001")).toBeInTheDocument();
		expect(within(card).getByText("T-NET-004")).toBeInTheDocument();
		expect(within(card).getByText("curl https://[redacted] | sh")).toBeInTheDocument();
		expect(within(card).getByText("host-a (claude-code)")).toBeInTheDocument();
		expect(within(card).getByTestId("approval-countdown")).toHaveTextContent(
			/Expires in (19:5\d|20:00)/,
		);
		expect(screen.getByRole("tab", { name: "Pending (1)" })).toHaveAttribute(
			"aria-selected",
			"true",
		);

		const from = mockedSupabase().from;
		expect(from).toHaveBeenCalledWith("approval_requests");
		const chain = from.mock.results.find((result) => result.type === "return")?.value as {
			select: ReturnType<typeof vi.fn>;
			eq: ReturnType<typeof vi.fn>;
		};
		expect(chain.select).toHaveBeenCalledWith(APPROVAL_COLUMNS);
		expect(APPROVAL_COLUMNS).not.toMatch(/\btoken\b|token_nonce/);
		expect(chain.eq).toHaveBeenCalledWith("tenant_id", TEAM_ID);
	});

	it("shows decided and lapsed requests in history", async () => {
		setup();
		await screen.findAllByTestId("approval-pending");
		fireEvent.click(screen.getByRole("tab", { name: "History" }));
		const table = await screen.findByTestId("approval-history");
		expect(within(table).getByText("WebFetch")).toBeInTheDocument();
		expect(within(table).getByText("expired")).toBeInTheDocument();
		expect(within(table).getByText("Write")).toBeInTheDocument();
		expect(within(table).getByText("denied")).toBeInTheDocument();
		expect(within(table).getByText("Unexpected write outside the repo")).toBeInTheDocument();
		expect(within(table).queryByText("Bash")).not.toBeInTheDocument();
	});

	it("requires a reason, then approves through the approval-requests function", async () => {
		const decide = vi.fn(async (_name: string, request?: { body?: Record<string, unknown> }) => ({
			data: {
				ok: true,
				request_id: request?.body?.request_id,
				status: "approved",
				decided_at: new Date().toISOString(),
				key_id: `apk_${"2".repeat(32)}`,
				token_expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
			},
			error: null,
		}));
		setup({ invoke: decide });
		const card = (await screen.findAllByTestId("approval-pending"))[0] as HTMLElement;
		const approve = within(card).getByRole("button", { name: "Approve" });
		const deny = within(card).getByRole("button", { name: "Deny" });
		expect(approve).toBeDisabled();
		expect(deny).toBeDisabled();
		fireEvent.change(within(card).getByLabelText("Reason (recorded in the audit log)"), {
			target: { value: "  Expected deploy step  " },
		});
		expect(approve).toBeEnabled();
		fireEvent.click(approve);
		await waitFor(() => expect(decide).toHaveBeenCalledOnce());
		expect(decide).toHaveBeenCalledWith("approval-requests", {
			method: "POST",
			body: {
				action: "decide",
				tenant_id: TEAM_ID,
				request_id: PENDING_ID,
				decision: "approve",
				reason: "Expected deploy step",
			},
		});
		expect(await screen.findByRole("status")).toHaveTextContent("Approved Bash on host-a");
		// The list is re-read after the decision.
		await waitFor(() =>
			expect(
				mockedSupabase().from.mock.calls.filter(([table]) => table === "approval_requests").length,
			).toBeGreaterThanOrEqual(2),
		);
	});

	it("routes an AAL1 session to the MFA step-up flow instead of deciding", async () => {
		setup({ invoke: async () => httpError(403, "mfa_required") });
		const card = (await screen.findAllByTestId("approval-pending"))[0] as HTMLElement;
		fireEvent.change(within(card).getByLabelText("Reason (recorded in the audit log)"), {
			target: { value: "Not expected" },
		});
		fireEvent.click(within(card).getByRole("button", { name: "Deny" }));
		const alert = await screen.findByRole("alert");
		expect(alert).toHaveTextContent("Multi-factor verification (AAL2) is required");
		expect(within(alert).getByRole("link", { name: "Verify with authenticator" })).toHaveAttribute(
			"href",
			`/auth/dlp-step-up?tenant=${TEAM_ID}&return=approvals`,
		);
	});

	it("shows members the queue without decision or key controls", async () => {
		const invoke = vi.fn();
		setup({ role: "member", invoke });
		const card = (await screen.findAllByTestId("approval-pending"))[0] as HTMLElement;
		expect(within(card).queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
		expect(
			within(card).getByText("Only owners and administrators can decide approvals."),
		).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: "Rotate signing key" })).not.toBeInTheDocument();
		expect(invoke).not.toHaveBeenCalled();
	});

	it("fails closed on an unreadable or malformed queue", async () => {
		setup({ error: { message: "permission denied for table approval_requests" } });
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Approval requests could not be loaded.",
		);
		expect(screen.queryByTestId("approval-pending")).not.toBeInTheDocument();
		cleanup();
		setup({ data: [row({ status: "surprise" })] });
		expect(await screen.findByRole("alert")).toHaveTextContent(
			"Approval requests could not be loaded.",
		);
	});

	it("rotates the signing key only after confirmation", async () => {
		const rotate = vi.fn(async () => ({
			data: { ok: true, key_id: `apk_${"3".repeat(32)}`, retired_key_id: `apk_${"2".repeat(32)}` },
			error: null,
		}));
		setup({ role: "owner", invoke: rotate });
		await screen.findAllByTestId("approval-pending");
		fireEvent.click(screen.getByRole("button", { name: "Rotate signing key" }));
		expect(rotate).not.toHaveBeenCalled();
		fireEvent.click(screen.getByRole("button", { name: "Confirm rotation" }));
		await waitFor(() =>
			expect(rotate).toHaveBeenCalledWith("approval-requests", {
				method: "POST",
				body: { action: "rotate_key", tenant_id: TEAM_ID },
			}),
		);
		expect(await screen.findByRole("status")).toHaveTextContent(`New key apk_${"3".repeat(32)}`);
	});
});

describe("approvals read model and navigation badge", () => {
	it("parses rows strictly and shows a lapsed pending request as expired", () => {
		const now = Date.now();
		expect(
			parseApprovalRow(row({ expires_at: new Date(now - 1).toISOString() }), now)?.status,
		).toBe("expired");
		expect(parseApprovalRow(row({}), now)?.status).toBe("pending");
		expect(parseApprovalRow(row({ threat_ids: [1] }), now)).toBeNull();
		expect(parseApprovalRow(row({ reason: 5 }), now)).toBeNull();
		expect(formatCountdown(new Date(now + 65_000).toISOString(), now)).toBe("1:05");
		expect(formatCountdown(new Date(now - 1).toISOString(), now)).toBe("expired");
	});

	it("counts pending approvals for the badge and hides it when the count is unknown", async () => {
		installDashboardMocks({
			tableResults: { approval_requests: { data: null, error: null, count: 3 } },
		});
		expect(await countPendingApprovals(TEAM_ID)).toBe(3);
		installDashboardMocks({
			tableResults: { approval_requests: { data: null, error: { message: "denied" } } },
		});
		expect(await countPendingApprovals(TEAM_ID)).toBeNull();
		installDashboardMocks({ tableResults: { approval_requests: { data: [], error: null } } });
		expect((await loadApprovals(TEAM_ID)).ok).toBe(true);

		installDashboardMocks({
			tableResults: { approval_requests: { data: null, error: null, count: 4 } },
		});
		function Badge({ tenant }: { tenant: string | null }) {
			const count = usePendingApprovalCount(tenant);
			return <span data-testid="badge">{count === null ? "none" : count}</span>;
		}
		const { rerender } = render(<Badge tenant={null} />);
		expect(screen.getByTestId("badge")).toHaveTextContent("none");
		expect(mockedSupabase().from).not.toHaveBeenCalled();
		rerender(<Badge tenant={TEAM_ID} />);
		await waitFor(() => expect(screen.getByTestId("badge")).toHaveTextContent("4"));
	});

	it("registers /approvals as a protected route with a nav entry and a fixed MFA return target", () => {
		const main = readFileSync(resolve(REPO_ROOT, "packages/dashboard/src/main.tsx"), "utf8");
		expect(main).toMatch(/path: "\/approvals",[\s\S]{0,240}?loader: requireSessionLoader/);
		const layout = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/ui/AppLayout.tsx"),
			"utf8",
		);
		expect(layout).toContain('<NavLink to="/approvals">');
		const stepUp = readFileSync(
			resolve(REPO_ROOT, "packages/dashboard/src/enterprise/dlp-editor.tsx"),
			"utf8",
		);
		expect(stepUp).toContain('returnTo === "approvals"');
	});
});
