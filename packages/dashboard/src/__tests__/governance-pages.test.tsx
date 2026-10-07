// @vitest-environment jsdom

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
	CHANGE_COLUMNS,
	enforcementOf,
	isReviewOverdue,
	loadGovernance,
	parseAsset,
	parseChange,
	parseException,
	pendingPolicyChangeNotice,
} from "../lib/ai-governance";
import { diffDocuments, diffStats } from "../lib/json-diff";
import { GovernanceChangeControlPage } from "../ui/pages/GovernanceChangeControlPage";
import { GovernanceRegisterPage } from "../ui/pages/GovernanceRegisterPage";
import { GovernanceRequestsPage } from "../ui/pages/GovernanceRequestsPage";
import {
	ADMIN_USER_ID,
	installDashboardMocks,
	MEMBER_USER_ID,
	mockedSupabase,
	type QueryCall,
	type QueryResolver,
	TEAM_ID,
} from "./helpers/dashboard-mocks";

const OWNER_ID = "55555555-5555-4555-8555-555555555555";
const SHELL_ID = "a0000000-0000-4000-8000-000000000001";
const SITE_ID = "a0000000-0000-4000-8000-000000000002";
const INTAKE_ID = "b0000000-0000-4000-8000-000000000001";
const OWN_INTAKE_ID = "b0000000-0000-4000-8000-000000000002";
const EXCEPTION_ID = "c0000000-0000-4000-8000-000000000001";
const CHANGE_ID = "d0000000-0000-4000-8000-000000000001";
const OWN_CHANGE_ID = "d0000000-0000-4000-8000-000000000002";
const DAY = 86_400_000;
const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();
const day = (offsetMs: number) => iso(offsetMs).slice(0, 10);

function asset(overrides: Record<string, unknown>) {
	return {
		id: SHELL_ID,
		asset_type: "mcp_server",
		identifier: "shell-runner",
		name: "Shell runner",
		vendor: null,
		owner_user_id: OWNER_ID,
		business_purpose: "Build scripts",
		data_categories: ["source_code"],
		risk_tier: "high",
		risk_score: 70,
		status: "banned",
		review_due_at: day(-3 * DAY),
		last_reviewed_at: null,
		last_reviewed_by: null,
		source: "posture",
		first_observed_at: iso(-30 * DAY),
		last_observed_at: iso(-DAY),
		version: 2,
		updated_at: iso(-DAY),
		...overrides,
	};
}

function intake(overrides: Record<string, unknown>) {
	return {
		id: INTAKE_ID,
		asset_id: null,
		asset_type: "ai_site",
		identifier: "claude",
		name: "Claude",
		vendor: "Anthropic",
		business_purpose: "Drafting release notes",
		data_categories: ["customer_data"],
		requested_status: "approved",
		status: "pending",
		requested_by: MEMBER_USER_ID,
		created_at: iso(-DAY),
		expires_at: iso(60 * DAY),
		decided_by: null,
		decided_at: null,
		decision_reason: null,
		...overrides,
	};
}

function change(overrides: Record<string, unknown>) {
	return {
		id: CHANGE_ID,
		change_kind: "runtime_publish",
		base_version: 3,
		target_version: null,
		payload_sha256: "a".repeat(64),
		summary: { policy_keys: 1 },
		status: "pending",
		requested_by: OWNER_ID,
		created_at: iso(-3_600_000),
		expires_at: iso(6 * DAY),
		decided_by: null,
		decided_at: null,
		decision_reason: null,
		applied_version: null,
		outcome_code: null,
		...overrides,
	};
}

const TABLES = () => ({
	ai_assets: {
		data: [
			asset({}),
			asset({
				id: SITE_ID,
				asset_type: "ai_site",
				identifier: "deepseek",
				name: "DeepSeek",
				status: "approved",
				review_due_at: day(90 * DAY),
				source: "browser_telemetry",
				risk_tier: "limited",
				risk_score: null,
				data_categories: [],
			}),
		],
		error: null,
	},
	ai_intake_requests: {
		data: [
			intake({}),
			intake({
				id: OWN_INTAKE_ID,
				identifier: "gemini",
				name: "Gemini",
				requested_by: ADMIN_USER_ID,
			}),
		],
		error: null,
	},
	ai_governance_exceptions: {
		data: [
			{
				id: EXCEPTION_ID,
				asset_id: SHELL_ID,
				scope_kind: "members",
				scope_user_ids: [MEMBER_USER_ID],
				scope_agent_ids: [],
				justification: "Migration week",
				status: "approved",
				requested_by: MEMBER_USER_ID,
				created_at: iso(-DAY),
				expires_at: iso(3 * DAY),
				starts_at: iso(-DAY),
				decided_by: OWNER_ID,
				decision_reason: "ok",
				revoked_by: null,
				revoke_reason: null,
			},
		],
		error: null,
	},
	policy_change_requests: {
		data: [
			change({}),
			change({ id: OWN_CHANGE_ID, requested_by: ADMIN_USER_ID, change_kind: "dlp_publish" }),
		],
		error: null,
	},
	ai_governance_reviewers: { data: [], error: null },
	ai_asset_evidence: { data: [], error: null },
	tenant_ai_governance_settings: {
		data: [{ policy_four_eyes: true, default_review_days: 180 }],
		error: null,
	},
});

type Invoke = (name: string, request?: { body?: Record<string, unknown> }) => unknown;

function setup(
	page: "register" | "requests" | "change",
	options: { role?: string; invoke?: Invoke; tables?: Record<string, unknown> } = {},
) {
	const mocks = installDashboardMocks({
		tableResults: { ...TABLES(), ...(options.tables ?? {}) } as never,
	});
	const original = mocks.invoke.getMockImplementation() as Invoke | undefined;
	mocks.invoke.mockImplementation(
		async (name: string, request?: { body?: Record<string, unknown> }) => {
			if (options.invoke && (name === "ai-governance" || name === "policy-management")) {
				const answer = await options.invoke(name, request);
				if (answer !== undefined) return answer;
			}
			if (name === "ai-governance" && request?.body?.action === "enforcement_preview") {
				return {
					data: {
						ok: true,
						connector_overlay: {
							mcp_deny_servers: ["shell-runner"],
							mcp_require_approval_servers: [],
						},
						browser_guard_managed_policy: { blockedSites: [] },
						runtime_policy_version: 0,
					},
					error: null,
				};
			}
			return original?.(name, request);
		},
	);
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id: TEAM_ID, name: "Runtime team" },
		currentRole: options.role ?? "admin",
		roleResolved: true,
		currentUserId: ADMIN_USER_ID,
		members: [
			{
				id: "m1",
				user_id: OWNER_ID,
				role: "owner",
				email: "owner@acme.example",
				joined_at: iso(-DAY),
			},
			{
				id: "m2",
				user_id: ADMIN_USER_ID,
				role: "admin",
				email: "admin@acme.example",
				joined_at: iso(-DAY),
			},
			{
				id: "m3",
				user_id: MEMBER_USER_ID,
				role: "member",
				email: "member@acme.example",
				joined_at: iso(-DAY),
			},
		],
	} as unknown as ReturnType<typeof useTeam>);
	const Page =
		page === "register"
			? GovernanceRegisterPage
			: page === "requests"
				? GovernanceRequestsPage
				: GovernanceChangeControlPage;
	render(
		<MemoryRouter>
			<Page />
		</MemoryRouter>,
	);
	return mocks;
}

afterEach(() => cleanup());

const OTHER_TEAM_ID = "99999999-9999-4999-8999-999999999999";
const AGENT_ID = "e0000000-0000-4000-8000-000000000001";

function tenantOf(calls: QueryCall[]): unknown {
	return calls.find(([method, args]) => method === "eq" && args[0] === "tenant_id")?.[1][1];
}

/** Behave like PostgREST with max_rows = 1000: honour .range(), cap every page at 1000. */
function pagedRows(all: unknown[]): QueryResolver {
	return (calls) => {
		const range = calls.find(([method]) => method === "range")?.[1] as [number, number] | undefined;
		const from = range?.[0] ?? 0;
		const to = range?.[1] ?? all.length - 1;
		const size = Math.min(to - from + 1, 1000);
		return { data: all.slice(from, from + size), error: null, count: all.length };
	};
}

function manyAssets(count: number) {
	return Array.from({ length: count }, (_, index) =>
		asset({
			id: `a0000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
			identifier: `mcp-${index}`,
			name: `Server ${String(index).padStart(5, "0")}`,
			status: "approved",
			review_due_at: day(90 * DAY),
		}),
	);
}

function teamContext(id: string) {
	vi.mocked(useTeam).mockReturnValue({
		currentTeam: { id, name: id === TEAM_ID ? "Tenant A" : "Tenant B" },
		currentRole: "admin",
		roleResolved: true,
		currentUserId: ADMIN_USER_ID,
		members: [],
	} as unknown as ReturnType<typeof useTeam>);
}

function rangesFor(table: string): unknown[] {
	const from = mockedSupabase().from;
	return from.mock.calls
		.map(([name], index) => ({
			name,
			chain: from.mock.results[index]?.value as { calls: QueryCall[] },
		}))
		.filter((entry) => entry.name === table)
		.map((entry) => entry.chain.calls.find(([method]) => method === "range")?.[1]);
}

describe("governance reads beyond one API page", () => {
	it("pages the register past the 1000-row API cap instead of silently stopping", async () => {
		installDashboardMocks({
			tableResults: { ...TABLES(), ai_assets: pagedRows(manyAssets(2300)) } as never,
		});
		const result = await loadGovernance(TEAM_ID);
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.assets).toHaveLength(2300);
		expect(result.value.truncated).toEqual({ assets: false, evidence: false });
		expect(rangesFor("ai_assets")).toEqual([
			[0, 999],
			[1000, 1999],
			[2000, 2999],
		]);
	});

	it("flags a read that hit its bound or a lower server cap as truncated", async () => {
		// The server reports 6000 rows; the reader stops at the 5000-row register quota.
		installDashboardMocks({
			tableResults: { ...TABLES(), ai_assets: pagedRows(manyAssets(6000)) } as never,
		});
		const capped = await loadGovernance(TEAM_ID);
		expect(capped.ok && capped.value.assets.length).toBe(5000);
		expect(capped.ok && capped.value.truncated.assets).toBe(true);

		// A server cap lower than the page size returns short pages; the exact count still exposes it.
		const all = manyAssets(1500);
		installDashboardMocks({
			tableResults: {
				...TABLES(),
				ai_assets: (calls: QueryCall[]) => {
					const range = calls.find(([method]) => method === "range")?.[1] as [number, number];
					return { data: all.slice(range[0], range[0] + 500), error: null, count: all.length };
				},
			} as never,
		});
		const short = await loadGovernance(TEAM_ID);
		expect(short.ok && short.value.truncated.assets).toBe(true);
	});

	it("tells the reader when the register list is incomplete", async () => {
		setup("register", {
			tables: {
				ai_assets: (calls: QueryCall[]) => ({ ...pagedRows(manyAssets(1200))(calls), count: 7000 }),
			},
		});
		expect(await screen.findByTestId("register-truncated")).toHaveTextContent(
			/Only the first 1.200 register entries could be read; counts and lists below are incomplete/,
		);
	});
});

describe("governance pages across a tenant switch", () => {
	function tenantTables(): Record<string, QueryResolver> {
		const tables = TABLES() as unknown as Record<string, { data: unknown[]; error: null }>;
		const scoped: Record<string, QueryResolver> = {};
		for (const [name, answer] of Object.entries(tables)) {
			scoped[name] = (calls) =>
				tenantOf(calls) === TEAM_ID ? answer : { data: [], error: null, count: 0 };
		}
		const exception = tables.ai_governance_exceptions?.data[0] as Record<string, unknown>;
		scoped.ai_governance_exceptions = (calls) => ({
			data: [
				{
					...exception,
					scope_kind: "agents",
					scope_user_ids: [],
					scope_agent_ids: [AGENT_ID],
					justification: tenantOf(calls) === TEAM_ID ? "Tenant A waiver" : "Tenant B waiver",
				},
			],
			error: null,
		});
		scoped.agents = (calls) =>
			tenantOf(calls) === TEAM_ID
				? { data: [{ id: AGENT_ID, iid: "a-host", display_name: "Tenant A laptop" }], error: null }
				: { data: null, error: { message: "permission denied for table agents" } };
		return scoped;
	}

	it("does not paint tenant A's rows, agents or decision notice into tenant B", async () => {
		const mocks = installDashboardMocks({ tableResults: tenantTables() as never });
		let finish: (value: unknown) => void = () => undefined;
		const original = mocks.invoke.getMockImplementation() as Invoke;
		mocks.invoke.mockImplementation((name: string, request?: { body?: Record<string, unknown> }) =>
			name === "ai-governance" && request?.body?.action === "decide_intake"
				? new Promise((resolve) => {
						finish = resolve;
					})
				: original(name, request),
		);
		teamContext(TEAM_ID);
		const view = render(
			<MemoryRouter>
				<GovernanceRequestsPage />
			</MemoryRouter>,
		);
		const card = (await screen.findAllByTestId("intake-pending")).find((item) =>
			within(item).queryByText(/Claude/),
		);
		if (!card) throw new Error("missing card");
		expect((await screen.findAllByText(/Tenant A laptop/)).length).toBeGreaterThan(0);
		fireEvent.change(within(card).getByLabelText(/Reason/), { target: { value: "Fine" } });
		fireEvent.click(within(card).getByRole("button", { name: "Approve" }));

		teamContext(OTHER_TEAM_ID);
		view.rerender(
			<MemoryRouter>
				<GovernanceRequestsPage />
			</MemoryRouter>,
		);
		expect((await screen.findAllByText(/Tenant B waiver/)).length).toBeGreaterThan(0);
		finish({ data: { ok: true, status: "approved" }, error: null });
		await new Promise((resolve) => setTimeout(resolve, 50));

		expect(screen.queryAllByTestId("intake-pending")).toHaveLength(0);
		expect(screen.queryByText(/Claude approved/)).not.toBeInTheDocument();
		expect(screen.queryByText(/Tenant A waiver/)).not.toBeInTheDocument();
		// B's agent read failed: A's agent label must not be reused for B's scope.
		expect(screen.queryByText(/Tenant A laptop/)).not.toBeInTheDocument();
		expect(screen.getAllByText(/Tenant B waiver/).length).toBeGreaterThan(0);
	});

	it("drops a register action's result when the tenant changed while it was in flight", async () => {
		const mocks = installDashboardMocks({ tableResults: tenantTables() as never });
		let finish: (value: unknown) => void = () => undefined;
		const original = mocks.invoke.getMockImplementation() as Invoke;
		mocks.invoke.mockImplementation((name: string, request?: { body?: Record<string, unknown> }) =>
			name === "ai-governance" && request?.body?.action === "import_candidates"
				? new Promise((resolve) => {
						finish = resolve;
					})
				: original(name, request),
		);
		teamContext(TEAM_ID);
		const view = render(
			<MemoryRouter>
				<GovernanceRegisterPage />
			</MemoryRouter>,
		);
		expect(await screen.findByText("Shell runner")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: "Import observed AI systems" }));

		teamContext(OTHER_TEAM_ID);
		view.rerender(
			<MemoryRouter>
				<GovernanceRegisterPage />
			</MemoryRouter>,
		);
		await waitFor(() => expect(screen.queryByText("Shell runner")).not.toBeInTheDocument());
		finish({
			data: null,
			error: Object.assign(new Error("non-2xx"), {
				context: new Response(JSON.stringify({ error: "mfa_required" }), { status: 403 }),
			}),
		});
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(screen.queryByText(/Multi-factor verification/)).not.toBeInTheDocument();
		expect(screen.queryByText("Shell runner")).not.toBeInTheDocument();
	});
});

describe("governance library", () => {
	it("parses rows strictly and derives lapsed states", () => {
		expect(parseAsset(asset({}))?.status).toBe("banned");
		expect(parseAsset(asset({ status: "deleted" }))).toBeNull();
		expect(parseAsset(asset({ data_categories: ["dna"] }))).toBeNull();
		expect(parseAsset(asset({ risk_score: "70" }))).toBeNull();
		expect(parseChange(change({ expires_at: iso(-1000) }), Date.now())?.status).toBe("expired");
		expect(parseChange(change({ summary: { policy_keys: "x" } }), Date.now())).toBeNull();
		expect(
			parseException(
				{ ...TABLES().ai_governance_exceptions.data[0], expires_at: iso(-1) },
				Date.now(),
			)?.status,
		).toBe("expired");
		expect(CHANGE_COLUMNS.split(",")).not.toContain("payload");
	});

	it("states only real enforcement effects", () => {
		expect(enforcementOf({ assetType: "mcp_server", identifier: "x", status: "banned" })).toBe(
			"connector_deny",
		);
		expect(enforcementOf({ assetType: "mcp_server", identifier: "x", status: "restricted" })).toBe(
			"connector_ask",
		);
		expect(enforcementOf({ assetType: "ai_site", identifier: "deepseek", status: "banned" })).toBe(
			"browser_block",
		);
		// Shadow AI catalog ids reach Browser Guard in the signed browser-guard-policy document.
		expect(enforcementOf({ assetType: "ai_site", identifier: "poe", status: "banned" })).toBe(
			"browser_block",
		);
		expect(enforcementOf({ assetType: "ai_site", identifier: "poe", status: "approved" })).toBe(
			"none",
		);
		expect(
			enforcementOf({ assetType: "ai_site", identifier: "chat.internal", status: "banned" }),
		).toBe("none");
		expect(
			enforcementOf({ assetType: "coding_agent", identifier: "codex", status: "banned" }),
		).toBe("none");
	});

	it("flags overdue reviews but never retired entries", () => {
		const overdue = parseAsset(asset({}));
		expect(overdue && isReviewOverdue(overdue, Date.now())).toBe(true);
		const retired = parseAsset(asset({ status: "retired" }));
		expect(retired && isReviewOverdue(retired, Date.now())).toBe(false);
	});

	it("diffs key-sorted policy documents and recognises a pending four-eyes publication", () => {
		const lines = diffDocuments({ b: 1, a: ["x"] }, { a: ["x", "y"], b: 1 });
		expect(diffStats(lines)).toEqual({ added: 2, removed: 1 });
		expect(
			diffDocuments({ a: 1, b: 2 }, { b: 2, a: 1 }).every((line) => line.kind === "same"),
		).toBe(true);
		expect(
			pendingPolicyChangeNotice({ ok: true, pending_approval: true, change_request_id: CHANGE_ID }),
		).toMatch(/nothing was published/);
		expect(pendingPolicyChangeNotice({ ok: true, version: 4 })).toBeNull();
	});
});

describe("GovernanceRegisterPage", () => {
	it("shows the register, overdue reviews and what is actually enforced", async () => {
		setup("register");
		const table = await screen.findByTestId("asset-register");
		expect(within(table).getByText("Shell runner")).toBeInTheDocument();
		expect(within(table).getByText("DeepSeek")).toBeInTheDocument();
		expect(screen.getByTestId("overdue-count")).toHaveTextContent("1");
		expect(screen.getByTestId("overdue-reviews")).toHaveTextContent("Shell runner");
		// The register row also shows the identifier, so read the enforcement preview's own entry.
		const blocked = await screen.findByText("MCP servers blocked (tenant-wide)");
		expect(blocked.nextElementSibling).toHaveTextContent("shell-runner");
		expect(screen.getByText(/No runtime policy is published/)).toBeInTheDocument();
		expect(screen.getByTestId("browser-guard-managed-policy")).toHaveTextContent(
			'"blockedSites": []',
		);
	});

	it("lets an administrator add an entry through the governance service", async () => {
		const mocks = setup("register", {
			invoke: (name, request) =>
				request?.body?.action === "upsert_asset"
					? { data: { ok: true, asset_id: SHELL_ID, version: 1 }, error: null }
					: undefined,
		});
		fireEvent.click(await screen.findByRole("button", { name: "Add AI system" }));
		fireEvent.change(screen.getByLabelText("Identifier"), { target: { value: "github" } });
		fireEvent.change(screen.getByLabelText("Name"), { target: { value: "GitHub MCP" } });
		fireEvent.click(screen.getByRole("button", { name: "Add to register" }));
		await waitFor(() =>
			expect(mocks.invoke).toHaveBeenCalledWith(
				"ai-governance",
				expect.objectContaining({
					body: expect.objectContaining({
						action: "upsert_asset",
						tenant_id: TEAM_ID,
						fields: expect.objectContaining({
							asset_type: "mcp_server",
							identifier: "github",
							name: "GitHub MCP",
						}),
					}),
				}),
			),
		);
		expect(await screen.findByText("Added to the register.")).toBeInTheDocument();
	});

	it("hides register changes from members and explains step-up failures", async () => {
		setup("register", { role: "member" });
		await screen.findByTestId("asset-register");
		expect(screen.queryByRole("button", { name: "Add AI system" })).not.toBeInTheDocument();
		expect(
			screen.queryByRole("button", { name: "Import observed AI systems" }),
		).not.toBeInTheDocument();
		cleanup();
		setup("register", {
			invoke: (_name, request) =>
				request?.body?.action === "import_candidates"
					? {
							data: null,
							error: Object.assign(new Error("non-2xx"), {
								context: new Response(JSON.stringify({ error: "mfa_required" }), { status: 403 }),
							}),
						}
					: undefined,
		});
		fireEvent.click(await screen.findByRole("button", { name: "Import observed AI systems" }));
		expect(await screen.findByText(/Multi-factor verification/)).toBeInTheDocument();
		expect(screen.getByRole("link", { name: "Verify with authenticator" })).toHaveAttribute(
			"href",
			expect.stringContaining("return=governance"),
		);
	});
});

describe("GovernanceRequestsPage", () => {
	it("never offers a decision on your own request and records the approver's reason", async () => {
		const mocks = setup("requests", {
			invoke: (_name, request) =>
				request?.body?.action === "decide_intake"
					? { data: { ok: true, status: "approved" }, error: null }
					: undefined,
		});
		const cards = await screen.findAllByTestId("intake-pending");
		const own = cards.find((card) => within(card).queryByText(/Gemini/));
		const other = cards.find((card) => within(card).queryByText(/Claude/));
		expect(own && within(own).getByText(/someone else must decide/)).toBeInTheDocument();
		expect(own && within(own).queryByRole("button", { name: "Approve" })).toBeNull();
		if (!other) throw new Error("missing card");
		const approve = within(other).getByRole("button", { name: "Approve" });
		expect(approve).toBeDisabled();
		fireEvent.change(within(other).getByLabelText(/Reason/), {
			target: { value: "Fine for release notes" },
		});
		fireEvent.click(approve);
		await waitFor(() =>
			expect(mocks.invoke).toHaveBeenCalledWith(
				"ai-governance",
				expect.objectContaining({
					body: {
						action: "decide_intake",
						tenant_id: TEAM_ID,
						request_id: INTAKE_ID,
						decision: "approve",
						reason: "Fine for release notes",
					},
				}),
			),
		);
	});

	it("lists active exceptions with their remaining time and scope", async () => {
		setup("requests");
		const active = await screen.findByTestId("exception-active");
		expect(active).toHaveTextContent("Shell runner");
		expect(active).toHaveTextContent("3 days left");
		expect(active).toHaveTextContent("member@acme.example");
	});
});

describe("GovernanceChangeControlPage", () => {
	it("requires reviewing the diff before approving someone else's change", async () => {
		const mocks = setup("change", {
			invoke: (name, request) => {
				if (name === "ai-governance" && request?.body?.action === "policy_change_detail") {
					return {
						data: {
							ok: true,
							request: {},
							proposed: { policy: { command_default: "deny" } },
							current: { version: 3, policy: { command_default: "ask" } },
						},
						error: null,
					};
				}
				if (name === "ai-governance" && request?.body?.action === "decide_policy_change") {
					return { data: { ok: true, status: "approved", applied_version: 4 }, error: null };
				}
				return undefined;
			},
		});
		const cards = await screen.findAllByTestId("change-pending");
		const own = cards.find((card) => within(card).queryByText(/Save DLP policy/));
		expect(own && within(own).getByRole("button", { name: "Withdraw" })).toBeInTheDocument();
		const other = cards.find((card) => within(card).queryByText(/Publish runtime policy/));
		if (!other) throw new Error("missing card");
		fireEvent.change(within(other).getByLabelText(/Reason/), {
			target: { value: "Diff reviewed" },
		});
		expect(within(other).getByRole("button", { name: "Approve and apply" })).toBeDisabled();
		fireEvent.click(within(other).getByRole("button", { name: "Review diff" }));
		const diff = await within(other).findByTestId("policy-diff");
		expect(diff).toHaveTextContent('- "command_default": "ask"');
		expect(diff).toHaveTextContent('+ "command_default": "deny"');
		fireEvent.click(within(other).getByRole("button", { name: "Approve and apply" }));
		await waitFor(() =>
			expect(mocks.invoke).toHaveBeenCalledWith(
				"ai-governance",
				expect.objectContaining({
					body: {
						action: "decide_policy_change",
						tenant_id: TEAM_ID,
						request_id: CHANGE_ID,
						decision: "approve",
						reason: "Diff reviewed",
					},
				}),
			),
		);
		expect(await screen.findByText(/applied as version 4/)).toBeInTheDocument();
	});

	it("shows four-eyes state, and history with diffs and rollback through the existing restore", async () => {
		const mocks = setup("change", {
			invoke: (name, request) => {
				if (name !== "policy-management") return undefined;
				if (request?.body?.action === "history") {
					return {
						data: {
							ok: true,
							truncated: false,
							revisions: [
								{ version: 2, policy: { command_default: "deny" }, created_at: iso(-DAY) },
								{ version: 1, policy: { command_default: "ask" }, created_at: iso(-2 * DAY) },
							],
						},
						error: null,
					};
				}
				if (request?.body?.action === "read")
					return {
						data: { ok: true, version: 2, policy: { command_default: "deny" } },
						error: null,
					};
				if (request?.body?.action === "restore") {
					return {
						data: {
							ok: true,
							pending_approval: true,
							change_request_id: CHANGE_ID,
							status: "pending",
						},
						error: null,
					};
				}
				return undefined;
			},
		});
		expect(await screen.findByTestId("four-eyes-state")).toHaveTextContent("on");
		const history = await screen.findByTestId("revision-history");
		fireEvent.click(within(history).getByRole("button", { name: "Diff vs version 1" }));
		expect(within(history).getByTestId("policy-diff")).toHaveTextContent(
			'+ "command_default": "deny"',
		);
		fireEvent.click(within(history).getByRole("button", { name: "Roll back to version 1" }));
		await waitFor(() =>
			expect(mocks.invoke).toHaveBeenCalledWith(
				"policy-management",
				expect.objectContaining({
					body: { action: "restore", tenant_id: TEAM_ID, expected_version: 2, target_version: 1 },
				}),
			),
		);
		expect(await screen.findByText(/nothing was published/)).toBeInTheDocument();
	});
});
