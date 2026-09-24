/**
 * Shared mocking scaffolding for the dashboard regression suites.
 *
 * The dashboard pages call the Supabase client through chainable PostgREST
 * builders, so the mocks below model the two shapes the code depends on:
 * a thenable query chain (awaited, or finished with `.maybeSingle()`) and the
 * `{ data, error }` result it resolves to. `.maybeSingle()` returns the first
 * row, which is what PostgREST does for a single-object request.
 */

import { createHash, webcrypto } from "node:crypto";
import { vi } from "vitest";
import { supabase } from "../../lib/supabase";

export function policySourceHash(content: string): string {
	return createHash("sha256").update(content, "utf8").digest("hex");
}

export const TEAM_ID = "11111111-1111-4111-8111-111111111111";
export const ADMIN_USER_ID = "22222222-2222-4222-8222-222222222222";
export const MEMBER_USER_ID = "33333333-3333-4333-8333-333333333333";
export const VIEWER_USER_ID = "44444444-4444-4444-8444-444444444444";
export const POLICY_ROW_ID = "55555555-5555-4555-8555-555555555555";
const JOINED_AT = "2026-01-01T00:00:00.000Z";

/** The PGRST202 error an older deployment without the directory RPC returns. */
const MISSING_MEMBER_DIRECTORY: QueryError = {
	code: "PGRST202",
	message: "Could not find list_team_members_with_email in the schema cache",
};

const TEAM = {
	id: TEAM_ID,
	tenant_id: TEAM_ID,
	name: "Runtime team",
	github_org: null,
	gitlab_group: null,
	plan: "pro",
	created_at: JOINED_AT,
	updated_at: JOINED_AT,
};

type QueryError = { message: string; code?: string };
type QueryResult = { data: unknown; error: QueryError | null };
type MockFn = ReturnType<typeof vi.fn>;

interface MockQueryChain {
	select: MockFn;
	insert: MockFn;
	update: MockFn;
	delete: MockFn;
	eq: MockFn;
	neq: MockFn;
	in: MockFn;
	order: MockFn;
	limit: MockFn;
	gte: MockFn;
	lte: MockFn;
	maybeSingle: MockFn;
	single: MockFn;
	then: (
		resolve: (value: QueryResult) => unknown,
		reject?: (reason: unknown) => unknown,
	) => unknown;
}

export interface MockedSupabase {
	auth: {
		getSession: MockFn;
		getUser: MockFn;
		signOut: MockFn;
		signInWithOAuth: MockFn;
		signInWithOtp: MockFn;
		exchangeCodeForSession: MockFn;
		onAuthStateChange: MockFn;
	};
	functions: { invoke: MockFn };
	from: MockFn;
	rpc: MockFn;
}

export function mockedSupabase(): MockedSupabase {
	return supabase as unknown as MockedSupabase;
}

function firstRow(data: unknown): unknown {
	return Array.isArray(data) ? (data[0] ?? null) : (data ?? null);
}

function chainFor(result: QueryResult): MockQueryChain {
	const chain = {} as MockQueryChain;
	const self = () => chain;
	chain.select = vi.fn(self);
	chain.insert = vi.fn(self);
	chain.update = vi.fn(self);
	chain.delete = vi.fn(self);
	chain.eq = vi.fn(self);
	chain.neq = vi.fn(self);
	chain.in = vi.fn(self);
	chain.order = vi.fn(self);
	chain.limit = vi.fn(self);
	chain.gte = vi.fn(self);
	chain.lte = vi.fn(self);
	chain.maybeSingle = vi.fn(async () => ({ data: firstRow(result.data), error: result.error }));
	chain.single = vi.fn(async () => ({ data: firstRow(result.data), error: result.error }));
	chain.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject);
	return chain;
}

interface MemberFixture {
	id?: string;
	user_id: string;
	role: string;
	email?: string;
	avatar_url?: string | null;
	invited_by?: string | null;
}

export interface MockOptions {
	/** Role of the signed-in user in TEAM_ID. `null` means "no team at all". */
	role?: string | null;
	members?: MemberFixture[];
	/** Whether the tenant-scoped directory RPC can return member emails. */
	memberDirectory?: "missing" | "present" | QueryError;
	/** Error for the fallback membership select (used when projection is "missing"). */
	fallbackMembersError?: QueryError | null;
	membershipsError?: QueryError | null;
	/** Result of membership writes (role change / removal). */
	memberWriteRows?: unknown[] | null;
	memberWriteError?: QueryError | null;
	invite?: { data?: unknown; error?: QueryError | null };
	policyRow?: (Record<string, unknown> & { id?: string }) | null;
	policyReadError?: QueryError | null;
	policySaveResponse?: { data: unknown; error: unknown };
	user?: { id: string } | null;
	/** Session returned to protected route layouts. Defaults to an authenticated AAL2 fixture. */
	session?: Record<string, unknown> | null;
}

export interface InstalledMocks {
	teamMembers: MockQueryChain;
	teamPolicies: MockQueryChain;
	other: MockQueryChain;
	invoke: MockFn;
}

/**
 * Install a complete Supabase double for the dashboard surfaces.
 *
 * Defaults describe an older deployment without the member directory RPC,
 * so the UI uses its explicit ID-only fallback.
 */
export function installDashboardMocks(options: MockOptions = {}): InstalledMocks {
	const mocked = mockedSupabase();
	vi.resetAllMocks();
	vi.stubGlobal("crypto", webcrypto);

	// These helpers render routes that already passed `requireSessionLoader`, so
	// the default fixture is an authenticated, server-confirmed AAL2 session. A
	// test that exercises signed-out behaviour can still request `session: null`.
	mocked.auth.getSession.mockResolvedValue({
		data: {
			session:
				options.session === undefined
					? { user: { id: options.user?.id ?? ADMIN_USER_ID }, access_token: "fixture-session" }
					: options.session,
		},
		error: null,
	});
	mocked.auth.getUser.mockResolvedValue({
		data: { user: options.user === null ? null : (options.user ?? { id: ADMIN_USER_ID }) },
		error: null,
	});
	mocked.auth.signOut.mockResolvedValue({ error: null });
	mocked.auth.signInWithOAuth.mockResolvedValue({ data: { url: null }, error: null });
	mocked.auth.signInWithOtp.mockResolvedValue({ data: {}, error: null });
	mocked.auth.exchangeCodeForSession.mockResolvedValue({ data: {}, error: null });
	mocked.auth.onAuthStateChange.mockReturnValue({
		data: { subscription: { unsubscribe: vi.fn() } },
	});
	mocked.functions.invoke.mockImplementation(
		async (
			name: string,
			request?: {
				body?: {
					action?: string;
					tenant_id?: string;
					content?: string;
					expected_document?: { id: string; version: number; source_sha256?: string } | null;
				};
			},
		) => {
			if (name === "identity-security" && request?.body?.action === "bootstrap") {
				return {
					data: {
						ok: true,
						memberships: [
							{
								team_id: options.role === null ? null : TEAM_ID,
								tenant_id: options.role === null ? (options.user?.id ?? ADMIN_USER_ID) : TEAM_ID,
								require_mfa: true,
								current_assurance: "aal2",
								next_assurance: "aal2",
								access_allowed: true,
							},
						],
					},
					error: null,
				};
			}
			if (name === "identity-security" && request?.body?.action === "status") {
				return {
					data: {
						ok: true,
						tenant_id: request.body.tenant_id,
						require_mfa: true,
						current_assurance: "aal2",
						next_assurance: "aal2",
						access_allowed: true,
					},
					error: null,
				};
			}
			if (name === "policy-management") {
				const action = request?.body?.action;
				if (action === "save_document_draft") {
					if (options.policySaveResponse) return options.policySaveResponse;
					return {
						data: {
							ok: true,
							source: {
								id: request?.body?.expected_document?.id ?? POLICY_ROW_ID,
								version: (request?.body?.expected_document?.version ?? 0) + 1,
								source_sha256: policySourceHash(request?.body?.content ?? ""),
								updated_at: JOINED_AT,
							},
							runtime_policy: { mcp_unknown: "ask" },
							diagnostics: [],
							semantics: { precedence: ["deny", "ask", "allow"] },
							simulation: { action: "ask", source: "mcp_unknown", matched: null },
						},
						error: null,
					};
				}
				if (action === "history")
					return { data: { ok: true, revisions: [], truncated: false }, error: null };
				if (action === "adoption")
					return { data: { ok: true, agents: [], truncated: false }, error: null };
				if (action === "rollout_progress")
					return {
						data: {
							ok: true,
							status: "none",
							version: null,
							rollout_progress: { targeted: 0, current: 0, stale: 0, outdated: 0, unknown: 0 },
						},
						error: null,
					};
				if (action === "read") return { data: { ok: true, version: 0, policy: null }, error: null };
				if (action === "read_dlp_policy") {
					return {
						data: {
							ok: true,
							version: 0,
							policy: null,
							saved: false,
							delivered: false,
							delivery_status: "not_delivered",
						},
						error: null,
					};
				}
			}
			if (name === "team-invite" && request?.body?.action === "list") {
				return { data: { ok: true, invitations: [] }, error: null };
			}
			return options.invite ?? { data: { ok: true }, error: null };
		},
	);

	const role = options.role === undefined ? "admin" : options.role;
	const members: MemberFixture[] =
		options.members ??
		(role ? [{ id: "member-row-1", user_id: ADMIN_USER_ID, role, invited_by: null }] : []);
	const membershipRows = role
		? [
				{
					team_id: TEAM_ID,
					role,
					user_id: ADMIN_USER_ID,
					joined_at: JOINED_AT,
					teams: TEAM,
				},
			]
		: [];

	const memberRows = members.map((member) => ({
		id: member.id ?? `member-${member.user_id}`,
		user_id: member.user_id,
		role: member.role,
		invited_by: member.invited_by ?? null,
		joined_at: JOINED_AT,
	}));

	const withEmailRows = members.map((member, index) => ({
		...memberRows[index],
		email: member.email ?? `${member.user_id}@company.invalid`,
		avatar_url: member.avatar_url ?? null,
	}));

	const projection = options.memberDirectory ?? "missing";
	const projectionResult: QueryResult =
		typeof projection === "object"
			? { data: null, error: projection }
			: projection === "present"
				? { data: withEmailRows, error: null }
				: { data: null, error: MISSING_MEMBER_DIRECTORY };
	if (!mocked.rpc) mocked.rpc = vi.fn();
	mocked.rpc.mockImplementation(async (name: string) =>
		name === "list_team_members_with_email"
			? projectionResult
			: { data: null, error: { code: "PGRST202", message: "RPC not available" } },
	);
	const fallbackResult: QueryResult = {
		data: memberRows,
		error: options.fallbackMembersError ?? null,
	};

	const membershipWriteResult: QueryResult = {
		data:
			options.memberWriteRows === null
				? []
				: (options.memberWriteRows ?? [{ user_id: ADMIN_USER_ID }]),
		error: options.memberWriteError ?? null,
	};

	const teamMembers = chainFor({ data: membershipRows, error: options.membershipsError ?? null });
	const membershipWrites = chainFor(membershipWriteResult);
	teamMembers.insert = vi.fn(() => membershipWrites);
	teamMembers.update = vi.fn(() => membershipWrites);
	teamMembers.delete = vi.fn(() => membershipWrites);
	teamMembers.select = vi.fn((columns?: string) => {
		if (typeof columns === "string" && columns.includes("teams!")) {
			return chainFor({ data: membershipRows, error: options.membershipsError ?? null });
		}
		return chainFor(fallbackResult);
	});

	const policyRow = options.policyRow
		? {
				version: 1,
				source_sha256: policySourceHash(String(options.policyRow.content ?? "")),
				...options.policyRow,
			}
		: null;
	const policyLoad: QueryResult = {
		data: policyRow ? [policyRow] : [],
		error: options.policyReadError ?? null,
	};
	const policyProbe: QueryResult = {
		data: policyRow ? [{ id: policyRow.id ?? POLICY_ROW_ID }] : [],
		error: options.policyReadError ?? null,
	};
	const policyWrite: QueryResult = {
		data: null,
		error: { message: "Direct policy mutations are forbidden; use save_document_draft." },
	};
	const teamPolicies = chainFor(policyLoad);
	const policyWrites = chainFor(policyWrite);
	teamPolicies.select = vi.fn((columns?: string) =>
		chainFor(typeof columns === "string" && columns.includes("content") ? policyLoad : policyProbe),
	);
	teamPolicies.insert = vi.fn(() => policyWrites);
	teamPolicies.update = vi.fn(() => policyWrites);
	teamPolicies.delete = vi.fn(() => policyWrites);

	const other = chainFor({ data: [], error: null });

	mocked.from.mockImplementation((table: string) => {
		if (table === "team_members") return teamMembers;
		if (table === "team_policies") return teamPolicies;
		return chainFor({ data: [], error: null });
	});

	return { teamMembers, teamPolicies, other, invoke: mocked.functions.invoke };
}
