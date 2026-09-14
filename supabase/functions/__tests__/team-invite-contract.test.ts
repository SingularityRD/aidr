// Contract suite for the `team-invite` Edge Function (TEN-03 / AIDR-019).
//
// This file is named in the edge-function contract manifest
// (`docs/production-readiness/edge-function-contract-manifest.json`), so the
// browser-invoked `team-invite` function cannot ship without an executable
// contract.
//
// The suite drives the real handler with an injected service-role client - no
// network, no Supabase project, no SMTP - and asserts:
//
//   1. authentication: the bearer token, the identity barrier (revocation,
//      MFA assurance) and the shared configuration guard, each failing closed;
//   2. authorization: role, membership, tenant status and tenant scoping are
//      all re-derived on the server, never taken from the request body;
//   3. the invitation lifecycle: single-use secrets, token rotation on replay
//      and resend, revoke, and pending-only operations;
//   4. failure mapping: duplicate key -> 409, everything else -> 503, and no
//      path that reports a delivery that did not happen;
//   5. the SQL contract of `20260911000001_team_invitations.sql`.
//
// The runtime acceptance path (consume, expiry, replay) lives behind
// `oauth-callback` and is driven end-to-end by
// `supabase/functions/__tests__/oauth-callback-contract.test.ts`; the SQL
// guards that back it are asserted here.

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Edge Function imports Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The client must always arrive through
// `createTeamInviteHandler({ db })`; constructing a real one is a test bug.
vi.mock("npm:@supabase/supabase-js@2", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through TeamInviteDeps.db");
	},
}));

// The Edge runtime provides `Deno.env` and `Deno.serve`; the test process does
// not. The env stub delegates to `process.env` so `vi.stubEnv` drives the same
// values the production `runtimeEnv` reader would see, and `serve` is a no-op
// because the suite drives the exported handler factory directly.
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: {
		get: (name: string) => process.env[name],
	},
	serve: () => undefined,
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

function repoFile(...segments: string[]): string {
	return readFileSync(join(ROOT, ...segments), "utf8");
}

const migration = repoFile("supabase", "migrations", "20260911000001_team_invitations.sql");
const handlerSource = repoFile("supabase", "functions", "team-invite", "index.ts");
const lifecycleSource = repoFile("supabase", "functions", "team-invite", "lifecycle.ts");
const consumerSource = repoFile("packages", "dashboard", "src", "enterprise", "team-provider.tsx");

const mod = await import("../team-invite/index.ts");

const TEAM = "11111111-1111-4111-8111-111111111111";
const OTHER_TEAM = "22222222-2222-4222-8222-222222222222";
const USER = "33333333-3333-4333-8333-333333333333";
const INVITE = "44444444-4444-4444-8444-444444444444";
const FOREIGN_INVITE = "55555555-5555-4555-8555-555555555555";
const CONSUMED_INVITE = "77777777-7777-4777-8777-777777777777";
const EXPIRED_INVITE = "88888888-8888-4888-8888-888888888888";
const VALID_TOKEN = "valid-token";
const SERVICE_KEY = "service-role-key-must-never-be-logged";
const DASHBOARD = "https://app.aidr.example";

const NOW = new Date().toISOString();
const LATER = new Date(Date.now() + 86_400_000).toISOString();
const EARLIER = new Date(Date.now() - 86_400_000).toISOString();

const CREATE = { team_id: TEAM, email: "New.Member@Example.COM", role: "member" } as const;

function jwt(issuedAtSeconds: number): string {
	return `header.${Buffer.from(JSON.stringify({ iat: issuedAtSeconds })).toString("base64url")}.signature`;
}

function sha256Hex(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function secretOf(inviteUrl: unknown): string {
	return new URL(String(inviteUrl)).searchParams.get("invite") ?? "";
}

function post(body: unknown, headers: Record<string, string> = {}): Request {
	return new Request("https://project.supabase.co/functions/v1/team-invite", {
		method: "POST",
		headers: { Authorization: `Bearer ${VALID_TOKEN}`, "Content-Type": "application/json", ...headers },
		body: JSON.stringify(body),
	});
}

interface InvitationRow {
	id: string;
	tenant_id: string;
	email: string;
	role: string;
	token_hash: string;
	created_by: string;
	expires_at: string;
	accepted_at: string | null;
	created_at: string;
}

function invitationRow(overrides: Partial<InvitationRow> = {}): InvitationRow {
	return {
		id: INVITE,
		tenant_id: TEAM,
		email: "existing@example.com",
		role: "member",
		token_hash: sha256Hex("seed-secret"),
		created_by: USER,
		expires_at: LATER,
		accepted_at: null,
		created_at: NOW,
		...overrides,
	};
}

function rowById(rows: InvitationRow[], id: string): InvitationRow {
	const row = rows.find((candidate) => candidate.id === id);
	if (!row) throw new Error(`missing fixture row ${id}`);
	return row;
}

interface DbOptions {
	/** Membership rows keyed by tenant id; `null` means "not a member any more". */
	memberships?: Record<string, { role: string; expires_at: string | null } | null>;
	membershipError?: boolean;
	tenantStatus?: string;
	tenantError?: boolean;
	revokedBefore?: string | null;
	stateError?: boolean;
	policyError?: boolean;
	requireMfa?: boolean;
	assuranceLevel?: string;
	assuranceError?: boolean;
	authError?: boolean;
	invitations?: InvitationRow[];
	listError?: boolean;
	insertError?: { code?: string; message?: string } | null;
	insertThrows?: boolean;
	updateError?: { code?: string; message?: string } | null;
	rateCount?: number;
	rateLimitError?: boolean;
}

type QueryOperation = "select" | "insert" | "update";

interface QueryFilter {
	column: string;
	value: unknown;
	compare?: boolean;
}

interface QueryCall {
	table: string;
	operation: QueryOperation;
	filters: QueryFilter[];
	order: { column: string; ascending: boolean } | null;
	limit: number | null;
}

/**
 * A service-role client double shaped like the PostgREST builder the handler
 * chains. `team_invitations` is a real in-memory table with the migration's
 * unique `token_hash`, so token rotation, revocation and replay are observed
 * on stored state rather than on mock call arguments.
 */
function database(options: DbOptions = {}) {
	const memberships = options.memberships ?? { [TEAM]: { role: "owner", expires_at: null } };
	const invitations: InvitationRow[] = (options.invitations ?? []).map((row) => ({ ...row }));
	const queries: QueryCall[] = [];
	const rpcs: Array<{ name: string; args: Record<string, unknown> }> = [];
	let generated = 0;
	let rateCount = options.rateCount ?? 1;

	// A structurally valid JWT authenticates; the identity barrier - not the
	// token string - is what revokes a session.
	const getUser = vi.fn(async (token: string) =>
		!options.authError && (token === VALID_TOKEN || token.includes("."))
			? { data: { user: { id: USER } }, error: null }
			: { data: { user: null }, error: new Error("invalid_access_token") },
	);
	const assurance = vi.fn(async () => ({
		data: options.assuranceError ? null : { currentLevel: options.assuranceLevel ?? "aal2" },
		error: options.assuranceError ? new Error("auth_down") : null,
	}));

	function value(row: Record<string, unknown>, column: string): unknown {
		return row[column];
	}

	function matches(call: QueryCall, rows: InvitationRow[]): InvitationRow[] {
		return rows.filter((row) =>
			call.filters.every((filter) => {
				const candidate = value(row as unknown as Record<string, unknown>, filter.column);
				return filter.compare === true ? String(candidate) > String(filter.value) : candidate === filter.value;
			}),
		);
	}

	/** Tables the handler only ever reads one row from. */
	function singleRow(table: string, call: QueryCall): { data: unknown; error: unknown } {
		const scope = (column: string) => call.filters.find((filter) => filter.column === column)?.value;
		if (table === "identity_user_session_state") {
			return options.stateError
				? { data: null, error: new Error("db_down") }
				: { data: { revoked_before: options.revokedBefore ?? null }, error: null };
		}
		if (table === "tenant_identity_policies") {
			return options.policyError
				? { data: null, error: new Error("db_down") }
				: { data: { require_mfa: options.requireMfa ?? false }, error: null };
		}
		if (table === "tenant_members") {
			return options.membershipError
				? { data: null, error: new Error("db_down") }
				: { data: memberships[String(scope("tenant_id"))] ?? null, error: null };
		}
		if (table === "tenants") {
			return options.tenantError
				? { data: null, error: new Error("db_down") }
				: { data: { status: options.tenantStatus ?? "active" }, error: null };
		}
		if (table === "rate_limits") {
			return options.rateLimitError
				? { data: null, error: new Error("db_down") }
				: { data: { count: rateCount }, error: null };
		}
		return { data: null, error: null };
	}

	function invitationQuery(
		call: QueryCall,
		payload: Record<string, unknown>,
		terminal: "single" | "all",
	): { data: unknown; error: unknown } {
		if (call.operation === "update") {
			if (options.updateError) return { data: null, error: options.updateError };
			const updated = matches(call, invitations);
			for (const row of updated) Object.assign(row, payload);
			return { data: terminal === "single" ? (updated[0] ?? null) : updated, error: null };
		}
		if (call.operation === "insert") {
			if (options.insertThrows) throw new Error("connection reset by peer");
			if (options.insertError) return { data: null, error: options.insertError };
			const row: InvitationRow = {
				accepted_at: null,
				created_at: new Date().toISOString(),
				// UUID-shaped, like the migration's `gen_random_uuid()` default.
				id: `aaaaaaaa-0000-4000-8000-${String(++generated).padStart(12, "0")}`,
				...(payload as unknown as InvitationRow),
			};
			if (invitations.some((existing) => existing.token_hash === row.token_hash)) {
				return {
					data: null,
					error: { code: "23505", message: "duplicate key value violates unique constraint" },
				};
			}
			invitations.push(row);
			return { data: row, error: null };
		}
		// The ordered read is the `list` action; it is the only select that can
		// report a list-specific failure.
		if (options.listError && call.order) return { data: null, error: { message: "db_down" } };
		const selected = matches(call, invitations);
		const ordering = call.order;
		if (ordering) {
			selected.sort((left, right) => {
				const a = String(value(left as unknown as Record<string, unknown>, ordering.column));
				const b = String(value(right as unknown as Record<string, unknown>, ordering.column));
				return ordering.ascending ? a.localeCompare(b) : b.localeCompare(a);
			});
		}
		const limited = call.limit === null ? selected : selected.slice(0, call.limit);
		return { data: terminal === "single" ? (limited[0] ?? null) : limited, error: null };
	}

	function record(call: QueryCall): QueryCall {
		return {
			table: call.table,
			operation: call.operation,
			filters: call.filters.map((filter) => ({ column: filter.column, value: filter.value })),
			order: call.order,
			limit: call.limit,
		};
	}

	function table(name: string) {
		const call: QueryCall = { table: name, operation: "select", filters: [], order: null, limit: null };
		let payload: Record<string, unknown> = {};
		const builder = {
			select(_columns?: string) {
				return builder;
			},
			insert(values: Record<string, unknown>) {
				call.operation = "insert";
				payload = values;
				return builder;
			},
			update(values: Record<string, unknown>) {
				call.operation = "update";
				payload = values;
				return builder;
			},
			eq(column: string, columnValue: unknown) {
				call.filters.push({ column, value: columnValue });
				return builder;
			},
			is(column: string, columnValue: unknown) {
				call.filters.push({ column, value: columnValue });
				return builder;
			},
			gt(column: string, columnValue: unknown) {
				call.filters.push({ column, value: columnValue, compare: true });
				return builder;
			},
			order(column: string, opts?: { ascending?: boolean }) {
				call.order = { column, ascending: opts?.ascending ?? true };
				return builder;
			},
			limit(count: number) {
				call.limit = count;
				return builder;
			},
			async maybeSingle() {
				queries.push(record(call));
				return name === "team_invitations" ? invitationQuery(call, payload, "single") : singleRow(name, call);
			},
			then(onFulfilled: (result: unknown) => unknown, onRejected?: (reason: unknown) => unknown) {
				queries.push(record(call));
				const result = name === "team_invitations" ? invitationQuery(call, payload, "all") : singleRow(name, call);
				return Promise.resolve(result).then(onFulfilled, onRejected);
			},
		};
		return builder;
	}

	const db = {
		auth: { getUser, mfa: { getAuthenticatorAssuranceLevel: assurance } },
		from: (name: string) => table(name),
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcs.push({ name, args });
			if (name === "increment_rate_limit") {
				if (options.rateLimitError) return { data: null, error: { message: "db_down" } };
				rateCount += 1;
				return { data: null, error: null };
			}
			return { data: null, error: null };
		}),
	};

	return { db, queries, rpcs, invitations, getUser, assurance };
}

/** The exact lookup `accept_team_invitation(p_hash)` performs. */
function redeemable(rows: InvitationRow[], secret: string): InvitationRow[] {
	const hash = sha256Hex(secret);
	return rows.filter(
		(row) => row.token_hash === hash && row.accepted_at === null && Date.parse(row.expires_at) > Date.now(),
	);
}

function inviteQueries(queries: QueryCall[]): QueryCall[] {
	return queries.filter((call) => call.table === "team_invitations");
}

/** Build a handler bound to a fresh database double. */
function handlerWith(options: DbOptions = {}) {
	const fake = database(options);
	return {
		...fake,
		handle: mod.createTeamInviteHandler({ db: fake.db as never }),
	};
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", SERVICE_KEY);
	vi.stubEnv("AIDR_DASHBOARD_URL", DASHBOARD);
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.restoreAllMocks();
});

describe("team-invite authentication", () => {
	it("rejects a missing bearer token before any database or email work", async () => {
		const fake = handlerWith();
		const requests = [
			new Request("https://project.supabase.co/functions/v1/team-invite", {
				method: "POST",
				body: JSON.stringify(CREATE),
			}),
			post(CREATE, { Authorization: "" }),
			post(CREATE, { Authorization: "Basic dXNlcjpwYXNz" }),
		];
		for (const request of requests) {
			const response = await fake.handle(request);
			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ error: "missing_access_token" });
		}
		expect(fake.getUser).not.toHaveBeenCalled();
		expect(fake.queries).toEqual([]);
		expect(fake.rpcs).toEqual([]);
	});

	it("rejects an invalid access token before the identity barrier or any invitation read", async () => {
		const fake = handlerWith();
		const response = await fake.handle(post(CREATE, { Authorization: "Bearer rejected-token" }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_access_token" });
		expect(fake.queries).toEqual([]);
	});

	it("returns 401 for a session the identity barrier reports as revoked", async () => {
		// The token was issued in 2027; the session was revoked in 2030.
		const fake = handlerWith({ revokedBefore: "2030-01-01T00:00:00.000Z" });
		const response = await fake.handle(post(CREATE, { Authorization: `Bearer ${jwt(1_800_000_000)}` }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "session_revoked" });
		expect(fake.queries.map((call) => call.table)).toEqual(["identity_user_session_state"]);
		expect(fake.invitations).toEqual([]);
	});

	it("returns 403 mfa_required for an aal1 session in an MFA tenant, and admits aal2", async () => {
		const aal1 = handlerWith({ requireMfa: true, assuranceLevel: "aal1" });
		const refused = await aal1.handle(post(CREATE));
		expect(refused.status).toBe(403);
		expect(await refused.json()).toEqual({ error: "mfa_required" });
		expect(inviteQueries(aal1.queries)).toEqual([]);
		expect(aal1.invitations).toEqual([]);

		const aal2 = handlerWith({ requireMfa: true, assuranceLevel: "aal2" });
		expect((await aal2.handle(post(CREATE))).status).toBe(200);
		expect(aal2.invitations).toHaveLength(1);
	});

	it("returns 503, never a success, when the identity barrier cannot be read", async () => {
		const state = handlerWith({ stateError: true });
		const stateResponse = await state.handle(post(CREATE));
		expect(stateResponse.status).toBe(503);
		expect(await stateResponse.json()).toEqual({ error: "identity_state_unavailable" });

		const policy = handlerWith({ policyError: true });
		const policyResponse = await policy.handle(post(CREATE));
		expect(policyResponse.status).toBe(503);
		expect(await policyResponse.json()).toEqual({ error: "identity_policy_unavailable" });

		for (const fake of [state, policy]) {
			expect(fake.invitations).toEqual([]);
			expect(fake.rpcs).toEqual([]);
		}
	});

	it("fails closed with the shared configuration body before any database work", async () => {
		const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
		vi.stubEnv("AIDR_DASHBOARD_URL", "");
		const fake = handlerWith();
		const response = await fake.handle(post(CREATE));
		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "server_misconfigured", missing: ["AIDR_DASHBOARD_URL"] });
		expect(fake.getUser).not.toHaveBeenCalled();
		expect(fake.queries).toEqual([]);
		const logged = errors.mock.calls.map((call) => call.join(" ")).join("\n");
		expect(logged).toContain("AIDR_DASHBOARD_URL");
		expect(logged).not.toContain(SERVICE_KEY);
	});

	it("answers preflight and refuses an unlisted browser origin before authentication", async () => {
		const fake = handlerWith();
		const preflight = await fake.handle(
			new Request("https://project.supabase.co/functions/v1/team-invite", { method: "OPTIONS" }),
		);
		expect(preflight.status).toBe(200);
		expect(await preflight.json()).toEqual({ ok: true });

		const foreign = await fake.handle(post(CREATE, { Origin: "https://evil.example" }));
		expect(foreign.status).toBe(403);
		expect(await foreign.json()).toEqual({ error: "origin_not_allowed" });
		expect(fake.queries).toEqual([]);
	});

	it("accepts only POST", async () => {
		const fake = handlerWith();
		const response = await fake.handle(
			new Request("https://project.supabase.co/functions/v1/team-invite", {
				method: "GET",
				headers: { Authorization: `Bearer ${VALID_TOKEN}` },
			}),
		);
		expect(response.status).toBe(405);
		expect(await response.json()).toEqual({ error: "method_not_allowed" });
		expect(fake.queries).toEqual([]);
	});
});

describe("team-invite authorization", () => {
	const actions = [
		{ ...CREATE },
		{ team_id: TEAM, action: "revoke", invitation_id: INVITE },
		{ team_id: TEAM, action: "resend", invitation_id: INVITE },
		{ team_id: TEAM, action: "list" },
	];

	it("refuses a viewer or member for create, revoke, resend and list", async () => {
		for (const role of ["viewer", "member"]) {
			for (const body of actions) {
				const fake = handlerWith({ memberships: { [TEAM]: { role, expires_at: null } } });
				const response = await fake.handle(post(body));
				expect(response.status, `${role}/${JSON.stringify(body)}`).toBe(403);
				expect(await response.json()).toEqual({ error: "team_forbidden" });
				expect(inviteQueries(fake.queries)).toEqual([]);
				expect(fake.rpcs).toEqual([]);
			}
		}
	});

	it("refuses an expired membership and a membership that no longer exists", async () => {
		const expired = handlerWith({ memberships: { [TEAM]: { role: "owner", expires_at: EARLIER } } });
		expect((await expired.handle(post(CREATE))).status).toBe(403);

		const removed = handlerWith({ memberships: { [TEAM]: null } });
		expect((await removed.handle(post(CREATE))).status).toBe(403);

		for (const fake of [expired, removed]) {
			expect(fake.invitations).toEqual([]);
			expect(fake.rpcs).toEqual([]);
		}
	});

	it("refuses a tenant that is not active and fails closed when its status is unreadable", async () => {
		const suspended = handlerWith({ tenantStatus: "suspended" });
		const refused = await suspended.handle(post(CREATE));
		expect(refused.status).toBe(403);
		expect(await refused.json()).toEqual({ error: "tenant_inactive" });
		expect(suspended.invitations).toEqual([]);

		const unreadable = handlerWith({ tenantError: true });
		const unavailable = await unreadable.handle(post(CREATE));
		expect(unavailable.status).toBe(503);
		expect(await unavailable.json()).toEqual({ error: "authorization_unavailable" });
		expect(unreadable.invitations).toEqual([]);
	});

	it("ignores a client-supplied tenant id and stays on the verified membership tenant", async () => {
		const fake = handlerWith();
		const response = await fake.handle(post({ ...CREATE, team_id: OTHER_TEAM }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "team_forbidden" });
		expect(fake.invitations).toEqual([]);
		expect(inviteQueries(fake.queries)).toEqual([]);
		// The membership probe used the body's tenant, but the tenant is only
		// ever *named* by the caller: acting on it requires verified membership.
		const members = fake.queries.filter((call) => call.table === "tenant_members");
		expect(members).toHaveLength(1);
		expect(members[0]?.filters).toContainEqual({ column: "tenant_id", value: OTHER_TEAM });
	});

	it("scopes every invitation read and write to the verified tenant", async () => {
		const fake = handlerWith({
			invitations: [
				invitationRow(),
				invitationRow({
					id: FOREIGN_INVITE,
					tenant_id: OTHER_TEAM,
					token_hash: sha256Hex("foreign-secret"),
				}),
			],
		});

		// A revoke that names another tenant's invitation id matches nothing.
		const revoke = await fake.handle(post({ team_id: TEAM, action: "revoke", invitation_id: FOREIGN_INVITE }));
		expect(revoke.status).toBe(404);
		const foreign = rowById(fake.invitations, FOREIGN_INVITE);
		expect(foreign.expires_at).toBe(LATER);
		expect(redeemable([foreign], "foreign-secret")).toHaveLength(1);

		const list = await fake.handle(post({ team_id: TEAM, action: "list" }));
		expect(list.status).toBe(200);
		const listed = (await list.json()) as { invitations: Array<{ id: string }> };
		expect(listed.invitations.map((row) => row.id)).toEqual([INVITE]);

		for (const call of inviteQueries(fake.queries)) {
			expect(call.filters, `${call.operation} without tenant scope`).toContainEqual({
				column: "tenant_id",
				value: TEAM,
			});
		}
	});

	it("refuses an unreadable membership or invitation list instead of inventing an answer", async () => {
		const membership = handlerWith({ membershipError: true });
		const refused = await membership.handle(post(CREATE));
		expect(refused.status).toBe(503);
		expect(await refused.json()).toEqual({ error: "authorization_unavailable" });

		const listed = handlerWith({ listError: true });
		const failed = await listed.handle(post({ team_id: TEAM, action: "list" }));
		expect(failed.status).toBe(503);
		expect(await failed.json()).toEqual({ error: "invitation_list_failed" });
	});
});

describe("team invitation lifecycle", () => {
	it("creates exactly one single-use secret and stores only its digest", async () => {
		const fake = handlerWith();
		const response = await fake.handle(post(CREATE));
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(Object.keys(body).sort()).toEqual([
			"delivery",
			"expires_at",
			"invitation_id",
			"invite_url",
			"ok",
		]);
		expect(body).toMatchObject({ ok: true, delivery: "manual" });

		const secret = secretOf(body.invite_url);
		expect(secret).toMatch(/^[0-9a-f]{64}$/);
		expect(body.invite_url).toBe(`${DASHBOARD}/enterprise?invite=${secret}`);

		expect(fake.invitations).toHaveLength(1);
		const row = fake.invitations[0] as InvitationRow;
		expect(row.token_hash).toBe(sha256Hex(secret));
		expect(row.token_hash).not.toContain(secret);
		expect(row).toMatchObject({
			tenant_id: TEAM,
			email: "new.member@example.com",
			role: "member",
			created_by: USER,
			accepted_at: null,
		});
		expect(Date.parse(row.expires_at)).toBeGreaterThan(Date.now());
		expect(redeemable(fake.invitations, secret)).toHaveLength(1);
		// The secret appears exactly once, inside the link, and the stored digest
		// never travels back to the browser.
		expect(JSON.stringify(body).split(secret)).toHaveLength(2);
		expect(JSON.stringify(body)).not.toContain(row.token_hash);
	});

	it("is idempotent for a repeated identical request id: one pending row, one live link", async () => {
		const fake = handlerWith();
		const request = { ...CREATE, request_id: "req-4f21c8de01" };
		const first = await fake.handle(post(request));
		const second = await fake.handle(post(request));
		expect([first.status, second.status]).toEqual([200, 200]);

		const firstBody = (await first.json()) as Record<string, unknown>;
		const secondBody = (await second.json()) as Record<string, unknown>;
		expect(Object.keys(secondBody).sort()).toEqual([
			"delivery",
			"expires_at",
			"invitation_id",
			"invite_url",
			"ok",
		]);
		expect(secondBody.invitation_id).toBe(firstBody.invitation_id);
		expect(fake.invitations).toHaveLength(1);

		const firstSecret = secretOf(firstBody.invite_url);
		const secondSecret = secretOf(secondBody.invite_url);
		expect(secondSecret).not.toBe(firstSecret);
		expect(redeemable(fake.invitations, firstSecret)).toHaveLength(0);
		expect(redeemable(fake.invitations, secondSecret)).toHaveLength(1);
		expect(JSON.stringify(secondBody)).not.toContain(firstSecret);
	});

	it("treats a different request (same recipient, different role) as a new invitation", async () => {
		const fake = handlerWith();
		expect((await fake.handle(post({ ...CREATE, role: "viewer" }))).status).toBe(200);
		expect((await fake.handle(post({ ...CREATE, role: "admin" }))).status).toBe(200);
		expect(fake.invitations.map((row) => row.role).sort()).toEqual(["admin", "viewer"]);
	});

	it("rotates the token on resend so the previous token stops working", async () => {
		const fake = handlerWith();
		const created = (await (await fake.handle(post(CREATE))).json()) as Record<string, unknown>;
		const createdSecret = secretOf(created.invite_url);

		const response = await fake.handle(
			post({ team_id: TEAM, action: "resend", invitation_id: created.invitation_id }),
		);
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(Object.keys(body).sort()).toEqual([
			"delivery",
			"email",
			"expires_at",
			"invitation_id",
			"invite_url",
			"ok",
			"role",
		]);
		expect(body).toMatchObject({
			ok: true,
			delivery: "manual",
			invitation_id: created.invitation_id,
			email: "new.member@example.com",
			role: "member",
		});

		const rotatedSecret = secretOf(body.invite_url);
		expect(rotatedSecret).not.toBe(createdSecret);
		expect(fake.invitations).toHaveLength(1);
		expect((fake.invitations[0] as InvitationRow).token_hash).toBe(sha256Hex(rotatedSecret));
		expect(redeemable(fake.invitations, createdSecret)).toHaveLength(0);
		expect(redeemable(fake.invitations, rotatedSecret)).toHaveLength(1);
	});

	it("keeps resend and revoke pending-only and never reopens a dead link", async () => {
		const fake = handlerWith({
			invitations: [
				invitationRow({
					id: CONSUMED_INVITE,
					accepted_at: NOW,
					token_hash: sha256Hex("used-secret"),
				}),
				invitationRow({ id: EXPIRED_INVITE, expires_at: EARLIER, token_hash: sha256Hex("old-secret") }),
				invitationRow({
					id: FOREIGN_INVITE,
					tenant_id: OTHER_TEAM,
					token_hash: sha256Hex("foreign-secret"),
				}),
			],
		});

		// Revocation needs a live invitation: consumed, expired, foreign and
		// unknown ids all stay pending-only.
		for (const invitationId of [CONSUMED_INVITE, EXPIRED_INVITE, FOREIGN_INVITE, INVITE]) {
			const response = await fake.handle(post({ team_id: TEAM, action: "revoke", invitation_id: invitationId }));
			expect(response.status, `revoke/${invitationId}`).toBe(404);
			expect(await response.json()).toEqual({ error: "invitation_not_pending" });
		}
		// A consumed, foreign or unknown invitation cannot be re-issued either.
		for (const invitationId of [CONSUMED_INVITE, FOREIGN_INVITE, INVITE]) {
			const response = await fake.handle(post({ team_id: TEAM, action: "resend", invitation_id: invitationId }));
			expect(response.status, `resend/${invitationId}`).toBe(404);
			expect(await response.json()).toEqual({ error: "invitation_not_pending" });
		}

		// Nothing rotated, nothing revoked, nothing reopened.
		expect(rowById(fake.invitations, CONSUMED_INVITE).token_hash).toBe(sha256Hex("used-secret"));
		expect(rowById(fake.invitations, EXPIRED_INVITE).token_hash).toBe(sha256Hex("old-secret"));
		const foreign = rowById(fake.invitations, FOREIGN_INVITE);
		expect(foreign.token_hash).toBe(sha256Hex("foreign-secret"));
		expect(foreign.expires_at).toBe(LATER);

		// An expired but unaccepted row may still be re-issued; that rotates the
		// token and moves the expiry forward, it does not reopen the old link.
		const reissued = await fake.handle(
			post({ team_id: TEAM, action: "resend", invitation_id: EXPIRED_INVITE }),
		);
		expect(reissued.status).toBe(200);
		const body = (await reissued.json()) as Record<string, unknown>;
		const expired = rowById(fake.invitations, EXPIRED_INVITE);
		expect(expired.token_hash).toBe(sha256Hex(secretOf(body.invite_url)));
		expect(expired.token_hash).not.toBe(sha256Hex("old-secret"));
		expect(Date.parse(expired.expires_at)).toBeGreaterThan(Date.now());
		expect(redeemable(fake.invitations, "old-secret")).toHaveLength(0);
	});

	it("revokes an invitation once and refuses the replay without changing state", async () => {
		const fake = handlerWith();
		const created = (await (await fake.handle(post(CREATE))).json()) as Record<string, unknown>;
		const secret = secretOf(created.invite_url);

		const revoke = await fake.handle(
			post({ team_id: TEAM, action: "revoke", invitation_id: created.invitation_id }),
		);
		expect(revoke.status).toBe(200);
		expect(await revoke.json()).toEqual({ ok: true, invitation_id: created.invitation_id });

		const row = fake.invitations[0] as InvitationRow;
		const revokedAt = row.expires_at;
		expect(Date.parse(revokedAt)).toBeLessThanOrEqual(Date.now());
		expect(redeemable(fake.invitations, secret)).toHaveLength(0);

		const replay = await fake.handle(
			post({ team_id: TEAM, action: "revoke", invitation_id: created.invitation_id }),
		);
		expect(replay.status).toBe(404);
		expect(await replay.json()).toEqual({ error: "invitation_not_pending" });
		expect(fake.invitations).toHaveLength(1);
		expect(row.expires_at).toBe(revokedAt);
	});
});

describe("team-invite failure mapping", () => {
	it("maps a duplicate-key conflict on an existing invitation to the documented 409", async () => {
		const creating = handlerWith({ insertError: { code: "23505", message: "duplicate key value" } });
		const created = await creating.handle(post(CREATE));
		expect(created.status).toBe(409);
		expect(await created.json()).toEqual({ error: "invitation_conflict" });

		const rotating = handlerWith({
			invitations: [invitationRow({ email: "new.member@example.com" })],
			updateError: { code: "23505", message: "duplicate key value" },
		});
		const replayed = await rotating.handle(post(CREATE));
		expect(replayed.status).toBe(409);
		expect(await replayed.json()).toEqual({ error: "invitation_conflict" });

		const resending = handlerWith({ updateError: { code: "23505", message: "duplicate key value" } });
		const resent = await resending.handle(
			post({ team_id: TEAM, action: "resend", invitation_id: INVITE }),
		);
		expect(resent.status).toBe(409);
		expect(await resent.json()).toEqual({ error: "invitation_conflict" });
	});

	it("returns 503 for any other database failure and never reports ok", async () => {
		const failing = handlerWith({ insertError: { code: "42P01", message: "relation does not exist" } });
		const response = await failing.handle(post(CREATE));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "invitation_create_failed" });

		const throwing = handlerWith({ insertThrows: true });
		const thrown = await throwing.handle(post(CREATE));
		expect(thrown.status).toBe(503);
		const body = (await thrown.json()) as Record<string, unknown>;
		expect(body).toEqual({ error: "invitation_unavailable" });
		expect(body.ok).toBeUndefined();
	});

	it("never reports a delivery that did not happen", async () => {
		const fake = handlerWith();
		const created = await fake.handle(post(CREATE));
		const body = (await created.json()) as Record<string, unknown>;
		expect(body.delivery).toBe("manual");
		for (const claim of ["sent", "delivered", "delivered_at", "email_sent", "message_id"]) {
			expect(Object.keys(body)).not.toContain(claim);
		}
		expect(JSON.stringify(body)).not.toMatch(/"(?:sent|delivered)":\s*true/);

		// There is no mail transport to fail: the function hands the operator a
		// link and says so, so no SMTP failure can be swallowed into a success.
		expect(handlerSource).not.toMatch(/smtp|sendgrid|mailgun|postmark|nodemailer|sendmail/i);
		expect(handlerSource).toContain('delivery: "manual"');

		// The same holds for a failure raised after the secret was minted.
		const failing = handlerWith({ insertThrows: true });
		const failed = await failing.handle(post(CREATE));
		expect(failed.status).toBe(503);
		expect(JSON.stringify(await failed.json())).not.toContain('"ok":true');
	});

	it("fails closed when the rate limiter is unavailable or exhausted", async () => {
		const unavailable = handlerWith({ rateLimitError: true });
		const refused = await unavailable.handle(post(CREATE));
		expect(refused.status).toBe(503);
		expect(await refused.json()).toEqual({ error: "rate_limit_unavailable" });

		const exhausted = handlerWith({ rateCount: 10 });
		const limited = await exhausted.handle(post(CREATE));
		expect(limited.status).toBe(429);
		expect(await limited.json()).toEqual({ error: "rate_limited" });
		expect(exhausted.invitations).toEqual([]);

		// The budget is per actor, not per tenant or global.
		const scoped = handlerWith();
		await scoped.handle(post(CREATE));
		expect(scoped.rpcs[0]?.args.p_key).toBe(`team-invite:${USER}`);
		const limits = scoped.queries.filter((call) => call.table === "rate_limits");
		expect(limits[0]?.filters).toContainEqual({ column: "key", value: `team-invite:${USER}` });
	});

	it("rejects a malformed body before any identity or invitation work", async () => {
		const fake = handlerWith();
		for (const body of [
			{},
			{ team_id: "not-a-uuid", email: "a@b.example", role: "member" },
			{ team_id: TEAM, email: "not-an-email", role: "member" },
			{ team_id: TEAM, email: "a@b.example", role: "owner" },
			{ team_id: TEAM, action: "delete" },
		]) {
			const response = await fake.handle(post(body));
			expect(response.status, JSON.stringify(body)).toBe(400);
		}
		const malformed = new Request("https://project.supabase.co/functions/v1/team-invite", {
			method: "POST",
			headers: { Authorization: `Bearer ${VALID_TOKEN}` },
			body: "{not json",
		});
		expect((await fake.handle(malformed)).status).toBe(400);
		expect(fake.queries).toEqual([]);
	});
});

describe("team invitation SQL contract", () => {
	it("keeps invitation rows and the acceptance RPC out of every browser role's reach", () => {
		expect(migration).toContain("alter table public.team_invitations enable row level security");
		expect(migration).toContain("revoke all on public.team_invitations from anon, authenticated");
		expect(migration).toContain("grant select, insert, update on public.team_invitations to service_role");
		expect(migration).not.toMatch(
			/grant [^;]*on public\.team_invitations[^;]*to (?:public|anon|authenticated)/,
		);
		// PostgreSQL grants no table privileges to `public` by default, so
		// revoking the browser roles is the operative restriction; the RPC below
		// is revoked from `public` explicitly.
		expect(migration).toContain(
			"revoke all on function public.accept_team_invitation(text, uuid) from public, anon, authenticated",
		);
		expect(migration).toContain(
			"grant execute on function public.accept_team_invitation(text, uuid) to service_role",
		);
		expect(migration).not.toMatch(
			/grant execute on function public\.accept_team_invitation[^;]*to (?:public|anon|authenticated)/,
		);
	});

	it("re-checks the recipient, the issuing admin, the tenant and the row inside the accepting transaction", () => {
		const rpc = migration.split("create function public.accept_team_invitation(")[1] ?? "";
		expect(rpc).toContain("security definer");
		expect(rpc).toContain("set search_path = public, pg_temp");
		expect(rpc).toContain(
			"select * into invite from public.team_invitations where token_hash = p_hash for update;",
		);
		expect(rpc).toContain("email_confirmed_at is not null");
		expect(rpc).toContain("verified_email <> invite.email");
		expect(rpc).toContain("invite.accepted_at is not null or invite.expires_at <= now()");
		expect(rpc).toContain("raise exception 'invalid_invitation'");
		expect(rpc).toContain("m.role in ('owner','admin')");
		expect(rpc).toContain("(m.expires_at is null or m.expires_at > now())");
		expect(rpc).toContain("t.status = 'active'");
		expect(rpc).toContain("raise exception 'invitation_revoked'");
	});

	it("stores only a token digest bound to a tenant, recipient, role and expiry", () => {
		expect(migration).toContain("tenant_id uuid not null references public.tenants(id)");
		expect(migration).toContain("email text not null");
		expect(migration).toContain("role text not null check(role in ('admin', 'member', 'viewer'))");
		expect(migration).toContain("token_hash text not null unique");
		expect(migration).toContain("created_by uuid not null references auth.users(id)");
		expect(migration).toContain("expires_at timestamptz not null default now() + interval '7 days'");
		expect(migration).toContain("accepted_at timestamptz");
		// Acceptance consumes the row once and never upgrades an existing member.
		expect(migration).toContain(
			"insert into public.team_members(team_id, tenant_id, user_id, role, invited_by)",
		);
		expect(migration).toContain("on conflict(team_id, user_id) do nothing");
		expect(migration).toContain("update public.team_invitations set accepted_at = now() where id = invite.id");
		expect(migration).toContain("'member.invitation_accepted'");
	});
});

describe("team-invite handler source contract", () => {
	it("validates configuration through the shared helper and never reads platform secrets itself", () => {
		expect(handlerSource).toContain('from "../_shared/config.ts"');
		expect(handlerSource).toContain("loadConfig(runtimeEnv, REQUIRED_ENV)");
		expect(handlerSource).toContain("configFailure(");
		expect(handlerSource).toContain("handleCors(req)");
		expect(handlerSource).toContain("corsJson(req");
		expect(handlerSource).toContain('from "../_shared/identity-barrier.ts"');
		expect(handlerSource).toContain("checkIdentityBarrier(db, token, auth.user.id, command.teamId)");
		expect(handlerSource).not.toMatch(/Deno\.env\.get\(\s*"(?:SUPABASE_URL|SUPABASE_SERVICE_ROLE_KEY)"\s*\)/);
		expect(handlerSource).not.toContain('?? ""');
		// The configuration guard runs at request time, before any client work.
		const guard = handlerSource.indexOf("loadConfig(runtimeEnv,");
		expect(guard).toBeGreaterThan(handlerSource.indexOf("handleCors(req)"));
		expect(guard).toBeLessThan(handlerSource.indexOf("deps.db ??"));
	});

	it("requires an owner/admin membership and hashes the secret before it is stored", () => {
		expect(handlerSource).toContain('from("tenant_members")');
		expect(handlerSource).toContain('["owner", "admin"].includes(member?.role)');
		expect(handlerSource).toContain("membershipActive(member)");
		expect(handlerSource).toContain('from("tenants")');
		expect(handlerSource).toContain('tenant?.status !== "active"');
		expect(handlerSource).toContain("invitationSecret()");
		expect(handlerSource).toContain("await sha256(secret)");
		expect(handlerSource).toContain("token_hash: tokenHash");
		expect(handlerSource).not.toMatch(/token_hash:\s*secret\b/);
	});

	it("rotates pending tokens instead of minting a second live link", () => {
		// The rotation always rewrites the digest, so the previous link dies.
		expect(lifecycleSource).toContain(
			"update({ token_hash: tokenHash, expires_at: invitationExpiry(now), created_by: actorId })",
		);
		expect(lifecycleSource).toContain('.is("accepted_at", null)');
		// Revocation is an expiry, which the acceptance RPC refuses.
		expect(lifecycleSource).toContain("update({ expires_at: now })");
		expect(lifecycleSource).toContain('.gt("expires_at", now)');
		expect(lifecycleSource).toContain('.eq("tenant_id", teamId)');
	});
});

describe("dashboard consumer contract", () => {
	it("confirms with the service before it claims an invitation exists", () => {
		expect(consumerSource).toContain('supabase.functions.invoke("team-invite", {');
		expect(consumerSource).toContain("body: { team_id: currentTeam.id, email, role },");
		expect(consumerSource).toContain("if (response?.ok !== true) {");
		expect(consumerSource).toContain("did not confirm the invitation");
		expect(consumerSource).toContain("No invitation was sent");
		const confirmation = consumerSource.indexOf("if (response?.ok !== true)");
		const returned = consumerSource.indexOf("return inviteUrl.toString();");
		expect(confirmation).toBeGreaterThan(-1);
		expect(returned).toBeGreaterThan(confirmation);
	});

	it("only ever surfaces a link this deployment issued for the enterprise route", () => {
		expect(consumerSource).toContain('if (typeof response.invite_url !== "string")');
		expect(consumerSource).toContain("inviteUrl.origin !== window.location.origin");
		expect(consumerSource).toContain('inviteUrl.pathname !== "/enterprise"');
	});

	it("never renders a delivery claim the service never made", () => {
		// The phrase exists exactly once, in the comment that forbids it as a
		// user-visible claim; a second occurrence would be a UI string.
		expect(consumerSource.split("Invitation sent")).toHaveLength(2);
		expect(consumerSource).toContain('// reported as "Invitation sent".');
	});
});
