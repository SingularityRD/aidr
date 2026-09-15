// Contract suite for the `policy-management` Edge Function.
//
// This file is named in the dashboard contract manifest
// (`docs/production-readiness/edge-function-contract-manifest.json`) so a
// browser-invoked Edge Function cannot ship without an executable contract. The
// companion `policy-document.test.ts` covers the *shared compiler's* semantics;
// this suite covers the handler that authenticates, authorizes, bounds and
// persists whatever reaches that compiler.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Edge Function imports Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The injected client is the only client the
// suite ever drives; `createClient` is a tripwire, not a fallback.
vi.mock("npm:@supabase/supabase-js@2", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through PolicyManagementDeps.db");
	},
}));

// DLP uses a generated copy of the core schema with the same pinned Zod bytes.
vi.mock("npm:zod@3.25.76", async () => import("../../../packages/core/node_modules/zod/index.js"));

// Stored policy documents are parsed with Deno's `npm:yaml@2.8.3`. The
// repository already vendors that exact version for `@singularityrd/aidr-core`,
// so the suite binds the Deno-only specifier to those bytes: the parser stays
// real, only the specifier is redirected.
vi.mock("npm:yaml@2.8.3", async () => {
	const real = (await import("../../../packages/core/node_modules/yaml/dist/index.js")) as {
		parseDocument?: unknown;
		default?: { parseDocument?: unknown };
	};
	const parseDocument = real.parseDocument ?? real.default?.parseDocument;
	if (typeof parseDocument !== "function") throw new Error("the real yaml parser is unavailable");
	return { parseDocument };
});

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
const HANDLER_URL = "https://project.supabase.co/functions/v1/policy-management";
const HANDLER_SOURCE = readFileSync(
	join(ROOT, "supabase", "functions", "policy-management", "index.ts"),
	"utf8",
);
const ROLLOUT_MIGRATION = readFileSync(
	join(ROOT, "supabase", "migrations", "20260911000004_policy_rollout.sql"),
	"utf8",
);
const STAGE_CAS_MIGRATION = readFileSync(
	join(ROOT, "supabase", "migrations", "20260913000002_policy_stage_cas.sql"),
	"utf8",
);

const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "33333333-3333-4333-8333-333333333333";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const NOW = "2026-09-13T00:00:00.000Z";

/** A policy every shared validator accepts. */
const POLICY: Record<string, unknown> = {
	command_default: "ask",
	file_default: "allow",
	mcp_default: "ask",
	mcp_allow_servers: ["github"],
	mcp_deny_tools: ["vault.read"],
};
/** Another tenant's policy, distinguishable in any response body. */
const OTHER_POLICY_MARKER = "other-tenant-only";
const OTHER_POLICY: Record<string, unknown> = {
	command_default: "deny",
	mcp_allow_servers: [OTHER_POLICY_MARKER],
};

const POLICY_DOCUMENT_LINES = [
	'version: "1.0"',
	"default_action: ask",
	"unknown_action: deny",
	"category_defaults:",
	"  command: deny",
	"rules:",
	"  - name: allow read",
	"    condition:",
	"      mcp_tool: github.read",
	"    action: allow",
	"    priority: 20",
];

const MUTATION_RPCS = new Set(["publish_runtime_policy", "stage_runtime_policy", "save_policy_document_draft"]);
const DOCUMENT_ID = "55555555-5555-4555-8555-555555555555";
const sourceHash = (content: string) => createHash("sha256").update(content, "utf8").digest("hex");
const VALID_DRAFT = POLICY_DOCUMENT_LINES.join("\n");
const EXPECTED_DOCUMENT = { id: DOCUMENT_ID, version: 7, source_sha256: sourceHash(VALID_DRAFT) };
function draftBody(overrides: Row = {}): Row {
	return { action: "save_document_draft", tenant_id: TENANT, content: VALID_DRAFT, expected_document: null, ...overrides };
}
/** Tables whose rows are a tenant's policy, fleet or receipts (never config). */
const POLICY_SCOPED_TABLES = new Set([
	"tenant_runtime_policies",
	"runtime_policy_revisions",
	"agents",
	"agent_policy_receipts",
	"agent_policy_assignments",
]);

type Row = Record<string, unknown>;

interface QueryRecord {
	table: string;
	filters: Row;
}

interface RpcRecord {
	name: string;
	args: Row;
}

interface DbOptions {
	user?: { id: string } | null;
	authError?: boolean;
	authThrow?: boolean;
	memberships?: Array<{ tenant_id: string; role: string; expires_at: string | null }>;
	memberError?: boolean;
	tenantStatus?: string | null;
	tenantError?: boolean;
	sessionError?: boolean;
	revokedBefore?: string | null;
	requireMfa?: boolean;
	identityPolicyError?: boolean;
	assuranceLevel?: string;
	assuranceError?: boolean;
	policies?: Record<string, Row | null>;
	policyReadError?: boolean;
	revisions?: Row[];
	revisionsError?: boolean;
	teamPolicies?: Row[];
	teamPoliciesError?: boolean;
	agents?: Row[];
	rateLimit?: "allow" | "deny" | "unavailable" | "throwing" | "malformed";
	rpc?: (name: string, args: Row) => { data: unknown; error: unknown };
}

/**
 * An honest, PostgREST-shaped fake.
 *
 * Policy rows are keyed by tenant and filtered by the tenant the handler asks
 * for, so a handler that trusted a raw body tenant would actually receive that
 * tenant's row and fail the isolation assertions below. The same applies to
 * `runtime_policy_revisions`: another tenant's revision is reachable only if the
 * handler asks for it with that tenant's id.
 */
function database(options: DbOptions = {}) {
	const rpcCalls: RpcRecord[] = [];
	const queries: QueryRecord[] = [];
	const draftRows = (options.teamPolicies ?? []).map((row) => ({ ...row }));
	const draftWrites: Row[] = [];
	const memberships = options.memberships ?? [{ tenant_id: TENANT, role: "owner", expires_at: null }];
	const policies = options.policies ?? {
		[TENANT]: { version: 3, policy: POLICY, updated_at: NOW },
		[OTHER_TENANT]: { version: 9, policy: OTHER_POLICY, updated_at: NOW },
	};
	const revisions = options.revisions ?? [
		{ tenant_id: TENANT, version: 3, policy: POLICY, created_at: NOW },
		{ tenant_id: OTHER_TENANT, version: 9, policy: OTHER_POLICY, created_at: NOW },
	];

	function singleRow(table: string, filters: Row): { data: unknown; error: unknown } {
		if (table === "identity_user_session_state") {
			return {
				data: { revoked_before: options.revokedBefore ?? null },
				error: options.sessionError ? new Error("db_down") : null,
			};
		}
		if (table === "tenant_identity_policies") {
			return {
				data: { require_mfa: options.requireMfa === true },
				error: options.identityPolicyError ? new Error("db_down") : null,
			};
		}
		if (table === "tenant_members") {
			if (options.memberError) return { data: null, error: new Error("db_down") };
			return { data: memberships.find((row) => row.tenant_id === filters.tenant_id) ?? null, error: null };
		}
		if (table === "tenants") {
			// `undefined` means the row exists and is active; `null` means the
			// tenant row is missing entirely.
			const status = options.tenantStatus === undefined ? "active" : options.tenantStatus;
			return {
				data: status === null ? null : { status },
				error: options.tenantError ? new Error("db_down") : null,
			};
		}
		if (table === "tenant_runtime_policies") {
			return {
				data: policies[String(filters.tenant_id)] ?? null,
				error: options.policyReadError ? new Error("db_down") : null,
			};
		}
		if (table === "runtime_policy_revisions") {
			const rows = revisions.filter((row) => row.tenant_id === filters.tenant_id);
			const match = filters.version === undefined ? rows[0] : rows.find((row) => row.version === filters.version);
			return { data: match ?? null, error: options.revisionsError ? new Error("db_down") : null };
		}
		return { data: null, error: null };
	}

	function listRows(table: string, filters: Row): { data: unknown; error: unknown } {
		const failed = options.revisionsError ? new Error("db_down") : null;
		if (table === "runtime_policy_revisions") {
			const rows = revisions
				.filter((row) => row.tenant_id === filters.tenant_id)
				.sort((a, b) => Number(b.version) - Number(a.version));
			return { data: rows, error: failed };
		}
		if (table === "team_policies") {
			return {
				data: (options.teamPolicies ?? []).filter((row) => row.team_id === filters.team_id),
				error: options.teamPoliciesError ? new Error("db_down") : null,
			};
		}
		if (table === "agents") {
			return { data: (options.agents ?? []).filter((row) => row.tenant_id === filters.tenant_id), error: null };
		}
		return { data: [], error: null };
	}

	const builder = (table: string) => {
		const filters: Row = {};
		// The same object is mutated by every `.eq()`/`.gt()`/`.in()` and is
		// retained by reference, so a test sees the final filter set.
		queries.push({ table, filters });
		const query = {
			select: () => query,
			eq: (column: string, value: unknown) => {
				filters[column] = value;
				return query;
			},
			gt: (column: string, value: unknown) => {
				filters[column] = value;
				return query;
			},
			in: (column: string, value: unknown) => {
				filters[column] = value;
				return query;
			},
			order: () => query,
			limit: () => query,
			maybeSingle: async () => singleRow(table, filters),
			then: (resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) =>
				Promise.resolve(listRows(table, filters)).then(resolve, reject),
		};
		return query;
	};

	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => {
				if (options.authThrow) throw new Error("auth_down");
				const user = options.user === undefined ? { id: USER } : options.user;
				return user && !options.authError && token === "valid-token"
					? { data: { user }, error: null }
					: { data: { user: null }, error: new Error("invalid_token") };
			}),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () =>
					options.assuranceError
						? { data: null, error: new Error("auth_down") }
						: { data: { currentLevel: options.assuranceLevel ?? "aal1" }, error: null },
				),
			},
		},
		from: (table: string) => builder(table),
		rpc: vi.fn(async (name: string, args: Row) => {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") {
				if (options.rateLimit === "unavailable") return { data: null, error: { code: "08006" } };
				if (options.rateLimit === "throwing") throw new Error("db_down");
				if (options.rateLimit === "malformed") return { data: { allowed: "yes" }, error: null };
				if (options.rateLimit === "deny") return { data: { allowed: false, remaining: 0 }, error: null };
				return { data: { allowed: true, remaining: 599 }, error: null };
			}
			if (options.rpc) return options.rpc(name, args);
			if (name === "save_policy_document_draft") {
				const current = draftRows.find((row) => row.team_id === args.p_tenant_id);
				if (current ? current.id !== args.p_expected_id || current.version !== args.p_expected_version || current.source_sha256 !== args.p_expected_source_sha256 : args.p_expected_id !== null) {
					return { data: null, error: { code: "PT409" } };
				}
				const row = {
					id: current?.id ?? DOCUMENT_ID, team_id: args.p_tenant_id, content: args.p_content,
					version: Number(current?.version ?? 0) + 1, source_sha256: sourceHash(String(args.p_content)), updated_at: NOW,
				};
				if (current) Object.assign(current, row); else draftRows.push(row);
				draftWrites.push(row);
				return { data: row, error: null };
			}
			// The published RPC returns the stored row; a targeted stage returns
			// only the new revision and its target count.
			if (name === "stage_runtime_policy") return { data: { version: 4, target_count: 1 }, error: null };
			return { data: { version: 4, policy: args.p_policy, updated_at: NOW }, error: null };
		}),
	};
	return { db, rpcCalls, queries, draftRows, draftWrites };
}

function mutations(calls: RpcRecord[]): RpcRecord[] {
	return calls.filter((call) => MUTATION_RPCS.has(call.name));
}

/**
 * The tenants named by every policy-scoped read. `tenant_members`,
 * `tenant_identity_policies` and `tenants` are excluded on purpose: those are
 * the *authorization* reads, and the caller's membership lookup is exactly the
 * step that decides whether a body-supplied tenant may be used at all.
 */
function policyScopedTenants(queries: QueryRecord[]): string[] {
	const ids: string[] = [];
	for (const entry of queries) {
		if (!POLICY_SCOPED_TABLES.has(entry.table)) continue;
		const scoped = entry.filters.tenant_id;
		if (typeof scoped === "string") ids.push(scoped);
	}
	return ids;
}

function policyScopedTeams(queries: QueryRecord[]): string[] {
	return queries
		.filter((entry) => entry.table === "team_policies" && typeof entry.filters.team_id === "string")
		.map((entry) => String(entry.filters.team_id));
}

async function handlerWith(options: DbOptions = {}) {
	const { db, rpcCalls, queries, draftRows, draftWrites } = database(options);
	const mod = await import("../policy-management/index.ts");
	return {
		handle: mod.createPolicyManagementHandler({ db: db as never }),
		db,
		rpcCalls,
		queries,
		draftRows,
		draftWrites,
	};
}

function post(body: unknown, headers: Record<string, string> = {}): Request {
	return new Request(HANDLER_URL, {
		method: "POST",
		headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json", ...headers },
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
}

function publishBody(overrides: Row = {}): Row {
	return { action: "publish", tenant_id: TENANT, expected_version: 3, policy: POLICY, ...overrides };
}

function stageBody(overrides: Row = {}): Row {
	return {
		action: "stage",
		tenant_id: TENANT,
		expected_version: 3,
		expected_revision_version: 3,
		agent_ids: [AGENT],
		policy: POLICY,
		...overrides,
	};
}

function teamPolicyRow(tenantId: string, document: string, id: string, marker: string): Row {
	return { team_id: tenantId, id, content: document, updated_at: NOW, marker };
}

const DOCUMENT_ROWS: Row[] = [
	teamPolicyRow(TENANT, POLICY_DOCUMENT_LINES.join("\n"), "doc-tenant", "tenant-document"),
	teamPolicyRow(
		OTHER_TENANT,
		["version: 1", "default_action: deny", `description: ${OTHER_POLICY_MARKER}`].join("\n"),
		"doc-other",
		OTHER_POLICY_MARKER,
	),
];

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.resetModules();
});

describe("policy-management handler - transport and authentication", () => {
	it("answers a preflight and refuses a non-POST method before any authentication", async () => {
		const { handle, db } = await handlerWith();
		const preflight = await handle(new Request(HANDLER_URL, { method: "OPTIONS" }));
		expect(preflight.status).toBe(200);
		const get = await handle(
			new Request(HANDLER_URL, { method: "GET", headers: { Authorization: "Bearer valid-token" } }),
		);
		expect(get.status).toBe(405);
		expect(await get.json()).toMatchObject({ error: "method_not_allowed" });
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("rejects a request without a bearer token before any database work", async () => {
		for (const headers of [{}, { Authorization: "" }, { Authorization: "Basic abc" }]) {
			const { handle, db, queries } = await handlerWith();
			const response = await handle(
				new Request(HANDLER_URL, { method: "POST", headers, body: JSON.stringify(publishBody()) }),
			);
			expect(response.status, JSON.stringify(headers)).toBe(401);
			expect(await response.json()).toMatchObject({ error: "missing_access_token" });
			expect(db.auth.getUser).not.toHaveBeenCalled();
			expect(db.rpc).not.toHaveBeenCalled();
			expect(queries).toHaveLength(0);
		}
	});

	it("fails fast on missing platform configuration instead of guessing a client", async () => {
		vi.stubEnv("SUPABASE_URL", "");
		const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
		try {
			const { handle, db } = await handlerWith();
			const response = await handle(post(publishBody()));
			expect(response.status).toBe(500);
			expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
			expect(db.rpc).not.toHaveBeenCalled();
		} finally {
			logged.mockRestore();
		}
	});

	it("rejects an unverifiable access token and a throwing auth lookup without ever succeeding", async () => {
		const stale = await handlerWith();
		const invalid = await stale.handle(post(publishBody(), { Authorization: "Bearer stale-token" }));
		expect(invalid.status).toBe(401);
		expect(await invalid.json()).toMatchObject({ error: "invalid_access_token" });
		expect(stale.rpcCalls).toHaveLength(0);

		const missingUser = await handlerWith({ user: null });
		expect((await missingUser.handle(post(publishBody()))).status).toBe(401);

		const authError = await handlerWith({ authError: true });
		expect((await authError.handle(post(publishBody()))).status).toBe(401);

		const throwing = await handlerWith({ authThrow: true });
		const thrown = await throwing.handle(post(publishBody()));
		expect(thrown.status).toBe(503);
		expect(await thrown.json()).toMatchObject({ error: "policy_unavailable" });
		expect(mutations(throwing.rpcCalls)).toHaveLength(0);
	});
});

describe("policy-management handler - authorization", () => {
	it("returns 503, never a success, when an identity-barrier lookup fails", async () => {
		const cases: Array<[DbOptions, string]> = [
			[{ sessionError: true }, "identity_state_unavailable"],
			[{ identityPolicyError: true }, "identity_policy_unavailable"],
			[{ requireMfa: true, assuranceError: true }, "assurance_unavailable"],
		];
		for (const [options, error] of cases) {
			const { handle, rpcCalls, queries } = await handlerWith(options);
			const response = await handle(post({ action: "read", tenant_id: TENANT }));
			expect(response.status, error).toBe(503);
			expect(await response.json()).toMatchObject({ error });
			expect(rpcCalls).toHaveLength(0);
			expect(queries.some((entry) => POLICY_SCOPED_TABLES.has(entry.table))).toBe(false);
		}
	});

	it("refuses a revoked session and a tenant that demands an assurance level the token lacks", async () => {
		const revoked = await handlerWith({ revokedBefore: "2100-01-01T00:00:00.000Z" });
		const revokedResponse = await revoked.handle(post({ action: "read", tenant_id: TENANT }));
		expect(revokedResponse.status).toBe(401);
		expect(await revokedResponse.json()).toMatchObject({ error: "session_revoked" });
		expect(revoked.rpcCalls).toHaveLength(0);

		const mfa = await handlerWith({ requireMfa: true, assuranceLevel: "aal1" });
		const mfaResponse = await mfa.handle(post({ action: "read", tenant_id: TENANT }));
		expect(mfaResponse.status).toBe(403);
		expect(await mfaResponse.json()).toMatchObject({ error: "mfa_required" });
		expect(mfa.rpcCalls).toHaveLength(0);
	});

	it("refuses an expired membership and a caller with no membership at all", async () => {
		const cases: Array<[DbOptions, string]> = [
			[{ memberships: [{ tenant_id: TENANT, role: "owner", expires_at: "2000-01-01T00:00:00.000Z" }] }, "expired"],
			[{ memberships: [{ tenant_id: TENANT, role: "admin", expires_at: "not-a-date" }] }, "unparsable expiry"],
			[{ memberships: [] }, "removed"],
		];
		for (const [options, label] of cases) {
			const { handle, rpcCalls } = await handlerWith(options);
			const response = await handle(post(publishBody()));
			expect(response.status, label).toBe(403);
			expect(await response.json()).toMatchObject({ error: "tenant_access_denied" });
			expect(mutations(rpcCalls), label).toHaveLength(0);
		}
	});

	it("answers 503 when the membership or tenant lookup itself fails", async () => {
		const memberDown = await handlerWith({ memberError: true });
		const memberResponse = await memberDown.handle(post(publishBody()));
		expect(memberResponse.status).toBe(503);
		expect(await memberResponse.json()).toMatchObject({ error: "authorization_unavailable" });

		const tenantDown = await handlerWith({ tenantError: true });
		const tenantResponse = await tenantDown.handle(post(publishBody()));
		expect(tenantResponse.status).toBe(503);
		expect(await tenantResponse.json()).toMatchObject({ error: "authorization_unavailable" });
		expect(mutations(tenantDown.rpcCalls)).toHaveLength(0);
	});

	it("refuses a tenant that is not active", async () => {
		for (const status of ["suspended", "trialing", "past_due", null]) {
			const { handle, rpcCalls } = await handlerWith({ tenantStatus: status });
			const response = await handle(post(publishBody()));
			expect(response.status, String(status)).toBe(403);
			expect(await response.json()).toMatchObject({ error: "tenant_access_denied" });
			expect(mutations(rpcCalls)).toHaveLength(0);
		}
	});

	// Every privileged action is refused for a role below owner/admin. Reads are
	// deliberately member-scoped: the dashboard's team policy page renders the
	// published policy to any member while gating every control on
	// `canManageTeam`, and the SQL publication RPCs repeat the owner/admin rule
	// inside the writing transaction.
	it("refuses every runtime mutating action for a member whose role is below owner/admin", async () => {
		const bodies: Row[] = [
			publishBody(),
			stageBody(),
			{ action: "restore", tenant_id: TENANT, expected_version: 3, target_version: 3 },
			{ action: "publish_document", tenant_id: TENANT, expected_version: 3 },
		];
		for (const body of bodies) {
			const { handle, rpcCalls } = await handlerWith({
				memberships: [{ tenant_id: TENANT, role: "viewer", expires_at: null }],
				teamPolicies: DOCUMENT_ROWS,
			});
			const response = await handle(post(body));
			expect(response.status, String(body.action)).toBe(403);
			expect(await response.json()).toMatchObject({ error: "policy_forbidden" });
			expect(mutations(rpcCalls), String(body.action)).toHaveLength(0);
		}
	});

	it("serves a member the policy of the team they belong to, and only that team", async () => {
		const { handle, queries, rpcCalls } = await handlerWith({
			memberships: [{ tenant_id: TENANT, role: "viewer", expires_at: null }],
		});
		const response = await handle(post({ action: "read", tenant_id: TENANT }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, version: 3, policy: POLICY });
		expect(policyScopedTenants(queries)).toEqual([TENANT]);
		// Every RPC, quota consumption included, is scoped to the verified tenant.
		expect(rpcCalls.map((call) => call.args.p_tenant_id)).toEqual([TENANT]);
		expect(rpcCalls.map((call) => call.name)).toEqual(["consume_tenant_rate_limit"]);
	});
});

describe("policy-management handler - request and policy validation", () => {
	it("rejects a policy that is not an object, is empty, or is absent without calling the write RPC", async () => {
		const cases: Array<[unknown, string]> = [
			["deny", "policy_must_be_object"],
			[[], "policy_must_be_object"],
			[null, "policy_must_be_object"],
			[undefined, "policy_must_be_object"],
			[{}, "empty_policy"],
		];
		for (const [policy, error] of cases) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(post(publishBody({ policy })));
			expect(response.status, String(error)).toBe(400);
			expect(await response.json()).toMatchObject({ error });
			expect(mutations(rpcCalls), String(error)).toHaveLength(0);
		}
	});

	it("rejects unsupported fields and out-of-range or invalid action values with 400 and no write", async () => {
		const cases: Array<[Row, string]> = [
			[{ command_default: "allow", telemetry_upload: true }, "unsupported_policy_field:telemetry_upload"],
			[{ command_default: "block" }, "invalid_action:command_default"],
			[{ mcp_default: "ALLOW" }, "invalid_action:mcp_default"],
			[{ mcp_risky: "review" }, "invalid_action:mcp_risky"],
			[{ mcp_allow_servers: "github" }, "invalid_list:mcp_allow_servers"],
			[{ mcp_deny_tools: ["vault"] }, "invalid_list:mcp_deny_tools"],
			[{ mcp_allow_servers: ["../etc/passwd"] }, "invalid_list:mcp_allow_servers"],
			[{ command_default: "ask", tenant_id: OTHER_TENANT }, "unsupported_policy_field:tenant_id"],
		];
		for (const [policy, error] of cases) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(post(publishBody({ policy })));
			expect(response.status, error).toBe(400);
			expect(await response.json()).toMatchObject({ error });
			expect(mutations(rpcCalls), error).toHaveLength(0);
		}
	});

	it("rejects a stored policy document the runtime cannot enforce, and publishes the one it can", async () => {
		const unsupported = [
			...POLICY_DOCUMENT_LINES.slice(0, 8),
			'      pattern: ".*"',
			...POLICY_DOCUMENT_LINES.slice(8),
		].join("\n");
		const rejected = await handlerWith({
			teamPolicies: [teamPolicyRow(TENANT, unsupported, "doc-tenant", "tenant-document")],
		});
		const rejectedResponse = await rejected.handle(
			post({ action: "publish_document", tenant_id: TENANT, expected_version: 3 }),
		);
		expect(rejectedResponse.status).toBe(400);
		expect(await rejectedResponse.json()).toMatchObject({
			error: "invalid_policy_document:rules.0.condition:unsupported_field:pattern",
		});
		expect(mutations(rejected.rpcCalls)).toHaveLength(0);

		const compiled = await handlerWith({ teamPolicies: DOCUMENT_ROWS });
		const dryRun = await compiled.handle(
			post({
				action: "compile_document",
				tenant_id: TENANT,
				simulation: { kind: "mcp", server: "unregistered-preview", tool: "call", inventory: "unknown" },
			}),
		);
		expect(dryRun.status).toBe(200);
		expect(await dryRun.json()).toMatchObject({
			ok: true,
			dry_run: true,
			source: { id: "doc-tenant", updated_at: NOW },
			runtime_policy: { command_default: "deny", mcp_allow_tools: ["github.read"] },
			semantics: { precedence: ["deny", "ask", "allow"], unknown_mcp: "deny" },
			simulation: { action: "deny", source: "mcp_unknown" },
		});
		expect(policyScopedTeams(compiled.queries)).toEqual([TENANT]);

		const published = await handlerWith({ teamPolicies: DOCUMENT_ROWS });
		const publishedResponse = await published.handle(
			post({ action: "publish_document", tenant_id: TENANT, expected_version: 3 }),
		);
		expect(publishedResponse.status).toBe(200);
		const body = (await publishedResponse.json()) as Row;
		expect(body).toMatchObject({ ok: true, version: 4, compiled_from: { id: "doc-tenant", updated_at: NOW } });
		expect(JSON.stringify(body)).not.toContain(OTHER_POLICY_MARKER);
		expect(mutations(published.rpcCalls)[0]?.args.p_policy).toMatchObject({
			command_default: "deny",
			mcp_allow_tools: ["github.read"],
		});
	});

	it("answers 404 and 503 for an unreadable stored document instead of compiling nothing", async () => {
		const missing = await handlerWith();
		const missingResponse = await missing.handle(post({ action: "compile_document", tenant_id: TENANT }));
		expect(missingResponse.status).toBe(404);
		expect(await missingResponse.json()).toMatchObject({ error: "policy_document_not_found" });

		const broken = await handlerWith({ teamPoliciesError: true });
		const brokenResponse = await broken.handle(post({ action: "compile_document", tenant_id: TENANT }));
		expect(brokenResponse.status).toBe(503);
		expect(await brokenResponse.json()).toMatchObject({ error: "policy_document_unavailable" });
	});

	it("rejects an unknown action, a bad version precondition and a bad agent cursor", async () => {
		const cases: Array<[Row, string]> = [
			[{ action: "delete_everything", tenant_id: TENANT }, "invalid_action"],
			[publishBody({ expected_version: undefined }), "invalid_version"],
			[publishBody({ expected_version: -1 }), "invalid_version"],
			[publishBody({ expected_version: 1.5 }), "invalid_version"],
			[{ action: "adoption", tenant_id: TENANT, after_agent: "not-a-uuid" }, "invalid_agent_cursor"],
		];
		for (const [body, error] of cases) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(post(body));
			expect(response.status, error).toBe(400);
			expect(await response.json()).toMatchObject({ error });
			expect(mutations(rpcCalls), error).toHaveLength(0);
		}
	});

	it("rejects a malformed stage target list and a revision precondition below the published version", async () => {
		const cases: Array<[Row, string]> = [
			[stageBody({ agent_ids: [] }), "invalid_stage_agents"],
			[stageBody({ agent_ids: ["not-a-uuid"] }), "invalid_stage_agents"],
			[stageBody({ agent_ids: Array.from({ length: 201 }, () => AGENT) }), "invalid_stage_agents"],
			[stageBody({ expected_revision_version: 1.5 }), "invalid_revision_version"],
			[stageBody({ expected_revision_version: 2 }), "invalid_revision_version"],
		];
		for (const [body, error] of cases) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(post(body));
			expect(response.status, error).toBe(400);
			expect(await response.json()).toMatchObject({ error });
			expect(mutations(rpcCalls), error).toHaveLength(0);
		}
	});

	it("rejects an invalid restore target and reports a revision that does not exist", async () => {
		for (const target of [0, -1, 1.5, "3", undefined]) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(
				post({ action: "restore", tenant_id: TENANT, expected_version: 3, target_version: target }),
			);
			expect(response.status, String(target)).toBe(400);
			expect(await response.json()).toMatchObject({ error: "invalid_target_version" });
			expect(mutations(rpcCalls)).toHaveLength(0);
		}

		const { handle, rpcCalls } = await handlerWith();
		const missing = await handle(
			post({ action: "restore", tenant_id: TENANT, expected_version: 3, target_version: 99 }),
		);
		expect(missing.status).toBe(404);
		expect(await missing.json()).toMatchObject({ error: "revision_not_found" });
		expect(mutations(rpcCalls)).toHaveLength(0);
	});

	it("rejects a body that is not an object, a non-uuid tenant and an oversized or malformed body", async () => {
		const notObject = await handlerWith();
		const arrayBody = await notObject.handle(post("[]"));
		expect(arrayBody.status).toBe(400);
		expect(await arrayBody.json()).toMatchObject({ error: "invalid_request" });

		const malformed = await handlerWith();
		const broken = await malformed.handle(post("{not json"));
		expect(broken.status).toBe(400);
		expect(await broken.json()).toMatchObject({ error: "invalid_json" });
		expect(mutations(malformed.rpcCalls)).toHaveLength(0);

		const tenantCases: unknown[] = ["not-a-uuid", 42, ["22222222-2222-4222-8222-222222222222"]];
		for (const tenant_id of tenantCases) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(post(publishBody({ tenant_id })));
			expect(response.status, JSON.stringify(tenant_id)).toBe(400);
			expect(await response.json()).toMatchObject({ error: "invalid_tenant" });
			expect(rpcCalls).toHaveLength(0);
		}

		const oversized = await handlerWith();
		const tooLarge = await oversized.handle(
			post(publishBody({ padding: "x".repeat(70_000) })),
		);
		expect(tooLarge.status).toBe(413);
		expect(await tooLarge.json()).toMatchObject({ error: "request_too_large" });
		expect(mutations(oversized.rpcCalls)).toHaveLength(0);
	});
});

describe("policy-management handler - optimistic concurrency", () => {
	it("maps a stale revision precondition to 409 and never writes", async () => {
		const { handle, rpcCalls } = await handlerWith({
			rpc: (name) =>
				name === "stage_runtime_policy"
					? { data: null, error: { code: "PT409", message: "policy_revision_conflict" } }
					: { data: null, error: null },
		});
		const response = await handle(post(stageBody({ expected_revision_version: 7 })));
		expect(response.status).toBe(409);
		const body = (await response.json()) as Row;
		expect(body).toMatchObject({ error: "policy_version_conflict" });
		expect(JSON.stringify(body)).not.toContain(OTHER_POLICY_MARKER);

		const writes = mutations(rpcCalls);
		expect(writes).toHaveLength(1);
		expect(writes[0]?.name).toBe("stage_runtime_policy");
		expect(rpcCalls.map((call) => call.name)).toEqual(["consume_tenant_rate_limit", "stage_runtime_policy"]);
	});

	it("maps a stale published version to 409 and never falls back to another write", async () => {
		const { handle, rpcCalls } = await handlerWith({
			rpc: () => ({ data: null, error: { code: "PT409", message: "policy_version_conflict" } }),
		});
		const response = await handle(post(publishBody()));
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ error: "policy_version_conflict" });
		expect(mutations(rpcCalls).map((call) => call.name)).toEqual(["publish_runtime_policy"]);
	});

	it("carries the version and revision preconditions, the caller and the exact policy into the RPC", async () => {
		const { handle, rpcCalls, queries } = await handlerWith();
		const response = await handle(post(stageBody({ expected_version: 3, expected_revision_version: 7 })));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			version: 4,
			target_count: 1,
			staged: true,
		});

		const writes = mutations(rpcCalls);
		expect(writes).toHaveLength(1);
		expect(writes[0]?.name).toBe("stage_runtime_policy");
		expect(writes[0]?.args).toEqual({
			p_tenant_id: TENANT,
			p_user_id: USER,
			p_expected_version: 3,
			p_expected_revision_version: 7,
			p_policy: POLICY,
			p_agent_ids: [AGENT],
		});
		// The tenant is one the handler verified a live membership for.
		const verified = queries
			.filter((entry) => entry.table === "tenant_members")
			.map((entry) => entry.filters.tenant_id);
		expect(verified).toContain(TENANT);
		expect(policyScopedTenants(queries)).not.toContain(OTHER_TENANT);
	});

	it("publishes the compiled revision rather than the raw submitted object", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post(publishBody()));
		expect(response.status).toBe(200);
		const writes = mutations(rpcCalls);
		expect(writes[0]?.name).toBe("publish_runtime_policy");
		expect(writes[0]?.args).toEqual({
			p_tenant_id: TENANT,
			p_user_id: USER,
			p_expected_version: 3,
			p_policy: POLICY,
		});
	});
});

describe("policy-management handler - exact draft compile and save", () => {
	const existing = () => [{ ...EXPECTED_DOCUMENT, team_id: TENANT, content: VALID_DRAFT, updated_at: NOW }];

	it.each([false, true])("makes zero policy mutations for rejected drafts (existing=%s)", async (update) => {
		const { handle, rpcCalls, draftRows, draftWrites } = await handlerWith({ teamPolicies: update ? existing() : [] });
		const before = structuredClone(draftRows);
		for (const content of [
			"version: [broken",
			`${VALID_DRAFT}\ndefault_action: allow`, // duplicate mapping keys
			'version: "1.0"\ndefault_action: &mode ask\nunknown_action: *mode\nrules: []',
			`${VALID_DRAFT}\ndlp: { enabled: true }`, // unsupported, not silently dropped
			VALID_DRAFT.replace("priority: 20", "priority: 1001"),
			VALID_DRAFT.replace("allow read", "a".repeat(161)),
			"",
			42,
		]) {
			const response = await handle(post(draftBody({ content, expected_document: update ? EXPECTED_DOCUMENT : null })));
			expect(response.status, String(content)).toBe(400);
			expect((await response.json()).ok).not.toBe(true);
		}
		expect(mutations(rpcCalls)).toEqual([]);
		expect(draftWrites).toEqual([]);
		expect(draftRows).toEqual(before);
	});

	it("compiles the submitted UTF-8 bytes rather than the stored row, then saves only those bytes", async () => {
		const content = `# café 雪\r\n${VALID_DRAFT.replaceAll("\n", "\r\n")}\r\n`;
		const { handle, rpcCalls, queries, draftRows } = await handlerWith({ teamPolicies: existing() });
		const response = await handle(post(draftBody({ content, expected_document: EXPECTED_DOCUMENT, simulation: { kind: "command" } })));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body).toMatchObject({ ok: true, source: { id: DOCUMENT_ID, version: 8, source_sha256: sourceHash(content) }, runtime_policy: { command_default: "deny" }, simulation: { action: "deny" } });
		expect(body.source.source_sha256).not.toBe(sourceHash(VALID_DRAFT));
		expect(mutations(rpcCalls)).toEqual([{ name: "save_policy_document_draft", args: {
			p_tenant_id: TENANT, p_user_id: USER, p_content: content, p_source_sha256: sourceHash(content),
			p_expected_id: DOCUMENT_ID, p_expected_version: 7, p_expected_source_sha256: EXPECTED_DOCUMENT.source_sha256,
		} }]);
		expect(draftRows[0]?.content).toBe(content);
		expect(queries.filter((query) => query.table === "team_policies")).toEqual([]);
	});

	it("dry-runs a first draft without requiring or mutating a stored row", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post(draftBody({ action: "compile_document_draft", simulation: { kind: "command" } })));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, dry_run: true, source: { source_sha256: sourceHash(VALID_DRAFT) } });
		expect(mutations(rpcCalls)).toEqual([]);
	});

	it.each([false, true])("allows just one competing save for the same loaded revision (existing=%s)", async (update) => {
		const { handle, draftRows, draftWrites } = await handlerWith({ teamPolicies: update ? existing() : [] });
		const drafts = [`# editor A\n${VALID_DRAFT}`, `# editor B\n${VALID_DRAFT}`];
		const responses = await Promise.all(drafts.map((content) => handle(post(draftBody({ content, expected_document: update ? EXPECTED_DOCUMENT : null })))));
		expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
		const winner = responses.findIndex((response) => response.status === 200);
		expect(draftWrites).toHaveLength(1);
		expect(draftRows).toHaveLength(1);
		expect(draftRows[0]?.content).toBe(drafts[winner]);
		expect(await responses[1 - winner].json()).toEqual({ error: "policy_document_conflict" });
	});

	it("refuses a stale source hash even when the row id and version match", async () => {
		const { handle, draftWrites, draftRows } = await handlerWith({ teamPolicies: existing() });
		const response = await handle(post(draftBody({ expected_document: { ...EXPECTED_DOCUMENT, source_sha256: "0".repeat(64) } })));
		expect(response.status).toBe(409);
		expect(draftWrites).toEqual([]);
		expect(draftRows).toEqual(existing());
	});

	it("rejects missing/malformed preconditions and invalid simulation before the mutation RPC", async () => {
		const { handle, rpcCalls } = await handlerWith();
		for (const expected_document of [undefined, {}, [], { ...EXPECTED_DOCUMENT, id: "wrong" }, { ...EXPECTED_DOCUMENT, version: 0 }, { ...EXPECTED_DOCUMENT, version: 1.2 }, { ...EXPECTED_DOCUMENT, source_sha256: "bad" }]) {
			const response = await handle(post(draftBody({ expected_document })));
			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({ error: "invalid_document_precondition" });
		}
		const response = await handle(post(draftBody({ simulation: { kind: "dlp" } })));
		expect(response.status).toBe(400);
		expect(mutations(rpcCalls)).toEqual([]);
	});

	it("keeps request/source work bounded in UTF-8 bytes", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post(draftBody({ content: `# ${"雪".repeat(22_000)}\n${VALID_DRAFT}` })));
		expect(response.status).toBe(413);
		expect(mutations(rpcCalls)).toEqual([]);
	});

	it.each(["owner", "admin", "member"])("preserves %s draft authoring without granting runtime publication", async (role) => {
		const { handle, rpcCalls } = await handlerWith({ memberships: [{ tenant_id: TENANT, role, expires_at: null }] });
		const response = await handle(post(draftBody({ updated_by: OTHER_TENANT })));
		expect(response.status).toBe(200);
		expect(mutations(rpcCalls)[0]?.args.p_user_id).toBe(USER);
		if (role === "member") expect((await handle(post(publishBody()))).status).toBe(403);
	});

	it("preserves viewer, expiry, tenant and MFA barriers for the new action", async () => {
		for (const options of [
			{ memberships: [{ tenant_id: TENANT, role: "viewer", expires_at: null }] },
			{ memberships: [{ tenant_id: TENANT, role: "member", expires_at: "2000-01-01" }] },
			{ memberships: [{ tenant_id: OTHER_TENANT, role: "owner", expires_at: null }] },
			{ tenantStatus: "suspended" },
			{ requireMfa: true, assuranceLevel: "aal1" },
		] satisfies DbOptions[]) {
			const { handle, rpcCalls } = await handlerWith(options);
			expect((await handle(post(draftBody()))).status).toBe(403);
			expect(mutations(rpcCalls)).toEqual([]);
		}
	});

	it("never acknowledges RPC failure or an unconfirmed/mismatched stored source", async () => {
		const valid = { id: DOCUMENT_ID, version: 1, source_sha256: sourceHash(VALID_DRAFT), updated_at: NOW };
		for (const result of [
			{ data: null, error: { code: "08006" } },
			{ data: valid, error: { code: "08006" } },
			{ data: null, error: null },
			{ data: {}, error: null },
			{ data: { ...valid, source_sha256: "0".repeat(64) }, error: null },
			{ data: { ...valid, version: 2 }, error: null },
			{ data: { ...valid, id: "not-a-uuid" }, error: null },
			{ data: { ...valid, updated_at: "not-a-timestamp" }, error: null },
		]) {
			const { handle } = await handlerWith({ rpc: () => result });
			const response = await handle(post(draftBody()));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "policy_document_save_failed" });
		}
		const { handle } = await handlerWith({ rpc: () => { throw new Error("connection lost"); } });
		const response = await handle(post(draftBody()));
		expect(response.status).toBe(503);
		expect((await response.json()).ok).not.toBe(true);
	});
});

describe("policy-management handler - failure mapping", () => {
	it("maps the recognised forbidden and invalid codes to 403 and 400", async () => {
		for (const [code, status] of [["42501", 403], ["22023", 400]] as const) {
			const { handle } = await handlerWith({ rpc: () => ({ data: null, error: { code } }) });
			const response = await handle(post(publishBody()));
			expect(response.status, code).toBe(status);
			expect(await response.json()).toMatchObject({ error: "policy_publish_failed" });
		}
	});

	it("maps any other Postgres error, and a missing payload, to 503 rather than a partial success", async () => {
		const cases: Array<[DbOptions, number]> = [
			[{ rpc: () => ({ data: null, error: { code: "08006" } }) }, 503],
			[{ rpc: () => ({ data: null, error: new Error("db_down") }) }, 503],
			[{ rpc: () => ({ data: null, error: null }) }, 503],
			[{ rpc: () => ({ data: {}, error: null }) }, 503],
		];
		for (const [options, status] of cases) {
			const { handle } = await handlerWith(options);
			const response = await handle(post(publishBody()));
			expect(response.status, JSON.stringify(options)).toBe(status);
			const body = (await response.json()) as Row;
			expect(body.ok).not.toBe(true);
		}
	});

	it("returns only the caller's own tenant policy and 503 when the policy read fails", async () => {
		const { handle } = await handlerWith({ policyReadError: true });
		const response = await handle(post({ action: "read", tenant_id: TENANT }));
		expect(response.status).toBe(503);
		expect(await response.json()).toMatchObject({ error: "policy_unavailable" });
	});

	it("answers 429 with retry metadata when the tenant quota is exhausted", async () => {
		const { handle, rpcCalls } = await handlerWith({ rateLimit: "deny" });
		const response = await handle(post(publishBody()));
		expect(response.status).toBe(429);
		expect(await response.json()).toMatchObject({ error: "rate_limited" });
		expect(response.headers.get("Retry-After")).toMatch(/^\d+$/);
		expect(response.headers.get("RateLimit-Remaining")).toBe("0");
		expect(mutations(rpcCalls)).toHaveLength(0);
	});

	it("fails closed when rate-limit storage errors, throws or returns a malformed row", async () => {
		for (const rateLimit of ["unavailable", "throwing", "malformed"] as const) {
			const { handle, rpcCalls } = await handlerWith({ rateLimit });
			const response = await handle(post(publishBody()));
			expect(response.status, rateLimit).toBe(503);
			expect(await response.json()).toMatchObject({ error: "rate_limit_unavailable" });
			expect(mutations(rpcCalls), rateLimit).toHaveLength(0);
		}
	});

	it("answers 503 when the history or adoption read fails instead of returning an empty fleet", async () => {
		const history = await handlerWith({ revisionsError: true });
		const historyResponse = await history.handle(post({ action: "history", tenant_id: TENANT }));
		expect(historyResponse.status).toBe(503);
		expect(await historyResponse.json()).toMatchObject({ error: "history_unavailable" });

		const adoption = await handlerWith({ policyReadError: true });
		const adoptionResponse = await adoption.handle(post({ action: "adoption", tenant_id: TENANT }));
		expect(adoptionResponse.status).toBe(503);
		expect(await adoptionResponse.json()).toMatchObject({ error: "adoption_unavailable" });
	});
});

describe("policy-management handler - tenant isolation", () => {
	it("never reads or writes another tenant's policy from a body-supplied tenant id", async () => {
		const { handle, rpcCalls, queries } = await handlerWith({
			memberships: [{ tenant_id: TENANT, role: "owner", expires_at: null }],
			teamPolicies: DOCUMENT_ROWS,
		});
		for (const action of ["read", "history", "adoption", "compile_document", "compile_document_draft", "save_document_draft", "publish", "stage"]) {
			const response = await handle(
				post(stageBody({ action, tenant_id: OTHER_TENANT, target_version: 9 })),
			);
			expect(response.status, action).toBe(403);
			const text = await response.text();
			expect(text, action).toContain("tenant_access_denied");
			expect(text, action).not.toContain(OTHER_POLICY_MARKER);
		}
		expect(rpcCalls).toHaveLength(0);
		expect(policyScopedTenants(queries)).not.toContain(OTHER_TENANT);
		expect(policyScopedTeams(queries)).not.toContain(OTHER_TENANT);
	});

	it("returns only the verified tenant's policy, never another tenant's row", async () => {
		const { handle, queries } = await handlerWith();
		const response = await handle(post({ action: "read", tenant_id: TENANT }));
		expect(response.status).toBe(200);
		const text = await response.text();
		expect(text).not.toContain(OTHER_POLICY_MARKER);
		expect(JSON.parse(text)).toMatchObject({ ok: true, version: 3, policy: POLICY });
		expect(policyScopedTenants(queries)).toEqual([TENANT]);
	});

	it("cannot reach another tenant's revision through restore", async () => {
		const { handle, rpcCalls, queries } = await handlerWith();
		const response = await handle(
			post({ action: "restore", tenant_id: TENANT, expected_version: 3, target_version: 9 }),
		);
		expect(response.status).toBe(404);
		const text = await response.text();
		expect(text).toContain("revision_not_found");
		expect(text).not.toContain(OTHER_POLICY_MARKER);
		expect(mutations(rpcCalls)).toHaveLength(0);
		expect(policyScopedTenants(queries)).not.toContain(OTHER_TENANT);
	});

	it("uses the selected tenant only because the caller holds a verified membership in it", async () => {
		const { handle, rpcCalls, queries } = await handlerWith({
			memberships: [
				{ tenant_id: TENANT, role: "owner", expires_at: null },
				{ tenant_id: OTHER_TENANT, role: "admin", expires_at: null },
			],
		});
		const response = await handle(post(publishBody({ tenant_id: OTHER_TENANT })));
		expect(response.status).toBe(200);
		const writes = mutations(rpcCalls);
		expect(writes).toHaveLength(1);
		expect(writes[0]?.args.p_tenant_id).toBe(OTHER_TENANT);
		expect(writes[0]?.args.p_user_id).toBe(USER);
		// The tenant that reached the RPC is one the handler looked up a
		// membership for, and no other tenant's policy was touched.
		const verified = queries
			.filter((entry) => entry.table === "tenant_members")
			.map((entry) => entry.filters.tenant_id);
		expect(verified).toContain(OTHER_TENANT);
		expect(policyScopedTenants(queries)).not.toContain(TENANT);
	});
});

describe("policy-management source and SQL contract", () => {
	it("validates configuration and CORS through the shared helpers", () => {
		expect(HANDLER_SOURCE).toContain('from "../_shared/config.ts"');
		expect(HANDLER_SOURCE).toContain("loadConfig(runtimeEnv,");
		expect(HANDLER_SOURCE).toContain("configFailure(");
		expect(HANDLER_SOURCE).toContain("handleCors(req)");
		expect(HANDLER_SOURCE).toContain("corsJson(req");
		expect(HANDLER_SOURCE).toMatch(/const config = loadConfig\(runtimeEnv, REQUIRED_ENV\);\s*\n\s*if \(!config\.ok\)/);
	});

	it("never reads the platform credentials outside the shared config helper", () => {
		expect(HANDLER_SOURCE).not.toMatch(/Deno\.env\.get\(\s*"SUPABASE_(URL|SERVICE_ROLE_KEY)"\s*\)/);
		expect(HANDLER_SOURCE).not.toMatch(/Deno\.env/);
		expect(HANDLER_SOURCE).not.toMatch(/\?\?\s*""/);
	});

	it("re-verifies identity, membership and role in the handler before any write", () => {
		expect(HANDLER_SOURCE).toContain('getBearerToken(req.headers.get("Authorization"))');
		expect(HANDLER_SOURCE).toContain('db.auth.getUser(token)');
		expect(HANDLER_SOURCE).toContain("checkIdentityBarrier(db, token, auth.user.id, tenant)");
		expect(HANDLER_SOURCE).toContain('db.from("tenant_members").select("role,expires_at")');
		expect(HANDLER_SOURCE).toContain("membershipActive(member)");
		expect(HANDLER_SOURCE).toContain('db.from("tenants").select("status")');
		expect(HANDLER_SOURCE).toContain('["owner", "admin"].includes(member.role)');
		expect(HANDLER_SOURCE).toContain("consumeTenantRateLimit(db, {");
		expect(HANDLER_SOURCE).toContain('error.code === "PT409" ? 409 : error.code === "42501" ? 403 : error.code === "22023" ? 400 : 503');
		expect(HANDLER_SOURCE).toContain("validateRuntimePolicy(");
		expect(HANDLER_SOURCE).toContain("compileRuntimePolicyDocument(");
		// A handler that writes nothing to the log cannot log a tenant's policy.
		expect(HANDLER_SOURCE).not.toMatch(/console\./);
	});

	it("exposes the factory the suite drives and still serves it from the Edge runtime", () => {
		expect(HANDLER_SOURCE).toContain("export function createPolicyManagementHandler(");
		expect(HANDLER_SOURCE).toContain("deps.db ?? createClient(");
		expect(HANDLER_SOURCE).toContain("Deno.serve(createPolicyManagementHandler())");
	});

	it("revokes the staged-policy tables and RPCs from browser roles and grants them to service_role", () => {
		expect(ROLLOUT_MIGRATION).toContain(
			"revoke all on public.agent_policy_assignments, public.agent_policy_receipts from anon, authenticated;",
		);
		expect(ROLLOUT_MIGRATION).toContain(
			"grant all on public.agent_policy_assignments, public.agent_policy_receipts to service_role;",
		);
		expect(ROLLOUT_MIGRATION).toContain(
			"revoke all on function public.stage_runtime_policy(uuid,uuid,bigint,jsonb,uuid[]) from public, anon, authenticated;",
		);
		expect(ROLLOUT_MIGRATION).toContain(
			"grant execute on function public.stage_runtime_policy(uuid,uuid,bigint,jsonb,uuid[]) to service_role;",
		);
		expect(ROLLOUT_MIGRATION).toContain(
			"revoke all on function public.record_policy_receipt(text,bigint,text) from public, anon, authenticated;",
		);
		expect(ROLLOUT_MIGRATION).toContain(
			"grant execute on function public.record_policy_receipt(text,bigint,text) to service_role;",
		);
		expect(STAGE_CAS_MIGRATION).toContain(
			"revoke all on function public.stage_runtime_policy(uuid,uuid,bigint,bigint,jsonb,uuid[]) from public, anon, authenticated;",
		);
		expect(STAGE_CAS_MIGRATION).toContain(
			"grant execute on function public.stage_runtime_policy(uuid,uuid,bigint,bigint,jsonb,uuid[]) to service_role;",
		);
		for (const [name, sql] of [
			["rollout", ROLLOUT_MIGRATION],
			["stage CAS", STAGE_CAS_MIGRATION],
		] as const) {
			expect(sql, name).not.toMatch(/grant[^;]*\bto\s+(?:public|anon|authenticated)\b/i);
			for (const revoke of sql.match(/revoke all on function[^;]*;/g) ?? []) {
				expect(revoke, name).toContain("public, anon, authenticated");
			}
		}
	});

	it("implements the atomic revision-precondition CAS on the newest revision under the tenant lock", () => {
		expect(STAGE_CAS_MIGRATION).toContain("drop function public.stage_runtime_policy(uuid, uuid, bigint, jsonb, uuid[]);");
		expect(STAGE_CAS_MIGRATION).toContain("create function public.stage_runtime_policy(");
		expect(STAGE_CAS_MIGRATION).toContain("p_expected_revision_version bigint");
		expect(STAGE_CAS_MIGRATION).toContain("perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text,911));");
		expect(STAGE_CAS_MIGRATION).toContain("select coalesce(max(version),0) into v_latest from public.runtime_policy_revisions where tenant_id=p_tenant_id;");
		expect(STAGE_CAS_MIGRATION).toContain("if v_latest <> p_expected_revision_version then raise exception 'policy_revision_conflict' using errcode='PT409'; end if;");
		expect(STAGE_CAS_MIGRATION).toContain("if coalesce(v_current,0) <> p_expected_version then raise exception 'policy_version_conflict' using errcode='PT409'; end if;");
		expect(STAGE_CAS_MIGRATION).toContain("m.role in ('owner','admin')");
		expect(STAGE_CAS_MIGRATION).toContain("t.status='active'");
		expect(STAGE_CAS_MIGRATION).toContain(
			"insert into public.runtime_policy_revisions(tenant_id,version,policy,updated_by) values(p_tenant_id,v_version,p_policy,p_user_id);",
		);
	});
});
