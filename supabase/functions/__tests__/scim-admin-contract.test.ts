import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("createClient must be injected through ScimAdminDeps.db"); },
}));

vi.stubEnv("AIDR_ALLOWED_ORIGINS", "");

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SOURCE = readFileSync(join(ROOT, "supabase", "functions", "scim-admin", "index.ts"), "utf8");
const MIGRATION = readFileSync(join(ROOT, "supabase", "migrations", "20260922000009_scim_admin_bootstrap.sql"), "utf8");
const EXPIRY_MIGRATION = readFileSync(join(ROOT, "supabase", "migrations", "20260923000018_scim_token_expiry.sql"), "utf8");
const SUPABASE_CONFIG = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
const { createScimAdminHandler } = await import("../scim-admin/index.ts");

const TENANT = "11111111-1111-4111-8111-111111111111";
const USER = "22222222-2222-4222-8222-222222222222";
const TOKEN_ID = "33333333-3333-4333-8333-333333333333";
const NEW_TOKEN_ID = "44444444-4444-4444-8444-444444444444";
const SESSION = "session-token";

interface Options {
	role?: string;
	expiresAt?: unknown;
	member?: boolean;
	tenantStatus?: string;
	pendingIdentity?: boolean;
	requireMfa?: boolean;
	assurance?: "aal1" | "aal2";
	revokedBefore?: string | null;
	tableError?: string;
	tokenCount?: number;
	mappingCount?: number;
	rpcError?: { code?: string; message?: string };
	rpcData?: unknown;
}

function fakeDb(options: Options = {}) {
	const calls: string[] = [];
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const rows: Record<string, Record<string, unknown>[]> = {
		identity_user_session_state: options.pendingIdentity
			? [{ user_id: USER, revoked_before: options.revokedBefore ?? null, global_revoke_pending_session_id: "pending" }]
			: options.revokedBefore ? [{ user_id: USER, revoked_before: options.revokedBefore, global_revoke_pending_session_id: null }] : [],
		tenant_identity_policies: [{ tenant_id: TENANT, require_mfa: options.requireMfa ?? false }],
		tenant_members: options.member === false ? [] : [{ tenant_id: TENANT, user_id: USER, role: options.role ?? "owner", expires_at: options.expiresAt === undefined ? null : options.expiresAt }],
		tenants: [{ id: TENANT, status: options.tenantStatus ?? "active" }],
		scim_tokens: Array.from({ length: options.tokenCount ?? 1 }, (_, index) => ({
			id: index === 0 ? TOKEN_ID : `33333333-3333-4333-8333-${index.toString(16).padStart(12, "0")}`,
			tenant_id: TENANT, label: index === 0 ? "entra" : `entra-${index}`, rotated_from: null,
			created_at: new Date(Date.UTC(2026, 8, 1) - index * 1000).toISOString(), expires_at: null,
			revoked_at: null, last_used_at: null, token_hash: "f".repeat(64),
		})),
		scim_group_role_mappings: Array.from({ length: options.mappingCount ?? 1 }, (_, index) => ({
			tenant_id: TENANT,
			external_group_id: options.mappingCount === undefined || options.mappingCount === 1
				? "entra-group-immutable-id" : `entra-group-${index.toString().padStart(4, "0")}`,
			role: "viewer", created_by: USER, created_at: "2026-09-01T00:00:00.000Z",
		})),
	};

	function query(table: string) {
		const filters = new Map<string, unknown>();
		const greaterThan = new Map<string, unknown>();
		let columns: string[] | null = null;
		let maxRows = Number.POSITIVE_INFINITY;
		let tokenAfter: { createdAt: string; id: string } | null = null;
		const orderBy: Array<{ column: string; ascending: boolean }> = [];
		const builder = {
			select: (value?: string) => { columns = typeof value === "string" ? value.split(",").map((column) => column.trim()) : null; return builder; },
			eq: (column: string, value: unknown) => { filters.set(column, value); return builder; },
			gt: (column: string, value: unknown) => { greaterThan.set(column, value); return builder; },
			or: (value: string) => {
				const match = /^created_at\.lt\.(.+),and\(created_at\.eq\.(.+),id\.gt\.([0-9a-f-]+)\)$/.exec(value);
				if (match) tokenAfter = { createdAt: match[2], id: match[3] };
				return builder;
			},
			order: (column: string, options?: { ascending?: boolean }) => { orderBy.push({ column, ascending: options?.ascending ?? true }); return builder; },
			limit: (value: number) => { maxRows = value; return builder; },
			maybeSingle: async () => {
				calls.push(table);
				if (options.tableError === table) return { data: null, error: new Error("storage unavailable") };
				return { data: result()[0] ?? null, error: null };
			},
			then: (resolve: (value: unknown) => unknown, reject?: (error: unknown) => unknown) => {
				calls.push(table);
				if (options.tableError === table) return Promise.resolve({ data: null, error: new Error("storage unavailable") }).then(resolve, reject);
				return Promise.resolve({ data: result(), error: null }).then(resolve, reject);
			},
		};
		function result() {
			const matches = (rows[table] ?? []).filter((row) => {
				if (![...filters].every(([column, value]) => row[column] === value)) return false;
				if (![...greaterThan].every(([column, value]) => String(row[column]) > String(value))) return false;
				if (table === "scim_tokens" && tokenAfter) {
					const createdAt = String(row.created_at);
					if (!(createdAt < tokenAfter.createdAt || (createdAt === tokenAfter.createdAt && String(row.id) > tokenAfter.id))) return false;
				}
				return true;
			});
			matches.sort((left, right) => {
				for (const { column, ascending } of orderBy) {
					const leftValue = String(left[column]);
					const rightValue = String(right[column]);
					const comparison = leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
					if (comparison !== 0) return ascending ? comparison : -comparison;
				}
				return 0;
			});
			return matches.slice(0, maxRows).map((row) => columns ? Object.fromEntries(columns.map((column) => [column, row[column]])) : row);
		}
		return builder;
	}

	return {
		calls,
		rpcCalls,
		rows,
		db: {
			from: (table: string) => query(table),
			rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
				rpcCalls.push({ name, args });
				if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 59 }, error: null };
				if (options.rpcError) return { data: null, error: options.rpcError };
				if (options.rpcData !== undefined) return { data: options.rpcData, error: null };
				if (name === "scim_admin_create_token") return { data: NEW_TOKEN_ID, error: null };
				if (name === "scim_admin_set_group_role_mapping") return { data: true, error: null };
				if (name === "scim_admin_remove_group_role_mapping" || name === "scim_admin_revoke_token") return { data: true, error: null };
				return { data: null, error: null };
			}),
			auth: {
				getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })),
				mfa: { getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: options.assurance ?? "aal2" }, error: null })) },
			},
		},
	};
}

function request(method: "GET" | "POST", body?: Record<string, unknown>, headers: Record<string, string> = {}, url = "https://project.supabase.co/functions/v1/scim-admin"): Request {
	return new Request(url, {
		method,
		headers: { Authorization: `Bearer ${SESSION}`, ...(method === "POST" ? { "Content-Type": "application/json" } : {}), ...headers },
		...(body ? { body: JSON.stringify(body) } : {}),
	});
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});

describe("SCIM tenant-owner management boundary", () => {
	it("creates a random one-time token while sending only its SHA-256 hash to storage", async () => {
		const fixture = fakeDb();
		const before = Date.now();
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", {
			action: "create_token", tenant_id: TENANT, label: "Entra provisioning",
		}));
		const after = Date.now();
		const payload = await response.json();
		expect(response.status).toBe(201);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(payload).toMatchObject({ ok: true, token_id: NEW_TOKEN_ID });
		expect(payload.scim_token).toMatch(/^aidr_scim_[A-Za-z0-9_-]{43}$/);
		const create = fixture.rpcCalls.find((call) => call.name === "scim_admin_create_token");
		expect(create?.args).toMatchObject({ p_tenant_id: TENANT, p_actor_user_id: USER, p_label: "Entra provisioning", p_rotated_from_id: null });
		expect(create?.args.p_token_hash).toMatch(/^[a-f0-9]{64}$/);
		expect(create?.args.p_token_hash).not.toBe(payload.scim_token);
		expect(JSON.stringify(create?.args)).not.toContain(payload.scim_token);
		const defaultTtl = 90 * 24 * 60 * 60 * 1000;
		expect(Date.parse(String(create?.args.p_expires_at))).toBeGreaterThanOrEqual(before + defaultTtl);
		expect(Date.parse(String(create?.args.p_expires_at))).toBeLessThanOrEqual(after + defaultTtl);
		expect(payload.expires_at).toBe(create?.args.p_expires_at);
	});

	it("accepts a bounded explicit expiry and returns it to the operator", async () => {
		const fixture = fakeDb();
		const expires = new Date(Date.now() + 364 * 24 * 60 * 60 * 1000).toISOString();
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", {
			action: "create_token", tenant_id: TENANT, label: "Entra provisioning", expires_at: expires,
		}));
		expect(response.status).toBe(201);
		expect((await response.json()).expires_at).toBe(expires);
		expect(fixture.rpcCalls.find((call) => call.name === "scim_admin_create_token")?.args.p_expires_at).toBe(expires);
	});

	it("lists token metadata and mappings without exposing stored hashes", async () => {
		const response = await createScimAdminHandler({ db: fakeDb().db as never })(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }));
		const payload = await response.json();
		expect(response.status).toBe(200);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(payload.tokens[0]).toMatchObject({ id: TOKEN_ID, label: "entra" });
		expect(payload.tokens[0]).not.toHaveProperty("token_hash");
		expect(payload.group_role_mappings).toEqual([{ external_group_id: "entra-group-immutable-id", role: "viewer", created_by: USER, created_at: "2026-09-01T00:00:00.000Z" }]);
	});

	it("uses stable keyset cursors when new rows arrive between pages", async () => {
		const fixture = fakeDb({ tokenCount: 101, mappingCount: 501 });
		const handler = createScimAdminHandler({ db: fixture.db as never });
		const headers = { "X-AIDR-Tenant-ID": TENANT };
		const first = await handler(request("GET", undefined, headers));
		const firstPage = await first.json();
		expect(first.status).toBe(200);
		expect(firstPage.tokens).toHaveLength(100);
		expect(firstPage.group_role_mappings).toHaveLength(500);
		expect(firstPage.next_token_cursor).toMatchObject({ id: "33333333-3333-4333-8333-000000000063" });
		expect(firstPage.next_mapping_cursor).toBe("entra-group-0499");

		fixture.rows.scim_tokens.unshift({
			id: "88888888-8888-4888-8888-888888888888", tenant_id: TENANT, label: "concurrent",
			rotated_from: null, created_at: "2026-09-02T00:00:00.000Z", expires_at: null,
			revoked_at: null, last_used_at: null, token_hash: "e".repeat(64),
		});
		fixture.rows.scim_group_role_mappings.unshift({
			tenant_id: TENANT, external_group_id: "entra-group-0000a", role: "viewer",
			created_by: USER, created_at: "2026-09-01T00:00:00.000Z",
		});

		const cursor = new URLSearchParams({
			token_after_created_at: firstPage.next_token_cursor.created_at,
			token_after_id: firstPage.next_token_cursor.id,
			mapping_after_external_group_id: firstPage.next_mapping_cursor,
		});
		const second = await handler(request("GET", undefined, headers,
			`https://project.supabase.co/functions/v1/scim-admin?${cursor}`));
		const secondPage = await second.json();
		expect(second.status).toBe(200);
		expect(secondPage.tokens).toHaveLength(1);
		expect(secondPage.group_role_mappings).toHaveLength(1);
		expect(secondPage.next_token_cursor).toBeNull();
		expect(secondPage.next_mapping_cursor).toBeNull();
		expect(secondPage.tokens[0].id).toBe("33333333-3333-4333-8333-000000000064");
		expect(secondPage.group_role_mappings[0].external_group_id).toBe("entra-group-0500");
	});

	it.each([
		"?token_after_created_at=2026-09-01T00%3A00%3A00.000Z",
		"?token_after_id=33333333-3333-4333-8333-000000000063",
		"?token_after_created_at=bad&token_after_id=33333333-3333-4333-8333-000000000063",
		"?token_after_created_at=2026-09-01T00%3A00%3A00.000Z&token_after_id=bad",
		"?mapping_after_external_group_id=",
		"?mapping_after_external_group_id=group&mapping_after_external_group_id=group2",
	])("rejects malformed GET cursors (%s)", async (cursor) => {
		const fixture = fakeDb();
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("GET", undefined,
			{ "X-AIDR-Tenant-ID": TENANT },
			`https://project.supabase.co/functions/v1/scim-admin${cursor}`));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_pagination" });
		expect(fixture.calls).not.toContain("scim_tokens");
	});

	it("rejects unapproved browser origins before authentication or database access", async () => {
		const fixture = fakeDb();
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("GET", undefined, {
			"X-AIDR-Tenant-ID": TENANT, Origin: "https://unapproved.example",
		}));
		expect(response.status).toBe(403);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(fixture.calls).toEqual([]);
		expect(fixture.db.auth.getUser).not.toHaveBeenCalled();
	});

	it("advertises the tenant header required by browser pagination", async () => {
		const fixture = fakeDb();
		const response = await createScimAdminHandler({ db: fixture.db as never })(new Request("https://project.supabase.co/functions/v1/scim-admin", { method: "OPTIONS" }));
		expect(response.status).toBe(200);
		expect(response.headers.get("Access-Control-Allow-Headers")).toContain("X-AIDR-Tenant-ID");
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(fixture.db.auth.getUser).not.toHaveBeenCalled();
	});

	it("permits rotation without revoking the prior token, and scopes revocation to the selected tenant", async () => {
		const fixture = fakeDb();
		const handler = createScimAdminHandler({ db: fixture.db as never });
		const rotated = await handler(request("POST", { action: "rotate_token", tenant_id: TENANT, token_id: TOKEN_ID, label: "Entra overlap" }));
		expect(rotated.status).toBe(201);
		expect(fixture.rpcCalls.find((call) => call.name === "scim_admin_create_token")?.args.p_rotated_from_id).toBe(TOKEN_ID);
		expect(Date.parse(String(fixture.rpcCalls.find((call) => call.name === "scim_admin_create_token")?.args.p_expires_at))).toBeGreaterThan(Date.now());
		const revoked = await handler(request("POST", { action: "revoke_token", tenant_id: TENANT, token_id: TOKEN_ID }));
		expect(revoked.status).toBe(200);
		expect(fixture.rpcCalls.find((call) => call.name === "scim_admin_revoke_token")?.args).toEqual({ p_tenant_id: TENANT, p_actor_user_id: USER, p_token_id: TOKEN_ID });
	});

	it("maps only exact immutable external IDs and the least-privilege role allowlist", async () => {
		const fixture = fakeDb();
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", {
			action: "set_group_mapping", tenant_id: TENANT, external_group_id: "00000000-0000-4000-8000-000000000123", role: "viewer",
		}));
		expect(response.status).toBe(200);
		expect(fixture.rpcCalls.find((call) => call.name === "scim_admin_set_group_role_mapping")?.args).toEqual({
			p_tenant_id: TENANT, p_actor_user_id: USER, p_external_group_id: "00000000-0000-4000-8000-000000000123", p_role: "viewer",
		});
	});

	it.each([
		{ action: "set_group_mapping", tenant_id: TENANT, external_group_id: "group", role: "owner" },
		{ action: "set_group_mapping", tenant_id: TENANT, external_group_id: " group ", role: "admin" },
		{ action: "set_group_mapping", tenant_id: TENANT, external_group_id: "group", role: "Admin" },
		{ action: "revoke_token", tenant_id: TENANT, token_id: "not-a-uuid" },
		{ action: "create_token", tenant_id: TENANT, label: "bad\nlabel" },
		{ action: "create_token", tenant_id: TENANT, label: "valid", expires_at: "not-a-time" },
		{ action: "create_token", tenant_id: TENANT, label: "valid", expires_at: null },
		{ action: "create_token", tenant_id: TENANT, label: "valid", expires_at: new Date(Date.now() + 366 * 24 * 60 * 60 * 1000).toISOString() },
		{ action: "rotate_token", tenant_id: TENANT, token_id: TOKEN_ID, label: "valid", expires_at: null },
		{ action: "create_token", tenant_id: TENANT, label: "valid", unexpected: true },
	])("rejects malformed or ambiguous command %# before tenant data access", async (body) => {
		const fixture = fakeDb();
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", body));
		expect(response.status).toBe(400);
		expect(fixture.calls).not.toContain("tenant_members");
		expect(fixture.rpcCalls.some((call) => call.name.startsWith("scim_admin_"))).toBe(false);
	});

	it.each([
		[{ role: "admin" }, "owner_required"],
		[{ role: "owner", member: false }, "owner_required"],
		[{ role: "owner", tenantStatus: "suspended" }, "owner_required"],
		[{ role: "owner", expiresAt: "2000-01-01T00:00:00.000Z" }, "owner_required"],
		[{ role: "owner", expiresAt: "not-a-date" }, "owner_required"],
	])("rejects non-owner/inactive tenant access %#", async (options, expected) => {
		const fixture = fakeDb(options);
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", {
			action: "create_token", tenant_id: TENANT, label: "bootstrap",
		}));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: expected });
		expect(fixture.rpcCalls.some((call) => call.name.startsWith("scim_admin_") && call.name !== "scim_admin_create_token")).toBe(false);
	});

	it("rejects a cross-tenant header/body mismatch", async () => {
		const fixture = fakeDb();
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", {
			action: "create_token", tenant_id: TENANT, label: "bootstrap",
		}, { "X-AIDR-Tenant-ID": "55555555-5555-4555-8555-555555555555" }));
		expect(response.status).toBe(400);
		expect(fixture.calls).not.toContain("tenant_members");
	});

	it("stops pending global identity revocation before tenant membership or SCIM reads", async () => {
		const fixture = fakeDb({ pendingIdentity: true });
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "session_revoked" });
		expect(fixture.calls).not.toContain("tenant_members");
		expect(fixture.calls).not.toContain("scim_tokens");
	});

	it("stops a revoked session before tenant membership or SCIM reads", async () => {
		const fixture = fakeDb({ revokedBefore: "2030-01-01T00:00:00.000Z" });
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "session_revoked" });
		expect(fixture.calls).not.toContain("tenant_members");
		expect(fixture.calls).not.toContain("scim_tokens");
	});

	it("stops tenant-MFA failures before membership or SCIM data reads", async () => {
		const fixture = fakeDb({ requireMfa: true, assurance: "aal1" });
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(fixture.calls).not.toContain("tenant_members");
		expect(fixture.calls).not.toContain("scim_tokens");
	});

	it.each([
		{ action: "create_token", tenant_id: TENANT, label: "Entra provisioning" },
		{ action: "rotate_token", tenant_id: TENANT, token_id: TOKEN_ID, label: "Entra rotated" },
		{ action: "set_group_mapping", tenant_id: TENANT, external_group_id: "entra-group-id", role: "admin" },
		{ action: "remove_group_mapping", tenant_id: TENANT, external_group_id: "entra-group-immutable-id" },
	])("requires an AAL2 session for privilege-granting action $action even without tenant MFA policy", async (body) => {
		const fixture = fakeDb({ assurance: "aal1" });
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", body));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(fixture.rpcCalls.map((call) => call.name)).toEqual([]);
	});

	it("fails closed when assurance cannot be read for a privilege-granting action", async () => {
		const fixture = fakeDb();
		fixture.db.auth.mfa.getAuthenticatorAssuranceLevel = vi.fn(async () => ({ data: null, error: new Error("auth down") })) as never;
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", {
			action: "create_token", tenant_id: TENANT, label: "Entra provisioning",
		}));
		expect(response.status).toBe(503);
		expect(fixture.rpcCalls.some((call) => call.name === "scim_admin_create_token")).toBe(false);
	});

	it("keeps token revocation and reads available at AAL1 so a leaked token can be cut off quickly", async () => {
		const revoke = fakeDb({ assurance: "aal1" });
		const revoked = await createScimAdminHandler({ db: revoke.db as never })(request("POST", {
			action: "revoke_token", tenant_id: TENANT, token_id: TOKEN_ID,
		}));
		expect(revoked.status).toBe(200);
		const read = fakeDb({ assurance: "aal1" });
		expect((await createScimAdminHandler({ db: read.db as never })(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }))).status).toBe(200);
	});

	it("fails closed if mapping reconciliation would take over a manual team membership", async () => {
		const fixture = fakeDb({ rpcError: { code: "42501", message: "scim_cannot_take_over_manual_membership" } });
		const response = await createScimAdminHandler({ db: fixture.db as never })(request("POST", {
			action: "set_group_mapping", tenant_id: TENANT, external_group_id: "entra-group-id", role: "admin",
		}));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "mapping_conflicts_with_manual_membership" });
	});

	it("keeps management RPCs service-role-only and records actor, tenant and no raw secret", () => {
		expect(MIGRATION).toContain("app.scim_assert_tenant_owner");
		expect(MIGRATION).toContain("scim_admin_create_token");
		expect(MIGRATION).toContain("scim_admin_revoke_token");
		expect(MIGRATION).toContain("scim_admin_set_group_role_mapping");
		expect(MIGRATION).toContain("scim_admin_remove_group_role_mapping");
		expect(MIGRATION).toMatch(/revoke all on function public\.scim_admin_create_token[\s\S]*?from public, anon, authenticated/i);
		expect(MIGRATION).toMatch(/grant execute on function public\.scim_admin_create_token[\s\S]*?to service_role/i);
		expect(MIGRATION).toContain("p_actor_user_id");
		expect(MIGRATION).toContain("p_token_hash");
		expect(MIGRATION).toMatch(/tm\.role\s*=\s*'owner'/i);
		expect(MIGRATION).toMatch(/t\.status\s*=\s*'active'/i);
		expect(MIGRATION).toMatch(/tm\.expires_at\s+is\s+null\s+or\s+tm\.expires_at\s*>\s*now\(\)/i);
		for (const name of ["scim_admin_create_token", "scim_admin_revoke_token", "scim_admin_set_group_role_mapping", "scim_admin_remove_group_role_mapping"]) {
			expect(MIGRATION).toMatch(new RegExp(`revoke all on function public\\.${name}[\\s\\S]*?from public, anon, authenticated`, "i"));
			expect(MIGRATION).toMatch(new RegExp(`grant execute on function public\\.${name}[\\s\\S]*?to service_role`, "i"));
		}
		expect(SUPABASE_CONFIG).toMatch(/\[functions\.scim-admin\][\s\S]*?verify_jwt\s*=\s*true/i);
		expect(SOURCE).toContain("await sha256(secret)");
		expect(SOURCE).not.toMatch(/console\.(?:log|info|warn|error)\([^\n]*(?:secret|scim_token)/i);
		expect(SOURCE.indexOf("checkIdentityBarrier(db, token, userId, tenantId)")).toBeLessThan(SOURCE.indexOf('db.from("scim_tokens")'));
		expect(EXPIRY_MIGRATION).toMatch(/coalesce\(p_expires_at,\s*v_now\s*\+\s*interval '90 days'\)/i);
		expect(EXPIRY_MIGRATION).toMatch(/v_expires_at\s*>\s*v_now\s*\+\s*interval '365 days'/i);
		expect(EXPIRY_MIGRATION).toMatch(/values\s*\(p_tenant_id,\s*p_token_hash,\s*p_label,\s*v_expires_at,\s*p_rotated_from_id\)/i);
		expect(EXPIRY_MIGRATION).not.toMatch(/update\s+public\.scim_tokens/i);
	});
});
