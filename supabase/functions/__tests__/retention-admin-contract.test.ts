import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("createClient must be injected through RetentionAdminDeps.db"); },
}));
vi.stubEnv("AIDR_ALLOWED_ORIGINS", "");
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SOURCE = readFileSync(join(ROOT, "supabase", "functions", "retention-admin", "index.ts"), "utf8");
const CONFIG = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
const { createRetentionAdminHandler } = await import("../retention-admin/index.ts");

const TENANT = "11111111-1111-4111-8111-111111111111";
const USER = "22222222-2222-4222-8222-222222222222";
const HOLD = "33333333-3333-4333-8333-333333333333";

interface Options {
	role?: string;
	expiresAt?: string | null;
	member?: boolean;
	tenantStatus?: string;
	pendingIdentity?: boolean;
	rpcError?: { code?: string; message?: string };
	rpcData?: unknown;
	holdCount?: number;
	rateLimited?: boolean;
}

function fakeDb(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const rows: Record<string, Record<string, unknown>[]> = {
		identity_user_session_state: options.pendingIdentity
			? [{ user_id: USER, revoked_before: null, global_revoke_pending_session_id: "pending" }] : [],
		tenant_identity_policies: [{ tenant_id: TENANT, require_mfa: false }],
		tenant_members: options.member === false ? []
			: [{ tenant_id: TENANT, user_id: USER, role: options.role ?? "owner", expires_at: options.expiresAt ?? null }],
		tenants: [{ id: TENANT, status: options.tenantStatus ?? "active" }],
		tenant_legal_holds: Array.from({ length: options.holdCount ?? 1 }, (_, index) => ({
			tenant_id: TENANT,
			id: index === 0 ? HOLD : `33333333-3333-4333-8333-${index.toString(16).padStart(12, "0")}`,
			hold_reference: "CASE-1", case_id: "CASE-1", hold_owner: "Counsel", reason: "preserve", placed_by: USER,
			placed_at: new Date(Date.UTC(2026, 9, 1) - index * 1000).toISOString(),
			released_by: null, released_at: null, release_reason: null,
		})),
		tenant_data_retention_policies: [
			{ tenant_id: TENANT, data_class: "telemetry", retention_days: 30, updated_at: "2026-10-01T00:00:00Z", updated_by: null },
			{ tenant_id: TENANT, data_class: "access_credentials", retention_days: 0, updated_at: "2026-10-01T00:00:00Z", updated_by: null },
		],
		retention_policy_bounds: [
			{ data_class: "telemetry", min_days: 7, max_days: 3650, tenant_configurable: true },
			{ data_class: "access_credentials", min_days: 0, max_days: 0, tenant_configurable: false },
		],
	};
	function query(table: string) {
		const filters = new Map<string, unknown>();
		let maxRows = Number.POSITIVE_INFINITY;
		let columns: string[] | null = null;
		const builder = {
			select: (value?: string) => { columns = typeof value === "string" ? value.split(",").map((column) => column.trim()) : null; return builder; },
			eq: (column: string, value: unknown) => { filters.set(column, value); return builder; },
			or: () => builder,
			order: () => builder,
			limit: (value: number) => { maxRows = value; return builder; },
			maybeSingle: async () => ({ data: result()[0] ?? null, error: null }),
			then: (resolve: (value: unknown) => unknown, reject?: (error: unknown) => unknown) =>
				Promise.resolve({ data: result(), error: null }).then(resolve, reject),
		};
		function result() {
			return (rows[table] ?? []).filter((row) => [...filters].every(([column, value]) => row[column] === value))
				.slice(0, maxRows).map((row) => columns ? Object.fromEntries(columns.map((column) => [column, row[column]])) : row);
		}
		return builder;
	}
	return {
		rpcCalls,
		db: {
			from: (table: string) => query(table),
			rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
				rpcCalls.push({ name, args });
				if (name === "consume_tenant_rate_limit") {
					return options.rateLimited
						? { data: { allowed: false, remaining: 0, retry_after_seconds: 30 }, error: null }
						: { data: { allowed: true, remaining: 59 }, error: null };
				}
				if (options.rpcError) return { data: null, error: options.rpcError };
				if (options.rpcData !== undefined) return { data: options.rpcData, error: null };
				if (name === "admin_place_tenant_legal_hold") return { data: HOLD, error: null };
				if (name === "admin_release_tenant_legal_hold") return { data: true, error: null };
				if (name === "admin_set_tenant_retention") {
					return { data: { data_class: args.p_data_class, retention_days: args.p_retention_days, previous_retention_days: 30, changed: true }, error: null };
				}
				return { data: null, error: null };
			}),
			auth: { getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })) },
		},
	};
}

const request = (method: "GET" | "POST", body?: Record<string, unknown>, headers: Record<string, string> = {}, url = "https://project.supabase.co/functions/v1/retention-admin") =>
	new Request(url, {
		method,
		headers: { Authorization: "Bearer session-token", ...(method === "POST" ? { "Content-Type": "application/json" } : {}), ...headers },
		...(body ? { body: JSON.stringify(body) } : {}),
	});

const place = { action: "place_hold", tenant_id: TENANT, case_id: "CASE-2026-001", owner: "Counsel A", reason: "Litigation preservation" };
const handler = (fixture: ReturnType<typeof fakeDb>) => createRetentionAdminHandler({ db: fixture.db as never });
const writes = (fixture: ReturnType<typeof fakeDb>) => fixture.rpcCalls.filter((call) => call.name.startsWith("admin_"));

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});

describe("retention-admin legal hold and retention API", () => {
	it("places a hold through the audited RPC for an active owner", async () => {
		const fixture = fakeDb();
		const response = await handler(fixture)(request("POST", place));
		expect(response.status).toBe(201);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(await response.json()).toEqual({ ok: true, hold_id: HOLD });
		expect(writes(fixture)).toEqual([{ name: "admin_place_tenant_legal_hold", args: {
			p_tenant_id: TENANT, p_actor_user_id: USER, p_case_id: "CASE-2026-001", p_hold_owner: "Counsel A",
			p_reason: "Litigation preservation", p_hold_reference: null,
		} }]);
	});

	it("releases a hold and reports a missing or already released hold as 404", async () => {
		const ok = fakeDb();
		const released = await handler(ok)(request("POST", { action: "release_hold", tenant_id: TENANT, hold_id: HOLD, reason: "Matter closed" }));
		expect(released.status).toBe(200);
		expect(writes(ok)[0]).toMatchObject({ name: "admin_release_tenant_legal_hold", args: { p_actor_user_id: USER, p_hold_id: HOLD, p_release_reason: "Matter closed" } });
		const gone = fakeDb({ rpcData: false });
		const missing = await handler(gone)(request("POST", { action: "release_hold", tenant_id: TENANT, hold_id: HOLD, reason: "Matter closed" }));
		expect(missing.status).toBe(404);
		expect(await missing.json()).toEqual({ error: "hold_not_found_or_released" });
	});

	it("sets a retention period through the bounded RPC", async () => {
		const fixture = fakeDb();
		const response = await handler(fixture)(request("POST", { action: "set_retention", tenant_id: TENANT, data_class: "telemetry", retention_days: 90, reason: "Policy" }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, data_class: "telemetry", retention_days: 90, previous_retention_days: 30, changed: true });
		expect(writes(fixture)[0]?.args).toMatchObject({ p_data_class: "telemetry", p_retention_days: 90, p_actor_user_id: USER });
	});

	it("allows owners and admins to read, and refuses admins every write", async () => {
		for (const role of ["owner", "admin"]) {
			const response = await handler(fakeDb({ role }))(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }));
			expect(response.status).toBe(200);
			const payload = await response.json();
			expect(payload.holds[0]).toMatchObject({ id: HOLD, case_id: "CASE-1", hold_owner: "Counsel" });
			expect(payload.active_hold).toMatchObject({ id: HOLD });
			expect(payload.retention_policies).toEqual([
				expect.objectContaining({ data_class: "access_credentials", configurable: false }),
				expect.objectContaining({ data_class: "telemetry", retention_days: 30, min_days: 7, max_days: 3650, configurable: true }),
			]);
		}
		const admin = fakeDb({ role: "admin" });
		const denied = await handler(admin)(request("POST", place));
		expect(denied.status).toBe(403);
		expect(await denied.json()).toEqual({ error: "owner_required" });
		expect(writes(admin)).toEqual([]);
	});

	it("refuses members, viewers, non-members, expired memberships and inactive tenants before any RPC", async () => {
		for (const options of [{ role: "member" }, { role: "viewer" }, { member: false }, { expiresAt: "2020-01-01T00:00:00Z" }, { tenantStatus: "closing" }] as Options[]) {
			const fixture = fakeDb(options);
			expect((await handler(fixture)(request("POST", place))).status).toBe(403);
			expect((await handler(fixture)(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }))).status).toBe(403);
			expect(writes(fixture)).toEqual([]);
		}
	});

	it("requires a bearer token and refuses a pending global revocation", async () => {
		const fixture = fakeDb();
		expect((await handler(fixture)(new Request("https://project.supabase.co/functions/v1/retention-admin", { method: "POST", body: "{}" }))).status).toBe(401);
		const pending = fakeDb({ pendingIdentity: true });
		const response = await handler(pending)(request("POST", place));
		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(writes(pending)).toEqual([]);
	});

	it("rejects malformed, unknown and over-broad requests without calling the database", async () => {
		const bad: Array<Record<string, unknown>> = [
			{ ...place, case_id: "bad;case" },
			{ ...place, owner: " padded " },
			{ ...place, reason: "" },
			{ ...place, extra: true },
			{ ...place, tenant_id: "not-a-uuid" },
			{ action: "release_hold", tenant_id: TENANT, hold_id: "nope", reason: "x" },
			{ action: "set_retention", tenant_id: TENANT, data_class: "telemetry", retention_days: 1.5, reason: "x" },
			{ action: "set_retention", tenant_id: TENANT, data_class: "bogus", retention_days: 10, reason: "x" },
			{ action: "set_retention", tenant_id: TENANT, data_class: "telemetry", retention_days: 99999, reason: "x" },
			{ action: "delete_everything", tenant_id: TENANT },
		];
		for (const body of bad) {
			const fixture = fakeDb();
			const response = await handler(fixture)(request("POST", body));
			expect(response.status, JSON.stringify(body)).toBe(400);
			expect(writes(fixture)).toEqual([]);
		}
		const mismatch = fakeDb();
		const response = await handler(mismatch)(request("POST", place, { "X-AIDR-Tenant-ID": "44444444-4444-4444-8444-444444444444" }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "tenant_mismatch" });
	});

	it("maps database refusals to stable, non-leaking errors", async () => {
		const cases: Array<[{ code?: string; message: string }, number, string]> = [
			[{ message: "retention_admin_owner_required" }, 403, "owner_required"],
			[{ code: "23505", message: "legal_hold_already_active" }, 409, "hold_already_active"],
			[{ message: "legal_hold_refused_pending_export_deletion" }, 409, "hold_refused_pending_deletion"],
			[{ message: "legal_hold_refused_pending_pack_deletion" }, 409, "hold_refused_pending_deletion"],
			[{ message: "legal_hold_invalid_request" }, 400, "invalid_request"],
			[{ message: "retention_days_out_of_bounds" }, 400, "retention_days_out_of_bounds"],
			[{ message: "retention_class_not_configurable" }, 400, "retention_class_not_configurable"],
			[{ message: "retention_change_refused_offboarding" }, 409, "retention_change_refused_offboarding"],
			[{ message: "connection to 10.0.0.5 refused: secret detail" }, 503, "retention_management_unavailable"],
		];
		for (const [rpcError, status, error] of cases) {
			const response = await handler(fakeDb({ rpcError }))(request("POST", place));
			const body = await response.json();
			expect(response.status).toBe(status);
			expect(body.error).toBe(error);
			expect(JSON.stringify(body)).not.toContain("10.0.0.5");
		}
		const refused = await (await handler(fakeDb({ rpcError: { message: "legal_hold_refused_pending_export_deletion" } }))(request("POST", place))).json();
		expect(refused.hold_active).toBe(false);
	});

	it("rate limits per tenant and subject with Retry-After", async () => {
		const fixture = fakeDb({ rateLimited: true });
		const response = await handler(fixture)(request("POST", place));
		expect(response.status).toBe(429);
		expect(response.headers.get("Retry-After")).toBeTruthy();
		expect(writes(fixture)).toEqual([]);
	});

	it("rejects bad pagination and pages hold history", async () => {
		const bad = await handler(fakeDb())(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }, "https://project.supabase.co/functions/v1/retention-admin?hold_after_id=nope"));
		expect(bad.status).toBe(400);
		const paged = await (await handler(fakeDb({ holdCount: 60 }))(request("GET", undefined, { "X-AIDR-Tenant-ID": TENANT }))).json();
		expect(paged.holds).toHaveLength(50);
		expect(paged.next_hold_cursor).toMatchObject({ id: expect.any(String), placed_at: expect.any(String) });
	});

	it("is deployed with gateway JWT verification and the shared identity barrier", () => {
		expect(CONFIG).toMatch(/\[functions\.retention-admin\][\s\S]*?verify_jwt = true/);
		expect(SOURCE).toContain("checkIdentityBarrier(db, token, userId, tenantId)");
		expect(SOURCE).not.toMatch(/\.(insert|update|delete|upsert)\(/);
	});
});
