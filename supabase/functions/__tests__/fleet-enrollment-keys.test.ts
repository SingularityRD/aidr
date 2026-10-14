// Fleet enrollment keys (C3): migration contract, shared validation and the
// /v1/fleet-keys handler. The live-database proof is
// scripts/fleet-enrollment-keys-postgres.test.mjs (disposable Supabase stack).
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	fleetEnrollRateLimit,
	fleetKeyHint,
	isFleetKeyBearer,
	isWellFormedFleetKey,
	randomFleetKey,
	validateFleetKeyCreate,
} from "../_shared/fleet-keys.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const sql = readFileSync(join(ROOT, "supabase", "migrations", "20261014000210_fleet_enrollment_keys.sql"), "utf8");

function fn(name: string): string {
	return sql.split(`create or replace function public.${name}(`)[1]?.split("\n$$;")[0] ?? "";
}

describe("fleet enrollment key migration", () => {
	it("stores keys hash-only, team-scoped, seat-capped, expiring and revocable", () => {
		expect(sql).toContain("key_hash text not null unique");
		expect(sql).toContain("check (key_hash ~ '^[a-f0-9]{64}$')");
		expect(sql).toContain("tenant_id uuid not null references public.tenants (id)");
		expect(sql).toContain("check (seat_cap between 1 and 100000)");
		expect(sql).toContain("check (enrolled_count between 0 and seat_cap)");
		expect(sql).toContain("expires_at <= created_at + interval '366 days'");
		expect(sql).toMatch(/revoked_at timestamptz,\n\s+revoked_by uuid/);
		expect(sql).not.toMatch(/\bplaintext\s+text\b|\bfleet_key\s+text\b/);
	});

	it("lets only tenant owners/admins read non-secret columns and nobody write directly", () => {
		expect(sql).toContain("alter table public.fleet_enrollment_keys enable row level security;");
		expect(sql).toContain("revoke all on public.fleet_enrollment_keys from public, anon, authenticated, service_role;");
		const browserGrant = sql.match(/grant select \(([^)]*)\)\s+on public\.fleet_enrollment_keys to authenticated;/)?.[1] ?? "";
		expect(browserGrant).toContain("key_hint");
		expect(browserGrant).not.toContain("key_hash");
		expect(sql).toContain("using (app.is_tenant_member_with_role(tenant_id, 'admin'))\n  with check (false);");
		expect(sql).toContain("create policy tenant_identity_access_restrict on public.fleet_enrollment_keys");
		expect(sql).toContain("before insert or update of key_hash on public.fleet_enrollment_keys\nfor each row execute function public.require_enrollment_admission();");
	});

	it("restricts every RPC to the service role and pins search_path", () => {
		for (const signature of [
			"issue_fleet_enrollment_key_with_audit(uuid, uuid, text, integer, integer, text, text)",
			"revoke_fleet_enrollment_key_with_audit(uuid, uuid, uuid)",
			"resolve_fleet_enrollment_key(text)",
			"exchange_fleet_enrollment_key(text, text, text, text, text)",
		]) {
			expect(sql).toMatch(new RegExp(`revoke all on function public\\.${signature.replace(/[()]/g, "\\$&")}\\s+from public, anon, authenticated;`));
			expect(sql).toMatch(new RegExp(`grant execute on function public\\.${signature.replace(/[()]/g, "\\$&")}\\s+to service_role;`));
		}
		// Four RPCs plus app.fleet_key_admin.
		expect(sql.match(/security definer\nset search_path = pg_catalog, public, pg_temp/g)?.length).toBe(5);
	});

	it("requires a live owner/admin for issue, revoke, resolve and exchange", () => {
		const admin = sql.split("create or replace function app.fleet_key_admin(")[1]?.split("\n$$;")[0] ?? "";
		expect(admin).toContain("m.role in ('owner', 'admin')");
		expect(admin).toContain("t.status = 'active'");
		expect(admin).toContain("app.directory_membership_grants(m.tenant_id, m.user_id, m.role)");
		for (const name of ["issue_fleet_enrollment_key_with_audit", "revoke_fleet_enrollment_key_with_audit"]) {
			expect(fn(name)).toContain("app.fleet_key_admin(p_tenant_id, p_actor_user_id)");
		}
		expect(fn("resolve_fleet_enrollment_key")).toContain("app.fleet_key_admin(v_key.tenant_id, v_key.created_by)");
		expect(fn("exchange_fleet_enrollment_key")).toContain("app.fleet_key_admin(v_key.tenant_id, v_key.created_by)");
	});

	it("audits issue, revoke and every enrollment in the same transaction", () => {
		expect(fn("issue_fleet_enrollment_key_with_audit")).toContain("'fleet_key.create'");
		expect(fn("revoke_fleet_enrollment_key_with_audit")).toContain("'fleet_key.revoke'");
		expect(fn("exchange_fleet_enrollment_key")).toContain("'fleet_key.enroll'");
		expect(fn("issue_fleet_enrollment_key_with_audit")).toContain("v_active >= 50");
	});

	it("rejects revoked/expired keys and enforces the cap before tenant seat admission", () => {
		const exchange = fn("exchange_fleet_enrollment_key");
		expect(exchange).toContain("for update;");
		expect(exchange).toContain("v_key.revoked_at is not null or v_key.expires_at <= clock_timestamp()");
		const cap = exchange.indexOf("'fleet_key_exhausted'");
		const register = exchange.indexOf("public.register_agent_for_ingest(");
		expect(cap).toBeGreaterThan(0);
		expect(register).toBeGreaterThan(cap);
		expect(exchange).toContain("if v_agent.seat_exceeded then");
		expect(exchange).toContain("enrolled_count = enrolled_count + case when v_agent.created then 1 else 0 end");
		expect(exchange.indexOf("insert into public.api_keys")).toBeGreaterThan(register);
		expect(fn("resolve_fleet_enrollment_key")).toContain("v_key.revoked_at is not null or v_key.expires_at <= clock_timestamp()");
	});

	it("admits the issuance rate-limit scope through the reviewed extension", () => {
		expect(sql).toContain("execute replace(v_definition, v_old, v_old || ', ''fleetkey_create''');");
	});
});

describe("fleet key format and request validation", () => {
	it("mints prefixed 256-bit keys and routes them by prefix", () => {
		const key = randomFleetKey();
		expect(isWellFormedFleetKey(key)).toBe(true);
		expect(isFleetKeyBearer(key)).toBe(true);
		expect(fleetKeyHint(key)).toBe(key.slice(-4));
		expect(randomFleetKey()).not.toBe(key);
		expect(isFleetKeyBearer("aidr_enroll_x")).toBe(false);
		expect(isWellFormedFleetKey(`${key}x`)).toBe(false);
	});

	it("bounds seat cap, lifetime and label", () => {
		expect(validateFleetKeyCreate({ seat_cap: 500 })).toEqual({ ok: true, value: { label: null, seatCap: 500, ttlDays: 90 } });
		expect(validateFleetKeyCreate({ seat_cap: 1, ttl_days: 365, label: " laptops " })).toEqual({
			ok: true, value: { label: "laptops", seatCap: 1, ttlDays: 365 },
		});
		for (const [body, error] of [
			[{}, "invalid_seat_cap"], [{ seat_cap: 0 }, "invalid_seat_cap"], [{ seat_cap: 100_001 }, "invalid_seat_cap"],
			[{ seat_cap: "500" }, "invalid_seat_cap"], [{ seat_cap: 1.5 }, "invalid_seat_cap"],
			[{ seat_cap: 5, ttl_days: 366 }, "invalid_ttl_days"], [{ seat_cap: 5, ttl_days: 0 }, "invalid_ttl_days"],
			[{ seat_cap: 5, label: "a\nb" }, "invalid_label"], [{ seat_cap: 5, label: "x".repeat(101) }, "invalid_label"],
			[{ seat_cap: 5, label: 7 }, "invalid_label"],
		] as const) {
			expect(validateFleetKeyCreate(body as Record<string, unknown>)).toEqual({ ok: false, error });
		}
	});

	it("parses the per-key exchange budget without ever turning it off", () => {
		expect(fleetEnrollRateLimit(undefined)).toBe(600);
		expect(fleetEnrollRateLimit("")).toBe(600);
		expect(fleetEnrollRateLimit("2000")).toBe(2000);
		for (const raw of ["0", "-5", "1.5", "abc", "100001", "1e3"]) expect(fleetEnrollRateLimit(raw)).toBeNull();
	});
});

// ── /v1/fleet-keys handler ─────────────────────────────────────────────────

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const KEY_ID = "44444444-4444-4444-8444-444444444444";

type HandlerOptions = {
	role?: string;
	rateCount?: number;
	rateStoreDown?: boolean;
	rpcResults?: Record<string, { data: unknown; error: unknown }>;
};

async function fleetKeys(options: HandlerOptions = {}) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => { handler = value; },
	});
	const selects: Record<string, string> = {};
	const rpc = vi.fn(async (name: string) => {
		if (name === "increment_rate_limit") {
			return { data: null, error: options.rateStoreDown ? { message: "down" } : null };
		}
		const result = options.rpcResults?.[name];
		if (result) return result;
		throw new Error(`unexpected RPC: ${name}`);
	});
	const single = (table: string) => {
		if (table === "tenant_members") return { tenant_id: TENANT_ID, role: options.role ?? "admin", expires_at: null };
		if (table === "tenants") return { status: "active" };
		if (table === "rate_limits") return { count: options.rateCount ?? 1 };
		return null;
	};
	sdk.createClient.mockReturnValue({
		rpc,
		auth: { getUser: async () => ({ data: { user: { id: USER_ID } }, error: null }) },
		from(table: string) {
			const query = {
				select: (columns: string) => { selects[table] = columns; return query; },
				eq: () => query,
				order: () => query,
				limit: async () => ({ data: [{ id: KEY_ID, key_hint: "AAAA" }], error: null }),
				maybeSingle: async () => ({ data: single(table), error: null }),
			};
			return query;
		},
	});
	vi.resetModules();
	vi.doMock("../_shared/identity-barrier.ts", () => ({ checkIdentityBarrier: async () => ({ ok: true }) }));
	await import("../fleet-keys/index.ts");
	if (!handler) throw new Error("fleet-keys did not register a handler");
	return { handler, rpc, selects };
}

function call(method: "GET" | "POST", body?: unknown) {
	return new Request("https://project.supabase.co/functions/v1/fleet-keys", {
		method,
		headers: { Authorization: "Bearer session", "X-AIDR-Tenant-ID": TENANT_ID, "Content-Type": "application/json" },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	vi.doUnmock("../_shared/identity-barrier.ts");
	sdk.createClient.mockReset();
});

describe("/v1/fleet-keys", () => {
	it.each(["member", "viewer"])("refuses a %s for every action", async (role) => {
		const app = await fleetKeys({ role });
		for (const request of [call("GET"), call("POST", { action: "create", seat_cap: 5 }), call("POST", { action: "revoke", id: KEY_ID })]) {
			const response = await app.handler(request);
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "tenant_admin_required" });
		}
		expect(app.rpc).not.toHaveBeenCalled();
	});

	it("lists keys without the stored hash", async () => {
		const app = await fleetKeys();
		const response = await app.handler(call("GET"));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, keys: [{ id: KEY_ID, key_hint: "AAAA" }] });
		expect(app.selects.fleet_enrollment_keys).not.toContain("key_hash");
	});

	it("returns the plaintext once and sends only its hash and hint to the database", async () => {
		const app = await fleetKeys({
			rpcResults: { issue_fleet_enrollment_key_with_audit: { data: { status: "issued", id: KEY_ID, expires_at: "2027-01-01T00:00:00Z" }, error: null } },
		});
		const response = await app.handler(call("POST", { action: "create", label: "laptops", seat_cap: 500, ttl_days: 90 }));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(isWellFormedFleetKey(body.fleet_key)).toBe(true);
		expect(body).toMatchObject({ ok: true, id: KEY_ID, seat_cap: 500 });
		const args = app.rpc.mock.calls.find(([name]) => name === "issue_fleet_enrollment_key_with_audit")?.[1] as Record<string, unknown>;
		expect(args).toMatchObject({ p_actor_user_id: USER_ID, p_tenant_id: TENANT_ID, p_label: "laptops", p_seat_cap: 500, p_ttl_days: 90 });
		expect(args.p_key_hash).toMatch(/^[a-f0-9]{64}$/);
		expect(args.p_key_hint).toBe(body.fleet_key.slice(-4));
		expect(JSON.stringify(app.rpc.mock.calls)).not.toContain(body.fleet_key);
	});

	it("fails closed on invalid input, rate limit, admission and audit outages", async () => {
		const invalid = await fleetKeys();
		expect((await invalid.handler(call("POST", { action: "create", seat_cap: 0 }))).status).toBe(400);
		expect((await invalid.handler(call("POST", { action: "rotate" }))).status).toBe(400);
		expect((await invalid.handler(call("POST", { action: "revoke", id: "not-a-uuid" }))).status).toBe(400);

		const limited = await fleetKeys({ rateCount: 11 });
		expect((await limited.handler(call("POST", { action: "create", seat_cap: 5 }))).status).toBe(429);
		expect(limited.rpc).not.toHaveBeenCalledWith("issue_fleet_enrollment_key_with_audit", expect.anything());

		const rateDown = await fleetKeys({ rateStoreDown: true });
		expect((await rateDown.handler(call("POST", { action: "create", seat_cap: 5 }))).status).toBe(503);
		expect(rateDown.rpc).not.toHaveBeenCalledWith("issue_fleet_enrollment_key_with_audit", expect.anything());

		const notAdmitted = await fleetKeys({ rpcResults: { issue_fleet_enrollment_key_with_audit: { data: null, error: { code: "42501" } } } });
		expect((await notAdmitted.handler(call("POST", { action: "create", seat_cap: 5 }))).status).toBe(403);

		const outage = await fleetKeys({ rpcResults: { issue_fleet_enrollment_key_with_audit: { data: null, error: { message: "down" } } } });
		const response = await outage.handler(call("POST", { action: "create", seat_cap: 5 }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "audit_unavailable" });

		const crowded = await fleetKeys({ rpcResults: { issue_fleet_enrollment_key_with_audit: { data: { status: "too_many_active_keys", active_keys: 50 }, error: null } } });
		expect((await crowded.handler(call("POST", { action: "create", seat_cap: 5 }))).status).toBe(409);
	});

	it("revokes through the audited RPC and reports unknown keys", async () => {
		const app = await fleetKeys({
			rpcResults: { revoke_fleet_enrollment_key_with_audit: { data: { status: "revoked", id: KEY_ID, revoked_at: "2026-10-14T00:00:00Z" }, error: null } },
		});
		const response = await app.handler(call("POST", { action: "revoke", id: KEY_ID }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, id: KEY_ID, revoked_at: "2026-10-14T00:00:00Z" });
		expect(app.rpc).toHaveBeenCalledWith("revoke_fleet_enrollment_key_with_audit", {
			p_actor_user_id: USER_ID, p_tenant_id: TENANT_ID, p_id: KEY_ID,
		});

		const missing = await fleetKeys({ rpcResults: { revoke_fleet_enrollment_key_with_audit: { data: { status: "not_found" }, error: null } } });
		expect((await missing.handler(call("POST", { action: "revoke", id: KEY_ID }))).status).toBe(404);
	});
});
