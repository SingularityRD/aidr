import { createHash, randomUUID, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	ADMISSION_SCOPE,
	type AdmitCredential,
	LEASE_SECONDS,
	type LeaseDatabase,
	parseTenantConcurrencyConfig,
	SERVICE_OVERLOADED,
	sharedLeaseAdmission,
	TENANT_LIMITER_UNAVAILABLE,
	TENANT_OVERLOADED,
	type TenantConcurrencyConfig,
	type TenantSlotRejection,
	tenantSlotGate,
	tenantSlotResponse,
	withTenantSlot,
} from "../_shared/tenant-concurrency.ts";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

vi.stubGlobal("crypto", webcrypto);

const quietLogger = () => ({ warn: vi.fn(), error: vi.fn() });
const env = (values: Record<string, string>) => (name: string) => values[name];
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const CONFIG: TenantConcurrencyConfig = { capacity: 10, perTenantMax: 7, fairShareFloor: 2, retryAfterSeconds: 1 };

/**
 * In-memory model of acquire/release_tenant_inflight_lease
 * (supabase/migrations/20261016000100_tenant_inflight_shared_leases.sql), so the
 * handlers can run against shared state the way separate workers and functions do.
 * The SQL itself is exercised by scripts/tenant-inflight-lease-postgres.test.mjs.
 */
class FakeLeases {
	slots = new Map<number, { leaseId: string; chargedTo: string; unresolvedKey: string | null }>();
	calls: Array<{ name: string; args: Record<string, unknown> }> = [];
	constructor(private tenantByHash: Map<string, string> = new Map()) {}

	snapshot(): Record<string, number> {
		const out: Record<string, number> = {};
		for (const { chargedTo } of this.slots.values()) out[chargedTo] = (out[chargedTo] ?? 0) + 1;
		return out;
	}

	rpc(name: string, args: Record<string, unknown>): { data: unknown; error: unknown } | null {
		if (name === "release_tenant_inflight_lease") {
			this.calls.push({ name, args });
			const held = this.slots.get(Number(args.p_slot));
			if (held?.leaseId === args.p_lease_id) this.slots.delete(Number(args.p_slot));
			return { data: Boolean(held), error: null };
		}
		if (name !== "acquire_tenant_inflight_lease") return null;
		this.calls.push({ name, args });
		const capacity = Number(args.p_capacity), max = Number(args.p_per_tenant_max), floor = Number(args.p_fair_share_floor);
		const key = String(args.p_key_hash);
		const charged = this.tenantByHash.get(key) ?? "unresolved";
		const live = [...this.slots.values()];
		const total = live.length;
		const held = live.filter((slot) => slot.chargedTo === charged).length;
		const active = new Set(live.map((slot) => slot.chargedTo)).size;
		const busy = live.some((slot) => slot.unresolvedKey === key);
		let reason: string | null = null;
		if (charged === "unresolved" && busy && total >= max) reason = "unresolved_key_busy";
		else if (total >= capacity) reason = "capacity";
		else if (held >= max) reason = "tenant_max";
		else if (total >= max && held >= Math.max(floor, Math.floor(capacity / Math.max(1, active + (held === 0 ? 1 : 0))))) reason = "fair_share";
		const counts = { charged_to: charged, held, total, active };
		if (reason) return { data: { admitted: false, reason, ...counts }, error: null };
		let slot = 1;
		while (this.slots.has(slot)) slot += 1;
		const leaseId = randomUUID();
		this.slots.set(slot, { leaseId, chargedTo: charged, unresolvedKey: charged === "unresolved" ? key : null });
		return {
			data: { admitted: true, slot, lease_id: leaseId, reclaimed: false, charged_to: charged, held: held + 1, total: total + 1, active: active + (held === 0 ? 1 : 0) },
			error: null,
		};
	}

	database(): LeaseDatabase {
		return { rpc: async (name, args) => this.rpc(name, args) ?? { data: null, error: { message: `unexpected RPC ${name}` } } };
	}
}

function scripted(answer: (name: string, args: Record<string, unknown>) => { data: unknown; error: unknown } | Promise<never>) {
	const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const db: LeaseDatabase = { rpc: async (name, args) => { calls.push({ name, args }); return answer(name, args); } };
	return { db, calls };
}

const admittedAnswer = (overrides: Record<string, unknown> = {}) => ({
	admitted: true, slot: 3, lease_id: "0d4c5f4e-5a7c-4c43-9a8a-1f5b8d2f0e11", reclaimed: false,
	charged_to: "tenant-a", held: 1, total: 1, active: 1, ...overrides,
});

describe("tenant concurrency configuration", () => {
	it("uses documented defaults and derives the per-tenant cap from capacity", () => {
		expect(parseTenantConcurrencyConfig(env({}))).toEqual({
			ok: true, config: { capacity: 10, perTenantMax: 7, fairShareFloor: 2, retryAfterSeconds: 1 },
		});
		expect(parseTenantConcurrencyConfig(env({ AIDR_TENANT_INFLIGHT_CAPACITY: "40" }))).toMatchObject({
			ok: true, config: { capacity: 40, perTenantMax: 30, fairShareFloor: 2 },
		});
		expect(parseTenantConcurrencyConfig(env({ AIDR_TENANT_INFLIGHT_CAPACITY: "1" }))).toMatchObject({
			ok: true, config: { capacity: 1, perTenantMax: 1, fairShareFloor: 1 },
		});
	});

	it("treats every malformed or out-of-range value as a configuration problem", () => {
		for (const values of [
			{ AIDR_TENANT_INFLIGHT_CAPACITY: "0" },
			{ AIDR_TENANT_INFLIGHT_CAPACITY: "-4" },
			{ AIDR_TENANT_INFLIGHT_CAPACITY: "12.5" },
			{ AIDR_TENANT_INFLIGHT_CAPACITY: "10001" },
			{ AIDR_TENANT_INFLIGHT_CAPACITY: "8", AIDR_TENANT_INFLIGHT_MAX: "9" },
			{ AIDR_TENANT_INFLIGHT_MAX: "abc" },
			{ AIDR_TENANT_INFLIGHT_CAPACITY: "8", AIDR_TENANT_INFLIGHT_MAX: "4", AIDR_TENANT_INFLIGHT_FAIR_SHARE_FLOOR: "5" },
			{ AIDR_TENANT_INFLIGHT_RETRY_AFTER_SECONDS: "61" },
		]) {
			expect(parseTenantConcurrencyConfig(env(values)).ok, JSON.stringify(values)).toBe(false);
		}
	});
});

describe("shared lease admission", () => {
	it("acquires with the key's SHA-256, the shared scope and the configured limits, and releases that lease once", async () => {
		const { db, calls } = scripted((name) => ({ data: name === "acquire_tenant_inflight_lease" ? admittedAnswer() : true, error: null }));
		const admit = sharedLeaseAdmission(CONFIG, { logger: quietLogger() });
		const slot = await admit(db, "aidr_secret_key");
		expect(slot).toMatchObject({ ok: true, chargedTo: "tenant-a" });
		expect(calls).toEqual([{
			name: "acquire_tenant_inflight_lease",
			args: {
				p_scope: ADMISSION_SCOPE, p_key_hash: hash("aidr_secret_key"),
				p_capacity: 10, p_per_tenant_max: 7, p_fair_share_floor: 2, p_lease_seconds: LEASE_SECONDS,
			},
		}]);
		// The plaintext key never reaches the database.
		expect(JSON.stringify(calls)).not.toContain("aidr_secret_key");
		if (!slot.ok) throw new Error("expected admission");
		await slot.release();
		await slot.release();
		expect(calls.slice(1)).toEqual([{
			name: "release_tenant_inflight_lease",
			args: { p_scope: ADMISSION_SCOPE, p_slot: 3, p_lease_id: "0d4c5f4e-5a7c-4c43-9a8a-1f5b8d2f0e11" },
		}]);
	});

	it("answers capacity with 503 service_overloaded and every other refusal with 429 tenant_overloaded", async () => {
		for (const [reason, status, error] of [
			["capacity", 503, SERVICE_OVERLOADED],
			["tenant_max", 429, TENANT_OVERLOADED],
			["fair_share", 429, TENANT_OVERLOADED],
			["unresolved_key_busy", 429, TENANT_OVERLOADED],
		] as const) {
			const { db } = scripted(() => ({ data: { admitted: false, reason, charged_to: "unresolved", held: 2, total: 7, active: 2 }, error: null }));
			const admit = sharedLeaseAdmission({ ...CONFIG, retryAfterSeconds: 3 }, { logger: quietLogger() });
			expect(await admit(db, "k")).toEqual({ ok: false, status, error, retryAfterSeconds: 3 });
		}
	});

	it("fails closed with a logged 503 tenant_limiter_unavailable when the acquire fails or answers unexpectedly", async () => {
		const answers: Array<() => { data: unknown; error: unknown } | Promise<never>> = [
			() => ({ data: null, error: { code: "PGRST003" } }),
			() => Promise.reject(new Error("socket hang up")),
			() => ({ data: null, error: null }),
			() => ({ data: [admittedAnswer()], error: null }),
			() => ({ data: admittedAnswer({ lease_id: "not-a-uuid" }), error: null }),
			() => ({ data: admittedAnswer({ slot: 0 }), error: null }),
			() => ({ data: admittedAnswer({ held: -1 }), error: null }),
			() => ({ data: admittedAnswer({ charged_to: "" }), error: null }),
			() => ({ data: admittedAnswer({ admitted: "yes" }), error: null }),
			() => ({ data: { admitted: false, reason: "maybe", charged_to: "t", held: 0, total: 0, active: 0 }, error: null }),
		];
		for (const answer of answers) {
			const logger = quietLogger();
			const { db, calls } = scripted(answer);
			const admit = sharedLeaseAdmission(CONFIG, { logger });
			expect(await admit(db, "k")).toEqual({ ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: 1 });
			expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_limiter_error"));
			// Nothing was admitted, so nothing is released.
			expect(calls.map(({ name }) => name)).toEqual(["acquire_tenant_inflight_lease"]);
		}
	});

	it("logs a failed release without throwing; the lease then frees itself at its expiry", async () => {
		for (const release of [() => ({ data: null, error: { code: "57014" } }), () => Promise.reject(new Error("reset"))]) {
			const logger = quietLogger();
			const { db } = scripted((name) => name === "acquire_tenant_inflight_lease" ? { data: admittedAnswer(), error: null } : release());
			const slot = await sharedLeaseAdmission(CONFIG, { logger })(db, "k");
			if (!slot.ok) throw new Error("expected admission");
			await expect(slot.release()).resolves.toBeUndefined();
			expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_release_failed"));
		}
	});

	it("logs when an admission reused a slot whose lease expired unreleased", async () => {
		const logger = quietLogger();
		const { db } = scripted((name) => ({ data: name === "acquire_tenant_inflight_lease" ? admittedAnswer({ reclaimed: true }) : true, error: null }));
		const slot = await sharedLeaseAdmission(CONFIG, { logger })(db, "k");
		expect(slot.ok).toBe(true);
		expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_lease_expired"));
	});

	it("rate-limits shed logging per charged tenant and reason", async () => {
		const logger = quietLogger();
		const { db } = scripted(() => ({ data: { admitted: false, reason: "tenant_max", charged_to: "t", held: 7, total: 7, active: 1 }, error: null }));
		const admit = sharedLeaseAdmission(CONFIG, { logger, now: () => 5_000 });
		for (let i = 0; i < 50; i += 1) await admit(db, "k");
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(JSON.parse(logger.warn.mock.calls[0][0])).toMatchObject({ event: "tenant_inflight_shed", tenant_id: "t", reason: "tenant_max", tenant_in_flight: 7 });
	});

	it("withTenantSlot releases after success, a thrown error and a rejected promise", async () => {
		const leases = new FakeLeases(new Map([[hash("k"), "tenant-a"]]));
		const db = leases.database();
		const admit = sharedLeaseAdmission({ capacity: 2, perTenantMax: 1, fairShareFloor: 1, retryAfterSeconds: 1 }, { logger: quietLogger() });
		const reject = (rejection: TenantSlotRejection) => {
			const answer = tenantSlotResponse(rejection);
			return new Response(JSON.stringify(answer.body), { status: answer.status, headers: answer.headers });
		};
		expect((await withTenantSlot(admit, db, "k", async () => new Response("ok"), reject)).status).toBe(200);
		await expect(withTenantSlot(admit, db, "k", async () => { throw new Error("boom"); }, reject)).rejects.toThrow("boom");
		await expect(withTenantSlot(admit, db, "k", () => Promise.reject(new Error("late")), reject)).rejects.toThrow("late");
		expect(leases.snapshot()).toEqual({});

		let finish!: () => void;
		const held = withTenantSlot(admit, db, "k", () => new Promise<Response>((resolve) => { finish = () => resolve(new Response("ok")); }), reject);
		await vi.waitFor(() => expect(leases.snapshot()).toEqual({ "tenant-a": 1 }));
		const shed = await withTenantSlot(admit, db, "k", async () => new Response("never"), reject);
		expect(shed.status).toBe(429);
		expect(shed.headers.get("Retry-After")).toBe("1");
		expect(await shed.json()).toEqual({ error: TENANT_OVERLOADED, retryable: true });
		finish();
		await held;
		expect(leases.snapshot()).toEqual({});
	});
});

describe("tenantSlotGate", () => {
	it("fails closed with a logged, stable error before any database call when the configuration is malformed", async () => {
		const logger = quietLogger();
		const { db, calls } = scripted(() => ({ data: admittedAnswer(), error: null }));
		const acquire = tenantSlotGate(env({ AIDR_TENANT_INFLIGHT_CAPACITY: "lots" }), logger);
		expect(await acquire(db, "a")).toEqual({ ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: 30 });
		expect(await acquire(db, "b")).toMatchObject({ ok: false, error: TENANT_LIMITER_UNAVAILABLE });
		expect(calls).toEqual([]);
		expect(logger.error).toHaveBeenCalledTimes(1);
		expect(logger.error.mock.calls[0][0]).toContain("tenant_inflight_limiter_misconfigured");
	});
});

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

const TENANTS: Record<string, string> = {
	"noisy-key": "22222222-2222-4222-8222-222222222222",
	"quiet-key": "55555555-5555-4555-8555-555555555555",
};
const USER_ID = "11111111-1111-4111-8111-111111111111";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";

type Deferred = { promise: Promise<void>; resolve: () => void };
function deferred(): Deferred {
	let resolve!: () => void;
	const promise = new Promise<void>((r) => { resolve = r; });
	return { promise, resolve };
}

/**
 * A database whose tenant is chosen by the presented key; `hold` pauses a
 * tenant's post-auth work. `leases` is the shared lease state: pass the same one
 * to several handlers to model separate workers and functions.
 */
function tenantDatabase(hold: Map<string, Deferred>, failRegistration = new Set<string>(), leases?: FakeLeases) {
	const tenantByHash = new Map(Object.entries(TENANTS).map(([key, tenant]) => [hash(key), tenant]));
	const shared = leases ?? new FakeLeases(tenantByHash);
	let currentTenant = "";
	const rpc = vi.fn(async (name: string, args: Record<string, unknown> = {}) => {
		const lease = shared.rpc(name, args);
		if (lease) return lease;
		const tenant = String(args.p_tenant_id ?? currentTenant);
		if (name === "consume_tenant_rate_limit") {
			await hold.get(tenant)?.promise;
			return { data: [{ allowed: true, remaining: 100 }], error: null };
		}
		if (name === "increment_rate_limit") return { data: null, error: null };
		if (name === "tenant_admission_capacity") return { data: 1, error: null };
		if (name === "register_agent_for_ingest") {
			if (failRegistration.has(tenant)) throw new Error("connection reset");
			return { data: [{ agent_id: AGENT_ID, seat_exceeded: false, allowed_agents: 1 }], error: null };
		}
		if (name === "effective_tenant_seats") return { data: [{ extra_agents: 0, provider_valid_until: null }], error: null };
		if (name === "get_tenant_admission") {
			return { data: { mode: "cloud", status: "active", access_kind: "licensed", allowed_agents: 1, expires_at: new Date(Date.now() + 86_400_000).toISOString(), trial_available: false }, error: null };
		}
		if (name === "ai_governance_policy_overlay") return { data: { mcp_deny_servers: [], mcp_require_approval_servers: [], browser_guard_blocked_sites: [] }, error: null };
		throw new Error(`unexpected RPC ${name}`);
	});
	const db = {
		rpc,
		from(table: string) {
			const filters: Record<string, unknown> = {};
			const query = {
				select() { return query; },
				eq(column: string, value: unknown) { filters[column] = value; return query; },
				async maybeSingle() {
					switch (table) {
						case "api_keys": {
							const tenant = tenantByHash.get(String(filters.key_hash));
							if (tenant) currentTenant = tenant;
							return { data: tenant ? { user_id: USER_ID, tenant_id: tenant, revoked: false, agent_id: null, scope: "tenant" } : null, error: null };
						}
						case "tenant_members": return { data: { role: "member", expires_at: null }, error: null };
						case "tenants": return { data: { status: "active" }, error: null };
						case "rate_limits": return { data: null, error: null };
						case "entitlements": return { data: { included_agents: 1, extra_agents: 0, premium_intel: false, premium_correlation: false, premium_pkg_plugin: false, revocation_epoch: 1 }, error: null };
						case "tenant_runtime_policies": return { data: { version: 3, policy: { command_default: "ask" } }, error: null };
						default: throw new Error(`unexpected relation ${table}`);
					}
				},
				upsert: async () => ({ error: null }),
			};
			return query;
		},
	};
	return { db, rpc, leases: shared };
}

function stubRuntime(serve: (handler: (request: Request) => Promise<Response>) => void) {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubEnv("AIDR_TENANT_INFLIGHT_CAPACITY", "3");
	vi.stubEnv("AIDR_TENANT_INFLIGHT_MAX", "2");
	vi.stubEnv("AIDR_TENANT_INFLIGHT_FAIR_SHARE_FLOOR", "1");
	vi.stubEnv("AIDR_TENANT_INFLIGHT_RETRY_AFTER_SECONDS", "2");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", { env: { get: (name: string) => process.env[name] }, serve });
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	vi.stubGlobal("crypto", webcrypto);
	sdk.createClient.mockReset();
});

/** A fresh module instance: what a new edge worker starts with. */
async function loadIngest(db: unknown, overrides: Record<string, string> = {}) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	stubRuntime((value) => { handler = value; });
	for (const [name, value] of Object.entries(overrides)) vi.stubEnv(name, value);
	sdk.createClient.mockReturnValue(db);
	vi.resetModules();
	await import("../ingest/index.ts");
	if (!handler) throw new Error("ingest did not register a handler");
	return handler;
}

async function loadPolicy(db: unknown) {
	stubRuntime(() => undefined);
	vi.resetModules();
	const { createPolicyHandler } = await import("../policy/index.ts");
	return createPolicyHandler({ db: db as never });
}

function ingestRequest(key: string, eventId: string) {
	return new Request("https://project.supabase.co/functions/v1/ingest", {
		method: "POST",
		headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
		body: JSON.stringify({ iid: "host-1", events: [{ event_id: eventId, type: "runtime_verdict", verdict: "deny" }] }),
	});
}
const policyRequest = (key: string) => new Request("https://project.supabase.co/functions/v1/policy", { headers: { Authorization: `Bearer ${key}` } });

const until = async (condition: () => boolean) => {
	for (let i = 0; i < 200 && !condition(); i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
	if (!condition()) throw new Error("condition not reached");
};
const rateLimitCalls = (rpc: ReturnType<typeof vi.fn>) => rpc.mock.calls.filter(([name]) => name === "consume_tenant_rate_limit").length;

describe("ingest fair-share admission", () => {
	it("sheds the noisy tenant's excess with 429 tenant_overloaded while the quiet tenant is served", async () => {
		const noisy = deferred();
		const fake = tenantDatabase(new Map([[TENANTS["noisy-key"], noisy]]));
		const handle = await loadIngest(fake.db);
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		try {
			const pending = [handle(ingestRequest("noisy-key", "n-1")), handle(ingestRequest("noisy-key", "n-2"))];
			await until(() => rateLimitCalls(fake.rpc) === 2);

			const shed = await handle(ingestRequest("noisy-key", "n-3"));
			expect(shed.status).toBe(429);
			expect(shed.headers.get("Retry-After")).toBe("2");
			expect(await shed.json()).toEqual({ error: "tenant_overloaded", retryable: true });

			const quiet = await handle(ingestRequest("quiet-key", "q-1"));
			expect(quiet.status).toBe(200);
			expect(await quiet.json()).toMatchObject({ ok: true, acknowledged_event_ids: ["q-1"] });

			noisy.resolve();
			expect((await Promise.all(pending)).map((response) => response.status)).toEqual([200, 200]);
			// Every lease came back: the noisy tenant is admitted again.
			expect((await handle(ingestRequest("noisy-key", "n-4"))).status).toBe(200);
			expect(fake.leases.snapshot()).toEqual({});
			expect(warn).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_shed"));
		} finally {
			warn.mockRestore();
		}
	});

	it("a fresh worker sees the leases an earlier worker holds and charges a known key to its tenant at once", async () => {
		const noisy = deferred();
		const fake = tenantDatabase(new Map([[TENANTS["noisy-key"], noisy]]));
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		try {
			const first = await loadIngest(fake.db);
			const pending = [first(ingestRequest("noisy-key", "n-1")), first(ingestRequest("noisy-key", "n-2"))];
			await until(() => rateLimitCalls(fake.rpc) === 2);
			// A replacement worker: new module state, same database.
			const second = await loadIngest(fake.db);
			expect((await second(ingestRequest("noisy-key", "n-3"))).status).toBe(429);
			// The quiet key is charged to its own tenant, never to a shared bucket.
			expect((await second(ingestRequest("quiet-key", "q-1"))).status).toBe(200);
			const acquires = fake.rpc.mock.calls.filter(([name]) => name === "acquire_tenant_inflight_lease");
			expect(acquires.every(([, args]) => !JSON.stringify(args).includes("-key"))).toBe(true);
			noisy.resolve();
			await Promise.all(pending);
			expect(fake.leases.snapshot()).toEqual({});
		} finally {
			warn.mockRestore();
		}
	});

	it("releases the lease when the handler throws", async () => {
		const quietTenant = TENANTS["quiet-key"];
		const fake = tenantDatabase(new Map(), new Set([quietTenant]));
		const handle = await loadIngest(fake.db);
		for (let i = 0; i < 4; i += 1) {
			await expect(handle(ingestRequest("quiet-key", `q-${i}`))).rejects.toThrow("connection reset");
		}
		// Four failures with a per-tenant cap of 2: no lease leaked, so every call was admitted.
		expect(fake.rpc.mock.calls.filter(([name]) => name === "register_agent_for_ingest")).toHaveLength(4);
		expect(fake.leases.snapshot()).toEqual({});
	});

	it("fails closed with 503 tenant_limiter_unavailable on a malformed limit, before any database call", async () => {
		const fake = tenantDatabase(new Map());
		const handle = await loadIngest(fake.db, { AIDR_TENANT_INFLIGHT_CAPACITY: "many" });
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		try {
			const response = await handle(ingestRequest("quiet-key", "q-1"));
			expect(response.status).toBe(503);
			expect(response.headers.get("Retry-After")).toBe("30");
			expect(await response.json()).toEqual({ error: "tenant_limiter_unavailable", retryable: true });
			expect(error).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_limiter_misconfigured"));
			expect(fake.rpc).not.toHaveBeenCalled();
		} finally {
			error.mockRestore();
		}
	});

	it("fails closed with 503 tenant_limiter_unavailable when the lease cannot be acquired", async () => {
		const fake = tenantDatabase(new Map());
		const failing = { ...fake.db, rpc: async (name: string, args: Record<string, unknown>) => name === "acquire_tenant_inflight_lease" ? { data: null, error: { code: "PGRST003" } } : fake.rpc(name, args) };
		const handle = await loadIngest(failing);
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		try {
			const response = await handle(ingestRequest("quiet-key", "q-1"));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "tenant_limiter_unavailable", retryable: true });
			expect(fake.rpc.mock.calls.map(([name]) => name)).not.toContain("consume_tenant_rate_limit");
		} finally {
			error.mockRestore();
		}
	});
});

describe("policy fair-share admission", () => {
	it("sheds an over-share tenant and serves another tenant", async () => {
		const noisy = deferred();
		const fake = tenantDatabase(new Map([[TENANTS["noisy-key"], noisy]]));
		const handle = await loadPolicy(fake.db);
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		try {
			const pending = [handle(policyRequest("noisy-key")), handle(policyRequest("noisy-key"))];
			await until(() => rateLimitCalls(fake.rpc) === 2);
			const shed = await handle(policyRequest("noisy-key"));
			expect(shed.status).toBe(429);
			expect(shed.headers.get("Retry-After")).toBe("2");
			expect(await shed.json()).toEqual({ error: "tenant_overloaded", retryable: true });
			expect((await handle(policyRequest("quiet-key"))).status).toBe(200);
			noisy.resolve();
			expect((await Promise.all(pending)).map((response) => response.status)).toEqual([200, 200]);
			expect((await handle(policyRequest("noisy-key"))).status).toBe(200);
		} finally {
			warn.mockRestore();
		}
	});

	it("shares one admission budget with ingest", async () => {
		const noisy = deferred();
		const fake = tenantDatabase(new Map([[TENANTS["noisy-key"], noisy]]));
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		try {
			const ingest = await loadIngest(fake.db);
			const pending = [ingest(ingestRequest("noisy-key", "n-1")), ingest(ingestRequest("noisy-key", "n-2"))];
			await until(() => rateLimitCalls(fake.rpc) === 2);
			const policy = await loadPolicy(fake.db);
			// The noisy tenant's two ingest leases count against its policy requests too.
			expect((await policy(policyRequest("noisy-key"))).status).toBe(429);
			expect((await policy(policyRequest("quiet-key"))).status).toBe(200);
			noisy.resolve();
			await Promise.all(pending);
			expect(fake.leases.snapshot()).toEqual({});
		} finally {
			warn.mockRestore();
		}
	});

	it("releases the lease when a database read throws", async () => {
		stubRuntime(() => undefined);
		vi.resetModules();
		const { createPolicyHandler } = await import("../policy/index.ts");
		const fake = tenantDatabase(new Map());
		const failing = {
			...fake.db,
			rpc: async (name: string, args: Record<string, unknown>) => {
				if (name === "ai_governance_policy_overlay") throw new Error("socket closed");
				return fake.rpc(name, args);
			},
		};
		let admitted = 0;
		const inner = sharedLeaseAdmission({ capacity: 3, perTenantMax: 2, fairShareFloor: 1, retryAfterSeconds: 1 }, { logger: quietLogger() });
		const admitTenantRequest: AdmitCredential = async (db, credential) => {
			const slot = await inner(db, credential);
			if (slot.ok) admitted += 1;
			return slot;
		};
		const handle = createPolicyHandler({ db: failing as never, admitTenantRequest });
		for (let i = 0; i < 5; i += 1) {
			const response = await handle(policyRequest("quiet-key"));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "policy_unavailable" });
		}
		expect(admitted).toBe(5);
		expect(fake.leases.snapshot()).toEqual({});
	});
});
