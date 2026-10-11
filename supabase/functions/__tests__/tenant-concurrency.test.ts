import { createHash, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type AdmitCredential,
	CredentialAdmission,
	parseTenantConcurrencyConfig,
	SERVICE_OVERLOADED,
	TENANT_LIMITER_UNAVAILABLE,
	TENANT_OVERLOADED,
	TenantConcurrencyLimiter,
	type TenantConcurrencyConfig,
	type TenantSlot,
	type TenantSlotRejection,
	tenantSlotGate,
	tenantSlotResponse,
	withTenantSlot,
} from "../_shared/tenant-concurrency.ts";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const quietLogger = () => ({ warn: vi.fn(), error: vi.fn() });

function limiter(config: Partial<TenantConcurrencyConfig> = {}, logger = quietLogger()) {
	return new TenantConcurrencyLimiter({
		capacity: 10, perTenantMax: 7, fairShareFloor: 2, retryAfterSeconds: 1, leaseMs: 150_000, ...config,
	}, { logger });
}

function admitted(slot: TenantSlot): () => void {
	if (!slot.ok) throw new Error(`expected admission, got ${slot.error}`);
	return slot.release;
}

function fill(gate: TenantConcurrencyLimiter, tenant: string, count: number): Array<() => void> {
	return Array.from({ length: count }, () => admitted(gate.tryAcquire(tenant)));
}

const env = (values: Record<string, string>) => (name: string) => values[name];

/** Admission that charges the credential string itself as the tenant (limiter-level tests). */
const direct = (gate: TenantConcurrencyLimiter): AdmitCredential => async (credential) => {
	const slot = gate.tryAcquire(credential);
	return slot.ok ? { ok: true, release: slot.release, authenticated: slot.rebind, unauthenticated: () => undefined } : slot;
};

describe("tenant concurrency configuration", () => {
	it("uses documented defaults and derives the per-tenant cap from capacity", () => {
		expect(parseTenantConcurrencyConfig(env({}))).toEqual({
			ok: true, config: { capacity: 10, perTenantMax: 7, fairShareFloor: 2, retryAfterSeconds: 1, leaseMs: 150_000 },
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

describe("tenant concurrency limiter", () => {
	it("lets a lone tenant use its per-tenant cap and no more", () => {
		const gate = limiter();
		fill(gate, "noisy", 7);
		expect(gate.tryAcquire("noisy")).toEqual({ ok: false, status: 429, error: TENANT_OVERLOADED, retryAfterSeconds: 1 });
		expect(gate.snapshot()).toEqual({ total: 7, tenants: { noisy: 7 } });
	});

	it("admits a quiet tenant while the noisy tenant holds everything it may, then sheds the noisy excess", () => {
		const gate = limiter();
		const noisy = fill(gate, "noisy", 7);
		// Under pressure with two active tenants the fair share is 10 / 2 = 5.
		fill(gate, "quiet", 3);
		expect(gate.snapshot()).toEqual({ total: 10, tenants: { noisy: 7, quiet: 3 } });
		// Global capacity reached: everyone waits, quiet included.
		expect(gate.tryAcquire("quiet")).toMatchObject({ ok: false, status: 503, error: SERVICE_OVERLOADED });
		// Two noisy requests finish; noisy is still above its share of 5 and is shed,
		// while the quiet tenant (3 < 5) is admitted into the freed capacity.
		noisy[0](); noisy[1]();
		expect(gate.tryAcquire("noisy")).toMatchObject({ ok: false, status: 429, error: TENANT_OVERLOADED });
		admitted(gate.tryAcquire("quiet"));
		admitted(gate.tryAcquire("quiet"));
		expect(gate.snapshot()).toEqual({ total: 10, tenants: { noisy: 5, quiet: 5 } });
	});

	it("converges heavy tenants to the fair share and respects the floor", () => {
		const gate = limiter({ capacity: 12, perTenantMax: 9, fairShareFloor: 2 });
		const a = fill(gate, "a", 9);
		fill(gate, "b", 2);
		// total 11 >= 9, three tenants would be active with c: share = 4; c holds 0.
		admitted(gate.tryAcquire("c"));
		expect(gate.fairShare(3)).toBe(4);
		expect(gate.fairShare(10)).toBe(2);
		// Freed capacity goes to tenants under their share, never back to "a" (8 >= 4).
		a[0]();
		expect(gate.tryAcquire("a")).toMatchObject({ ok: false, status: 429, error: TENANT_OVERLOADED });
		admitted(gate.tryAcquire("b"));
		// Floor: with many active tenants each may still hold two.
		const many = limiter({ capacity: 6, perTenantMax: 4, fairShareFloor: 2 });
		fill(many, "x", 2);
		fill(many, "y", 2);
		admitted(many.tryAcquire("z"));
		admitted(many.tryAcquire("z"));
		expect(many.snapshot()).toEqual({ total: 6, tenants: { x: 2, y: 2, z: 2 } });
	});

	it("admits anyone below the pressure threshold", () => {
		const gate = limiter();
		fill(gate, "a", 3);
		fill(gate, "b", 3);
		// total 6 < perTenantMax 7: no fair-share check yet.
		admitted(gate.tryAcquire("a"));
		expect(gate.snapshot().total).toBe(7);
	});

	it("releases exactly once and never leaks or goes negative", () => {
		const gate = limiter();
		const release = admitted(gate.tryAcquire("t"));
		release();
		release();
		expect(gate.snapshot()).toEqual({ total: 0, tenants: {} });
		const many = fill(gate, "t", 7);
		for (const r of many) r();
		for (const r of many) r();
		expect(gate.snapshot()).toEqual({ total: 0, tenants: {} });
	});

	it("reclaims and logs a slot whose work never settles", () => {
		vi.useFakeTimers();
		try {
			const logger = quietLogger();
			const gate = new TenantConcurrencyLimiter(
				{ capacity: 2, perTenantMax: 1, fairShareFloor: 1, retryAfterSeconds: 1, leaseMs: 1_000 },
				{ logger },
			);
			const release = admitted(gate.tryAcquire("t"));
			expect(gate.tryAcquire("t")).toMatchObject({ ok: false });
			vi.advanceTimersByTime(1_000);
			expect(gate.snapshot().total).toBe(0);
			expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_lease_expired"));
			// The late release after reclamation is a no-op.
			const second = admitted(gate.tryAcquire("t"));
			release();
			expect(gate.snapshot()).toEqual({ total: 1, tenants: { t: 1 } });
			second();
		} finally {
			vi.useRealTimers();
		}
	});

	it("moves a slot to another tenant only within that tenant's cap and share, and never after release", () => {
		const gate = limiter({ capacity: 6, perTenantMax: 4, fairShareFloor: 1 });
		const slot = gate.tryAcquire("unresolved");
		if (!slot.ok) throw new Error("expected admission");
		expect(slot.rebind("a")).toBeNull();
		expect(gate.snapshot()).toEqual({ total: 1, tenants: { a: 1 } });
		slot.release();
		expect(slot.rebind("b")).toBeNull();
		expect(gate.snapshot()).toEqual({ total: 0, tenants: {} });

		// "a" already holds its cap: a request authenticated as "a" through the
		// unresolved bucket is refused instead of pushing "a" past it.
		const held = fill(gate, "a", 4);
		const late = gate.tryAcquire("unresolved");
		if (!late.ok) throw new Error("expected admission");
		expect(late.rebind("a")).toMatchObject({ status: 429, error: TENANT_OVERLOADED });
		expect(gate.snapshot().tenants).toEqual({ a: 4, unresolved: 1 });
		// Under pressure the target's fair share applies too: 6 / 2 active = 3.
		held[0]();
		const another = gate.tryAcquire("unresolved");
		if (!another.ok) throw new Error("expected admission");
		expect(another.rebind("a")).toMatchObject({ status: 429, error: TENANT_OVERLOADED });
		expect(another.rebind("b")).toBeNull();
		late.release(); another.release();
		for (const release of held.slice(1)) release();
		expect(gate.snapshot()).toEqual({ total: 0, tenants: {} });
	});

	it("fails closed and logs on an internal error without touching other tenants' slots", () => {
		const logger = quietLogger();
		const gate = limiter({}, logger);
		const release = admitted(gate.tryAcquire("t"));
		expect(gate.tryAcquire("")).toEqual({ ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: 1 });
		expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_limiter_error"));
		admitted(gate.tryAcquire("t"))();
		release();
		expect(gate.snapshot().total).toBe(0);
	});

	it("rate-limits shed logging per tenant and reason", () => {
		const logger = quietLogger();
		const gate = limiter({ capacity: 2, perTenantMax: 1, fairShareFloor: 1 }, logger);
		fill(gate, "t", 1);
		for (let i = 0; i < 50; i += 1) gate.tryAcquire("t");
		expect(logger.warn).toHaveBeenCalledTimes(1);
		expect(JSON.parse(logger.warn.mock.calls[0][0])).toMatchObject({ event: "tenant_inflight_shed", tenant_id: "t", reason: "tenant_max" });
	});

	it("withTenantSlot releases after success, a thrown error and a rejected promise", async () => {
		const gate = limiter({ capacity: 2, perTenantMax: 1, fairShareFloor: 1 });
		const acquire = direct(gate);
		const reject = (rejection: TenantSlotRejection) => {
			const answer = tenantSlotResponse(rejection);
			return new Response(JSON.stringify(answer.body), { status: answer.status, headers: answer.headers });
		};
		expect((await withTenantSlot(acquire, "t", async () => new Response("ok"), reject)).status).toBe(200);
		await expect(withTenantSlot(acquire, "t", async () => { throw new Error("boom"); }, reject)).rejects.toThrow("boom");
		await expect(withTenantSlot(acquire, "t", () => Promise.reject(new Error("late")), reject)).rejects.toThrow("late");
		expect(gate.snapshot().total).toBe(0);

		let finish!: () => void;
		const held = withTenantSlot(acquire, "t", () => new Promise<Response>((resolve) => { finish = () => resolve(new Response("ok")); }), reject);
		const shed = await withTenantSlot(acquire, "t", async () => new Response("never"), reject);
		expect(shed.status).toBe(429);
		expect(shed.headers.get("Retry-After")).toBe("1");
		expect(await shed.json()).toEqual({ error: TENANT_OVERLOADED, retryable: true });
		finish();
		await held;
		expect(gate.snapshot().total).toBe(0);
	});

	it("handles a burst of concurrent tenants without exceeding capacity or leaking", async () => {
		const gate = limiter({ capacity: 8, perTenantMax: 6, fairShareFloor: 2 });
		const acquire = direct(gate);
		let peak = 0;
		const outcomes: Record<string, number[]> = { noisy: [0, 0], quiet: [0, 0] };
		const quietHeldWhenRejected: number[] = [];
		let current = "";
		const reject = () => {
			if (current === "quiet") quietHeldWhenRejected.push(gate.snapshot().tenants.quiet ?? 0);
			return new Response(null, { status: 429 });
		};
		const work = async () => {
			peak = Math.max(peak, gate.snapshot().total);
			await new Promise((resolve) => setTimeout(resolve, Math.random() * 5));
			if (Math.random() < 0.2) throw new Error("handler failure");
			return new Response("ok");
		};
		const calls: Promise<void>[] = [];
		for (let i = 0; i < 400; i += 1) {
			const tenant = i % 11 === 0 ? "quiet" : "noisy";
			current = tenant;
			calls.push(withTenantSlot(acquire, tenant, work, reject)
				.then((response) => { outcomes[tenant][response.status === 429 ? 1 : 0] += 1; })
				.catch(() => { outcomes[tenant][0] += 1; }));
			if (i % 20 === 0) await new Promise((resolve) => setTimeout(resolve, 1));
		}
		await Promise.all(calls);
		expect(peak).toBeLessThanOrEqual(8);
		expect(gate.snapshot()).toEqual({ total: 0, tenants: {} });
		// The quiet tenant is only ever refused once it already holds the slots one
		// tenant alone can never take (capacity - perTenantMax = 2).
		expect(quietHeldWhenRejected.every((held) => held >= 2)).toBe(true);
		expect(outcomes.noisy[1]).toBeGreaterThan(outcomes.quiet[1]);
	});
});

describe("credential admission", () => {
	it("charges an unseen credential to the shared unresolved bucket, then to its authenticated tenant", async () => {
		const gate = limiter({ capacity: 10, perTenantMax: 7, fairShareFloor: 2 });
		const admission = new CredentialAdmission(gate);
		const first = await admission.admit("key-noisy");
		if (!first.ok) throw new Error("expected admission");
		expect(gate.snapshot().tenants).toEqual({ unresolved: 1 });
		expect(first.authenticated("tenant-noisy")).toBeNull();
		expect(gate.snapshot().tenants).toEqual({ "tenant-noisy": 1 });
		// The same key is now charged to its tenant before authentication runs,
		// so the tenant's cap applies without touching the database.
		const held = [first];
		for (let i = 0; i < 6; i += 1) {
			const slot = await admission.admit("key-noisy");
			if (!slot.ok) throw new Error("expected admission");
			held.push(slot);
		}
		expect(gate.snapshot().tenants).toEqual({ "tenant-noisy": 7 });
		expect(await admission.admit("key-noisy")).toMatchObject({ ok: false, status: 429, error: TENANT_OVERLOADED });
		// A quiet tenant's first request goes through the unresolved reserve.
		const quiet = await admission.admit("key-quiet");
		expect(quiet.ok).toBe(true);
		for (const slot of held) slot.release();
		if (quiet.ok) quiet.release();
		expect(gate.snapshot()).toEqual({ total: 0, tenants: {} });
	});

	it("caps a flood of unknown or invalid keys at one fair share", async () => {
		const gate = limiter({ capacity: 10, perTenantMax: 7, fairShareFloor: 2 });
		const admission = new CredentialAdmission(gate);
		const known = await admission.admit("key-quiet");
		if (!known.ok) throw new Error("expected admission");
		known.authenticated("tenant-quiet");
		const outcomes = await Promise.all(Array.from({ length: 30 }, (_, i) => admission.admit(`random-${i}`)));
		// Pressure starts at 7 in flight; with two active buckets the share is 5,
		// so the unresolved bucket stops at 6 and never reaches the capacity.
		expect(outcomes.filter((slot) => slot.ok)).toHaveLength(6);
		expect(gate.snapshot().tenants).toEqual({ "tenant-quiet": 1, unresolved: 6 });
		// The known tenant is still admitted beside the flood.
		expect((await admission.admit("key-quiet")).ok).toBe(true);
	});

	it("under pressure lets an unresolved key have one request in flight until it authenticates", async () => {
		const gate = limiter({ capacity: 10, perTenantMax: 5, fairShareFloor: 2 });
		const admission = new CredentialAdmission(gate);
		fill(gate, "tenant-a", 2);
		// Below pressure an unresolved key may send several requests at once.
		const early = await Promise.all([admission.admit("noisy-k1"), admission.admit("noisy-k1")]);
		expect(early.every((slot) => slot.ok)).toBe(true);
		const more = await Promise.all([admission.admit("noisy-k2"), admission.admit("noisy-k3")]);
		expect(gate.underPressure()).toBe(true);
		// Under pressure a second unresolved request for the same key is shed ...
		expect(await admission.admit("noisy-k2")).toMatchObject({ ok: false, status: 429, error: TENANT_OVERLOADED });
		// ... while another tenant's first request is still admitted.
		const quiet = await admission.admit("quiet-k");
		expect(quiet.ok).toBe(true);
		// Once the key has authenticated it is charged to its tenant instead.
		const k2 = more[0];
		if (!k2.ok) throw new Error("expected admission");
		expect(k2.authenticated("tenant-noisy")).toBeNull();
		expect((await admission.admit("noisy-k2")).ok).toBe(true);
	});

	it("forgets a credential that failed authentication and expires old hints", async () => {
		let now = 1_000;
		const gate = limiter({ capacity: 10, perTenantMax: 7, fairShareFloor: 2 });
		const admission = new CredentialAdmission(gate, { now: () => now });
		const slot = await admission.admit("revoked-key");
		if (!slot.ok) throw new Error("expected admission");
		slot.authenticated("tenant-a");
		slot.release();
		const again = await admission.admit("revoked-key");
		if (!again.ok) throw new Error("expected admission");
		expect(gate.snapshot().tenants).toEqual({ "tenant-a": 1 });
		again.unauthenticated();
		again.release();
		const third = await admission.admit("revoked-key");
		expect(gate.snapshot().tenants).toEqual({ unresolved: 1 });
		if (third.ok) { third.authenticated("tenant-a"); third.release(); }
		now += 300_001;
		const expired = await admission.admit("revoked-key");
		expect(gate.snapshot().tenants).toEqual({ unresolved: 1 });
		if (expired.ok) expired.release();
	});
});

describe("tenantSlotGate", () => {
	it("fails closed with a logged, stable error when the configuration is malformed", async () => {
		const logger = quietLogger();
		const acquire = tenantSlotGate(env({ AIDR_TENANT_INFLIGHT_CAPACITY: "lots" }), logger);
		expect(await acquire("a")).toEqual({ ok: false, status: 503, error: TENANT_LIMITER_UNAVAILABLE, retryAfterSeconds: 30 });
		expect(await acquire("b")).toMatchObject({ ok: false, error: TENANT_LIMITER_UNAVAILABLE });
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

/** A database whose tenant is chosen by the presented key; `hold` pauses a tenant's post-auth work. */
function tenantDatabase(hold: Map<string, Deferred>, failRegistration = new Set<string>()) {
	const tenantByHash = new Map(Object.entries(TENANTS).map(([key, tenant]) => [createHash("sha256").update(key).digest("hex"), tenant]));
	let currentTenant = "";
	const rpc = vi.fn(async (name: string, args: Record<string, unknown> = {}) => {
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
	return { db, rpc };
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
	sdk.createClient.mockReset();
});

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

function ingestRequest(key: string, eventId: string) {
	return new Request("https://project.supabase.co/functions/v1/ingest", {
		method: "POST",
		headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
		body: JSON.stringify({ iid: "host-1", events: [{ event_id: eventId, type: "runtime_verdict", verdict: "deny" }] }),
	});
}

const until = async (condition: () => boolean) => {
	for (let i = 0; i < 200 && !condition(); i += 1) await new Promise((resolve) => setTimeout(resolve, 1));
	if (!condition()) throw new Error("condition not reached");
};

describe("ingest fair-share admission", () => {
	it("sheds the noisy tenant's excess with 429 tenant_overloaded while the quiet tenant is served", async () => {
		const noisy = deferred();
		const fake = tenantDatabase(new Map([[TENANTS["noisy-key"], noisy]]));
		const handle = await loadIngest(fake.db);
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		try {
			const pending = [handle(ingestRequest("noisy-key", "n-1")), handle(ingestRequest("noisy-key", "n-2"))];
			await until(() => fake.rpc.mock.calls.filter(([name]) => name === "consume_tenant_rate_limit").length === 2);

			const shed = await handle(ingestRequest("noisy-key", "n-3"));
			expect(shed.status).toBe(429);
			expect(shed.headers.get("Retry-After")).toBe("2");
			expect(await shed.json()).toEqual({ error: "tenant_overloaded", retryable: true });

			const quiet = await handle(ingestRequest("quiet-key", "q-1"));
			expect(quiet.status).toBe(200);
			expect(await quiet.json()).toMatchObject({ ok: true, acknowledged_event_ids: ["q-1"] });

			noisy.resolve();
			expect((await Promise.all(pending)).map((response) => response.status)).toEqual([200, 200]);
			// Every slot came back: the noisy tenant is admitted again.
			expect((await handle(ingestRequest("noisy-key", "n-4"))).status).toBe(200);
			expect(warn).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_shed"));
		} finally {
			warn.mockRestore();
		}
	});

	it("releases the slot when the handler throws", async () => {
		const quietTenant = TENANTS["quiet-key"];
		const fake = tenantDatabase(new Map(), new Set([quietTenant]));
		const handle = await loadIngest(fake.db);
		for (let i = 0; i < 4; i += 1) {
			await expect(handle(ingestRequest("quiet-key", `q-${i}`))).rejects.toThrow("connection reset");
		}
		// Four failures with a per-tenant cap of 2: no slot leaked, so the next call is admitted.
		const registration = fake.rpc.mock.calls.filter(([name]) => name === "register_agent_for_ingest");
		expect(registration).toHaveLength(4);
	});

	it("fails closed with 503 tenant_limiter_unavailable on a malformed limit, before any tenant work", async () => {
		const fake = tenantDatabase(new Map());
		const handle = await loadIngest(fake.db, { AIDR_TENANT_INFLIGHT_CAPACITY: "many" });
		const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
		try {
			const response = await handle(ingestRequest("quiet-key", "q-1"));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "tenant_limiter_unavailable", retryable: true });
			expect(error).toHaveBeenCalledWith(expect.stringContaining("tenant_inflight_limiter_misconfigured"));
			expect(fake.rpc.mock.calls.map(([name]) => name)).not.toContain("consume_tenant_rate_limit");
		} finally {
			error.mockRestore();
		}
	});
});

describe("policy fair-share admission", () => {
	it("sheds an over-share tenant and serves another tenant from the same isolate", async () => {
		stubRuntime(() => undefined);
		vi.resetModules();
		const { createPolicyHandler } = await import("../policy/index.ts");
		const noisy = deferred();
		const fake = tenantDatabase(new Map([[TENANTS["noisy-key"], noisy]]));
		const handle = createPolicyHandler({ db: fake.db as never });
		const get = (key: string) => new Request("https://project.supabase.co/functions/v1/policy", { headers: { Authorization: `Bearer ${key}` } });
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		try {
			const pending = [handle(get("noisy-key")), handle(get("noisy-key"))];
			await until(() => fake.rpc.mock.calls.filter(([name]) => name === "consume_tenant_rate_limit").length === 2);
			const shed = await handle(get("noisy-key"));
			expect(shed.status).toBe(429);
			expect(shed.headers.get("Retry-After")).toBe("2");
			expect(await shed.json()).toEqual({ error: "tenant_overloaded", retryable: true });
			expect((await handle(get("quiet-key"))).status).toBe(200);
			noisy.resolve();
			expect((await Promise.all(pending)).map((response) => response.status)).toEqual([200, 200]);
			expect((await handle(get("noisy-key"))).status).toBe(200);
		} finally {
			warn.mockRestore();
		}
	});

	it("releases the slot when a database read throws", async () => {
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
		let held = 0;
		const gate = limiter({ capacity: 3, perTenantMax: 2, fairShareFloor: 1 });
		const admit = new CredentialAdmission(gate);
		const admitTenantRequest: AdmitCredential = async (credential) => {
			const slot = await admit.admit(credential);
			if (slot.ok) held += 1;
			return slot;
		};
		const handle = createPolicyHandler({ db: failing as never, admitTenantRequest });
		for (let i = 0; i < 5; i += 1) {
			const response = await handle(new Request("https://project.supabase.co/functions/v1/policy", { headers: { Authorization: "Bearer quiet-key" } }));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "policy_unavailable" });
		}
		expect(held).toBe(5);
		expect(gate.snapshot()).toEqual({ total: 0, tenants: {} });
	});
});
