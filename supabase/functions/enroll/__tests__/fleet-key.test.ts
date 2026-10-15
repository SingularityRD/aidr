// /v1/enroll accepts a fleet enrollment key (aidr_fleet_*) wherever it accepts
// a single-use enrollment code (C3). The handler runs against a mocked client;
// the SQL side is covered by ../../__tests__/fleet-enrollment-keys.test.ts and
// scripts/fleet-enrollment-keys-postgres.test.mjs.
import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";
const KEY_ID = "44444444-4444-4444-8444-444444444444";
// Assembled at runtime: a syntactically valid, synthetic fleet key.
const FLEET_KEY = ["aidr", "fleet", "A".repeat(43)].join("_");

type Options = {
	resolution?: { data: unknown; error: unknown };
	exchange?: { data: unknown; error: unknown };
	rateCount?: number;
	env?: Record<string, string>;
};

async function enroll(options: Options = {}) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	for (const [name, value] of Object.entries(options.env ?? {})) vi.stubEnv(name, value);
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => { handler = value; },
	});
	const audit = vi.fn(async () => ({ error: null }));
	const rateKeys: string[] = [];
	const rpc = vi.fn(async (name: string, args: Record<string, unknown> = {}) => {
		if (name === "resolve_fleet_enrollment_key") {
			return options.resolution ?? { data: { key_id: KEY_ID, tenant_id: TENANT_ID, user_id: USER_ID }, error: null };
		}
		if (name === "resolve_enrollment_token") return { data: null, error: null };
		if (name === "increment_rate_limit") {
			rateKeys.push(String(args.p_key));
			return { data: null, error: null };
		}
		if (name === "exchange_fleet_enrollment_key") {
			return options.exchange ?? {
				data: { status: "enrolled", user_id: USER_ID, tenant_id: TENANT_ID, agent_id: AGENT_ID,
					fleet_key_id: KEY_ID, new_agent: true, included_agents: 1, extra_agents: 1,
					allowed_agents: 2, revocation_epoch: 1,
					premium_intel: false, premium_correlation: false, premium_pkg_plugin: false },
				error: null,
			};
		}
		if (name === "effective_tenant_seats") {
			return { data: [{ extra_agents: 1, provider_valid_until: new Date(Date.now() + 30 * 86_400_000).toISOString() }], error: null };
		}
		if (name === "get_tenant_admission") {
			return { data: { mode: "onprem", status: "active", access_kind: "licensed", allowed_agents: 2,
				expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(), trial_available: false }, error: null };
		}
		throw new Error(`unexpected RPC: ${name}`);
	});
	sdk.createClient.mockReturnValue({
		rpc,
		from(table: string) {
			if (table === "rate_limits") {
				const query = { select: () => query, eq: () => query,
					maybeSingle: async () => ({ data: null, error: null }),
					single: async () => ({ data: { count: options.rateCount ?? 1 }, error: null }) };
				return query;
			}
			if (table === "entitlement_snapshots") return { upsert: async () => ({ error: null }) };
			if (table === "admin_audit_logs") return { insert: audit };
			throw new Error(`unexpected table: ${table}`);
		},
	});
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("enroll did not register a handler");
	return { handler, rpc, audit, rateKeys };
}

function request(bearer = FLEET_KEY) {
	return new Request("https://project.supabase.co/functions/v1/enroll", {
		method: "POST",
		headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" },
		body: JSON.stringify({ iid: "host-1", agent_runtime: "claude-code" }),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("fleet enrollment key exchange", () => {
	it("enrolls a machine through the fleet RPCs and never sends the plaintext key", async () => {
		const app = await enroll();
		const response = await app.handler(request());
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.api_key).toMatch(/^aidr_live_/);
		expect(app.rpc.mock.calls.map(([name]) => name)).toEqual([
			"resolve_fleet_enrollment_key", "increment_rate_limit", "exchange_fleet_enrollment_key",
			"effective_tenant_seats", "get_tenant_admission",
		]);
		const exchange = app.rpc.mock.calls.find(([name]) => name === "exchange_fleet_enrollment_key")?.[1];
		expect(exchange).toMatchObject({ p_iid: "host-1", p_agent_runtime: "claude-code" });
		expect(String(exchange?.p_fleet_key_hash)).toMatch(/^[a-f0-9]{64}$/);
		expect(JSON.stringify(app.rpc.mock.calls)).not.toContain(FLEET_KEY);
		// The fleet RPC audits inside its own transaction; no second, best-effort row.
		expect(app.audit).not.toHaveBeenCalled();
	});

	it("charges one bucket per fleet key, sized for a large rollout", async () => {
		// 31 exchanges in a minute would block a single-use code (default 30).
		const app = await enroll({ rateCount: 31 });
		expect((await app.handler(request())).status).toBe(200);
		expect(app.rateKeys).toEqual([`enroll:fleet:${KEY_ID}`]);

		const limited = await enroll({ rateCount: 601 });
		const response = await limited.handler(request());
		expect(response.status).toBe(429);
		const body = await response.json();
		expect(body).toMatchObject({ error: "rate_limited", enrollment_outcome: "not_committed" });
		expect(body.retry_after_seconds).toBeGreaterThan(0);
		expect(limited.rpc).not.toHaveBeenCalledWith("exchange_fleet_enrollment_key", expect.anything());
	});

	it("honours the operator's per-key budget and refuses an invalid one", async () => {
		const tight = await enroll({ rateCount: 6, env: { AIDR_ENROLL_FLEET_RL_PER_MIN: "5" } });
		expect((await tight.handler(request())).status).toBe(429);
		for (const value of ["0", "unlimited", "1000001", "-1"]) {
			const app = await enroll({ env: { AIDR_ENROLL_FLEET_RL_PER_MIN: value } });
			const response = await app.handler(request());
			expect(response.status).toBe(503);
			expect(await response.json()).toMatchObject({ error: "enrollment_rate_limit_config_invalid" });
			expect(app.rpc).not.toHaveBeenCalled();
		}
	});

	it("treats a revoked, expired or unknown fleet key like an invalid code", async () => {
		const app = await enroll({ resolution: { data: null, error: null } });
		const response = await app.handler(request());
		expect(response.status).toBe(401);
		expect(await response.json()).toMatchObject({ error: "invalid_or_expired_enrollment_token" });
		expect(app.rateKeys).toEqual(["enroll:v1:unresolved"]);
		expect(app.rpc).not.toHaveBeenCalledWith("exchange_fleet_enrollment_key", expect.anything());
	});

	it("never looks up a malformed fleet key and charges the unresolved budget", async () => {
		const app = await enroll();
		const response = await app.handler(request(`${FLEET_KEY}x`));
		expect(response.status).toBe(401);
		expect(app.rpc.mock.calls.map(([name]) => name)).toEqual(["increment_rate_limit"]);
		expect(app.rateKeys).toEqual(["enroll:v1:unresolved"]);
	});

	it("reports the key's own seat cap separately from the tenant seat limit", async () => {
		const exhausted = await enroll({
			exchange: { data: { status: "fleet_key_exhausted", seat_cap: 500, enrolled_count: 500 }, error: null },
		});
		const capped = await exhausted.handler(request());
		expect(capped.status).toBe(409);
		expect(await capped.json()).toEqual({
			error: "fleet_key_exhausted", seat_cap: 500, enrolled_count: 500, enrollment_outcome: "not_committed",
		});

		const seats = await enroll({
			exchange: { data: { status: "seat_exceeded", allowed_agents: 2, current_agents: 2 }, error: null },
		});
		const full = await seats.handler(request());
		expect(full.status).toBe(402);
		expect(await full.json()).toMatchObject({ error: "agent_limit_exceeded", allowed_agents: 2 });
	});

	it("keeps tenant admission and lost responses fail closed", async () => {
		const notAdmitted = await enroll({ exchange: { data: null, error: { code: "42501" } } });
		expect((await notAdmitted.handler(request())).status).toBe(403);
		const lost = await enroll({ exchange: { data: null, error: { message: "response lost" } } });
		const response = await lost.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toMatchObject({ enrollment_outcome: "unknown" });
	});

	it("still routes single-use codes to the one-time token RPCs", async () => {
		const app = await enroll();
		expect((await app.handler(request("aidr_enroll_synthetic"))).status).toBe(401);
		expect(app.rpc).toHaveBeenCalledWith("resolve_enrollment_token", expect.anything());
		expect(app.rpc).not.toHaveBeenCalledWith("resolve_fleet_enrollment_key", expect.anything());
	});
});
