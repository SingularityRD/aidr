import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

// The Edge Function imports Supabase through Deno's `npm:` specifier, which the
// Node runner cannot resolve. The suite always injects `createDb`.
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through DevicePollDeps.createDb");
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

type DevicePollModule = typeof import("../device-poll/index.ts");
let createDevicePollHandler: DevicePollModule["createDevicePollHandler"];
beforeAll(async () => {
	({ createDevicePollHandler } = await import("../device-poll/index.ts"));
});
afterEach(() => {
	vi.unstubAllEnvs();
});

const AGGREGATE_PREFIX = "device_poll:v1:aggregate|";

function harness(options: { env?: Record<string, string>; counterError?: boolean; knownSession?: boolean } = {}) {
	for (const [name, value] of Object.entries({
		SUPABASE_URL: "https://test.invalid",
		SUPABASE_SERVICE_ROLE_KEY: "test",
		AIDR_DEVICE_POLL_INTERVAL_SECONDS: undefined,
		AIDR_DEVICE_POLL_RL_PER_MIN: undefined,
		AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN: undefined,
		...options.env,
	})) vi.stubEnv(name, value);
	const counts = new Map<string, number>();
	let sessionLookups = 0;
	const db = {
		async rpc(name: string, args: { p_key: string; p_window_start: number; p_delta: number }) {
			if (name !== "increment_rate_limit") throw new Error(`unexpected RPC ${name}`);
			if (options.counterError) return { error: { message: "counter unavailable" } };
			const key = `${args.p_key}|${args.p_window_start}`;
			counts.set(key, (counts.get(key) ?? 0) + args.p_delta);
			return { error: null };
		},
		from(table: string) {
			const filters = new Map<string, unknown>();
			const query = {
				select: () => query,
				eq: (column: string, value: unknown) => {
					filters.set(column, value);
					return query;
				},
				async maybeSingle() {
					if (table === "rate_limits") {
						return { data: { count: counts.get(`${filters.get("key")}|${filters.get("window_start")}`) ?? 0 }, error: null };
					}
					if (table === "device_sessions") {
						sessionLookups++;
						return options.knownSession === false
							? { data: null, error: null }
							: {
									data: {
										id: "s1", user_id: null, tenant_id: null, authorized_at: null, exchanged_at: null,
										expires_at: new Date(Date.now() + 60_000).toISOString(), user_code: "ABCDEFGH",
									},
									error: null,
								};
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return query;
		},
	};
	const handler = createDevicePollHandler({ createDb: () => db as never });
	const poll = (code = "aidr_device_secret-one") =>
		handler(new Request("https://test.invalid/device-poll", {
			method: "POST",
			headers: { Authorization: `Bearer ${code}` },
		}));
	return { poll, counts, get sessionLookups() { return sessionLookups; } };
}

describe("device-poll application rate limiting", () => {
	it("answers RFC 8628 slow_down once a device code exceeds its per-minute budget", async () => {
		const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: "2" } });
		expect((await app.poll()).status).toBe(200);
		expect((await app.poll()).status).toBe(200);
		const limited = await app.poll();
		expect(limited.status).toBe(400);
		expect(await limited.json()).toMatchObject({ error: "slow_down", interval_seconds: 8 });
		expect(limited.headers.get("Retry-After")).toBe("8");
	});

	it("keeps devices independent of each other", async () => {
		const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: "1" } });
		expect((await app.poll("aidr_device_secret-one")).status).toBe(200);
		expect((await app.poll("aidr_device_secret-one")).status).toBe(400);
		expect((await app.poll("aidr_device_secret-two")).status).toBe(200);
	});

	it("bounds invalid codes with the aggregate bucket without creating per-code counter rows", async () => {
		const app = harness({
			knownSession: false,
			env: { AIDR_DEVICE_POLL_RL_PER_MIN: "1", AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN: "2" },
		});
		expect((await app.poll("aidr_device_guess-1")).status).toBe(401);
		expect((await app.poll("aidr_device_guess-2")).status).toBe(401);
		const limited = await app.poll("aidr_device_guess-3");
		expect(limited.status).toBe(429);
		expect(limited.headers.get("Retry-After")).toMatch(/^\d+$/);
		expect([...app.counts.keys()].every((key) => key.startsWith(AGGREGATE_PREFIX))).toBe(true);
		expect(app.sessionLookups).toBe(2);
	});

	it("fails closed with 503 and Retry-After when the counter store is unavailable", async () => {
		const app = harness({ counterError: true });
		const response = await app.poll();
		expect(response.status).toBe(503);
		expect(response.headers.get("Retry-After")).toMatch(/^\d+$/);
		expect(await response.json()).toMatchObject({ error: "rate_limit_unavailable", enrollment_outcome: "unknown" });
		expect(app.sessionLookups).toBe(0);
	});

	it("rejects invalid limit configuration before any database work", async () => {
		for (const env of [
			{ AIDR_DEVICE_POLL_RL_PER_MIN: "0" },
			{ AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN: "0" },
			// The aggregate bound may not be lower than one device's budget.
			{ AIDR_DEVICE_POLL_RL_PER_MIN: "50", AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN: "10" },
		]) {
			const app = harness({ env });
			const response = await app.poll();
			expect(response.status).toBe(500);
			expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
			expect(app.counts.size).toBe(0);
			vi.unstubAllEnvs();
		}
	});

	it("never keys a bucket by the plaintext device code", async () => {
		const app = harness();
		await app.poll("aidr_device_plaintext-secret");
		expect(app.counts.size).toBeGreaterThan(0);
		expect([...app.counts.keys()].some((key) => key.includes("plaintext-secret"))).toBe(false);
	});
});
