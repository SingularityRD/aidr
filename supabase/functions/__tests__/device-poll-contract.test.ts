// Contract suite for the public device-code poll (`supabase/functions/device-poll`).
//
// The route has no gateway JWT: the 256-bit device code is the credential. It
// must therefore bound how often a live code can be polled (one budget per
// device-code hash, through the same reviewed `increment_rate_limit` RPC that
// device-start uses), answer an over-eager client with the RFC 8628 `slow_down`
// error and a five-second longer interval, keep the existing pending, expired
// and denied answers unchanged, and fail closed when the budget cannot be read.

import { createHash } from "node:crypto";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through DevicePollDeps.createDb");
	},
}));

const served = vi.hoisted(() => ({ handlers: [] as unknown[] }));
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => {
		served.handlers.push(handler);
	},
};

type DevicePollModule = typeof import("../device-poll/index.ts");
let module: DevicePollModule;
beforeAll(async () => {
	module = await import("../device-poll/index.ts");
});
afterEach(() => {
	vi.unstubAllEnvs();
});

const DEVICE_CODE = "aidr_device_contract-secret";
const DEVICE_HASH = createHash("sha256").update(DEVICE_CODE).digest("hex");
const BUDGET_KEY = `device_start:v2:poll:${DEVICE_HASH}`;
const NOW = Date.parse("2026-09-25T10:00:30.000Z");
const WINDOW = Math.floor(NOW / 60_000);

type Row = Record<string, unknown>;

function harness(options: {
	session?: Row | null;
	env?: Record<string, string | undefined>;
	capacity?: number;
	membership?: Row | null;
	incrementError?: boolean;
	incrementThrows?: boolean;
	countError?: boolean;
	countValue?: unknown;
	issueStatus?: string;
} = {}) {
	let nowMs = NOW;
	const counters = new Map<string, number>();
	const rpcCalls: Array<{ name: string; args: Row }> = [];
	const tables: string[] = [];
	let clientCreations = 0;
	const session: Row | null = options.session === undefined
		? {
			id: "session-1", user_id: null, tenant_id: null, authorized_at: null, exchanged_at: null,
			expires_at: new Date(NOW + 600_000).toISOString(), user_code: "USERCODE",
		}
		: options.session;
	const client = {
		from(table: string) {
			tables.push(table);
			const filters = new Map<string, unknown>();
			const query = {
				select: (_columns: string) => query,
				eq: (column: string, value: unknown) => { filters.set(column, value); return query; },
				async maybeSingle() {
					if (table === "rate_limits") {
						if (options.countError) return { data: null, error: { message: "counter unavailable" } };
						if (options.countValue !== undefined) return { data: { count: options.countValue }, error: null };
						return { data: { count: counters.get(`${filters.get("key")}:${filters.get("window_start")}`) ?? 0 }, error: null };
					}
					if (table === "device_sessions") {
						return { data: filters.get("device_code_hash") === DEVICE_HASH ? session : null, error: null };
					}
					if (table === "tenant_members") {
						return { data: options.membership === undefined ? { role: "member", expires_at: null } : options.membership, error: null };
					}
					if (table === "tenants") return { data: { status: "active" }, error: null };
					if (table === "enrollment_tokens") return { data: null, error: null };
					throw new Error(`unexpected table ${table}`);
				},
			};
			return query;
		},
		async rpc(name: string, args: Row) {
			rpcCalls.push({ name, args });
			if (name === "increment_rate_limit") {
				if (options.incrementThrows) throw new Error("network failure");
				if (options.incrementError) return { data: null, error: { message: "storage unavailable" } };
				const key = `${args.p_key}:${args.p_window_start}`;
				counters.set(key, (counters.get(key) ?? 0) + Number(args.p_delta));
				return { data: null, error: null };
			}
			if (name === "tenant_admission_capacity") return { data: options.capacity ?? 1, error: null };
			if (name === "issue_device_enrollment_token") {
				return { data: { status: options.issueStatus ?? "issued" }, error: null };
			}
			throw new Error(`unexpected rpc ${name}`);
		},
	};
	// The handler reads configuration from the Edge runtime per request; the
	// Deno.env stub above delegates to process.env.
	for (const [name, value] of Object.entries({
		SUPABASE_URL: "https://test.invalid",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
		AIDR_DEVICE_POLL_INTERVAL_SECONDS: undefined,
		AIDR_DEVICE_POLL_RL_PER_MIN: undefined,
		...options.env,
	})) vi.stubEnv(name, value);
	const handler = module.createDevicePollHandler({
		createDb: () => { clientCreations++; return client as never; },
		now: () => nowMs,
	});
	const poll = async (deviceCode = DEVICE_CODE) => {
		const response = await handler(new Request("https://test.invalid/functions/v1/device-poll", {
			method: "POST",
			headers: { Authorization: `Bearer ${deviceCode}` },
		}));
		return {
			status: response.status,
			retryAfter: response.headers.get("Retry-After"),
			body: await response.json() as Row,
		};
	};
	return {
		poll,
		counters,
		rpcCalls,
		tables,
		get clientCreations() { return clientCreations; },
		advance(ms: number) { nowMs += ms; },
		issueCalls: () => rpcCalls.filter((call) => call.name === "issue_device_enrollment_token").length,
		admissionCalls: () => rpcCalls.filter((call) => call.name === "tenant_admission_capacity").length,
	};
}

function authorizedSession(overrides: Row = {}): Row {
	return {
		id: "session-1", user_id: "user-1", tenant_id: "tenant-1",
		authorized_at: new Date(NOW - 60_000).toISOString(), exchanged_at: null,
		expires_at: new Date(NOW + 600_000).toISOString(), user_code: "USERCODE",
		...overrides,
	};
}

describe("device-poll handler export", () => {
	it("exports the handler factory and keeps the Deno.serve registration", () => {
		expect(typeof module.createDevicePollHandler).toBe("function");
		expect(served.handlers).toHaveLength(1);
		expect(typeof served.handlers[0]).toBe("function");
		expect(module.DEVICE_POLL_SLOW_DOWN_INCREMENT_SECONDS).toBe(5);
	});
});

describe("device-poll states are preserved", () => {
	it("answers authorization_pending with the advertised interval", async () => {
		const app = harness();
		expect(await app.poll()).toMatchObject({
			status: 200,
			body: { ok: true, status: "pending", error: "authorization_pending", interval_seconds: 3 },
		});
	});

	it("answers an expired code with device_code_expired without consuming a budget", async () => {
		const app = harness({ session: authorizedSession({ authorized_at: null, user_id: null, expires_at: new Date(NOW - 1_000).toISOString() }) });
		expect(await app.poll()).toMatchObject({ status: 401, body: { error: "device_code_expired" } });
		expect(app.counters.size).toBe(0);
	});

	it("denies a tenant that is not admitted", async () => {
		expect(await harness({ session: authorizedSession(), capacity: 0 }).poll())
			.toMatchObject({ status: 403, body: { error: "tenant_not_admitted" } });
		expect(await harness({ session: authorizedSession(), membership: null }).poll())
			.toMatchObject({ status: 403, body: { error: "tenant_not_admitted" } });
		expect(await harness({ session: authorizedSession(), issueStatus: "tenant_not_admitted" }).poll())
			.toMatchObject({ status: 403, body: { error: "tenant_not_admitted" } });
	});

	it("issues the enrollment token for an authorized, admitted session", async () => {
		const app = harness({ session: authorizedSession() });
		const response = await app.poll();
		expect(response).toMatchObject({ status: 200, body: { ok: true, status: "approved" } });
		expect(response.body.enrollment_token).toMatch(/^aidr_enroll_[A-Za-z0-9_-]+$/);
		expect(app.issueCalls()).toBe(1);
	});

	it("does not create a budget row for an unknown device code", async () => {
		const app = harness();
		expect(await app.poll("aidr_device_unknown")).toMatchObject({ status: 401, body: { error: "device_code_invalid" } });
		expect(app.counters.size).toBe(0);
		expect(app.rpcCalls).toEqual([]);
	});
});

describe("device-poll per-device-code rate limit", () => {
	it("consumes the device_start-scoped budget keyed by the device-code hash", async () => {
		const app = harness();
		await app.poll();
		expect(app.rpcCalls[0]).toEqual({
			name: "increment_rate_limit",
			args: { p_key: BUDGET_KEY, p_window_start: WINDOW, p_delta: 1 },
		});
		expect(BUDGET_KEY.length).toBeLessThanOrEqual(160);
		expect(BUDGET_KEY).not.toContain(DEVICE_CODE);
	});

	it("answers RFC 8628 slow_down with a five-second longer interval once the budget is spent", async () => {
		const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: "3" } });
		for (let i = 0; i < 3; i++) expect((await app.poll()).body.error).toBe("authorization_pending");
		const slowed = await app.poll();
		expect(slowed).toEqual({ status: 400, retryAfter: "8", body: { error: "slow_down", interval_seconds: 8 } });

		// A later window restores the normal answer.
		app.advance(60_000);
		expect(await app.poll()).toMatchObject({ status: 200, body: { error: "authorization_pending" } });
	});

	it("raises the slow_down interval relative to a configured poll interval", async () => {
		const app = harness({ env: { AIDR_DEVICE_POLL_INTERVAL_SECONDS: "10", AIDR_DEVICE_POLL_RL_PER_MIN: "1" } });
		expect((await app.poll()).body.interval_seconds).toBe(10);
		expect(await app.poll()).toMatchObject({ status: 400, body: { error: "slow_down", interval_seconds: 15 } });
	});

	it("does no admission or issue work for a throttled authorized session", async () => {
		const app = harness({ session: authorizedSession({ exchanged_at: new Date(NOW).toISOString() }), env: { AIDR_DEVICE_POLL_RL_PER_MIN: "1" } });
		await app.poll();
		const admissions = app.admissionCalls();
		expect(await app.poll()).toMatchObject({ status: 400, body: { error: "slow_down" } });
		expect(app.admissionCalls()).toBe(admissions);
		expect(app.issueCalls()).toBe(0);
	});

	it("tolerates a compliant client by default and throttles a tight loop", async () => {
		const app = harness();
		// Default budget: ceil(60 / 3) + 10 = 30 polls per minute.
		for (let i = 0; i < 30; i++) expect((await app.poll()).status).toBe(200);
		expect(await app.poll()).toMatchObject({ status: 400, body: { error: "slow_down" } });
	});

	it("keys the budget per device code, not per caller", async () => {
		const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: "1" } });
		await app.poll();
		expect(await app.poll()).toMatchObject({ status: 400, body: { error: "slow_down" } });
		expect([...app.counters.keys()]).toEqual([`${BUDGET_KEY}:${WINDOW}`]);
	});

	it.each([
		["increment error", { incrementError: true }],
		["increment exception", { incrementThrows: true }],
		["count read error", { countError: true }],
		["missing count", { countValue: null }],
		["non-integer count", { countValue: "many" }],
	])("fails closed on %s without issuing a token", async (_label, failure) => {
		const app = harness({ session: authorizedSession(), ...failure });
		const response = await app.poll();
		expect(response).toMatchObject({
			status: 503,
			retryAfter: "3",
			body: { error: "rate_limit_unavailable", enrollment_outcome: "unknown" },
		});
		expect(response.body.enrollment_token).toBeUndefined();
		expect(app.issueCalls()).toBe(0);
		expect(app.admissionCalls()).toBe(0);
	});

	it.each(["0", "-1", "1.5", "601", "not-a-number"])(
		"rejects AIDR_DEVICE_POLL_RL_PER_MIN=%s before database work",
		async (value) => {
			const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: value } });
			expect(await app.poll()).toMatchObject({
				status: 500,
				body: { error: "server_misconfigured", invalid: ["AIDR_DEVICE_POLL_RL_PER_MIN"] },
			});
			expect(app.clientCreations).toBe(0);
		},
	);
});
