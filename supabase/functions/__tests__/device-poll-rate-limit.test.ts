import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { readDeviceCode } from "../_shared/auth.ts";
import { evaluateDevicePollState } from "../_shared/device-auth.ts";
import { INGRESS_SECRET_ENV, ingressIpBucket, validIngressSecret, verifiedIngressIp } from "../_shared/trusted-ingress.ts";
import { consumeRateLimit, validRateLimit } from "../_shared/rate-limit.ts";

const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "device-poll", "index.ts"), "utf8");
const compiled = ts.transpileModule(source.replace(/^import .*;\r?\n/gm, ""), {
	compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
}).outputText;

type Handler = (request: Request) => Promise<Response>;

function harness(options: { env?: Record<string, string>; counterError?: boolean; knownSession?: boolean } = {}) {
	const counts = new Map<string, number>();
	let sessionLookups = 0;
	let handler: Handler | undefined;
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
				eq: (column: string, value: unknown) => { filters.set(column, value); return query; },
				async maybeSingle() {
					if (table === "rate_limits") {
						return { data: { count: counts.get(`${filters.get("key")}|${filters.get("window_start")}`) ?? 0 }, error: null };
					}
					if (table === "device_sessions") {
						sessionLookups++;
						return options.knownSession === false ? { data: null, error: null } : {
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
	new Function("Deno", "createClient", "readDeviceCode", "configFailure", "loadConfig",
		"runtimeEnv", "corsJson", "handleCors", "evaluateDevicePollState", "consumeRateLimit", "validRateLimit",
		"INGRESS_SECRET_ENV", "ingressIpBucket", "validIngressSecret", "verifiedIngressIp", compiled)(
		{ env: { get: (name: string) => options.env?.[name] }, serve: (fn: Handler) => { handler = fn; } },
		() => db,
		readDeviceCode,
		() => { throw new Error("unexpected config failure"); },
		() => ({ ok: true, values: { SUPABASE_URL: "https://test.invalid", SUPABASE_SERVICE_ROLE_KEY: "test" } }),
		{},
		(_request: Request, status: number, body: unknown, headers: Record<string, string> = {}) => Response.json(body, { status, headers }),
		() => null,
		evaluateDevicePollState,
		consumeRateLimit,
		validRateLimit,
		INGRESS_SECRET_ENV, ingressIpBucket, validIngressSecret, verifiedIngressIp,
	);
	const poll = (code = "aidr_device_secret-one", headers: Record<string, string> = {}) => handler!(new Request("https://test.invalid/device-poll", {
		method: "POST", headers: { Authorization: `Bearer ${code}`, ...headers },
	}));
	return { poll, counts, get sessionLookups() { return sessionLookups; } };
}

const SECRET = "device-ingress-test-secret-at-least-32-bytes";

function signed(ip: string, context = "device-poll:v1", secret = SECRET): Record<string, string> {
	const timestamp = String(Math.floor(Date.now() / 1000));
	return {
		"x-aidr-client-ip": ip,
		"x-aidr-client-timestamp": timestamp,
		"x-aidr-client-signature": createHmac("sha256", secret).update(`${context}\n${timestamp}\n${ip}`).digest("hex"),
	};
}

describe("device-poll trusted-ingress per-client bucket", () => {
	const env = {
		AIDR_DEVICE_START_INGRESS_SECRET: SECRET,
		AIDR_DEVICE_POLL_RL_PER_MIN: "1",
		AIDR_DEVICE_POLL_CLIENT_RL_PER_MIN: "2",
		AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN: "3",
	};

	it("limits one attested client before it can drain the shared aggregate", async () => {
		const app = harness({ knownSession: false, env });
		expect((await app.poll("aidr_device_guess-1", signed("203.0.113.7"))).status).toBe(401);
		expect((await app.poll("aidr_device_guess-2", signed("203.0.113.7"))).status).toBe(401);
		for (let i = 0; i < 5; i++) expect((await app.poll(`aidr_device_guess-x${i}`, signed("203.0.113.7"))).status).toBe(429);
		// The over-quota client never consumed the signed backstop.
		expect((await app.poll("aidr_device_guess-3", signed("198.51.100.9"))).status).toBe(401);
		expect(app.sessionLookups).toBe(3);
		expect([...app.counts.keys()].some((key) => key.includes("203.0.113.7"))).toBe(false);
	});

	it("keeps unsigned callers out of the attested clients' budget", async () => {
		const app = harness({ knownSession: false, env });
		for (let i = 0; i < 3; i++) expect((await app.poll(`aidr_device_direct-${i}`)).status).toBe(401);
		expect((await app.poll("aidr_device_direct-x")).status).toBe(429);
		expect((await app.poll("aidr_device_signed", signed("198.51.100.9"))).status).toBe(401);
	});

	it("treats forged, cross-route or stale proofs as unsigned", async () => {
		const app = harness({ knownSession: false, env });
		for (const headers of [
			signed("203.0.113.7", "device-poll:v1", "wrong-secret-that-is-at-least-32-bytes-long"),
			signed("203.0.113.7", "device-start:v1"),
			{ ...signed("203.0.113.7"), "x-aidr-client-timestamp": "1" },
		]) await app.poll("aidr_device_guess", headers);
		expect([...app.counts.keys()].every((key) => key.startsWith("device_poll:v1:aggregate|"))).toBe(true);
	});

	it("rejects a configured but weak ingress secret", async () => {
		const app = harness({ env: { AIDR_DEVICE_START_INGRESS_SECRET: "short" } });
		const response = await app.poll();
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
		expect(app.counts.size).toBe(0);
	});
});

describe("device-poll application rate limiting", () => {
	it("returns 429 with Retry-After once a device exceeds its per-minute budget", async () => {
		const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: "2" } });
		expect((await app.poll()).status).toBe(200);
		expect((await app.poll()).status).toBe(200);
		const limited = await app.poll();
		expect(limited.status).toBe(429);
		expect(await limited.json()).toMatchObject({ error: "rate_limited" });
		const retry = Number(limited.headers.get("Retry-After"));
		expect(Number.isInteger(retry) && retry >= 1 && retry <= 60).toBe(true);
	});

	it("keeps devices independent of each other", async () => {
		const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: "1" } });
		expect((await app.poll("aidr_device_secret-one")).status).toBe(200);
		expect((await app.poll("aidr_device_secret-one")).status).toBe(429);
		expect((await app.poll("aidr_device_secret-two")).status).toBe(200);
	});

	it("bounds invalid codes with the aggregate bucket without creating per-code counter rows", async () => {
		const app = harness({ knownSession: false, env: { AIDR_DEVICE_POLL_RL_PER_MIN: "1", AIDR_DEVICE_POLL_GLOBAL_RL_PER_MIN: "2" } });
		expect((await app.poll("aidr_device_guess-1")).status).toBe(401);
		expect((await app.poll("aidr_device_guess-2")).status).toBe(401);
		const limited = await app.poll("aidr_device_guess-3");
		expect(limited.status).toBe(429);
		expect(limited.headers.get("Retry-After")).toMatch(/^\d+$/);
		expect([...app.counts.keys()].every((key) => key.startsWith("device_poll:v1:aggregate|"))).toBe(true);
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
		const app = harness({ env: { AIDR_DEVICE_POLL_RL_PER_MIN: "0" } });
		const response = await app.poll();
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
		expect(app.counts.size).toBe(0);
	});

	it("never keys a bucket by the plaintext device code", async () => {
		const app = harness();
		await app.poll("aidr_device_plaintext-secret");
		expect([...app.counts.keys()].some((key) => key.includes("plaintext-secret"))).toBe(false);
	});
});
