import { createHmac, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { describe, expect, it, vi } from "vitest";
import * as deviceAuth from "../_shared/device-auth.ts";
import * as requestLimits from "../_shared/request-limits.ts";
import * as trustedIngress from "../_shared/trusted-ingress.ts";

const source = readFileSync(
	join(dirname(fileURLToPath(import.meta.url)), "..", "device-start", "index.ts"),
	"utf8",
);
const javascript = ts.transpileModule(source, {
	compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;

const SECRET = "device-start-ingress-test-secret-at-least-32-bytes";

type Handler = (request: Request) => Promise<Response>;

function harness(overrides: Record<string, string> = {}, rpcUnavailable = false) {
	const env: Record<string, string> = {
		SUPABASE_URL: "https://test.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
		AIDR_DEVICE_START_INGRESS_SECRET: SECRET,
		AIDR_DASHBOARD_URL: "https://dashboard.test",
		AIDR_DASHBOARD_VERIFY_URL: "https://dashboard.test/verify",
		...overrides,
	};
	const counts = new Map<string, number>();
	let minted = 0;
	const inserted: Array<Record<string, unknown>> = [];
	let clientCreations = 0;
	let handler: Handler | undefined;
	const database = {
		rpc: async (_name: string, args: { p_key: string; p_window_start: number; p_delta: number }) => {
			if (rpcUnavailable) return { error: { message: "storage unavailable" } };
			const key = `${args.p_key}:${args.p_window_start}`;
			counts.set(key, (counts.get(key) ?? 0) + args.p_delta);
			return { error: null };
		},
		from: (table: string) => {
			if (table === "device_sessions") return {
				insert: async (row: Record<string, unknown>) => { minted++; inserted.push(row); return { error: null }; },
			};
			let key = "";
			let window = 0;
			const query = {
				select: () => query,
				eq: (field: string, value: string | number) => {
					if (field === "key") key = String(value);
					if (field === "window_start") window = Number(value);
					return query;
				},
				maybeSingle: async () => ({ data: { count: counts.get(`${key}:${window}`) ?? 0 }, error: null }),
			};
			return query;
		},
	};
	const modules: Record<string, unknown> = {
		"npm:@supabase/supabase-js@2.116.0": { createClient: () => { clientCreations++; return database; } },
		"../_shared/config.ts": {
			runtimeEnv: (name: string) => env[name],
			loadConfig: (_reader: unknown, required: readonly string[]) => {
				const missing = required.filter((name) => !env[name]?.trim());
				return missing.length
					? { ok: false, error: { missing } }
					: { ok: true, values: Object.fromEntries(required.map((name) => [name, env[name]])) };
			},
			configFailure: (_name: string, error: { missing: string[] }, json: (status: number, body: Record<string, unknown>) => Response) =>
				json(500, { error: "server_misconfigured", missing: error.missing }),
		},
		"../_shared/trusted-ingress.ts": trustedIngress,
		"../_shared/device-auth.ts": deviceAuth,
		"../_shared/request-limits.ts": requestLimits,
		"../_shared/cors.ts": {
			corsJson: (_request: Request, status: number, body: Record<string, unknown>) =>
				new Response(JSON.stringify(body), { status }),
			handleCors: () => null,
		},
	};
	const module = { exports: {} };
	runInNewContext(javascript, {
		module,
		exports: module.exports,
		require: (name: string) => {
			if (!(name in modules)) throw new Error(`unexpected module: ${name}`);
			return modules[name];
		},
		Deno: { env: { get: (name: string) => env[name] }, serve: (value: Handler) => { handler = value; } },
		crypto: webcrypto,
		URL,
		Request,
		Response,
		TextEncoder,
		Uint8Array,
		Date,
		Number,
		String,
		Array,
		Math,
		btoa,
	});
	if (!handler) throw new Error("device-start did not register a handler");
	return { handler, counts, inserted, get minted() { return minted; }, get clientCreations() { return clientCreations; } };
}

function signedRequest(ip: string, headers: Record<string, string> = {}, secret = SECRET, timestamp = Math.floor(Date.now() / 1000)) {
	const signature = createHmac("sha256", secret)
		.update(`device-start:v1\n${timestamp}\n${ip}`)
		.digest("hex");
	return new Request("https://aidr.test/functions/v1/device-start", {
		method: "POST",
		headers: {
			"x-aidr-client-ip": ip,
			"x-aidr-client-timestamp": String(timestamp),
			"x-aidr-client-signature": signature,
			...headers,
		},
	});
}

describe("device-start requester context (CP-1)", () => {
	it("records the attested IP, the device-reported context, the scope and a bounded expiry", async () => {
		const runtime = harness();
		const request = signedRequest("198.51.100.4");
		const response = await runtime.handler(new Request(request.url, {
			method: "POST",
			headers: request.headers,
			body: JSON.stringify({
				iid: "iid-1", agent_runtime: "claude-code", agent_runtime_version: "2.1.0", os: "darwin", hostname: "build-mac",
			}),
		}));
		expect(response.status).toBe(200);
		const body = await response.json() as { expires_at: string };
		expect(runtime.inserted[0]).toMatchObject({
			requested_ip: "198.51.100.4",
			requested_runtime: "claude-code",
			requested_runtime_version: "2.1.0",
			requested_os: "darwin",
			requested_hostname: "build-mac",
			requested_scope: "tenant",
		});
		const lifetime = Date.parse(body.expires_at) - Date.now();
		expect(lifetime).toBeGreaterThan(9 * 60_000);
		expect(lifetime).toBeLessThanOrEqual(10 * 60_000);
	});

	it("drops malformed device-reported fields and still mints for an empty body", async () => {
		const runtime = harness();
		const request = signedRequest("198.51.100.5");
		await runtime.handler(new Request(request.url, {
			method: "POST", headers: request.headers, body: JSON.stringify({ os: "x\u0000", hostname: "bad host" }),
		}));
		expect(runtime.inserted[0]).toMatchObject({ requested_os: null, requested_hostname: null, requested_ip: "198.51.100.5" });
		expect((await runtime.handler(signedRequest("198.51.100.6"))).status).toBe(200);
	});

	it.each(["0", "16", "60", "ten"])("fails closed on AIDR_DEVICE_TTL_MINUTES=%s", async (ttl) => {
		const runtime = harness({ AIDR_DEVICE_TTL_MINUTES: ttl });
		const response = await runtime.handler(signedRequest("198.51.100.7"));
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured", invalid: ["AIDR_DEVICE_TTL_MINUTES"] });
		expect(runtime.minted).toBe(0);
	});
});

describe("anonymous device-start ingress and rate limits", () => {
	it("mints a browser-compatible device session from a signed ingress request", async () => {
		const runtime = harness();
		const response = await runtime.handler(signedRequest("198.51.100.4", { Origin: "https://dashboard.test" }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, user_code: expect.any(String), device_code: expect.stringMatching(/^aidr_device_/) });
		expect(runtime.minted).toBe(1);
	});

	it("returns only a same-origin verification link and fails closed on an unsafe link", async () => {
		const valid = harness();
		const validResponse = await valid.handler(signedRequest("198.51.100.4"));
		expect(validResponse.status).toBe(200);
		expect((await validResponse.json()).verification_url).toMatch(/^https:\/\/dashboard\.test\/verify\?code=[A-Z2-9]{8}$/);
		for (const unsafe of [
			"https://attacker.test/verify",
			"https://dashboard.test/verify#discard-code",
			"https://dashboard.test@attacker.test/verify",
			"http://dashboard.test/verify",
		]) {
			const runtime = harness({ AIDR_DASHBOARD_VERIFY_URL: unsafe });
			const response = await runtime.handler(signedRequest("198.51.100.4"));
			expect(response.status).toBe(500);
			expect(await response.json()).toEqual({ error: "server_misconfigured", invalid: ["AIDR_DASHBOARD_VERIFY_URL"] });
			expect(runtime.minted).toBe(0);
		}
		const missing = harness({ AIDR_DASHBOARD_VERIFY_URL: "" });
		const missingResponse = await missing.handler(signedRequest("198.51.100.4"));
		expect(missingResponse.status).toBe(500);
		expect(await missingResponse.json()).toEqual({ error: "server_misconfigured", missing: ["AIDR_DASHBOARD_VERIFY_URL"] });
		expect(missing.minted).toBe(0);
	});

	it("does not let rotating caller-controlled proxy headers evade the signed-client quota", async () => {
		// The handler's quota key is `Math.floor(Date.now() / 60000)`, so a run that
		// straddles a minute boundary legitimately resets the window and the 31st
		// request is a 200. Pin the clock where the handler reads it (the VM context
		// receives this same `Date` object) so the assertion is about the quota rule
		// and not about how fast this machine happened to run.
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-09-13T00:00:30.000Z"));
		try {
			const runtime = harness();
			const statuses: number[] = [];
			for (let i = 0; i < 31; i++) {
				const request = signedRequest("198.51.100.4", {
					"x-forwarded-for": `203.0.113.${i + 1}`,
					"cf-connecting-ip": `203.0.113.${i + 1}`,
					"x-real-ip": `203.0.113.${i + 1}`,
				});
				statuses.push((await runtime.handler(request)).status);
			}
			expect(statuses.slice(0, 30)).toEqual(Array(30).fill(200));
			expect(statuses[30]).toBe(429);
			expect(runtime.minted).toBe(30);
		} finally {
			vi.useRealTimers();
		}
	});

	it("resets the quota in the next minute window instead of locking a client out permanently", async () => {
		vi.useFakeTimers({ toFake: ["Date"] });
		try {
			vi.setSystemTime(new Date("2026-09-13T00:00:30.000Z"));
			const runtime = harness();
			for (let i = 0; i < 30; i++) {
				expect((await runtime.handler(signedRequest("198.51.100.4"))).status).toBe(200);
			}
			expect((await runtime.handler(signedRequest("198.51.100.4"))).status).toBe(429);

			vi.setSystemTime(new Date("2026-09-13T00:01:30.000Z"));
			expect((await runtime.handler(signedRequest("198.51.100.4"))).status).toBe(200);
		} finally {
			vi.useRealTimers();
		}
	});

	it("rejects forged ingress IPs, stale signatures and missing ingress proof", async () => {
		const runtime = harness();
		const valid = signedRequest("198.51.100.4");
		valid.headers.set("x-aidr-client-ip", "203.0.113.5");
		expect((await runtime.handler(valid)).status).toBe(403);
		expect((await runtime.handler(signedRequest("198.51.100.4", {}, SECRET, Math.floor(Date.now() / 1000) - 120))).status).toBe(403);
		const unsigned = new Request("https://aidr.test/functions/v1/device-start", { method: "POST", headers: { "x-forwarded-for": "198.51.100.4" } });
		const response = await runtime.handler(unsigned);
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "trusted_ingress_required" });
		expect(runtime.clientCreations).toBe(0);
		expect(runtime.minted).toBe(0);
	});

	it("caps aggregate minting even when many distinct IPs have valid ingress proofs", async () => {
		const runtime = harness({ AIDR_DEVICE_START_GLOBAL_RL_PER_MIN: "30" });
		const statuses: number[] = [];
		for (let i = 1; i <= 31; i++) statuses.push((await runtime.handler(signedRequest(`198.51.100.${i}`))).status);
		expect(statuses.slice(0, 30)).toEqual(Array(30).fill(200));
		expect(statuses[30]).toBe(429);
		expect(runtime.minted).toBe(30);
	});

	it("fails closed on absent/weak ingress secret or unavailable rate-limit storage", async () => {
		const absent = harness({ AIDR_DEVICE_START_INGRESS_SECRET: "" });
		const absentResponse = await absent.handler(signedRequest("198.51.100.4"));
		expect(absentResponse.status).toBe(500);
		expect(await absentResponse.json()).toEqual({ error: "server_misconfigured", missing: ["AIDR_DEVICE_START_INGRESS_SECRET"] });
		expect(absent.minted).toBe(0);

		const weak = harness({ AIDR_DEVICE_START_INGRESS_SECRET: "weak" });
		expect((await weak.handler(signedRequest("198.51.100.4"))).status).toBe(500);
		expect(weak.minted).toBe(0);

		const unavailable = harness({}, true);
		expect((await unavailable.handler(signedRequest("198.51.100.4"))).status).toBe(429);
		expect(unavailable.minted).toBe(0);
	});
});
