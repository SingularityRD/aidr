import { createHash, createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	counts: new Map<string, number>(),
	readError: false,
	incrementError: false,
	keys: [] as string[],
	upsert: vi.fn(),
	clients: 0,
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		state.clients++;
		return {
			rpc: async (_name: string, args: { p_key: string; p_window_start: number; p_delta: number }) => {
				state.keys.push(args.p_key);
				if (state.incrementError) return { error: { message: "counter unavailable" } };
				const key = `${args.p_key}:${args.p_window_start}`;
				state.counts.set(key, (state.counts.get(key) ?? 0) + args.p_delta);
				return { error: null };
			},
			from: (table: string) => {
				if (table === "waitlist_signups") return { upsert: state.upsert };
				if (table !== "rate_limits") throw new Error(`unexpected table: ${table}`);
				let key = "";
				let window = 0;
				const query = {
					select: () => query,
					eq: (column: string, value: string | number) => {
						if (column === "key") key = String(value);
						if (column === "window_start") window = Number(value);
						return query;
					},
					maybeSingle: async () => state.readError
						? { data: null, error: { message: "counter unavailable" } }
						: { data: state.counts.has(`${key}:${window}`) ? { count: state.counts.get(`${key}:${window}`) } : null, error: null },
				};
				return query;
			},
		};
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

type WaitlistModule = typeof import("../waitlist-signup/index.ts");
let waitlist: WaitlistModule;
let handleWaitlistSignup: (request: Request) => Promise<Response>;

const INGRESS_SECRET = "waitlist-ingress-test-secret-at-least-32-bytes";
const GLOBAL_KEY = "waitlist:global:v1";

function request(
	headers: Record<string, string> = {},
	body: Record<string, unknown> = { email: "person@example.test", name: "Test Person" },
): Request {
	return new Request("https://project.supabase.co/functions/v1/waitlist-signup", {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: JSON.stringify(body),
	});
}

function signedHeaders(ip: string, context = "waitlist-signup:v1", secret = INGRESS_SECRET): Record<string, string> {
	const timestamp = String(Math.floor(Date.now() / 1000));
	return {
		"x-aidr-client-ip": ip,
		"x-aidr-client-timestamp": timestamp,
		"x-aidr-client-signature": createHmac("sha256", secret).update(`${context}\n${timestamp}\n${ip}`).digest("hex"),
	};
}

function turnstileFetch(answer: () => Promise<Response> | Response) {
	return vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => await answer());
}

async function load(env: Record<string, string> = {}): Promise<void> {
	for (const [name, value] of Object.entries(env)) vi.stubEnv(name, value);
	vi.resetModules();
	waitlist = await import("../waitlist-signup/index.ts");
	handleWaitlistSignup = waitlist.handleWaitlistSignup;
}

describe("waitlist handler", () => {
	beforeEach(async () => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		vi.stubEnv("AIDR_WAITLIST_RL_PER_MIN", "2");
		state.counts = new Map();
		state.readError = false;
		state.incrementError = false;
		state.keys = [];
		state.clients = 0;
		state.upsert.mockReset().mockResolvedValue({ error: null });
		await load();
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	it("does not write when the rate-limit row cannot be read", async () => {
		state.readError = true;
		const response = await handleWaitlistSignup(request());
		expect(response.status).toBe(429);
		expect(await response.json()).toEqual({ error: "rate_limited" });
		expect(state.upsert).not.toHaveBeenCalled();
	});

	it("does not write when the rate-limit increment fails", async () => {
		state.incrementError = true;
		expect((await handleWaitlistSignup(request())).status).toBe(429);
		expect(state.upsert).not.toHaveBeenCalled();
	});

	it("writes a bounded signup insert-only after a recorded rate-limit increment", async () => {
		const response = await handleWaitlistSignup(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(state.upsert).toHaveBeenCalledWith({
			email: "person@example.test", name: "Test Person", company: null, message: null,
		}, { onConflict: "email_lower", ignoreDuplicates: true });
		expect(state.keys).toEqual([GLOBAL_KEY]);
	});

	it("answers a repeated address with the same generic response and never overwrites", async () => {
		await load({ AIDR_WAITLIST_RL_PER_MIN: "10" });
		const first = await handleWaitlistSignup(request({}, { email: "person@example.test", name: "Original" }));
		const second = await handleWaitlistSignup(request({}, { email: "PERSON@example.test", name: "Attacker overwrite" }));
		expect(first.status).toBe(second.status);
		expect(await first.json()).toEqual(await second.json());
		for (const call of state.upsert.mock.calls) {
			expect(call[1]).toEqual({ onConflict: "email_lower", ignoreDuplicates: true });
		}
	});

	it("does not let spoofed proxy headers create bypass buckets", async () => {
		for (let attempt = 0; attempt < 2; attempt++) {
			const headers = {
				"x-forwarded-for": `198.51.100.${attempt + 1}`,
				"cf-connecting-ip": `203.0.113.${attempt + 1}`,
				"x-real-ip": `192.0.2.${attempt + 1}`,
			};
			expect((await handleWaitlistSignup(request(headers))).status).toBe(200);
		}
		const refused = await handleWaitlistSignup(request({
			"x-forwarded-for": "attacker-controlled-third-value",
			"cf-connecting-ip": "another-value",
			"x-real-ip": "yet-another-value",
		}));
		expect(refused.status).toBe(429);
		expect(await refused.json()).toEqual({ error: "rate_limited" });
		expect(state.keys).toEqual(Array(3).fill(GLOBAL_KEY));
		expect(state.upsert).toHaveBeenCalledTimes(2);
	});
});

describe("waitlist email and field validation", () => {
	beforeEach(async () => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		state.counts = new Map();
		state.keys = [];
		state.clients = 0;
		state.upsert.mockReset().mockResolvedValue({ error: null });
		await load();
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	it.each([
		"person@example.test",
		"first.last+tag@sub.example.co.uk",
		"o'brien@example.org",
		"user@xn--bcher-kva.example",
		" padded@example.com ",
	])("accepts %s", (email) => {
		expect(waitlist.normalizeWaitlistEmail(email)).toBe(email.trim());
	});

	it.each([
		"",
		"@",
		"no-at-sign",
		"a@b",
		"two@@example.com",
		"a@b@example.com",
		".leading@example.com",
		"trailing.@example.com",
		"double..dot@example.com",
		"space inside@example.com",
		"user@-bad.example.com",
		"user@bad-.example.com",
		"user@example.c",
		"user@example.123",
		"user@[127.0.0.1]",
		"\"quoted\"@example.com",
		`${"a".repeat(65)}@example.com`,
		`user@${"a".repeat(64)}.com`,
		`${"a".repeat(64)}@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.com`,
		"user@exa mple.com",
		"user@example.com\u0000",
	])("rejects %j", (email) => {
		expect(waitlist.normalizeWaitlistEmail(email)).toBeNull();
	});

	it("rejects a non-string email and an invalid address before any database work", async () => {
		for (const email of [42, null, ["a@example.com"], "not-an-email"]) {
			const response = await handleWaitlistSignup(request({}, { email }));
			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({ error: "invalid_email" });
		}
		expect(state.clients).toBe(0);
	});

	it.each([
		["oversized name", { name: "n".repeat(201) }],
		["oversized company", { company: "c".repeat(201) }],
		["oversized message", { message: "m".repeat(2001) }],
		["non-string name", { name: 7 }],
		["newline in name", { name: "a\nb" }],
		["control character in message", { message: "hello\u0000" }],
	])("rejects %s before any database work", async (_label, fields) => {
		const response = await handleWaitlistSignup(request({}, { email: "person@example.test", ...fields }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_field" });
		expect(state.clients).toBe(0);
	});

	it("keeps a multi-line message and normalizes empty optional fields to null", async () => {
		const response = await handleWaitlistSignup(request({}, {
			email: "person@example.test", name: "  ", company: "", message: "line one\nline two",
		}));
		expect(response.status).toBe(200);
		expect(state.upsert.mock.calls[0]![0]).toEqual({
			email: "person@example.test", name: null, company: null, message: "line one\nline two",
		});
	});
});

describe("waitlist Turnstile verification", () => {
	beforeEach(async () => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		vi.stubEnv("TURNSTILE_SECRET_KEY", "turnstile-secret");
		state.counts = new Map();
		state.keys = [];
		state.clients = 0;
		state.upsert.mockReset().mockResolvedValue({ error: null });
		await load();
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	function handlerWith(fetchImpl: typeof fetch) {
		return waitlist.createWaitlistSignupHandler({ fetch: fetchImpl });
	}

	it("verifies the token server-side before writing", async () => {
		const fetchMock = turnstileFetch(() => Response.json({ success: true, hostname: "aidr.example" }));
		const response = await handlerWith(fetchMock)(request({}, { email: "person@example.test", turnstile_token: "token-1" }));
		expect(response.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, init] = fetchMock.mock.calls[0]!;
		expect(url).toBe(waitlist.TURNSTILE_VERIFY_URL);
		expect(init?.method).toBe("POST");
		const form = new URLSearchParams(String(init?.body));
		expect(form.get("secret")).toBe("turnstile-secret");
		expect(form.get("response")).toBe("token-1");
		expect(form.has("remoteip")).toBe(false);
		expect(state.upsert).toHaveBeenCalledTimes(1);
	});

	it("accepts the widget's implicit cf-turnstile-response field", async () => {
		const fetchMock = turnstileFetch(() => Response.json({ success: true }));
		const response = await handlerWith(fetchMock)(request({}, { email: "person@example.test", "cf-turnstile-response": "token-2" }));
		expect(response.status).toBe(200);
		expect(new URLSearchParams(String(fetchMock.mock.calls[0]![1]?.body)).get("response")).toBe("token-2");
	});

	it.each([
		["missing", {}],
		["empty", { turnstile_token: "  " }],
		["non-string", { turnstile_token: 12 }],
		["oversized", { turnstile_token: "t".repeat(2049) }],
	])("refuses a %s token without calling Cloudflare or the database", async (_label, fields) => {
		const fetchMock = turnstileFetch(() => Response.json({ success: true }));
		const response = await handlerWith(fetchMock)(request({}, { email: "person@example.test", ...fields }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "captcha_required" });
		expect(fetchMock).not.toHaveBeenCalled();
		expect(state.clients).toBe(0);
	});

	it("refuses a token Cloudflare rejects without consuming rate-limit storage", async () => {
		const fetchMock = turnstileFetch(() => Response.json({ success: false, "error-codes": ["invalid-input-response"] }));
		const response = await handlerWith(fetchMock)(request({}, { email: "person@example.test", turnstile_token: "forged" }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "captcha_failed" });
		expect(state.keys).toEqual([]);
		expect(state.upsert).not.toHaveBeenCalled();
	});

	it.each([
		["a network failure", () => { throw new TypeError("fetch failed"); }],
		["a non-200 answer", () => new Response("upstream", { status: 500 })],
		["a malformed answer", () => new Response("not json", { status: 200 })],
		["an answer without success", () => Response.json({ hostname: "aidr.example" })],
		["a non-boolean success", () => Response.json({ success: "true" })],
		["an oversized answer", () => new Response(JSON.stringify({ success: true, pad: "x".repeat(20_000) }), { status: 200 })],
	])("fails closed on %s", async (_label, answer) => {
		const response = await handlerWith(turnstileFetch(answer as () => Response))(
			request({}, { email: "person@example.test", turnstile_token: "token" }),
		);
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "captcha_unavailable" });
		expect(state.upsert).not.toHaveBeenCalled();
	});

	it("does not call Cloudflare when no Turnstile secret is configured", async () => {
		vi.stubEnv("TURNSTILE_SECRET_KEY", "");
		await load();
		const fetchMock = turnstileFetch(() => Response.json({ success: false }));
		const response = await handlerWith(fetchMock)(request());
		expect(response.status).toBe(200);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

describe("waitlist per-client rate limit", () => {
	beforeEach(async () => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		vi.stubEnv("AIDR_WAITLIST_INGRESS_SECRET", INGRESS_SECRET);
		vi.stubEnv("AIDR_WAITLIST_IP_RL_PER_MIN", "2");
		vi.stubEnv("AIDR_WAITLIST_RL_PER_MIN", "100");
		state.counts = new Map();
		state.keys = [];
		state.clients = 0;
		state.upsert.mockReset().mockResolvedValue({ error: null });
		await load();
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	it("throttles one attested client without affecting another", async () => {
		expect((await handleWaitlistSignup(request(signedHeaders("198.51.100.7")))).status).toBe(200);
		expect((await handleWaitlistSignup(request(signedHeaders("198.51.100.7")))).status).toBe(200);
		const refused = await handleWaitlistSignup(request(signedHeaders("198.51.100.7")));
		expect(refused.status).toBe(429);
		expect(await refused.json()).toEqual({ error: "rate_limited" });
		expect((await handleWaitlistSignup(request(signedHeaders("2001:db8::1")))).status).toBe(200);
		expect(state.upsert).toHaveBeenCalledTimes(3);

		// The bucket key is a digest of the attested IP, never the raw address.
		const ipHash = createHash("sha256").update("198.51.100.7").digest("hex");
		expect(state.keys).toContain(`waitlist:v2:client:${ipHash}`);
		expect(state.keys.some((key) => key.includes("198.51.100.7"))).toBe(false);
		// The refused request never consumed the shared aggregate bucket.
		expect(state.keys.filter((key) => key === GLOBAL_KEY)).toHaveLength(3);
	});

	it.each([
		["unsigned", { "x-forwarded-for": "198.51.100.8" }],
		["signed for another route", signedHeaders("198.51.100.8", "device-start:v1")],
		["signed with another secret", signedHeaders("198.51.100.8", "waitlist-signup:v1", "another-secret-that-is-also-32-bytes-long")],
	])("refuses a request %s before any database work", async (_label, headers) => {
		const response = await handleWaitlistSignup(request(headers));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "trusted_ingress_required" });
		expect(state.clients).toBe(0);
	});

	it("passes the attested client IP to Turnstile", async () => {
		vi.stubEnv("TURNSTILE_SECRET_KEY", "turnstile-secret");
		await load();
		const fetchMock = turnstileFetch(() => Response.json({ success: true }));
		const handler = waitlist.createWaitlistSignupHandler({ fetch: fetchMock });
		const response = await handler(request(signedHeaders("203.0.113.9"), { email: "person@example.test", turnstile_token: "token" }));
		expect(response.status).toBe(200);
		expect(new URLSearchParams(String(fetchMock.mock.calls[0]![1]?.body)).get("remoteip")).toBe("203.0.113.9");
	});

	it("fails closed on a weak ingress secret or an invalid per-client limit", async () => {
		vi.spyOn(console, "error").mockImplementation(() => undefined);
		await load({ AIDR_WAITLIST_INGRESS_SECRET: "too-short" });
		const weak = await handleWaitlistSignup(request(signedHeaders("198.51.100.9", "waitlist-signup:v1", "too-short")));
		expect(weak.status).toBe(500);
		expect(await weak.json()).toEqual({ error: "server_misconfigured", invalid: ["AIDR_WAITLIST_INGRESS_SECRET"] });

		await load({ AIDR_WAITLIST_INGRESS_SECRET: INGRESS_SECRET, AIDR_WAITLIST_IP_RL_PER_MIN: "0" });
		const invalid = await handleWaitlistSignup(request(signedHeaders("198.51.100.9")));
		expect(invalid.status).toBe(500);
		expect(await invalid.json()).toEqual({ error: "server_misconfigured", invalid: ["AIDR_WAITLIST_IP_RL_PER_MIN"] });
		expect(state.clients).toBe(0);
	});
});
