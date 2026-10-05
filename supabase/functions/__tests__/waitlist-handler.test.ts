import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
	count: 0,
	readError: false,
	keys: [] as string[],
	insert: vi.fn(),
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => ({
		rpc: async (_name: string, args: { p_key: string; p_delta: number }) => {
			state.keys.push(args.p_key);
			state.count += args.p_delta;
			return { error: null };
		},
		from: (table: string) => {
			if (table === "waitlist_signups") return { insert: state.insert };
			if (table !== "rate_limits") throw new Error(`unexpected table: ${table}`);
			let key = "";
			const query = {
				select: () => query,
			eq: (column: string, value: string) => {
				if (column === "key") key = value;
				return query;
			},
			maybeSingle: async () => state.readError
				? { data: null, error: { message: "counter unavailable" } }
				: { data: key === "waitlist:global:v1" ? { count: state.count } : null, error: null },
			};
			return query;
		},
	}),
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};
let handleWaitlistSignup: (request: Request) => Promise<Response>;

function request(headers: Record<string, string> = {}): Request {
	return new Request("https://project.supabase.co/functions/v1/waitlist-signup", {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: JSON.stringify({ email: "person@example.test", name: "Test Person" }),
	});
}

describe("waitlist handler", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		vi.stubEnv("AIDR_WAITLIST_RL_PER_MIN", "2");
		state.count = 0;
		state.readError = false;
		state.keys = [];
		state.insert.mockReset().mockResolvedValue({ error: null });
	});
	beforeEach(async () => {
		vi.resetModules();
		({ handleWaitlistSignup } = await import("../waitlist-signup/index.ts"));
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
		expect(state.insert).not.toHaveBeenCalled();
	});

	it("writes a bounded signup after a recorded rate-limit increment", async () => {
		const response = await handleWaitlistSignup(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(state.insert).toHaveBeenCalledWith({
			email: "person@example.test", name: "Test Person", company: null, message: null,
		});
		expect(state.keys).toEqual(["waitlist:global:v1"]);
	});

	it("is insert-only: a duplicate email keeps the original row and answers like a first signup", async () => {
		const first = await handleWaitlistSignup(request());
		state.insert.mockResolvedValueOnce({ error: { code: "23505", message: "duplicate key value" } });
		const duplicate = await handleWaitlistSignup(request());
		expect(duplicate.status).toBe(first.status);
		expect(await duplicate.json()).toEqual(await first.json());
		// Nothing else is attempted against an existing row (no upsert/update/select by email).
		expect(state.insert).toHaveBeenCalledTimes(2);
	});

	it("still reports genuine database failures", async () => {
		state.insert.mockResolvedValueOnce({ error: { code: "XX000", message: "boom" } });
		const response = await handleWaitlistSignup(request());
		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "db_error" });
	});

	it("never calls upsert or update on the waitlist table", () => {
		const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "waitlist-signup", "index.ts"), "utf8");
		expect(source).not.toMatch(/\.upsert\(|\.update\(/);
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
		expect(state.keys).toEqual(Array(3).fill("waitlist:global:v1"));
		expect(state.insert).toHaveBeenCalledTimes(2);
	});
});
