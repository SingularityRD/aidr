import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const SECRET = "identity-ingress-test-secret-at-least-32-bytes";
const CHALLENGE = "c".repeat(64);

const state = vi.hoisted(() => ({
	counts: new Map<string, number>(),
	audits: 0,
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => ({
		auth: { resetPasswordForEmail: async () => ({ error: null }) },
		async rpc(name: string, args: { p_key: string; p_window_start: number; p_delta: number }) {
			if (name === "increment_rate_limit") {
				const key = `${args.p_key}|${args.p_window_start}`;
				state.counts.set(key, (state.counts.get(key) ?? 0) + args.p_delta);
				return { data: null, error: null };
			}
			if (name === "issue_identity_password_recovery_grant") return { data: true, error: null };
			throw new Error(`unexpected RPC: ${name}`);
		},
		from(table: string) {
			if (table === "admin_audit_logs") return { insert: async () => { state.audits++; return { error: null }; } };
			if (table !== "rate_limits") throw new Error(`unexpected table: ${table}`);
			const filters = new Map<string, unknown>();
			const query = {
				select: () => query,
				eq: (column: string, value: unknown) => { filters.set(column, value); return query; },
				maybeSingle: async () => ({
					data: { count: state.counts.get(`${filters.get("key")}|${filters.get("window_start")}`) ?? 0 },
					error: null,
				}),
			};
			return query;
		},
	}),
}));

let handle: ((request: Request) => Promise<Response>) | undefined;
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: typeof handle) => { handle = handler; },
};
await import("../identity-security/index.ts");

function signed(ip: string, context = "identity-security:v1"): Record<string, string> {
	const timestamp = String(Math.floor(Date.now() / 1000));
	return {
		"x-aidr-client-ip": ip,
		"x-aidr-client-timestamp": timestamp,
		"x-aidr-client-signature": createHmac("sha256", SECRET).update(`${context}\n${timestamp}\n${ip}`).digest("hex"),
	};
}

let sequence = 0;
function reset(headers: Record<string, string> = {}): Promise<Response> {
	// A distinct email per call isolates the aggregate tiers from the per-subject bucket.
	return handle!(new Request("https://project.supabase.co/functions/v1/identity-security", {
		method: "POST",
		headers: { "Content-Type": "application/json", ...headers },
		body: JSON.stringify({ action: "request_password_reset", email: `user${sequence++}@example.test`, recovery_challenge: CHALLENGE }),
	}));
}

describe("identity recovery trusted-ingress per-client bucket", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		vi.stubEnv("AIDR_DASHBOARD_URL", "https://dashboard.example.test");
		vi.stubEnv("AIDR_DEVICE_START_INGRESS_SECRET", SECRET);
		state.counts.clear();
		state.audits = 0;
	});
	afterEach(() => vi.unstubAllEnvs());

	it("stops one attested client at its own quota before the shared aggregate", async () => {
		for (let i = 0; i < 20; i++) expect((await reset(signed("203.0.113.7"))).status).toBe(202);
		for (let i = 0; i < 3; i++) expect((await reset(signed("203.0.113.7"))).status).toBe(429);
		const signedAggregate = [...state.counts].find(([key]) => key.startsWith("identity-reset:v2:signed-aggregate|"));
		expect(signedAggregate?.[1]).toBe(20);
		expect((await reset(signed("198.51.100.9"))).status).toBe(202);
		expect([...state.counts.keys()].some((key) => key.includes("203.0.113.7"))).toBe(false);
	});

	it("keeps unsigned and forged-proof callers in the legacy aggregate, apart from attested clients", async () => {
		await reset();
		await reset(signed("203.0.113.7", "device-start:v1"));
		await reset({ ...signed("203.0.113.7"), "x-aidr-client-signature": "0".repeat(64) });
		const tiers = [...state.counts].filter(([key]) => key.includes("aggregate"));
		expect(tiers).toHaveLength(1);
		expect(tiers[0]?.[0]).toMatch(/^identity-reset:aggregate\|/);
		expect(tiers[0]?.[1]).toBe(3);
	});

	it("still throttles unsigned callers through the aggregate when no ingress secret is configured", async () => {
		vi.stubEnv("AIDR_DEVICE_START_INGRESS_SECRET", "");
		expect((await reset(signed("203.0.113.7"))).status).toBe(202);
		expect([...state.counts.keys()].some((key) => key.startsWith("identity-reset:aggregate|"))).toBe(true);
		expect([...state.counts.keys()].some((key) => key.includes(":v2:"))).toBe(false);
	});

	it("rejects a configured but weak ingress secret", async () => {
		vi.stubEnv("AIDR_DEVICE_START_INGRESS_SECRET", "short");
		const response = await reset();
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
		expect(state.counts.size).toBe(0);
	});
});
