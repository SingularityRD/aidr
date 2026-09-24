import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const USER = "11111111-1111-4111-8111-111111111111";
const mutations = vi.hoisted(() => ({ rpc: vi.fn(), role: "owner", listFilters: [] as Array<{ table: string; column: string; value: unknown }> }));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => ({
		auth: { getUser: async () => ({ data: { user: { id: USER } }, error: null }) },
		from: (table: string) => {
			const data = table === "tenant_members"
				? { tenant_id: USER, role: mutations.role, expires_at: null }
				: table === "tenants" ? { status: "active" } : null;
			const query = {
				select: () => query,
				eq: (column: string, value: unknown) => {
					if (table === "api_keys" || table === "enrollment_tokens") mutations.listFilters.push({ table, column, value });
					return query;
				},
				order: () => query,
				limit: async () => ({ data: [], error: null }),
				maybeSingle: async () => ({ data, error: null }),
			};
			return query;
		},
		rpc: mutations.rpc,
	}),
}));

vi.mock("../_shared/identity-barrier.ts", () => ({
	checkIdentityBarrier: async () => ({ ok: true }),
}));

const handlers: Array<(req: Request) => Promise<Response>> = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: (req: Request) => Promise<Response>) => { handlers.push(handler); },
};
await import("../api-keys/index.ts");
await import("../enrollment-tokens/index.ts");

function post(route: string, body: string): Request {
	return new Request(`https://project.supabase.co/functions/v1/${route}`, {
		method: "POST",
		headers: { Authorization: "Bearer test-access-token", "Content-Type": "application/json" },
		body,
	});
}

describe("credential mutation request boundaries", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		mutations.rpc.mockReset();
		mutations.role = "owner";
		mutations.listFilters.length = 0;
	});
	afterEach(() => vi.unstubAllEnvs());

	it.each([
		["api-keys", 0],
		["enrollment-tokens", 1],
	] as const)("rejects malformed and oversized %s POST bodies before issuing a credential", async (route, index) => {
		for (const [body, status, error] of [
			["{", 400, "invalid_json"],
			["null", 400, "invalid_json"],
			["[]", 400, "invalid_json"],
			[JSON.stringify({ label: "x".repeat(8 * 1024) }), 413, "request_too_large"],
		] as const) {
			const response = await handlers[index]?.(post(route, body));
			expect(response?.status).toBe(status);
			expect(await response?.json()).toEqual({ error });
		}
		expect(mutations.rpc).not.toHaveBeenCalled();
	});

	it.each([
		["api-keys", 0],
		["enrollment-tokens", 1],
	] as const)("does not issue a %s credential when the rate-limit row is missing", async (route, index) => {
		mutations.rpc.mockResolvedValue({ data: null, error: null });
		const response = await handlers[index]?.(post(route, JSON.stringify({ action: "create" })));
		expect(response?.status).toBe(429);
		expect(await response?.json()).toEqual({ error: "rate_limited" });
		expect(mutations.rpc).toHaveBeenCalledTimes(1);
		expect(mutations.rpc).toHaveBeenCalledWith("increment_rate_limit", expect.any(Object));
	});

	it.each([
		["api-keys", 0],
		["enrollment-tokens", 1],
	] as const)("limits a viewer's %s list to their own credential metadata", async (route, index) => {
		mutations.role = "viewer";
		const response = await handlers[index]?.(new Request(`https://project.supabase.co/functions/v1/${route}`, {
			method: "GET", headers: { Authorization: "Bearer test-access-token" },
		}));
		expect(response?.status).toBe(200);
		expect(mutations.listFilters).toContainEqual({ table: route === "api-keys" ? "api_keys" : "enrollment_tokens", column: "user_id", value: USER });
	});
});
