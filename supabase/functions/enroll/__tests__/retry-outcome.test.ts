import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

type RpcResult = { data: unknown; error: unknown };
const resolved = { data: { user_id: "user-1", tenant_id: "tenant-1" }, error: null };

async function enrollmentHandler(exchangeResult: RpcResult, resolution: RpcResult = resolved) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://test.invalid");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (fn: typeof handler) => { handler = fn; },
	});
	const rpc = vi.fn(async (name: string) => {
		if (name === "resolve_enrollment_token") return resolution;
		if (name === "increment_rate_limit") return { data: null, error: null };
		if (name === "exchange_enrollment_token") return exchangeResult;
		throw new Error(`unexpected RPC: ${name}`);
	});
	sdk.createClient.mockReturnValue({
		rpc,
		from: (table: string) => {
			if (table !== "rate_limits") throw new Error(`unexpected table: ${table}`);
			const query = {
				select: () => query, eq: () => query,
				single: async () => ({ data: { count: 1 }, error: null }),
			};
			return query;
		},
	});
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("enroll handler was not registered");
	return { handler, rpc };
}

function request() {
	return new Request("https://test.invalid/enroll", {
		method: "POST", headers: { Authorization: "Bearer aidr_enroll_test-token" },
		body: JSON.stringify({ iid: "iid-1" }),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("enrollment retry outcome", () => {
	it("does not present a consumed-token resolver rejection as a confirmed rollback", async () => {
		const app = await enrollmentHandler({ data: null, error: null }, { data: null, error: null });
		const response = await app.handler(request());
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({
			error: "invalid_or_expired_enrollment_token", enrollment_outcome: "unknown",
		});
		expect(app.rpc.mock.calls.map(([name]) => name)).toEqual(["resolve_enrollment_token"]);
	});

	it("keeps an actual lost exchange RPC response explicitly uncertain", async () => {
		const app = await enrollmentHandler({ data: null, error: { message: "response lost" } });
		const response = await app.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({
			error: "enrollment_exchange_failed", enrollment_outcome: "unknown",
		});
		expect(app.rpc.mock.calls.map(([name]) => name)).toEqual([
			"resolve_enrollment_token", "increment_rate_limit", "exchange_enrollment_token",
		]);
	});

	it("keeps a token consumed between resolution and exchange uncertain", async () => {
		const app = await enrollmentHandler({ data: { status: "invalid_token" }, error: null });
		const response = await app.handler(request());
		expect(response.status).toBe(401);
		expect(await response.json()).toMatchObject({ enrollment_outcome: "unknown" });
		expect(app.rpc).toHaveBeenCalledWith("exchange_enrollment_token", expect.anything());
	});

	it("allows retry after a resolver outage that never called exchange", async () => {
		const app = await enrollmentHandler({ data: null, error: null }, {
			data: null, error: { message: "authorization unavailable" },
		});
		const response = await app.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({
			error: "enrollment_authorization_unavailable", enrollment_outcome: "not_committed",
		});
		expect(app.rpc.mock.calls.map(([name]) => name)).toEqual(["resolve_enrollment_token"]);
	});

	it("allows retry after a confirmed database admission rollback", async () => {
		const app = await enrollmentHandler({ data: null, error: { code: "42501" } });
		const response = await app.handler(request());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({
			error: "tenant_not_admitted", enrollment_outcome: "not_committed",
		});
	});

	it("reports a committed invalid entitlement without exposing the lost key", async () => {
		const app = await enrollmentHandler({
			data: { status: "enrolled", user_id: "user-1", tenant_id: "tenant-1", agent_id: "agent-1" },
			error: null,
		});
		const response = await app.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({
			error: "enrollment_exchange_result_invalid", enrollment_outcome: "committed",
		});
	});
});
