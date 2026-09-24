import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER_ID = "11111111-1111-4111-8111-111111111111";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const AGENT_ID = "33333333-3333-4333-8333-333333333333";

type RateFailure = "update" | "read" | "missing" | "over-limit";

async function enroll(
	effectiveRows: unknown,
	allowedAgents = 2,
	admissionResult?: Record<string, unknown>,
	rateFailure?: RateFailure,
) {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (value: typeof handler) => { handler = value; },
	});
	const upsert = vi.fn(async (_row: Record<string, unknown>) => ({ error: null }));
	const rpc = vi.fn(async (name: string) => {
		if (name === "resolve_enrollment_token") return {
			data: { user_id: USER_ID, tenant_id: TENANT_ID }, error: null,
		};
		if (name === "increment_rate_limit") return {
			data: null, error: rateFailure === "update" ? { message: "rate store unavailable" } : null,
		};
		if (name === "exchange_enrollment_token") return {
			data: { status: "enrolled", user_id: USER_ID, tenant_id: TENANT_ID,
				agent_id: AGENT_ID, included_agents: 1, extra_agents: 1,
				allowed_agents: allowedAgents, revocation_epoch: 1,
				premium_intel: false, premium_correlation: false, premium_pkg_plugin: false },
			error: null,
		};
		if (name === "effective_tenant_seats") return { data: effectiveRows, error: null };
		if (name === "get_tenant_admission") return { data: admissionResult ?? {
			mode: "cloud", status: "active", access_kind: "licensed",
			allowed_agents: allowedAgents,
			expires_at: new Date(Date.now() + 30 * 86_400_000).toISOString(),
			trial_available: false,
		}, error: null };
		throw new Error(`unexpected RPC: ${name}`);
	});
	sdk.createClient.mockReturnValue({
		rpc,
		from(table: string) {
			if (table === "rate_limits") {
				const query = { select: () => query, eq: () => query,
					single: async () => ({
						data: rateFailure === "missing" ? null : { count: rateFailure === "over-limit" ? 999 : 1 },
						error: rateFailure === "read" ? { message: "rate store unavailable" } : null,
					}) };
				return query;
			}
			if (table === "entitlement_snapshots") return { upsert };
			if (table === "admin_audit_logs") return { insert: async () => ({ error: null }) };
			throw new Error(`unexpected table: ${table}`);
		},
	});
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("enroll did not register a handler");
	return { handler, rpc, upsert };
}

function request() {
	return new Request("https://project.supabase.co/functions/v1/enroll", {
		method: "POST",
		headers: { Authorization: "Bearer aidr_enroll_test-token", "Content-Type": "application/json" },
		body: JSON.stringify({ iid: "host-1" }),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("enrollment provider term", () => {
	it.each(["update", "read", "missing"] as const)("fails closed when rate-limit %s is unavailable", async (failure) => {
		const runtime = await enroll([], 2, undefined, failure);
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "enrollment_rate_limit_unavailable" });
		expect(runtime.rpc).not.toHaveBeenCalledWith("exchange_enrollment_token", expect.anything());
		expect(runtime.upsert).not.toHaveBeenCalled();
	});

	it("returns a real rate-limit response for an over-limit counter", async () => {
		const runtime = await enroll([], 2, undefined, "over-limit");
		const response = await runtime.handler(request());
		expect(response.status).toBe(429);
		expect(await response.json()).toEqual({ error: "rate_limited" });
		expect(runtime.rpc).not.toHaveBeenCalledWith("exchange_enrollment_token", expect.anything());
	});

	it("caps the persisted signed-snapshot inputs at the verified period end", async () => {
		const term = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await enroll([{ extra_agents: 1, provider_valid_until: term }]);
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		const snapshot = runtime.upsert.mock.calls[0]?.[0]?.entitlement as Record<string, unknown>;
		expect(snapshot).toMatchObject({ extra_agents: 1, allowed_agents: 2 });
		expect(Date.parse(snapshot.expires_at as string)).toBeLessThanOrEqual(Date.parse(term));
		expect(Date.parse(snapshot.grace_until as string)).toBeLessThanOrEqual(Date.parse(term));
	});

	it("does not issue a stale paid snapshot after a committed exchange", async () => {
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }]);
		const response = await runtime.handler(request());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({
			error: "enrollment_committed_entitlement_unavailable", enrollment_outcome: "committed",
		});
		expect(runtime.upsert).not.toHaveBeenCalled();
	});

	it("caps trial expiry and offline grace without applying that cap to paid mode", async () => {
		const trialEnd = new Date(Date.now() + 2 * 3_600_000).toISOString();
		const runtime = await enroll([{ extra_agents: 0, provider_valid_until: null }], 1, {
			mode: "cloud", status: "active", access_kind: "trial", allowed_agents: 1,
			expires_at: trialEnd, trial_available: false,
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		const snapshot = runtime.upsert.mock.calls[0]?.[0]?.entitlement as Record<string, unknown>;
		expect(snapshot).toMatchObject({ extra_agents: 0, allowed_agents: 1 });
		expect(Date.parse(snapshot.expires_at as string)).toBeLessThanOrEqual(Date.parse(trialEnd));
		expect(Date.parse(snapshot.grace_until as string)).toBeLessThanOrEqual(Date.parse(trialEnd));
	});
});
