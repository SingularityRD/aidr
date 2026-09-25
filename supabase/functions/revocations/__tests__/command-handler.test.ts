import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("test must inject its database"); },
}));

const tenantId = "11111111-1111-4111-8111-111111111111";
const userId = "22222222-2222-4222-8222-222222222222";
const agentId = "33333333-3333-4333-8333-333333333333";
const commandId = "44444444-4444-4444-8444-444444444444";
const bearer = "enrolled-agent-key";
const keyHash = createHash("sha256").update(bearer).digest("hex");
const deviceAttestation = {
	schema_version: 1,
	installation_id: "installation-001",
	key_hash: keyHash,
};

function database(options: { revoked?: boolean; accessTokenValid?: boolean; scope?: string } = {}) {
	const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const tableReads: string[] = [];
	const accessTokenChecks: string[] = [];
	const db = {
		auth: {
			getUser: async (token: string) => {
				accessTokenChecks.push(token);
				return options.accessTokenValid === true
					? { data: { user: { id: userId } }, error: null }
					: { data: { user: null }, error: { message: "invalid access token" } };
			},
			mfa: { getAuthenticatorAssuranceLevel: async () => ({ data: null, error: null }) },
		},
		from(table: string) {
			tableReads.push(table);
			const row = table === "api_keys"
				? { tenant_id: tenantId, user_id: userId, agent_id: agentId, revoked: options.revoked === true, scope: options.scope ?? "tenant" }
				: table === "tenant_members"
					? { role: "owner", expires_at: null }
					: table === "tenants"
						? { status: "active" }
						: { id: agentId, tenant_id: tenantId, iid: "installation-001" };
			const query = { eq: () => query, maybeSingle: async () => ({ data: row, error: null }) };
			return { select: () => query };
		},
		async rpc(name: string, args: Record<string, unknown>) {
			calls.push({ name, args });
			if (name === "consume_tenant_rate_limit") {
				return { data: { allowed: true, remaining: 10 }, error: null };
			}
			if (name === "poll_fleet_response_command") {
				return { data: {
					id: commandId, command_type: "agent_pause", attempts: 1,
					expires_at: "2030-01-01T00:00:00.000Z", rollback_of: null,
				}, error: null };
			}
			return { data: {
				id: commandId,
				state: args.p_stage === "ack" ? "acknowledged" : args.p_outcome,
			}, error: null };
		},
	};
	return { db, calls, tableReads, accessTokenChecks };
}

function post(body: Record<string, unknown>, authorization: string | null = `Bearer ${bearer}`) {
	return new Request("https://project.supabase.co/functions/v1/revocations", {
		method: "POST",
		headers: {
			...(authorization ? { Authorization: authorization } : {}),
			"Content-Type": "application/json",
		},
		body: JSON.stringify(body),
	});
}

describe("fleet response device handler", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
	});

	it("polls, acknowledges, and reports only the enrolled agent's command", async () => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database();
		const handle = createFleetCommandHandler({ db: db as never });
		const common = { tenant_id: tenantId, device_attestation: deviceAttestation };
		const poll = await handle(post({ ...common, action: "poll" }));
		expect(poll.status).toBe(200);
		expect(await poll.json()).toMatchObject({
			ok: true, command: { id: commandId, command_type: "agent_pause" },
		});
		const ack = await handle(post({ ...common, action: "ack", command_id: commandId, outcome: "accepted" }));
		expect(await ack.json()).toEqual({ ok: true, command_id: commandId, state: "acknowledged" });
		const result = await handle(post({ ...common, action: "result", command_id: commandId, outcome: "succeeded" }));
		expect(await result.json()).toEqual({ ok: true, command_id: commandId, state: "succeeded" });
		expect(calls.filter((call) => call.name === "record_fleet_response_command")).toMatchObject([
			{ args: { p_tenant_id: tenantId, p_agent_id: agentId, p_key_hash: keyHash, p_stage: "ack" } },
			{ args: { p_tenant_id: tenantId, p_agent_id: agentId, p_key_hash: keyHash, p_stage: "result" } },
		]);
		const mismatched = await handle(post({ ...common, action: "poll", tenant_id: userId }));
		expect(mismatched.status).toBe(403);
		expect(calls.filter((call) => call.name === "poll_fleet_response_command")).toHaveLength(1);
	});

	it("rejects a revoked device credential before poll or result state can change", async () => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database({ revoked: true });
		const handle = createFleetCommandHandler({ db: db as never });
		const common = { tenant_id: tenantId, device_attestation: deviceAttestation };

		for (const body of [
			{ ...common, action: "poll" },
			{ ...common, action: "result", command_id: commandId, outcome: "succeeded" },
		]) {
			const response = await handle(post(body));
			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ error: "invalid_api_key" });
		}
		expect(calls).toEqual([]);
	});

	it("refuses an ingest-only Browser Guard key before poll or result state can change", async () => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls } = database({ scope: "ingest:browser_guard" });
		const handle = createFleetCommandHandler({ db: db as never });
		const common = { tenant_id: tenantId, device_attestation: deviceAttestation };

		for (const body of [
			{ ...common, action: "poll" },
			{ ...common, action: "result", command_id: commandId, outcome: "succeeded" },
		]) {
			const response = await handle(post(body));
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "api_key_scope_denied" });
		}
		expect(calls).toEqual([]);
	});

	it.each([
		["missing", null, "missing_access_token", 0],
		["invalid", "Bearer expired-human-session", "invalid_access_token", 1],
	] as const)("rejects %s human credentials before operator reads or mutations", async (_kind, authorization, error, expectedAuthChecks) => {
		vi.stubGlobal("Deno", {
			env: { get: (name: string) => ({
				SUPABASE_URL: "https://project.supabase.co",
				SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
			} as Record<string, string>)[name] },
			serve: () => undefined,
		});
		const { createFleetCommandHandler } = await import("../index.ts");
		const { db, calls, tableReads, accessTokenChecks } = database();
		const handle = createFleetCommandHandler({ db: db as never });
		const response = await handle(post({ action: "queue", tenant_id: tenantId }, authorization));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error });
		expect(accessTokenChecks).toHaveLength(expectedAuthChecks);
		expect(tableReads).toEqual([]);
		expect(calls).toEqual([]);
	});
});
