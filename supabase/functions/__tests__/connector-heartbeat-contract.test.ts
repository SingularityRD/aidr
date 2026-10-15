// Contract suite for the device-reported `connector-heartbeat` endpoint (C10).
//
// The handler factory runs against a Supabase-shaped double so request
// validation, API-key authentication, agent binding and the RPC contract stay
// executable without a live project. The SQL behaviour (state history and the
// agent.unprotected alert) is covered by scripts/connector-heartbeat-postgres.test.mjs.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through ConnectorHeartbeatDeps.db");
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const { createConnectorHeartbeatHandler, parseHeartbeat } = await import("../connector-heartbeat/index.ts");

const URL = "https://project.supabase.co/functions/v1/connector-heartbeat";
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const OTHER_AGENT = "55555555-5555-4555-8555-555555555555";
const API_KEY = "aidr-contract-device-key";

interface DbOptions {
	agentId?: string | null;
	agent?: { id: string; iid: string } | null;
	agentError?: boolean;
	rpcError?: boolean;
	revoked?: boolean;
}

function database(options: DbOptions = {}) {
	const lookups: Array<Record<string, unknown>> = [];
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	function resultFor(table: string, filters: Record<string, unknown>) {
		if (table === "api_keys") {
			return {
				data: {
					id: "66666666-6666-4666-8666-666666666666",
					user_id: USER,
					tenant_id: TENANT,
					agent_id: options.agentId === undefined ? AGENT : options.agentId,
					revoked: options.revoked === true,
					scope: "tenant",
				},
				error: null,
			};
		}
		if (table === "tenant_members") return { data: { role: "member", expires_at: null }, error: null };
		if (table === "tenants") return { data: { status: "active" }, error: null };
		if (table === "agents") {
			lookups.push(filters);
			return {
				data: options.agent === undefined ? { id: AGENT, iid: "iid-device-1" } : options.agent,
				error: options.agentError ? new Error("db_down") : null,
			};
		}
		return { data: null, error: null };
	}
	function from(table: string) {
		const filters: Record<string, unknown> = {};
		const query = {
			select: () => query,
			eq(column: string, value: unknown) {
				filters[column] = value;
				return query;
			},
			maybeSingle: async () => resultFor(table, { ...filters }),
		};
		return query;
	}
	const db = {
		from: vi.fn(from),
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "tenant_admission_capacity") return { data: 1, error: null };
			if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 100 }, error: null };
			if (name === "record_connector_heartbeat") {
				return options.rpcError ? { data: null, error: { code: "08006" } } : { data: { recorded: 1, alerts: 0 }, error: null };
			}
			return { data: null, error: null };
		}),
	};
	return { db, lookups, rpcCalls };
}

const body = (overrides: Record<string, unknown> = {}) => ({
	iid: "iid-device-1",
	connectors: [{ connector: "claude-code", state: "protected", enforcement: "machine_policy", host_version: "2.1.250" }],
	...overrides,
});

function post(value: unknown, auth = true): Request {
	return new Request(URL, {
		method: "POST",
		headers: { ...(auth ? { Authorization: `Bearer ${API_KEY}` } : {}), "Content-Type": "application/json" },
		body: JSON.stringify(value),
	});
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});
afterEach(() => vi.unstubAllEnvs());

describe("parseHeartbeat", () => {
	it("accepts the documented shape and fills defaults", () => {
		expect(parseHeartbeat({ iid: "iid-1", connectors: [{ connector: "codex", state: "hook_untrusted" }] })).toEqual({
			iid: "iid-1",
			reports: [{ connector: "codex", state: "hook_untrusted", enforcement: "user_config", protection_locked: false, disable_attempts: 0 }],
		});
	});

	it.each([
		[null],
		[[]],
		[{ iid: "iid-1" }],
		[{ iid: "iid-1", connectors: [] }],
		[{ iid: "bad iid", connectors: [{ connector: "codex", state: "protected" }] }],
		[{ iid: "iid-1", connectors: [{ connector: "codex", state: "protected", command: "x" }] }],
		[{ iid: "iid-1", connectors: [{ connector: "notepad", state: "protected" }] }],
		[{ iid: "iid-1", connectors: [{ connector: "codex", state: "ok" }] }],
		[{ iid: "iid-1", connectors: [{ connector: "codex", state: "protected" }, { connector: "codex", state: "protected" }] }],
		[{ iid: "iid-1", connectors: [{ connector: "codex", state: "protected", disable_attempts: -1 }] }],
		[{ iid: "iid-1", connectors: [{ connector: "codex", state: "protected", protection_locked: "yes" }] }],
		[{ iid: "iid-1", connectors: [{ connector: "codex", state: "protected", host_version: "1 2" }] }],
		[{ iid: "iid-1", connectors: [{ connector: "codex", state: "protected" }], path: "/home/user" }],
	])("refuses %j", (value) => {
		expect(parseHeartbeat(value)).toBeNull();
	});
});

describe("connector-heartbeat handler", () => {
	it("refuses non-POST, missing credentials and invalid bodies before any database work", async () => {
		const fake = database();
		const handle = createConnectorHeartbeatHandler({ db: fake.db as never });
		expect((await handle(new Request(URL, { method: "GET" }))).status).toBe(405);
		expect((await handle(post(body(), false))).status).toBe(401);
		const invalid = await handle(post({ iid: "iid-device-1", connectors: [{ connector: "x", state: "protected" }] }));
		expect(invalid.status).toBe(400);
		expect(await invalid.json()).toEqual({ error: "invalid_heartbeat" });
		expect(fake.db.from).not.toHaveBeenCalled();
	});

	it("records the reports for the key's own agent", async () => {
		const fake = database();
		const response = await createConnectorHeartbeatHandler({ db: fake.db as never })(post(body()));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, recorded: 1 });
		expect(fake.lookups).toEqual([{ tenant_id: TENANT, id: AGENT }]);
		const call = fake.rpcCalls.find((entry) => entry.name === "record_connector_heartbeat");
		expect(call?.args).toEqual({
			p_tenant_id: TENANT,
			p_agent_id: AGENT,
			p_reports: [{
				connector: "claude-code",
				state: "protected",
				enforcement: "machine_policy",
				protection_locked: false,
				disable_attempts: 0,
				host_version: "2.1.250",
			}],
		});
	});

	it("refuses an agent-bound key reporting for another installation", async () => {
		const fake = database({ agent: { id: AGENT, iid: "iid-device-2" } });
		const response = await createConnectorHeartbeatHandler({ db: fake.db as never })(post(body()));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "agent_key_mismatch" });
		expect(fake.rpcCalls.some((entry) => entry.name === "record_connector_heartbeat")).toBe(false);
	});

	it("resolves an unbound tenant key by installation id and never creates an agent", async () => {
		const fake = database({ agentId: null, agent: null });
		const response = await createConnectorHeartbeatHandler({ db: fake.db as never })(post(body()));
		expect(response.status).toBe(404);
		expect(await response.json()).toEqual({ error: "agent_not_enrolled" });
		expect(fake.lookups).toEqual([{ tenant_id: TENANT, iid: "iid-device-1" }]);

		const known = database({ agentId: null, agent: { id: OTHER_AGENT, iid: "iid-device-1" } });
		const ok = await createConnectorHeartbeatHandler({ db: known.db as never })(post(body()));
		expect(ok.status).toBe(200);
		expect(known.rpcCalls.find((entry) => entry.name === "record_connector_heartbeat")?.args.p_agent_id).toBe(OTHER_AGENT);
	});

	it("refuses heartbeats for a retired agent (SEC-6)", async () => {
		const retired = database({ agentId: null, agent: { id: OTHER_AGENT, iid: "iid-device-1", retired_at: "2026-10-14T00:00:00Z" } as never });
		const response = await createConnectorHeartbeatHandler({ db: retired.db as never })(post(body()));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "agent_retired" });
		expect(retired.rpcCalls.some((entry) => entry.name === "record_connector_heartbeat")).toBe(false);
	});

	it("fails closed on a revoked key and on storage errors", async () => {
		const revoked = database({ revoked: true });
		expect((await createConnectorHeartbeatHandler({ db: revoked.db as never })(post(body()))).status).toBe(401);
		const lookupDown = database({ agentError: true });
		expect((await createConnectorHeartbeatHandler({ db: lookupDown.db as never })(post(body()))).status).toBe(503);
		const rpcDown = database({ rpcError: true });
		const response = await createConnectorHeartbeatHandler({ db: rpcDown.db as never })(post(body()));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "heartbeat_unavailable" });
	});
});
