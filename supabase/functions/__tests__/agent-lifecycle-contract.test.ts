// Contract suite for the `agent-lifecycle` Edge Function (seat lifecycle).
// Drives the real handler with an injected service-role client double and
// asserts parsing, owner/admin + AAL2 authorization, the RPCs it calls and
// failure mapping. The SQL behaviour is covered by agent-retirement.rollback.sql.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through AgentLifecycleDeps.client");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const migration = readFileSync(join(ROOT, "supabase", "migrations", "20261014120100_agent_retirement.sql"), "utf8");
const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "33333333-3333-4333-8333-333333333333";
const URL_BASE = "https://project.supabase.co/functions/v1/agent-lifecycle";
const ENV: Record<string, string> = {
	SUPABASE_URL: "https://project.supabase.co",
	SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

interface Options {
	role?: string | null;
	assurance?: string;
	rpcError?: { code: string; message?: string };
	rpcData?: unknown;
}

function database(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) =>
				token === "valid-token"
					? { data: { user: { id: USER } }, error: null }
					: { data: { user: null }, error: new Error("invalid") }),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({
					data: { currentLevel: options.assurance ?? "aal2" },
					error: null,
				})),
			},
		},
		from(table: string) {
			const builder = {
				select: () => builder,
				eq: () => builder,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") {
						return { data: { require_mfa: false, required_saml_provider_id: null }, error: null };
					}
					if (table === "tenant_members") {
						return options.role === null
							? { data: null, error: null }
							: { data: { role: options.role ?? "admin", expires_at: null }, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 5 }, error: null };
			if (options.rpcError) return { data: null, error: options.rpcError };
			if (options.rpcData !== undefined) return { data: options.rpcData, error: null };
			if (name === "retire_agent") {
				return { data: { status: "retired", agent_id: args.p_agent_id, revoked_keys: 2 }, error: null };
			}
			if (name === "set_agent_auto_retirement") {
				return { data: { status: "configured", auto_retire_offline_days: args.p_days }, error: null };
			}
			throw new Error(`unexpected rpc ${name}`);
		}),
	};
	return { db, rpcCalls };
}

async function handlerWith(options: Options = {}) {
	const fake = database(options);
	const mod = await import("../agent-lifecycle/index.ts");
	const handle = mod.createAgentLifecycleHandler({
		env: (name) => ENV[name],
		client: () => fake.db as never,
		now: () => Date.parse("2026-10-14T10:00:00.000Z"),
	});
	return { ...fake, handle, mod };
}

function post(body: unknown, token = "valid-token"): Request {
	return new Request(URL_BASE, {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

const mutations = (calls: Array<{ name: string }>) =>
	calls.filter((call) => call.name !== "consume_tenant_rate_limit").map((call) => call.name);

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("agent-lifecycle parsing", () => {
	it("accepts retire and bounded auto-retire commands only", async () => {
		const { mod } = await handlerWith();
		const parse = mod.parseAgentLifecycleCommand;
		expect(parse({ action: "retire", tenant_id: TENANT, agent_id: AGENT })).toEqual({
			ok: true,
			command: { action: "retire", tenantId: TENANT, agentId: AGENT, note: null },
		});
		expect(parse({ action: "set_auto_retire", tenant_id: TENANT, days: null })).toMatchObject({ ok: true });
		expect(parse({ action: "set_auto_retire", tenant_id: TENANT, days: 30 })).toMatchObject({ ok: true });
		for (const days of [6, 366, 7.5, "30"]) {
			expect(parse({ action: "set_auto_retire", tenant_id: TENANT, days })).toEqual({ ok: false, error: "invalid_days" });
		}
		expect(parse({ action: "set_auto_retire", tenant_id: TENANT })).toEqual({ ok: false, error: "invalid_request" });
		expect(parse({ action: "retire", tenant_id: TENANT, agent_id: "x" })).toEqual({ ok: false, error: "invalid_agent" });
		expect(parse({ action: "retire", tenant_id: TENANT, agent_id: AGENT, note: "a\u0007b" })).toEqual({
			ok: false,
			error: "invalid_note",
		});
		expect(parse({ action: "retire", tenant_id: TENANT, agent_id: AGENT, extra: 1 })).toEqual({
			ok: false,
			error: "invalid_request",
		});
		expect(parse({ action: "delete", tenant_id: TENANT })).toEqual({ ok: false, error: "invalid_action" });
	});
});

describe("agent-lifecycle authorization", () => {
	it("refuses a missing or invalid bearer before any database work", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const missing = await handle(new Request(URL_BASE, { method: "POST", body: "{}" }));
		expect(missing.status).toBe(401);
		const invalid = await handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT }, "bad"));
		expect(invalid.status).toBe(401);
		expect(rpcCalls).toEqual([]);
	});

	it("allows owners and admins only, and only at AAL2", async () => {
		for (const role of ["member", "viewer"]) {
			const { handle, rpcCalls } = await handlerWith({ role });
			const response = await handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT }));
			expect(response.status, role).toBe(403);
			expect(await response.json()).toEqual({ error: "workspace_role_insufficient" });
			expect(mutations(rpcCalls)).toEqual([]);
		}
		const nonMember = await handlerWith({ role: null });
		expect((await nonMember.handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT }))).status).toBe(403);
		const aal1 = await handlerWith({ assurance: "aal1" });
		const response = await aal1.handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(mutations(aal1.rpcCalls)).toEqual([]);
	});
});

describe("agent-lifecycle actions", () => {
	it("retires through retire_agent with the authenticated actor", async () => {
		const { handle, rpcCalls } = await handlerWith({ role: "owner" });
		const response = await handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT, note: " reimaged " }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, status: "retired", agent_id: AGENT, revoked_keys: 2 });
		expect(rpcCalls.find((call) => call.name === "retire_agent")?.args).toEqual({
			p_actor_user_id: USER,
			p_tenant_id: TENANT,
			p_agent_id: AGENT,
			p_note: "reimaged",
		});
	});

	it("maps database refusals and never reports an unconfirmed retirement as done", async () => {
		const notFound = await handlerWith({ rpcError: { code: "P0002", message: "agent_not_found" } });
		expect((await notFound.handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT }))).status).toBe(404);
		const forbidden = await handlerWith({ rpcError: { code: "42501", message: "agent_retirement_forbidden" } });
		expect((await forbidden.handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT }))).status).toBe(403);
		const drifted = await handlerWith({ rpcData: { status: "retired", agent_id: "someone-else" } });
		const response = await drifted.handle(post({ action: "retire", tenant_id: TENANT, agent_id: AGENT }));
		expect(response.status).toBe(503);
	});

	it("configures automatic retirement and refuses a drifted confirmation", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post({ action: "set_auto_retire", tenant_id: TENANT, days: 30 }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, auto_retire_offline_days: 30 });
		expect(rpcCalls.find((call) => call.name === "set_agent_auto_retirement")?.args).toEqual({
			p_actor_user_id: USER,
			p_tenant_id: TENANT,
			p_days: 30,
		});
		const drifted = await handlerWith({ rpcData: { status: "configured", auto_retire_offline_days: 90 } });
		expect((await drifted.handle(post({ action: "set_auto_retire", tenant_id: TENANT, days: 30 }))).status).toBe(503);
	});
});

describe("agent-lifecycle deployment and SQL contract", () => {
	it("is deployed with gateway JWT verification", () => {
		expect(config).toMatch(/\[functions\.agent-lifecycle\]\n(?:#.*\n)*verify_jwt = true/);
	});

	it("keeps retirement writes service-only and seat counting on active agents", () => {
		expect(migration).toContain("grant execute on function public.retire_agent(uuid, uuid, uuid, text) to service_role;");
		expect(migration).toContain("revoke all on function public.retire_agent(uuid, uuid, uuid, text) from public, anon, authenticated;");
		expect(migration).toContain("m.role in ('owner', 'admin')");
		expect(migration).toContain("update public.api_keys set revoked = true");
		expect(migration).toMatch(/where a\.tenant_id = v_tenant_id and a\.retired_at is null/);
		expect(migration).toContain("raise exception 'agent_retirement_protected'");
	});
});
