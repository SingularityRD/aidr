import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("policy test requires an injected database"); },
}));

const served: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => served.push(handler),
};

const { createPolicyHandler } = await import("../policy/index.ts");
const { canonicalPolicy, sha256 } = await import("../_shared/runtime-policy.ts");
const URL = "https://project.supabase.co/functions/v1/policy";
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const KEY = "aidr-policy-contract-key";
const CURRENT = { command_default: "ask" };
const STAGED = { command_default: "deny" };

type Options = {
	agentId?: string | null;
	keyRevoked?: boolean;
	tenantStatus?: string;
	rate?: "deny" | "unavailable";
	governance?: unknown;
	governanceError?: boolean;
	assignment?: number | null;
	assignmentError?: boolean;
	current?: unknown;
	currentError?: boolean;
	revision?: unknown;
	revisionError?: boolean;
};

function database(options: Options = {}) {
	const queries: Array<{ table: string; filters: Record<string, unknown> }> = [];
	const rpcCalls: string[] = [];
	const rpcArgs: Record<string, unknown>[] = [];
	function from(table: string) {
		const filters: Record<string, unknown> = {};
		const query = {
			select: (_columns: string) => query,
			eq: (column: string, value: unknown) => { filters[column] = value; return query; },
			maybeSingle: async () => {
				queries.push({ table, filters: { ...filters } });
				switch (table) {
					case "api_keys": return { data: options.keyRevoked ? { user_id: USER, tenant_id: TENANT, agent_id: AGENT, revoked: true, scope: "tenant" } : { user_id: USER, tenant_id: TENANT, agent_id: options.agentId === undefined ? AGENT : options.agentId, revoked: false, scope: "tenant" }, error: null };
					case "tenant_members": return { data: { role: "member", expires_at: null }, error: null };
					case "tenants": return { data: { status: options.tenantStatus ?? "active" }, error: null };
					case "agent_policy_assignments": return { data: options.assignment === null ? null : { version: options.assignment ?? 4 }, error: options.assignmentError ? new Error("db_down") : null };
					case "tenant_runtime_policies": return { data: options.current === null ? null : { version: 3, policy: options.current ?? CURRENT }, error: options.currentError ? new Error("db_down") : null };
					case "runtime_policy_revisions": return { data: options.revision === null ? null : { version: 4, policy: options.revision ?? STAGED }, error: options.revisionError ? new Error("db_down") : null };
					default: throw new Error(`unexpected relation ${table}`);
				}
			},
		};
		return query;
	}
	const db = {
		from,
		rpc: async (name: string, args: Record<string, unknown> = {}) => {
			rpcCalls.push(name);
			rpcArgs.push(args);
			if (name === "tenant_admission_capacity") return { data: 1, error: null };
			if (name === "ai_governance_policy_overlay") {
				return options.governanceError ? { data: null, error: new Error("db_down") }
					: { data: "governance" in options ? options.governance : { mcp_deny_servers: [], mcp_require_approval_servers: [], browser_guard_blocked_sites: [] }, error: null };
			}
			if (name !== "consume_tenant_rate_limit") throw new Error(`unexpected RPC ${name}`);
			return options.rate === "unavailable" ? { data: null, error: new Error("db_down") }
				: { data: { allowed: options.rate !== "deny", remaining: options.rate === "deny" ? 0 : 299 }, error: null };
		},
	};
	return { db, queries, rpcCalls, rpcArgs };
}

function get(token = KEY) {
	return new Request(URL, { headers: { Authorization: `Bearer ${token}` } });
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});
afterEach(() => vi.unstubAllEnvs());

describe("policy fetch", () => {
	it("serves the same handler in Edge and tests", () => {
		expect(served).toHaveLength(1);
		expect(typeof served[0]).toBe("function");
	});

	it("rejects unsupported methods, missing credentials and missing configuration", async () => {
		const fake = database();
		const handle = createPolicyHandler({ db: fake.db as never });
		expect((await handle(new Request(URL, { method: "POST" }))).status).toBe(405);
		expect((await handle(new Request(URL))).status).toBe(401);
		vi.stubEnv("SUPABASE_URL", "");
		const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
		try {
			expect((await handle(get())).status).toBe(500);
		} finally {
			logged.mockRestore();
		}
		expect(fake.queries).toHaveLength(0);
	});

	it("returns only an authenticated agent's assigned revision with its canonical digest", async () => {
		const fake = database();
		const response = await createPolicyHandler({ db: fake.db as never })(get());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ policy_version: "4", cache_seconds: 30, runtime_policy: STAGED, policy_sha256: await sha256(canonicalPolicy(STAGED)), agent_bound: true });
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(fake.queries.find((q) => q.table === "agent_policy_assignments")?.filters).toEqual({ tenant_id: TENANT, agent_id: AGENT });
		expect(fake.queries.find((q) => q.table === "runtime_policy_revisions")?.filters).toEqual({ tenant_id: TENANT, version: 4 });
		expect(fake.rpcCalls).toEqual(["tenant_admission_capacity", "consume_tenant_rate_limit", "ai_governance_policy_overlay"]);
	});

	it("uses the published tenant policy for an unbound key or an unassigned agent", async () => {
		for (const options of [{ agentId: null }, { assignment: null }]) {
			const fake = database(options);
			const response = await createPolicyHandler({ db: fake.db as never })(get());
			expect(response.status).toBe(200);
			expect(await response.json()).toMatchObject({ policy_version: "3", runtime_policy: CURRENT, agent_bound: options.agentId !== null });
			expect(fake.queries.some((q) => q.table === "runtime_policy_revisions")).toBe(false);
		}
	});

	it("rejects bad credentials, suspended tenants and quota failures before reading policy", async () => {
		for (const [options, status] of [
			[{ keyRevoked: true }, 401], [{ tenantStatus: "suspended" }, 403],
			[{ rate: "deny" }, 429], [{ rate: "unavailable" }, 503],
		] as const) {
			const fake = database(options);
			const response = await createPolicyHandler({ db: fake.db as never })(get());
			expect(response.status).toBe(status);
			expect(fake.queries.some((q) => q.table === "runtime_policy_revisions" || q.table === "tenant_runtime_policies")).toBe(false);
		}
	});

	it("adds the AI governance overlay for this member and agent next to, never inside, the published policy", async () => {
		const governance = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: ["github"], browser_guard_blocked_sites: ["deepseek"] };
		const fake = database({ governance });
		const response = await createPolicyHandler({ db: fake.db as never })(get());
		expect(response.status).toBe(200);
		const overlay = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: ["github"] };
		expect(await response.json()).toEqual({
			policy_version: "4", cache_seconds: 30, runtime_policy: STAGED, policy_sha256: await sha256(canonicalPolicy(STAGED)),
			agent_bound: true, governance: overlay, governance_sha256: await sha256(canonicalPolicy(overlay)),
		});
		expect(fake.rpcArgs[fake.rpcCalls.indexOf("ai_governance_policy_overlay")]).toEqual({
			p_tenant_id: TENANT, p_user_id: USER, p_agent_id: AGENT,
		});
	});

	it("fails closed when the governance overlay is unreadable or malformed", async () => {
		for (const options of [
			{ governanceError: true },
			{ governance: { mcp_deny_servers: ["bad id!"], mcp_require_approval_servers: [] } },
			{ governance: { mcp_deny_servers: "shell-runner", mcp_require_approval_servers: [] } },
			{ governance: null },
		]) {
			const response = await createPolicyHandler({ db: database(options).db as never })(get());
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "policy_unavailable" });
		}
	});

	it("never supplies an invalid, missing or unavailable policy", async () => {
		for (const [options, status] of [
			[{ assignmentError: true }, 503], [{ revisionError: true }, 503],
			[{ revision: null }, 404], [{ revision: { typo: "deny" } }, 503],
		] as const) {
			const fake = database(options);
			const response = await createPolicyHandler({ db: fake.db as never })(get());
			expect(response.status).toBe(status);
		}
	});
});
