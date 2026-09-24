// Contract suite for the agent-reported `policy-ack` receipt endpoint.
//
// Receipts are evidence that an enrolled agent loaded a revision. They are not
// host-enforcement attestation or proof of fleet convergence. The suite drives
// the real handler factory with a Supabase-shaped double so authentication,
// tenant binding, hash verification, quotas and the boolean RPC contract stay
// executable without a live project.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through PolicyAckDeps.db");
	},
}));

const serveCalls: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => {
		serveCalls.push(handler);
	},
};

const { createPolicyAckHandler } = await import("../policy-ack/index.ts");
const { canonicalPolicy, sha256 } = await import("../_shared/runtime-policy.ts");

const FUNCTION_URL = "https://project.supabase.co/functions/v1/policy-ack";
const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "33333333-3333-4333-8333-333333333333";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const API_KEY = "aidr-contract-agent-key";
const API_KEY_HASH = await sha256(API_KEY);
const POLICY = { command_default: "deny", mcp_unknown: "ask" };
const POLICY_SHA256 = await sha256(canonicalPolicy(POLICY));

interface DbOptions {
	key?: Record<string, unknown> | null;
	apiKeyError?: boolean;
	membership?: Record<string, unknown> | null;
	membershipError?: boolean;
	tenant?: Record<string, unknown> | null;
	tenantError?: boolean;
	revision?: Record<string, unknown> | null;
	revisionError?: boolean;
	rotated?: boolean;
	rate?: "allow" | "deny" | "unavailable" | "throwing" | "malformed";
	receipt?: boolean | "error";
}

type QueryResult = { data: unknown; error: unknown };

type RpcCall = { name: string; args: Record<string, unknown> };

function database(options: DbOptions = {}) {
	const calls: Array<{ table: string; select: string; filters: Record<string, unknown> }> = [];
	const rpcCalls: RpcCall[] = [];
	const activeKey = options.key === undefined
		? {
			user_id: USER,
			tenant_id: TENANT,
			agent_id: AGENT,
			revoked: false,
			scope: "tenant",
			...(options.rotated ? { previous_hash: API_KEY_HASH, previous_hash_expires_at: "2099-01-01T00:00:00.000Z" } : {}),
		}
		: options.key;

	function resultFor(table: string, columns: string, filters: Record<string, unknown>): QueryResult {
		if (table === "api_keys") {
			return {
				data: options.rotated && !columns.includes("previous_hash") ? null : activeKey,
				error: options.apiKeyError ? new Error("db_down") : null,
			};
		}
		if (table === "tenant_members") {
			return {
				data: options.membership === undefined ? { role: "member", expires_at: null } : options.membership,
				error: options.membershipError ? new Error("db_down") : null,
			};
		}
		if (table === "tenants") {
			return {
				data: options.tenant === undefined ? { status: "active" } : options.tenant,
				error: options.tenantError ? new Error("db_down") : null,
			};
		}
		if (table === "runtime_policy_revisions") {
			return {
				data: options.revision === undefined ? { policy: POLICY } : options.revision,
				error: options.revisionError ? new Error("db_down") : null,
			};
		}
		return { data: null, error: null };
	}

	function from(table: string) {
		let columns = "";
		const filters: Record<string, unknown> = {};
		const query = {
			select(value: string) {
				columns = value;
				return query;
			},
			eq(column: string, value: unknown) {
				filters[column] = value;
				return query;
			},
			maybeSingle: async () => {
				calls.push({ table, select: columns, filters: { ...filters } });
				return resultFor(table, columns, filters);
			},
		};
		return query;
	}

	const db = {
		from: vi.fn(from),
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "tenant_admission_capacity") return { data: 1, error: null };
			if (name === "consume_tenant_rate_limit") {
				if (options.rate === "unavailable") return { data: null, error: { code: "08006" } };
				if (options.rate === "throwing") throw new Error("db_down");
				if (options.rate === "malformed") return { data: { allowed: "yes", remaining: 1 }, error: null };
				if (options.rate === "deny") return { data: { allowed: false, remaining: 0 }, error: null };
				return { data: { allowed: true, remaining: 299 }, error: null };
			}
			if (options.receipt === "error") return { data: null, error: { code: "08006" } };
			return { data: options.receipt === false ? false : true, error: null };
		}),
	};
	return { db, calls, rpcCalls };
}

function post(body: unknown, headers: Record<string, string> = {}): Request {
	return new Request(FUNCTION_URL, {
		method: "POST",
		headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json", ...headers },
		body: typeof body === "string" ? body : JSON.stringify(body),
	});
}

function receiptBody(overrides: Record<string, unknown> = {}) {
	return { version: 3, policy_sha256: POLICY_SHA256, ...overrides };
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});

afterEach(() => {
	vi.unstubAllEnvs();
});

describe("policy-ack transport and configuration", () => {
	it("is wired to the Edge runtime through the exported factory", () => {
		expect(serveCalls).toHaveLength(1);
		expect(typeof serveCalls[0]).toBe("function");
	});

	it("refuses non-POST requests and missing credentials before database work", async () => {
		const fake = database();
		const handle = createPolicyAckHandler({ db: fake.db as never });
		const get = await handle(new Request(FUNCTION_URL, { method: "GET" }));
		expect(get.status).toBe(405);
		const missing = await handle(new Request(FUNCTION_URL, { method: "POST", body: JSON.stringify(receiptBody()) }));
		expect(missing.status).toBe(401);
		expect(await missing.json()).toMatchObject({ error: "missing_api_key" });
		expect(fake.calls).toHaveLength(0);
		expect(fake.rpcCalls).toHaveLength(0);
	});

	it("fails fast when platform configuration is incomplete", async () => {
		vi.stubEnv("SUPABASE_URL", "");
		const fake = database();
		const logged = vi.spyOn(console, "error").mockImplementation(() => undefined);
		try {
			const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody()));
			expect(response.status).toBe(500);
			expect(await response.json()).toMatchObject({ error: "server_misconfigured", missing: ["SUPABASE_URL"] });
			expect(fake.calls).toHaveLength(0);
			expect(fake.rpcCalls).toHaveLength(0);
		} finally {
			logged.mockRestore();
		}
	});
});

describe("policy-ack request validation", () => {
	it.each([
		[null, "invalid_receipt"],
		[[], "invalid_receipt"],
		[{ version: 0, policy_sha256: POLICY_SHA256 }, "invalid_receipt"],
		[{ version: -1, policy_sha256: POLICY_SHA256 }, "invalid_receipt"],
		[{ version: 1.5, policy_sha256: POLICY_SHA256 }, "invalid_receipt"],
		[{ version: "3", policy_sha256: POLICY_SHA256 }, "invalid_receipt"],
		[{ version: 3, policy_sha256: "A".repeat(64) }, "invalid_receipt"],
		[{ version: 3, policy_sha256: "0".repeat(63) }, "invalid_receipt"],
		[{ version: 3 }, "invalid_receipt"],
	] as const)("rejects malformed receipt %j before authorization", async (body, error) => {
		const fake = database();
		const response = await createPolicyAckHandler({ db: fake.db as never })(post(body));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error });
		expect(fake.calls).toHaveLength(0);
		expect(fake.rpcCalls).toHaveLength(0);
	});

	it("bounds the JSON body instead of retaining an oversized receipt", async () => {
		const fake = database();
		const response = await createPolicyAckHandler({ db: fake.db as never })(post({ ...receiptBody(), padding: "x".repeat(3000) }));
		expect(response.status).toBe(413);
		expect(await response.json()).toMatchObject({ error: "request_too_large" });
		expect(fake.calls).toHaveLength(0);
	});
});

describe("policy-ack authentication and receipt contract", () => {
	it("rejects invalid, revoked and unbound keys without recording a receipt", async () => {
		const invalid = database({ key: null });
		const invalidResponse = await createPolicyAckHandler({ db: invalid.db as never })(post(receiptBody()));
		expect(invalidResponse.status).toBe(401);
		expect(invalid.rpcCalls).toHaveLength(0);

		const revoked = database({ key: { user_id: USER, tenant_id: TENANT, revoked: true } });
		const revokedResponse = await createPolicyAckHandler({ db: revoked.db as never })(post(receiptBody()));
		expect(revokedResponse.status).toBe(401);
		expect(revoked.rpcCalls).toHaveLength(0);

		const unbound = database({ key: { user_id: USER, tenant_id: TENANT, agent_id: null, revoked: false, scope: "tenant" } });
		const unboundResponse = await createPolicyAckHandler({ db: unbound.db as never })(post(receiptBody()));
		expect(unboundResponse.status).toBe(403);
		expect(await unboundResponse.json()).toMatchObject({ error: "agent_bound_key_required" });
		expect(unbound.rpcCalls.map(({ name }) => name)).toEqual(["tenant_admission_capacity", "consume_tenant_rate_limit"]);
	});

	it("fails closed on API-key, membership, tenant and revision storage errors", async () => {
		for (const options of [{ apiKeyError: true }, { membershipError: true }, { tenantError: true }, { revisionError: true }]) {
			const fake = database(options);
			const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody()));
			expect(response.status, JSON.stringify(options)).toBe(503);
			expect(fake.rpcCalls.some(({ name }) => name === "record_policy_receipt")).toBe(false);
		}
	});

	it("uses the binding from the hash that authenticated the request", async () => {
		const fake = database({ key: { user_id: USER, tenant_id: OTHER_TENANT, agent_id: AGENT, revoked: false, scope: "tenant" } });
		const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody()));
		expect(response.status).toBe(200);
		expect(fake.rpcCalls.some(({ name }) => name === "record_policy_receipt")).toBe(true);
	});

	it("keeps the bounded retired-hash overlap bound to the same agent receipt", async () => {
		const fake = database({ rotated: true });
		const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody()));
		expect(response.status).toBe(200);
		expect(fake.rpcCalls.find(({ name }) => name === "record_policy_receipt")?.args.p_key_hash).toBe(API_KEY_HASH);
	});

	it("returns quota metadata and never calls the receipt RPC after a quota failure", async () => {
		for (const rate of ["deny", "unavailable", "throwing", "malformed"] as const) {
			const fake = database({ rate });
			const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody()));
			expect(response.status, rate).toBe(rate === "deny" ? 429 : 503);
			expect(fake.rpcCalls.map(({ name }) => name)).toEqual(["tenant_admission_capacity", "consume_tenant_rate_limit"]);
			if (rate === "deny") {
				expect(response.headers.get("Retry-After")).toMatch(/^\d+$/);
				expect(response.headers.get("RateLimit-Remaining")).toBe("0");
			}
		}
	});

	it("requires the exact canonical revision hash and does not acknowledge missing revisions", async () => {
		const missing = database({ revision: null });
		const missingResponse = await createPolicyAckHandler({ db: missing.db as never })(post(receiptBody()));
		expect(missingResponse.status).toBe(409);
		expect(await missingResponse.json()).toMatchObject({ error: "policy_receipt_mismatch" });
		expect(missing.rpcCalls.some(({ name }) => name === "record_policy_receipt")).toBe(false);

		const mismatch = database();
		const mismatchResponse = await createPolicyAckHandler({ db: mismatch.db as never })(post(receiptBody({ policy_sha256: "0".repeat(64) })));
		expect(mismatchResponse.status).toBe(409);
		expect(mismatch.rpcCalls.some(({ name }) => name === "record_policy_receipt")).toBe(false);
	});

	it("does not record adoption for a malformed or unsupported stored policy", async () => {
		for (const policy of [undefined, {}, { command_default: "permit" }, { typo: "deny" }]) {
			const fake = database({ revision: { policy } });
			const digest = await sha256(canonicalPolicy(policy));
			const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody({ policy_sha256: digest })));
			expect(response.status, JSON.stringify(policy)).toBe(503);
			expect(await response.json()).toMatchObject({ error: "policy_unavailable" });
			expect(fake.rpcCalls.some(({ name }) => name === "record_policy_receipt")).toBe(false);
		}
	});

	it("records only the verified key hash, tenant revision and receipt hash", async () => {
		const fake = database();
		const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody()));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(response.headers.get("RateLimit-Remaining")).toBe("299");
		const revisionRead = fake.calls.find(({ table }) => table === "runtime_policy_revisions");
		expect(revisionRead?.filters).toEqual({ tenant_id: TENANT, version: 3 });
		const receipt = fake.rpcCalls.find(({ name }) => name === "record_policy_receipt");
		expect(receipt?.args).toEqual({
			p_key_hash: await sha256(API_KEY),
			p_version: 3,
			p_policy_sha256: POLICY_SHA256,
		});
	});

	it("never turns a rejected or unavailable receipt RPC into a success", async () => {
		const rejected = database({ receipt: false });
		const rejectedResponse = await createPolicyAckHandler({ db: rejected.db as never })(post(receiptBody()));
		expect(rejectedResponse.status).toBe(409);
		expect(await rejectedResponse.json()).toMatchObject({ error: "receipt_rejected" });

		const unavailable = database({ receipt: "error" });
		const unavailableResponse = await createPolicyAckHandler({ db: unavailable.db as never })(post(receiptBody()));
		expect(unavailableResponse.status).toBe(503);
		expect(await unavailableResponse.json()).toMatchObject({ error: "receipt_unavailable" });
	});

	it("does not accept a malformed bound-agent identifier", async () => {
		const fake = database({ key: { user_id: USER, tenant_id: TENANT, agent_id: "not-an-agent", revoked: false, scope: "tenant" } });
		const response = await createPolicyAckHandler({ db: fake.db as never })(post(receiptBody()));
		expect(response.status).toBe(403);
		expect(await response.json()).toMatchObject({ error: "agent_bound_key_required" });
		expect(fake.rpcCalls.map(({ name }) => name)).toEqual(["tenant_admission_capacity", "consume_tenant_rate_limit"]);
	});
});
