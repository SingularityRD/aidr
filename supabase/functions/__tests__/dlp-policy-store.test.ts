import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DlpPolicySchema } from "../../../packages/core/src/dlp/policy.ts";
import { dlpEdgeSchemaSource, edgeSchemaPath } from "../../../scripts/sync-dlp-edge-schema.mjs";

vi.mock("npm:zod@3.25.76", () => {
	const requireCore = createRequire(new URL("../../../packages/core/package.json", import.meta.url));
	return requireCore("zod");
});

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("client must be injected"); },
}));
vi.mock("npm:yaml@2.8.3", () => {
	const requireCore = createRequire(new URL("../../../packages/core/package.json", import.meta.url));
	return requireCore("yaml");
});

const TENANT = "22222222-2222-4222-8222-222222222222";
const FOREIGN = "33333333-3333-4333-8333-333333333333";
const USER = "11111111-1111-4111-8111-111111111111";
const NOW = "2026-09-16T12:00:00.000Z";
type Row = Record<string, any>;

function policy(): Row {
	return {
		version: 1, tenantId: TENANT,
		labels: [{ id: "secret", tenantId: TENANT, name: " Secret ", sensitivity: "restricted" }],
		rules: [{ id: "rule", tenantId: TENANT, labelId: "secret", name: "Rule", action: "block",
			matchers: [{ type: "keyword", values: ["secret-value"] }] }],
	};
}
function exception(id = "exception"): Row {
	return { id, tenantId: TENANT, ruleId: "rule", ownerId: USER, justification: "Known false positive",
		scope: "rule", createdAt: "2026-01-01T00:00:00Z", expiresAt: "2099-01-01T00:00:00Z" };
}
interface Options {
	role?: string;
	expiresAt?: string;
	status?: string;
	aal?: string;
	requireMfa?: boolean;
	assuranceError?: boolean;
	readError?: boolean;
	readResult?: unknown;
	authError?: boolean;
	sessionError?: boolean;
	revokedBefore?: string;
	rateDenied?: boolean;
	writeError?: string;
	writeResult?: unknown;
	writeThrows?: boolean;
}

/** Tenant-filtered fake with CAS state; actual transaction tests live in the SQL fixture. */
async function fixture(options: Options = {}) {
	let stored: Row | null = null;
	const revisions: Row[] = [];
	const audit: Row[] = [];
	const queries: Array<{ table: string; filters: Row }> = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => ({
				data: { user: token === "valid-token" && !options.authError ? { id: USER } : null }, error: null,
			})),
			mfa: { getAuthenticatorAssuranceLevel: vi.fn(async () => ({
				data: { currentLevel: options.aal ?? "aal2" }, error: options.assuranceError ? {} : null,
			})) },
		},
		from(table: string) {
			const filters: Row = {};
			queries.push({ table, filters });
			const query = {
				select: () => query,
				eq: (key: string, value: unknown) => { filters[key] = value; return query; },
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return {
						data: { revoked_before: options.revokedBefore ?? null }, error: options.sessionError ? {} : null,
					};
					if (table === "tenant_identity_policies") return { data: { require_mfa: options.requireMfa ?? false }, error: null };
					if (table === "tenant_members") return {
						data: filters.tenant_id === TENANT && filters.user_id === USER
							? { role: options.role ?? "owner", expires_at: options.expiresAt ?? null } : null, error: null,
					};
					if (table === "tenants") return { data: { status: options.status ?? "active" }, error: null };
					if (table === "tenant_dlp_policies") return {
						data: filters.tenant_id === TENANT
							? ("readResult" in options ? options.readResult : stored)
							: { version: 99, policy: { tenantId: FOREIGN } },
						error: options.readError ? {} : null,
					};
					throw new Error(`unexpected table ${table}`);
				},
			};
			return query;
		},
		rpc: vi.fn(async (name: string, args: Row) => {
			if (name === "consume_tenant_rate_limit") return { data: { allowed: !options.rateDenied, remaining: 10 }, error: null };
			if (name !== "publish_dlp_policy") throw new Error(`unexpected rpc ${name}`);
			if (options.writeThrows) throw new Error("storage offline");
			if (options.writeError) return { data: null, error: { code: options.writeError } };
			if ("writeResult" in options) return { data: options.writeResult, error: null };
			if (args.p_tenant_id !== TENANT || args.p_user_id !== USER) return { data: null, error: { code: "42501" } };
			if (args.p_expected_version !== (stored?.version ?? 0)) return { data: null, error: { code: "PT409" } };
			stored = { version: args.p_expected_version + 1, policy: args.p_policy, updated_at: NOW };
			revisions.push(structuredClone(stored));
			audit.push({ action: "dlp_policy.save", version: stored.version });
			return { data: stored, error: null };
		}),
	};
	const { createPolicyManagementHandler } = await import("../policy-management/index.ts");
	const handle = createPolicyManagementHandler({ db: db as never });
	const call = (body: Row, token = "valid-token") => handle(new Request("https://example.test/policy-management", {
		method: "POST", headers: { Authorization: token ? `Bearer ${token}` : "", "Content-Type": "application/json" },
		body: JSON.stringify({ tenant_id: TENANT, ...body }),
	}));
	return { call, db, queries, revisions, audit, writes: () => db.rpc.mock.calls.filter(([name]) => name === "publish_dlp_policy") };
}
const read = { action: "read_dlp_policy" };
const publish = (overrides: Row = {}) => ({ action: "publish_dlp_policy", expected_version: 0, policy: policy(), ...overrides });

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: (key: string) => process.env[key] }, serve: () => undefined });
	vi.stubEnv("SUPABASE_URL", "https://example.test");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "server-only-key");
	vi.spyOn(Date, "now").mockReturnValue(Date.parse(NOW));
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

describe("DLP editor load/save protocol", () => {
	it("reads empty, publishes v1 and reloads the server-normalized policy, never claiming delivery", async () => {
		const f = await fixture();
		const empty = await f.call(read);
		expect(empty.status).toBe(200);
		expect(await empty.json()).toMatchObject({ ok: true, policy: null, version: 0, saved: false, delivered: false });
		const response = await f.call(publish());
		expect(response.status).toBe(200);
		const saved = await response.json();
		expect(saved).toMatchObject({ ok: true, version: 1, saved: true, delivered: false, delivery_status: "not_delivered" });
		expect(saved.policy).toEqual(DlpPolicySchema.parse(policy()));
		expect(await (await f.call(read)).json()).toEqual(saved);
		expect(f.revisions).toHaveLength(1);
		expect(f.audit).toEqual([{ action: "dlp_policy.save", version: 1 }]);
		expect(f.queries.filter(q => q.table === "tenant_dlp_policies").every(q => q.filters.tenant_id === TENANT)).toBe(true);
	});

	it("returns 409 on stale expected_version without changing stored history; server owns revision numbers", async () => {
		const f = await fixture();
		expect((await f.call(publish())).status).toBe(200);
		const conflict = await f.call(publish());
		expect(conflict.status).toBe(409);
		expect(await conflict.json()).toEqual({ error: "policy_version_conflict" });
		expect(f.revisions).toHaveLength(1);
		const next = await f.call(publish({ expected_version: 1, policy: { ...policy(), version: 800 } }));
		expect(next.status).toBe(200);
		expect(await next.json()).toMatchObject({ version: 2, policy: { version: 2 } });
		expect(f.revisions.map(row => row.version)).toEqual([1, 2]);
	});

	it.each([
		undefined,
		{ version: 1, policy: { version: 1, tenantId: TENANT }, updated_at: "not-a-time" },
		{ version: 1, policy: { version: 1, tenantId: TENANT } },
	])("fails closed instead of acknowledging malformed saved-row data %j", async readResult => {
		const f = await fixture({ readResult });
		const response = await f.call(read);
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "dlp_policy_unavailable" });
	});

	it.each([undefined, null, -1, 1.5, "0", Number.MAX_SAFE_INTEGER])("refuses invalid expected_version %s", async expected_version => {
		const f = await fixture();
		expect((await f.call(publish({ expected_version }))).status).toBe(400);
		expect(f.writes()).toHaveLength(0);
	});
});

describe("DLP authorization is server-owned", () => {
	it.each(["", "invalid-token"])("denies missing/invalid authentication (%s)", async token => {
		const f = await fixture();
		for (const body of [read, publish()]) expect((await f.call(body, token)).status).toBe(401);
		expect(f.writes()).toHaveLength(0);
	});
	it("never reads or writes a foreign tenant selected in the body", async () => {
		const f = await fixture();
		for (const body of [read, publish()]) expect((await f.call({ ...body, tenant_id: FOREIGN })).status).toBe(403);
		expect(f.writes()).toHaveLength(0);
		expect(f.queries.some(q => q.table === "tenant_dlp_policies")).toBe(false);
	});
	it.each(["viewer", "member"])("denies %s publication, while preserving member-scoped reads", async role => {
		const f = await fixture({ role });
		expect((await f.call(publish())).status).toBe(403);
		expect((await f.call(read)).status).toBe(200);
		expect(f.writes()).toHaveLength(0);
	});
	it("allows an admin with AAL2", async () => {
		const f = await fixture({ role: "admin" });
		expect((await f.call(publish())).status).toBe(200);
	});
	it.each([false, true])("denies AAL1 reads and writes even with require_mfa=%s", async requireMfa => {
		const f = await fixture({ aal: "aal1", requireMfa });
		for (const body of [read, publish()]) {
			const response = await f.call(body);
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "mfa_required" });
		}
		expect(f.writes()).toHaveLength(0);
	});
	it.each([
		[{ expiresAt: "2000-01-01T00:00:00Z" }, 403],
		[{ expiresAt: "invalid" }, 403],
		[{ status: "suspended" }, 403],
		[{ revokedBefore: "2099-01-01T00:00:00Z" }, 401],
		[{ sessionError: true }, 503],
		[{ assuranceError: true }, 503],
		[{ rateDenied: true }, 429],
	] as const)("fails closed for authorization state %j", async (options, status) => {
		const f = await fixture(options);
		for (const body of [read, publish()]) expect((await f.call(body)).status).toBe(status);
		expect(f.writes()).toHaveLength(0);
	});
});

const invalidCases: Array<[string, (p: Row) => unknown]> = [
	["null", () => null], ["array", () => []], ["empty", () => ({})],
	["unknown field", p => ({ ...p, browserValidated: true })],
	["no labels", p => ({ ...p, labels: [] })],
	["invalid MIME", p => ({ ...p, supportedFormats: ["bad"] })],
	["oversized content cap", p => ({ ...p, maxContentBytes: 10485761 })],
	["foreign label", p => { p.labels[0].tenantId = FOREIGN; return p; }],
	["foreign rule", p => { p.rules[0].tenantId = FOREIGN; return p; }],
	["unknown label reference", p => { p.rules[0].labelId = "missing"; return p; }],
	["duplicate label", p => ({ ...p, labels: [p.labels[0], p.labels[0]] })],
	["allow action", p => { p.rules[0].action = "allow"; return p; }],
	["invalid regex", p => { p.rules[0].matchers = [{ type: "regex", pattern: "[" }]; return p; }],
	["empty matching regex", p => { p.rules[0].matchers = [{ type: "regex", pattern: "a*" }]; return p; }],
	["unsafe nested regex", p => { p.rules[0].matchers = [{ type: "regex", pattern: "(a+)+" }]; return p; }],
	["regex backreference", p => { p.rules[0].matchers = [{ type: "regex", pattern: "(a)\\1" }]; return p; }],
	["invalid flags", p => { p.rules[0].matchers = [{ type: "regex", pattern: "secret", flags: "gg" }]; return p; }],
	["invalid expiry", p => ({ ...p, exceptions: [{ ...exception(), expiresAt: "yesterday" }] })],
	["expiry before creation", p => ({ ...p, exceptions: [{ ...exception(), expiresAt: "2025-01-01T00:00:00Z" }] })],
	["foreign exception", p => ({ ...p, exceptions: [{ ...exception(), tenantId: FOREIGN }] })],
	["missing fingerprint", p => ({ ...p, exceptions: [{ ...exception(), scope: "match" }] })],
	["missing rule", p => ({ ...p, exceptions: [{ ...exception(), ruleId: "missing" }] })],
	["expired exception dominance", p => ({ ...p, exceptions: ["e1", "e2"].map(id => ({ ...exception(id), expiresAt: "2026-02-01T00:00:00Z" })) })],
];

describe("engine-schema validation at the server boundary (no browser trust)", () => {
	it("ships the exact core schema with only its dependency specifier adapted for Deno", () => {
		expect(readFileSync(edgeSchemaPath, "utf8").replaceAll("\r\n", "\n")).toBe(dlpEdgeSchemaSource());
	});
	it.each(invalidCases)("rejects %s before storage", async (_name, change) => {
		const f = await fixture();
		const invalid = change(policy());
		expect(DlpPolicySchema.safeParse(invalid).success).toBe(false);
		const response = await f.call(publish({ policy: invalid, validated: true }));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "invalid_dlp_policy" });
		expect(f.writes()).toHaveLength(0);
	});
	it("binds an otherwise engine-valid foreign policy to the authenticated tenant", async () => {
		const f = await fixture();
		const foreign = JSON.parse(JSON.stringify(policy()).replaceAll(TENANT, FOREIGN));
		expect(DlpPolicySchema.safeParse(foreign).success).toBe(true);
		const response = await f.call(publish({ policy: foreign }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "dlp_tenant_mismatch" });
		expect(f.writes()).toHaveLength(0);
	});
	it("accepts and normalizes regexes, offsets and fingerprints exactly like core", async () => {
		const f = await fixture();
		const p = policy();
		p.supportedFormats = ["TEXT/*"];
		p.rules[0].matchers = [{ type: "regex", pattern: "secret-[0-9]+", flags: "im" }];
		p.exceptions = [{ ...exception(), scope: "content", fingerprint: "a".repeat(64), expiresAt: "2099-01-01T00:00:00+02:00" }];
		const response = await f.call(publish({ policy: p }));
		expect(response.status).toBe(200);
		expect((await response.json()).policy).toEqual(DlpPolicySchema.parse(p));
	});
	it("preserves the engine's single-expired-exception allowance", async () => {
		const f = await fixture();
		const p = { ...policy(), exceptions: [{ ...exception(), expiresAt: "2026-02-01T00:00:00Z" }] };
		expect(DlpPolicySchema.safeParse(p).success).toBe(true);
		expect((await f.call(publish({ policy: p }))).status).toBe(200);
	});
});

describe("storage failures are never successful saves", () => {
	it.each(["08006", "23505", "42501", "22023"])("maps SQL error %s without success", async writeError => {
		const f = await fixture({ writeError });
		const response = await f.call(publish());
		expect(response.status).toBe(writeError === "42501" ? 403 : writeError === "22023" ? 400 : 503);
		expect((await response.json()).ok).not.toBe(true);
		expect(f.revisions).toHaveLength(0);
	});
	it.each([null, {}, { version: 1 }, { version: 0 }, { version: 1, policy: { version: 1, tenantId: FOREIGN }, updated_at: NOW }, { version: 1, policy: { version: 1, tenantId: TENANT }, updated_at: "not-a-time" }])("does not acknowledge malformed RPC payload %j", async writeResult => {
		const f = await fixture({ writeResult });
		const response = await f.call(publish());
		expect(response.status).toBe(503);
		expect((await response.json()).ok).not.toBe(true);
	});
	it("does not turn a thrown write or a failed read into success/empty", async () => {
		const write = await fixture({ writeThrows: true });
		expect((await write.call(publish())).status).toBe(503);
		const load = await fixture({ readError: true });
		expect((await load.call(read)).status).toBe(503);
	});
});
