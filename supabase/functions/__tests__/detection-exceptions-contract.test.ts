// Contract suite for the `detection-exceptions` Edge Function.
//
// The real handler runs against an in-memory service-role double whose RPCs
// mirror the SQL contract of the detection-exceptions migration (the SQL text
// itself is pinned by detection-exceptions-migration.test.ts). Covers session
// and identity-barrier gating, owner/admin only, AAL2 for every action,
// cross-tenant isolation, the actor always being the session user, request
// validation (bounded expiry, protected self-defense rules), error mapping, and
// that there is no API-key (agent) path at all.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({
	createClient: vi.fn((): unknown => {
		throw new Error("createClient must be injected through DetectionExceptionsDeps.client");
	}),
}));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const served: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => served.push(handler),
};

const { createDetectionExceptionsHandler } = await import("../detection-exceptions/index.ts");
const { parseDetectionExceptionRequest, validateDetectionExceptionFeed, isProtectedRuleId } = await import(
	"../_shared/detection-exceptions.ts"
);

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const HANDLER_SOURCE = readFileSync(join(ROOT, "supabase", "functions", "detection-exceptions", "index.ts"), "utf8");

const TENANT_A = "22222222-2222-4222-8222-222222222222";
const TENANT_B = "99999999-9999-4999-8999-999999999999";
const OWNER_A = "11111111-1111-4111-8111-111111111111";
const ADMIN_A = "12121212-1212-4121-8121-121212121212";
const MEMBER_A = "13131313-1313-4131-8131-131313131313";
const OWNER_B = "15151515-1515-4151-8151-151515151515";
const AGENT_A = "33333333-3333-4333-8333-333333333333";
const T0 = Date.parse("2026-10-07T10:00:00.000Z");
const URL_BASE = "https://project.supabase.co/functions/v1/detection-exceptions";
const ENV = { SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "service-role" } as Record<string, string>;

type Row = Record<string, unknown>;

class World {
	readonly members: Row[] = [];
	readonly tenants: Row[] = [
		{ id: TENANT_A, status: "active" },
		{ id: TENANT_B, status: "active" },
	];
	readonly exceptions: Row[] = [];
	readonly audit: Array<{ tenant: unknown; actor: unknown; action: string }> = [];
	readonly rpcCalls: Array<{ name: string; args: Row }> = [];
	readonly sessions = new Map<string, { user: string; aal: "aal1" | "aal2" }>();
	private seq = 0;

	constructor(private readonly options: { rateDenied?: boolean; failTables?: string[] } = {}) {
		for (const [tenant, user, role] of [
			[TENANT_A, OWNER_A, "owner"], [TENANT_A, ADMIN_A, "admin"], [TENANT_A, MEMBER_A, "member"], [TENANT_B, OWNER_B, "owner"],
		]) {
			this.members.push({ tenant_id: tenant, user_id: user, role, expires_at: null });
			this.sessions.set(`session-${user}`, { user, aal: "aal2" });
			this.sessions.set(`aal1-${user}`, { user, aal: "aal1" });
		}
	}

	private table(name: string): Row[] {
		switch (name) {
			case "tenant_members": return this.members;
			case "tenants": return this.tenants;
			case "detection_exceptions": return this.exceptions;
			case "identity_user_session_state": return [];
			case "tenant_identity_policies": return [];
			default: throw new Error(`unexpected table ${name}`);
		}
	}

	db() {
		const world = this;
		return {
			auth: {
				getUser: vi.fn(async (token: string) => {
					const session = world.sessions.get(token);
					return session ? { data: { user: { id: session.user } }, error: null } : { data: { user: null }, error: new Error("invalid") };
				}),
				mfa: {
					getAuthenticatorAssuranceLevel: vi.fn(async (token: string) => ({
						data: { currentLevel: world.sessions.get(token)?.aal ?? "aal1" }, error: null,
					})),
				},
			},
			from(name: string) {
				const filters: Array<(row: Row) => boolean> = [];
				const result = () => {
					if (world.options.failTables?.includes(name)) return { data: null, error: { message: "db_down" } };
					return { data: world.table(name).filter((row) => filters.every((f) => f(row))).map((row) => ({ ...row })), error: null };
				};
				const builder = {
					select: () => builder,
					eq: (column: string, value: unknown) => { filters.push((row) => row[column] === value); return builder; },
					order: () => builder,
					limit: async () => result(),
					maybeSingle: async () => {
						const { data, error } = result();
						return { data: data?.[0] ?? null, error };
					},
				};
				return builder;
			},
			rpc: vi.fn(async (name: string, args: Row) => {
				world.rpcCalls.push({ name, args });
				try {
					return { data: world.rpc(name, args), error: null };
				} catch (error) {
					return { data: null, error };
				}
			}),
		};
	}

	private rpc(name: string, a: Row): unknown {
		const fail = (code: string, message: string): never => { throw { code, message }; };
		const role = this.members.find((m) => m.tenant_id === a.p_tenant_id && m.user_id === a.p_actor_user_id)?.role;
		switch (name) {
			case "consume_tenant_rate_limit":
				return this.options.rateDenied ? { allowed: false, remaining: 0 } : { allowed: true, remaining: 10 };
			case "create_detection_exception": {
				if (role !== "owner" && role !== "admin") fail("42501", "detection_exception_forbidden");
				const fields = a.p_fields as Row;
				if (String(fields.rule_id).toUpperCase().startsWith("CLT-SELF-")) fail("22023", "detection_exception_protected_rule");
				this.seq += 1;
				const row = {
					id: `aaaaaaaa-0000-4000-8000-${String(this.seq).padStart(12, "0")}`,
					tenant_id: a.p_tenant_id, ...fields, created_by: a.p_actor_user_id, created_at: new Date(T0).toISOString(),
					revoked_at: null,
				};
				this.exceptions.push(row);
				this.audit.push({ tenant: a.p_tenant_id, actor: a.p_actor_user_id, action: "detection_exception.created" });
				return { exception_id: row.id, expires_at: fields.expires_at };
			}
			case "revoke_detection_exception": {
				if (role !== "owner" && role !== "admin") fail("42501", "detection_exception_forbidden");
				const row = this.exceptions.find((e) => e.id === a.p_exception_id && e.tenant_id === a.p_tenant_id);
				if (!row) fail("P0002", "detection_exception_not_found");
				if ((row as Row).revoked_at) fail("55000", "detection_exception_not_active");
				(row as Row).revoked_at = new Date(T0).toISOString();
				this.audit.push({ tenant: a.p_tenant_id, actor: a.p_actor_user_id, action: "detection_exception.revoked" });
				return { exception_id: a.p_exception_id, revoked: true };
			}
			default:
				throw new Error(`unexpected rpc ${name}`);
		}
	}
}

function handler(world: World) {
	return createDetectionExceptionsHandler({ env: (name) => ENV[name], client: () => world.db() as never, now: () => T0 });
}

async function call(world: World, token: string | null, body: unknown) {
	const response = await handler(world)(
		new Request(URL_BASE, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
			body: JSON.stringify(body),
		}),
	);
	return { status: response.status, body: (await response.json()) as Row };
}

const CREATE = {
	action: "create",
	tenant_id: TENANT_A,
	rule_id: "CLT-CMD-011",
	subject_kind: "agent",
	subject_value: AGENT_A,
	expires_at: new Date(T0 + 7 * 86_400_000).toISOString(),
	reason: "release scripts",
};

describe("detection-exceptions handler", () => {
	it("creates an exception for an owner/admin with AAL2, as the session user, and audits it", async () => {
		const world = new World();
		const created = await call(world, `session-${ADMIN_A}`, CREATE);
		expect(created.status).toBe(200);
		expect(created.body.ok).toBe(true);
		const rpc = world.rpcCalls.find((c) => c.name === "create_detection_exception");
		expect(rpc?.args.p_actor_user_id).toBe(ADMIN_A);
		expect(rpc?.args.p_tenant_id).toBe(TENANT_A);
		expect(world.audit.map((a) => a.action)).toEqual(["detection_exception.created"]);

		const listed = await call(world, `session-${OWNER_A}`, { action: "list", tenant_id: TENANT_A });
		expect(listed.status).toBe(200);
		expect((listed.body.exceptions as Row[]).map((e) => e.rule_id)).toEqual(["CLT-CMD-011"]);

		const id = created.body.exception_id as string;
		const revoked = await call(world, `session-${OWNER_A}`, { action: "revoke", tenant_id: TENANT_A, exception_id: id, reason: "done" });
		expect(revoked.status).toBe(200);
		const again = await call(world, `session-${OWNER_A}`, { action: "revoke", tenant_id: TENANT_A, exception_id: id, reason: "done" });
		expect(again).toEqual({ status: 409, body: { error: "detection_exception_not_active" } });
	});

	it("requires a session, owner/admin role, AAL2 and an active membership", async () => {
		const world = new World();
		expect((await call(world, null, CREATE)).status).toBe(401);
		expect((await call(world, "bogus", CREATE)).status).toBe(401);
		expect(await call(world, `session-${MEMBER_A}`, CREATE)).toEqual({
			status: 403, body: { error: "detection_exception_role_insufficient" },
		});
		expect(await call(world, `aal1-${OWNER_A}`, CREATE)).toEqual({ status: 403, body: { error: "mfa_required" } });
		expect(await call(world, `aal1-${OWNER_A}`, { action: "list", tenant_id: TENANT_A })).toEqual({
			status: 403, body: { error: "mfa_required" },
		});
		// Another tenant's owner cannot act on tenant A.
		expect((await call(world, `session-${OWNER_B}`, CREATE)).status).toBe(403);
		expect(world.rpcCalls.filter((c) => c.name !== "consume_tenant_rate_limit")).toEqual([]);
	});

	it("refuses self-defense rules, unbounded expiries and malformed input before any RPC", async () => {
		const world = new World();
		const cases: Array<[Row, string]> = [
			[{ ...CREATE, rule_id: "CLT-SELF-007" }, "protected_rule"],
			[{ ...CREATE, rule_id: "clt-canary-001" }, "protected_rule"],
			[{ ...CREATE, expires_at: new Date(T0 + 31 * 86_400_000).toISOString() }, "invalid_expires_at"],
			[{ ...CREATE, expires_at: new Date(T0 + 60_000).toISOString() }, "invalid_expires_at"],
			[{ ...CREATE, expires_at: undefined }, "invalid_request"],
			[{ ...CREATE, subject_kind: "tenant" }, "invalid_subject"],
			[{ ...CREATE, subject_value: "not-a-uuid" }, "invalid_subject"],
			[{ ...CREATE, artifact_sha256: "abc" }, "invalid_artifact_sha256"],
			[{ ...CREATE, reason: " " }, "invalid_reason"],
			[{ ...CREATE, extra: true }, "invalid_request"],
			[{ ...CREATE, action: "approve" }, "invalid_action"],
		];
		for (const [body, error] of cases) {
			expect(await call(world, `session-${OWNER_A}`, body), JSON.stringify(body)).toEqual({ status: 400, body: { error } });
		}
		expect(world.rpcCalls).toEqual([]);
	});

	it("maps rate limiting and storage failures to closed answers", async () => {
		expect((await call(new World({ rateDenied: true }), `session-${OWNER_A}`, CREATE)).status).toBe(429);
		expect(await call(new World({ failTables: ["detection_exceptions"] }), `session-${OWNER_A}`, { action: "list", tenant_id: TENANT_A }))
			.toEqual({ status: 503, body: { error: "detection_exceptions_unavailable" } });
		expect((await call(new World({ failTables: ["tenant_members"] }), `session-${OWNER_A}`, CREATE)).status).toBe(503);
	});

	it("has no API-key (agent) path: only the user-session identity barrier", () => {
		expect(HANDLER_SOURCE).toContain("checkIdentityBarrier(db, token, userId, tenantId)");
		expect(HANDLER_SOURCE).not.toContain("authenticateTenantApiKey");
		expect(HANDLER_SOURCE).toContain('assurance.currentLevel !== "aal2"');
		expect(served).toHaveLength(1);
	});
});

describe("shared detection-exception rules", () => {
	it("protects self-defense and canary rules", () => {
		expect(isProtectedRuleId("CLT-SELF-001")).toBe(true);
		expect(isProtectedRuleId("clt-canary-002")).toBe(true);
		expect(isProtectedRuleId("CLT-CMD-011")).toBe(false);
	});

	it("parses only bounded, exact requests", () => {
		expect(parseDetectionExceptionRequest({ ...CREATE, subject_kind: "repo", subject_value: "github.com/acme/app" }, T0).ok).toBe(true);
		expect(parseDetectionExceptionRequest({ ...CREATE, tenant_id: "x" }, T0)).toEqual({ ok: false, error: "invalid_tenant_id" });
	});

	it("validates the per-principal feed strictly and sorts it", () => {
		const row = {
			id: "bbbbbbbb-0000-4000-8000-000000000002",
			rule_id: "CLT-CMD-011",
			artifact_sha256: null,
			subject_kind: "repo",
			subject_value: "github.com/acme/app",
			created_at: "2026-10-01T00:00:00+00:00",
			expires_at: "2026-10-08T00:00:00+00:00",
			created_by: OWNER_A,
			reason: "r",
		};
		const other = { ...row, id: "bbbbbbbb-0000-4000-8000-000000000001" };
		const feed = validateDetectionExceptionFeed({ exceptions: [row, other], changed_at: "2026-10-01T00:00:00+00:00" });
		expect(feed?.exceptions.map((e) => e.id)).toEqual([other.id, row.id]);
		expect(feed?.exceptions[0]?.created_at).toBe("2026-10-01T00:00:00.000Z");
		expect(feed?.changedAt).toBe("2026-10-01T00:00:00.000Z");
		expect(validateDetectionExceptionFeed({ exceptions: [{ ...row, rule_id: "CLT-SELF-008" }], changed_at: null })).toBeNull();
		expect(validateDetectionExceptionFeed({ exceptions: [{ ...row, expires_at: "2026-11-15T00:00:00+00:00" }], changed_at: null })).toBeNull();
		expect(validateDetectionExceptionFeed({ exceptions: [], changed_at: "garbage" })).toBeNull();
		expect(validateDetectionExceptionFeed(null)).toBeNull();
	});
});
