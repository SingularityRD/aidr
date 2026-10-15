// Contract suite for the `incidents` Edge Function (incident triage, E1).
//
// The real handler runs against an in-memory service-role double whose RPC
// mirrors the SQL contract of 20261014000100_incident_triage.sql (the SQL
// itself runs on real PostgreSQL in scripts/incident-triage-postgres.test.mjs).
// Covers: every member may read, only owner/admin at AAL2 may change triage,
// the actor is always the session user, cross-tenant isolation, request
// validation (closing needs a note, bounded snooze), error mapping, and that
// there is no API-key (agent) path.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through IncidentsDeps.client");
	},
}));

const served: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => served.push(handler),
};

const { createIncidentsHandler } = await import("../incidents/index.ts");
const { parseIncidentTriageRequest, incidentTriageErrorCode, incidentTriageRpcStatus } = await import(
	"../_shared/incident-triage.ts"
);

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const HANDLER_SOURCE = readFileSync(join(ROOT, "supabase", "functions", "incidents", "index.ts"), "utf8");

const TENANT_A = "22222222-2222-4222-8222-222222222222";
const TENANT_B = "99999999-9999-4999-8999-999999999999";
const OWNER_A = "11111111-1111-4111-8111-111111111111";
const ADMIN_A = "12121212-1212-4121-8121-121212121212";
const MEMBER_A = "13131313-1313-4131-8131-131313131313";
const VIEWER_A = "14141414-1414-4141-8141-141414141414";
const OWNER_B = "15151515-1515-4151-8151-151515151515";
const T0 = Date.parse("2026-10-14T10:00:00.000Z");
const URL_BASE = "https://project.supabase.co/functions/v1/incidents";
const ENV = { SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "service-role" } as Record<string, string>;

type Row = Record<string, unknown>;

class World {
	readonly members: Row[] = [];
	readonly tenants: Row[] = [
		{ id: TENANT_A, status: "active" },
		{ id: TENANT_B, status: "active" },
	];
	readonly events: Row[] = [
		{ id: 101, tenant_id: TENANT_A, type: "runtime_verdict", verdict: "deny" },
		{ id: 102, tenant_id: TENANT_A, type: "runtime_verdict", verdict: "allow" },
		{ id: 201, tenant_id: TENANT_B, type: "runtime_verdict", verdict: "deny" },
	];
	readonly triage: Row[] = [];
	readonly history: Row[] = [];
	readonly audit: string[] = [];
	readonly rpcCalls: Array<{ name: string; args: Row }> = [];
	readonly sessions = new Map<string, { user: string; aal: "aal1" | "aal2" }>();

	constructor(private readonly options: { rateDenied?: boolean; failTables?: string[] } = {}) {
		for (const [tenant, user, role] of [
			[TENANT_A, OWNER_A, "owner"], [TENANT_A, ADMIN_A, "admin"], [TENANT_A, MEMBER_A, "member"],
			[TENANT_A, VIEWER_A, "viewer"], [TENANT_B, OWNER_B, "owner"],
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
			case "incident_triage": return this.triage;
			case "incident_triage_history": return this.history;
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
		switch (name) {
			case "consume_tenant_rate_limit":
				return this.options.rateDenied ? { allowed: false, remaining: 0 } : { allowed: true, remaining: 10 };
			case "update_incident_triage": {
				const role = this.members.find((m) => m.tenant_id === a.p_tenant_id && m.user_id === a.p_actor_user_id)?.role;
				if (role !== "owner" && role !== "admin") fail("42501", "incident_triage_forbidden");
				const event = this.events.find((e) => e.id === a.p_event_id && e.tenant_id === a.p_tenant_id);
				if (!event || (event.type === "runtime_verdict" && event.verdict === "allow")) fail("P0002", "incident_not_found");
				const existing = this.triage.find((t) => t.event_id === a.p_event_id);
				if (Number(existing?.version ?? 0) !== a.p_expected_version) fail("40001", "incident_triage_conflict");
				const fields = a.p_fields as Row;
				const owner = fields.owner_user_id;
				if (owner && !this.members.some((m) => m.tenant_id === a.p_tenant_id && m.user_id === owner && m.role !== "viewer")) {
					fail("22023", "incident_owner_not_member");
				}
				const version = Number(existing?.version ?? 0) + 1;
				const row = { event_id: a.p_event_id, tenant_id: a.p_tenant_id, ...fields, version, updated_by: a.p_actor_user_id };
				if (existing) Object.assign(existing, row);
				else this.triage.push(row);
				this.history.push({ tenant_id: a.p_tenant_id, event_id: a.p_event_id, to_status: fields.status, version });
				this.audit.push("incident.triaged");
				return row;
			}
			default:
				throw new Error(`unexpected rpc ${name}`);
		}
	}
}

async function call(world: World, token: string | null, body: unknown) {
	const response = await createIncidentsHandler({ env: (name) => ENV[name], client: () => world.db() as never, now: () => T0 })(
		new Request(URL_BASE, {
			method: "POST",
			headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
			body: JSON.stringify(body),
		}),
	);
	return { status: response.status, body: (await response.json()) as Row };
}

const ACK = {
	action: "update",
	tenant_id: TENANT_A,
	event_id: 101,
	expected_version: 0,
	status: "acknowledged",
	owner_user_id: MEMBER_A,
};

describe("incidents handler", () => {
	it("lets an owner/admin at AAL2 triage, assign and close, as the session user, with history", async () => {
		const world = new World();
		const acknowledged = await call(world, `session-${ADMIN_A}`, ACK);
		expect(acknowledged.status).toBe(200);
		expect((acknowledged.body.triage as Row).version).toBe(1);
		const rpc = world.rpcCalls.find((c) => c.name === "update_incident_triage");
		expect(rpc?.args).toMatchObject({
			p_tenant_id: TENANT_A,
			p_actor_user_id: ADMIN_A,
			p_event_id: 101,
			p_expected_version: 0,
			p_fields: { status: "acknowledged", owner_user_id: MEMBER_A, resolution_note: null, snoozed_until: null },
		});

		const closed = await call(world, `session-${OWNER_A}`, {
			...ACK, expected_version: 1, status: "false_positive", resolution_note: "Release script, reviewed",
		});
		expect(closed.status).toBe(200);
		// A stale version is a conflict, not a silent overwrite.
		expect(await call(world, `session-${OWNER_A}`, { ...ACK, expected_version: 1, status: "open" })).toEqual({
			status: 409, body: { error: "incident_triage_conflict" },
		});
		expect(world.audit).toEqual(["incident.triaged", "incident.triaged"]);

		const history = await call(world, `session-${VIEWER_A}`, { action: "history", tenant_id: TENANT_A, event_id: 101 });
		expect(history.status).toBe(200);
		expect((history.body.history as Row[]).map((h) => h.to_status)).toEqual(["acknowledged", "false_positive"]);
	});

	it("lets every active member read, and tells the page whether this role may triage", async () => {
		const world = new World();
		await call(world, `session-${OWNER_A}`, ACK);
		for (const [user, canTriage] of [[OWNER_A, true], [MEMBER_A, false], [VIEWER_A, false]] as const) {
			const listed = await call(world, `aal1-${user}`, { action: "list", tenant_id: TENANT_A });
			expect(listed.status, user).toBe(200);
			expect(listed.body.can_triage).toBe(canTriage);
			expect((listed.body.triage as Row[]).map((t) => t.event_id)).toEqual([101]);
		}
		// Tenant B's owner sees nothing of tenant A.
		expect(await call(world, `session-${OWNER_B}`, { action: "list", tenant_id: TENANT_A })).toEqual({
			status: 403, body: { error: "workspace_forbidden" },
		});
	});

	it("refuses changes from members, viewers, AAL1 sessions and other tenants before the RPC", async () => {
		const world = new World();
		expect((await call(world, null, ACK)).status).toBe(401);
		expect((await call(world, "bogus", ACK)).status).toBe(401);
		for (const user of [MEMBER_A, VIEWER_A]) {
			expect(await call(world, `session-${user}`, ACK)).toEqual({ status: 403, body: { error: "incident_role_insufficient" } });
		}
		expect(await call(world, `aal1-${OWNER_A}`, ACK)).toEqual({ status: 403, body: { error: "mfa_required" } });
		expect((await call(world, `session-${OWNER_B}`, ACK)).status).toBe(403);
		expect(world.rpcCalls.filter((c) => c.name === "update_incident_triage")).toEqual([]);
	});

	it("maps database refusals: another tenant's event, a non-incident, an outsider owner", async () => {
		const world = new World();
		expect(await call(world, `session-${OWNER_A}`, { ...ACK, event_id: 201 })).toEqual({
			status: 404, body: { error: "incident_not_found" },
		});
		expect(await call(world, `session-${OWNER_A}`, { ...ACK, event_id: 102 })).toEqual({
			status: 404, body: { error: "incident_not_found" },
		});
		expect(await call(world, `session-${OWNER_A}`, { ...ACK, owner_user_id: OWNER_B })).toEqual({
			status: 400, body: { error: "incident_owner_not_member" },
		});
		expect(await call(world, `session-${OWNER_A}`, { ...ACK, owner_user_id: VIEWER_A })).toEqual({
			status: 400, body: { error: "incident_owner_not_member" },
		});
	});

	it("validates requests before any database access", async () => {
		const world = new World();
		const cases: Array<[Row, string]> = [
			[{ ...ACK, status: "resolved" }, "incident_resolution_note_required"],
			[{ ...ACK, status: "false_positive", resolution_note: "   " }, "incident_resolution_note_required"],
			[{ ...ACK, status: "closed" }, "invalid_status"],
			[{ ...ACK, event_id: -1 }, "invalid_event_id"],
			[{ ...ACK, event_id: "1e3" }, "invalid_event_id"],
			[{ ...ACK, expected_version: 1.5 }, "invalid_expected_version"],
			[{ ...ACK, owner_user_id: "someone" }, "invalid_owner"],
			[{ ...ACK, resolution_note: "x".repeat(1001) }, "invalid_resolution_note"],
			[{ ...ACK, resolution_note: "bell\u0007" }, "invalid_resolution_note"],
			[{ ...ACK, snoozed_until: new Date(T0 + 31 * 86_400_000).toISOString() }, "invalid_snoozed_until"],
			[{ ...ACK, snoozed_until: new Date(T0 + 60_000).toISOString() }, "invalid_snoozed_until"],
			[{ ...ACK, status: "resolved", resolution_note: "done", snoozed_until: new Date(T0 + 86_400_000).toISOString() }, "incident_snooze_closed"],
			[{ ...ACK, agent_callable: true }, "invalid_request"],
			[{ ...ACK, action: "delete" }, "invalid_action"],
			[{ ...ACK, tenant_id: "x" }, "invalid_tenant_id"],
		];
		for (const [body, error] of cases) {
			expect(await call(world, `session-${OWNER_A}`, body), JSON.stringify(body)).toEqual({ status: 400, body: { error } });
		}
		expect(world.rpcCalls).toEqual([]);
	});

	it("maps rate limiting and storage failures to closed answers", async () => {
		expect((await call(new World({ rateDenied: true }), `session-${OWNER_A}`, ACK)).status).toBe(429);
		expect(await call(new World({ failTables: ["incident_triage"] }), `session-${OWNER_A}`, { action: "list", tenant_id: TENANT_A }))
			.toEqual({ status: 503, body: { error: "incidents_unavailable" } });
		expect((await call(new World({ failTables: ["tenant_members"] }), `session-${OWNER_A}`, ACK)).status).toBe(503);
	});

	it("has no API-key (agent) path and never touches enforcement", () => {
		expect(HANDLER_SOURCE).toContain("checkIdentityBarrier(db, token, userId, tenantId)");
		expect(HANDLER_SOURCE).not.toContain("authenticateTenantApiKey");
		expect(HANDLER_SOURCE).toContain('assurance.currentLevel !== "aal2"');
		expect(HANDLER_SOURCE).not.toMatch(/detection_exception|runtime_polic/);
		expect(served).toHaveLength(1);
	});
});

describe("incident triage request rules", () => {
	it("accepts a bounded snooze on an open incident and normalizes it", () => {
		const parsed = parseIncidentTriageRequest(
			{ ...ACK, status: "open", snoozed_until: "2026-10-15T10:00:00+03:00" },
			T0,
		);
		expect(parsed).toMatchObject({ ok: true, command: { fields: { snoozed_until: "2026-10-15T07:00:00.000Z" } } });
	});

	it("maps only known RPC errors and their SQLSTATEs", () => {
		expect(incidentTriageErrorCode("incident_triage_conflict")).toBe("incident_triage_conflict");
		expect(incidentTriageErrorCode("invalid_incident_triage:status")).toBe("invalid_incident_triage");
		expect(incidentTriageErrorCode("permission denied for table events")).toBeNull();
		expect([incidentTriageRpcStatus("42501"), incidentTriageRpcStatus("P0002"), incidentTriageRpcStatus("40001"),
			incidentTriageRpcStatus("22023"), incidentTriageRpcStatus("XX000")]).toEqual([403, 404, 409, 400, 503]);
	});
});
