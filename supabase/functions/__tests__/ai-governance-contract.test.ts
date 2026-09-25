// Contract suite for the `ai-governance` Edge Function (docs/ai-governance.md).
//
// The real handler runs against an in-memory service-role double whose RPCs
// mirror the SQL contract of 20260927000040_ai_governance_register.sql and
// 20260927000041_policy_change_control.sql (the SQL itself runs against
// PostgreSQL in scripts/ai-governance-postgres.test.mjs). The suite covers
// session and identity-barrier gating, roles, AAL2, cross-tenant isolation,
// the actor always being the session user, four-eyes (no self-approval),
// designated reviewers, exception expiry in the enforcement feed, policy
// change detail/diff access and error mapping.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({
	createClient: vi.fn((): unknown => {
		throw new Error("createClient must be injected through AiGovernanceDeps.client");
	}),
}));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const served: unknown[] = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: unknown) => served.push(handler),
};

const { createAiGovernanceHandler } = await import("../ai-governance/index.ts");
const { GOVERNANCE_ACTIONS, parseGovernanceRequest } = await import("../_shared/ai-governance.ts");

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (...parts: string[]) => readFileSync(join(ROOT, ...parts), "utf8");
const REGISTER_SQL = read("supabase", "migrations", "20260927000040_ai_governance_register.sql");
const CHANGE_SQL = read("supabase", "migrations", "20260927000041_policy_change_control.sql");
const HANDLER_SOURCE = read("supabase", "functions", "ai-governance", "index.ts");

const TENANT_A = "22222222-2222-4222-8222-222222222222";
const TENANT_B = "99999999-9999-4999-8999-999999999999";
const OWNER_A = "11111111-1111-4111-8111-111111111111";
const ADMIN_A = "12121212-1212-4121-8121-121212121212";
const MEMBER_A = "13131313-1313-4131-8131-131313131313";
const REVIEWER_A = "16161616-1616-4161-8161-161616161616";
const VIEWER_A = "14141414-1414-4141-8141-141414141414";
const OWNER_B = "15151515-1515-4151-8151-151515151515";
const AGENT_A = "33333333-3333-4333-8333-333333333333";
const T0 = Date.parse("2026-09-27T10:00:00.000Z");
const URL_BASE = "https://project.supabase.co/functions/v1/ai-governance";
const ENV = { SUPABASE_URL: "https://project.supabase.co", SUPABASE_SERVICE_ROLE_KEY: "service-role" } as Record<string, string>;

type Row = Record<string, unknown>;
type RpcError = { code: string; message: string };

interface WorldOptions {
	identityPolicy?: { require_mfa: boolean; required_saml_provider_id: string | null };
	rateDenied?: boolean;
	failTables?: string[];
}

/** In-memory control plane mirroring the governance RPC contract. */
class World {
	clock = T0;
	readonly members: Row[] = [];
	readonly tenants: Row[] = [
		{ id: TENANT_A, status: "active" },
		{ id: TENANT_B, status: "active" },
	];
	readonly assets: Row[] = [];
	readonly intake: Row[] = [];
	readonly exceptions: Row[] = [];
	readonly changes: Row[] = [];
	readonly reviewers: Row[] = [{ tenant_id: TENANT_A, user_id: REVIEWER_A }];
	readonly settings: Row[] = [];
	readonly runtime: Row[] = [{ tenant_id: TENANT_A, version: 3, policy: { command_default: "ask" } }];
	readonly dlp: Row[] = [];
	readonly audit: Array<{ tenant: string; actor: string | null; action: string }> = [];
	readonly rpcCalls: Array<{ name: string; args: Row }> = [];
	readonly sessions = new Map<string, { user: string; aal: "aal1" | "aal2" }>();
	private seq = 0;

	constructor(private readonly options: WorldOptions = {}) {
		for (const [tenant, user, role] of [
			[TENANT_A, OWNER_A, "owner"], [TENANT_A, ADMIN_A, "admin"], [TENANT_A, MEMBER_A, "member"],
			[TENANT_A, REVIEWER_A, "member"], [TENANT_A, VIEWER_A, "viewer"], [TENANT_B, OWNER_B, "owner"],
		]) {
			this.members.push({ tenant_id: tenant, user_id: user, role, expires_at: null });
			this.sessions.set(`session-${user}`, { user, aal: "aal2" });
			this.sessions.set(`aal1-${user}`, { user, aal: "aal1" });
		}
	}

	private id(): string {
		this.seq += 1;
		return `aaaaaaaa-0000-4000-8000-${String(this.seq).padStart(12, "0")}`;
	}

	private role(tenant: unknown, user: unknown): string | null {
		if (!this.tenants.some((t) => t.id === tenant && t.status === "active")) return null;
		return (this.members.find((m) => m.tenant_id === tenant && m.user_id === user)?.role as string) ?? null;
	}

	private reviewer(tenant: unknown, user: unknown): boolean {
		return this.role(tenant, user) === "member" && this.reviewers.some((r) => r.tenant_id === tenant && r.user_id === user);
	}

	private fourEyes(tenant: unknown): boolean {
		return this.settings.some((s) => s.tenant_id === tenant && s.policy_four_eyes === true);
	}

	private table(name: string): Row[] {
		switch (name) {
			case "tenant_members": return this.members;
			case "tenants": return this.tenants;
			case "policy_change_requests": return this.changes;
			case "tenant_runtime_policies": return this.runtime;
			case "tenant_dlp_policies": return this.dlp;
			case "identity_user_session_state": return [];
			case "tenant_identity_policies":
				return this.options.identityPolicy ? [{ tenant_id: TENANT_A, ...this.options.identityPolicy }] : [];
			default: throw new Error(`unexpected table ${name}`);
		}
	}

	db() {
		const world = this;
		return {
			auth: {
				getUser: vi.fn(async (token: string) => {
					const session = world.sessions.get(token);
					return session
						? { data: { user: { id: session.user } }, error: null }
						: { data: { user: null }, error: new Error("invalid") };
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
					return { data: null, error: error as RpcError };
				}
			}),
		};
	}

	/** Seed helpers used by the tests (as a service-role migration would). */
	addAsset(row: Row): Row {
		const asset = { id: this.id(), tenant_id: TENANT_A, status: "proposed", risk_tier: "unassessed", version: 1, ...row };
		this.assets.push(asset);
		return asset;
	}

	private rpc(name: string, a: Row): unknown {
		const fail = (code: string, message: string): never => { throw { code, message }; };
		const now = this.clock;
		const actorRole = this.role(a.p_tenant_id, a.p_actor_user_id);
		const ownerAdmin = actorRole === "owner" || actorRole === "admin";
		switch (name) {
			case "consume_tenant_rate_limit":
				return this.options.rateDenied ? { allowed: false, remaining: 0 } : { allowed: true, remaining: 10 };
			case "ai_governance_policy_overlay": {
				const waived = new Set(this.exceptions.filter((e) => e.tenant_id === a.p_tenant_id && e.status === "approved" &&
					Date.parse(String(e.starts_at)) <= now && Date.parse(String(e.expires_at)) > now &&
					(e.scope_kind === "tenant" ||
						(e.scope_kind === "members" && (e.scope_user_ids as string[]).includes(String(a.p_user_id))) ||
						(e.scope_kind === "agents" && (e.scope_agent_ids as string[]).includes(String(a.p_agent_id)))))
					.map((e) => e.asset_id));
				const effective = this.assets.filter((x) => x.tenant_id === a.p_tenant_id && !waived.has(x.id));
				const pick = (type: string, status: string) =>
					effective.filter((x) => x.asset_type === type && x.status === status).map((x) => String(x.identifier)).sort();
				return {
					mcp_deny_servers: pick("mcp_server", "banned"),
					mcp_require_approval_servers: pick("mcp_server", "restricted"),
					browser_guard_blocked_sites: pick("ai_site", "banned").filter((s) => ["chatgpt", "deepseek", "gemini"].includes(s)),
				};
			}
			case "upsert_ai_asset": {
				if (!ownerAdmin) fail("42501", "ai_governance_forbidden");
				const fields = a.p_fields as Row;
				if (a.p_asset_id === null) {
					if (this.assets.some((x) => x.tenant_id === a.p_tenant_id && x.asset_type === fields.asset_type && x.identifier === fields.identifier)) {
						fail("23505", "ai_asset_exists");
					}
					const asset = this.addAsset({ tenant_id: a.p_tenant_id, ...fields });
					this.audit.push({ tenant: String(a.p_tenant_id), actor: String(a.p_actor_user_id), action: "ai_asset.created" });
					return { asset_id: asset.id, version: 1, status: asset.status, created: true, changed: [] };
				}
				const asset = this.assets.find((x) => x.id === a.p_asset_id && x.tenant_id === a.p_tenant_id) ?? fail("P0002", "ai_asset_not_found");
				if (asset.version !== a.p_expected_version) fail("PT409", "ai_asset_version_conflict");
				const rank = (s: unknown) => (s === "banned" ? 2 : s === "restricted" ? 1 : 0);
				if (this.fourEyes(a.p_tenant_id) && fields.status !== undefined && rank(fields.status) < rank(asset.status)) {
					fail("42501", "governance_four_eyes_required");
				}
				Object.assign(asset, fields, { version: Number(asset.version) + 1 });
				return { asset_id: asset.id, version: asset.version, status: asset.status, created: false, changed: Object.keys(fields) };
			}
			case "import_ai_asset_candidates":
				if (!ownerAdmin) fail("42501", "ai_governance_forbidden");
				return { created: 0, refreshed: 0, skipped: 0, created_by_source: {} };
			case "review_ai_asset": {
				if (!ownerAdmin && !this.reviewer(a.p_tenant_id, a.p_actor_user_id)) fail("42501", "ai_governance_forbidden");
				const asset = this.assets.find((x) => x.id === a.p_asset_id && x.tenant_id === a.p_tenant_id) ?? fail("P0002", "ai_asset_not_found");
				asset.last_reviewed_by = a.p_actor_user_id;
				return { asset_id: asset.id, version: asset.version, review_due_at: a.p_next_review_due ?? "2027-03-26" };
			}
			case "submit_ai_intake_request": {
				if (!["owner", "admin", "member"].includes(String(actorRole))) fail("42501", "ai_governance_forbidden");
				const row = { id: this.id(), tenant_id: a.p_tenant_id, status: "pending", requested_by: a.p_actor_user_id,
					expires_at: new Date(now + 90 * 86_400_000).toISOString(), ...(a.p_fields as Row) };
				this.intake.push(row);
				return { request_id: row.id, status: "pending", asset_id: null, expires_at: row.expires_at };
			}
			case "decide_ai_intake_request": {
				if (!ownerAdmin && !this.reviewer(a.p_tenant_id, a.p_actor_user_id)) fail("42501", "ai_governance_forbidden");
				const row = this.intake.find((r) => r.id === a.p_request_id && r.tenant_id === a.p_tenant_id) ?? fail("P0002", "ai_intake_request_not_found");
				if (row.status !== "pending") return { outcome: "already_final", request_id: row.id, status: row.status };
				if (Date.parse(String(row.expires_at)) <= now) {
					row.status = "expired";
					return { outcome: "expired", request_id: row.id, status: "expired" };
				}
				if (row.requested_by === a.p_actor_user_id) fail("42501", "four_eyes_self_approval");
				row.status = a.p_decision === "approve" ? "approved" : "rejected";
				row.decided_by = a.p_actor_user_id;
				let assetId: unknown = null;
				if (row.status === "approved") {
					assetId = this.addAsset({ tenant_id: a.p_tenant_id, asset_type: row.asset_type, identifier: row.identifier,
						status: row.requested_status ?? "approved" }).id;
				}
				return { outcome: "decided", request_id: row.id, status: row.status, ...(assetId ? { asset_id: assetId } : {}) };
			}
			case "request_ai_governance_exception": {
				if (!["owner", "admin", "member"].includes(String(actorRole))) fail("42501", "ai_governance_forbidden");
				const fields = a.p_fields as Row;
				const asset = this.assets.find((x) => x.id === fields.asset_id && x.tenant_id === a.p_tenant_id) ?? fail("P0002", "ai_asset_not_found");
				if (!["banned", "restricted"].includes(String(asset.status))) fail("55000", "ai_governance_exception_not_restricted");
				const row = { id: this.id(), tenant_id: a.p_tenant_id, asset_id: asset.id, status: "pending", requested_by: a.p_actor_user_id,
					scope_kind: fields.scope_kind ?? "tenant", scope_user_ids: fields.scope_user_ids ?? [], scope_agent_ids: fields.scope_agent_ids ?? [],
					expires_at: fields.expires_at, starts_at: null };
				this.exceptions.push(row);
				return { exception_id: row.id, status: "pending", expires_at: row.expires_at };
			}
			case "decide_ai_governance_exception": {
				if (!ownerAdmin) fail("42501", "ai_governance_forbidden");
				const row = this.exceptions.find((r) => r.id === a.p_exception_id && r.tenant_id === a.p_tenant_id) ?? fail("P0002", "ai_governance_exception_not_found");
				if (row.status !== "pending") return { outcome: "already_final", exception_id: row.id, status: row.status };
				if (Date.parse(String(row.expires_at)) <= now) {
					row.status = "expired";
					return { outcome: "expired", exception_id: row.id, status: "expired" };
				}
				if (row.requested_by === a.p_actor_user_id) fail("42501", "four_eyes_self_approval");
				row.status = a.p_decision === "approve" ? "approved" : "rejected";
				row.starts_at = row.status === "approved" ? new Date(now).toISOString() : null;
				return { outcome: "decided", exception_id: row.id, status: row.status, expires_at: row.expires_at };
			}
			case "revoke_ai_governance_exception": {
				if (!ownerAdmin) fail("42501", "ai_governance_forbidden");
				const row = this.exceptions.find((r) => r.id === a.p_exception_id && r.tenant_id === a.p_tenant_id) ?? fail("P0002", "ai_governance_exception_not_found");
				if (row.status !== "approved" || Date.parse(String(row.expires_at)) <= now) {
					return { outcome: "not_active", exception_id: row.id, status: row.status === "approved" ? "expired" : row.status };
				}
				row.status = "revoked";
				return { outcome: "revoked", exception_id: row.id, status: "revoked" };
			}
			case "update_ai_governance_settings": {
				if (!ownerAdmin) fail("42501", "ai_governance_forbidden");
				let settings = this.settings.find((s) => s.tenant_id === a.p_tenant_id);
				if (!settings) {
					settings = { tenant_id: a.p_tenant_id, policy_four_eyes: false, default_review_days: 180 };
					this.settings.push(settings);
				}
				if (a.p_policy_four_eyes === true) settings.policy_four_eyes = true;
				if (a.p_policy_four_eyes === false && settings.policy_four_eyes) {
					const change = { id: this.id(), tenant_id: a.p_tenant_id, change_kind: "disable_four_eyes", status: "pending",
						requested_by: a.p_actor_user_id, base_version: 0, payload: {} };
					this.changes.push(change);
					return { policy_four_eyes: true, default_review_days: settings.default_review_days, pending_disable_request_id: change.id };
				}
				return { policy_four_eyes: settings.policy_four_eyes, default_review_days: settings.default_review_days, pending_disable_request_id: null };
			}
			case "decide_policy_change_request": {
				if (!ownerAdmin) fail("42501", "policy_forbidden");
				const row = this.changes.find((r) => r.id === a.p_request_id && r.tenant_id === a.p_tenant_id) ?? fail("P0002", "policy_change_request_not_found");
				if (row.status !== "pending") return { outcome: "already_final", request_id: row.id, status: row.status };
				if (row.requested_by === a.p_actor_user_id) fail("42501", "four_eyes_self_approval");
				if (a.p_decision === "reject") {
					row.status = "rejected";
					return { outcome: "decided", request_id: row.id, status: "rejected" };
				}
				const current = this.runtime.find((r) => r.tenant_id === a.p_tenant_id);
				if (row.change_kind === "runtime_publish" && Number(current?.version ?? 0) !== row.base_version) {
					row.status = "superseded";
					return { outcome: "superseded", request_id: row.id, status: "superseded", outcome_code: "policy_version_conflict" };
				}
				row.status = "approved";
				if (current && row.change_kind === "runtime_publish") {
					current.version = Number(current.version) + 1;
					current.policy = (row.payload as Row).policy;
				}
				return { outcome: "decided", request_id: row.id, status: "approved", change_kind: row.change_kind,
					applied_version: current?.version ?? null };
			}
			case "cancel_ai_governance_request":
			case "link_ai_asset_evidence":
			case "set_ai_governance_reviewer":
				if (!ownerAdmin && name !== "cancel_ai_governance_request") fail("42501", "ai_governance_forbidden");
				return { outcome: "cancelled", request_id: a.p_request_id ?? null, linked: true, designated: a.p_designated ?? null };
			default:
				throw new Error(`unexpected rpc ${name}`);
		}
	}
}

function setup(options: WorldOptions = {}) {
	const world = new World(options);
	const db = world.db();
	const handler = createAiGovernanceHandler({
		env: (name) => ENV[name],
		client: () => db as never,
		now: () => world.clock,
	});
	const call = async (body: Row, token: string | null = `session-${OWNER_A}`, method = "POST") => {
		const response = await handler(new Request(URL_BASE, {
			method,
			headers: {
				"Content-Type": "application/json",
				...(token ? { Authorization: `Bearer ${token}` } : {}),
			},
			...(method === "POST" ? { body: JSON.stringify(body) } : {}),
		}));
		return { status: response.status, body: (await response.json()) as Row };
	};
	return { world, db, call };
}

const privileged = (world: World) => world.rpcCalls.filter((c) => c.name !== "consume_tenant_rate_limit");

describe("ai-governance: request gating", () => {
	it("registers one Edge handler", () => {
		expect(served).toHaveLength(1);
	});

	it("refuses other methods, a missing session and malformed bodies before any privileged access", async () => {
		const { world, db, call } = setup();
		expect((await call({}, null, "GET")).status).toBe(405);
		expect(await call({ action: "enforcement_preview", tenant_id: TENANT_A }, null)).toEqual({
			status: 401, body: { error: "missing_access_token" },
		});
		expect((await call({ action: "nope", tenant_id: TENANT_A })).body).toEqual({ error: "invalid_action" });
		expect((await call({ action: "enforcement_preview", tenant_id: "not-a-uuid" })).body).toEqual({ error: "invalid_tenant" });
		expect((await call({ action: "enforcement_preview", tenant_id: TENANT_A, actor_user_id: MEMBER_A })).status).toBe(400);
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(world.rpcCalls).toEqual([]);
	});

	it("rejects an invalid session and enforces the tenant identity barrier", async () => {
		const { world, call } = setup({ identityPolicy: { require_mfa: true, required_saml_provider_id: null } });
		expect(await call({ action: "enforcement_preview", tenant_id: TENANT_A }, "forged")).toEqual({
			status: 401, body: { error: "invalid_access_token" },
		});
		expect(await call({ action: "enforcement_preview", tenant_id: TENANT_A }, `aal1-${MEMBER_A}`)).toEqual({
			status: 403, body: { error: "mfa_required" },
		});
		expect(privileged(world)).toEqual([]);
	});

	it("never reads or writes another tenant's governance data", async () => {
		const { world, call } = setup();
		for (const body of [
			{ action: "enforcement_preview", tenant_id: TENANT_A },
			{ action: "upsert_asset", tenant_id: TENANT_A, fields: { asset_type: "mcp_server", identifier: "x", name: "X" } },
			{ action: "policy_change_detail", tenant_id: TENANT_A, request_id: "aaaaaaaa-0000-4000-8000-000000000001" },
		]) {
			expect(await call(body, `session-${OWNER_B}`)).toEqual({ status: 403, body: { error: "workspace_forbidden" } });
		}
		expect(privileged(world)).toEqual([]);
	});

	it("applies the per-action role matrix before step-up, rate limit or RPC", async () => {
		const { world, call } = setup();
		const asset = { action: "upsert_asset", tenant_id: TENANT_A, fields: { asset_type: "mcp_server", identifier: "x", name: "X" } };
		expect(await call(asset, `session-${MEMBER_A}`)).toEqual({ status: 403, body: { error: "governance_role_insufficient" } });
		expect(await call({ action: "submit_intake", tenant_id: TENANT_A,
			fields: { asset_type: "ai_site", identifier: "claude", name: "Claude", business_purpose: "Docs" } }, `session-${VIEWER_A}`))
			.toEqual({ status: 403, body: { error: "governance_role_insufficient" } });
		expect((await call({ action: "enforcement_preview", tenant_id: TENANT_A }, `session-${VIEWER_A}`)).status).toBe(200);
		expect(privileged(world).map((c) => c.name)).toEqual(["ai_governance_policy_overlay"]);
		// Every owner/admin-only action in the matrix is refused to members.
		for (const [action, rule] of Object.entries(GOVERNANCE_ACTIONS)) {
			if (!rule.roles.includes("member")) expect(rule.roles, action).toEqual(["owner", "admin"]);
			if (action.startsWith("decide_") || action === "upsert_asset" || action === "update_settings") expect(rule.aal2, action).toBe(true);
		}
	});

	it("requires AAL2 for decisions and register changes, not for filing a request", async () => {
		const { world, call } = setup();
		expect(await call({ action: "upsert_asset", tenant_id: TENANT_A,
			fields: { asset_type: "mcp_server", identifier: "x", name: "X" } }, `aal1-${ADMIN_A}`))
			.toEqual({ status: 403, body: { error: "mfa_required" } });
		expect(privileged(world)).toEqual([]);
		const filed = await call({ action: "submit_intake", tenant_id: TENANT_A,
			fields: { asset_type: "ai_site", identifier: "claude", name: "Claude", business_purpose: "Drafting release notes" } },
			`aal1-${MEMBER_A}`);
		expect(filed.status).toBe(200);
		expect(filed.body).toMatchObject({ ok: true, status: "pending" });
	});

	it("passes the session user as the actor, never a body value", async () => {
		const { world, call } = setup();
		await call({ action: "submit_intake", tenant_id: TENANT_A,
			fields: { asset_type: "mcp_server", identifier: "github", name: "GitHub", business_purpose: "PR reviews" } },
			`session-${MEMBER_A}`);
		const rpc = privileged(world).find((c) => c.name === "submit_ai_intake_request");
		expect(rpc?.args).toMatchObject({ p_tenant_id: TENANT_A, p_actor_user_id: MEMBER_A });
		expect(HANDLER_SOURCE).not.toMatch(/p_actor_user_id:\s*command\./);
	});

	it("fails closed on rate limits, unreadable membership and RPC contract breaches", async () => {
		expect((await setup({ rateDenied: true }).call({ action: "enforcement_preview", tenant_id: TENANT_A })).status).toBe(429);
		expect((await setup({ failTables: ["tenant_members"] }).call({ action: "enforcement_preview", tenant_id: TENANT_A })).body)
			.toEqual({ error: "authorization_unavailable" });
		expect((await setup({ failTables: ["tenant_runtime_policies"] }).call({ action: "enforcement_preview", tenant_id: TENANT_A })).body)
			.toEqual({ error: "governance_unavailable" });
	});
});

describe("ai-governance: register, intake and four-eyes", () => {
	it("maps RPC refusals to stable codes without leaking database messages", async () => {
		const { world, call } = setup();
		const created = await call({ action: "upsert_asset", tenant_id: TENANT_A,
			fields: { asset_type: "mcp_server", identifier: "shell-runner", name: "Shell runner", status: "banned" } });
		expect(created).toMatchObject({ status: 200, body: { ok: true, created: true, status: "banned" } });
		expect(await call({ action: "upsert_asset", tenant_id: TENANT_A,
			fields: { asset_type: "mcp_server", identifier: "shell-runner", name: "Shell runner" } }))
			.toEqual({ status: 409, body: { error: "ai_asset_exists" } });
		expect(await call({ action: "upsert_asset", tenant_id: TENANT_A, asset_id: String(created.body.asset_id),
			expected_version: 7, fields: { name: "Renamed" } })).toEqual({ status: 409, body: { error: "ai_asset_version_conflict" } });
		expect(world.audit.map((e) => e.action)).toEqual(["ai_asset.created"]);
	});

	it("never lets a requester decide their own intake request, and scopes reviewers", async () => {
		const { call } = setup();
		const filed = await call({ action: "submit_intake", tenant_id: TENANT_A,
			fields: { asset_type: "ai_site", identifier: "claude", name: "Claude", business_purpose: "Drafting docs" } },
			`session-${REVIEWER_A}`);
		const decide = (token: string) => call({ action: "decide_intake", tenant_id: TENANT_A,
			request_id: filed.body.request_id, decision: "approve", reason: "Reviewed" }, token);
		expect(await decide(`session-${REVIEWER_A}`)).toEqual({ status: 403, body: { error: "four_eyes_self_approval" } });
		expect(await decide(`session-${MEMBER_A}`)).toEqual({ status: 403, body: { error: "ai_governance_forbidden" } });
		const approved = await decide(`session-${OWNER_A}`);
		expect(approved).toMatchObject({ status: 200, body: { ok: true, status: "approved" } });
		expect(await decide(`session-${ADMIN_A}`)).toEqual({ status: 409, body: { error: "request_final", status: "approved" } });
	});

	it("lets a designated reviewer decide someone else's intake request at AAL2", async () => {
		const { call } = setup();
		const filed = await call({ action: "submit_intake", tenant_id: TENANT_A,
			fields: { asset_type: "mcp_server", identifier: "github", name: "GitHub", business_purpose: "Pull requests" } },
			`session-${MEMBER_A}`);
		const body = { action: "decide_intake", tenant_id: TENANT_A, request_id: filed.body.request_id, decision: "reject", reason: "Use the approved Git MCP" };
		expect(await call(body, `aal1-${REVIEWER_A}`)).toEqual({ status: 403, body: { error: "mfa_required" } });
		expect(await call(body, `session-${REVIEWER_A}`)).toMatchObject({ status: 200, body: { status: "rejected" } });
	});

	it("reports an intake request that lapsed before the decision", async () => {
		const { world, call } = setup();
		const filed = await call({ action: "submit_intake", tenant_id: TENANT_A,
			fields: { asset_type: "ai_site", identifier: "gemini", name: "Gemini", business_purpose: "Research" } }, `session-${MEMBER_A}`);
		world.clock += 91 * 86_400_000;
		expect(await call({ action: "decide_intake", tenant_id: TENANT_A, request_id: filed.body.request_id,
			decision: "approve", reason: "Late" })).toEqual({ status: 409, body: { error: "request_expired", status: "expired" } });
	});

	it("refuses a direct relaxation of an enforced ban while four-eyes is on", async () => {
		const { world, call } = setup();
		const asset = world.addAsset({ asset_type: "mcp_server", identifier: "shell-runner", status: "banned" });
		expect((await call({ action: "update_settings", tenant_id: TENANT_A, policy_four_eyes: true })).body)
			.toMatchObject({ ok: true, policy_four_eyes: true });
		expect(await call({ action: "upsert_asset", tenant_id: TENANT_A, asset_id: asset.id, expected_version: 1,
			fields: { status: "approved" } })).toEqual({ status: 403, body: { error: "governance_four_eyes_required" } });
		// Tightening stays immediate.
		expect((await call({ action: "upsert_asset", tenant_id: TENANT_A, asset_id: asset.id, expected_version: 1,
			fields: { risk_tier: "high" } })).status).toBe(200);
	});

	it("turns a request to disable four-eyes into a change request for a second approver", async () => {
		const { world, call } = setup();
		await call({ action: "update_settings", tenant_id: TENANT_A, policy_four_eyes: true });
		const off = await call({ action: "update_settings", tenant_id: TENANT_A, policy_four_eyes: false });
		expect(off.body).toMatchObject({ ok: true, policy_four_eyes: true });
		const requestId = String(off.body.pending_disable_request_id);
		const decide = (token: string) => call({ action: "decide_policy_change", tenant_id: TENANT_A, request_id: requestId,
			decision: "approve", reason: "Agreed" }, token);
		expect(await decide(`session-${OWNER_A}`)).toEqual({ status: 403, body: { error: "four_eyes_self_approval" } });
		expect(await decide(`session-${MEMBER_A}`)).toEqual({ status: 403, body: { error: "governance_role_insufficient" } });
		expect((await decide(`session-${ADMIN_A}`)).body).toMatchObject({ ok: true, status: "approved" });
		expect(world.changes[0].status).toBe("approved");
	});

	it("reports a superseded policy change instead of applying a stale diff", async () => {
		const { world, call } = setup();
		world.changes.push({ id: "bbbbbbbb-0000-4000-8000-000000000001", tenant_id: TENANT_A, change_kind: "runtime_publish",
			status: "pending", requested_by: OWNER_A, base_version: 2, payload: { policy: { command_default: "deny" } } });
		expect(await call({ action: "decide_policy_change", tenant_id: TENANT_A, request_id: "bbbbbbbb-0000-4000-8000-000000000001",
			decision: "approve", reason: "Looks right" }, `session-${ADMIN_A}`)).toEqual({
			status: 409, body: { error: "policy_change_superseded", status: "superseded", outcome_code: "policy_version_conflict" },
		});
	});
});

describe("ai-governance: enforcement feed and change detail", () => {
	it("previews what connectors and Browser Guard receive, and honours exception expiry", async () => {
		const { world, call } = setup();
		const shell = world.addAsset({ asset_type: "mcp_server", identifier: "shell-runner", status: "banned" });
		world.addAsset({ asset_type: "mcp_server", identifier: "github", status: "restricted" });
		world.addAsset({ asset_type: "ai_site", identifier: "deepseek", status: "banned" });
		world.addAsset({ asset_type: "coding_agent", identifier: "codex", status: "banned" });
		const preview = await call({ action: "enforcement_preview", tenant_id: TENANT_A }, `session-${VIEWER_A}`);
		expect(preview).toEqual({ status: 200, body: {
			ok: true,
			connector_overlay: { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: ["github"] },
			browser_guard_managed_policy: { blockedSites: ["deepseek"] },
			runtime_policy_version: 3,
		} });

		const requested = await call({ action: "request_exception", tenant_id: TENANT_A, fields: {
			asset_id: shell.id, scope_kind: "tenant", justification: "Migration week",
			expires_at: new Date(world.clock + 2 * 86_400_000).toISOString(),
		} }, `session-${MEMBER_A}`);
		const exceptionId = requested.body.exception_id;
		expect(await call({ action: "decide_exception", tenant_id: TENANT_A, exception_id: exceptionId,
			decision: "approve", reason: "Mine" }, `session-${MEMBER_A}`)).toEqual({ status: 403, body: { error: "governance_role_insufficient" } });
		expect((await call({ action: "decide_exception", tenant_id: TENANT_A, exception_id: exceptionId,
			decision: "approve", reason: "Two days only" }, `session-${ADMIN_A}`)).body).toMatchObject({ status: "approved" });
		expect((await call({ action: "enforcement_preview", tenant_id: TENANT_A })).body.connector_overlay)
			.toEqual({ mcp_deny_servers: [], mcp_require_approval_servers: ["github"] });

		world.clock += 2 * 86_400_000 + 1;
		expect((await call({ action: "enforcement_preview", tenant_id: TENANT_A })).body.connector_overlay)
			.toEqual({ mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: ["github"] });
		expect(await call({ action: "revoke_exception", tenant_id: TENANT_A, exception_id: exceptionId, reason: "Done" }))
			.toEqual({ status: 409, body: { error: "exception_not_active", status: "expired" } });
	});

	it("serves a change request's proposed and current policy to owners/admins at AAL2 only", async () => {
		const { world, call } = setup();
		const id = "bbbbbbbb-0000-4000-8000-000000000002";
		world.changes.push({ id, tenant_id: TENANT_A, change_kind: "runtime_publish", status: "pending", requested_by: OWNER_A,
			base_version: 3, payload: { policy: { command_default: "deny" } }, payload_sha256: "a".repeat(64) });
		world.changes.push({ id: "bbbbbbbb-0000-4000-8000-000000000003", tenant_id: TENANT_B, change_kind: "runtime_publish",
			status: "pending", requested_by: OWNER_B, base_version: 0, payload: { policy: { command_default: "allow" } } });
		const detail = await call({ action: "policy_change_detail", tenant_id: TENANT_A, request_id: id }, `session-${ADMIN_A}`);
		expect(detail.status).toBe(200);
		expect(detail.body.proposed).toEqual({ policy: { command_default: "deny" } });
		expect(detail.body.current).toEqual({ version: 3, policy: { command_default: "ask" } });
		expect(detail.body.request).not.toHaveProperty("payload");
		expect(await call({ action: "policy_change_detail", tenant_id: TENANT_A, request_id: id }, `aal1-${ADMIN_A}`))
			.toEqual({ status: 403, body: { error: "mfa_required" } });
		expect(await call({ action: "policy_change_detail", tenant_id: TENANT_A, request_id: id }, `session-${MEMBER_A}`))
			.toEqual({ status: 403, body: { error: "governance_role_insufficient" } });
		expect(await call({ action: "policy_change_detail", tenant_id: TENANT_A, request_id: "bbbbbbbb-0000-4000-8000-000000000003" }))
			.toEqual({ status: 404, body: { error: "not_found" } });
	});
});

describe("ai-governance: request schema and SQL invariants", () => {
	it("accepts only known fields with bounded values", () => {
		const ok = (value: Row) => parseGovernanceRequest({ tenant_id: TENANT_A, ...value }).ok;
		expect(ok({ action: "upsert_asset", fields: { asset_type: "mcp_server", identifier: "github", name: "GitHub" } })).toBe(true);
		expect(ok({ action: "upsert_asset", fields: { asset_type: "mcp_server", identifier: "github" } })).toBe(false);
		expect(ok({ action: "upsert_asset", fields: { asset_type: "mcp_server", identifier: "bad id", name: "x" } })).toBe(false);
		expect(ok({ action: "upsert_asset", fields: { asset_type: "llm", identifier: "x", name: "x" } })).toBe(false);
		expect(ok({ action: "upsert_asset", asset_id: AGENT_A, fields: { name: "x" } })).toBe(false);
		expect(ok({ action: "upsert_asset", fields: { asset_type: "ai_site", identifier: "x", name: "x", data_categories: ["dna"] } })).toBe(false);
		expect(ok({ action: "upsert_asset", fields: { asset_type: "ai_site", identifier: "x", name: "x", risk_score: 101 } })).toBe(false);
		expect(ok({ action: "upsert_asset", fields: { asset_type: "ai_site", identifier: "x", name: "x", created_by: OWNER_A } })).toBe(false);
		expect(ok({ action: "decide_intake", request_id: AGENT_A, decision: "approve", reason: "" })).toBe(false);
		expect(ok({ action: "decide_intake", request_id: AGENT_A, decision: "approve", reason: "a\u0007b" })).toBe(false);
		expect(ok({ action: "request_exception", fields: { asset_id: AGENT_A, justification: "x", expires_at: "2027-01-01T00:00:00Z",
			scope_kind: "agents", scope_agent_ids: ["not-a-uuid"] } })).toBe(false);
		expect(ok({ action: "link_evidence", asset_id: AGENT_A, kind: "incident", ref: "0", link: true })).toBe(false);
		expect(ok({ action: "update_settings", default_review_days: 7 })).toBe(false);
		expect(ok({ action: "update_settings" })).toBe(false);
	});

	it("keeps four-eyes and tenant isolation in the database, not only in this handler", () => {
		for (const constraint of [
			"ai_intake_requests_four_eyes check (decided_by is null or decided_by <> requested_by)",
			"ai_governance_exceptions_four_eyes check (decided_by is null or decided_by <> requested_by)",
		]) expect(REGISTER_SQL).toContain(constraint);
		expect(CHANGE_SQL).toContain("policy_change_requests_four_eyes check (decided_by is null or decided_by <> requested_by)");
		expect(CHANGE_SQL).toContain("before insert on public.runtime_policy_revisions");
		expect(CHANGE_SQL).toContain("before insert on public.dlp_policy_revisions");
		expect(CHANGE_SQL).toMatch(/grant select \([^)]*\) on public\.policy_change_requests to authenticated/);
		expect(CHANGE_SQL.match(/grant select \(([^)]*)\) on public\.policy_change_requests/)?.[1]).not.toContain("payload,");
		for (const table of ["tenant_ai_governance_settings", "ai_governance_reviewers", "ai_assets", "ai_asset_evidence",
			"ai_intake_requests", "ai_governance_exceptions"]) {
			expect(REGISTER_SQL).toContain(`create policy tenant_identity_access_restrict on public.${table}`);
			expect(REGISTER_SQL).toContain(`alter table public.${table} enable row level security`);
		}
		expect(REGISTER_SQL).toContain("from public, anon, authenticated;\ngrant execute on function public.upsert_ai_asset");
	});
});
