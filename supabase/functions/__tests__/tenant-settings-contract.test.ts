// Contract suite for the `tenant-settings` Edge Function (workspace rename,
// retention and closure). It drives the real handler with an injected
// service-role client double and asserts the authorization, AAL2, typed-name
// confirmation and failure mapping, plus the SQL contract of the RPCs.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through TenantSettingsDeps.client");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const migration = readFileSync(
	join(ROOT, "supabase", "migrations", "20260925000040_tenant_workspace_settings.sql"),
	"utf8",
);
const ownerBoundsMigration = readFileSync(
	join(ROOT, "supabase", "migrations", "20261010000110_workspace_settings_retention_owner_bounds.sql"),
	"utf8",
);
const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
const manifest = JSON.parse(
	readFileSync(join(ROOT, "docs", "production-readiness", "edge-function-contract-manifest.json"), "utf8"),
) as { functions: Record<string, { tests: string[] }> };

const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const RUN = "55555555-5555-4555-8555-555555555555";
const URL_BASE = "https://project.supabase.co/functions/v1/tenant-settings";

interface TenantRow {
	id: string;
	name: string;
	kind: string;
	status: string;
	retention_days: number;
	created_at: string;
}

interface Options {
	role?: string | null;
	expiresAt?: string | null;
	assurance?: string;
	assuranceError?: boolean;
	tenant?: Partial<TenantRow> | null;
	memberError?: boolean;
	tenantError?: boolean;
	requireMfa?: boolean;
	rateAllowed?: boolean;
	rateError?: boolean;
	updateError?: { code: string; message?: string } | null;
	closeError?: { code: string } | null;
	closeResult?: Record<string, unknown> | null;
}

function database(options: Options = {}) {
	const tenant: TenantRow | null = options.tenant === null ? null : {
		id: TENANT,
		name: "Acme Security",
		kind: "team",
		status: "active",
		retention_days: 90,
		created_at: "2026-01-01T00:00:00.000Z",
		...options.tenant,
	};
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const tables: string[] = [];
	const assurance = vi.fn(async () => options.assuranceError
		? { data: null, error: new Error("auth_down") }
		: { data: { currentLevel: options.assurance ?? "aal2" }, error: null });
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) => token === "valid-token"
				? { data: { user: { id: USER } }, error: null }
				: { data: { user: null }, error: new Error("invalid") }),
			mfa: { getAuthenticatorAssuranceLevel: assurance },
		},
		from(table: string) {
			tables.push(table);
			const builder = {
				select: () => builder,
				eq: () => builder,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") {
						return { data: { require_mfa: options.requireMfa ?? false, required_saml_provider_id: null }, error: null };
					}
					if (table === "tenant_members") {
						if (options.memberError) return { data: null, error: new Error("db_down") };
						return options.role === null
							? { data: null, error: null }
							: { data: { role: options.role ?? "owner", expires_at: options.expiresAt ?? null }, error: null };
					}
					if (table === "tenants") {
						return options.tenantError ? { data: null, error: new Error("db_down") } : { data: tenant, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") {
				if (options.rateError) return { data: null, error: { message: "db_down" } };
				return { data: { allowed: options.rateAllowed ?? true, remaining: 5 }, error: null };
			}
			if (name === "update_tenant_workspace_settings") {
				if (options.updateError) return { data: null, error: options.updateError };
				const changed: string[] = [];
				if (args.p_name !== null && args.p_name !== tenant?.name) changed.push("name");
				if (args.p_retention_days !== null && args.p_retention_days !== tenant?.retention_days) changed.push("retention_days");
				return {
					data: {
						id: TENANT,
						name: args.p_name ?? tenant?.name,
						retention_days: args.p_retention_days ?? tenant?.retention_days,
						status: "active",
						changed,
					},
					error: null,
				};
			}
			if (name === "request_workspace_closure") {
				if (options.closeError) return { data: null, error: options.closeError };
				return {
					data: options.closeResult === undefined
						? {
							run_id: RUN, tenant_id: TENANT, status: "requested", resumed: false,
							backup_scope: "excluded_external_retention", backup_exception: "Backups are separate.",
						}
						: options.closeResult,
					error: null,
				};
			}
			throw new Error(`unexpected rpc ${name}`);
		}),
	};
	return { db, rpcCalls, tables, assurance };
}

async function handlerWith(options: Options = {}) {
	const fake = database(options);
	const mod = await import("../tenant-settings/index.ts");
	const handle = mod.createTenantSettingsHandler({
		env: (name) => ({
			SUPABASE_URL: "https://project.supabase.co",
			SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
		} as Record<string, string>)[name],
		client: () => fake.db as never,
		now: () => Date.parse("2026-09-25T10:00:00.000Z"),
	});
	return { ...fake, handle };
}

function get(tenant: string = TENANT, token = "valid-token"): Request {
	return new Request(URL_BASE, {
		method: "GET",
		headers: { Authorization: `Bearer ${token}`, "X-AIDR-Tenant-ID": tenant },
	});
}

function patch(body: unknown, token = "valid-token"): Request {
	return new Request(URL_BASE, {
		method: "PATCH",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

function mutations(rpcCalls: Array<{ name: string }>) {
	return rpcCalls.filter((call) => call.name !== "consume_tenant_rate_limit").map((call) => call.name);
}

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("tenant-settings reads", () => {
	it("returns the workspace and role-derived permissions to any active member", async () => {
		for (const [role, canEdit, canClose] of [
			["owner", true, true], ["admin", true, false], ["member", false, false], ["viewer", false, false],
		] as const) {
			// Retention is owner-only, like closure.
			const canEditRetention = canClose;
			const { handle, rpcCalls, assurance } = await handlerWith({ role, assurance: "aal1" });
			const response = await handle(get());
			expect(response.status, role).toBe(200);
			expect(await response.json()).toEqual({
				ok: true,
				workspace: {
					id: TENANT, name: "Acme Security", kind: "team", status: "active",
					retention_days: 90, created_at: "2026-01-01T00:00:00.000Z",
				},
				role,
				permissions: { can_edit: canEdit, can_edit_retention: canEditRetention, can_close: canClose, requires_aal2: true },
				// The telemetry row of retention_policy_bounds, not the 1-day column constraint.
				retention_bounds: { min: 7, max: 3650 },
			});
			// Reads do not require step-up and never mutate or consume quota.
			expect(assurance).not.toHaveBeenCalled();
			expect(rpcCalls).toEqual([]);
		}
	});

	it("reports a closing workspace as read-only", async () => {
		const { handle } = await handlerWith({ tenant: { status: "closing" } });
		const body = await (await handle(get())).json();
		expect(body.workspace.status).toBe("closing");
		expect(body.permissions).toMatchObject({ can_edit: false, can_edit_retention: false, can_close: false });
	});

	it("refuses non-members, expired or JIT members and closed or missing workspaces", async () => {
		const cases: Options[] = [
			{ role: null },
			{ role: "support_jit" },
			{ expiresAt: "2026-09-25T09:00:00.000Z" },
			{ tenant: { status: "closed" } },
			{ tenant: null },
		];
		for (const options of cases) {
			const { handle } = await handlerWith(options);
			const response = await handle(get());
			expect(response.status, JSON.stringify(options)).toBe(403);
			expect(await response.json()).toEqual({ error: "workspace_forbidden" });
		}
	});

	it("fails closed on unreadable authorization state", async () => {
		for (const options of [{ memberError: true }, { tenantError: true }] satisfies Options[]) {
			const { handle } = await handlerWith(options);
			const response = await handle(get());
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "authorization_unavailable" });
		}
	});

	it("rejects missing credentials and malformed tenant ids before any database work", async () => {
		const { handle, tables, db } = await handlerWith();
		const missing = await handle(new Request(URL_BASE, { method: "GET", headers: { "X-AIDR-Tenant-ID": TENANT } }));
		expect(missing.status).toBe(401);
		expect((await handle(get("not-a-uuid"))).status).toBe(400);
		expect(tables).toEqual([]);
		expect(db.auth.getUser).not.toHaveBeenCalled();
		const invalid = await handle(get(TENANT, "forged"));
		expect(invalid.status).toBe(401);
		expect(await invalid.json()).toEqual({ error: "invalid_access_token" });
		expect(tables).toEqual([]);
	});

	it("applies the tenant identity barrier (MFA-required tenants need AAL2 even to read)", async () => {
		const { handle } = await handlerWith({ requireMfa: true, assurance: "aal1" });
		const response = await handle(get());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
	});

	it("allows only GET and PATCH", async () => {
		const { handle } = await handlerWith();
		for (const method of ["POST", "PUT", "DELETE"]) {
			const response = await handle(new Request(URL_BASE, { method, headers: { Authorization: "Bearer valid-token" } }));
			expect(response.status, method).toBe(405);
		}
	});
});

describe("tenant-settings updates", () => {
	it("renames the workspace for an owner or admin at AAL2 through the audited RPC", async () => {
		for (const role of ["owner", "admin"]) {
			const { handle, rpcCalls } = await handlerWith({ role });
			const response = await handle(patch({ tenant_id: TENANT, action: "update", name: "  Acme Platform  " }));
			expect(response.status, role).toBe(200);
			const body = await response.json();
			expect(body).toMatchObject({ ok: true, changed: ["name"], workspace: { name: "Acme Platform", retention_days: 90 } });
			expect(rpcCalls.find((call) => call.name === "update_tenant_workspace_settings")?.args).toEqual({
				p_tenant_id: TENANT, p_actor_user_id: USER, p_name: "Acme Platform", p_retention_days: null,
			});
			expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({
				p_tenant_id: TENANT, p_subject: USER, p_endpoint: "tenant-settings",
			});
		}
	});

	it("extends retention without confirmation and requires explicit confirmation to shorten it", async () => {
		const extend = await handlerWith();
		const extended = await extend.handle(patch({ tenant_id: TENANT, action: "update", retention_days: 365 }));
		expect(extended.status).toBe(200);
		expect(await extended.json()).toMatchObject({ changed: ["retention_days"], workspace: { retention_days: 365 } });

		const shorten = await handlerWith();
		const refused = await shorten.handle(patch({ tenant_id: TENANT, action: "update", retention_days: 30 }));
		expect(refused.status).toBe(409);
		expect(await refused.json()).toEqual({ error: "retention_reduction_unconfirmed", current_retention_days: 90 });
		expect(mutations(shorten.rpcCalls)).toEqual([]);

		const confirmed = await shorten.handle(patch({
			tenant_id: TENANT, action: "update", retention_days: 30, confirm_retention_reduction: true,
		}));
		expect(confirmed.status).toBe(200);
		expect(mutations(shorten.rpcCalls)).toEqual(["update_tenant_workspace_settings"]);
	});

	it("lets an admin rename but never change retention, and needs no owner for an unchanged value", async () => {
		const admin = await handlerWith({ role: "admin" });
		for (const body of [
			{ tenant_id: TENANT, action: "update", retention_days: 7, confirm_retention_reduction: true },
			{ tenant_id: TENANT, action: "update", retention_days: 365 },
			{ tenant_id: TENANT, action: "update", name: "Acme Platform", retention_days: 30, confirm_retention_reduction: true },
		]) {
			const response = await admin.handle(patch(body));
			expect(response.status, JSON.stringify(body)).toBe(403);
			expect(await response.json()).toEqual({ error: "workspace_role_insufficient" });
		}
		expect(admin.rpcCalls).toEqual([]);
		expect(admin.assurance).not.toHaveBeenCalled();

		const rename = await handlerWith({ role: "admin" });
		const renamed = await rename.handle(patch({ tenant_id: TENANT, action: "update", name: "Acme Platform", retention_days: 90 }));
		expect(renamed.status).toBe(200);
		expect(await renamed.json()).toMatchObject({ changed: ["name"], workspace: { name: "Acme Platform", retention_days: 90 } });
		expect(mutations(rename.rpcCalls)).toEqual(["update_tenant_workspace_settings"]);
	});

	it("surfaces the bounded retention setter's refusals with stable codes", async () => {
		for (const [updateError, status, body] of [
			[{ code: "42501", message: "retention_admin_owner_required" }, 403, { error: "workspace_role_insufficient" }],
			[{ code: "22023", message: "retention_days_out_of_bounds" }, 400, { error: "invalid_retention_days", reason: "retention_days_out_of_bounds" }],
			[{ code: "22023", message: "retention_days_exceeds_plan" }, 400, { error: "invalid_retention_days", reason: "retention_days_exceeds_plan" }],
			[{ code: "55000", message: "retention_change_refused_offboarding" }, 409, { error: "retention_change_refused_offboarding" }],
			[{ code: "42501", message: "workspace_settings_forbidden" }, 403, { error: "workspace_forbidden" }],
		] as const) {
			const { handle } = await handlerWith({ updateError });
			const response = await handle(patch({ tenant_id: TENANT, action: "update", retention_days: 365 }));
			expect(response.status, updateError.message).toBe(status);
			expect(await response.json()).toEqual(body);
		}
	});

	it("validates names and retention bounds before any identity work", async () => {
		const { handle, db } = await handlerWith();
		const cases: Array<[unknown, string]> = [
			[{ tenant_id: TENANT, action: "update" }, "no_changes"],
			[{ tenant_id: TENANT, action: "update", name: "   " }, "invalid_workspace_name"],
			[{ tenant_id: TENANT, action: "update", name: "x".repeat(201) }, "invalid_workspace_name"],
			[{ tenant_id: TENANT, action: "update", name: "Bad\u0007Name" }, "invalid_workspace_name"],
			[{ tenant_id: TENANT, action: "update", name: 42 }, "invalid_workspace_name"],
			[{ tenant_id: TENANT, action: "update", retention_days: 0 }, "invalid_retention_days"],
			[{ tenant_id: TENANT, action: "update", retention_days: 1 }, "invalid_retention_days"],
			[{ tenant_id: TENANT, action: "update", retention_days: 6 }, "invalid_retention_days"],
			[{ tenant_id: TENANT, action: "update", retention_days: 3651 }, "invalid_retention_days"],
			[{ tenant_id: TENANT, action: "update", retention_days: 30.5 }, "invalid_retention_days"],
			[{ tenant_id: TENANT, action: "update", retention_days: "30" }, "invalid_retention_days"],
			[{ tenant_id: TENANT, action: "update", name: "A", role: "owner" }, "invalid_request"],
			[{ tenant_id: "nope", action: "update", name: "A" }, "invalid_request"],
			[{ tenant_id: TENANT, action: "delete" }, "invalid_action"],
			[{ tenant_id: TENANT, action: "close" }, "invalid_request"],
		];
		for (const [body, error] of cases) {
			const response = await handle(patch(body));
			expect(response.status, JSON.stringify(body)).toBe(400);
			expect(await response.json()).toEqual({ error });
		}
		expect(db.auth.getUser).not.toHaveBeenCalled();
	});

	it("keeps members and viewers read-only and requires AAL2 for owners and admins", async () => {
		for (const role of ["member", "viewer"]) {
			const { handle, rpcCalls, assurance } = await handlerWith({ role });
			const response = await handle(patch({ tenant_id: TENANT, action: "update", name: "Other" }));
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "workspace_role_insufficient" });
			expect(rpcCalls).toEqual([]);
			expect(assurance).not.toHaveBeenCalled();
		}
		const aal1 = await handlerWith({ assurance: "aal1" });
		const stepUp = await aal1.handle(patch({ tenant_id: TENANT, action: "update", name: "Other" }));
		expect(stepUp.status).toBe(403);
		expect(await stepUp.json()).toEqual({ error: "mfa_required" });
		expect(aal1.rpcCalls).toEqual([]);

		const unknown = await handlerWith({ assuranceError: true });
		const unavailable = await unknown.handle(patch({ tenant_id: TENANT, action: "update", name: "Other" }));
		expect(unavailable.status).toBe(503);
		expect(await unavailable.json()).toEqual({ error: "assurance_unavailable" });
	});

	it("refuses changes to a workspace that is not active", async () => {
		const { handle, rpcCalls } = await handlerWith({ tenant: { status: "suspended" } });
		const response = await handle(patch({ tenant_id: TENANT, action: "update", name: "Other" }));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "workspace_not_active" });
		expect(rpcCalls).toEqual([]);
	});

	it("fails closed on rate limiting and maps RPC failures", async () => {
		const limited = await handlerWith({ rateAllowed: false });
		expect((await limited.handle(patch({ tenant_id: TENANT, action: "update", name: "X" }))).status).toBe(429);
		expect(mutations(limited.rpcCalls)).toEqual([]);
		const noLimiter = await handlerWith({ rateError: true });
		expect((await noLimiter.handle(patch({ tenant_id: TENANT, action: "update", name: "X" }))).status).toBe(503);
		expect(mutations(noLimiter.rpcCalls)).toEqual([]);

		for (const [code, status, error] of [
			["42501", 403, "workspace_forbidden"],
			["22023", 400, "invalid_workspace_settings"],
			["55000", 409, "workspace_not_active"],
			["XX000", 503, "workspace_update_failed"],
		] as const) {
			const { handle } = await handlerWith({ updateError: { code } });
			const response = await handle(patch({ tenant_id: TENANT, action: "update", name: "X" }));
			expect(response.status, code).toBe(status);
			expect(await response.json()).toEqual({ error });
		}
	});
});

describe("tenant-settings closure", () => {
	it("closes only when the owner types the exact workspace name, through the offboarding lifecycle", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(patch({ tenant_id: TENANT, action: "close", confirm_name: " Acme Security " }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			ok: true,
			closure: {
				run_id: RUN, status: "requested",
				backup_scope: "excluded_external_retention", backup_exception: "Backups are separate.",
			},
		});
		expect(rpcCalls.find((call) => call.name === "request_workspace_closure")?.args).toEqual({
			p_tenant_id: TENANT, p_actor_user_id: USER, p_confirm_name: " Acme Security ",
		});
	});

	it("rejects a mismatched confirmation without calling the lifecycle", async () => {
		for (const confirm of ["acme security", "Acme", ""]) {
			const { handle, rpcCalls } = await handlerWith();
			const response = await handle(patch({ tenant_id: TENANT, action: "close", confirm_name: confirm }));
			expect(response.status, confirm).toBe(400);
			expect(await response.json()).toEqual({ error: "confirmation_mismatch" });
			expect(mutations(rpcCalls)).toEqual([]);
		}
	});

	it("is owner-only and requires AAL2", async () => {
		const admin = await handlerWith({ role: "admin" });
		const forbidden = await admin.handle(patch({ tenant_id: TENANT, action: "close", confirm_name: "Acme Security" }));
		expect(forbidden.status).toBe(403);
		expect(await forbidden.json()).toEqual({ error: "workspace_role_insufficient" });
		expect(admin.rpcCalls).toEqual([]);

		const aal1 = await handlerWith({ assurance: "aal1" });
		const stepUp = await aal1.handle(patch({ tenant_id: TENANT, action: "close", confirm_name: "Acme Security" }));
		expect(stepUp.status).toBe(403);
		expect(await stepUp.json()).toEqual({ error: "mfa_required" });
		expect(aal1.rpcCalls).toEqual([]);
	});

	it("maps a lost race to the right status and never reports an unconfirmed closure", async () => {
		for (const [closeError, status, error] of [
			[{ code: "22023" }, 400, "confirmation_mismatch"],
			[{ code: "42501" }, 403, "workspace_forbidden"],
			[{ code: "55000" }, 409, "workspace_not_active"],
			[{ code: "P0002" }, 503, "workspace_closure_failed"],
		] as const) {
			const { handle } = await handlerWith({ closeError });
			const response = await handle(patch({ tenant_id: TENANT, action: "close", confirm_name: "Acme Security" }));
			expect(response.status).toBe(status);
			expect(await response.json()).toEqual({ error });
		}
		for (const closeResult of [null, { run_id: RUN, tenant_id: "33333333-3333-4333-8333-333333333333", status: "requested" }, { tenant_id: TENANT }]) {
			const { handle } = await handlerWith({ closeResult });
			const response = await handle(patch({ tenant_id: TENANT, action: "close", confirm_name: "Acme Security" }));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "workspace_closure_failed" });
		}
	});
});

describe("tenant-settings SQL and deployment contract", () => {
	const update = migration.split("create or replace function public.update_tenant_workspace_settings(")[1]?.split("$$;")[0] ?? "";
	const close = migration.split("create or replace function public.request_workspace_closure(")[1]?.split("$$;")[0] ?? "";

	it("re-checks role, membership expiry and tenant status under row locks", () => {
		expect(update).toContain("security definer");
		expect(update).toContain("m.role in ('owner', 'admin')");
		expect(update).toContain("(m.expires_at is null or m.expires_at > clock_timestamp())");
		expect(update).toContain("for share of m, team");
		expect(update).toContain("from public.tenants where id = p_tenant_id for update");
		expect(update).toContain("v_tenant.status <> 'active'");
		expect(close).toContain("m.role = 'owner'");
		expect(close).toContain("for share of m, team");
		expect(close).toContain("for update");
		expect(close).toContain("btrim(p_confirm_name) is distinct from v_tenant.name");
	});

	it("bounds retention to the tenants constraint and keeps per-class policy in step", () => {
		expect(update).toContain("p_retention_days not between 1 and 3650");
		expect(update).toContain("update public.tenant_data_retention_policies p");
		expect(update).toContain("when 'commercial_records' then greatest(v_days, 2555)");
		expect(update).toContain("when 'security_audit' then greatest(v_days, 365)");
		expect(update).toContain("when 'operational_ephemera' then least(v_days, 7)");
		expect(update).toContain("update public.teams set name = v_name where tenant_id = p_tenant_id");
	});

	it("audits both streams without storing the workspace name and delegates closure to offboarding", () => {
		expect(update).toContain("'tenant.settings_updated'");
		expect(update).toContain("insert into public.admin_audit_logs");
		expect(update).toContain("insert into public.audit_logs");
		expect(update).not.toMatch(/'name',\s*v_name\s*\)/);
		expect(close).toContain("'tenant.closure_requested'");
		expect(close).toContain("public.request_tenant_offboarding(p_tenant_id, p_actor_user_id)");
	});

	it("grants the RPCs to service_role only", () => {
		for (const signature of [
			"public.update_tenant_workspace_settings(uuid, uuid, text, integer)",
			"public.request_workspace_closure(uuid, uuid, text)",
		]) {
			expect(migration).toContain(`revoke all on function ${signature}\n  from public, anon, authenticated;`);
			expect(migration).toContain(`grant execute on function ${signature}\n  to service_role;`);
		}
	});

	describe("owner-only, bounded retention (20261010000110)", () => {
		const fixed = ownerBoundsMigration
			.split("create or replace function public.update_tenant_workspace_settings(")[1]?.split("$$;")[0] ?? "";

		it("redefines the RPC in a forward-only migration ordered after the bounded setter", () => {
			expect(fixed).toContain("security definer");
			expect(fixed).toContain("set search_path = pg_catalog, public, pg_temp");
			// The last migration (in apply order) that defines the RPC is this one.
			const definers = readdirSync(join(ROOT, "supabase", "migrations"))
				.filter((name) => name.endsWith(".sql"))
				.sort()
				.filter((name) => readFileSync(join(ROOT, "supabase", "migrations", name), "utf8")
					.includes("create or replace function public.update_tenant_workspace_settings("));
			expect(definers.at(-1)).toBe("20261010000110_workspace_settings_retention_owner_bounds.sql");
			expect(ownerBoundsMigration).toContain(
				"revoke all on function public.update_tenant_workspace_settings(uuid, uuid, text, integer)\n  from public, anon, authenticated;",
			);
			expect(ownerBoundsMigration).toContain(
				"grant execute on function public.update_tenant_workspace_settings(uuid, uuid, text, integer)\n  to service_role;",
			);
		});

		it("keeps the admin rename path and its row locks", () => {
			expect(fixed).toContain("m.role in ('owner', 'admin')");
			expect(fixed).toContain("for share of m, team");
			expect(fixed).toContain("from public.tenants where id = p_tenant_id for update");
			expect(fixed).toContain("update public.teams set name = v_name where tenant_id = p_tenant_id");
			// Membership before tenant row, as in every other workspace RPC.
			expect(fixed.indexOf("for share of m, team")).toBeLessThan(fixed.indexOf("for update;"));
		});

		it("routes every retention change through the owner check and the bounded setter", () => {
			const retention = fixed.split("if 'retention_days' = any(v_changed) then")[1]?.split("if cardinality(v_changed) > 0 then")[0] ?? "";
			expect(retention).toContain("perform app.retention_assert_tenant_owner(p_tenant_id, p_actor_user_id);");
			expect(retention).toContain("perform public.admin_set_tenant_retention(");
			expect(retention).toContain("from public.retention_policy_bounds where data_class = 'telemetry'");
			expect(retention).toContain("raise exception 'retention_days_out_of_bounds'");
			expect(retention).toContain("v_target := least(greatest(v_target, v_class.min_days), v_class.max_days);");
			expect(retention).toContain("b.tenant_configurable");
			// The owner check precedes every write.
			expect(retention.indexOf("retention_assert_tenant_owner")).toBeLessThan(retention.indexOf("admin_set_tenant_retention"));
			// No direct, unbounded write of the requested value into class policies.
			expect(fixed).not.toMatch(/else v_days end,\s*updated_by/);
			expect(fixed).not.toContain("when 'operational_ephemera' then least(v_days, 7)");
			// The shared tenant lock is taken before any row lock on the retention path.
			expect(fixed.indexOf("pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606))"))
				.toBeLessThan(fixed.indexOf("for share of m, team"));
		});

		it("still audits both streams without the workspace name", () => {
			expect(fixed).toContain("'tenant.settings_updated'");
			expect(fixed).toContain("insert into public.admin_audit_logs");
			expect(fixed).toContain("insert into public.audit_logs");
			expect(fixed).not.toMatch(/'name',\s*v_name\s*\)/);
		});
	});

	it("is registered for deployment and in the browser contract manifest", () => {
		expect(config).toMatch(/^\[functions\.tenant-settings\]\n(?:#.*\n)*verify_jwt = true$/m);
		expect(manifest.functions["tenant-settings"]?.tests).toContain(
			"supabase/functions/__tests__/tenant-settings-contract.test.ts",
		);
	});
});
