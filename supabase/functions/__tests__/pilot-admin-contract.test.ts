import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through PilotAdminDeps.db");
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const ACTOR = "11111111-1111-4111-8111-111111111111";
const TARGET = "22222222-2222-4222-8222-222222222222";
const TEAM = "33333333-3333-4333-8333-333333333333";
const TOKEN = "valid-token";

interface Application {
	user_id: string;
	tenant_id: string;
	status: string;
	cohort?: string | null;
	notes?: string | null;
}

interface Membership {
	user_id: string;
	tenant_id: string;
	role: string;
	expires_at: string | null;
}

function database(options: {
	level?: "aal1" | "aal2";
	assuranceError?: boolean;
	adminPresent?: boolean;
	authorizationError?: boolean;
	revokeAdminBeforeDecision?: boolean;
	application?: Application | null;
	applications?: Application[];
	concurrentApplication?: Application;
	memberships?: Membership[];
	tenantStatus?: string;
	rpcError?: string;
	rpcData?: unknown;
	auditError?: boolean;
} = {}) {
	const applications: Application[] = options.applications?.map((row) => ({ ...row })) ??
		(options.application === undefined
			? [{ user_id: TARGET, tenant_id: TEAM, status: "pending" }]
			: options.application ? [{ ...options.application }] : []);
	const writes: Array<{ table: string; values: Record<string, unknown> }> = [];
	const assurance = vi.fn(async () => ({
		data: options.assuranceError ? null : { currentLevel: options.level ?? "aal2" },
		error: options.assuranceError ? { message: "auth_down" } : null,
	}));
	const from = vi.fn((table: string) => {
		const query = {
			select: () => query,
			eq: () => query,
			maybeSingle: async () => {
				if (table === "identity_user_session_state") return { data: { revoked_before: null }, error: null };
				if (table === "pilot_admins") {
					return options.authorizationError
						? { data: null, error: { message: "db_down" } }
						: { data: options.adminPresent === false ? null : { user_id: ACTOR }, error: null };
				}
				throw new Error(`Unexpected read from ${table}`);
			},
		};
		return query;
	});
	const rpc = vi.fn(async (name: string, args: Record<string, unknown>) => {
		if (name !== "decide_pilot_application") throw new Error(`Unexpected RPC ${name}`);
		if (options.rpcError) return { data: null, error: { message: options.rpcError } };
		if (Object.hasOwn(options, "rpcData")) return { data: options.rpcData, error: null };
		if (options.revokeAdminBeforeDecision) return { data: null, error: { message: "pilot_admin_forbidden" } };

		const target = args.p_target_user_id as string;
		if (options.concurrentApplication) applications.push({ ...options.concurrentApplication });
		const existing = applications.filter((row) => row.user_id === target);
		const requestedTenant = args.p_tenant_id as string | null;
		if (!requestedTenant && new Set(existing.map((row) => row.tenant_id)).size > 1) {
			return { data: null, error: { message: "tenant_required" } };
		}
		const tenant = requestedTenant ?? existing[0]?.tenant_id ?? target;
		const membership = options.memberships?.find((row) => row.user_id === target && row.tenant_id === tenant);
		if (options.tenantStatus === "inactive" || (options.memberships &&
			(!membership || !["owner", "admin", "member"].includes(membership.role) ||
				(membership.expires_at !== null && new Date(membership.expires_at) <= new Date())))) {
			return { data: null, error: { message: "tenant_access_denied" } };
		}
		if (options.auditError) return { data: null, error: { message: "audit_insert_failed" } };

		const status = args.p_action === "approve" ? "approved" : "denied";
		const values = {
			user_id: target,
			tenant_id: tenant,
			status,
			cohort: args.p_cohort as string | null,
			notes: args.p_notes as string | null,
		};
		const index = applications.findIndex((row) => row.user_id === target && row.tenant_id === tenant);
		if (index < 0) applications.push(values);
		else applications[index] = { ...applications[index]!, ...values };
		writes.push({ table: "pilot_applications", values });
		writes.push({
			table: "admin_audit_logs",
			values: {
				actor_user_id: args.p_actor_user_id,
				tenant_id: tenant,
				target_user_id: target,
				action: `pilot.${args.p_action}`,
			},
		});
		return { data: { tenant_id: tenant, status }, error: null };
	});

	return {
		db: {
			auth: {
				getUser: vi.fn(async () => ({ data: { user: { id: ACTOR } }, error: null })),
				mfa: { getAuthenticatorAssuranceLevel: assurance },
			},
			from,
			rpc,
		},
		assurance,
		rpc,
		writes,
		application: (tenantId?: string) => applications.find((row) => tenantId ? row.tenant_id === tenantId : true) ?? null,
	};
}

async function handler(options: Parameters<typeof database>[0] = {}) {
	const fake = database(options);
	const mod = await import("../pilot-admin/index.ts");
	return { handle: mod.createPilotAdminHandler({ db: fake.db as never }), ...fake };
}

function request(body: Record<string, unknown> = { action: "approve", user_id: TARGET }) {
	return new Request("https://project.supabase.co/functions/v1/pilot-admin", {
		method: "POST",
		headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.resetModules();
});

describe("pilot-admin authorization and tenant binding", () => {
	it("requires aal2 before deciding an application", async () => {
		const { handle, rpc, writes, application } = await handler({ level: "aal1" });
		const response = await handle(request());

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(rpc).not.toHaveBeenCalled();
		expect(writes).toHaveLength(0);
		expect(application()?.status).toBe("pending");
	});

	it("fails closed when Auth cannot establish the assurance level", async () => {
		const { handle, rpc } = await handler({ assuranceError: true });
		const response = await handle(request());

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "assurance_unavailable" });
		expect(rpc).not.toHaveBeenCalled();
	});

	it("requires pilot-admin authorization before the RPC", async () => {
		const { handle, rpc } = await handler({ adminPresent: false });
		const response = await handle(request());

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "forbidden" });
		expect(rpc).not.toHaveBeenCalled();
	});

	it("fails closed when pilot-admin authorization is unavailable", async () => {
		const { handle, rpc } = await handler({ authorizationError: true });
		const response = await handle(request());

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "authorization_unavailable" });
		expect(rpc).not.toHaveBeenCalled();
	});

	it("preserves the existing tenant and binds its audit record in one decision", async () => {
		const { handle, rpc, writes, application } = await handler();
		const response = await handle(request({ action: "approve", user_id: TARGET, cohort: "cohort-a" }));

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, user_id: TARGET, tenant_id: TEAM, status: "approved" });
		expect(rpc).toHaveBeenCalledOnce();
		expect(rpc).toHaveBeenCalledWith("decide_pilot_application", {
			p_actor_user_id: ACTOR,
			p_target_user_id: TARGET,
			p_tenant_id: null,
			p_action: "approve",
			p_cohort: "cohort-a",
			p_notes: null,
		});
		expect(application()).toMatchObject({ user_id: TARGET, tenant_id: TEAM, status: "approved", cohort: "cohort-a" });
		expect(writes.map((entry) => entry.table)).toEqual(["pilot_applications", "admin_audit_logs"]);
		expect(writes[1]?.values).toMatchObject({
			actor_user_id: ACTOR,
			tenant_id: TEAM,
			target_user_id: TARGET,
			action: "pilot.approve",
		});
	});

	it("uses the personal tenant default only when no application exists", async () => {
		const { handle, application } = await handler({ application: null });
		const response = await handle(request());

		expect(response.status).toBe(200);
		expect(application()).toMatchObject({ user_id: TARGET, tenant_id: TARGET, status: "approved" });
	});

	it("requires an explicit tenant when applications exist in multiple tenants", async () => {
		const { handle, writes } = await handler({ applications: [
			{ user_id: TARGET, tenant_id: TARGET, status: "pending" },
			{ user_id: TARGET, tenant_id: TEAM, status: "pending" },
		] });
		const response = await handle(request());

		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "tenant_required" });
		expect(writes).toHaveLength(0);
	});

	it("approves only the explicitly selected tenant application", async () => {
		const { handle, rpc, application } = await handler({ applications: [
			{ user_id: TARGET, tenant_id: TARGET, status: "pending" },
			{ user_id: TARGET, tenant_id: TEAM, status: "pending" },
		] });
		const response = await handle(request({ action: "approve", user_id: TARGET, tenant_id: TEAM }));

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, user_id: TARGET, tenant_id: TEAM, status: "approved" });
		expect(rpc).toHaveBeenCalledWith("decide_pilot_application", expect.objectContaining({ p_tenant_id: TEAM }));
		expect(application(TARGET)?.status).toBe("pending");
		expect(application(TEAM)?.status).toBe("approved");
	});

	it("requires active membership in the selected tenant", async () => {
		const { handle, writes } = await handler({ memberships: [] });
		const response = await handle(request({ action: "approve", user_id: TARGET, tenant_id: TEAM }));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_access_denied" });
		expect(writes).toHaveLength(0);
	});

	it("rejects ambiguity when another application commits before the decision", async () => {
		const { handle, writes, application } = await handler({
			concurrentApplication: { user_id: TARGET, tenant_id: TARGET, status: "pending" },
		});
		const response = await handle(request());

		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "tenant_required" });
		expect(application(TARGET)?.status).toBe("pending");
		expect(application(TEAM)?.status).toBe("pending");
		expect(writes).toHaveLength(0);
	});

	it("honors the RPC's pilot-admin recheck when access is revoked", async () => {
		const { handle, writes } = await handler({ revokeAdminBeforeDecision: true });
		const response = await handle(request());

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_access_denied" });
		expect(writes).toHaveLength(0);
	});

	it("reports an RPC failure without a partial application or audit write", async () => {
		const { handle, writes, application } = await handler({ auditError: true });
		const response = await handle(request());

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(application()?.status).toBe("pending");
		expect(writes).toHaveLength(0);
	});

	it.each([
		[null],
		[{ tenant_id: "not-a-uuid", status: "approved" }],
		[{ tenant_id: TEAM, status: "pending" }],
	])("rejects an unexpected RPC result: %j", async (rpcData) => {
		const { handle, writes } = await handler({ rpcData });
		const response = await handle(request());

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
		expect(writes).toHaveLength(0);
	});

	it("rejects an RPC result for a different requested tenant", async () => {
		const { handle } = await handler({ rpcData: { tenant_id: TARGET, status: "approved" } });
		const response = await handle(request({ action: "approve", user_id: TARGET, tenant_id: TEAM }));

		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "pilot_application_unavailable" });
	});
});
