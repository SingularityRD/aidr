import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through OperatorAdminDeps.db");
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const ACTOR = "11111111-1111-4111-8111-111111111111";
const OWNER = "22222222-2222-4222-8222-222222222222";
const TENANT = "33333333-3333-4333-8333-333333333333";
const NOW = Date.parse("2026-09-25T12:00:00.000Z");
const FUTURE = "2027-09-25T00:00:00.000Z";
const TOKEN = "valid-token";
const TERMS_SHA = "A".repeat(64);
const PRIVACY_SHA = "b".repeat(64);

interface Operator {
	user_id: string;
	expires_at: string;
	revoked_at: string | null;
}

function database(options: {
	level?: "aal1" | "aal2";
	assuranceError?: boolean;
	operator?: Operator | null;
	operatorError?: boolean;
	sessionRevoked?: boolean;
	rpcError?: { message: string; code?: string };
	rpcData?: unknown;
} = {}) {
	const operator = options.operator === undefined
		? { user_id: ACTOR, expires_at: "2026-10-25T00:00:00.000Z", revoked_at: null }
		: options.operator;
	const reads: string[] = [];
	const assurance = vi.fn(async () => ({
		data: options.assuranceError ? null : { currentLevel: options.level ?? "aal2" },
		error: options.assuranceError ? { message: "auth_down" } : null,
	}));
	const from = vi.fn((table: string) => {
		const query = {
			select: () => query,
			eq: () => query,
			maybeSingle: async () => {
				reads.push(table);
				if (table === "identity_user_session_state") {
					return { data: options.sessionRevoked ? { revoked_before: "2999-01-01T00:00:00Z" } : { revoked_before: null }, error: null };
				}
				if (table === "platform_operators") {
					return options.operatorError
						? { data: null, error: { message: "db_down" } }
						: { data: operator, error: null };
				}
				throw new Error(`Unexpected read from ${table}`);
			},
		};
		return query;
	});
	// Simulates the operator_* SQL wrappers' successful results.
	const rpc = vi.fn(async (name: string, args: Record<string, unknown>) => {
		if (options.rpcError) return { data: null, error: options.rpcError };
		if (Object.hasOwn(options, "rpcData")) return { data: options.rpcData, error: null };
		switch (name) {
			case "operator_configure_admission_mode":
				return { data: { status: "configured", mode: args.p_mode }, error: null };
			case "operator_configure_legal_documents":
				return { data: { status: "configured", configured_at: "2026-09-25T12:00:00Z" }, error: null };
			case "operator_grant_license":
				return {
					data: {
						status: "granted",
						tenant_id: args.p_tenant_id,
						plan_id: args.p_plan_id,
						owner_user_id: args.p_owner_user_id ?? OWNER,
						allowed_agents: args.p_seats,
						expires_at: args.p_expires_at,
					},
					error: null,
				};
			case "operator_revoke_license":
				return { data: { status: "revoked", tenant_id: args.p_tenant_id }, error: null };
			case "operator_list_tenants":
				return {
					data: {
						tenants: [{ id: TENANT, name: "Acme", kind: "team", status: "active", admission: null }],
						next_cursor: TENANT,
					},
					error: null,
				};
			case "operator_tenant_usage":
				return {
					data: {
						tenant: { id: args.p_tenant_id, kind: "team", status: "active" },
						admission_mode: "cloud",
						allowed_agents: 10,
						agents: { enrolled: 4, active_7d: 3 },
						members: 2,
					},
					error: null,
				};
		}
		throw new Error(`Unexpected RPC ${name}`);
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
		reads,
		rpc,
	};
}

async function handler(options: Parameters<typeof database>[0] = {}) {
	const fake = database(options);
	const mod = await import("../operator-admin/index.ts");
	return { handle: mod.createOperatorAdminHandler({ db: fake.db as never, now: () => NOW }), ...fake };
}

function request(body: unknown, init: { method?: string; token?: string | null } = {}) {
	const token = init.token === undefined ? TOKEN : init.token;
	return new Request("https://project.supabase.co/functions/v1/operator-admin", {
		method: init.method ?? "POST",
		headers: {
			...(token ? { Authorization: `Bearer ${token}` } : {}),
			"Content-Type": "application/json",
		},
		...((init.method ?? "POST") === "POST" ? { body: typeof body === "string" ? body : JSON.stringify(body) } : {}),
	});
}

const legalBody = {
	action: "configure_legal_documents",
	terms: { version: "2026.09", sha256: TERMS_SHA, url: "https://aidr.example/legal/terms" },
	privacy: { version: "2026.09", sha256: PRIVACY_SHA, url: "https://aidr.example/legal/privacy" },
	approval_reference: " LEGAL-42 ",
};
const grantBody = {
	action: "grant_license",
	tenant_id: TENANT,
	plan_id: "business",
	seats: 30,
	expires_at: FUTURE,
	reference: " PO-2026-001 ",
};

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.resetModules();
});

describe("operator-admin authorization", () => {
	it("answers a missing configuration variable before any auth work", async () => {
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "");
		const { handle, db, rpc } = await handler();
		const response = await handle(request({ action: "list_tenants" }));

		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(rpc).not.toHaveBeenCalled();
	});

	it("accepts POST only", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request(undefined, { method: "GET" }));
		expect(response.status).toBe(405);
		expect(rpc).not.toHaveBeenCalled();
	});

	it("requires a bearer token", async () => {
		const { handle, db } = await handler();
		const response = await handle(request({ action: "list_tenants" }, { token: null }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "missing_access_token" });
		expect(db.auth.getUser).not.toHaveBeenCalled();
	});

	it("honors the identity barrier before the operator lookup", async () => {
		const { handle, reads, rpc } = await handler({ sessionRevoked: true });
		const response = await handle(request({ action: "list_tenants" }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "session_revoked" });
		expect(reads).toEqual(["identity_user_session_state"]);
		expect(rpc).not.toHaveBeenCalled();
	});

	it.each([
		["no operator row", null],
		["a revoked operator", { user_id: ACTOR, expires_at: "2026-10-25T00:00:00.000Z", revoked_at: "2026-09-01T00:00:00Z" }],
		["an expired operator", { user_id: ACTOR, expires_at: "2026-09-25T11:59:59.000Z", revoked_at: null }],
		["an unreadable expiry", { user_id: ACTOR, expires_at: "not-a-date", revoked_at: null }],
	])("forbids %s before reading the body or calling SQL", async (_label, operator) => {
		const { handle, rpc, assurance } = await handler({ operator: operator as Operator | null });
		const response = await handle(request("{"));

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "forbidden" });
		expect(assurance).not.toHaveBeenCalled();
		expect(rpc).not.toHaveBeenCalled();
	});

	it("fails closed when the operator allowlist is unavailable", async () => {
		const { handle, rpc } = await handler({ operatorError: true });
		const response = await handle(request({ action: "list_tenants" }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "authorization_unavailable" });
		expect(rpc).not.toHaveBeenCalled();
	});

	it("requires aal2 for every action", async () => {
		const { handle, rpc } = await handler({ level: "aal1" });
		const response = await handle(request({ action: "list_tenants" }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(rpc).not.toHaveBeenCalled();
	});

	it("fails closed when Auth cannot establish the assurance level", async () => {
		const { handle, rpc } = await handler({ assuranceError: true });
		const response = await handle(request({ action: "list_tenants" }));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "assurance_unavailable" });
		expect(rpc).not.toHaveBeenCalled();
	});

	it.each([
		[{ action: "approve" }],
		[{ action: 7 }],
		[{}],
		[[{ action: "list_tenants" }]],
	])("rejects an unknown action %j", async (body) => {
		const { handle, rpc } = await handler();
		const response = await handle(request(body));
		expect(response.status).toBe(400);
		expect(rpc).not.toHaveBeenCalled();
	});
});

describe("operator-admin actions call exactly one audited SQL wrapper", () => {
	it("configures the admission mode", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request({ action: "configure_admission_mode", mode: "onprem" }));

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			ok: true,
			action: "configure_admission_mode",
			result: { status: "configured", mode: "onprem" },
		});
		expect(rpc).toHaveBeenCalledExactlyOnceWith("operator_configure_admission_mode", {
			p_actor_user_id: ACTOR,
			p_mode: "onprem",
		});
	});

	it("configures legal documents with normalized digests and a trimmed approval reference", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request(legalBody));

		expect(response.status).toBe(200);
		expect(rpc).toHaveBeenCalledExactlyOnceWith("operator_configure_legal_documents", {
			p_actor_user_id: ACTOR,
			p_terms_version: "2026.09",
			p_terms_sha256: "a".repeat(64),
			p_terms_url: "https://aidr.example/legal/terms",
			p_privacy_version: "2026.09",
			p_privacy_sha256: PRIVACY_SHA,
			p_privacy_url: "https://aidr.example/legal/privacy",
			p_approval_reference: "LEGAL-42",
		});
	});

	it("grants a license with the actor bound server-side", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request({ ...grantBody, actor_user_id: OWNER }));

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			action: "grant_license",
			result: { status: "granted", tenant_id: TENANT, plan_id: "business", allowed_agents: 30 },
		});
		expect(rpc).toHaveBeenCalledExactlyOnceWith("operator_grant_license", {
			p_actor_user_id: ACTOR,
			p_tenant_id: TENANT,
			p_plan_id: "business",
			p_seats: 30,
			p_expires_at: FUTURE,
			p_grant_reference: "PO-2026-001",
			p_owner_user_id: null,
		});
	});

	it("passes an explicit owner for a multi-owner tenant", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request({ ...grantBody, owner_user_id: OWNER.toUpperCase() }));
		expect(response.status).toBe(200);
		expect(rpc).toHaveBeenCalledWith("operator_grant_license", expect.objectContaining({ p_owner_user_id: OWNER }));
	});

	it("revokes a license", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request({ action: "revoke_license", tenant_id: TENANT, reason: "contract ended" }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			ok: true,
			action: "revoke_license",
			result: { status: "revoked", tenant_id: TENANT },
		});
		expect(rpc).toHaveBeenCalledExactlyOnceWith("operator_revoke_license", {
			p_actor_user_id: ACTOR,
			p_tenant_id: TENANT,
			p_reason: "contract ended",
		});
	});

	it("reports an idempotent revoke of an inactive license", async () => {
		const { handle } = await handler({ rpcData: { status: "not_active" } });
		const response = await handle(request({ action: "revoke_license", tenant_id: TENANT, reason: "cleanup" }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ result: { status: "not_active" } });
	});

	it("lists tenants with a default page size and keyset cursor", async () => {
		const { handle, rpc } = await handler();
		const first = await handle(request({ action: "list_tenants" }));
		expect(first.status).toBe(200);
		expect(await first.json()).toMatchObject({ result: { next_cursor: TENANT } });
		expect(rpc).toHaveBeenLastCalledWith("operator_list_tenants", {
			p_actor_user_id: ACTOR,
			p_limit: 50,
			p_after: null,
		});

		await handle(request({ action: "list_tenants", limit: 200, after: TENANT }));
		expect(rpc).toHaveBeenLastCalledWith("operator_list_tenants", {
			p_actor_user_id: ACTOR,
			p_limit: 200,
			p_after: TENANT,
		});
	});

	it("reads one tenant's aggregate usage", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request({ action: "tenant_usage", tenant_id: TENANT }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			result: { tenant: { id: TENANT }, allowed_agents: 10, agents: { enrolled: 4, active_7d: 3 }, members: 2 },
		});
		expect(rpc).toHaveBeenCalledExactlyOnceWith("operator_tenant_usage", {
			p_actor_user_id: ACTOR,
			p_tenant_id: TENANT,
		});
	});
});

describe("operator-admin input validation happens before SQL", () => {
	it.each([
		[{ action: "configure_admission_mode", mode: "unconfigured" }, "invalid_mode"],
		[{ action: "configure_admission_mode" }, "invalid_mode"],
		[{ ...legalBody, terms: { ...legalBody.terms, sha256: "abc" } }, "invalid_legal_documents"],
		[{ ...legalBody, terms: { ...legalBody.terms, url: "http://aidr.example/terms" } }, "invalid_legal_documents"],
		[{ ...legalBody, terms: { ...legalBody.terms, url: "https://user:pw@aidr.example/terms" } }, "invalid_legal_documents"],
		[{ ...legalBody, privacy: { ...legalBody.privacy, url: "https://aidr.example/privacy#top" } }, "invalid_legal_documents"],
		[{ ...legalBody, privacy: { ...legalBody.privacy, version: "../v1" } }, "invalid_legal_documents"],
		[{ ...legalBody, approval_reference: "line\nbreak" }, "invalid_legal_documents"],
		[{ ...legalBody, approval_reference: "   " }, "invalid_legal_documents"],
		[{ ...grantBody, tenant_id: "not-a-uuid" }, "invalid_tenant"],
		[{ ...grantBody, plan_id: "Business" }, "invalid_plan"],
		[{ ...grantBody, seats: 0 }, "invalid_seats"],
		[{ ...grantBody, seats: 100_001 }, "invalid_seats"],
		[{ ...grantBody, seats: 2.5 }, "invalid_seats"],
		[{ ...grantBody, seats: "30" }, "invalid_seats"],
		[{ ...grantBody, expires_at: "2026-09-25T11:00:00Z" }, "invalid_expiry"],
		[{ ...grantBody, expires_at: "someday" }, "invalid_expiry"],
		[{ ...grantBody, reference: "x".repeat(201) }, "invalid_reference"],
		[{ ...grantBody, owner_user_id: "owner" }, "invalid_owner"],
		[{ action: "revoke_license", tenant_id: TENANT }, "invalid_reason"],
		[{ action: "revoke_license", reason: "x" }, "invalid_tenant"],
		[{ action: "list_tenants", limit: 0 }, "invalid_page"],
		[{ action: "list_tenants", limit: 201 }, "invalid_page"],
		[{ action: "list_tenants", after: "abc" }, "invalid_page"],
		[{ action: "tenant_usage" }, "invalid_tenant"],
	])("rejects %j with %s", async (body, error) => {
		const { handle, rpc } = await handler();
		const response = await handle(request(body));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error });
		expect(rpc).not.toHaveBeenCalled();
	});

	it("rejects malformed JSON after authorization", async () => {
		const { handle, rpc } = await handler();
		const response = await handle(request("{"));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_json" });
		expect(rpc).not.toHaveBeenCalled();
	});
});

describe("operator-admin SQL failures fail closed", () => {
	it.each([
		["platform_operator_forbidden", { action: "list_tenants" }, 403, "forbidden"],
		["admission_mode_immutable", { action: "configure_admission_mode", mode: "cloud" }, 409, "admission_mode_immutable"],
		["invalid_admission_mode", { action: "configure_admission_mode", mode: "cloud" }, 400, "invalid_mode"],
		["admission_mode_not_licensed", grantBody, 409, "admission_mode_not_licensed"],
		["admission_operator_forbidden", grantBody, 403, "admission_operator_required"],
		["admission_owner_forbidden", grantBody, 409, "owner_not_eligible"],
		["owner_required", grantBody, 400, "owner_required"],
		["invalid_plan", grantBody, 400, "invalid_plan"],
		["invalid_admission_grant", grantBody, 400, "invalid_grant"],
		["tenant_admission_closed", grantBody, 409, "tenant_closed"],
		["tenant_not_found", { action: "tenant_usage", tenant_id: TENANT }, 404, "tenant_not_found"],
		["invalid_admission_revocation", { action: "revoke_license", tenant_id: TENANT, reason: "x" }, 400, "invalid_reason"],
		["admission_entitlement_missing", { action: "revoke_license", tenant_id: TENANT, reason: "x" }, 503, "operator_action_unavailable"],
		["audit insert failed", legalBody, 503, "operator_action_unavailable"],
	])("maps %s", async (message, body, status, error) => {
		const { handle } = await handler({ rpcError: { message } });
		const response = await handle(request(body));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error });
	});

	it("maps a legal-document CHECK violation to a validation error", async () => {
		const { handle } = await handler({ rpcError: { message: "new row violates check constraint", code: "23514" } });
		const response = await handle(request(legalBody));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_legal_documents" });
	});

	it.each([
		["configure_admission_mode", { action: "configure_admission_mode", mode: "cloud" }, { status: "configured", mode: "pilot" }],
		["configure_legal_documents", legalBody, null],
		["grant_license", grantBody, { status: "granted", tenant_id: OWNER, plan_id: "business" }],
		["grant_license", grantBody, { status: "granted", tenant_id: TENANT, plan_id: "team" }],
		["revoke_license", { action: "revoke_license", tenant_id: TENANT, reason: "x" }, { status: "revoked", tenant_id: OWNER }],
		["list_tenants", { action: "list_tenants", limit: 1 }, { tenants: [{}, {}], next_cursor: null }],
		["list_tenants", { action: "list_tenants" }, { tenants: [], next_cursor: "nope" }],
		["tenant_usage", { action: "tenant_usage", tenant_id: TENANT }, { tenant: { id: OWNER } }],
	])("rejects a drifted %s result", async (_action, body, rpcData) => {
		const { handle } = await handler({ rpcData });
		const response = await handle(request(body));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "operator_action_unavailable" });
	});
});
