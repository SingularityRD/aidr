import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const USER_ID = "11111111-1111-4111-8111-111111111111";
const KEY_ID = "22222222-2222-4222-8222-222222222222";
const TOKEN_ID = "33333333-3333-4333-8333-333333333333";

const fixture = vi.hoisted(() => ({ role: "owner", count: 1, rpc: vi.fn() }));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => ({
		auth: { getUser: async () => ({ data: { user: { id: USER_ID } }, error: null }) },
		from: (table: string) => {
			const query = {
				select: () => query,
				eq: () => query,
				maybeSingle: async () => ({
					data: table === "tenant_members"
						? { tenant_id: USER_ID, role: fixture.role, expires_at: null }
						: table === "tenants"
							? { status: "active" }
							: table === "rate_limits"
								? { count: fixture.count }
								: null,
					error: null,
				}),
			};
			return query;
		},
		rpc: fixture.rpc,
	}),
}));

vi.mock("../_shared/identity-barrier.ts", () => ({
	checkIdentityBarrier: async () => ({ ok: true }),
}));

const handlers: Array<(request: Request) => Promise<Response>> = [];
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: (request: Request) => Promise<Response>) => { handlers.push(handler); },
};
await import("../api-keys/index.ts");
await import("../enrollment-tokens/index.ts");

function post(index: 0 | 1, body: Record<string, unknown>): Promise<Response> {
	const route = index === 0 ? "api-keys" : "enrollment-tokens";
	return handlers[index](new Request(`https://project.supabase.co/functions/v1/${route}`, {
		method: "POST",
		headers: {
			Authorization: "Bearer synthetic-access-token",
			"Content-Type": "application/json",
			"X-AIDR-Tenant-ID": USER_ID,
		},
		body: JSON.stringify(body),
	}));
}

describe("dashboard credential Edge actions", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "synthetic-service-role-key");
		fixture.role = "owner";
		fixture.count = 1;
		fixture.rpc.mockReset();
	});
	afterEach(() => vi.unstubAllEnvs());

	it("revokes an API key only after the audit RPC confirms the selected tenant", async () => {
		fixture.rpc.mockResolvedValue({ data: { status: "revoked" }, error: null });
		const response = await post(0, { action: "revoke", id: ` ${KEY_ID} ` });
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(fixture.rpc).toHaveBeenCalledWith("revoke_api_key_with_audit", {
			p_actor_user_id: USER_ID,
			p_tenant_id: USER_ID,
			p_id: KEY_ID,
		});
	});

	it.each([
		["not_found", 404, "key_not_found_or_not_owned"],
		["forbidden", 403, "tenant_not_authorized"],
		["conflict", 409, "key_revoke_conflict"],
	] as const)("does not claim a revoked key on %s", async (status, httpStatus, code) => {
		fixture.rpc.mockResolvedValue({ data: { status }, error: null });
		const response = await post(0, { action: "revoke", id: KEY_ID });
		expect(response.status).toBe(httpStatus);
		expect(await response.json()).toEqual({ error: code });
	});

	it("fails closed when API-key audit persistence is unavailable", async () => {
		fixture.rpc.mockResolvedValue({ data: null, error: { code: "08006" } });
		const response = await post(0, { action: "revoke", id: KEY_ID });
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "audit_unavailable" });
		expect(fixture.rpc).toHaveBeenCalledTimes(2);
	});

	it("issues an enrollment token once and sends only its hash to the audit RPC", async () => {
		fixture.rpc.mockImplementation(async (name: string) => ({
			data: name === "issue_enrollment_token_with_audit"
				? { status: "issued", expires_at: "2030-01-01T00:00:00.000Z" }
				: null,
			error: null,
		}));
		const response = await post(1, { action: "create", label: " isolated-demo ", ttl_hours: 2 });
		expect(response.status).toBe(200);
		const body = await response.json() as { ok: boolean; enrollment_token: string; expires_at: string };
		expect(body.ok).toBe(true);
		expect(body.enrollment_token).toMatch(/^aidr_enroll_[A-Za-z0-9_-]{43}$/);
		expect(body.expires_at).toBe("2030-01-01T00:00:00.000Z");
		expect(fixture.rpc).toHaveBeenCalledWith("issue_enrollment_token_with_audit", {
			p_actor_user_id: USER_ID,
			p_tenant_id: USER_ID,
			p_label: "isolated-demo",
			p_ttl_hours: 2,
			p_token_hash: createHash("sha256").update(body.enrollment_token).digest("hex"),
		});
		expect(JSON.stringify(fixture.rpc.mock.calls)).not.toContain(body.enrollment_token);
	});

	it("does not return a new enrollment token when audit persistence fails", async () => {
		fixture.rpc.mockImplementation(async (name: string) => name === "increment_rate_limit"
			? { data: null, error: null }
			: { data: null, error: { code: "08006" } });
		const response = await post(1, { action: "create" });
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "audit_unavailable" });
		expect(fixture.rpc.mock.calls.filter(([name]) => name === "issue_enrollment_token_with_audit")).toHaveLength(2);
	});

	it("deletes an enrollment token only after the audit RPC confirms it", async () => {
		fixture.rpc.mockResolvedValue({ data: { status: "deleted" }, error: null });
		const response = await post(1, { action: "delete", id: TOKEN_ID });
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(fixture.rpc).toHaveBeenCalledWith("delete_enrollment_token_with_audit", {
			p_actor_user_id: USER_ID,
			p_tenant_id: USER_ID,
			p_id: TOKEN_ID,
		});
	});

	it("does not claim token deletion when audit persistence fails", async () => {
		fixture.rpc.mockResolvedValue({ data: null, error: { code: "08006" } });
		const response = await post(1, { action: "delete", id: TOKEN_ID });
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "audit_unavailable" });
		expect(fixture.rpc).toHaveBeenCalledTimes(2);
	});

	it.each([
		["not_found", 404, "token_not_found_or_not_owned"],
		["forbidden", 403, "tenant_not_authorized"],
		["conflict", 409, "token_delete_conflict"],
	] as const)("does not claim a deleted token on %s", async (status, httpStatus, code) => {
		fixture.rpc.mockResolvedValue({ data: { status }, error: null });
		const response = await post(1, { action: "delete", id: TOKEN_ID });
		expect(response.status).toBe(httpStatus);
		expect(await response.json()).toEqual({ error: code });
	});

	it("denies viewer mutation before reaching either credential RPC", async () => {
		fixture.role = "viewer";
		for (const [index, body] of [
			[0, { action: "revoke", id: KEY_ID }],
			[1, { action: "delete", id: TOKEN_ID }],
		] as const) {
			const response = await post(index, body);
			expect(response.status).toBe(403);
			expect(await response.json()).toEqual({ error: "tenant_role_insufficient" });
		}
		expect(fixture.rpc).not.toHaveBeenCalled();
	});
});
