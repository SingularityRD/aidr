import { describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: () => { throw new Error("unexpected client creation"); } }));

(globalThis as unknown as { Deno: unknown }).Deno = { serve: () => undefined };

const { SupabaseScimStore } = await import("../index.ts");
const { ScimConflictError, ScimInvalidValueError } = await import("../scim.ts");

const tenantA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const tenantB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const authUserId = "11111111-1111-4111-8111-111111111111";
const scimUserId = "22222222-2222-4222-8222-222222222222";
const email = "person@example.com";
const input = { externalId: "directory-person", userName: email, displayName: "Person", active: true };

function fixture(
	lookup: (tenantId: string) => string | null,
	createError = false,
	samlProviderId: string | null = null,
	recoveredUserId: string | null = null,
	failFirstBind = false,
) {
	const row: Record<string, unknown> = {
		id: scimUserId, external_id: input.externalId, user_name: email, display_name: input.displayName,
		active: true, version: 1, created_at: "2026-09-23T00:00:00Z", updated_at: "2026-09-23T00:00:00Z", auth_user_id: null,
	};
	const rpcCalls: { name: string; args: Record<string, unknown> }[] = [];
	let authUserCreated = false;
	let bindCalls = 0;
	const createUser = vi.fn(async (attributes: unknown) => {
		if (createError || authUserCreated) return { data: { user: null }, error: { message: "User already registered" } };
		authUserCreated = true;
		return { data: { user: { id: authUserId, ...attributes as Record<string, unknown> } }, error: null };
	});
	const db = {
		from: (table: string) => {
			if (table === "tenant_identity_policies") {
				const query = { eq: () => query, maybeSingle: async () => ({ data: samlProviderId ? { required_saml_provider_id: samlProviderId } : null, error: null }) };
				return { select: () => query };
			}
			if (table !== "scim_users") throw new Error("unexpected table");
			const query = { eq: () => query, single: async () => ({ data: { ...row }, error: null }) };
			return { select: () => query };
		},
		rpc: async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "scim_claim_user") return { data: { user_id: scimUserId, created: true }, error: null };
			if (name === "scim_user_id_by_email") return {
				data: args.p_email === email ? lookup(String(args.p_tenant_id)) : null, error: null,
			};
			if (name === "scim_recover_unbound_auth_user") return {
				data: authUserCreated && args.p_tenant_id === tenantA && args.p_scim_user_id === scimUserId && args.p_email === email ? recoveredUserId : null,
				error: null,
			};
			if (name === "scim_bind_user") {
				bindCalls++;
				if (failFirstBind && bindCalls === 1) return { data: null, error: { code: "08006", message: "temporary database connection failure" } };
				row.auth_user_id = args.p_auth_user_id;
				return { data: null, error: null };
			}
			throw new Error("unexpected RPC");
		},
		auth: { admin: { createUser } },
	};
	return { store: new SupabaseScimStore(db as never), rpcCalls, createUser };
}

describe("SCIM auth identity binding", () => {
	it("leaves a SAML tenant user pending without email lookup or Auth precreation", async () => {
		const { store, rpcCalls, createUser } = fixture(() => authUserId, false, "33333333-3333-4333-8333-333333333333");
		const result = await store.createUser(tenantA, input);
		expect(result.created).toBe(true);
		expect(createUser).not.toHaveBeenCalled();
		expect(rpcCalls.map((call) => call.name)).toEqual(["scim_claim_user"]);
	});

	it("binds an existing user in the token tenant without creating another auth user", async () => {
		const { store, rpcCalls, createUser } = fixture((tenantId) => tenantId === tenantA ? authUserId : null);
		const result = await store.createUser(tenantA, input);
		expect(result.user.userName).toBe(email);
		expect(createUser).not.toHaveBeenCalled();
		expect(rpcCalls.find((call) => call.name === "scim_bind_user")?.args).toEqual({
			p_tenant_id: tenantA, p_scim_user_id: scimUserId, p_auth_user_id: authUserId,
		});
	});

	it("recovers a same-tenant user created during a provisioning race", async () => {
		let lookups = 0;
		const { store, rpcCalls } = fixture((tenantId) => ++lookups === 1 ? null : tenantId === tenantA ? authUserId : null, true);
		await expect(store.createUser(tenantA, input)).resolves.toMatchObject({ user: { userName: email } });
		expect(rpcCalls.filter((call) => call.name === "scim_user_id_by_email").map((call) => call.args)).toEqual([
			{ p_tenant_id: tenantA, p_email: email },
			{ p_tenant_id: tenantA, p_email: email },
		]);
	});

	it("does not bind an auth user that belongs only to another tenant", async () => {
		const { store, rpcCalls } = fixture((tenantId) => tenantId === tenantB ? authUserId : null, true);
		await expect(store.createUser(tenantA, input)).rejects.toThrow("SCIM auth user creation failed");
		expect(rpcCalls.filter((call) => call.name === "scim_user_id_by_email").map((call) => call.args)).toEqual([
			{ p_tenant_id: tenantA, p_email: email },
			{ p_tenant_id: tenantA, p_email: email },
		]);
		expect(rpcCalls.filter((call) => call.name === "scim_recover_unbound_auth_user").map((call) => call.args)).toEqual([
			{ p_tenant_id: tenantA, p_scim_user_id: scimUserId, p_email: email },
			{ p_tenant_id: tenantA, p_scim_user_id: scimUserId, p_email: email },
		]);
		expect(rpcCalls.some((call) => call.name === "scim_bind_user")).toBe(false);
	});

	it("recovers a committed SCIM Auth create after the initial bind fails", async () => {
		const { store, rpcCalls, createUser } = fixture(() => null, false, null, authUserId, true);
		await expect(store.createUser(tenantA, input)).rejects.toThrow("SCIM persistence unavailable");
		expect(createUser).toHaveBeenCalledWith(expect.objectContaining({
			app_metadata: { aidr_scim_provisioned: true, aidr_scim_tenant_id: tenantA, aidr_scim_user_id: scimUserId },
		}));
		await expect(store.createUser(tenantA, input)).resolves.toMatchObject({ user: { userName: email } });
		expect(rpcCalls.filter((call) => call.name === "scim_recover_unbound_auth_user")).toHaveLength(2);
		expect(rpcCalls.filter((call) => call.name === "scim_bind_user")).toHaveLength(2);
	});
});

describe("SCIM persistence errors", () => {
	it("reports invalid references and manual membership collisions without retryable 503s", async () => {
		for (const failure of [
			{ code: "22023", message: "scim_cross_tenant_or_unknown_user", kind: ScimInvalidValueError },
			{ code: "22P02", message: "invalid input syntax for type uuid", kind: ScimInvalidValueError },
			{ code: "42501", message: "scim_cannot_take_over_manual_membership", kind: ScimConflictError },
		]) {
			const db = { rpc: async () => ({ data: null, error: failure }) };
			const store = new SupabaseScimStore(db as never);
			await expect(store.updateGroup(tenantA, scimUserId, {
				externalId: "directory-group", displayName: "Operators", members: [scimUserId],
			}, null)).rejects.toBeInstanceOf(failure.kind);
		}
	});

	it("compares the resource version while deactivating without If-Match", async () => {
		const row = {
			id: scimUserId, external_id: input.externalId, user_name: email, display_name: input.displayName,
			active: true, version: 1, created_at: "2026-09-23T00:00:00Z", updated_at: "2026-09-23T00:00:00Z",
		};
		const query = { eq: () => query, maybeSingle: async () => ({ data: row, error: null }) };
		const rpc = vi.fn(async () => ({ data: true, error: null }));
		const store = new SupabaseScimStore({ from: () => ({ select: () => query }), rpc } as never);
		await store.deactivateUser(tenantA, scimUserId, null);
		expect(rpc).toHaveBeenCalledWith("scim_update_user", expect.objectContaining({ p_expected_version: 1, p_active: false }));
	});
});
