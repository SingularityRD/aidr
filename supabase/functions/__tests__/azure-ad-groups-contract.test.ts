import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through AzureAdGroupsDeps.db");
	},
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SOURCE = readFileSync(join(ROOT, "supabase", "functions", "azure-ad-groups", "index.ts"), "utf8");
const { createAzureAdGroupsHandler } = await import("../azure-ad-groups/index.ts");

const TENANT = "11111111-1111-4111-8111-111111111111";
const USER = "22222222-2222-4222-8222-222222222222";
const SCIM_USER = "33333333-3333-4333-8333-333333333333";
const GROUP = "44444444-4444-4444-8444-444444444444";
const OTHER_TENANT = "55555555-5555-4555-8555-555555555555";
const OTHER_SCIM_USER = "66666666-6666-4666-8666-666666666666";
const OTHER_GROUP = "77777777-7777-4777-8777-777777777777";
const TOKEN = "session-token";

interface FakeOptions {
	requireMfa?: boolean;
	assurance?: "aal1" | "aal2";
	revokedBefore?: string | null;
	scimUserActive?: boolean;
	membershipExpiry?: unknown;
	overflowMemberships?: boolean;
	includeOtherTenant?: boolean;
}

function fakeDb(options: FakeOptions = {}) {
	const calls: string[] = [];
	const rows: Record<string, Record<string, unknown>[]> = {
		identity_user_session_state: [{ user_id: USER, revoked_before: options.revokedBefore ?? null }],
		tenant_identity_policies: [{ tenant_id: TENANT, require_mfa: options.requireMfa ?? false }],
		tenant_members: [{ tenant_id: TENANT, user_id: USER, role: "admin", expires_at: options.membershipExpiry === undefined ? null : options.membershipExpiry }],
		tenants: [{ id: TENANT, status: "active" }],
		scim_users: [{ tenant_id: TENANT, id: SCIM_USER, auth_user_id: USER, active: options.scimUserActive ?? true }],
		scim_group_memberships: [{ tenant_id: TENANT, group_id: GROUP, user_id: SCIM_USER }],
		scim_groups: [{ tenant_id: TENANT, id: GROUP, external_id: "immutable-directory-id", display_name: "Renamed Admins" }],
		scim_group_role_mappings: [{ tenant_id: TENANT, external_group_id: "immutable-directory-id", role: "admin" }],
	};
	if (options.overflowMemberships) {
		for (let i = 0; i < 501; i += 1) {
			const overflowGroup = `88888888-8888-4${i.toString(16).padStart(3, "0")}-8888-${i.toString(16).padStart(12, "0")}`;
			rows.scim_group_memberships.push({ tenant_id: TENANT, group_id: overflowGroup, user_id: SCIM_USER });
		}
	}
	if (options.includeOtherTenant) {
		rows.tenant_identity_policies.push({ tenant_id: OTHER_TENANT, require_mfa: false });
		rows.tenant_members.push({ tenant_id: OTHER_TENANT, user_id: USER, role: "viewer", expires_at: null });
		rows.tenants.push({ id: OTHER_TENANT, status: "active" });
		rows.scim_users.push({ tenant_id: OTHER_TENANT, id: OTHER_SCIM_USER, auth_user_id: USER, active: true });
		rows.scim_group_memberships.push({ tenant_id: OTHER_TENANT, group_id: OTHER_GROUP, user_id: OTHER_SCIM_USER });
		rows.scim_groups.push({ tenant_id: OTHER_TENANT, id: OTHER_GROUP, external_id: "immutable-directory-id", display_name: "Other Tenant Name" });
		rows.scim_group_role_mappings.push({ tenant_id: OTHER_TENANT, external_group_id: "immutable-directory-id", role: "viewer" });
	}

	function query(table: string) {
		const filters = new Map<string, unknown>();
		const builder = {
			select: () => builder,
			eq: (column: string, value: unknown) => { filters.set(column, value); return builder; },
			in: (column: string, values: unknown[]) => { filters.set(column, values); return builder; },
			order: () => builder,
			limit: () => builder,
			maybeSingle: async () => {
				calls.push(table);
				const result = (rows[table] ?? []).filter((row) => {
					for (const [column, expected] of filters) {
						if (Array.isArray(expected) ? !expected.includes(row[column]) : row[column] !== expected) return false;
					}
					return true;
				});
				return { data: result[0] ?? null, error: null };
			},
			then: (resolve: (value: unknown) => unknown, reject?: (error: unknown) => unknown) => {
				calls.push(table);
				const result = (rows[table] ?? []).filter((row) => {
					for (const [column, expected] of filters) {
						if (Array.isArray(expected) ? !expected.includes(row[column]) : row[column] !== expected) return false;
					}
					return true;
				});
				return Promise.resolve({ data: result, error: null }).then(resolve, reject);
			},
		};
		return builder;
	}

	return {
		calls,
		db: {
			from: (table: string) => query(table),
			auth: {
				getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })),
				mfa: {
					getAuthenticatorAssuranceLevel: vi.fn(async () => ({ data: { currentLevel: options.assurance ?? "aal1" }, error: null })),
				},
			},
		},
	};
}

function getRequest(headers: Record<string, string> = {}): Request {
	return new Request("https://control.example/functions/v1/azure-ad-groups", {
		method: "GET",
		headers: { Authorization: `Bearer ${TOKEN}`, ...headers },
	});
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
});

describe("verified SCIM group read boundary", () => {
	it("returns server-owned immutable external ids and never uses display names as ids", async () => {
		const fixture = fakeDb();
		const response = await createAzureAdGroupsHandler({ db: fixture.db as never })(getRequest());
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			user_id: USER,
			groups: [{ id: "immutable-directory-id", external_id: "immutable-directory-id", display_name: "Renamed Admins", role: "admin" }],
		});
		expect(fixture.db.auth.getUser).toHaveBeenCalledWith(TOKEN);
		expect(fixture.calls.indexOf("identity_user_session_state")).toBeLessThan(fixture.calls.indexOf("tenant_members"));
		expect(fixture.calls).not.toContain("admin_audit_logs");
	});

	it("rejects an explicit tenant without active membership", async () => {
		const fixture = fakeDb();
		const response = await createAzureAdGroupsHandler({ db: fixture.db as never })(getRequest({ "X-AIDR-Tenant-ID": "55555555-5555-4555-8555-555555555555" }));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "tenant_access_denied" });
	});

	it("keeps identical external ids tenant-scoped", async () => {
		const fixture = fakeDb({ includeOtherTenant: true });
		const all = await createAzureAdGroupsHandler({ db: fixture.db as never })(getRequest());
		expect(all.status).toBe(200);
		expect(await all.json()).toMatchObject({
			groups: [
				{ id: "immutable-directory-id", tenant_id: TENANT, display_name: "Renamed Admins", role: "admin" },
				{ id: "immutable-directory-id", tenant_id: OTHER_TENANT, display_name: "Other Tenant Name", role: "viewer" },
			],
		});
		const selected = await createAzureAdGroupsHandler({ db: fakeDb({ includeOtherTenant: true }).db as never })(getRequest({ "X-AIDR-Tenant-ID": TENANT }));
		expect(await selected.json()).toMatchObject({ groups: [{ tenant_id: TENANT }] });
	});

	it("fails closed instead of truncating an oversized membership projection", async () => {
		const fixture = fakeDb({ overflowMemberships: true });
		const response = await createAzureAdGroupsHandler({ db: fixture.db as never })(getRequest());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "verified_groups_unavailable" });
		expect(fixture.calls).not.toContain("scim_groups");
	});

	it("fails closed on a malformed membership expiry", async () => {
		const fixture = fakeDb({ membershipExpiry: 42 });
		const response = await createAzureAdGroupsHandler({ db: fixture.db as never })(getRequest());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "verified_groups_unavailable" });
		expect(fixture.calls).not.toContain("scim_users");
	});

	it("does not expose groups for a deactivated SCIM user", async () => {
		const fixture = fakeDb({ scimUserActive: false });
		const response = await createAzureAdGroupsHandler({ db: fixture.db as never })(getRequest());
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, user_id: USER, groups: [] });
	});

	it("applies the shared MFA barrier before reading SCIM tables", async () => {
		const fixture = fakeDb({ requireMfa: true });
		const response = await createAzureAdGroupsHandler({ db: fixture.db as never })(getRequest());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(fixture.calls).not.toContain("scim_users");
	});

	it("fails closed on a revoked session and rejects writes", async () => {
		const revoked = fakeDb({ revokedBefore: "2030-01-01T00:00:00.000Z" });
		const response = await createAzureAdGroupsHandler({ db: revoked.db as never })(getRequest());
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "session_revoked" });
		const write = await createAzureAdGroupsHandler({ db: revoked.db as never })(new Request("https://control.example/functions/v1/azure-ad-groups", {
			method: "POST",
			headers: { Authorization: `Bearer ${TOKEN}` },
		}));
		expect(write.status).toBe(405);
		expect(write.headers.get("Allow")).toBe("GET");
	});

	it("has a read-only deployment contract", () => {
		expect(SOURCE).toContain("checkIdentityBarrier");
		expect(SOURCE).toContain("method !== \"GET\"");
		expect(SOURCE).toContain("external_id");
		expect(SOURCE).toContain(".eq(\"active\", true)");
		const barrier = SOURCE.indexOf("checkIdentityBarrier(db, token, userId");
		const scimRead = SOURCE.indexOf('db.from("scim_users")');
		expect(barrier).toBeGreaterThanOrEqual(0);
		expect(scimRead).toBeGreaterThan(barrier);
		expect(SOURCE).not.toContain("user_metadata");
		expect(SOURCE).not.toMatch(/\.from\([^\n]+\)\.(insert|update|upsert|delete)\(/);
	});
});
