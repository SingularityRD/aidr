import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";

type StoredResult = { data: unknown; error: unknown };
type QueryCall = { table: string; filters: Record<string, unknown> };

function database(results: Record<string, StoredResult>) {
	const calls: QueryCall[] = [];
	const client = {
		from(table: string) {
			const filters: Record<string, unknown> = {};
			const builder = {
				select() {
					return builder;
				},
				eq(column: string, value: unknown) {
					filters[column] = value;
					return builder;
				},
				maybeSingle() {
					const result = results[table] ?? { data: null, error: null };
					calls.push({ table, filters: { ...filters } });
					return Promise.resolve({ ...result, filters });
				},
				then<TResult1 = StoredResult, TResult2 = never>(
					onfulfilled?: ((value: StoredResult) => TResult1 | PromiseLike<TResult1>) | null,
					onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
				) {
					return builder.maybeSingle().then(onfulfilled, onrejected);
				},
			};
			return builder;
		},
	};
	return { calls, client };
}

const activeRows: Record<string, StoredResult> = {
	api_keys: {
		data: { user_id: "user-1", tenant_id: "tenant-1", revoked: false },
		error: null,
	},
	tenant_members: { data: { expires_at: null }, error: null },
	tenants: { data: { status: "active" }, error: null },
};

describe("tenant API key authorization", () => {
	it("accepts a non-revoked key with an active tenant and membership", async () => {
		const { calls, client } = database(activeRows);
		await expect(authenticateTenantApiKey(client, "secret-key")).resolves.toEqual({
			ok: true,
			userId: "user-1",
			tenantId: "tenant-1",
		});

		const expectedHash = createHash("sha256").update("secret-key").digest("hex");
		expect(calls).toEqual([
			{ table: "api_keys", filters: { key_hash: expectedHash } },
			{
				table: "tenant_members",
				filters: { tenant_id: "tenant-1", user_id: "user-1" },
			},
			{ table: "tenants", filters: { id: "tenant-1" } },
		]);
	});

	it("preserves revoked and unknown keys as invalid credentials", async () => {
		for (const data of [null, { user_id: "user-1", tenant_id: "tenant-1", revoked: true }]) {
			const { client } = database({ ...activeRows, api_keys: { data, error: null } });
			await expect(authenticateTenantApiKey(client, "key")).resolves.toEqual({
				ok: false,
				status: 401,
				error: "invalid_api_key",
			});
		}
	});

	it("rejects a suspended tenant", async () => {
		const { client } = database({
			...activeRows,
			tenants: { data: { status: "suspended" }, error: null },
		});
		await expect(authenticateTenantApiKey(client, "key")).resolves.toEqual({
			ok: false,
			status: 403,
			error: "tenant_access_denied",
		});
	});

	it("rejects missing, expired, and malformed memberships", async () => {
		for (const data of [
			null,
			{ expires_at: "" },
			{ expires_at: "2000-01-01T00:00:00.000Z" },
			{ expires_at: "invalid" },
		]) {
			const { client } = database({ ...activeRows, tenant_members: { data, error: null } });
			await expect(authenticateTenantApiKey(client, "key", Date.parse("2026-01-01"))).resolves.toEqual({
				ok: false,
				status: 403,
				error: "tenant_access_denied",
			});
		}
	});

	it("fails closed when any authorization lookup is unavailable", async () => {
		for (const table of ["api_keys", "tenant_members", "tenants"]) {
			const { client } = database({
				...activeRows,
				[table]: { data: null, error: { message: "offline" } },
			});
			await expect(authenticateTenantApiKey(client, "key")).resolves.toEqual({
				ok: false,
				status: 503,
				error: "authorization_unavailable",
			});
		}
	});

	it.each([
		["revoked key", "api_keys", { user_id: "user-1", tenant_id: "tenant-1", revoked: true }, 401],
		["removed membership", "tenant_members", null, 403],
		["expired membership", "tenant_members", { expires_at: "2026-01-01T00:00:00.000Z" }, 403],
		["suspended tenant", "tenants", { status: "suspended" }, 403],
		["closing tenant", "tenants", { status: "closing" }, 403],
		["closed tenant", "tenants", { status: "closed" }, 403],
	] as const)("rechecks a %s on the next request", async (_reason, table, data, status) => {
		const rows = { ...activeRows };
		const { calls, client } = database(rows);
		const now = Date.parse("2026-01-01T00:00:00.000Z");
		await expect(authenticateTenantApiKey(client, "key", now)).resolves.toMatchObject({ ok: true });

		rows[table] = { data, error: null };
		await expect(authenticateTenantApiKey(client, "key", now)).resolves.toMatchObject({
			ok: false,
			status,
		});
		expect(calls.filter((call) => call.table === "api_keys")).toHaveLength(2);
	});
});

describe("reputation endpoint authorization wiring", () => {
	const functionsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

	it.each([
		["url-check", "urls.length === 0"],
		["file-check", "hashes.length === 0"],
	])("guards %s before an empty request can return success", (name, emptyRequestGuard) => {
		const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
		const handler = source.slice(source.indexOf("Deno.serve("));
		const authorization = handler.indexOf("await authenticateTenantApiKey(");
		const emptySuccess = handler.indexOf(emptyRequestGuard);

		expect(source).toContain('from "../_shared/api-key-auth.ts"');
		expect(authorization).toBeGreaterThanOrEqual(0);
		expect(emptySuccess).toBeGreaterThan(authorization);
		expect(source).not.toContain('.from("api_keys")');
	});

	it.each(["packs-manifest", "packs-download"])(
		"guards %s before reading entitlements or signing storage URLs",
		(name) => {
			const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
			const handler = source.slice(source.indexOf("Deno.serve("));
			const authorization = handler.indexOf("await authenticateTenantApiKey(");
			const entitlementRead = handler.indexOf('.from("entitlements")');
			const signing = handler.indexOf(".createSignedUrl(");

			expect(source).toContain('from "../_shared/api-key-auth.ts"');
			expect(authorization).toBeGreaterThanOrEqual(0);
			expect(entitlementRead).toBeGreaterThan(authorization);
			expect(signing).toBeGreaterThan(authorization);
			expect(source).not.toContain('.from("api_keys")');
			expect(source).toContain('"Cache-Control": "no-store"');
		},
	);
});
