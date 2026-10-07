import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
	authenticateTenantApiKey,
	authenticateTenantApiKeyBudgeted,
	DEFAULT_UNRESOLVED_API_KEY_LIMIT_PER_MINUTE,
	unresolvedApiKeyBucket,
	unresolvedApiKeyLimit,
} from "../_shared/api-key-auth.ts";

type StoredResult = { data: unknown; error: unknown };
type QueryCall = { table: string; filters: Record<string, unknown> };

function database(results: Record<string, StoredResult>, admission: StoredResult = { data: 1, error: null }) {
	const calls: QueryCall[] = [];
	const client = {
		rpc(name: string, args: Record<string, unknown>) {
			calls.push({ table: name, filters: args });
			return Promise.resolve(admission);
		},
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
		data: { user_id: "user-1", tenant_id: "tenant-1", revoked: false, scope: "tenant" },
		error: null,
	},
	tenant_members: { data: { role: "member", expires_at: null }, error: null },
	tenants: { data: { status: "active" }, error: null },
};

describe("tenant API key authorization", () => {
	it("accepts a non-revoked key with an active tenant and membership", async () => {
		const { calls, client } = database(activeRows);
		await expect(authenticateTenantApiKey(client, "secret-key")).resolves.toEqual({
			ok: true,
			userId: "user-1",
			tenantId: "tenant-1",
			scope: "tenant",
			installLimit: null,
		});

		const expectedHash = createHash("sha256").update("secret-key").digest("hex");
		expect(calls).toEqual([
			{ table: "api_keys", filters: { key_hash: expectedHash } },
			{
				table: "tenant_members",
				filters: { tenant_id: "tenant-1", user_id: "user-1" },
			},
			{ table: "tenants", filters: { id: "tenant-1" } },
			{ table: "tenant_admission_capacity", filters: { p_tenant_id: "tenant-1" } },
		]);
	});

	it("rejects an old key after trial expiry or licensed admission revocation", async () => {
		const { client } = database(activeRows, { data: 0, error: null });
		await expect(authenticateTenantApiKey(client, "key")).resolves.toEqual({
			ok: false,
			status: 403,
			error: "tenant_access_denied",
		});
	});

	it("fails closed when admission cannot be checked", async () => {
		for (const admission of [{ data: null, error: { message: "offline" } }, { data: null, error: null }]) {
			const { client } = database(activeRows, admission);
			await expect(authenticateTenantApiKey(client, "key")).resolves.toEqual({
				ok: false,
				status: 503,
				error: "authorization_unavailable",
			});
		}
	});

	it("preserves revoked and unknown keys as invalid credentials", async () => {
		for (const data of [null, { user_id: "user-1", tenant_id: "tenant-1", revoked: true, scope: "tenant" }]) {
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
			{ expires_at: null },
			{ role: "member", expires_at: "" },
			{ role: "member", expires_at: "2000-01-01T00:00:00.000Z" },
			{ role: "member", expires_at: "invalid" },
		]) {
			const { client } = database({ ...activeRows, tenant_members: { data, error: null } });
			await expect(authenticateTenantApiKey(client, "key", Date.parse("2026-01-01"))).resolves.toEqual({
				ok: false,
				status: 403,
				error: "tenant_access_denied",
			});
		}
	});

	it.each(["viewer", "support_jit"])("rejects a key after its owner is demoted to %s", async (role) => {
		const { client } = database({
			...activeRows,
			tenant_members: { data: { role, expires_at: null }, error: null },
		});
		await expect(authenticateTenantApiKey(client, "key")).resolves.toEqual({
			ok: false,
			status: 403,
			error: "tenant_access_denied",
		});
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
		["revoked key", "api_keys", { user_id: "user-1", tenant_id: "tenant-1", revoked: true, scope: "tenant" }, 401],
		["removed membership", "tenant_members", null, 403],
		["expired membership", "tenant_members", { role: "member", expires_at: "2026-01-01T00:00:00.000Z" }, 403],
		["demoted membership", "tenant_members", { role: "viewer", expires_at: null }, 403],
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

describe("unresolved API-key budget before credential lookup", () => {
	const NOW = Date.UTC(2026, 9, 7, 12, 0, 30);
	const WINDOW = Math.floor(NOW / 60_000);

	it("checks the per-endpoint budget before any key lookup and charges only unresolved keys", async () => {
		const { calls, client } = database({ rate_limits: { data: { count: 5 }, error: null } });
		const result = await authenticateTenantApiKeyBudgeted(client, "garbage", "file-check", NOW);
		expect(result).toEqual({ ok: false, status: 401, error: "invalid_api_key" });
		expect(calls[0]).toEqual({ table: "rate_limits", filters: { key: unresolvedApiKeyBucket("file-check"), window_start: WINDOW } });
		expect(calls.map((call) => call.table)).toEqual(["rate_limits", "api_keys", "api_keys", "increment_rate_limit"]);
		expect(calls.at(-1)?.filters).toEqual({ p_key: "api-key:v1:unresolved:file-check", p_window_start: WINDOW, p_delta: 1 });
	});

	it("never charges the budget for a valid key", async () => {
		const { calls, client } = database({ ...activeRows, rate_limits: { data: null, error: null } });
		await expect(authenticateTenantApiKeyBudgeted(client, "secret-key", "ingest", NOW)).resolves.toMatchObject({ ok: true });
		expect(calls.some((call) => call.table === "increment_rate_limit")).toBe(false);
	});

	it("answers 429 without any credential lookup once the budget is spent", async () => {
		const { calls, client } = database({ ...activeRows, rate_limits: { data: { count: DEFAULT_UNRESOLVED_API_KEY_LIMIT_PER_MINUTE }, error: null } });
		await expect(authenticateTenantApiKeyBudgeted(client, "secret-key", "policy", NOW))
			.resolves.toEqual({ ok: false, status: 429, error: "rate_limited" });
		expect(calls.map((call) => call.table)).toEqual(["rate_limits"]);
	});

	it.each([
		[{ data: null, error: { message: "down" } }],
		[{ data: { count: "5" }, error: null }],
		[{ data: { count: -1 }, error: null }],
		[{ data: { status: "active" }, error: null }],
	])("fails closed with 503 before any key lookup on an unreadable budget %#", async (row) => {
		const { calls, client } = database({ ...activeRows, rate_limits: row });
		await expect(authenticateTenantApiKeyBudgeted(client, "secret-key", "policy-ack", NOW))
			.resolves.toEqual({ ok: false, status: 503, error: "rate_limit_unavailable" });
		expect(calls.map((call) => call.table)).toEqual(["rate_limits"]);
	});

	it("fails closed on an invalid configured budget or endpoint name", async () => {
		expect(unresolvedApiKeyLimit("0")).toBeNull();
		expect(unresolvedApiKeyLimit("abc")).toBeNull();
		expect(unresolvedApiKeyLimit("2000000")).toBeNull();
		expect(unresolvedApiKeyLimit("")).toBe(DEFAULT_UNRESOLVED_API_KEY_LIMIT_PER_MINUTE);
		expect(unresolvedApiKeyLimit("300")).toBe(300);
		const { calls, client } = database(activeRows);
		await expect(authenticateTenantApiKeyBudgeted(client, "secret-key", "Bad Endpoint", NOW))
			.resolves.toEqual({ ok: false, status: 503, error: "rate_limit_unavailable" });
		expect(calls).toEqual([]);
	});

	it.each(["ingest", "file-check", "url-check", "policy", "policy-ack", "packs-manifest", "packs-download", "revocations"])(
		"wires %s through the budgeted guard",
		(name) => {
			const source = readFileSync(join(resolve(dirname(fileURLToPath(import.meta.url)), ".."), name, "index.ts"), "utf8");
			expect(source).toContain(`authenticateTenantApiKeyBudgeted(`);
			expect(source).toMatch(new RegExp(`authenticateTenantApiKeyBudgeted\\([^)]*"${name}"[,)]`));
		},
	);
});

describe("reputation endpoint authorization wiring", () => {
	const functionsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

	it.each([
		["url-check", "urls.length === 0"],
		["file-check", "hashes.length === 0"],
	])("guards %s before an empty request can return success", (name, emptyRequestGuard) => {
		const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
		const handler = source.slice(source.indexOf("Deno.serve("));
		const authorization = handler.indexOf("await authenticateTenantApiKeyBudgeted(");
		const emptySuccess = handler.indexOf(emptyRequestGuard);

		expect(source).toContain('from "../_shared/api-key-auth.ts"');
		expect(authorization).toBeGreaterThanOrEqual(0);
		expect(emptySuccess).toBeGreaterThan(authorization);
		expect(source).not.toContain('.from("api_keys")');
	});

	it.each(["packs-manifest", "packs-download"])(
		"guards %s before reading entitlements or issuing/fetching pack URLs",
		(name) => {
			const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
			const handler = source.slice(source.indexOf("Deno.serve("));
			const authorization = handler.indexOf("await authenticateTenantApiKeyBudgeted(");
			const entitlementRead = handler.indexOf('.from("entitlements")');
			const grant = handler.indexOf("signPackDownloadGrant(");

			expect(source).toContain('from "../_shared/api-key-auth.ts"');
			expect(authorization).toBeGreaterThanOrEqual(0);
			expect(entitlementRead).toBeGreaterThan(authorization);
			expect(grant).toBeGreaterThan(entitlementRead);
			if (name === "packs-manifest") expect(source).not.toContain('.from("api_keys")');
			else expect(source).toContain('.from("api_keys")');
			expect(source).toContain('"Cache-Control": "no-store"');
		},
	);

	it("rechecks grants and current API-key state before proxying pack bytes", () => {
		const source = readFileSync(join(functionsDir, "packs-download", "index.ts"), "utf8");
		const proxy = source.slice(source.indexOf("async function streamGrantedPack"), source.indexOf("Deno.serve("));
		expect(proxy.indexOf("readPackDownloadGrant(")).toBeGreaterThanOrEqual(0);
		expect(proxy.indexOf('from("api_keys")')).toBeGreaterThan(proxy.indexOf("readPackDownloadGrant("));
		expect(proxy.indexOf("authenticateTenantApiKeyHash(")).toBeGreaterThan(proxy.indexOf('from("api_keys")'));
		expect(proxy.indexOf('from("entitlements")')).toBeGreaterThan(proxy.indexOf("authenticateTenantApiKeyHash("));
		expect(proxy.indexOf('from("pack_versions")')).toBeGreaterThan(proxy.indexOf('from("entitlements")'));
		expect(proxy.indexOf(".createSignedUrl(")).toBeGreaterThan(proxy.indexOf('from("pack_versions")'));
	});
});

describe("ingest-only Browser Guard keys", () => {
	const browserKey = {
		id: "44444444-4444-4444-8444-444444444444",
		user_id: "user-1",
		tenant_id: "tenant-1",
		revoked: false,
		agent_id: null,
		scope: "ingest:browser_guard",
		install_limit: 250,
	};
	const browserRows = { ...activeRows, api_keys: { data: browserKey, error: null } };

	it("is refused by every endpoint that does not opt in, before tenant state is read", async () => {
		const { calls, client } = database(browserRows);
		await expect(authenticateTenantApiKey(client, "browser-key")).resolves.toEqual({
			ok: false,
			status: 403,
			error: "api_key_scope_denied",
		});
		expect(calls.map(({ table }) => table)).toEqual(["api_keys"]);
		await expect(
			authenticateTenantApiKey(client, "browser-key", Date.now(), { allowedScopes: ["tenant"] }),
		).resolves.toMatchObject({ ok: false, error: "api_key_scope_denied" });
	});

	it("authenticates for an endpoint that opts in and reports its scope and limit", async () => {
		const { client } = database(browserRows);
		await expect(
			authenticateTenantApiKey(client, "browser-key", Date.now(), {
				allowedScopes: ["tenant", "ingest:browser_guard"],
			}),
		).resolves.toEqual({
			ok: true,
			userId: "user-1",
			tenantId: "tenant-1",
			apiKeyId: browserKey.id,
			agentId: null,
			scope: "ingest:browser_guard",
			installLimit: 250,
		});
	});

	it("still applies membership, tenant and admission checks to an ingest key", async () => {
		const options = { allowedScopes: ["ingest:browser_guard"] as const };
		for (const [table, data] of [
			["tenant_members", { role: "viewer", expires_at: null }],
			["tenants", { status: "suspended" }],
		] as const) {
			const { client } = database({ ...browserRows, [table]: { data, error: null } });
			await expect(authenticateTenantApiKey(client, "k", Date.now(), options)).resolves.toMatchObject({
				ok: false,
				status: 403,
				error: "tenant_access_denied",
			});
		}
		const { client } = database(browserRows, { data: 0, error: null });
		await expect(authenticateTenantApiKey(client, "k", Date.now(), options)).resolves.toMatchObject({
			ok: false,
			error: "tenant_access_denied",
		});
	});

	it("treats a row without a known type or a coherent limit as no credential", async () => {
		const options = { allowedScopes: ["tenant", "ingest:browser_guard"] as const };
		for (const data of [
			{ ...browserKey, scope: undefined },
			{ ...browserKey, scope: "admin" },
			{ ...browserKey, install_limit: null },
			{ ...browserKey, install_limit: 0 },
			{ ...browserKey, install_limit: 1.5 },
			{ ...browserKey, scope: "tenant", install_limit: 10 },
		]) {
			const { client } = database({ ...activeRows, api_keys: { data, error: null } });
			await expect(authenticateTenantApiKey(client, "k", Date.now(), options)).resolves.toEqual({
				ok: false,
				status: 401,
				error: "invalid_api_key",
			});
		}
	});

	it("requires the key row id so the installation cap can be bound to it", async () => {
		const { id: _id, ...withoutId } = browserKey;
		const { client } = database({ ...activeRows, api_keys: { data: withoutId, error: null } });
		await expect(
			authenticateTenantApiKey(client, "k", Date.now(), { allowedScopes: ["ingest:browser_guard"] }),
		).resolves.toMatchObject({ ok: false, status: 403, error: "api_key_scope_denied" });
	});

	it("is honoured only by /v1/ingest; direct key readers refuse non-tenant keys", () => {
		const functionsDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
		const optingIn: string[] = [];
		for (const name of [
			"ingest",
			"policy",
			"policy-ack",
			"url-check",
			"file-check",
			"packs-manifest",
			"packs-download",
			"revocations",
		]) {
			const source = readFileSync(join(functionsDir, name, "index.ts"), "utf8");
			if (source.includes("allowedScopes")) optingIn.push(name);
		}
		expect(optingIn).toEqual(["ingest"]);
		// Revocations (feed and fleet commands) authenticate through the shared
		// guard, whose default scope list is tenant-only, and never read api_keys
		// directly.
		const revocations = readFileSync(join(functionsDir, "revocations", "index.ts"), "utf8");
		expect(revocations.match(/\.from\("api_keys"\)/g) ?? []).toHaveLength(0);
		expect(revocations.match(/authenticateTenantApiKey(?:Budgeted)?\(/g)).toHaveLength(2);
	});
});
