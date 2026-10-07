import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const createClient = vi.hoisted(() => vi.fn());
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient }));

type Handler = (request: Request) => Promise<Response>;
type Row = Record<string, unknown>;
const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";
const KEY = "customer-api-key";
const KEY_HASH = createHash("sha256").update(KEY).digest("hex");
const GRANT_SECRET = "pack-download-grant-secret-32-bytes-minimum";
let handle: Handler;

function pack(packId: string, tenantId: string | null): Row {
	return {
		pack_id: packId,
		version: "1.0.0",
		tenant_id: tenantId,
		storage_path: `${packId}/1.0.0.pack`,
		manifest_json: { pack_id: packId, version: "1.0.0" },
		manifest_sig_b64: "signed-manifest",
		key_id: "publisher-1",
		issued_at: "2026-09-23T00:00:00Z",
		expires_at: null,
	};
}

function database(options: {
		key?: Row | null;
		membership?: Row | null;
		tenant?: Row | null;
		entitlement?: Row | null;
		packs?: unknown;
		failTable?: string;
		failSigning?: boolean;
	} = {}) {
	const rows: Record<string, unknown> = {
		api_keys: options.key === undefined
			? [{ id: "33333333-3333-4333-8333-333333333333", key_hash: KEY_HASH, user_id: "user-1", tenant_id: TENANT, revoked: false }]
			: options.key ? [options.key] : [],
		tenant_members: options.membership === undefined
			? [{ user_id: "user-1", tenant_id: TENANT, role: "member", expires_at: null }]
			: options.membership ? [options.membership] : [],
		tenants: options.tenant === undefined
			? [{ id: TENANT, status: "active" }]
			: options.tenant ? [options.tenant] : [],
		entitlements: options.entitlement === undefined
			? [{ tenant_id: TENANT, premium_intel: true, premium_pkg_plugin: false }]
			: options.entitlement ? [options.entitlement] : [],
		pack_versions: options.packs === undefined
			? [pack("shared", null), pack("private", TENANT), pack("foreign", OTHER_TENANT)]
			: options.packs,
	};
	const queries: Array<{ table: string; filters: Record<string, unknown>; or: string | null; limit: number | null }> = [];
	const createSignedUrl = vi.fn(async (path: string, ttl: number) => options.failSigning
		? { data: null, error: { message: "private storage failure" } }
		: { data: { signedUrl: `https://storage.example.test/${path}?token=short-lived` }, error: null });
	const client = {
		async rpc(name: string) {
			if (name === "increment_rate_limit") return { data: null, error: null };
			if (name !== "tenant_admission_capacity") throw new Error(`Unexpected RPC: ${name}`);
			return { data: 1, error: null };
		},
		from(table: string) {
			const filters: Record<string, unknown> = {};
			let or: string | null = null;
			let limit: number | null = null;
			const query = {
				select: () => query,
				eq(column: string, value: unknown) { filters[column] = value; return query; },
				or(value: string) { or = value; return query; },
				order: () => query,
				limit(value: number) { limit = value; return query; },
				async maybeSingle() {
					const result = await run();
					return { ...result, data: Array.isArray(result.data) ? result.data[0] ?? null : result.data };
				},
				then(resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) {
					return run().then(resolve, reject);
				},
			};
			async function run() {
				queries.push({ table, filters: { ...filters }, or, limit });
				if (options.failTable === table) return { data: null, error: { message: "private database failure" } };
				const source = rows[table];
				if (!Array.isArray(source)) return { data: source, error: null };
				let selected = source.filter((row: Row) => Object.entries(filters).every(([name, value]) => row[name] === value));
				if (or) {
					expect(or).toBe(`tenant_id.is.null,tenant_id.eq.${TENANT}`);
					selected = selected.filter((row: Row) => row.tenant_id === null || row.tenant_id === TENANT);
				}
				return { data: limit === null ? selected : selected.slice(0, limit), error: null };
			}
			return query;
		},
		storage: { from: vi.fn((bucket: string) => {
			expect(bucket).toBe("aidr-packs");
			return { createSignedUrl };
		}) },
	};
	createClient.mockReturnValue(client);
	return { queries, createSignedUrl };
}

function request(method = "GET", bearer: string | null = KEY) {
	return new Request("https://project.supabase.co/functions/v1/packs-manifest", {
		method,
		headers: bearer ? { Authorization: `Bearer ${bearer}` } : {},
	});
}

beforeAll(async () => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-key");
	vi.stubEnv("AIDR_PACK_DOWNLOAD_GRANT_SECRET", GRANT_SECRET);
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => process.env[name] },
		serve: (handler: Handler) => { handle = handler; },
	});
	await import("../packs-manifest/index.ts");
});

beforeEach(() => {
	createClient.mockReset();
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-key");
	vi.stubEnv("AIDR_PACK_DOWNLOAD_GRANT_SECRET", GRANT_SECRET);
});

afterAll(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
});

describe("packs manifest handler", () => {
	it("requires configuration, GET and a bearer key before opening a database", async () => {
		const wrongMethod = await handle(request("POST"));
		expect(wrongMethod.status).toBe(405);
		const missingKey = await handle(request("GET", null));
		expect(missingKey.status).toBe(401);
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "");
		const misconfigured = await handle(request());
		expect(misconfigured.status).toBe(500);
		expect(await misconfigured.json()).toEqual({ error: "server_misconfigured", missing: ["SUPABASE_SERVICE_ROLE_KEY"] });
		expect(createClient).not.toHaveBeenCalled();
	});

	it("rejects revoked keys and inactive tenant membership without signing", async () => {
		let db = database({ key: { key_hash: KEY_HASH, user_id: "user-1", tenant_id: TENANT, revoked: true } });
		expect((await handle(request())).status).toBe(401);
		expect(db.createSignedUrl).not.toHaveBeenCalled();
		db = database({ membership: { user_id: "user-1", tenant_id: TENANT, role: "viewer", expires_at: null } });
		expect((await handle(request())).status).toBe(403);
		expect(db.createSignedUrl).not.toHaveBeenCalled();
		for (const options of [
			{ membership: null },
			{ membership: { user_id: "user-1", tenant_id: TENANT, role: "member", expires_at: "2000-01-01T00:00:00Z" } },
			{ tenant: { id: TENANT, status: "closing" } },
			{ tenant: { id: TENANT, status: "closed" } },
		]) {
			db = database(options);
			expect((await handle(request())).status).toBe(403);
			expect(db.createSignedUrl).not.toHaveBeenCalled();
		}
	});

	it("returns no managed packs without premium entitlement", async () => {
		const db = database({ entitlement: { tenant_id: TENANT, premium_intel: false, premium_pkg_plugin: false } });
		const response = await handle(request());
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, packs: [] });
		expect(db.queries.some((query) => query.table === "pack_versions")).toBe(false);
		expect(db.createSignedUrl).not.toHaveBeenCalled();
	});

	it("returns only public and caller-tenant packs with scoped AIDR download URLs", async () => {
		const db = database();
		const response = await handle(request());
		expect(response.status).toBe(200);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		const body = await response.json() as { packs: Array<{ pack_id: string; download_url: string }> };
		expect(body.packs.map((item) => item.pack_id)).toEqual(["shared", "private"]);
		expect(body.packs.every((item) => item.download_url.startsWith("https://project.supabase.co/functions/v1/packs-download?grant="))).toBe(true);
		expect(body.packs.every((item) => !item.download_url.includes(KEY) && !item.download_url.includes(KEY_HASH))).toBe(true);
		expect(db.createSignedUrl).not.toHaveBeenCalled();
		expect(db.queries.find((query) => query.table === "entitlements")?.filters).toEqual({ tenant_id: TENANT });
		expect(db.queries.find((query) => query.table === "pack_versions")?.limit).toBe(50);
	});

	it("uses the declared public API origin when the database origin is internal", async () => {
		vi.stubEnv("SUPABASE_URL", "http://api-gw:8000");
		vi.stubEnv("AIDR_PUBLIC_API_ORIGIN", "https://api.customer.example");
		database();
		const response = await handle(request());
		expect(response.status).toBe(200);
		const body = await response.json() as { packs: Array<{ download_url: string }> };
		expect(body.packs.length).toBeGreaterThan(0);
		expect(body.packs.every((item) => new URL(item.download_url).origin === "https://api.customer.example")).toBe(true);
	});

	it("does not sign expired or malformed-expiry packs", async () => {
		const expired = pack("expired", null);
		expired.expires_at = new Date(Date.now() - 60_000).toISOString();
		const malformed = pack("malformed", TENANT);
		malformed.expires_at = "invalid-date";
		const ambiguousTenant = pack("ambiguous-tenant", TENANT);
		ambiguousTenant.tenant_id = undefined;
		const active = pack("active", TENANT);
		active.expires_at = new Date(Date.now() + 60_000).toISOString();
		const db = database({ packs: [expired, malformed, ambiguousTenant, active] });
		const response = await handle(request());
		expect(response.status).toBe(200);
		expect((await response.json() as { packs: Array<{ pack_id: string }> }).packs.map((item) => item.pack_id)).toEqual(["active"]);
		expect(db.createSignedUrl).not.toHaveBeenCalled();
	});

	it("fails closed when the download-grant secret is missing or too short", async () => {
		vi.stubEnv("AIDR_PACK_DOWNLOAD_GRANT_SECRET", "");
		let response = await handle(request());
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
		expect(createClient).not.toHaveBeenCalled();

		vi.stubEnv("AIDR_PACK_DOWNLOAD_GRANT_SECRET", "too-short");
		response = await handle(request());
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ error: "server_misconfigured" });
		expect(createClient).not.toHaveBeenCalled();
		vi.stubEnv("AIDR_PACK_DOWNLOAD_GRANT_SECRET", GRANT_SECRET);
	});

	it("reports database failures without a successful empty manifest", async () => {
		let db = database({ failTable: "entitlements" });
		let response = await handle(request());
		expect(response.status).toBe(500);
		expect(db.createSignedUrl).not.toHaveBeenCalled();
		db = database({ failTable: "pack_versions" });
		response = await handle(request());
		expect(response.status).toBe(500);
		expect(db.createSignedUrl).not.toHaveBeenCalled();
	});
});
