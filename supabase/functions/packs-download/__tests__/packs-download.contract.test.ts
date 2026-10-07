import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { describe, expect, it, vi } from "vitest";

const ENTRY = resolve(dirname(fileURLToPath(import.meta.url)), "..", "index.ts");
const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";
const API_KEY_ID = "33333333-3333-4333-8333-333333333333";
const KEY_HASH = createHash("sha256").update("customer-key").digest("hex");
const GRANT_SECRET = "pack-download-grant-secret-32-bytes-minimum";
type Row = Record<string, unknown>;
type Handler = (request: Request) => Promise<Response>;

function harness(options: {
	key?: Row | null;
	membership?: Row | null;
	tenant?: Row | null;
	entitlement?: Row | null;
	pack?: Row | null;
	failTable?: string;
	signError?: boolean;
	signValue?: unknown;
	fetch?: typeof fetch;
	env?: Record<string, string | undefined>;
	rateAllowed?: () => boolean;
	rateError?: boolean;
} = {}) {
	const rows: Record<string, Row | null> = {
		api_keys: options.key === undefined ? { id: API_KEY_ID, key_hash: KEY_HASH, user_id: "user-1", tenant_id: TENANT, revoked: false, scope: "tenant" } : options.key,
		tenant_members: options.membership === undefined ? { tenant_id: TENANT, user_id: "user-1", role: "member", expires_at: null } : options.membership,
		tenants: options.tenant === undefined ? { id: TENANT, status: "active" } : options.tenant,
		entitlements: options.entitlement === undefined ? { tenant_id: TENANT, premium_intel: true, premium_pkg_plugin: false } : options.entitlement,
		pack_versions: options.pack === undefined ? { pack_id: "intel", version: "1", tenant_id: TENANT, expires_at: null, storage_path: "tenant/intel-1.json" } : options.pack,
	};
	const queries: Array<{ table: string; filters: Row }> = [];
	const sign = vi.fn(async (_path: string, _ttl: number) => options.signError
		? { data: null, error: { message: "private storage failure" } }
		: { data: { signedUrl: options.signValue ?? "https://test.supabase.co/storage/v1/object/sign/aidr-packs/tenant/intel-1.json?token=storage-token" }, error: null });
	const fetchMock = options.fetch ?? vi.fn(async () => new Response("pack-bytes", {
		status: 200,
		headers: { "Content-Type": "application/vnd.aidr.pack", "Content-Length": "10", "Accept-Ranges": "bytes" },
	}));
	const rpcCalls: Array<{ name: string; args: Row }> = [];
	const db = {
		async rpc(name: string, args: Row = {}) {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") {
				if (options.rateError) return { data: null, error: { message: "rate storage unavailable" } };
				return { data: { allowed: options.rateAllowed ? options.rateAllowed() : true, remaining: 10 }, error: null };
			}
			if (name === "increment_rate_limit") return { data: null, error: null };
			if (name !== "tenant_admission_capacity") throw new Error(`Unexpected RPC: ${name}`);
			return { data: 1, error: null };
		},
		from(table: string) {
			const filters: Row = {};
			const query = {
				select(_columns: string) { return query; },
				eq(field: string, value: unknown) { filters[field] = value; return query; },
				async maybeSingle() {
					queries.push({ table, filters: { ...filters } });
					if (options.failTable === table) return { data: null, error: { message: "private database failure" } };
					const row = rows[table];
					return { data: row && Object.entries(filters).every(([field, value]) => row[field] === value) ? row : null, error: null };
				},
			};
			return query;
		},
		storage: { from: (_bucket: string) => ({ createSignedUrl: sign }) },
	};
	const env: Record<string, string | undefined> = {
		SUPABASE_URL: "https://test.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
		AIDR_PACK_DOWNLOAD_GRANT_SECRET: GRANT_SECRET,
		...options.env,
	};
	let handler: Handler | undefined;
	const loaded = new Map<string, { exports: unknown }>();
	function load(path: string): unknown {
		if (loaded.has(path)) return loaded.get(path)?.exports;
		const javascript = ts.transpileModule(readFileSync(path, "utf8"), {
			compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
		}).outputText;
		const module = { exports: {} };
		loaded.set(path, module);
		runInNewContext(javascript, {
			module, exports: module.exports,
			require: (name: string) => {
				if (name === "npm:@supabase/supabase-js@2.116.0") return { createClient: () => db };
				if (!name.startsWith(".")) throw new Error(`Unexpected import: ${name}`);
				return load(resolve(dirname(path), name));
			},
			Deno: { env: { get: (name: string) => env[name] }, serve: (value: Handler) => { handler = value; } },
			crypto: webcrypto, btoa, atob, fetch: fetchMock, URL, Request, Response, Headers, TextDecoder, TextEncoder, Uint8Array, Date, console,
		});
		return module.exports;
	}
	load(ENTRY);
	if (!handler) throw new Error("packs-download did not register a handler");
	return { handler, queries, sign, fetch: fetchMock, rows, rpcCalls };
}

function request(token: string | null = "customer-key", search = "pack_id=intel&version=1", method = "GET") {
	return new Request(`https://test.supabase.co/functions/v1/packs-download?${search}`, {
		method,
		headers: token ? { Authorization: `Bearer ${token}` } : {},
	});
}

function grantRequest(downloadUrl: string, method = "GET") {
	return new Request(downloadUrl, { method });
}

describe("packs-download customer contract", () => {
	it("charges one per-key bucket on both the grant-minting and the byte-streaming path", async () => {
		const runtime = harness();
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		const { download_url } = await response.json() as { download_url: string };
		expect((await runtime.handler(grantRequest(download_url))).status).toBe(200);
		const quota = runtime.rpcCalls.filter((call) => call.name === "consume_tenant_rate_limit");
		expect(quota.map((call) => call.args)).toEqual([
			expect.objectContaining({ p_tenant_id: TENANT, p_subject: API_KEY_ID, p_endpoint: "packs-download", p_subject_limit: 120, p_tenant_limit: 3000 }),
			expect.objectContaining({ p_tenant_id: TENANT, p_subject: API_KEY_ID, p_endpoint: "packs-download", p_subject_limit: 120, p_tenant_limit: 3000 }),
		]);
	});

	it("rejects a rate-limited key before reading entitlements or signing storage URLs, on both paths", async () => {
		let allowed = true;
		const runtime = harness({ rateAllowed: () => allowed });
		const { download_url } = await (await runtime.handler(request())).json() as { download_url: string };
		allowed = false;
		const minted = await runtime.handler(request());
		expect(minted.status).toBe(429);
		expect(await minted.json()).toEqual({ error: "rate_limited" });
		expect(minted.headers.get("Retry-After")).not.toBeNull();
		const entitlementReads = runtime.queries.filter((query) => query.table === "entitlements").length;
		const streamed = await runtime.handler(grantRequest(download_url));
		expect(streamed.status).toBe(429);
		expect(runtime.queries.filter((query) => query.table === "entitlements")).toHaveLength(entitlementReads);
	});

	it("fails closed with 503 when the per-key budget storage is unavailable, on both paths", async () => {
		const issuer = harness();
		const { download_url } = await (await issuer.handler(request())).json() as { download_url: string };
		const runtime = harness({ rateError: true });
		const minted = await runtime.handler(request());
		expect(minted.status).toBe(503);
		expect(await minted.json()).toEqual({ error: "rate_limit_unavailable" });
		expect(runtime.queries.some((query) => query.table === "entitlements")).toBe(false);
		const streamed = await runtime.handler(grantRequest(download_url));
		expect(streamed.status).toBe(503);
		expect(await streamed.json()).toEqual({ error: "rate_limit_unavailable" });
		expect(runtime.sign).not.toHaveBeenCalled();
		expect(runtime.fetch).not.toHaveBeenCalled();
	});

	it("checks the unresolved-credential budget before looking up a bearer key", async () => {
		const runtime = harness({ key: null });
		const response = await runtime.handler(request("unknown-key"));
		expect(response.status).toBe(401);
		expect(runtime.queries[0]?.table).toBe("rate_limits");
		expect(runtime.rpcCalls.map((call) => call.name)).toEqual(["increment_rate_limit"]);
	});

	it("issues an externally reachable proxy URL when database access uses an internal origin", async () => {
		const runtime = harness({ env: { SUPABASE_URL: "http://api-gw:8000", AIDR_PUBLIC_API_ORIGIN: "https://api.customer.example" } });
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		const body = await response.json() as { download_url: string };
		expect(new URL(body.download_url).origin).toBe("https://api.customer.example");
	});

	it("returns the same anonymous-download URL shape, but fetches through a revocable AIDR grant", async () => {
		const runtime = harness();
		const response = await runtime.handler(request());
		expect(response.status).toBe(200);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		const body = await response.json() as { download_url: string };
		const downloadUrl = new URL(body.download_url);
		expect(downloadUrl.origin).toBe("https://test.supabase.co");
		expect(downloadUrl.pathname).toBe("/functions/v1/packs-download");
		expect(downloadUrl.searchParams.has("grant")).toBe(true);
		expect(body.download_url).not.toContain("customer-key");
		expect(body.download_url).not.toContain(KEY_HASH);
		expect(runtime.sign).not.toHaveBeenCalled();

		const download = await runtime.handler(grantRequest(body.download_url));
		expect(download.status).toBe(200);
		expect(await download.text()).toBe("pack-bytes");
		expect(download.headers.get("Content-Type")).toBe("application/vnd.aidr.pack");
		expect(download.headers.get("Content-Length")).toBe("10");
		expect(download.headers.get("Cache-Control")).toBe("private, no-store");
		expect(download.headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(download.headers.get("Content-Disposition")).toContain("attachment");
		expect(runtime.sign).toHaveBeenCalledExactlyOnceWith("tenant/intel-1.json", 60);
		expect(runtime.fetch).toHaveBeenCalledOnce();
		expect(runtime.fetch).toHaveBeenCalledWith(
			"https://test.supabase.co/storage/v1/object/sign/aidr-packs/tenant/intel-1.json?token=storage-token",
			expect.objectContaining({ redirect: "manual", method: "GET" }),
		);
	});

	it.each([
		["revoked key", "api_keys", { id: API_KEY_ID, key_hash: KEY_HASH, user_id: "user-1", tenant_id: TENANT, revoked: true, scope: "tenant" }, 401],
		["removed membership", "tenant_members", null, 403],
		["demoted membership", "tenant_members", { tenant_id: TENANT, user_id: "user-1", role: "viewer", expires_at: null }, 403],
		["suspended tenant", "tenants", { id: TENANT, status: "suspended" }, 403],
		["premium entitlement removed", "entitlements", { tenant_id: TENANT, premium_intel: false, premium_pkg_plugin: false }, 403],
	] as const)("rechecks %s between URL issue and byte download", async (_label, table, value, status) => {
		const runtime = harness();
		const issued = await runtime.handler(request());
		const { download_url: downloadUrl } = await issued.json() as { download_url: string };
		runtime.rows[table] = value as Row | null;

		const response = await runtime.handler(grantRequest(downloadUrl));
		expect(response.status).toBe(status);
		expect(runtime.sign).not.toHaveBeenCalled();
		expect(runtime.fetch).not.toHaveBeenCalled();
	});

	it("streams byte ranges and forwards only the supported range headers", async () => {
		const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => new Response("bytes-2-4", {
			status: 206,
			headers: {
				"Content-Type": "application/vnd.aidr.pack",
				"Content-Length": "9",
				"Content-Range": "bytes 2-10/11",
				"Accept-Ranges": "bytes",
				"Set-Cookie": "provider-secret=hidden",
			},
		}));
		const runtime = harness({ fetch: fetchMock });
		const issued = await runtime.handler(request());
		const { download_url: downloadUrl } = await issued.json() as { download_url: string };
		const ranged = new Request(downloadUrl, { headers: { Range: "bytes=2-10", "If-Range": "\"pack-etag\"", Cookie: "browser-secret" } });
		const response = await runtime.handler(ranged);

		expect(response.status).toBe(206);
		expect(await response.text()).toBe("bytes-2-4");
		expect(response.headers.get("Content-Range")).toBe("bytes 2-10/11");
		expect(response.headers.get("Accept-Ranges")).toBe("bytes");
		expect(response.headers.get("Set-Cookie")).toBeNull();
		const init = fetchMock.mock.calls[0]?.[1];
		expect(new Headers(init?.headers).get("Range")).toBe("bytes=2-10");
		expect(new Headers(init?.headers).get("If-Range")).toBe("\"pack-etag\"");
		expect(new Headers(init?.headers).get("Cookie")).toBeNull();
	});

	it("does not follow provider redirects or sign a URL outside the configured Storage origin", async () => {
		const redirectedFetch = vi.fn(async () => new Response(null, { status: 302, headers: { Location: "https://attacker.example.test/" } }));
		const runtime = harness({ fetch: redirectedFetch });
		const issued = await runtime.handler(request());
		const { download_url: downloadUrl } = await issued.json() as { download_url: string };
		expect((await runtime.handler(grantRequest(downloadUrl))).status).toBe(502);

		const foreign = harness({ signValue: "https://attacker.example.test/storage/v1/object/sign/aidr-packs/file?token=x" });
		const issuedForeign = await foreign.handler(request());
		const { download_url: foreignUrl } = await issuedForeign.json() as { download_url: string };
		expect((await foreign.handler(grantRequest(foreignUrl))).status).toBe(502);
		expect(foreign.fetch).not.toHaveBeenCalled();
	});

	it("rejects tampered grants before any authorization or storage work", async () => {
		const runtime = harness();
		const issued = await runtime.handler(request());
		const { download_url: downloadUrl } = await issued.json() as { download_url: string };
		const tampered = new URL(downloadUrl);
		const grant = tampered.searchParams.get("grant")!;
		tampered.searchParams.set("grant", `${grant.slice(0, -1)}x`);
		expect((await runtime.handler(grantRequest(tampered.toString()))).status).toBe(401);
		expect(runtime.queries.filter((query) => query.table === "api_keys")).toHaveLength(1);
		expect(runtime.sign).not.toHaveBeenCalled();
	});

	it("rejects non-GET, missing credentials and missing coordinates before database access", async () => {
		for (const [req, status] of [[request(null, undefined, "POST"), 405], [request(null), 401], [request("customer-key", "pack_id=intel"), 400]] as const) {
			const runtime = harness();
			expect((await runtime.handler(req)).status).toBe(status);
			expect(runtime.queries).toEqual([]);
			expect(runtime.sign).not.toHaveBeenCalled();
		}
	});

	it("denies invalid or revoked keys and inactive tenant membership", async () => {
		for (const [options, status] of [
			[{ key: null }, 401],
			[{ key: { key_hash: KEY_HASH, user_id: "user-1", tenant_id: TENANT, revoked: true, scope: "tenant" } }, 401],
			[{ membership: null }, 403],
			[{ membership: { tenant_id: TENANT, user_id: "user-1", role: "viewer", expires_at: null } }, 403],
			[{ membership: { tenant_id: TENANT, user_id: "user-1", role: "member", expires_at: "2000-01-01T00:00:00Z" } }, 403],
			[{ tenant: { id: TENANT, status: "suspended" } }, 403],
			[{ tenant: { id: TENANT, status: "closing" } }, 403],
			[{ tenant: { id: TENANT, status: "closed" } }, 403],
		] as const) {
			const runtime = harness(options);
			expect((await runtime.handler(request())).status).toBe(status);
			expect(runtime.queries.some((query) => query.table === "entitlements")).toBe(false);
			expect(runtime.sign).not.toHaveBeenCalled();
		}
	});

	it("refuses an ingest-only Browser Guard key before any budget, entitlement or Storage work", async () => {
		const runtime = harness({
			key: {
				id: API_KEY_ID,
				key_hash: KEY_HASH,
				user_id: "user-1",
				tenant_id: TENANT,
				revoked: false,
				scope: "ingest:browser_guard",
				install_limit: 50,
			},
		});
		const response = await runtime.handler(request());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "api_key_scope_denied" });
		expect(runtime.rpcCalls.filter((call) => call.name === "consume_tenant_rate_limit")).toEqual([]);
		expect(runtime.queries.some((query) => query.table === "entitlements")).toBe(false);
		expect(runtime.sign).not.toHaveBeenCalled();
	});

	it("refuses a grant whose key was re-typed ingest-only before streaming", async () => {
		const runtime = harness();
		const issued = await runtime.handler(request());
		const { download_url: downloadUrl } = await issued.json() as { download_url: string };
		runtime.rows.api_keys = { ...runtime.rows.api_keys, scope: "ingest:browser_guard", install_limit: 50 };
		const response = await runtime.handler(grantRequest(downloadUrl));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "api_key_scope_denied" });
		expect(runtime.fetch).not.toHaveBeenCalled();
	});

	it("denies unpaid access and never queries a pack", async () => {
		const runtime = harness({ entitlement: { tenant_id: TENANT, premium_intel: false, premium_pkg_plugin: false } });
		const response = await runtime.handler(request());
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "premium_required" });
		expect(runtime.queries.some((query) => query.table === "pack_versions")).toBe(false);
		expect(runtime.sign).not.toHaveBeenCalled();
	});

	it("does not sign another tenant's pack", async () => {
		const runtime = harness({ pack: { pack_id: "intel", version: "1", tenant_id: OTHER_TENANT, expires_at: null, storage_path: "other/private.json" } });
		const response = await runtime.handler(request());
		expect(response.status).toBe(404);
		expect(await response.json()).toEqual({ error: "pack_not_found" });
		expect(runtime.sign).not.toHaveBeenCalled();
	});

	it("allows a shared pack and either paid entitlement", async () => {
		const runtime = harness({
			entitlement: { tenant_id: TENANT, premium_intel: false, premium_pkg_plugin: true },
			pack: { pack_id: "intel", version: "1", tenant_id: null, expires_at: "2099-01-01T00:00:00.000Z", storage_path: "shared/intel-1.json" },
		});
		expect((await runtime.handler(request())).status).toBe(200);
		expect(runtime.sign).not.toHaveBeenCalled();
	});

	it("does not sign expired or malformed pack rows", async () => {
		for (const patch of [
			{ expires_at: "2000-01-01T00:00:00.000Z" },
			{ expires_at: "invalid" },
			{ tenant_id: undefined },
			{ storage_path: "" },
		]) {
			const runtime = harness({ pack: { pack_id: "intel", version: "1", tenant_id: TENANT, expires_at: null, storage_path: "tenant/intel-1.json", ...patch } });
			const response = await runtime.handler(request());
			expect(response.status).toBe(404);
			expect(await response.json()).toEqual({ error: "pack_not_found" });
			expect(runtime.sign).not.toHaveBeenCalled();
		}
	});

	it("does not grant a signed URL beyond the pack's expiry", async () => {
		const expiresAt = new Date(Date.now() + 30_000).toISOString();
		const runtime = harness({ pack: { pack_id: "intel", version: "1", tenant_id: TENANT, expires_at: expiresAt, storage_path: "tenant/intel-1.json" } });
		expect((await runtime.handler(request())).status).toBe(200);
		const body = await (await runtime.handler(request())).json() as { download_url: string };
		const grant = new URL(body.download_url).searchParams.get("grant");
		expect(grant).toBeTruthy();
		expect(runtime.sign).not.toHaveBeenCalled();
	});

	it("fails closed on database and Storage failures without exposing provider details", async () => {
		for (const options of [{ failTable: "api_keys" }, { failTable: "entitlements" }, { failTable: "pack_versions" }]) {
			const runtime = harness(options);
			const response = await runtime.handler(request());
			expect(response.status).toBeGreaterThanOrEqual(400);
			expect(JSON.stringify(await response.json())).not.toContain("private");
		}
		for (const options of [{ signError: true }, { signValue: 123 }]) {
			const runtime = harness(options);
			const issued = await runtime.handler(request());
			const { download_url: downloadUrl } = await issued.json() as { download_url: string };
			const response = await runtime.handler(grantRequest(downloadUrl));
			expect(response.status).toBeGreaterThanOrEqual(400);
			expect(JSON.stringify(await response.json())).not.toContain("private");
		}
	});

	it("reports missing server configuration before authentication", async () => {
		const runtime = harness({ env: { SUPABASE_SERVICE_ROLE_KEY: undefined } });
		const response = await runtime.handler(request());
		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "server_misconfigured", missing: ["SUPABASE_SERVICE_ROLE_KEY"] });
		expect(runtime.queries).toEqual([]);
	});

	it("fails closed when the new grant secret is absent or too short", async () => {
		for (const env of [{ AIDR_PACK_DOWNLOAD_GRANT_SECRET: undefined }, { AIDR_PACK_DOWNLOAD_GRANT_SECRET: "short" }]) {
			const runtime = harness({ env });
			const response = await runtime.handler(request());
			expect(response.status).toBe(500);
			expect(JSON.stringify(await response.json())).not.toContain(GRANT_SECRET);
			expect(runtime.queries).toEqual([]);
		}
	});
});
