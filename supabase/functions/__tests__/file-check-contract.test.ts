import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PackageChecker } from "../../../packages/core/src/package-checker.js";

const lookup = vi.hoisted(() => ({
	result: { data: [] as unknown[], error: null as unknown },
	authAccepted: true,
	authCalls: [] as string[],
	clientCalls: 0,
	databaseCalls: [] as string[],
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		lookup.clientCalls += 1;
		return {
		rpc: async () => {
			lookup.databaseCalls.push("rpc");
			return { data: [{ allowed: true, remaining: 599 }], error: null };
		},
		from: (table: string) => {
			lookup.databaseCalls.push(table);
			if (table !== "file_reputation") throw new Error(`unexpected table: ${table}`);
			let verifiedOnly = false;
			const query = {
				select: () => query,
				eq: (column: string, value: unknown) => {
					if (column === "provenance_verified") verifiedOnly = value === true;
					return query;
				},
				in: async () => ({
					...lookup.result,
					data: verifiedOnly && Array.isArray(lookup.result.data)
						? lookup.result.data.filter((row) => (row as { provenance_verified?: unknown }).provenance_verified === true)
						: lookup.result.data,
				}),
			};
			return query;
		},
		};
	},
}));

vi.mock("../_shared/api-key-auth.ts", () => ({
	authenticateTenantApiKey: async (_db: unknown, key: string) => {
		lookup.authCalls.push(key);
		return lookup.authAccepted
			? { ok: true, tenantId: "tenant-1", userId: "user-1" }
			: { ok: false, status: 401, error: "invalid_api_key" };
	},
}));

let handle: ((request: Request) => Promise<Response>) | undefined;
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: (handler: typeof handle) => { handle = handler; },
};
await import("../file-check/index.ts");

function request(authorization: string | null = "Bearer test-key"): Request {
	return new Request("https://project.supabase.co/functions/v1/file-check", {
		method: "POST",
		headers: { ...(authorization ? { Authorization: authorization } : {}), "Content-Type": "application/json" },
		body: JSON.stringify({ requests: [{ key: { sha256: "a".repeat(64) } }] }),
	});
}

describe("file-check reputation lookup", () => {
	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
		lookup.authAccepted = true;
		lookup.authCalls = [];
		lookup.clientCalls = 0;
		lookup.databaseCalls = [];
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.unstubAllGlobals();
		lookup.result = { data: [], error: null };
	});

	it("rejects a missing API key before creating the service-role client", async () => {
		const response = await handle?.(request(null));
		expect(response?.status).toBe(401);
		expect(await response?.json()).toEqual({ error: "missing_api_key" });
		expect(lookup.clientCalls).toBe(0);
		expect(lookup.authCalls).toEqual([]);
	});

	it("rejects an invalid API key before any reputation or quota query", async () => {
		lookup.authAccepted = false;
		const response = await handle?.(request());
		expect(response?.status).toBe(401);
		expect(await response?.json()).toEqual({ error: "invalid_api_key" });
		expect(lookup.authCalls).toEqual(["test-key"]);
		expect(lookup.databaseCalls).toEqual([]);
	});

	it("treats a database failure as an unavailable reputation leg", async () => {
		lookup.result = { data: null as unknown as unknown[], error: new Error("offline") };
		const response = await handle?.(request());
		expect(response?.status).toBe(503);
		expect(await response?.json()).toEqual({ error: "reputation_lookup_unavailable" });
	});

	it("does not classify an unlisted hash as clean", async () => {
		const response = await handle?.(request());
		expect(response?.status).toBe(503);
		expect(await response?.json()).toEqual({ error: "reputation_coverage_unavailable" });
	});

	it("answers a hash with an explicit benign reputation row", async () => {
		lookup.result = { data: [{ sha256: "a".repeat(64), provenance_verified: true, created_at: new Date().toISOString(), severity: "SEVERITY_UNKNOWN", malware_name: [] }], error: null };
		const response = await handle?.(request());
		expect(response?.status).toBe(200);
		expect(await response?.json()).toEqual({
			responses: [{ key: { sha256: "a".repeat(64) }, severity: "SEVERITY_UNKNOWN", malware_name: [] }],
		});
	});

	it("does not trust historical benign rows without verified provenance", async () => {
		lookup.result = { data: [{ sha256: "a".repeat(64), provenance_verified: false, created_at: new Date().toISOString(), severity: "SEVERITY_UNKNOWN", malware_name: [] }], error: null };
		const response = await handle?.(request());
		expect(response?.status).toBe(503);
		expect(await response?.json()).toEqual({ error: "reputation_coverage_unavailable" });
	});

	it("rejects an old benign hash row instead of returning a clean verdict", async () => {
		lookup.result = { data: [{ sha256: "a".repeat(64), provenance_verified: true, created_at: "2000-01-01T00:00:00.000Z", severity: "SEVERITY_UNKNOWN", malware_name: [] }], error: null };
		const response = await handle?.(request());
		expect(response?.status).toBe(503);
		expect(await response?.json()).toEqual({ error: "reputation_stale" });
	});

	it("rejects conflicting tenant hash rows regardless of database order", async () => {
		const hash = "a".repeat(64);
		const created_at = new Date().toISOString();
		const rows = [
			{ sha256: hash, provenance_verified: true, created_at, severity: "SEVERITY_MALWARE", malware_name: ["malware"] },
			{ sha256: hash, provenance_verified: true, created_at, severity: "SEVERITY_UNKNOWN", malware_name: [] },
		];
		for (const data of [rows, [...rows].reverse()]) {
			lookup.result = { data, error: null };
			const response = await handle?.(request());
			expect(response?.status).toBe(503);
			expect(await response?.json()).toEqual({ error: "reputation_conflict" });
		}
	});

	it("identical tenant hash rows still return the keyed classification", async () => {
		const hash = "a".repeat(64);
		const row = { sha256: hash, provenance_verified: true, created_at: new Date().toISOString(), severity: "SEVERITY_MALWARE", malware_name: ["malware"] };
		lookup.result = { data: [row, { ...row }], error: null };
		const response = await handle?.(request());
		expect(response?.status).toBe(200);
		expect(await response?.json()).toEqual({
			responses: [{ key: { sha256: hash }, severity: "SEVERITY_MALWARE", malware_name: ["malware"] }],
		});
	});

	it("carries an unlisted hash through to an unknown package verdict", async () => {
		const registry = {
			"dist-tags": { latest: "1.0.0" },
			versions: { "1.0.0": { dist: { integrity: `sha256-${Buffer.alloc(32, 0xaa).toString("base64")}` } } },
			time: { created: "2020-01-01T00:00:00.000Z" },
		};
		vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
			if (String(input).endsWith("/file-check")) return handle?.(new Request(String(input), init));
			return new Response(JSON.stringify(registry), { status: 200, headers: { "Content-Type": "application/json" } });
		}));
		const result = await new PackageChecker({
			fileCheckEndpoint: "https://project.supabase.co/functions/v1/file-check",
			apiKey: "test-key",
		}).checkSinglePackage({ name: "established-package", registry: "npm" });
		expect(result.verdict).toBe("unknown");
		expect(result.details).toContain("file reputation check is unavailable");
	});
});
