import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { consumeRateLimit } from "../../_shared/rate-limit.ts";
import { createScimHandler, SCIM_AUTH_FAILURE_BUCKET, type ScimRateLimitResult, type ScimStore, type ScimTenant } from "../scim.ts";

const tenants: Record<string, ScimTenant> = {
	"token-a-with-at-least-thirty-two-bytes": { tenantId: "tenant-a", tokenId: "tok-a" },
	"token-b-with-at-least-thirty-two-bytes": { tenantId: "tenant-b", tokenId: "tok-b" },
};

function store(unavailable = false) {
	const counts = new Map<string, number>();
	let authenticated = 0;
	const impl = {
		async rateLimit(key: string, limit: number): Promise<ScimRateLimitResult> {
			if (unavailable) return { status: "unavailable", retryAfterSeconds: 5 };
			const count = (counts.get(key) ?? 0) + 1;
			counts.set(key, count);
			return count > limit ? { status: "limited", retryAfterSeconds: 17 } : { status: "allowed" };
		},
		async authenticate(token: string) { authenticated++; return tenants[token] ?? null; },
		async requireScimFeature() { return { ok: true, entitlement: {} }; },
	} as unknown as ScimStore;
	return { impl, counts, get authenticated() { return authenticated; } };
}

const get = (token: string) => new Request("https://aidr.test/functions/v1/scim/v2/ServiceProviderConfig", {
	headers: { Authorization: `Bearer ${token}` },
});

describe("SCIM rate limiting", () => {
	it("limits one tenant token with 429 and Retry-After without affecting another tenant", async () => {
		const s = store();
		const handle = createScimHandler(s.impl, { globalPerMinute: 100, perTokenPerMinute: 2 });
		expect((await handle(get("token-a-with-at-least-thirty-two-bytes"))).status).toBe(200);
		expect((await handle(get("token-a-with-at-least-thirty-two-bytes"))).status).toBe(200);
		const limited = await handle(get("token-a-with-at-least-thirty-two-bytes"));
		expect(limited.status).toBe(429);
		expect(limited.headers.get("Retry-After")).toBe("17");
		expect(limited.headers.get("Content-Type")).toContain("application/scim+json");
		expect(await limited.json()).toMatchObject({ status: "429" });
		expect((await handle(get("token-b-with-at-least-thirty-two-bytes"))).status).toBe(200);
	});

	it("bounds unauthenticated guessing by counting only failed authentications", async () => {
		const s = store();
		const handle = createScimHandler(s.impl, { globalPerMinute: 2, perTokenPerMinute: 2 });
		expect((await handle(get("wrong-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))).status).toBe(401);
		expect((await handle(get("wrong-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))).status).toBe(401);
		const limited = await handle(get("wrong-token-cccccccccccccccccccccccccccccccccc"));
		expect(limited.status).toBe(429);
		expect(limited.headers.get("Retry-After")).toBe("17");
		// Invalid credentials never create per-token counters.
		expect([...s.counts.keys()]).toEqual([SCIM_AUTH_FAILURE_BUCKET]);
	});

	it("keeps valid tenant tokens working while garbage tokens exhaust the failure bucket", async () => {
		const s = store();
		const handle = createScimHandler(s.impl, { globalPerMinute: 3, perTokenPerMinute: 5 });
		for (let attempt = 0; attempt < 20; attempt++) {
			expect([401, 429]).toContain((await handle(get(`garbage-token-${String(attempt).padStart(30, "x")}`))).status);
		}
		expect(s.counts.get(SCIM_AUTH_FAILURE_BUCKET)).toBe(20);
		expect((await handle(get("token-a-with-at-least-thirty-two-bytes"))).status).toBe(200);
		expect((await handle(get("token-b-with-at-least-thirty-two-bytes"))).status).toBe(200);
		// Successful authentications are charged to their own token only.
		expect(s.counts.get(SCIM_AUTH_FAILURE_BUCKET)).toBe(20);
		expect(s.counts.get("scim:v1:token:tok-a")).toBe(1);
		expect(s.counts.get("scim:v1:token:tok-b")).toBe(1);
	});

	it("fails closed with 503 and Retry-After when counters are unavailable", async () => {
		const s = store(true);
		const handle = createScimHandler(s.impl, { globalPerMinute: 10, perTokenPerMinute: 10 });
		const response = await handle(get("token-a-with-at-least-thirty-two-bytes"));
		expect(response.status).toBe(503);
		expect(response.headers.get("Retry-After")).toBe("5");
		const rejected = await handle(get("wrong-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
		expect(rejected.status).toBe(503);
	});

	it("is wired into the deployed entry point with validated limits", () => {
		const entry = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "..", "index.ts"), "utf8");
		expect(entry).toContain("createScimHandler(new SupabaseScimStore(db), SCIM_RATE_LIMITS)");
		expect(entry).toContain("consumeRateLimit(this.db");
		expect(entry).toContain("server_misconfigured");
	});
});

describe("shared fixed-window limiter", () => {
	function db(options: { rpcError?: boolean; count?: unknown; readError?: boolean } = {}) {
		return {
			async rpc() { return { error: options.rpcError ? { message: "x" } : null }; },
			from: () => {
				const q = { select: () => q, eq: () => q, maybeSingle: async () => ({ data: { count: options.count ?? 1 }, error: options.readError ? { message: "x" } : null }) };
				return q;
			},
		};
	}
	it("allows at the limit, limits above it, and fails closed on any storage anomaly", async () => {
		const now = Date.UTC(2026, 9, 5, 12, 0, 45);
		expect(await consumeRateLimit(db({ count: 3 }), "k", 3, now)).toEqual({ status: "allowed" });
		expect(await consumeRateLimit(db({ count: 4 }), "k", 3, now)).toEqual({ status: "limited", retryAfterSeconds: 15 });
		for (const bad of [db({ rpcError: true }), db({ readError: true }), db({ count: "3" }), db({ count: 0 })]) {
			expect((await consumeRateLimit(bad, "k", 3, now)).status).toBe("unavailable");
		}
		expect((await consumeRateLimit(db(), "k", 0, now)).status).toBe("unavailable");
	});
});
