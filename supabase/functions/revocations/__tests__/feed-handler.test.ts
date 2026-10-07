import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const runtime = vi.hoisted(() => ({
	client: null as unknown,
	handler: null as unknown,
	feedReads: 0,
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: () => runtime.client }));

const tenantId = "11111111-1111-4111-8111-111111111111";
const userId = "22222222-2222-4222-8222-222222222222";

async function feedWithSigningKey(privateKey: string, options: { previousHashExpiresAt?: string; revoked?: boolean; rateAllowed?: boolean; admission?: number; scope?: string } = {}) {
	runtime.feedReads = 0;
	runtime.client = {
		rpc: async (name: string) => name === "tenant_admission_capacity"
			? { data: options.admission ?? 1, error: null }
			: { data: { allowed: options.rateAllowed !== false, remaining: 100 }, error: null },
		from(table: string) {
			if (table === "revocations") {
				runtime.feedReads += 1;
				return {
				select: () => ({ or: () => ({ order: () => ({
					limit: async () => ({ data: [], count: 0, error: null }),
				}) }) }),
				};
			}
			const row = table === "api_keys"
				? { user_id: userId, tenant_id: tenantId, revoked: options.revoked === true,
					scope: options.scope ?? "tenant",
					previous_hash: createHash("sha256").update("enrolled-key").digest("hex"),
					previous_hash_expires_at: options.previousHashExpiresAt }
				: table === "tenant_members"
					? { role: "owner", expires_at: null }
					: { status: "active" };
			let lookupColumn = "";
			const query = {
				eq: (column: string) => { lookupColumn = column; return query; },
				maybeSingle: async () => ({ data: table === "api_keys" && options.previousHashExpiresAt && lookupColumn === "key_hash" ? null : row, error: null }),
			};
			return { select: () => query };
		},
	};
	const env: Record<string, string> = {
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role",
		AIDR_REVOCATION_SIGNING_KEY_ID: "test-key",
		AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: privateKey,
	};
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => env[name] },
		serve: (handler: unknown) => { runtime.handler = handler; },
	});
	vi.resetModules();
	await import("../index.ts");
	return (runtime.handler as (req: Request) => Promise<Response>)(new Request(
		"https://project.supabase.co/functions/v1/revocations",
		{ headers: { Authorization: "Bearer enrolled-key" } },
	));
}

describe("revocation feed signing", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
	});

	it("returns a signed feed when configured with a valid Ed25519 key", async () => {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const key = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
		const response = await feedWithSigningKey(key);
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body).toMatchObject({
			revocations_signed: {
				alg: "ed25519",
				key_id: "test-key",
				payload: { revocations: { artifact_ids: [], pack_ids: [] } },
			},
		});
		expect(verify(
			null,
			Buffer.from(JSON.stringify(body.revocations_signed.payload)),
			publicKey,
			Buffer.from(body.revocations_signed.sig_b64, "base64"),
		)).toBe(true);
	});

	it("refuses an ingest-only Browser Guard key without serving the feed", async () => {
		const { privateKey } = generateKeyPairSync("ed25519");
		const key = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
		const response = await feedWithSigningKey(key, { scope: "ingest:browser_guard" });
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "api_key_scope_denied" });
	});

	it("fails when a configured key cannot sign, without a successful null feed", async () => {
		const response = await feedWithSigningKey("invalid-pkcs8");
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "revocation_signing_unavailable" });
	});

	it("keeps a retired API key able to refresh revocations only during its overlap", async () => {
		const { privateKey } = generateKeyPairSync("ed25519");
		const key = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
		const expiresAt = new Date(Date.now() + 60_000).toISOString();
		expect((await feedWithSigningKey(key, { previousHashExpiresAt: expiresAt })).status).toBe(200);
		for (const options of [
			{ previousHashExpiresAt: "2000-01-01T00:00:00.000Z" },
			{ previousHashExpiresAt: expiresAt, revoked: true },
		]) {
			const response = await feedWithSigningKey(key, options);
			expect(response.status).toBe(401);
			expect(await response.json()).toEqual({ error: "invalid_api_key" });
			expect(runtime.feedReads).toBe(0);
		}
	});

	it("checks admission and tenant rate limits before reading or signing the feed", async () => {
		for (const options of [{ admission: 0 }, { rateAllowed: false }]) {
			const response = await feedWithSigningKey("unused", options);
			expect(response.status).toBe(options.admission === 0 ? 403 : 429);
			expect(runtime.feedReads).toBe(0);
		}
	});
});
