import { generateKeyPairSync, verify } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const runtime = vi.hoisted(() => ({
	client: null as unknown,
	handler: null as unknown,
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: () => runtime.client }));

const tenantId = "11111111-1111-4111-8111-111111111111";
const userId = "22222222-2222-4222-8222-222222222222";

async function feedWithSigningKey(privateKey: string) {
	runtime.client = {
		from(table: string) {
			if (table === "revocations") return {
				select: () => ({ or: () => ({ order: () => ({
					limit: async () => ({ data: [], count: 0, error: null }),
				}) }) }),
			};
			const row = table === "api_keys"
				? { user_id: userId, tenant_id: tenantId, revoked: false }
				: table === "tenant_members"
					? { role: "owner", expires_at: null }
					: { status: "active" };
			const query = { eq: () => query, maybeSingle: async () => ({ data: row, error: null }) };
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

	it("fails when a configured key cannot sign, without a successful null feed", async () => {
		const response = await feedWithSigningKey("invalid-pkcs8");
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "revocation_signing_unavailable" });
	});
});
