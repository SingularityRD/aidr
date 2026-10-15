// Contract suite for the `license-admin` Edge Function (tenant side of the
// signed license import). The signature is verified server-side against the
// registry in AIDR_LICENSE_PUBLIC_KEYS_B64; a refused document never reaches
// the database, and an accepted one is only STAGED (submit_license_import).
// DEV test keys only: generated in memory for every run.

import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error JavaScript module without type declarations
import { publicKeyEntry, signLicense } from "../../../scripts/license-issue.mjs";
// @ts-expect-error JavaScript module without type declarations
import { canonicalJson } from "../../../scripts/license-verify.mjs";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through LicenseAdminDeps.client");
	},
}));

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const config = readFileSync(join(ROOT, "supabase", "config.toml"), "utf8");
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const URL_BASE = "https://project.supabase.co/functions/v1/license-admin";
const NOW = Date.parse("2027-03-01T00:00:00Z");

const devKey = generateKeyPairSync("ed25519").privateKey;
const strangerKey = generateKeyPairSync("ed25519").privateKey;
const registry = {
	format: "aidr-license-public-keys-v1",
	schema_version: 1,
	keys: [publicKeyEntry(devKey, { keyId: "dev-1", notBefore: "2026-01-01T00:00:00Z" })],
};
const REGISTRY_B64 = Buffer.from(JSON.stringify(registry)).toString("base64");

function license(overrides: Record<string, unknown> = {}, key = devKey) {
	return signLicense(
		{
			license_id: "LIC-2026-0042",
			customer: "Example Customer AG",
			customer_id: "example-ag",
			plan_id: "enterprise",
			seats: 250,
			features: ["managed_policy"],
			deployment: "onprem",
			issued_at: "2026-09-01T00:00:00Z",
			not_before: "2026-09-01T00:00:00Z",
			expires_at: "2027-09-01T00:00:00Z",
			grace_days: 14,
			...overrides,
		},
		{ privateKey: key, keyId: "dev-1" },
	);
}

interface Options {
	role?: string;
	assurance?: string;
	env?: Record<string, string>;
	rpcError?: { code: string; message?: string };
}

function database(options: Options = {}) {
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	const db = {
		auth: {
			getUser: vi.fn(async (token: string) =>
				token === "valid-token"
					? { data: { user: { id: USER } }, error: null }
					: { data: { user: null }, error: new Error("invalid") }),
			mfa: {
				getAuthenticatorAssuranceLevel: vi.fn(async () => ({
					data: { currentLevel: options.assurance ?? "aal2" },
					error: null,
				})),
			},
		},
		from(table: string) {
			const builder = {
				select: () => builder,
				eq: () => builder,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: null, error: null };
					if (table === "tenant_identity_policies") {
						return { data: { require_mfa: false, required_saml_provider_id: null }, error: null };
					}
					if (table === "tenant_members") {
						return { data: { role: options.role ?? "admin", expires_at: null }, error: null };
					}
					throw new Error(`unexpected table ${table}`);
				},
			};
			return builder;
		},
		rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
			rpcCalls.push({ name, args });
			if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 5 }, error: null };
			if (name === "submit_license_import") {
				if (options.rpcError) return { data: null, error: options.rpcError };
				return {
					data: {
						status: "pending",
						import: { id: "44444444-4444-4444-8444-444444444444", canonical_sha256: args.p_canonical_sha256 },
					},
					error: null,
				};
			}
			throw new Error(`unexpected rpc ${name}`);
		}),
	};
	return { db, rpcCalls };
}

async function handlerWith(options: Options = {}) {
	const fake = database(options);
	const mod = await import("../license-admin/index.ts");
	const env: Record<string, string> = {
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
		AIDR_LICENSE_PUBLIC_KEYS_B64: REGISTRY_B64,
		...options.env,
	};
	const handle = mod.createLicenseAdminHandler({
		env: (name) => env[name],
		client: () => fake.db as never,
		now: () => NOW,
	});
	return { ...fake, handle };
}

function post(body: unknown, token = "valid-token"): Request {
	return new Request(URL_BASE, {
		method: "POST",
		headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});
}

const submit = (document: unknown) => post({ action: "submit", tenant_id: TENANT, license: document });
const staged = (calls: Array<{ name: string }>) => calls.filter((call) => call.name === "submit_license_import");

beforeEach(() => {
	vi.stubGlobal("Deno", { env: { get: () => undefined }, serve: () => undefined });
});
afterEach(() => {
	vi.unstubAllGlobals();
	vi.resetModules();
});

describe("license-admin submit", () => {
	it("verifies the signature server-side and stages the license with its canonical digest", async () => {
		const document = license();
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(submit(document));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body).toMatchObject({
			ok: true,
			status: "pending",
			license: {
				status: "valid",
				license_id: "LIC-2026-0042",
				seats: 250,
				grace_ends_at: "2027-09-15T00:00:00.000Z",
			},
		});
		const expected = createHash("sha256").update(canonicalJson(document)).digest("hex");
		expect(staged(rpcCalls)).toEqual([
			{
				name: "submit_license_import",
				args: { p_actor_user_id: USER, p_tenant_id: TENANT, p_document: document, p_canonical_sha256: expected },
			},
		]);
	});

	it("refuses tampered, foreign-key, expired and other-customer licenses before the database", async () => {
		const valid = license();
		const cases: Array<[unknown, string, Record<string, string>?]> = [
			[{ ...valid, payload: { ...valid.payload, seats: 5000 } }, "bad_signature"],
			[license({}, strangerKey), "bad_signature"],
			[{ ...valid, key_id: "nobody-1" }, "unknown_key"],
			[license({ issued_at: "2025-06-01T00:00:00Z", not_before: "2025-06-01T00:00:00Z", expires_at: "2026-01-01T00:00:00Z" }), "key_window"],
			[license({ expires_at: "2027-01-01T00:00:00Z" }), "expired"],
			[valid, "customer_mismatch", { AIDR_LICENSE_CUSTOMER_ID: "other-customer" }],
		];
		for (const [document, reason, env] of cases) {
			const { handle, rpcCalls } = await handlerWith({ env });
			const response = await handle(submit(document));
			expect(response.status, reason).toBe(422);
			expect(await response.json(), reason).toEqual({ error: "license_rejected", reason });
			expect(staged(rpcCalls), reason).toEqual([]);
		}
	});

	it("stages a renewal that is not valid yet (it is applied later)", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(submit(license({ not_before: "2027-09-01T00:00:00Z", expires_at: "2028-09-01T00:00:00Z" })));
		expect(response.status).toBe(200);
		expect((await response.json()).license.status).toBe("not_yet_valid");
		expect(staged(rpcCalls)).toHaveLength(1);
	});

	it("fails closed without a trust registry", async () => {
		for (const [env, error] of [
			[{ AIDR_LICENSE_PUBLIC_KEYS_B64: "" }, "license_registry_unavailable"],
			[{ AIDR_LICENSE_PUBLIC_KEYS_B64: "!!" }, "license_registry_invalid"],
			[
				{ AIDR_LICENSE_PUBLIC_KEYS_B64: Buffer.from(JSON.stringify({ ...registry, keys: [] })).toString("base64") },
				"license_registry_empty",
			],
		] as const) {
			const { handle, rpcCalls } = await handlerWith({ env });
			const response = await handle(submit(license()));
			expect(response.status, error).toBe(503);
			expect(await response.json()).toEqual({ error });
			expect(staged(rpcCalls)).toEqual([]);
		}
	});

	it("is limited to owners/admins at AAL2", async () => {
		const member = await handlerWith({ role: "member" });
		expect((await member.handle(submit(license()))).status).toBe(403);
		const aal1 = await handlerWith({ assurance: "aal1" });
		const response = await aal1.handle(submit(license()));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "mfa_required" });
		expect(staged(member.rpcCalls)).toEqual([]);
		expect(staged(aal1.rpcCalls)).toEqual([]);
		const anonymous = await handlerWith();
		expect((await anonymous.handle(submit(license()).clone())).status).toBe(200);
		expect((await anonymous.handle(post({ action: "submit", tenant_id: TENANT, license: license() }, "bad"))).status).toBe(401);
	});

	it("rejects malformed requests and maps database refusals", async () => {
		const { handle } = await handlerWith();
		expect((await handle(post({ action: "apply", tenant_id: TENANT, license: license() }))).status).toBe(400);
		expect((await handle(post({ action: "submit", tenant_id: "x", license: license() }))).status).toBe(400);
		expect((await handle(post({ action: "submit", tenant_id: TENANT, license: "text" }))).status).toBe(400);
		const bound = await handlerWith({ rpcError: { code: "42501", message: "license_bound_to_other_tenant" } });
		const response = await bound.handle(submit(license()));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "license_bound_to_other_tenant" });
	});

	it("is deployed with gateway JWT verification", () => {
		expect(config).toMatch(/\[functions\.license-admin\]\n(?:#.*\n)*verify_jwt = true/);
	});
});
