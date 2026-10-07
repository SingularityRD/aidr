import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { verifyEd25519CanonicalJson } from "../../../packages/core/src/managed.ts";
import { type PolicyHighWater, policyBodySequence, verifySignedPolicy } from "../../../packages/core/src/policy-signature.ts";

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => { throw new Error("policy signature test requires an injected database"); },
}));

(globalThis as unknown as { Deno: unknown }).Deno = {
	env: { get: (name: string) => process.env[name] },
	serve: () => undefined,
};

const { createPolicyHandler } = await import("../policy/index.ts");
const { canonicalJson, policySequence, resolvePolicySigning, signRuntimePolicyEnvelope } = await import("../_shared/policy-signature.ts");

const URL = "https://project.supabase.co/functions/v1/policy";
const TENANT = "22222222-2222-4222-8222-222222222222";
const USER = "11111111-1111-4111-8111-111111111111";
const AGENT = "44444444-4444-4444-8444-444444444444";
const TOKEN = "aidr-policy-signature-key";
const POLICY = { command_default: "ask" };
const PUBLISHED = "2026-10-01T12:00:00.000Z";
const NOW = new Date("2026-10-05T12:00:00.000Z");

function keypair() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return {
		pkcs8B64: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
		publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}
const POLICY_KEY = keypair();
const OTHER_KEY = keypair();
const ENTITLEMENT_KEY = keypair();

function database(options: { agentBound?: boolean; updatedAt?: string | null; publishedAt?: string } = {}) {
	const bound = options.agentBound ?? false;
	function from(table: string) {
		const query = {
			select: (_columns: string) => query,
			eq: (_column: string, _value: unknown) => query,
			maybeSingle: async () => {
				switch (table) {
					case "api_keys": return { data: { id: "key-1", user_id: USER, tenant_id: TENANT, agent_id: bound ? AGENT : null, revoked: false, scope: "tenant", install_limit: null }, error: null };
					case "tenant_members": return { data: { role: "member", expires_at: null }, error: null };
					case "tenants": return { data: { status: "active" }, error: null };
					case "agent_policy_assignments": return { data: { version: 4, assigned_at: options.publishedAt ?? PUBLISHED }, error: null };
					case "runtime_policy_revisions": return { data: { version: 4, policy: POLICY, created_at: "2026-09-01T00:00:00.000Z" }, error: null };
					case "tenant_runtime_policies": return { data: { version: 3, policy: POLICY, ...(options.updatedAt === null ? {} : { updated_at: options.updatedAt ?? options.publishedAt ?? PUBLISHED }) }, error: null };
					default: throw new Error(`unexpected relation ${table}`);
				}
			},
		};
		return query;
	}
	const rpc = async (name: string) => {
		if (name === "tenant_admission_capacity") return { data: 1, error: null };
		// No AI governance bans: the response carries no overlay.
		if (name === "ai_governance_policy_overlay") return { data: { mcp_deny_servers: [], mcp_require_approval_servers: [] }, error: null };
		return { data: { allowed: true, remaining: 299 }, error: null };
	};
	return { from, rpc };
}

async function fetchPolicy(options: Parameters<typeof database>[0] = {}, now: Date = NOW) {
	const response = await createPolicyHandler({ db: database(options) as never, now: () => now })(
		new Request(URL, { headers: { Authorization: `Bearer ${TOKEN}` } }),
	);
	return { response, body: (await response.json()) as Record<string, unknown> };
}

function verify(body: Record<string, unknown>, extra: { keys?: string[]; now?: number; highWater?: PolicyHighWater | null; revoked?: string[] } = {}) {
	return verifySignedPolicy({
		body,
		publicKeysPem: extra.keys ?? [POLICY_KEY.publicPem],
		now: extra.now ?? NOW.getTime(),
		revokedKeyIds: new Set(extra.revoked ?? []),
		highWater: extra.highWater ?? null,
	});
}

function useSigningKey(keyId = "policy-2026-10", pair = POLICY_KEY) {
	vi.stubEnv("AIDR_POLICY_SIGNING_KEY_ID", keyId);
	vi.stubEnv("AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64", pair.pkcs8B64);
}

beforeEach(() => {
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
	for (const name of ["AIDR_POLICY_SIGNING_KEY_ID", "AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64", "AIDR_POLICY_SIGNATURE_TTL_HOURS", "AIDR_ENTITLEMENT_SIGNING_KEY_ID", "AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64"]) vi.stubEnv(name, "");
});
afterEach(() => vi.unstubAllEnvs());

describe("canonicalisation parity with packages/core", () => {
	const corpus: unknown[] = [
		{ b: 1, a: 2 },
		{ z: { y: [3, { d: 1, c: 2 }], x: null }, a: "text" },
		{ "é": 1, e: 2, "Z": 3, "a": 4, "10": 5, "9": 6 },
		{ nested: [[{ b: 1, a: [] }]], flag: true, n: -0.5, s: "quote\"slash\\ nl\n" },
		{ "\u{1F600}": 1, "ﬁ": 2, "Ａ": 3 },
		{ schema_version: 1, key_id: "k", policy_version: "4", policy_sha256: "a".repeat(64), sequence: 1791201600000, issued_at: "2026-10-05T12:00:00.000Z", expires_at: "2026-10-06T12:00:00.000Z", tenant_id: TENANT },
		[],
		"scalar",
	];

	it("produces bytes core accepts under an Ed25519 signature for every corpus value", async () => {
		const { createPrivateKey, sign } = await import("node:crypto");
		const key = createPrivateKey({ key: Buffer.from(POLICY_KEY.pkcs8B64, "base64"), format: "der", type: "pkcs8" });
		for (const value of corpus) {
			const sig = sign(null, Buffer.from(canonicalJson(value), "utf8"), key).toString("base64");
			expect(verifyEd25519CanonicalJson({ value, sig_b64: sig, public_keys_pem: [POLICY_KEY.publicPem] }), JSON.stringify(value)).toBe(true);
		}
	});

	it("is not trivially satisfied: a different serialisation does not verify", async () => {
		const { createPrivateKey, sign } = await import("node:crypto");
		const key = createPrivateKey({ key: Buffer.from(POLICY_KEY.pkcs8B64, "base64"), format: "der", type: "pkcs8" });
		const value = { b: 1, a: 2 };
		const sig = sign(null, Buffer.from(JSON.stringify(value), "utf8"), key).toString("base64");
		expect(verifyEd25519CanonicalJson({ value, sig_b64: sig, public_keys_pem: [POLICY_KEY.publicPem] })).toBe(false);
	});
});

describe("signing configuration", () => {
	const reader = (values: Record<string, string>) => (name: string) => values[name];

	it("serves unsigned only when no key is configured", () => {
		expect(resolvePolicySigning(reader({}))).toEqual({ ok: true, config: null });
	});

	it("uses a dedicated policy key, falling back to the entitlement key", () => {
		const policy = resolvePolicySigning(reader({ AIDR_POLICY_SIGNING_KEY_ID: "p", AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64: "AA==", AIDR_ENTITLEMENT_SIGNING_KEY_ID: "e", AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: "BB==" }));
		expect(policy).toMatchObject({ ok: true, config: { keyId: "p", ttlHours: 24 } });
		const fallback = resolvePolicySigning(reader({ AIDR_ENTITLEMENT_SIGNING_KEY_ID: "e", AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: "BB==", AIDR_POLICY_SIGNATURE_TTL_HOURS: "48" }));
		expect(fallback).toMatchObject({ ok: true, config: { keyId: "e", ttlHours: 48 } });
	});

	it("fails closed on half-configured pairs and invalid TTLs", () => {
		for (const env of [
			{ AIDR_POLICY_SIGNING_KEY_ID: "p" },
			{ AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64: "AA==" },
			{ AIDR_ENTITLEMENT_SIGNING_KEY_ID: "e" },
			{ AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: "BB==" },
			{ AIDR_POLICY_SIGNATURE_TTL_HOURS: "0" },
			{ AIDR_POLICY_SIGNATURE_TTL_HOURS: "721" },
			{ AIDR_POLICY_SIGNATURE_TTL_HOURS: "abc" },
		]) {
			expect(resolvePolicySigning(reader(env)), JSON.stringify(env)).toEqual({ ok: false, error: "policy_signing_unavailable" });
		}
	});

	it("derives the sequence from the latest publish timestamp", () => {
		expect(policySequence("2026-10-01T00:00:00.000Z", "2026-10-02T00:00:00.000Z", undefined)).toBe(Date.parse("2026-10-02T00:00:00.000Z"));
		expect(policySequence(undefined, null, "not a date")).toBeNull();
	});

	it("refuses to sign with an unusable key or sequence", async () => {
		const input = { tenantId: TENANT, policyVersion: "1", policySha256: "a".repeat(64), now: NOW };
		expect(await signRuntimePolicyEnvelope({ ...input, sequence: 5 }, { keyId: "k", pkcs8B64: "not-a-key", ttlHours: 24 })).toBeNull();
		expect(await signRuntimePolicyEnvelope({ ...input, sequence: 0 }, { keyId: "k", pkcs8B64: POLICY_KEY.pkcs8B64, ttlHours: 24 })).toBeNull();
	});
});

describe("policy endpoint signed envelope verified by core verifySignedPolicy", () => {
	it("serves an unsigned policy when no key is configured", async () => {
		const { response, body } = await fetchPolicy();
		expect(response.status).toBe(200);
		expect(body.policy_signed).toBeUndefined();
		expect(verify(body)).toEqual({ ok: false, reason: "missing_signature" });
	});

	it("serves a signature core accepts, bound to digest, version, tenant and publish time", async () => {
		useSigningKey();
		const { response, body } = await fetchPolicy();
		expect(response.status).toBe(200);
		const result = verify(body);
		expect(result).toMatchObject({ ok: true, envelope: { schema_version: 1, key_id: "policy-2026-10", policy_version: "3", policy_sha256: body.policy_sha256, sequence: Date.parse(PUBLISHED), tenant_id: TENANT, issued_at: NOW.toISOString(), expires_at: "2026-10-06T12:00:00.000Z" } });
		expect(policyBodySequence(body)).toEqual({ sequence: Date.parse(PUBLISHED), policySha256: body.policy_sha256 });
	});

	it("signs an agent-bound policy with the latest of revision and assignment time", async () => {
		useSigningKey();
		const { body } = await fetchPolicy({ agentBound: true, publishedAt: "2026-10-03T00:00:00.000Z" });
		expect(body.agent_bound).toBe(true);
		expect(verify(body)).toMatchObject({ ok: true, envelope: { policy_version: "4", sequence: Date.parse("2026-10-03T00:00:00.000Z") } });
	});

	it("falls back to the entitlement key when no policy key is set", async () => {
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "ent-1");
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", ENTITLEMENT_KEY.pkcs8B64);
		const { body } = await fetchPolicy();
		expect(verify(body, { keys: [ENTITLEMENT_KEY.publicPem] })).toMatchObject({ ok: true, envelope: { key_id: "ent-1" } });
		expect(verify(body, { keys: [POLICY_KEY.publicPem] })).toEqual({ ok: false, reason: "bad_signature" });
	});

	it("prefers the dedicated policy key over the entitlement key", async () => {
		useSigningKey();
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "ent-1");
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", ENTITLEMENT_KEY.pkcs8B64);
		const { body } = await fetchPolicy();
		expect(verify(body)).toMatchObject({ ok: true, envelope: { key_id: "policy-2026-10" } });
	});

	it("honours the configured validity window", async () => {
		useSigningKey();
		vi.stubEnv("AIDR_POLICY_SIGNATURE_TTL_HOURS", "2");
		const { body } = await fetchPolicy();
		expect(verify(body)).toMatchObject({ ok: true, envelope: { expires_at: "2026-10-05T14:00:00.000Z" } });
	});

	it("is rejected by core when tampered", async () => {
		useSigningKey();
		const { body } = await fetchPolicy();
		const signed = body.policy_signed as { sig_b64: string; envelope: Record<string, unknown> };
		expect(verify({ ...body, policy_sha256: "b".repeat(64) })).toEqual({ ok: false, reason: "binding_mismatch" });
		expect(verify({ ...body, policy_version: "99" })).toEqual({ ok: false, reason: "binding_mismatch" });
		expect(verify({ ...body, policy_signed: { ...signed, envelope: { ...signed.envelope, sequence: 1 } } })).toEqual({ ok: false, reason: "bad_signature" });
		expect(verify({ ...body, policy_signed: { ...signed, envelope: { ...signed.envelope, expires_at: "2030-01-01T00:00:00.000Z" } } })).toEqual({ ok: false, reason: "bad_signature" });
		const flipped = Buffer.from(signed.sig_b64, "base64");
		flipped[0] ^= 0xff;
		expect(verify({ ...body, policy_signed: { ...signed, sig_b64: flipped.toString("base64") } })).toEqual({ ok: false, reason: "bad_signature" });
	});

	it("is rejected by core under the wrong key, a revoked key id, and outside the validity window", async () => {
		useSigningKey();
		const { body } = await fetchPolicy();
		expect(verify(body, { keys: [OTHER_KEY.publicPem] })).toEqual({ ok: false, reason: "bad_signature" });
		expect(verify(body, { keys: [OTHER_KEY.publicPem, POLICY_KEY.publicPem] }).ok).toBe(true);
		expect(verify(body, { revoked: ["policy-2026-10"] })).toEqual({ ok: false, reason: "key_revoked" });
		expect(verify(body, { now: NOW.getTime() + 24 * 3_600_000 })).toEqual({ ok: false, reason: "expired" });
		expect(verify(body, { now: NOW.getTime() - 10 * 60_000 })).toEqual({ ok: false, reason: "not_yet_valid" });
	});

	it("advances the sequence on re-publish so core refuses the older signed policy", async () => {
		useSigningKey();
		const older = (await fetchPolicy({ publishedAt: "2026-10-01T12:00:00.000Z" })).body;
		const newer = (await fetchPolicy({ publishedAt: "2026-10-04T12:00:00.000Z" })).body;
		const high = policyBodySequence(newer);
		expect(verify(newer, { highWater: high }).ok).toBe(true);
		expect(verify(older, { highWater: high })).toEqual({ ok: false, reason: "rollback" });
		// Same sequence with a different digest is a conflicting replay.
		expect(verify(older, { highWater: { sequence: policyBodySequence(older)?.sequence ?? 0, policySha256: "c".repeat(64) } })).toEqual({ ok: false, reason: "rollback" });
		expect(verify(older, { highWater: policyBodySequence(older) }).ok).toBe(true);
	});

	it("fails closed with 503 on a half-configured policy key, before authentication or any query", async () => {
		for (const name of ["AIDR_POLICY_SIGNING_KEY_ID", "AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64"]) {
			vi.stubEnv("AIDR_POLICY_SIGNING_KEY_ID", "");
			vi.stubEnv("AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64", "");
			vi.stubEnv(name, name.endsWith("KEY_ID") ? "policy-2026-10" : POLICY_KEY.pkcs8B64);
			const { response, body } = await fetchPolicy();
			expect(response.status).toBe(503);
			expect(body).toEqual({ error: "policy_signing_unavailable" });
		}
	});

	it("fails closed with 503 on a half-configured entitlement key fallback, an unusable key or a missing publish time", async () => {
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "ent-1");
		expect((await fetchPolicy()).response.status).toBe(503);
		vi.stubEnv("AIDR_ENTITLEMENT_SIGNING_KEY_ID", "");
		vi.stubEnv("AIDR_POLICY_SIGNING_KEY_ID", "policy-2026-10");
		vi.stubEnv("AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64", Buffer.from("not a key").toString("base64"));
		const unusable = await fetchPolicy();
		expect(unusable.response.status).toBe(503);
		expect(unusable.body).toEqual({ error: "policy_signing_unavailable" });
		useSigningKey();
		const unstamped = await fetchPolicy({ updatedAt: null });
		expect(unstamped.response.status).toBe(503);
		expect(unstamped.body).toEqual({ error: "policy_signing_unavailable" });
	});
});
