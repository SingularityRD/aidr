import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	canonicalDelegatedCredentialJson,
	type DelegatedCredentialClaimsV1,
	type DelegatedCredentialVerificationContext,
	delegationDoesNotEscalate,
	verifyDelegatedCredential,
} from "../delegated-credential.js";

const keyPair = generateKeyPairSync("ed25519");
const publicKey = keyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64");

const baseClaims: DelegatedCredentialClaimsV1 = {
	version: 1,
	issuer: "https://control.aidr.example",
	subjectUserId: "11111111-1111-4111-8111-111111111111",
	tenantId: "22222222-2222-4222-8222-222222222222",
	agentId: "33333333-3333-4333-8333-333333333333",
	tool: { serverId: "github-mcp", name: "repository.write" },
	resource: { type: "repository", id: "acme/payments" },
	audience: "https://github-mcp.acme.internal",
	scopes: ["contents:read", "contents:write"],
	issuedAt: 1_800_000_000,
	notBefore: 1_800_000_000,
	expiresAt: 1_800_000_300,
	tokenId: "44444444-4444-4444-8444-444444444444",
	delegationDepth: 0,
};

const context = {
	issuer: baseClaims.issuer,
	audience: baseClaims.audience,
	tenantId: baseClaims.tenantId,
	subjectUserId: baseClaims.subjectUserId,
	agentId: baseClaims.agentId,
	tool: baseClaims.tool,
	resource: baseClaims.resource,
	requiredScopes: ["contents:write"],
	now: 1_800_000_100,
};

function encode(value: unknown): string {
	return Buffer.from(canonicalDelegatedCredentialJson(value)).toString("base64url");
}

function tokenFor(claims: DelegatedCredentialClaimsV1, keyId = "test-k1"): string {
	const header = encode({ alg: "EdDSA", typ: "aidr-delegation+jwt", kid: keyId, version: 1 });
	const payload = encode(claims);
	const signature = sign(null, Buffer.from(`${header}.${payload}`, "ascii"), keyPair.privateKey);
	return `${header}.${payload}.${signature.toString("base64url")}`;
}

function verify(
	claims: DelegatedCredentialClaimsV1,
	overrides: Partial<DelegatedCredentialVerificationContext> = {},
) {
	return verifyDelegatedCredential({
		token: tokenFor(claims),
		publicKeysById: { "test-k1": publicKey },
		context: { ...context, ...overrides },
	});
}

describe("delegated credential verification", () => {
	it("accepts an exact, signed user-agent-tool-resource lineage", () => {
		const result = verify(baseClaims);
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.keyId).toBe("test-k1");
			expect(result.claims.tokenId).toBe(baseClaims.tokenId);
		}
	});

	it.each([
		["audience_mismatch", { audience: "https://other.example" }],
		["identity_mismatch", { agentId: "55555555-5555-4555-8555-555555555555" }],
		["tool_mismatch", { tool: { ...baseClaims.tool, name: "repository.delete" } }],
		["resource_mismatch", { resource: { ...baseClaims.resource, id: "acme/other" } }],
		["scope_insufficient", { requiredScopes: ["administration:write"] }],
	] as const)("rejects context reuse: %s", (code, override) => {
		expect(verify(baseClaims, override)).toEqual({ ok: false, code });
	});

	it("rejects expiry without extending authority by clock skew", () => {
		expect(verify(baseClaims, { now: baseClaims.expiresAt })).toEqual({
			ok: false,
			code: "token_expired",
		});
	});

	it("rejects invalid verification time and numeric limits instead of bypassing authority bounds", () => {
		const expired = { ...baseClaims, expiresAt: context.now - 1 };
		const overlong = { ...baseClaims, expiresAt: baseClaims.issuedAt + 901 };
		const future = {
			...baseClaims,
			issuedAt: context.now + 100,
			notBefore: context.now + 100,
			expiresAt: context.now + 200,
		};
		const child = {
			...baseClaims,
			tokenId: "55555555-5555-4555-8555-555555555555",
			delegationDepth: 1,
			parentTokenId: baseClaims.tokenId,
		};
		for (const [claims, overrides] of [
			[expired, { now: Number.NaN }],
			[expired, { now: new Date(Number.NaN) }],
			[future, { clockSkewSeconds: Number.NaN }],
			[overlong, { maxLifetimeSeconds: Number.NaN }],
			[child, { maxDelegationDepth: Number.NaN }],
		] as const) {
			expect(verify(claims, overrides)).toEqual({ ok: false, code: "invalid_context" });
		}
	});

	it("requires a concrete scope before authorizing a tool call", () => {
		expect(verify(baseClaims, { requiredScopes: [] })).toEqual({
			ok: false,
			code: "invalid_context",
		});
		expect(verify(baseClaims, { tool: undefined })).toEqual({
			ok: false,
			code: "invalid_context",
		});
	});

	it("rejects tokens with an excessive lifetime or depth", () => {
		expect(verify({ ...baseClaims, expiresAt: baseClaims.issuedAt + 901 })).toEqual({
			ok: false,
			code: "token_lifetime_exceeded",
		});
		const child = {
			...baseClaims,
			tokenId: "55555555-5555-4555-8555-555555555555",
			delegationDepth: 1,
			parentTokenId: baseClaims.tokenId,
		};
		expect(verify(child, { maxDelegationDepth: 0 })).toEqual({
			ok: false,
			code: "delegation_depth_exceeded",
		});
	});

	it("rejects a modified payload and an unknown signing key", () => {
		const token = tokenFor(baseClaims);
		const parts = token.split(".");
		const modified = tokenFor({ ...baseClaims, scopes: ["administration:write"] }).split(".")[1];
		expect(
			verifyDelegatedCredential({
				token: `${parts[0]}.${modified}.${parts[2]}`,
				publicKeysById: { "test-k1": publicKey },
				context,
			}),
		).toEqual({ ok: false, code: "invalid_signature" });
		expect(verifyDelegatedCredential({ token, publicKeysById: {}, context })).toEqual({
			ok: false,
			code: "unknown_signing_key",
		});
		const inheritedNameToken = tokenFor(baseClaims, "constructor");
		expect(
			verifyDelegatedCredential({ token: inheritedNameToken, publicKeysById: {}, context }),
		).toEqual({ ok: false, code: "unknown_signing_key" });
	});

	it("rejects an RSA key even when Node accepts its signature with a null algorithm", () => {
		const rsa = generateKeyPairSync("rsa", { modulusLength: 512 });
		const header = encode({ alg: "EdDSA", typ: "aidr-delegation+jwt", kid: "rsa-k1", version: 1 });
		const payload = encode(baseClaims);
		const signature = sign("sha256", Buffer.from(`${header}.${payload}`, "ascii"), rsa.privateKey);
		const token = `${header}.${payload}.${signature.toString("base64url")}`;
		const rsaPublicKey = rsa.publicKey.export({ format: "der", type: "spki" }).toString("base64");
		expect(
			verifyDelegatedCredential({ token, publicKeysById: { "rsa-k1": rsaPublicKey }, context }),
		).toEqual({ ok: false, code: "unknown_signing_key" });
	});

	it("requires canonical payloads and rejects ambiguous extra claims", () => {
		const header = encode({ alg: "EdDSA", typ: "aidr-delegation+jwt", kid: "test-k1", version: 1 });
		const nonCanonicalJson = JSON.stringify({ ...baseClaims, unexpected: true });
		const payload = Buffer.from(nonCanonicalJson).toString("base64url");
		const signature = sign(null, Buffer.from(`${header}.${payload}`, "ascii"), keyPair.privateKey);
		expect(
			verifyDelegatedCredential({
				token: `${header}.${payload}.${signature.toString("base64url")}`,
				publicKeysById: { "test-k1": publicKey },
				context,
			}),
		).toEqual({ ok: false, code: "invalid_claims" });
	});
});

describe("delegation attenuation", () => {
	const child: DelegatedCredentialClaimsV1 = {
		...baseClaims,
		scopes: ["contents:read"],
		issuedAt: baseClaims.issuedAt + 1,
		notBefore: baseClaims.notBefore + 1,
		expiresAt: baseClaims.expiresAt - 1,
		tokenId: "55555555-5555-4555-8555-555555555555",
		delegationDepth: 1,
		parentTokenId: baseClaims.tokenId,
	};

	it("accepts a shorter, narrower child", () => {
		expect(delegationDoesNotEscalate(baseClaims, child)).toBe(true);
		expect(verify(child, { requiredScopes: ["contents:read"], parentClaims: baseClaims }).ok).toBe(
			true,
		);
	});

	it.each([
		{ scopes: ["administration:write"] },
		{ expiresAt: baseClaims.expiresAt + 1 },
		{ tool: { ...child.tool, name: "repository.delete" } },
		{ resource: { ...child.resource, id: "acme/other" } },
		{ audience: "https://other.example" },
		{ parentTokenId: "66666666-6666-4666-8666-666666666666" },
	])("rejects authority growth or lineage substitution: %o", (change) => {
		expect(delegationDoesNotEscalate(baseClaims, { ...child, ...change })).toBe(false);
	});
});
