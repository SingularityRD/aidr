import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyDelegatedCredential } from "../../../packages/core/src/delegated-credential.js";
import {
	canonicalDelegatedJson,
	matchesDelegatedContext,
	signDelegatedCredential,
	verifyDelegatedCredentialForBroker,
} from "../_shared/delegated-credential.ts";

const keyPair = generateKeyPairSync("ed25519");
const privateKey = keyPair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
const publicKey = keyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
const now = 1_800_000_000;
const claims = {
	version: 1 as const,
	issuer: "https://control.aidr.example",
	subjectUserId: "11111111-1111-4111-8111-111111111111",
	tenantId: "22222222-2222-4222-8222-222222222222",
	agentId: "33333333-3333-4333-8333-333333333333",
	tool: { serverId: "github-mcp", name: "repository.write" },
	resource: { type: "repository", id: "acme/payments" },
	audience: "https://github-mcp.acme.internal",
	scopes: ["contents:read", "contents:write"],
	issuedAt: now,
	notBefore: now,
	expiresAt: now + 300,
	tokenId: "44444444-4444-4444-8444-444444444444",
	delegationDepth: 0,
};

describe("Edge broker and core delegated credential contract", () => {
	it("produces an Ed25519 token accepted by the core with exact context binding", async () => {
		const signed = await signDelegatedCredential({
			claims,
			keyId: "test-k1",
			privateKeyPkcs8Base64: privateKey,
		});
		expect(signed.claimsSha256).toMatch(/^[a-f0-9]{64}$/);
		expect(canonicalDelegatedJson(signed.claims)).toBe(canonicalDelegatedJson(claims));
		expect(
			verifyDelegatedCredential({
				token: signed.token,
				publicKeysById: { "test-k1": publicKey },
				context: {
					issuer: claims.issuer,
					audience: claims.audience,
					tenantId: claims.tenantId,
					subjectUserId: claims.subjectUserId,
					agentId: claims.agentId,
					tool: claims.tool,
					resource: claims.resource,
					requiredScopes: ["contents:write"],
					now: now + 10,
				},
			}).ok,
		).toBe(true);
	});

	it("rejects signature tampering, expiry and issuer substitution at the broker", async () => {
		const signed = await signDelegatedCredential({ claims, keyId: "test-k1", privateKeyPkcs8Base64: privateKey });
		const parts = signed.token.split(".");
		const changedPayload = Buffer.from(canonicalDelegatedJson({ ...claims, audience: "https://evil.example" })).toString("base64url");
		expect((await verifyDelegatedCredentialForBroker({ token: `${parts[0]}.${changedPayload}.${parts[2]}`, keyId: "test-k1", publicKeySpkiBase64: publicKey, issuer: claims.issuer, nowSeconds: now + 1 })).ok).toBe(false);
		expect(await verifyDelegatedCredentialForBroker({ token: signed.token, keyId: "test-k1", publicKeySpkiBase64: publicKey, issuer: claims.issuer, nowSeconds: claims.expiresAt })).toEqual({ ok: false, error: "expired_token" });
		expect(await verifyDelegatedCredentialForBroker({ token: signed.token, keyId: "test-k1", publicKeySpkiBase64: publicKey, issuer: "https://other.example", nowSeconds: now + 1 })).toEqual({ ok: false, error: "invalid_token" });
	});

	it("requires tool, resource, audience and every requested scope during introspection", () => {
		const exact = {
			audience: claims.audience,
			tool: { server_id: claims.tool.serverId, name: claims.tool.name },
			resource: claims.resource,
			required_scopes: ["contents:write"],
		};
		expect(matchesDelegatedContext(claims, exact)).toBe(true);
		expect(matchesDelegatedContext(claims, { ...exact, audience: "https://other.example" })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, tool: { ...exact.tool, name: "repository.delete" } })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, resource: { ...exact.resource, id: "acme/other" } })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, required_scopes: ["administration:write"] })).toBe(false);
	});
});

describe("delegated credential persistence boundary", () => {
	const here = dirname(fileURLToPath(import.meta.url));
	const migration = readFileSync(resolve(here, "../../migrations/20260912000010_delegated_credentials.sql"), "utf8");
	const handler = readFileSync(resolve(here, "../delegated-credentials/index.ts"), "utf8");

	it("keeps grants and receipts service-only", () => {
		expect(migration).toContain("revoke all on public.delegated_credential_grants, public.delegated_credential_receipts from public, anon, authenticated");
		expect(migration).toContain("grant all on public.delegated_credential_grants, public.delegated_credential_receipts to service_role");
		expect(migration).not.toMatch(/grant\s+(?:insert|update|delete|all).*delegated_credential_(?:grants|receipts).*authenticated/i);
	});

	it("rechecks membership on issue, child delegation and every introspection", () => {
		const checks = migration.match(/app\.active_delegation_member\(/g) ?? [];
		expect(checks.length).toBeGreaterThanOrEqual(4);
		expect(migration).toContain("not(v_scopes <@ v_grant.scopes)");
		expect(migration).toContain("v_parent.delegation_depth+1>v_grant.max_delegation_depth");
		expect(migration).toContain("v_parent.claims<>p_parent_claims");
	});

	it("activates a token only after signing and supports grant-wide revocation", () => {
		expect(migration).toContain("state='active',claims_sha256=p_claims_sha256");
		expect(migration).toContain("state='reserved' and claims=p_claims");
		expect(migration).toContain("set state='revoked',revoked_at=coalesce(revoked_at,now()) where grant_id=p_grant_id");
		expect(handler).toContain('db.rpc("finalize_delegated_credential"');
		expect(handler).toContain('db.rpc("validate_delegated_credential"');
		expect(handler).toContain('response.headers.set("Cache-Control", "no-store")');
	});

	it("provides an audited tenant-bound path from an observed token to its root grant", () => {
		expect(migration).toContain("create function public.read_delegated_credential_lineage");
		expect(migration).toContain("where r.token_id=p_token_id and r.tenant_id=p_tenant_id");
		expect(migration).toContain("m.role in ('owner','admin','support_jit')");
		expect(migration).toContain("'delegated_credential.lineage_read'");
		expect(handler).toContain('body.action === "lineage"');
		expect(handler).toContain('db.rpc("read_delegated_credential_lineage"');
	});

	it("checks the authenticated human session and tenant MFA before every privileged RPC", () => {
		const verifiedUser = handler.indexOf("await db.auth.getUser(bearer)");
		const barrier = handler.indexOf("await checkIdentityBarrier(db, bearer, auth.user.id, body.tenant_id)");
		const privilegedRpcs = [
			'"create_delegated_credential_grant"',
			'"revoke_delegated_credential_grant"',
			'"read_delegated_credential_lineage"',
			'"reserve_delegated_credential"',
		];
		expect(verifiedUser).toBeGreaterThan(0);
		expect(barrier).toBeGreaterThan(verifiedUser);
		expect(handler).toContain("!uuid(body.tenant_id)");
		for (const rpc of privilegedRpcs) expect(handler.indexOf(rpc)).toBeGreaterThan(barrier);
		expect(handler).toContain("if (!identity.ok) return corsJson(req, identity.status, { error: identity.error })");
	});

	it("keeps signed broker-token introspection and redelegation ahead of JWT session handling", () => {
		const signedTokenPath = handler.indexOf('body.action === "introspect" || body.action === "redelegate"');
		const signedVerification = handler.indexOf("await verifyDelegatedCredentialForBroker(");
		const humanSession = handler.indexOf("await db.auth.getUser(bearer)");
		expect(signedTokenPath).toBeGreaterThan(0);
		expect(signedVerification).toBeGreaterThan(signedTokenPath);
		expect(humanSession).toBeGreaterThan(signedVerification);
		expect(handler.slice(signedTokenPath, humanSession)).not.toContain("checkIdentityBarrier(");
	});
});
