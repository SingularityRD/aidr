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
	authSessionIssuedAt: now - 60,
	tokenId: "44444444-4444-4444-8444-444444444444",
	delegationDepth: 0,
};

describe("Edge broker and core delegated credential contract", () => {
	it("requires an authenticated-session binding before signing", async () => {
		const legacyClaims: Record<string, unknown> = { ...claims };
		delete legacyClaims.authSessionIssuedAt;
		await expect(signDelegatedCredential({ claims: legacyClaims, keyId: "test-k1", privateKeyPkcs8Base64: privateKey })).rejects.toThrow("invalid_delegated_claims");
	});

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
			tenant_id: claims.tenantId,
			subject_user_id: claims.subjectUserId,
			agent_id: claims.agentId,
			audience: claims.audience,
			tool: { server_id: claims.tool.serverId, name: claims.tool.name },
			resource: claims.resource,
			required_scopes: ["contents:write"],
		};
		expect(matchesDelegatedContext(claims, exact)).toBe(true);
		expect(matchesDelegatedContext(claims, { ...exact, audience: "https://other.example" })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, tenant_id: "55555555-5555-4555-8555-555555555555" })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, subject_user_id: "55555555-5555-4555-8555-555555555555" })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, agent_id: "55555555-5555-4555-8555-555555555555" })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, tool: { ...exact.tool, name: "repository.delete" } })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, resource: { ...exact.resource, id: "acme/other" } })).toBe(false);
		expect(matchesDelegatedContext(claims, { ...exact, required_scopes: ["administration:write"] })).toBe(false);
		const { tenant_id: _tenantId, ...withoutTenant } = exact;
		expect(matchesDelegatedContext(claims, withoutTenant)).toBe(false);
	});
});

describe("delegated credential persistence boundary", () => {
	const here = dirname(fileURLToPath(import.meta.url));
	const migration = readFileSync(resolve(here, "../../migrations/20260912000010_delegated_credentials.sql"), "utf8");
	const sessionBindingMigration = readFileSync(resolve(here, "../../migrations/20260923000002_delegated_identity_session_binding.sql"), "utf8");
	const globalRevocationMigration = readFileSync(resolve(here, "../../migrations/20260922000006_identity_global_revocation_saga.sql"), "utf8");
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

	it("authorizes the tenant subject before consuming quota or doing privileged work", () => {
		expect(handler).toContain("await readBoundedText(req, 32_768)");
		expect(handler.match(/await consumeTenantRateLimit\(db, \{/g)).toHaveLength(2);
		const humanBarrier = handler.indexOf("await checkIdentityBarrier(db, bearer, auth.user.id, body.tenant_id)");
		const humanAuthorization = handler.indexOf("await authorizeHumanQuota(db, auth.user.id, body)");
		const humanRate = handler.indexOf("await consumeTenantRateLimit(db, {", humanBarrier);
		expect(humanAuthorization).toBeGreaterThan(humanBarrier);
		expect(humanRate).toBeGreaterThan(humanAuthorization);
		expect(humanRate).toBeGreaterThan(humanBarrier);
		expect(handler).toContain('.from("tenant_members")');
		expect(handler).toContain('.eq("user_id", String(body.subject_user_id))');
		expect(handler).toContain('.from("delegated_credential_grants")');
		for (const rpc of [
			'"create_delegated_credential_grant"',
			'"revoke_delegated_credential_grant"',
			'"read_delegated_credential_lineage"',
			'"reserve_delegated_credential"',
		]) expect(handler.indexOf(rpc)).toBeGreaterThan(humanRate);
	});

	it("validates signed-token context and active state before charging quota", () => {
		const signedPath = handler.indexOf('body.action === "introspect" || body.action === "redelegate"');
		const context = handler.indexOf("matchesDelegatedContext(verified.claims, body.context)", signedPath);
		const active = handler.indexOf('db.rpc("validate_delegated_credential"', signedPath);
		const rate = handler.indexOf("await consumeTenantRateLimit(db, {", signedPath);
		expect(context).toBeGreaterThan(signedPath);
		expect(active).toBeGreaterThan(context);
		expect(rate).toBeGreaterThan(active);
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

	it("binds issuance to the authenticated session, not a caller-supplied timestamp", () => {
		const verifiedUser = handler.indexOf("await db.auth.getUser(bearer)");
		const barrier = handler.indexOf("await checkIdentityBarrier(db, bearer, auth.user.id, body.tenant_id)");
		const sessionIat = handler.indexOf("jwtIssuedAtMs(bearer)");
		const reserve = handler.indexOf('db.rpc("reserve_delegated_credential"');
		const issueValidator = handler.slice(handler.indexOf("function validIssue"), handler.indexOf("function validRedelegation"));

		expect(verifiedUser).toBeGreaterThan(0);
		expect(barrier).toBeGreaterThan(verifiedUser);
		expect(sessionIat).toBeGreaterThan(barrier);
		expect(reserve).toBeGreaterThan(sessionIat);
		expect(issueValidator).not.toContain("validated_session_issued_at");
		expect(handler).toContain("validated_session_issued_at: new Date(sessionIssuedAtMs).toISOString()");
	});

	it("rejects replay of a signed delegated token after global logout or password-reset revocation", () => {
		const reserve = sessionBindingMigration.slice(
			sessionBindingMigration.indexOf("create or replace function public.reserve_delegated_credential"),
			sessionBindingMigration.indexOf("create or replace function public.reserve_child_delegated_credential"),
		);
		const child = sessionBindingMigration.slice(
			sessionBindingMigration.indexOf("create or replace function public.reserve_child_delegated_credential"),
			sessionBindingMigration.indexOf("create or replace function public.validate_delegated_credential"),
		);
		const validate = sessionBindingMigration.slice(
			sessionBindingMigration.indexOf("create or replace function public.validate_delegated_credential"),
		);
		const perUserLock = "pg_advisory_xact_lock(hashtextextended(p_user_id::text, 2611))";

		expect(globalRevocationMigration).toContain(perUserLock);
		expect(reserve).toContain("pg_advisory_xact_lock(hashtextextended(p_actor_user_id::text, 2611))");
		expect(child).toContain("pg_advisory_xact_lock(hashtextextended(v_user_id::text, 2611))");
		expect(reserve).toContain("v_session_issued_at <= v_revoked_before");
		expect(child).toContain("to_timestamp(v_session_issued_at) <= v_revoked_before");
		expect(child).toContain("'authSessionIssuedAt',v_session_issued_at");
		expect(validate).toContain("v_row.claims<>p_claims");
		expect(validate).toContain("v_revoke_pending is not null");
		expect(validate).toContain("to_timestamp(v_session_issued_at) <= v_revoked_before");
		expect(handler).toContain('db.rpc("validate_delegated_credential"');
	});
});
