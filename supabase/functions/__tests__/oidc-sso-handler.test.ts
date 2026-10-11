import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createOidcHandler } from "../oidc-sso/handler.ts";
import { JwksCache } from "../oidc-sso/jwks.ts";
import { base64UrlEncode, pkceChallenge } from "../oidc-sso/oidc.ts";
import {
	baseClaims,
	caller,
	entitledPlan,
	freePlan,
	ISSUER_A,
	ISSUER_B,
	type IdpFixture,
	makeIdp,
	makeKey,
	makeWorld,
	MEMBER_A,
	mintJwt,
	NOW_MS,
	NOW_S,
	OWNER_A,
	OWNER_A2,
	OWNER_B,
	post,
	PROVIDER_A,
	PROVIDER_B,
	providerRow,
	SESSION_1,
	sha256Text,
	TENANT_A,
	TENANT_B,
	type TestKey,
	type World,
} from "./oidc-test-kit.ts";

interface Ctx {
	world: World;
	handler: (req: Request) => Promise<Response>;
	idpA: IdpFixture;
	idpB: IdpFixture;
	keyA: TestKey;
	keyB: TestKey;
}

async function call(ctx: Ctx, body: Record<string, unknown>, token?: string) {
	const response = await ctx.handler(post(body, token));
	return { status: response.status, json: (await response.json()) as Record<string, unknown> };
}

function discoveryFor(idp: IdpFixture) {
	return {
		issuer: idp.issuer,
		authorization_endpoint: idp.authorizationEndpoint,
		token_endpoint: idp.tokenEndpoint,
		jwks_uri: idp.jwksUri,
		id_token_signing_alg_values_supported: ["RS256", "ES256"],
	};
}

async function setup(): Promise<Ctx> {
	const keyA = await makeKey("RS256", "kA");
	const keyB = await makeKey("RS256", "kB");
	const idpA = makeIdp(ISSUER_A, [keyA], "https://login.microsoftonline.com");
	const idpB = makeIdp(ISSUER_B, [keyB], "https://tenant-b.okta.com");
	const idps = [idpA, idpB];
	const clock = { now: NOW_MS };
	const cache = new JwksCache({
		now: () => clock.now,
		fetchKeys: async (uri) => {
			const idp = idps.find((candidate) => candidate.jwksUri === uri);
			if (!idp) return null;
			idp.jwksFetches += 1;
			return idp.failJwks ? null : idp.keys.map((key) => key.publicJwk);
		},
	});
	const world = makeWorld({ idps, jwks: (uri, kid, alg) => cache.getKey(uri, kid, alg) });
	world.clock.now = NOW_MS;
	// Share one clock between the world and the cache.
	Object.defineProperty(world.clock, "now", { get: () => clock.now, set: (value: number) => void (clock.now = value) });
	const store = world.store;
	store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(idpA) }));
	store.providers.set(
		PROVIDER_B,
		providerRow({
			id: PROVIDER_B,
			tenant_id: TENANT_B,
			kind: "okta",
			issuer: ISSUER_B,
			client_id: "client-b",
			client_secret_ref: "TENANT_B",
			discovery: discoveryFor(idpB),
		}),
	);
	store.domains.push(
		{ tenant_id: TENANT_A, domain: "a-corp.test", verification_token: "t".repeat(40), verified_at: new Date(NOW_MS).toISOString() },
		{ tenant_id: TENANT_B, domain: "b-corp.test", verification_token: "u".repeat(40), verified_at: new Date(NOW_MS).toISOString() },
	);
	store.policies.set(TENANT_A, { required_oidc_provider_id: PROVIDER_A, required_saml_provider_id: null, break_glass_enabled: true, require_mfa: false });
	store.policies.set(TENANT_B, { required_oidc_provider_id: PROVIDER_B, required_saml_provider_id: null, break_glass_enabled: false, require_mfa: false });
	store.scimUsers.push(
		{ tenant_id: TENANT_A, external_id: "subject-1", auth_user_id: null },
		{ tenant_id: TENANT_B, external_id: "subject-1", auth_user_id: null },
	);
	store.members.set(`${TENANT_A}:${OWNER_A}`, "owner");
	store.members.set(`${TENANT_A}:${OWNER_A2}`, "owner");
	store.members.set(`${TENANT_A}:${MEMBER_A}`, "member");
	store.members.set(`${TENANT_B}:${OWNER_B}`, "owner");
	world.callers.set("owner-a", caller(OWNER_A));
	world.callers.set("owner-a-aal1", caller(OWNER_A, { assurance: "aal1" }));
	world.callers.set("member-a", caller(MEMBER_A));
	world.callers.set("owner-b", caller(OWNER_B));
	return { world, handler: createOidcHandler(world.deps), idpA, idpB, keyA, keyB };
}

interface Started {
	params: URLSearchParams;
	authorizationUrl: string;
	bindingVerifier: string;
}

async function begin(ctx: Ctx, extra: Record<string, unknown> = {}, token?: string): Promise<Started> {
	const bindingVerifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
	const result = await call(
		ctx,
		{ action: "start", provider_id: PROVIDER_A, binding_challenge: await sha256Text(bindingVerifier), ...extra },
		token,
	);
	expect(result.status, JSON.stringify(result.json)).toBe(200);
	const authorizationUrl = String(result.json.authorization_url);
	return { params: new URL(authorizationUrl).searchParams, authorizationUrl, bindingVerifier };
}

async function finish(
	ctx: Ctx,
	started: Started,
	options: { idToken?: string | null; bindingVerifier?: string; code?: string; idp?: IdpFixture; state?: string } = {},
) {
	(options.idp ?? ctx.idpA).nextIdToken = options.idToken === undefined ? null : options.idToken;
	return call(ctx, {
		action: "callback",
		code: options.code ?? "authorization-code",
		state: options.state ?? started.params.get("state"),
		binding_verifier: options.bindingVerifier ?? started.bindingVerifier,
	});
}

async function tokenFor(ctx: Ctx, started: Started, claims: Record<string, unknown> = {}, key: TestKey = ctx.keyA) {
	return mintJwt({ key, claims: baseClaims({ nonce: started.params.get("nonce"), ...claims }) });
}

let ctx: Ctx;
beforeEach(async () => {
	ctx = await setup();
});

describe("successful login (enforced tenant, SCIM-provisioned user)", () => {
	it("runs start -> callback -> bind_session end to end and binds the SSO session", async () => {
		const started = await begin(ctx);
		expect(started.authorizationUrl.startsWith(`${ctx.idpA.authorizationEndpoint}?`)).toBe(true);
		expect(Object.fromEntries(started.params)).toMatchObject({
			response_type: "code",
			client_id: "client-a",
			redirect_uri: "https://app.aidr.test/auth/oidc/callback",
			code_challenge_method: "S256",
			scope: "openid email profile",
		});

		const done = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		expect(done.status, JSON.stringify(done.json)).toBe(200);
		expect(done.json).toMatchObject({ ok: true, verification_type: "magiclink", tenant_id: TENANT_A });
		expect(JSON.stringify(done.json)).not.toMatch(/id_token|access_token|s3cr3t|client_secret/);

		// The token request carried the PKCE verifier that matches the challenge in the URL.
		const tokenRequest = ctx.idpA.requests.find((request) => request.url === ctx.idpA.tokenEndpoint);
		const form = new URLSearchParams(tokenRequest?.body);
		expect(form.get("grant_type")).toBe("authorization_code");
		expect(form.get("redirect_uri")).toBe("https://app.aidr.test/auth/oidc/callback");
		expect(await pkceChallenge(String(form.get("code_verifier")))).toBe(started.params.get("code_challenge"));
		expect(tokenRequest?.authorization).toBe(`Basic ${btoa("client-a:s3cr3t-A")}`);
		expect(form.has("client_secret")).toBe(false);

		// Provisioned by SCIM subject, never by email.
		const userId = [...ctx.world.store.authUsers][0] as string;
		expect(ctx.world.store.scimUsers[0]?.auth_user_id).toBe(userId);
		expect(ctx.world.store.identities).toHaveLength(1);
		expect(ctx.world.store.auditActions()).toContain("identity.oidc.login_succeeded");

		// The new browser session proves possession of the one-time ticket exactly once.
		ctx.world.callers.set("new-session", caller(userId, { sessionId: SESSION_1 }));
		const bound = await call(ctx, { action: "bind_session", login_ticket: done.json.login_ticket }, "new-session");
		expect(bound.status).toBe(200);
		expect(ctx.world.store.sessions.get(SESSION_1)).toMatchObject({ user_id: userId, provider_id: PROVIDER_A, tenant_id: TENANT_A });
		const replay = await call(ctx, { action: "bind_session", login_ticket: done.json.login_ticket }, "new-session");
		expect(replay.status).toBe(401);
	});

	it("does not let another user's session consume a ticket", async () => {
		const started = await begin(ctx);
		const done = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		const attacker = await call(ctx, { action: "bind_session", login_ticket: done.json.login_ticket }, "member-a");
		expect(attacker.status).toBe(401);
		expect(ctx.world.store.sessions.size).toBe(0);
	});

	it("rejects an expired login ticket and an unauthenticated bind", async () => {
		const started = await begin(ctx);
		const done = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		const userId = [...ctx.world.store.authUsers][0] as string;
		ctx.world.callers.set("new-session", caller(userId));
		ctx.world.clock.now += 3 * 60_000;
		expect((await call(ctx, { action: "bind_session", login_ticket: done.json.login_ticket }, "new-session")).status).toBe(401);
		expect((await call(ctx, { action: "bind_session", login_ticket: done.json.login_ticket })).status).toBe(401);
		expect((await call(ctx, { action: "bind_session", login_ticket: "short" }, "new-session")).status).toBe(400);
	});
});

describe("callback rate limiting", () => {
	it("rejects unknown, expired or replayed state without consuming any bucket", async () => {
		for (let index = 0; index < 30; index += 1) {
			const result = await call(ctx, { action: "callback", code: "c", state: `${"s".repeat(40)}${index}`, binding_verifier: "v".repeat(43) });
			expect(result).toEqual({ status: 400, json: { error: "sso_login_failed", reason: "request_invalid" } });
		}
		expect([...ctx.world.store.counters.keys()].some((key) => key.startsWith("oidc-callback"))).toBe(false);
		expect(ctx.world.store.pendingLookups).toBe(30);
	});

	it("counts a pending state against its own provider, not a deployment-wide bucket", async () => {
		const started = await begin(ctx);
		ctx.world.store.counters.set(`oidc-callback:v2:unsigned:${PROVIDER_B}`, 1_200);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		expect(result.status).not.toBe(429);
		expect(ctx.world.store.counters.get(`oidc-callback:v2:unsigned:${PROVIDER_A}`)).toBe(1);
		const blocked = await begin(ctx);
		ctx.world.store.counters.set(`oidc-callback:v2:unsigned:${PROVIDER_A}`, 1_200);
		expect(await finish(ctx, blocked, { idToken: await tokenFor(ctx, blocked) })).toEqual({ status: 429, json: { error: "rate_limited" } });
	});

	it("fails closed when the pending-state lookup is unavailable", async () => {
		const started = await begin(ctx);
		ctx.world.store.failPendingLookup = true;
		expect(await finish(ctx, started)).toEqual({ status: 503, json: { error: "sso_unavailable" } });
		expect([...ctx.world.store.counters.keys()].some((key) => key.startsWith("oidc-callback"))).toBe(false);
	});
});

describe("state, PKCE binding and replay", () => {
	it("rejects a replayed state and never exchanges the code twice", async () => {
		const started = await begin(ctx);
		const token = await tokenFor(ctx, started);
		expect((await finish(ctx, started, { idToken: token })).status).toBe(200);
		const exchanges = ctx.idpA.requests.filter((request) => request.url === ctx.idpA.tokenEndpoint).length;
		const replay = await finish(ctx, started, { idToken: token });
		expect(replay.status).toBe(400);
		expect(replay.json).toEqual({ error: "sso_login_failed", reason: "request_invalid" });
		expect(ctx.idpA.requests.filter((request) => request.url === ctx.idpA.tokenEndpoint).length).toBe(exchanges);
	});

	it("rejects an unknown, forged or expired state", async () => {
		const started = await begin(ctx);
		const token = await tokenFor(ctx, started);
		expect((await finish(ctx, started, { idToken: token, state: "x".repeat(43) })).json.reason).toBe("request_invalid");
		ctx.world.clock.now += 11 * 60_000;
		expect((await finish(ctx, started, { idToken: token })).json.reason).toBe("request_invalid");
	});

	it("blocks login CSRF: a different browser (wrong binding secret) cannot finish someone else's flow", async () => {
		const started = await begin(ctx);
		const attackerBinding = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started), bindingVerifier: attackerBinding });
		expect(result.status).toBe(401);
		expect(result.json.reason).toBe("binding_mismatch");
		expect(ctx.idpA.requests.some((request) => request.url === ctx.idpA.tokenEndpoint)).toBe(false);
		// The state was burned by the failed attempt, so the real browser cannot reuse it either.
		const retry = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		expect(retry.status).toBe(400);
		expect(ctx.world.store.auditActions()).toContain("identity.oidc.login_failed");
	});

	it("validates callback input shape before touching the store", async () => {
		for (const body of [
			{ action: "callback" },
			{ action: "callback", code: "c", state: "short", binding_verifier: "b".repeat(43) },
			{ action: "callback", code: "c".repeat(5000), state: "s".repeat(43), binding_verifier: "b".repeat(43) },
			{ action: "callback", code: "c", state: "s".repeat(43), binding_verifier: "bad!" },
		]) {
			expect((await call(ctx, body)).status).toBe(400);
		}
		expect(ctx.world.store.requests.size).toBe(0);
	});
});

describe("ID token failures surface as a coarse, audited denial", () => {
	async function expectDenied(claims: Record<string, unknown> | null, internal: string, options: { key?: TestKey; header?: Record<string, unknown>; mutate?: (token: string) => string } = {}) {
		const started = await begin(ctx);
		let token = await mintJwt({
			key: options.key ?? ctx.keyA,
			header: options.header,
			claims: baseClaims({ nonce: started.params.get("nonce"), ...(claims ?? {}) }),
		});
		if (options.mutate) token = options.mutate(token);
		const result = await finish(ctx, started, { idToken: token });
		expect(result.status).toBe(401);
		expect(result.json).toEqual({ error: "sso_login_failed", reason: "token_invalid" });
		const failure = ctx.world.store.audits.filter((entry) => entry.action === "identity.oidc.login_failed").at(-1);
		expect(failure?.detail.reason).toBe(internal);
		expect(ctx.world.store.authUsers.size).toBe(0);
		expect(ctx.world.store.tickets.size).toBe(0);
	}

	it("wrong audience", () => expectDenied({ aud: "other-client" }, "id_token_audience_mismatch"));
	it("wrong issuer", () => expectDenied({ iss: ISSUER_B }, "id_token_issuer_mismatch"));
	it("expired token", () => expectDenied({ exp: NOW_S - 600, iat: NOW_S - 1200 }, "id_token_expired"));
	it("nonce mismatch", () => expectDenied({ nonce: "other" }, "id_token_nonce_mismatch"));
	it("alg=none", async () => {
		const started = await begin(ctx);
		const none = await mintJwt({ key: null, header: { alg: "none" }, claims: baseClaims({ nonce: started.params.get("nonce") }), rawSignature: "" });
		const result = await finish(ctx, started, { idToken: none });
		expect(result.json.reason).toBe("token_invalid");
		expect(ctx.world.store.audits.at(-1)?.detail.reason).toBe("id_token_alg_not_allowed");
	});
	it("signature from an unknown key", async () => {
		const rogue = await makeKey("RS256", "kA");
		await expectDenied(null, "id_token_signature_invalid", { key: rogue });
	});
	it("unknown kid", async () => {
		const rogue = await makeKey("RS256", "rogue-kid");
		await expectDenied(null, "id_token_unknown_kid", { key: rogue });
	});
	it("a token algorithm outside the provider allow-list (ES256 token, RS256-only provider)", async () => {
		const ec = await makeKey("ES256", "kA");
		await expectDenied(null, "id_token_alg_not_allowed", { key: ec });
	});
	it("an ID token that is not a JWT", async () => {
		await expectDenied(null, "id_token_malformed_token", { mutate: () => "not-a-jwt" });
	});

	it("a missing id_token in the token response", async () => {
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: null });
		expect(result.json.reason).toBe("token_exchange_failed");
	});

	it("an IdP outage during JWKS fetch fails closed", async () => {
		ctx.idpA.failJwks = true;
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		expect(result.json.reason).toBe("token_invalid");
		expect(ctx.world.store.audits.at(-1)?.detail.reason).toBe("id_token_key_fetch_failed");
	});
});

describe("signing key rotation", () => {
	it("accepts a token signed by a newly published key and stops trusting a retired one", async () => {
		const first = await begin(ctx);
		expect((await finish(ctx, first, { idToken: await tokenFor(ctx, first) })).status).toBe(200);

		const rotated = await makeKey("RS256", "kA-2");
		ctx.idpA.keys = [rotated, ctx.keyA];
		ctx.world.clock.now += 31_000;
		const second = await begin(ctx);
		ctx.world.store.scimUsers[0]!.auth_user_id = [...ctx.world.store.authUsers][0] as string;
		const viaNewKey = await finish(ctx, second, { idToken: await tokenFor(ctx, second, { iat: Math.floor(ctx.world.clock.now / 1000) - 5, exp: Math.floor(ctx.world.clock.now / 1000) + 600 }, rotated) });
		expect(viaNewKey.status, JSON.stringify(viaNewKey.json)).toBe(200);

		// The IdP retires the old key; after the cache TTL it no longer verifies.
		ctx.idpA.keys = [rotated];
		ctx.world.clock.now += 11 * 60_000;
		const third = await begin(ctx);
		const stale = await tokenFor(ctx, third, { iat: Math.floor(ctx.world.clock.now / 1000) - 5, exp: Math.floor(ctx.world.clock.now / 1000) + 600 }, ctx.keyA);
		const denied = await finish(ctx, third, { idToken: stale });
		expect(denied.json.reason).toBe("token_invalid");
		expect(ctx.world.store.audits.at(-1)?.detail.reason).toBe("id_token_unknown_kid");
	});
});

describe("tenant-bound domain verification and cross-tenant isolation", () => {
	it("rejects an email whose domain this tenant has not verified", async () => {
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started, { email: "mallory@other-corp.test" }) });
		expect(result.status).toBe(401);
		expect(result.json.reason).toBe("domain_not_verified");
		expect(ctx.world.store.authUsers.size).toBe(0);
	});

	it("rejects a missing email claim and email_verified=false", async () => {
		const noEmail = await begin(ctx);
		expect((await finish(ctx, noEmail, { idToken: await tokenFor(ctx, noEmail, { email: undefined }) })).json.reason).toBe("email_claim_missing");
		const unverified = await begin(ctx);
		expect((await finish(ctx, unverified, { idToken: await tokenFor(ctx, unverified, { email_verified: false }) })).json.reason).toBe("domain_not_verified");
	});

	it("never lets tenant B's IdP sign a user into tenant A by asserting A's email domain", async () => {
		const started = await begin(ctx, { provider_id: PROVIDER_B });
		const token = await mintJwt({
			key: ctx.keyB,
			claims: baseClaims({ iss: ISSUER_B, aud: "client-b", email: "alice@a-corp.test", nonce: started.params.get("nonce") }),
		});
		const result = await finish(ctx, started, { idToken: token, idp: ctx.idpB });
		expect(result.json.reason).toBe("domain_not_verified");
		expect(ctx.world.store.identities).toHaveLength(0);
		expect(ctx.world.store.audits.at(-1)).toMatchObject({ tenant_id: TENANT_B });
	});

	it("rejects tenant A's IdP token presented in tenant B's flow (issuer and audience differ)", async () => {
		const started = await begin(ctx, { provider_id: PROVIDER_B });
		const result = await finish(ctx, started, {
			idToken: await mintJwt({ key: ctx.keyA, claims: baseClaims({ nonce: started.params.get("nonce"), email: "alice@b-corp.test" }) }),
			idp: ctx.idpB,
		});
		expect(result.json.reason).toBe("token_invalid");
		expect(ctx.world.store.audits.at(-1)?.detail.reason).toMatch(/id_token_(issuer_mismatch|unknown_kid|signature_invalid)/);
	});

	it("keys identities by provider: the same subject in two tenants is two different users", async () => {
		const a = await begin(ctx);
		expect((await finish(ctx, a, { idToken: await tokenFor(ctx, a) })).status).toBe(200);
		const b = await begin(ctx, { provider_id: PROVIDER_B });
		const bToken = await mintJwt({
			key: ctx.keyB,
			claims: baseClaims({ iss: ISSUER_B, aud: "client-b", email: "alice@b-corp.test", nonce: b.params.get("nonce") }),
		});
		expect((await finish(ctx, b, { idToken: bToken, idp: ctx.idpB })).status).toBe(200);
		const [first, second] = ctx.world.store.identities;
		expect(first?.subject).toBe(second?.subject);
		expect(first?.auth_user_id).not.toBe(second?.auth_user_id);
		expect(new Set(ctx.world.store.scimUsers.map((row) => row.auth_user_id)).size).toBe(2);
	});

	it("start by email domain only resolves a domain verified by exactly that tenant", async () => {
		const verified = await call(ctx, { action: "start", email: "x@a-corp.test", binding_challenge: await sha256Text("b") });
		expect(verified.status).toBe(200);
		expect(String(verified.json.authorization_url)).toContain("client_id=client-a");
		ctx.world.store.domains.push({ tenant_id: TENANT_B, domain: "claimed.test", verification_token: "z".repeat(40), verified_at: null });
		const unverified = await call(ctx, { action: "start", domain: "claimed.test", binding_challenge: await sha256Text("b") });
		expect(unverified.status).toBe(404);
	});

	it("refuses to let a second tenant verify a domain another tenant already proved", async () => {
		ctx.world.store.domains.push({ tenant_id: TENANT_B, domain: "a-corp.test", verification_token: "y".repeat(40), verified_at: null });
		ctx.world.store.domains = ctx.world.store.domains.filter((row) => !(row.tenant_id === TENANT_B && row.domain === "b-corp.test"));
		ctx.world.txt.set("_aidr-sso.a-corp.test", [`aidr-sso-verification=${"y".repeat(40)}`]);
		const result = await call(ctx, { action: "verify_domain", tenant_id: TENANT_B, domain: "a-corp.test" }, "owner-b");
		expect(result.status).toBe(409);
		expect(result.json.error).toBe("domain_verified_by_another_tenant");
	});
});

describe("membership, provisioning and group mapping", () => {
	it("denies an enforced login for a subject SCIM has not provisioned and mints no session", async () => {
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started, { sub: "not-provisioned" }) });
		expect(result.status).toBe(403);
		expect(result.json.reason).toBe("not_provisioned");
		expect(ctx.world.store.tickets.size).toBe(0);
	});

	it("denies on a SCIM binding conflict without minting a session", async () => {
		ctx.world.store.failBind = true;
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		expect(result.status).toBe(403);
		expect(result.json.reason).toBe("identity_conflict");
		expect(ctx.world.store.tickets.size).toBe(0);
	});

	it("lets a user sign in before enforcement without granting any tenant access", async () => {
		ctx.world.store.policies.set(TENANT_A, { required_oidc_provider_id: null, required_saml_provider_id: null, break_glass_enabled: true, require_mfa: false });
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		expect(result.status).toBe(200);
		const userId = [...ctx.world.store.authUsers][0] as string;
		expect(await ctx.world.store.memberRole(userId, TENANT_A)).toBeNull();
		expect(ctx.world.store.scimUsers[0]?.auth_user_id).toBeNull();
	});

	describe("groups_mode = require_mapped", () => {
		beforeEach(() => {
			ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(ctx.idpA), groups_claim: "groups", groups_mode: "require_mapped" }));
			ctx.world.store.mappings.set(TENANT_A, new Map([["grp-admins", "admin"], ["grp-viewers", "viewer"]]));
		});

		it("admits a user in a mapped group and audits the claim-derived role", async () => {
			const started = await begin(ctx);
			const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started, { groups: ["grp-viewers", "grp-admins"] }) });
			expect(result.status).toBe(200);
			expect(ctx.world.store.audits.find((entry) => entry.action === "identity.oidc.login_succeeded")?.detail.claims_role).toBe("admin");
		});

		it("denies unmapped groups, a missing claim and Entra group overage", async () => {
			const unmapped = await begin(ctx);
			expect((await finish(ctx, unmapped, { idToken: await tokenFor(ctx, unmapped, { groups: ["grp-other"] }) })).json.reason).toBe("group_not_mapped");
			const missing = await begin(ctx);
			expect((await finish(ctx, missing, { idToken: await tokenFor(ctx, missing) })).json.reason).toBe("group_not_mapped");
			const overage = await begin(ctx);
			const response = await finish(ctx, overage, { idToken: await tokenFor(ctx, overage, { _claim_names: { groups: "src1" } }) });
			expect(response.status).toBe(403);
			expect(response.json.reason).toBe("groups_overage");
		});
	});

	it("ignores groups entirely when the mode is 'ignore' (SCIM stays the authority)", async () => {
		ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(ctx.idpA), groups_claim: "groups" }));
		const started = await begin(ctx);
		expect((await finish(ctx, started, { idToken: await tokenFor(ctx, started, { groups: ["anything"] }) })).status).toBe(200);
	});
});

describe("token endpoint client authentication", () => {
	it("supports client_secret_post and public (none) clients, and fails closed without the secret", async () => {
		ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(ctx.idpA), token_auth_method: "client_secret_post" }));
		const post1 = await begin(ctx);
		await finish(ctx, post1, { idToken: await tokenFor(ctx, post1) });
		const form = new URLSearchParams(ctx.idpA.requests.find((request) => request.url === ctx.idpA.tokenEndpoint)?.body);
		expect(form.get("client_secret")).toBe("s3cr3t-A");
		expect(form.get("client_id")).toBe("client-a");

		ctx.idpA.requests.length = 0;
		ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(ctx.idpA), token_auth_method: "none", client_secret_ref: null }));
		const none = await begin(ctx);
		await finish(ctx, none, { idToken: await tokenFor(ctx, none) });
		const publicForm = new URLSearchParams(ctx.idpA.requests.find((request) => request.url === ctx.idpA.tokenEndpoint)?.body);
		expect(publicForm.has("client_secret")).toBe(false);
		expect(ctx.idpA.requests.find((request) => request.url === ctx.idpA.tokenEndpoint)?.authorization).toBeUndefined();

		ctx.world.secrets.clear();
		ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(ctx.idpA) }));
		const missing = await begin(ctx);
		const result = await finish(ctx, missing, { idToken: await tokenFor(ctx, missing) });
		expect(result.json.reason).toBe("token_exchange_failed");
		expect(ctx.world.store.audits.at(-1)?.detail.reason).toBe("client_secret_not_configured");
	});

	it("treats a token-endpoint failure as a denial", async () => {
		ctx.idpA.failTokenEndpoint = true;
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started) });
		expect(result.json.reason).toBe("token_exchange_failed");
	});
});

describe("client secret tenant binding (a reference alone never releases a secret)", () => {
	const ATTACKER_ISSUER = "https://idp.attacker.example/oauth2/default";

	function attackerIdp(): IdpFixture {
		const idp = makeIdp(ATTACKER_ISSUER, [ctx.keyA]);
		ctx.world.idps.push(idp);
		return idp;
	}

	/** Every outbound request the fake network saw, with Basic credentials decoded. */
	function outbound(): string {
		return ctx.world.idps
			.flatMap((idp) => idp.requests)
			.map((request) => {
				const basic = request.authorization?.replace(/^Basic /, "");
				return `${request.url} ${request.body ?? ""} ${request.authorization ?? ""} ${basic ? decodeURIComponent(atob(basic)) : ""}`;
			})
			.join("\n");
	}

	async function attemptLogin(row: Partial<Parameters<typeof providerRow>[0]>, idp: IdpFixture) {
		ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(idp), ...row }));
		const started = await begin(ctx);
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started), idp });
		return { result, tokenRequests: idp.requests.filter((request) => request.url === idp.tokenEndpoint) };
	}

	it("never sends another tenant's secret to an attacker token endpoint", async () => {
		const evil = attackerIdp();
		for (const method of ["client_secret_basic", "client_secret_post"] as const) {
			const { result, tokenRequests } = await attemptLogin(
				{ kind: "generic", issuer: ATTACKER_ISSUER, client_secret_ref: "TENANT_B", token_auth_method: method },
				evil,
			);
			expect(result.json.reason).toBe("token_exchange_failed");
			expect(ctx.world.store.audits.at(-1)?.detail.reason).toBe("client_secret_not_configured");
			expect(tokenRequests).toHaveLength(0);
		}
		expect(outbound()).not.toContain("s3cr3t-B");
		expect(ctx.world.secretEnvReads).not.toContain("AIDR_OIDC_CLIENT_SECRET_TENANT_B");
	});

	it("does not release the tenant's own secret to a different issuer", async () => {
		const evil = attackerIdp();
		const { result, tokenRequests } = await attemptLogin({ kind: "generic", issuer: ATTACKER_ISSUER, client_secret_ref: "TENANT_A" }, evil);
		expect(result.json.reason).toBe("token_exchange_failed");
		expect(tokenRequests).toHaveLength(0);
		expect(outbound()).not.toContain("s3cr3t");
	});

	it("does not release another tenant's secret even on that tenant's real issuer", async () => {
		const { result } = await attemptLogin(
			{ kind: "okta", issuer: ISSUER_B, client_id: "client-b", client_secret_ref: "TENANT_B" },
			ctx.idpB,
		);
		expect(result.json.reason).toBe("token_exchange_failed");
		expect(ctx.idpB.requests.filter((request) => request.url === ctx.idpB.tokenEndpoint)).toHaveLength(0);
		expect(outbound()).not.toContain("s3cr3t-B");
	});

	it("honours a client_id pin in the binding", async () => {
		ctx.world.secretBindings = { TENANT_A: { tenant_id: TENANT_A, issuer: ISSUER_A, client_id: "client-a" } };
		const pinned = await attemptLogin({ client_id: "client-other" }, ctx.idpA);
		expect(pinned.tokenRequests).toHaveLength(0);
		expect(outbound()).not.toContain("s3cr3t-A");
	});

	it("binds nothing when the bindings document is missing or malformed", async () => {
		for (const bindings of [{}, { TENANT_A: { tenant_id: "not-a-uuid", issuer: ISSUER_A } }, { TENANT_A: { tenant_id: TENANT_A, issuer: "http://x" } }]) {
			ctx.world.secretBindings = bindings;
			const { result, tokenRequests } = await attemptLogin({}, ctx.idpA);
			expect(result.json.reason).toBe("token_exchange_failed");
			expect(tokenRequests).toHaveLength(0);
		}
		expect(outbound()).not.toContain("s3cr3t");
	});

	it("sends the bound secret for the legitimate tenant, issuer and client", async () => {
		const { tokenRequests } = await attemptLogin({}, ctx.idpA);
		expect(tokenRequests).toHaveLength(1);
		const basic = String(tokenRequests[0].authorization).replace(/^Basic /, "");
		expect(atob(basic)).toBe("client-a:s3cr3t-A");
	});

	it("gives an owner no oracle for other tenants' references", async () => {
		ctx.world.store.policies.delete(TENANT_A);
		attackerIdp();
		const body = { action: "put_provider", tenant_id: TENANT_A, kind: "generic", display_name: "Mine", issuer: ATTACKER_ISSUER, client_id: "mine" };
		const otherTenant = await call(ctx, { ...body, client_secret_ref: "TENANT_B", enabled: true }, "owner-a");
		const unknown = await call(ctx, { ...body, client_secret_ref: "NO_SUCH_REF", enabled: true }, "owner-a");
		expect(otherTenant).toEqual({ status: 422, json: { error: "client_secret_not_configured" } });
		expect(unknown).toEqual(otherTenant);

		expect((await call(ctx, { ...body, client_secret_ref: "TENANT_B" }, "owner-a")).status).toBe(200);
		const config = await call(ctx, { action: "get_config", tenant_id: TENANT_A }, "owner-a");
		expect(config.json).toMatchObject({ provider: { client_secret_configured: false, enabled: false } });
		expect(outbound()).not.toContain("s3cr3t");
	});
});

describe("start", () => {
	it("answers unknown domains and providers without minting any counter or request", async () => {
		const binding_challenge = await sha256Text("b");
		for (let index = 0; index < 50; index += 1) {
			expect(await call(ctx, { action: "start", domain: `unknown-${index}.test`, binding_challenge }))
				.toEqual({ status: 404, json: { error: "sso_not_available" } });
		}
		expect(await call(ctx, { action: "start", provider_id: "99999999-9999-4999-8999-999999999999", binding_challenge }))
			.toEqual({ status: 404, json: { error: "sso_not_available" } });
		expect(ctx.world.store.counters.size).toBe(0);
		expect(ctx.world.store.requests.size).toBe(0);
	});

	it("bounds a known provider by its own bucket only, so one tenant cannot starve another's sign-in", async () => {
		ctx.world.store.counters.set(`oidc-start:v2:unsigned:${PROVIDER_A}`, 600);
		const binding_challenge = await sha256Text("b");
		expect(await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge }))
			.toEqual({ status: 429, json: { error: "rate_limited" } });
		expect((await call(ctx, { action: "start", provider_id: PROVIDER_B, binding_challenge })).status).toBe(200);
		expect([...ctx.world.store.counters.keys()].some((key) => key.includes("aggregate"))).toBe(false);
	});

	it("limits an attested client by its own bucket and keeps signed callers off the unsigned bucket", async () => {
		const binding_challenge = await sha256Text("b");
		ctx.world.store.counters.set(`oidc-start:v2:unsigned:${PROVIDER_A}`, 600);
		ctx.world.deps.clientIp = async () => "198.51.100.20";
		expect((await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge })).status).toBe(200);
		const clientKey = [...ctx.world.store.counters.keys()].find((key) => key.startsWith("oidc-start:v2:client:"));
		expect(clientKey).toMatch(/^oidc-start:v2:client:[0-9a-f]{64}$/);
		expect(clientKey).not.toContain("198.51.100.20");
		ctx.world.store.counters.set(String(clientKey), 60);
		expect(await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge }))
			.toEqual({ status: 429, json: { error: "rate_limited" } });
		expect(ctx.world.store.counters.get(`oidc-start:v2:signed:${PROVIDER_A}`)).toBe(1);
	});

	it("fails closed when the provider bucket is unreadable", async () => {
		const keys: string[] = [];
		ctx.world.store.rateLimit = async (key) => { keys.push(key); return "unavailable"; };
		expect(await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge: await sha256Text("b") }))
			.toEqual({ status: 503, json: { error: "sso_unavailable" } });
		expect(keys).toEqual([`oidc-start:v2:unsigned:${PROVIDER_A}`]);
		expect(ctx.world.store.requests.size).toBe(0);
	});

	it("answers identically for unknown, disabled and un-discovered providers", async () => {
		const challenge = await sha256Text("b");
		ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: discoveryFor(ctx.idpA), enabled: false }));
		const disabled = await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge: challenge });
		ctx.world.store.providers.set(PROVIDER_A, providerRow({ discovery: null }));
		const undiscovered = await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge: challenge });
		const unknown = await call(ctx, { action: "start", provider_id: "99999999-9999-4999-8999-999999999999", binding_challenge: challenge });
		for (const result of [disabled, undiscovered, unknown]) expect(result).toEqual({ status: 404, json: { error: "sso_not_available" } });
	});

	it("validates input and rate limits per provider", async () => {
		expect((await call(ctx, { action: "start", provider_id: PROVIDER_A })).status).toBe(400);
		expect((await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge: "nothex" })).status).toBe(400);
		expect((await call(ctx, { action: "start", binding_challenge: await sha256Text("b") })).status).toBe(400);
		expect((await call(ctx, { action: "start", provider_id: "not-a-uuid", binding_challenge: await sha256Text("b") })).status).toBe(400);
		const challenge = await sha256Text("b");
		let limited = 0;
		for (let index = 0; index < 620; index += 1) {
			const result = await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge: challenge });
			if (result.status === 429) limited += 1;
		}
		expect(limited).toBeGreaterThan(0);
	});

	it("stores only hashes of state and nonce", async () => {
		const started = await begin(ctx);
		const [row] = [...ctx.world.store.requests.values()];
		expect(row?.state_hash).toBe(await sha256Text(String(started.params.get("state"))));
		expect(row?.nonce_hash).toBe(await sha256Text(String(started.params.get("nonce"))));
		expect(JSON.stringify(row)).not.toContain(String(started.params.get("state")));
		expect(row?.binding_hash).toBe(await sha256Text(started.bindingVerifier));
	});
});

describe("identity linking (migrating an existing owner or SCIM user)", () => {
	it("links the authenticated user's existing Auth account instead of creating a new one", async () => {
		const started = await begin(ctx, { mode: "link" }, "owner-a");
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started, { sub: "owner-subject", email: "owner@a-corp.test" }) });
		expect(result.status, JSON.stringify(result.json)).toBe(200);
		expect(result.json).toMatchObject({ ok: true, linked: true });
		expect(result.json.login_ticket).toBeUndefined();
		expect(ctx.world.store.identities).toEqual([expect.objectContaining({ subject: "owner-subject", auth_user_id: OWNER_A })]);
		expect(ctx.world.store.authUsers.size).toBe(0);
		expect(ctx.world.store.auditActions()).toContain("identity.oidc.identity_linked");

		// A later login by that subject resolves to the SAME Auth user.
		ctx.world.store.authUsers.add(OWNER_A);
		const login = await begin(ctx);
		const done = await finish(ctx, login, { idToken: await tokenFor(ctx, login, { sub: "owner-subject", email: "owner@a-corp.test" }) });
		expect(done.status).toBe(200);
		expect(ctx.world.store.identities).toHaveLength(1);
	});

	it("requires a session and tenant membership to start a link", async () => {
		const challenge = await sha256Text("b");
		expect((await call(ctx, { action: "start", provider_id: PROVIDER_A, mode: "link", binding_challenge: challenge })).status).toBe(401);
		expect((await call(ctx, { action: "start", provider_id: PROVIDER_A, mode: "link", binding_challenge: challenge }, "owner-b")).status).toBe(403);
	});

	it("refuses to link a subject already bound to a different user, or a second subject for one user", async () => {
		ctx.world.store.identities.push({ provider_id: PROVIDER_A, subject: "taken", auth_user_id: MEMBER_A, tenant_id: TENANT_A, email_claim: null });
		const clash = await begin(ctx, { mode: "link" }, "owner-a");
		const taken = await finish(ctx, clash, { idToken: await tokenFor(ctx, clash, { sub: "taken" }) });
		expect(taken.status).toBe(409);
		expect(taken.json.reason).toBe("identity_conflict");

		ctx.world.store.identities.push({ provider_id: PROVIDER_A, subject: "first", auth_user_id: OWNER_A, tenant_id: TENANT_A, email_claim: null });
		const second = await begin(ctx, { mode: "link" }, "owner-a");
		expect((await finish(ctx, second, { idToken: await tokenFor(ctx, second, { sub: "second" }) })).status).toBe(409);
	});

	it("refuses a link whose subject disagrees with the user's SCIM external id", async () => {
		ctx.world.store.scimUsers.push({ tenant_id: TENANT_A, external_id: "scim-subject", auth_user_id: MEMBER_A });
		const started = await begin(ctx, { mode: "link" }, "member-a");
		const result = await finish(ctx, started, { idToken: await tokenFor(ctx, started, { sub: "someone-else" }) });
		expect(result.status).toBe(409);
		expect(ctx.world.store.audits.at(-1)?.detail.reason).toBe("scim_subject_mismatch");
	});
});

describe("audit as a precondition", () => {
	it("denies the login when the success audit event cannot be written", async () => {
		const started = await begin(ctx);
		const token = await tokenFor(ctx, started);
		const store = ctx.world.store;
		const original = store.audit.bind(store);
		store.audit = async (values) => (values.action === "identity.oidc.login_succeeded" ? false : original(values));
		const result = await finish(ctx, started, { idToken: token });
		expect(result.status).toBe(503);
		expect(result.json).toEqual({ error: "sso_unavailable" });
	});
});

describe("owner administration", () => {
	const provider = {
		kind: "entra",
		display_name: "Contoso",
		issuer: ISSUER_A,
		client_id: "client-a",
		client_secret_ref: "TENANT_A",
	};

	it("requires an authenticated owner at AAL2 for every mutation", async () => {
		const request = { action: "put_provider", tenant_id: TENANT_A, ...provider };
		expect((await call(ctx, request)).status).toBe(401);
		expect(await call(ctx, request, "member-a")).toMatchObject({ status: 403, json: { error: "owner_required" } });
		expect(await call(ctx, request, "owner-a-aal1")).toMatchObject({ status: 403, json: { error: "mfa_required" } });
		expect(await call(ctx, request, "owner-b")).toMatchObject({ status: 403, json: { error: "owner_required" } });
		expect((await call(ctx, { action: "put_provider", ...provider }, "owner-a")).status).toBe(400);
	});

	it("rejects invalid provider settings", async () => {
		ctx.world.store.policies.delete(TENANT_B);
		const base = { action: "put_provider", tenant_id: TENANT_B, ...provider };
		const cases: Array<[Record<string, unknown>, string]> = [
			[{ issuer: "https://login.microsoftonline.com/common/v2.0" }, "invalid_entra_issuer"],
			[{ issuer: "http://x.example" }, "invalid_issuer"],
			[{ kind: "saml" }, "invalid_kind"],
			[{ allowed_algs: ["HS256"] }, "invalid_algorithms"],
			[{ allowed_algs: ["none"] }, "invalid_algorithms"],
			[{ client_secret_ref: "lower-case" }, "invalid_client_secret_ref"],
			[{ client_secret_ref: null }, "client_secret_ref_required"],
			[{ subject_claim: "email" }, "invalid_subject_claim"],
			[{ groups_mode: "require_mapped" }, "groups_claim_required"],
			[{ session_max_seconds: 10 }, "invalid_session_lifetime"],
			[{ clock_skew_seconds: 9999 }, "invalid_clock_skew"],
			[{ client_id: "has space" }, "invalid_client_id"],
		];
		for (const [override, reason] of cases) {
			const result = await call(ctx, { ...base, ...override }, "owner-b");
			expect(result, reason).toMatchObject({ status: 400, json: { error: "invalid_provider", reason } });
		}
	});

	it("fetches and validates discovery through the guarded fetcher, enables only with a configured secret, and audits", async () => {
		ctx.world.store.providers.delete(PROVIDER_A);
		ctx.world.store.policies.delete(TENANT_A);
		const saved = await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider, enabled: true }, "owner-a");
		expect(saved.status, JSON.stringify(saved.json)).toBe(200);
		expect(saved.json).toMatchObject({ ok: true, enabled: true, redirect_uri: "https://app.aidr.test/auth/oidc/callback" });
		const row = await ctx.world.store.findProviderByTenant(TENANT_A);
		expect(row?.discovery?.jwks_uri).toBe(ctx.idpA.jwksUri);
		expect(row?.subject_claim).toBe("oid"); // Entra preset
		expect(ctx.world.jwksInvalidated).toContain(ctx.idpA.jwksUri);
		expect(ctx.world.store.auditActions()).toContain("identity.oidc.provider_updated");

		ctx.world.secrets.clear();
		const noSecret = await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider, enabled: true }, "owner-a");
		expect(noSecret).toMatchObject({ status: 422, json: { error: "client_secret_not_configured" } });
	});

	it("rejects discovery that fails the issuer check or the egress policy", async () => {
		ctx.world.store.providers.delete(PROVIDER_A);
		ctx.world.store.policies.delete(TENANT_A);
		ctx.idpA.discoveryOverride = { issuer: "https://evil.example" };
		expect(await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider }, "owner-a")).toMatchObject({
			status: 422,
			json: { error: "discovery_failed", reason: "discovery_issuer_mismatch" },
		});
		ctx.idpA.discoveryOverride = { token_endpoint: "http://insecure.example/token" };
		expect((await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider }, "owner-a")).json.reason).toBe("discovery_endpoint_invalid");
		ctx.idpA.discoveryOverride = undefined;
		const blocked = await call(
			ctx,
			{ action: "put_provider", tenant_id: TENANT_A, ...provider, kind: "generic", issuer: "https://169.254.169.254/latest" },
			"owner-a",
		);
		expect(blocked).toMatchObject({ status: 422, json: { reason: "discovery_blocked_host" } });
		expect(ctx.world.store.providers.size).toBe(1); // only tenant B's
	});

	it("locks provider edits while the tenant enforces it", async () => {
		const result = await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider }, "owner-a");
		expect(result).toMatchObject({ status: 409, json: { error: "provider_locked_by_enforcement" } });
		expect((await call(ctx, { action: "refresh_discovery", tenant_id: TENANT_A }, "owner-a")).status).toBe(200);
		expect(ctx.world.jwksInvalidated).toContain(ctx.idpA.jwksUri);
	});

	it("exposes configuration without secrets", async () => {
		const result = await call(ctx, { action: "get_config", tenant_id: TENANT_A }, "owner-a");
		expect(result.status).toBe(200);
		expect(result.json).toMatchObject({ enforced: true, saml_enforced: false, provider: { client_secret_configured: true, issuer: ISSUER_A } });
		expect(JSON.stringify(result.json)).not.toContain("s3cr3t");
		expect((await call(ctx, { action: "get_config", tenant_id: TENANT_A }, "member-a")).status).toBe(403);
	});

	it("verifies domains through DNS TXT and keeps unverified tokens out of verified rows", async () => {
		const added = await call(ctx, { action: "add_domain", tenant_id: TENANT_A, domain: "New-Corp.Test" }, "owner-a");
		expect(added.status).toBe(200);
		expect(added.json).toMatchObject({ domain: "new-corp.test", verified: false, txt_name: "_aidr-sso.new-corp.test" });
		const txtValue = String(added.json.txt_value);
		expect(txtValue).toMatch(/^aidr-sso-verification=[A-Za-z0-9_-]{43}$/);

		expect(await call(ctx, { action: "verify_domain", tenant_id: TENANT_A, domain: "new-corp.test" }, "owner-a")).toMatchObject({ status: 422, json: { error: "dns_lookup_failed" } });
		ctx.world.txt.set("_aidr-sso.new-corp.test", ["aidr-sso-verification=wrong"]);
		expect((await call(ctx, { action: "verify_domain", tenant_id: TENANT_A, domain: "new-corp.test" }, "owner-a")).json.error).toBe("verification_record_not_found");
		ctx.world.txt.set("_aidr-sso.new-corp.test", ["v=spf1", txtValue]);
		expect((await call(ctx, { action: "verify_domain", tenant_id: TENANT_A, domain: "new-corp.test" }, "owner-a")).json).toEqual({ ok: true, verified: true });
		expect(ctx.world.store.auditActions()).toEqual(expect.arrayContaining(["identity.oidc.domain_added", "identity.oidc.domain_verified"]));
		expect((await call(ctx, { action: "add_domain", tenant_id: TENANT_A, domain: "not a domain" }, "owner-a")).status).toBe(400);
		expect((await call(ctx, { action: "verify_domain", tenant_id: TENANT_A, domain: "missing.test" }, "owner-a")).status).toBe(404);
	});

	it("protects the last verified domain while enforcement is on", async () => {
		const locked = await call(ctx, { action: "remove_domain", tenant_id: TENANT_A, domain: "a-corp.test" }, "owner-a");
		expect(locked).toMatchObject({ status: 409, json: { error: "last_verified_domain_locked_by_enforcement" } });
		ctx.world.store.policies.set(TENANT_A, { required_oidc_provider_id: null, required_saml_provider_id: null, break_glass_enabled: true, require_mfa: false });
		expect((await call(ctx, { action: "remove_domain", tenant_id: TENANT_A, domain: "a-corp.test" }, "owner-a")).status).toBe(200);
	});
});

describe("provider writes are one transaction with the owner re-check and audit", () => {
	const provider = { kind: "entra", display_name: "Contoso", issuer: ISSUER_A, client_id: "client-a", client_secret_ref: "TENANT_A" };

	beforeEach(() => {
		ctx.world.store.providers.delete(PROVIDER_A);
		ctx.world.store.policies.delete(TENANT_A);
	});

	it("leaves no provider row when the audit write fails", async () => {
		const audit = vi.spyOn(ctx.world.store, "audit");
		ctx.world.store.failAudit = true;
		const result = await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider, enabled: true }, "owner-a");
		expect(result).toEqual({ status: 503, json: { error: "sso_unavailable" } });
		expect(await ctx.world.store.findProviderByTenant(TENANT_A)).toBeNull();
		expect(ctx.world.jwksInvalidated).toEqual([]);
		// The handler no longer writes a separate, non-transactional audit row.
		expect(audit).not.toHaveBeenCalled();
	});

	it("rejects an owner demoted while discovery was in flight and writes nothing", async () => {
		const fetchJson = ctx.world.deps.fetchJson;
		ctx.world.deps.fetchJson = async (url, init) => {
			ctx.world.store.members.set(`${TENANT_A}:${OWNER_A}`, "admin");
			return fetchJson(url, init);
		};
		const handler = createOidcHandler(ctx.world.deps);
		const response = await handler(post({ action: "put_provider", tenant_id: TENANT_A, ...provider, enabled: true }, "owner-a"));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "owner_required" });
		expect(await ctx.world.store.findProviderByTenant(TENANT_A)).toBeNull();
		expect(ctx.world.store.auditActions()).not.toContain("identity.oidc.provider_updated");
	});

	it("audits a saved provider inside the same write", async () => {
		const saved = await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider }, "owner-a");
		expect(saved.status).toBe(200);
		const row = await ctx.world.store.findProviderByTenant(TENANT_A);
		expect(ctx.world.store.audits.at(-1)).toMatchObject({
			actor_user_id: OWNER_A,
			tenant_id: TENANT_A,
			action: "identity.oidc.provider_updated",
			detail: { provider_id: row?.id, issuer: ISSUER_A, enabled: false, request_id: "req-test" },
		});
	});

	it("keeps discovery unchanged when the refresh cannot be audited or the actor lost ownership", async () => {
		const before = providerRow({ discovery: { ...discoveryFor(ctx.idpA), jwks_uri: "https://login.microsoftonline.com/old/keys" } });
		ctx.world.store.providers.set(PROVIDER_A, before);
		ctx.world.store.failAudit = true;
		expect(await call(ctx, { action: "refresh_discovery", tenant_id: TENANT_A }, "owner-a")).toEqual({ status: 503, json: { error: "sso_unavailable" } });
		expect(ctx.world.store.providers.get(PROVIDER_A)).toEqual(before);
		expect(ctx.world.jwksInvalidated).toEqual([]);

		ctx.world.store.failAudit = false;
		const fetchJson = ctx.world.deps.fetchJson;
		ctx.world.deps.fetchJson = async (url, init) => {
			ctx.world.store.members.delete(`${TENANT_A}:${OWNER_A}`);
			return fetchJson(url, init);
		};
		const handler = createOidcHandler(ctx.world.deps);
		const response = await handler(post({ action: "refresh_discovery", tenant_id: TENANT_A }, "owner-a"));
		expect(response.status).toBe(403);
		expect(ctx.world.store.providers.get(PROVIDER_A)).toEqual(before);
		expect(ctx.world.store.auditActions()).not.toContain("identity.oidc.discovery_refreshed");
	});

	it("a refresh racing a disable writes only discovery: the provider stays disabled", async () => {
		const before = providerRow({ discovery: { ...discoveryFor(ctx.idpA), jwks_uri: "https://login.microsoftonline.com/old/keys" } });
		ctx.world.store.providers.set(PROVIDER_A, before);
		expect(before.enabled).toBe(true);
		const save = vi.spyOn(ctx.world.store, "saveProvider");
		const fetchJson = ctx.world.deps.fetchJson;
		ctx.world.deps.fetchJson = async (url, init) => {
			// Another owner disables the provider (and renames it) while discovery is in flight.
			const current = ctx.world.store.providers.get(PROVIDER_A);
			if (current) ctx.world.store.providers.set(PROVIDER_A, { ...current, enabled: false, display_name: "Disabled meanwhile" });
			return fetchJson(url, init);
		};
		const handler = createOidcHandler(ctx.world.deps);
		const response = await handler(post({ action: "refresh_discovery", tenant_id: TENANT_A }, "owner-a"));
		expect(response.status).toBe(200);
		const after = ctx.world.store.providers.get(PROVIDER_A);
		expect(after).toMatchObject({ enabled: false, display_name: "Disabled meanwhile", discovery: discoveryFor(ctx.idpA) });
		expect(save).not.toHaveBeenCalled();
		expect(ctx.world.store.audits.at(-1)).toMatchObject({
			actor_user_id: OWNER_A,
			tenant_id: TENANT_A,
			action: "identity.oidc.discovery_refreshed",
			detail: { provider_id: PROVIDER_A, jwks_changed: true },
		});
		expect(ctx.world.jwksInvalidated).toContain("https://login.microsoftonline.com/old/keys");
	});

	it("refuses a refresh whose issuer or algorithms changed while discovery was in flight", async () => {
		const before = providerRow({ discovery: discoveryFor(ctx.idpA) });
		for (const change of [{ issuer: "https://login.microsoftonline.com/replacement/v2.0" }, { allowed_algs: ["ES256" as const] }]) {
			ctx.world.store.providers.set(PROVIDER_A, before);
			const audits = ctx.world.store.audits.length;
			const fetchJson = ctx.world.deps.fetchJson;
			ctx.world.deps.fetchJson = async (url, init) => {
				ctx.world.store.providers.set(PROVIDER_A, { ...before, ...change, discovery: null, enabled: false });
				return fetchJson(url, init);
			};
			const handler = createOidcHandler(ctx.world.deps);
			const response = await handler(post({ action: "refresh_discovery", tenant_id: TENANT_A }, "owner-a"));
			ctx.world.deps.fetchJson = fetchJson;
			expect(response.status, JSON.stringify(change)).toBe(409);
			expect(await response.json()).toEqual({ error: "provider_changed" });
			expect(ctx.world.store.providers.get(PROVIDER_A)).toEqual({ ...before, ...change, discovery: null, enabled: false });
			expect(ctx.world.store.audits).toHaveLength(audits);
			expect(ctx.world.jwksInvalidated).toEqual([]);
		}
	});

	it("maps the database guards to stable conflicts", async () => {
		for (const result of ["provider_locked_by_enforcement", "provider_identity_namespace_locked"] as const) {
			vi.spyOn(ctx.world.store, "saveProvider").mockResolvedValueOnce(result);
			expect(await call(ctx, { action: "put_provider", tenant_id: TENANT_A, ...provider }, "owner-a")).toEqual({ status: 409, json: { error: result } });
		}
	});
});

describe("enforce-SSO and break-glass", () => {
	const request = { action: "set_enforcement", tenant_id: TENANT_A, provider_id: PROVIDER_A, reason: "Cut over to Entra SSO", change_ref: "CHG-1042" };

	it("passes the acting session to the audited database operation", async () => {
		const result = await call(ctx, request, "owner-a");
		expect(result).toMatchObject({ status: 200, json: { ok: true, enforced: true } });
		expect(ctx.world.store.enforcementCalls[0]).toMatchObject({ tenantId: TENANT_A, actorUserId: OWNER_A, sessionId: SESSION_1, providerId: PROVIDER_A, changeRef: "CHG-1042" });
		const off = await call(ctx, { ...request, provider_id: null }, "owner-a");
		expect(off.json).toMatchObject({ ok: true, enforced: false });
	});

	it("requires owner, AAL2, a reason and a change reference", async () => {
		expect((await call(ctx, request, "member-a")).status).toBe(403);
		expect((await call(ctx, request, "owner-a-aal1")).status).toBe(403);
		expect((await call(ctx, { ...request, reason: undefined }, "owner-a")).status).toBe(400);
		expect((await call(ctx, { ...request, change_ref: undefined }, "owner-a")).status).toBe(400);
		expect((await call(ctx, { ...request, provider_id: "nope" }, "owner-a")).status).toBe(400);
		expect(ctx.world.store.enforcementCalls).toHaveLength(0);
	});

	it("maps database refusals to stable errors and hides unexpected ones", async () => {
		for (const [error, status] of [
			["oidc_verified_owners_required", 409],
			["oidc_actor_session_required", 403],
			["oidc_existing_identity_conflict", 409],
			["oidc_saml_enforcement_active", 409],
		] as const) {
			ctx.world.store.enforcementResult = { ok: false, error };
			expect(await call(ctx, request, "owner-a")).toEqual({ status, json: { error } });
		}
		ctx.world.store.enforcementResult = { ok: false, error: "relation does not exist" };
		expect(await call(ctx, request, "owner-a")).toEqual({ status: 503, json: { error: "sso_unavailable" } });
	});

	describe("break-glass suspension", () => {
		const attempt = (overrides: Record<string, unknown> = {}) =>
			call(ctx, { action: "break_glass_suspend_enforcement", email: "owner@a-corp.test", recovery_code: "ABCDE-12345-ABCDE-12345-ABCDE-12345-ABCDE-12345", ...overrides });

		it("rejects malformed input without touching any counter", async () => {
			expect((await attempt({ recovery_code: "bad" })).status).toBe(401);
			expect((await attempt({ email: "not-an-email" })).status).toBe(401);
			expect(ctx.world.store.counters.size).toBe(0);
		});

		it("bounds unsigned callers by an unsigned aggregate plus a per-email bucket", async () => {
			ctx.world.store.counters.set("oidc-break-glass:v2:unsigned-aggregate", 299);
			expect((await attempt({ email: "first@example.test" })).status).toBe(401);
			expect(await attempt({ email: "second@example.test" })).toEqual({ status: 429, json: { error: "rate_limited" } });
			expect([...ctx.world.store.counters.keys()].filter((key) => key.startsWith("oidc-break-glass:v2:email:"))).toHaveLength(1);
		});

		it("gives an attested client its own bucket, unaffected by an exhausted unsigned aggregate", async () => {
			ctx.world.store.counters.set("oidc-break-glass:v2:unsigned-aggregate", 10_000);
			ctx.world.deps.clientIp = async () => "198.51.100.20";
			expect((await attempt()).status).toBe(401);
			const clientKey = [...ctx.world.store.counters.keys()].find((key) => key.startsWith("oidc-break-glass:v2:client:"));
			expect(clientKey).toMatch(/^oidc-break-glass:v2:client:[0-9a-f]{64}$/);
			ctx.world.store.counters.set(String(clientKey), 20);
			expect(await attempt({ email: "other@a-corp.test" })).toEqual({ status: 429, json: { error: "rate_limited" } });
			ctx.world.deps.clientIp = async () => "198.51.100.21";
			expect((await attempt({ email: "other@a-corp.test" })).status).toBe(401);
		});

		it("fails closed before the email bucket when the client bucket is unreadable", async () => {
			const keys: string[] = [];
			ctx.world.store.rateLimit = async (key) => { keys.push(key); return "unavailable"; };
			expect(await attempt()).toEqual({ status: 503, json: { error: "recovery_unavailable" } });
			expect(keys).toEqual(["oidc-break-glass:v2:unsigned-aggregate"]);
		});

		it("answers 401 for an unknown or malformed code without revealing why", async () => {
			expect(await attempt()).toEqual({ status: 401, json: { error: "invalid_or_expired_recovery_code" } });
			expect((await attempt({ recovery_code: "bad" })).status).toBe(401);
			expect((await attempt({ email: "not-an-email" })).status).toBe(401);
		});

		it("suspends enforcement for a valid code and grants no session", async () => {
			ctx.world.store.breakGlassResult = { tenant_id: TENANT_A, user_id: OWNER_A };
			const result = await attempt();
			expect(result).toEqual({ status: 200, json: { ok: true, enforcement_suspended: true, next_step: "sign_in_with_password_then_repair_provider" } });
			expect(JSON.stringify(result.json)).not.toMatch(/token|session_id/);
		});

		it("is rate limited per email like the password break-glass flow", async () => {
			let last = 0;
			for (let index = 0; index < 7; index += 1) last = (await attempt()).status;
			expect(last).toBe(429);
		});

		it("fails closed on a database error", async () => {
			ctx.world.store.breakGlassResult = "error";
			expect((await attempt()).status).toBe(503);
		});
	});
});

describe("plan gating (entra_sso)", () => {
	const adminActions: Array<Record<string, unknown>> = [
		{ action: "get_config", tenant_id: TENANT_A },
		{ action: "put_provider", tenant_id: TENANT_A, kind: "entra", display_name: "Contoso", issuer: ISSUER_A, client_id: "client-a", client_secret_ref: "TENANT_A" },
		{ action: "refresh_discovery", tenant_id: TENANT_A },
		{ action: "add_domain", tenant_id: TENANT_A, domain: "new-corp.test" },
		{ action: "verify_domain", tenant_id: TENANT_A, domain: "a-corp.test" },
		{ action: "remove_domain", tenant_id: TENANT_A, domain: "a-corp.test" },
		{ action: "set_enforcement", tenant_id: TENANT_A, provider_id: null, reason: "Downgrade cleanup", change_ref: "CHG-1" },
	];

	function spyOnConfig() {
		const store = ctx.world.store;
		const methods = [
			"findProviderByTenant", "listDomains", "verifiedDomains", "policy", "saveProvider", "refreshProviderDiscovery", "addDomain",
			"markDomainVerified", "removeDomain", "setEnforcement", "audit",
		] as const;
		const spies = methods.map((method) => vi.spyOn(store, method));
		const fetches = vi.spyOn(ctx.world.deps, "fetchJson");
		const dns = vi.spyOn(ctx.world.deps, "resolveTxt");
		return () => [...spies, fetches, dns].reduce((total, spy) => total + spy.mock.calls.length, 0);
	}

	it.each(adminActions)("answers 402 for $action on a free plan before any SSO configuration is touched", async (body) => {
		ctx.world.store.plans.set(TENANT_A, { data: freePlan(TENANT_A), error: null });
		const touched = spyOnConfig();
		const result = await call(ctx, body, "owner-a");
		expect(result).toEqual({
			status: 402,
			json: { error: "plan_feature_required", feature: "entra_sso", plan_id: "free", required_plan: "team" },
		});
		expect(ctx.world.store.planRpcCalls).toEqual([TENANT_A]);
		expect(touched()).toBe(0);
		expect(ctx.world.store.enforcementCalls).toHaveLength(0);
	});

	it.each([
		["an RPC error", { data: null, error: { message: "private database error" } }],
		["a malformed row", { data: { tenant_id: TENANT_A, plan_id: "platinum" }, error: null }],
		["another tenant's row", { data: entitledPlan(TENANT_B), error: null }],
		["no row", { data: null, error: null }],
	])("fails closed with 503 on %s", async (_label, answer) => {
		ctx.world.store.plans.set(TENANT_A, answer);
		const touched = spyOnConfig();
		for (const body of [adminActions[0], adminActions[1]]) {
			expect(await call(ctx, body, "owner-a")).toEqual({ status: 503, json: { error: "plan_entitlement_unavailable" } });
		}
		expect(touched()).toBe(0);
	});

	it("checks the plan only after authentication and owner authorization", async () => {
		ctx.world.store.plans.set(TENANT_A, { data: freePlan(TENANT_A), error: null });
		expect((await call(ctx, adminActions[0])).status).toBe(401);
		expect(await call(ctx, adminActions[0], "member-a")).toMatchObject({ status: 403, json: { error: "owner_required" } });
		expect(await call(ctx, adminActions[1], "owner-a-aal1")).toMatchObject({ status: 403, json: { error: "mfa_required" } });
		expect(ctx.world.store.planRpcCalls).toEqual([]);
	});

	it("never gates the public sign-in and recovery actions of a downgraded tenant", async () => {
		ctx.world.store.plans.set(TENANT_A, { data: freePlan(TENANT_A), error: null });
		const started = await begin(ctx);
		expect(started.params.get("client_id")).toBe("client-a");
		ctx.world.store.breakGlassResult = { tenant_id: TENANT_A, user_id: OWNER_A };
		const recovered = await call(ctx, {
			action: "break_glass_suspend_enforcement",
			email: "owner@a-corp.test",
			recovery_code: "ABCDE-12345-ABCDE-12345-ABCDE-12345-ABCDE-12345",
		});
		expect(recovered.status).toBe(200);
		expect(ctx.world.store.planRpcCalls).toEqual([]);
	});

	it("lets an entitled tenant administer SSO", async () => {
		const result = await call(ctx, adminActions[0], "owner-a");
		expect(result.status).toBe(200);
		expect(ctx.world.store.planRpcCalls).toEqual([TENANT_A]);
	});
});

describe("dispatch", () => {
	it("rejects non-POST, bad JSON, oversized bodies and unknown actions", async () => {
		expect((await ctx.handler(new Request("https://edge.test/x", { method: "GET" }))).status).toBe(405);
		expect((await ctx.handler(new Request("https://edge.test/x", { method: "POST", body: "{nope" }))).status).toBe(400);
		expect((await ctx.handler(new Request("https://edge.test/x", { method: "POST", body: "[]" }))).status).toBe(400);
		expect((await ctx.handler(new Request("https://edge.test/x", { method: "POST", body: JSON.stringify({ action: "x", pad: "y".repeat(20_000) }) }))).status).toBe(413);
		expect((await call(ctx, { action: "drop_tables" })).status).toBe(400);
	});

	it("turns an unexpected store failure into a generic 503", async () => {
		ctx.world.store.rateLimit = async () => {
			throw new Error("db password is hunter2");
		};
		const result = await call(ctx, { action: "start", provider_id: PROVIDER_A, binding_challenge: await sha256Text("b") });
		expect(result).toEqual({ status: 503, json: { error: "sso_unavailable" } });
	});
});

describe("SupabaseOidcStore.saveProvider", () => {
	function fakeDb(error: { message: string } | null) {
		const rpc = vi.fn(async (_name: string, _args: Record<string, unknown>) => ({ data: error ? null : { provider_id: PROVIDER_A }, error }));
		const from = vi.fn(() => {
			throw new Error("provider writes must not use table access");
		});
		return { db: { rpc, from }, rpc, from };
	}

	it("writes provider and audit through the single transactional RPC", async () => {
		const { SupabaseOidcStore } = await import("../oidc-sso/store.ts");
		const fake = fakeDb(null);
		const store = new SupabaseOidcStore(fake.db as never);
		const row = providerRow({ discovery: null, enabled: false });
		const result = await store.saveProvider(row, OWNER_A, { action: "identity.oidc.provider_updated", detail: { request_id: "r" } });
		expect(result).toBe("saved");
		expect(fake.from).not.toHaveBeenCalled();
		expect(fake.rpc).toHaveBeenCalledTimes(1);
		const [name, args] = fake.rpc.mock.calls[0];
		expect(name).toBe("oidc_save_provider");
		expect(args).toMatchObject({
			p_actor_user_id: OWNER_A,
			p_provider: { id: PROVIDER_A, tenant_id: TENANT_A, issuer: ISSUER_A, client_secret_ref: "TENANT_A", enabled: false },
			p_audit_action: "identity.oidc.provider_updated",
			p_audit_detail: { request_id: "r" },
		});
	});

	it.each([
		["oidc_provider_forbidden", "owner_required"],
		["oidc_tenant_inactive", "owner_required"],
		["oidc_provider_locked_by_enforcement", "provider_locked_by_enforcement"],
		["oidc_provider_identity_namespace_locked", "provider_identity_namespace_locked"],
		["insert into admin_audit_logs failed", "error"],
	])("maps %s to %s", async (message, expected) => {
		const { SupabaseOidcStore } = await import("../oidc-sso/store.ts");
		const store = new SupabaseOidcStore(fakeDb({ message }).db as never);
		expect(await store.saveProvider(providerRow(), OWNER_A, { action: "identity.oidc.discovery_refreshed", detail: {} })).toBe(expected);
	});
});

describe("SupabaseOidcStore.refreshProviderDiscovery", () => {
	function fakeDb(error: { message: string } | null) {
		const rpc = vi.fn(async (_name: string, _args: Record<string, unknown>) => ({ data: error ? null : { provider_id: PROVIDER_A }, error }));
		const from = vi.fn(() => {
			throw new Error("provider writes must not use table access");
		});
		return { db: { rpc, from }, rpc, from };
	}

	it("sends only the discovery plus the read issuer/algorithms, never the full row", async () => {
		const { SupabaseOidcStore } = await import("../oidc-sso/store.ts");
		const fake = fakeDb(null);
		const store = new SupabaseOidcStore(fake.db as never);
		const row = providerRow();
		const discovery = { issuer: ISSUER_A, authorization_endpoint: "https://a/authorize", token_endpoint: "https://a/token", jwks_uri: "https://a/keys" };
		expect(await store.refreshProviderDiscovery(row, discovery, OWNER_A, { jwks_changed: false })).toBe("saved");
		expect(fake.from).not.toHaveBeenCalled();
		const [name, args] = fake.rpc.mock.calls[0];
		expect(name).toBe("oidc_update_provider_discovery");
		expect(args).toEqual({
			p_actor_user_id: OWNER_A,
			p_tenant_id: TENANT_A,
			p_provider_id: PROVIDER_A,
			p_expected_issuer: row.issuer,
			p_expected_allowed_algs: row.allowed_algs,
			p_discovery: discovery,
			p_audit_detail: { jwks_changed: false },
		});
		expect(JSON.stringify(args)).not.toMatch(/"enabled"|client_secret_ref|client_id/);
	});

	it.each([
		["oidc_provider_forbidden", "owner_required"],
		["oidc_tenant_inactive", "owner_required"],
		["oidc_provider_changed", "provider_changed"],
		["insert into admin_audit_logs failed", "error"],
	])("maps %s to %s", async (message, expected) => {
		const { SupabaseOidcStore } = await import("../oidc-sso/store.ts");
		const store = new SupabaseOidcStore(fakeDb({ message }).db as never);
		const discovery = { issuer: ISSUER_A, authorization_endpoint: "https://a/authorize", token_endpoint: "https://a/token", jwks_uri: "https://a/keys" };
		expect(await store.refreshProviderDiscovery(providerRow(), discovery, OWNER_A, {})).toBe(expected);
	});
});

describe("oidc_update_provider_discovery SQL contract (20261011000300)", () => {
	const sql = readFileSync(
		join(dirname(fileURLToPath(import.meta.url)), "..", "..", "migrations", "20261011000300_oidc_provider_discovery_refresh.sql"),
		"utf8",
	);
	const body = sql.split("create or replace function public.oidc_update_provider_discovery(")[1]?.split("$$;")[0] ?? "";
	const signature = "public.oidc_update_provider_discovery(uuid, uuid, uuid, text, text[], jsonb, jsonb)";

	it("is a pinned-search-path security definer granted to service_role only", () => {
		expect(body).toContain("security definer");
		expect(body).toContain("set search_path = pg_catalog, public, pg_temp");
		expect(sql).toContain(`revoke all on function ${signature}\n  from public, anon, authenticated;`);
		expect(sql).toContain(`grant execute on function ${signature}\n  to service_role;`);
		expect(sql).not.toMatch(/grant execute on function public\.oidc_update_provider_discovery[^;]*\b(anon|authenticated)\b/);
	});

	it("locks, re-checks the owner, locks the row and refuses a changed provider before writing", () => {
		const lock = body.indexOf("pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2606))");
		const share = body.indexOf("for share of m, t");
		const row = body.indexOf("from public.oidc_providers where id = p_provider_id for update");
		const changed = body.indexOf("v_row.issuer is distinct from p_expected_issuer");
		const update = body.indexOf("update public.oidc_providers");
		const audit = body.indexOf("insert into public.admin_audit_logs");
		expect(lock).toBeGreaterThan(-1);
		expect(lock).toBeLessThan(share);
		expect(share).toBeLessThan(row);
		expect(row).toBeLessThan(changed);
		expect(changed).toBeLessThan(update);
		expect(update).toBeLessThan(audit);
		expect(body).toContain("m.role = 'owner'");
		expect(body).toContain("(m.expires_at is null or m.expires_at > clock_timestamp())");
		expect(body).toContain("v_row.allowed_algs is distinct from p_expected_allowed_algs");
		expect(body).toContain("raise exception 'oidc_provider_changed' using errcode = '55000'");
		expect(body).toContain("'identity.oidc.discovery_refreshed'");
	});

	it("writes only the discovery columns", () => {
		const update = body.split("update public.oidc_providers")[1]?.split(";")[0] ?? "";
		expect(update).toContain("set discovery = p_discovery,");
		expect(update).toContain("discovery_fetched_at = now()");
		expect(update).not.toMatch(/\b(enabled|issuer|client_id|client_secret_ref|token_auth_method|allowed_algs|display_name)\s*=/);
		expect(body).not.toContain("insert into public.oidc_providers");
		expect(sql).not.toMatch(/disable trigger|session_replication_role/i);
	});
});

describe("oidc_save_provider SQL contract (20261010000120)", () => {
	const sql = readFileSync(
		join(dirname(fileURLToPath(import.meta.url)), "..", "..", "migrations", "20261010000120_oidc_provider_atomic_save.sql"),
		"utf8",
	);
	const body = sql.split("create or replace function public.oidc_save_provider(")[1]?.split("$$;")[0] ?? "";

	it("is a pinned-search-path security definer granted to service_role only", () => {
		expect(body).toContain("security definer");
		expect(body).toContain("set search_path = pg_catalog, public, pg_temp");
		expect(sql).toContain("revoke all on function public.oidc_save_provider(uuid, jsonb, text, jsonb)\n  from public, anon, authenticated;");
		expect(sql).toContain("grant execute on function public.oidc_save_provider(uuid, jsonb, text, jsonb) to service_role;");
		expect(sql).not.toMatch(/grant execute on function public\.oidc_save_provider[^;]*\b(anon|authenticated)\b/);
	});

	it("takes the tenant lock, then re-checks a live owner under row locks, before writing", () => {
		const lock = body.indexOf("pg_advisory_xact_lock(hashtextextended(v_row.tenant_id::text, 2606))");
		const owner = body.indexOf("m.role = 'owner'");
		const share = body.indexOf("for share of m, t");
		const upsert = body.indexOf("insert into public.oidc_providers");
		const audit = body.indexOf("insert into public.admin_audit_logs");
		expect(lock).toBeGreaterThan(-1);
		expect(lock).toBeLessThan(owner);
		expect(owner).toBeLessThan(share);
		expect(share).toBeLessThan(upsert);
		expect(upsert).toBeLessThan(audit);
		expect(body).toContain("(m.expires_at is null or m.expires_at > clock_timestamp())");
		expect(body).toContain("t.status = 'active'");
		expect(body).toContain("raise exception 'oidc_provider_forbidden' using errcode = '42501'");
	});

	it("never moves a provider between tenants and allows only the two provider audit actions", () => {
		expect(body).toContain("where p.tenant_id = excluded.tenant_id");
		expect(body).toContain("p_audit_action not in ('identity.oidc.provider_updated', 'identity.oidc.discovery_refreshed')");
		// Update path keeps the existing guard trigger in force (no trigger disabling).
		expect(sql).not.toMatch(/disable trigger|session_replication_role/i);
	});
});
