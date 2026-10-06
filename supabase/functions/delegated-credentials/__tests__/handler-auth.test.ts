import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyDelegatedCredentialForBroker } from "../../_shared/delegated-credential.ts";

const runtime = vi.hoisted(() => ({
	db: null as unknown,
	handler: null as unknown,
}));

vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: () => runtime.db }));

const TENANT = "11111111-1111-4111-8111-111111111111";
const USER = "22222222-2222-4222-8222-222222222222";
const AGENT = "33333333-3333-4333-8333-333333333333";
const GRANT = "44444444-4444-4444-8444-444444444444";
const SESSION = "55555555-5555-4555-8555-555555555555";
const PROVIDER = "66666666-6666-4666-8666-666666666666";
const NOW = Math.floor(Date.now() / 1000) * 1000;
const keyPair = generateKeyPairSync("ed25519");
const CLAIMS = {
	version: 1, issuer: "https://control.example.test", subjectUserId: USER, tenantId: TENANT, agentId: AGENT,
	tool: { serverId: "github-mcp", name: "repository.read" }, resource: { type: "repository", id: "acme/example" },
	audience: "https://tool.example.test", scopes: ["contents:read"], issuedAt: NOW / 1000, notBefore: NOW / 1000,
	expiresAt: NOW / 1000 + 300, authSessionIssuedAt: NOW / 1000 - 60,
	tokenId: "77777777-7777-4777-8777-777777777777", delegationDepth: 0,
};
const env: Record<string, string> = {
	SUPABASE_URL: "https://project.supabase.co",
	SUPABASE_SERVICE_ROLE_KEY: "synthetic-service-role",
	AIDR_DELEGATION_ISSUER: "https://control.example.test",
	AIDR_DELEGATION_SIGNING_KEY_ID: "test-key",
	AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64: keyPair.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
	AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64: keyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
};

function authJwt(patch: Record<string, unknown> = {}) {
	return `header.${Buffer.from(JSON.stringify({ sub: USER, session_id: SESSION, iat: NOW / 1000 - 60,
		exp: NOW / 1000 + 1800, aal: "aal1", ...patch })).toString("base64url")}.verified-signature`;
}
const ISSUE = { action: "issue", tenant_id: TENANT, grant_id: GRANT, scopes: ["contents:read"], ttl_seconds: 300 };
const GRANT_BODY = { action: "grant", tenant_id: TENANT, subject_user_id: USER, agent_id: AGENT,
	tool_server_id: "github-mcp", tool_name: "repository.read", resource_type: "repository", resource_id: "acme/example",
	audience: "https://tool.example.test", scopes: ["contents:read"] };
const GRANT_RESULT = { grant_id: GRANT, expires_at: new Date(NOW + 3600_000).toISOString() };

function database(options: {
	authenticatedToken?: string; assurance?: string | null; assuranceError?: boolean;
	revokedBefore?: string; reserveError?: { code: string; message?: string }; finalizeDenied?: boolean;
	role?: string; grantError?: { code: string; message?: string }; grantResult?: Record<string, unknown> | null | false;
} = {}) {
	const calls: string[] = [];
	const rpcCalls: Array<{ name: string; args: Record<string, unknown> }> = [];
	return {
		calls,
		rpcCalls,
		db: {
			auth: {
				getUser: async (token: string) => {
					calls.push("auth.getUser");
					return token === options.authenticatedToken ? { data: { user: { id: USER } }, error: null }
						: { data: { user: null }, error: { message: "invalid access token" } };
				},
				mfa: {
					getAuthenticatorAssuranceLevel: async (token: string) => {
						calls.push(`auth.mfa:${token}`);
						return { data: options.assurance === null ? null : { currentLevel: options.assurance ?? "aal1" },
							error: options.assuranceError ? { message: "private MFA error" } : null };
					},
				},
			},
			from: (table: string) => {
				calls.push(`from:${table}`);
				if (!options.authenticatedToken) throw new Error("unauthorized route must not read service-role tables");
				const row = table === "identity_user_session_state"
					? { revoked_before: options.revokedBefore ?? null, global_revoke_pending_session_id: null }
					: table === "tenant_identity_policies" ? null
						: table === "tenant_members" ? { role: options.role ?? "member", expires_at: null }
							: table === "tenants" ? { status: "active" }
								: { subject_user_id: USER, revoked_at: null, expires_at: new Date(NOW + 3600_000).toISOString() };
				const chain = { select: () => chain, eq: () => chain, maybeSingle: async () => ({ data: row, error: null }) };
				return chain;
			},
			rpc: async (name: string, args: Record<string, unknown>) => {
				calls.push(`rpc:${name}`);
				rpcCalls.push({ name, args });
				if (!options.authenticatedToken) throw new Error("unauthorized route must not call service-role RPCs");
				if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 110 }, error: null };
				if (name === "create_delegated_credential_grant") return options.grantError ? { data: null, error: options.grantError }
					: { data: options.grantResult === undefined ? GRANT_RESULT : options.grantResult, error: null };
				if (name === "reserve_delegated_credential") return options.reserveError
					? { data: null, error: options.reserveError } : { data: { claims: CLAIMS }, error: null };
				if (name === "finalize_delegated_credential") return { data: options.finalizeDenied !== true, error: null };
				throw new Error("unexpected RPC");
			},
		},
	};
}

async function handler(db: unknown) {
	runtime.db = db;
	runtime.handler = null;
	vi.stubGlobal("Deno", {
		env: { get: (name: string) => env[name] },
		serve: (route: unknown) => { runtime.handler = route; },
	});
	vi.resetModules();
	await import("../index.ts");
	return runtime.handler as (request: Request) => Promise<Response>;
}

function post(action: string, authorization?: string, body?: Record<string, unknown>) {
	return new Request("https://project.supabase.co/functions/v1/delegated-credentials", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			...(authorization ? { Authorization: authorization } : {}),
		},
		body: JSON.stringify(body ?? {
			action,
			tenant_id: TENANT,
			scopes: ["contents:read"],
			context: {},
		}),
	});
}

describe("delegated credential handler authentication boundaries", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.resetModules();
		vi.restoreAllMocks();
	});

	it.each([
		["missing", undefined, "missing_access_token", 0],
		["invalid", "Bearer expired-human-session", "invalid_access_token", 1],
	] as const)("rejects %s human credentials before privileged reads or RPCs", async (_kind, authorization, error, expectedAuthChecks) => {
		const { db, calls } = database();
		const handle = await handler(db);
		const response = await handle(post("grant", authorization));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error });
		expect(calls.filter((call) => call.startsWith("auth."))).toHaveLength(expectedAuthChecks);
		expect(calls.filter((call) => !call.startsWith("auth."))).toEqual([]);
	});

	it.each(["introspect", "redelegate"])("rejects missing delegated credentials for %s before broker access", async (action) => {
		const { db, calls } = database();
		const handle = await handler(db);
		const response = await handle(post(action));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "missing_delegated_credential" });
		expect(calls).toEqual([]);
	});

	it.each(["introspect", "redelegate"])("rejects invalid delegated credentials for %s before broker access", async (action) => {
		const { db, calls } = database();
		const handle = await handler(db);
		const response = await handle(post(action, "Bearer not-a-delegated-token-with-no-signature"));

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_token" });
		expect(calls).toEqual([]);
	});

	it.each(["aal1", "aal2"])("captures only verified session proof with SDK %s, while signed claims stay unchanged", async (aal) => {
		vi.spyOn(Date, "now").mockReturnValue(NOW);
		const token = authJwt({ aal: aal === "aal1" ? "aal2" : "aal1", amr: [{ method: "sso/saml", provider: PROVIDER.toUpperCase() }] });
		const { db, rpcCalls, calls } = database({ authenticatedToken: token, assurance: aal });
		const response = await (await handler(db))(post("issue", `Bearer ${token}`, ISSUE));
		expect(response.status).toBe(201);
		const body = await response.json();
		const reserve = rpcCalls.find(call => call.name === "reserve_delegated_credential");
		expect(reserve?.args).toEqual({ p_actor_user_id: USER, p_issuer: env.AIDR_DELEGATION_ISSUER, p_request: {
			...ISSUE, validated_session_issued_at: new Date(NOW - 60_000).toISOString(), validated_session: {
				session_id: SESSION, issued_at: new Date(NOW - 60_000).toISOString(), expires_at: new Date(NOW + 1800_000).toISOString(),
				aal, saml_provider_id: PROVIDER,
			},
		} });
		expect(calls.indexOf("auth.getUser")).toBeLessThan(calls.indexOf(`auth.mfa:${token}`));
		expect(body).not.toHaveProperty("validated_session");
		expect(JSON.stringify(body)).not.toContain(SESSION);
		expect(JSON.stringify(body)).not.toContain(PROVIDER);
		const verified = await verifyDelegatedCredentialForBroker({ token: body.access_token, keyId: "test-key",
			publicKeySpkiBase64: env.AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64, issuer: env.AIDR_DELEGATION_ISSUER, nowSeconds: NOW / 1000 });
		expect(verified.ok).toBe(true);
		if (verified.ok) expect(verified.claims).toEqual(CLAIMS);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
	});

	it("records a null SAML provider for an authenticated email session", async () => {
		vi.spyOn(Date, "now").mockReturnValue(NOW);
		const token = authJwt();
		const { db, rpcCalls } = database({ authenticatedToken: token });
		expect((await (await handler(db))(post("issue", `Bearer ${token}`, ISSUE))).status).toBe(201);
		expect(rpcCalls.find(call => call.name === "reserve_delegated_credential")?.args.p_request).toMatchObject({
			validated_session: { saml_provider_id: null, aal: "aal1" },
		});
	});

	it.each([
		{ validated_session: { session_id: SESSION, aal: "aal2", saml_provider_id: PROVIDER } },
		{ validated_session_issued_at: new Date(NOW).toISOString() }, { session_id: SESSION }, { aal: "aal2" },
		{ saml_provider_id: PROVIDER }, { actor_user_id: USER },
	])("rejects caller-provided proof and actor overrides before reservation %#", async (patch) => {
		const token = authJwt();
		const { db, rpcCalls, calls } = database({ authenticatedToken: token });
		const response = await (await handler(db))(post("issue", `Bearer ${token}`, { ...ISSUE, ...patch }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_delegation_request" });
		expect(rpcCalls).toEqual([]);
		expect(calls.some(call => call.startsWith("auth.mfa:"))).toBe(false);
	});

	it.each([
		{ session_id: undefined }, { session_id: "bad" }, { session_id: null },
		{ iat: undefined }, { iat: 0 }, { iat: NOW / 1000 - 60.5 }, { iat: NOW / 1000 + 120 }, { iat: 9e15 },
		{ exp: undefined }, { exp: null }, { exp: "future" }, { exp: NOW / 1000 }, { exp: NOW / 1000 - 120 },
		{ exp: NOW / 1000 + 30.5 }, { exp: 9e15 }, { iat: NOW / 1000 + 30, exp: NOW / 1000 + 20 },
	])("fails invalid, missing or stale authenticated proof before reservation %#", async (patch) => {
		vi.spyOn(Date, "now").mockReturnValue(NOW);
		const token = authJwt(patch);
		const { db, rpcCalls } = database({ authenticatedToken: token });
		const response = await (await handler(db))(post("issue", `Bearer ${token}`, ISSUE));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_access_token" });
		expect(rpcCalls.some(call => call.name === "reserve_delegated_credential" || call.name === "finalize_delegated_credential")).toBe(false);
	});

	it.each([{ assurance: null }, { assurance: "aal3" }, { assuranceError: true }])("fails closed when SDK assurance is unavailable or invalid %#", async (options) => {
		const token = authJwt();
		const { db, rpcCalls } = database({ ...options, authenticatedToken: token });
		const response = await (await handler(db))(post("issue", `Bearer ${token}`, ISSUE));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "assurance_unavailable" });
		expect(rpcCalls.some(call => call.name === "reserve_delegated_credential")).toBe(false);
	});

	it.each([undefined, "Bearer forged-human-jwt"])('rejects unauthenticated issue before any private proof or privileged access %#', async (authorization) => {
		const { db, calls } = database();
		const response = await (await handler(db))(post("issue", authorization, ISSUE));
		expect(response.status).toBe(401);
		expect(calls.filter(call => !call.startsWith("auth."))).toEqual([]);
	});

	it("rejects a revoked authenticated session before assurance lookup or reservation", async () => {
		const token = authJwt();
		const { db, calls, rpcCalls } = database({ authenticatedToken: token, revokedBefore: new Date(NOW).toISOString() });
		const response = await (await handler(db))(post("issue", `Bearer ${token}`, ISSUE));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "session_revoked" });
		expect(calls.some(call => call.startsWith("auth.mfa:"))).toBe(false);
		expect(rpcCalls).toEqual([]);
	});

	it.each([
		[{ reserveError: { code: "42501", message: "private SSO session proof" } }, 403, "delegation_forbidden"],
		[{ reserveError: { code: "XX000", message: "private service details" } }, 503, "delegation_unavailable"],
		[{ finalizeDenied: true }, 503, "delegation_not_finalized"],
	] as const)("returns no signed token when private reservation or finalization denies issuance %#", async (options, status, error) => {
		const token = authJwt();
		const { db } = database({ ...options, authenticatedToken: token });
		const response = await (await handler(db))(post("issue", `Bearer ${token}`, ISSUE));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error });
	});

	it.each(["owner", "admin"])("captures the same trusted private proof for %s grant creation without changing its public DTO", async (role) => {
		vi.spyOn(Date, "now").mockReturnValue(NOW);
		const token = authJwt({ aal: "aal1", amr: [{ method: "sso/saml", provider: PROVIDER }] });
		const { db, rpcCalls, calls } = database({ authenticatedToken: token, assurance: "aal2", role,
			grantResult: { ...GRANT_RESULT, validated_session: { session_id: SESSION }, private_token: "private detail" } });
		const response = await (await handler(db))(post("grant", `Bearer ${token}`, GRANT_BODY));
		expect(response.status).toBe(201);
		expect(await response.json()).toEqual({ ok: true, ...GRANT_RESULT });
		expect(rpcCalls.find(call => call.name === "create_delegated_credential_grant")?.args).toEqual({
			p_actor_user_id: USER, p_request: { ...GRANT_BODY,
				validated_session_issued_at: new Date(NOW - 60_000).toISOString(), validated_session: {
					session_id: SESSION, issued_at: new Date(NOW - 60_000).toISOString(), expires_at: new Date(NOW + 1800_000).toISOString(),
					aal: "aal2", saml_provider_id: PROVIDER,
				},
			},
		});
		expect(calls.indexOf("auth.getUser")).toBeLessThan(calls.indexOf(`auth.mfa:${token}`));
		expect(calls.indexOf(`auth.mfa:${token}`)).toBeLessThan(calls.indexOf("rpc:create_delegated_credential_grant"));
		expect(rpcCalls.some(call => call.name === "reserve_delegated_credential" || call.name === "finalize_delegated_credential")).toBe(false);
	});

	it.each([
		{ validated_session: { session_id: SESSION, aal: "aal2", saml_provider_id: PROVIDER } },
		{ validated_session_issued_at: new Date(NOW).toISOString() }, { session_id: SESSION }, { aal: "aal2" },
		{ saml_provider_id: PROVIDER }, { actor_user_id: USER },
	])("rejects caller-supplied grant proof before SDK capture or create RPC %#", async (patch) => {
		const token = authJwt();
		const { db, rpcCalls, calls } = database({ authenticatedToken: token, role: "owner" });
		const response = await (await handler(db))(post("grant", `Bearer ${token}`, { ...GRANT_BODY, ...patch }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_grant" });
		expect(rpcCalls).toEqual([]);
		expect(calls.some(call => call.startsWith("auth.mfa:"))).toBe(false);
	});

	it.each([{ session_id: undefined }, { session_id: "bad" }, { iat: NOW / 1000 + 120 }, { exp: undefined },
		{ exp: NOW / 1000 }, { exp: 9e15 }])("rejects missing, invalid or expired grant issuer proof before creation %#", async (patch) => {
		vi.spyOn(Date, "now").mockReturnValue(NOW);
		const token = authJwt(patch);
		const { db, rpcCalls } = database({ authenticatedToken: token, role: "owner" });
		const response = await (await handler(db))(post("grant", `Bearer ${token}`, GRANT_BODY));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_access_token" });
		expect(rpcCalls.some(call => call.name === "create_delegated_credential_grant")).toBe(false);
	});

	it.each([{ assurance: null }, { assurance: "aal3" }, { assuranceError: true }])("fails unavailable grant issuer assurance before creation %#", async (options) => {
		const token = authJwt();
		const { db, rpcCalls } = database({ ...options, authenticatedToken: token, role: "owner" });
		const response = await (await handler(db))(post("grant", `Bearer ${token}`, GRANT_BODY));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "assurance_unavailable" });
		expect(rpcCalls.some(call => call.name === "create_delegated_credential_grant")).toBe(false);
	});

	it.each([
		[{ grantError: { code: "42501", message: "private provider switched during lock wait" } }, 403, "delegation_forbidden"],
		[{ grantError: { code: "XX000", message: "private grant service failure" } }, 503, "delegation_unavailable"],
		[{ grantResult: false }, 503, "delegation_unavailable"], [{ grantResult: null }, 503, "delegation_unavailable"],
	] as const)("reports post-lock grant denial and failed results without a public grant %#", async (options, status, error) => {
		const token = authJwt();
		const { db, rpcCalls } = database({ ...options, authenticatedToken: token, role: "owner" });
		const response = await (await handler(db))(post("grant", `Bearer ${token}`, GRANT_BODY));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error });
		expect(rpcCalls.some(call => call.name === "create_delegated_credential_grant")).toBe(true);
	});
});
