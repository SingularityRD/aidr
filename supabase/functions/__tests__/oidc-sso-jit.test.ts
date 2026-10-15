// Just-in-time OIDC provisioning: handler wiring, group-claim extraction and
// the operator-controlled internal IdP egress exemption. The provisioning
// transaction itself (role mapping, SCIM precedence, removal, audit, RLS) is
// covered against real PostgreSQL by scripts/oidc-jit-provisioning-postgres.test.mjs.

import { beforeEach, describe, expect, it } from "vitest";

import { normalizeInternalIdpHosts } from "../../../scripts/lib/onprem-sso.mjs";

import { assertSafeUrl, isOperatorPrivateAddress, parseInternalHosts, safeFetchJson } from "../_shared/safe-fetch.ts";
import { createOidcHandler } from "../oidc-sso/handler.ts";
import { JwksCache } from "../oidc-sso/jwks.ts";
import { base64UrlEncode, groupClaimValues } from "../oidc-sso/oidc.ts";
import type { JitStatus } from "../oidc-sso/types.ts";
import {
	baseClaims,
	caller,
	freePlan,
	ISSUER_A,
	type IdpFixture,
	makeIdp,
	makeKey,
	makeWorld,
	MEMBER_A,
	mintJwt,
	NOW_MS,
	OWNER_A,
	post,
	PROVIDER_A,
	providerRow,
	sha256Text,
	TENANT_A,
	type TestKey,
	type World,
} from "./oidc-test-kit.ts";

interface Ctx {
	world: World;
	handler: (req: Request) => Promise<Response>;
	idp: IdpFixture;
	key: TestKey;
}

let ctx: Ctx;

async function call(body: Record<string, unknown>, token?: string) {
	const response = await ctx.handler(post(body, token));
	return { status: response.status, json: (await response.json()) as Record<string, unknown> };
}

async function login(claims: Record<string, unknown> = {}) {
	const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
	const started = await call({ action: "start", provider_id: PROVIDER_A, binding_challenge: await sha256Text(verifier) });
	expect(started.status, JSON.stringify(started.json)).toBe(200);
	const params = new URL(String(started.json.authorization_url)).searchParams;
	ctx.idp.nextIdToken = await mintJwt({ key: ctx.key, claims: baseClaims({ nonce: params.get("nonce"), ...claims }) });
	return call({ action: "callback", code: "authorization-code", state: params.get("state"), binding_verifier: verifier });
}

beforeEach(async () => {
	const key = await makeKey("RS256", "kA");
	const idp = makeIdp(ISSUER_A, [key], "https://login.microsoftonline.com");
	const cache = new JwksCache({
		now: () => NOW_MS,
		fetchKeys: async (uri) => (uri === idp.jwksUri ? idp.keys.map((entry) => entry.publicJwk) : null),
	});
	const world = makeWorld({ idps: [idp], jwks: (uri, kid, alg) => cache.getKey(uri, kid, alg) });
	const store = world.store;
	store.providers.set(
		PROVIDER_A,
		providerRow({
			groups_claim: "groups",
			discovery: {
				issuer: idp.issuer,
				authorization_endpoint: idp.authorizationEndpoint,
				token_endpoint: idp.tokenEndpoint,
				jwks_uri: idp.jwksUri,
			},
		}),
	);
	store.domains.push({ tenant_id: TENANT_A, domain: "a-corp.test", verification_token: "t".repeat(40), verified_at: new Date(NOW_MS).toISOString() });
	store.members.set(`${TENANT_A}:${OWNER_A}`, "owner");
	store.members.set(`${TENANT_A}:${MEMBER_A}`, "member");
	store.jitPolicies.set(TENANT_A, { enabled: true, issuer: ISSUER_A, allowed_domains: ["a-corp.test"], default_role: null });
	store.jitMappings.set(TENANT_A, new Map([["/aidr/admins", "admin"], ["/aidr/users", "member"]]));
	world.callers.set("owner-a", caller(OWNER_A));
	world.callers.set("owner-a-aal1", caller(OWNER_A, { assurance: "aal1" }));
	world.callers.set("member-a", caller(MEMBER_A));
	ctx = { world, handler: createOidcHandler(world.deps), idp, key };
});

describe("JIT provisioning at login", () => {
	it("is not consulted when the tenant has not opted in (existing behaviour)", async () => {
		ctx.world.store.jitPolicies.delete(TENANT_A);
		const result = await login({ groups: ["/aidr/admins"] });
		expect(result.status).toBe(200);
		expect(ctx.world.store.jitCalls).toHaveLength(0);
		const userId = [...ctx.world.store.authUsers][0] as string;
		expect(await ctx.world.store.memberRole(userId, TENANT_A)).toBeNull();
	});

	it("provisions from the group claim without SCIM and audits the JIT outcome", async () => {
		const result = await login({ groups: ["/aidr/users", "/aidr/admins", "/aidr/users"] });
		expect(result.status, JSON.stringify(result.json)).toBe(200);
		expect(result.json).toMatchObject({ ok: true, tenant_id: TENANT_A, verification_type: "magiclink" });
		const userId = [...ctx.world.store.authUsers][0] as string;
		expect(await ctx.world.store.memberRole(userId, TENANT_A)).toBe("admin");
		expect(ctx.world.store.jitCalls).toEqual([
			{
				providerId: PROVIDER_A,
				authUserId: userId,
				subject: "subject-1",
				emailDomain: "a-corp.test",
				groups: ["/aidr/users", "/aidr/admins"],
				groupsEvaluable: true,
				requestId: "req-test",
			},
		]);
		const audit = ctx.world.store.audits.find((entry) => entry.action === "identity.oidc.login_succeeded");
		expect(audit?.detail).toMatchObject({ jit: "provisioned", enforced: false });
	});

	it("accepts the single-string group claim ADFS sends for one group", async () => {
		const result = await login({ groups: "/aidr/users" });
		expect(result.status).toBe(200);
		expect(ctx.world.store.jitCalls[0]?.groups).toEqual(["/aidr/users"]);
	});

	it("uses the default role when no group matches, and denies when there is none", async () => {
		const denied = await login({ groups: ["unrelated"] });
		expect(denied).toEqual({ status: 403, json: { error: "sso_login_failed", reason: "group_not_mapped" } });
		expect(ctx.world.store.tickets.size).toBe(0);
		expect(ctx.world.store.audits.at(-1)).toMatchObject({ action: "identity.oidc.login_failed", detail: { reason: "jit_no_role" } });

		ctx.world.store.jitPolicies.set(TENANT_A, { enabled: true, issuer: ISSUER_A, allowed_domains: ["a-corp.test"], default_role: "viewer" });
		const admitted = await login({ groups: ["unrelated"] });
		expect(admitted.status).toBe(200);
	});

	it("refuses a domain outside the JIT allow-list and Entra group overage without changing anything", async () => {
		ctx.world.store.jitPolicies.set(TENANT_A, { enabled: true, issuer: ISSUER_A, allowed_domains: ["other.test"], default_role: "member" });
		expect((await login({ groups: ["/aidr/users"] })).json).toEqual({ error: "sso_login_failed", reason: "domain_not_verified" });

		ctx.world.store.jitPolicies.set(TENANT_A, { enabled: true, issuer: ISSUER_A, allowed_domains: ["a-corp.test"], default_role: "member" });
		const overage = await login({ _claim_names: { groups: "src1" } });
		expect(overage).toEqual({ status: 403, json: { error: "sso_login_failed", reason: "groups_overage" } });
		expect(ctx.world.store.jitCalls.at(-1)).toMatchObject({ groups: null, groupsEvaluable: false });
		const malformed = await login({ groups: [1, 2] });
		expect(malformed.json.reason).toBe("groups_overage");
	});

	it.each<[JitStatus, number, string]>([
		["removed_by_admin", 403, "not_provisioned"],
		["scim_inactive", 403, "not_provisioned"],
		["directory_authoritative", 403, "not_provisioned"],
		["disabled", 403, "not_provisioned"],
		["tenant_inactive", 403, "not_provisioned"],
		["revoked", 403, "group_not_mapped"],
		["scim_conflict", 409, "identity_conflict"],
		["other_tenant", 409, "identity_conflict"],
	])("maps the %s outcome to a coarse %i %s denial with no session", async (status, http, reason) => {
		ctx.world.store.jitOutcome = { status, role: null };
		const result = await login({ groups: ["/aidr/admins"] });
		expect(result).toEqual({ status: http, json: { error: "sso_login_failed", reason } });
		expect(ctx.world.store.tickets.size).toBe(0);
		expect(ctx.world.store.audits.at(-1)?.detail.reason).toBe(`jit_${status}`);
	});

	it("still requires a live membership after an admitted outcome (e.g. SCIM bound with no SCIM group)", async () => {
		ctx.world.store.jitOutcome = { status: "scim_bound", role: null };
		const result = await login({ groups: ["/aidr/admins"] });
		expect(result).toEqual({ status: 403, json: { error: "sso_login_failed", reason: "not_provisioned" } });
	});

	it("fails closed when the JIT policy cannot be read or the transaction fails", async () => {
		ctx.world.store.failJitRead = true;
		expect(await login()).toEqual({ status: 503, json: { error: "sso_login_failed", reason: "provider_unavailable" } });
		ctx.world.store.failJitRead = false;
		ctx.world.store.jitOutcome = "error";
		expect(await login()).toEqual({ status: 503, json: { error: "sso_login_failed", reason: "provider_unavailable" } });
		expect(ctx.world.store.tickets.size).toBe(0);
	});
});

describe("JIT administration", () => {
	const policy = {
		action: "put_jit_policy",
		tenant_id: TENANT_A,
		enabled: true,
		allowed_domains: ["A-Corp.test "],
		default_role: "viewer",
		mappings: [
			{ group: "cn=aidr-admins,ou=groups,dc=corp,dc=example", role: "admin" },
			{ group: "/aidr/users", role: "member" },
		],
	};

	it("requires an owner at AAL2 and the SSO plan feature", async () => {
		expect((await call(policy)).status).toBe(401);
		expect(await call(policy, "member-a")).toMatchObject({ status: 403, json: { error: "owner_required" } });
		expect(await call(policy, "owner-a-aal1")).toMatchObject({ status: 403, json: { error: "mfa_required" } });
		ctx.world.store.plans.set(TENANT_A, { data: freePlan(TENANT_A), error: null });
		expect((await call(policy, "owner-a")).status).toBe(402);
		expect(ctx.world.store.jitSaves).toHaveLength(0);
	});

	it("validates the policy before writing", async () => {
		const bad: Array<Record<string, unknown>> = [
			{ enabled: "yes" },
			{ allowed_domains: ["not a domain"] },
			{ allowed_domains: "a-corp.test" },
			{ default_role: "admin" },
			{ default_role: "owner" },
			{ mappings: [{ group: "g", role: "owner" }] },
			{ mappings: [{ group: "g", role: "admin" }, { group: "g", role: "viewer" }] },
			{ mappings: [{ group: "line\nbreak", role: "admin" }] },
			{ mappings: [{ group: "x".repeat(257), role: "admin" }] },
			{ mappings: Array.from({ length: 101 }, (_, index) => ({ group: `g${index}`, role: "viewer" })) },
		];
		for (const override of bad) {
			const result = await call({ ...policy, ...override }, "owner-a");
			expect(result, JSON.stringify(override)).toMatchObject({ status: 400, json: { error: "invalid_jit_policy" } });
		}
		expect(ctx.world.store.jitSaves).toHaveLength(0);
	});

	it("refuses domains this tenant has not verified and saves a valid policy", async () => {
		expect(await call({ ...policy, allowed_domains: ["unverified.test"] }, "owner-a")).toMatchObject({
			status: 409,
			json: { error: "jit_domain_not_verified" },
		});
		expect(await call(policy, "owner-a")).toMatchObject({ status: 200, json: { ok: true, enabled: true } });
		expect(ctx.world.store.jitSaves.at(-1)).toMatchObject({
			providerId: PROVIDER_A,
			allowedDomains: ["a-corp.test"],
			defaultRole: "viewer",
			mappings: policy.mappings,
		});
		const config = await call({ action: "get_config", tenant_id: TENANT_A }, "owner-a");
		expect(config.json.jit).toMatchObject({
			enabled: true,
			issuer_matches: true,
			allowed_domains: ["a-corp.test"],
			default_role: "viewer",
			directory_authoritative: false,
			active_members: 0,
			removed_members: [{ user_id: "77777777-7777-4777-8777-777777777777", email: "gone@a-corp.test" }],
		});
	});

	it("re-admits only a removed JIT user, as an owner at AAL2", async () => {
		const request = { action: "jit_readmit", tenant_id: TENANT_A, user_id: "77777777-7777-4777-8777-777777777777" };
		expect(await call(request, "member-a")).toMatchObject({ status: 403 });
		expect(await call(request, "owner-a")).toMatchObject({ status: 200, json: { ok: true } });
		expect(await call({ ...request, user_id: MEMBER_A }, "owner-a")).toMatchObject({ status: 409, json: { error: "jit_member_not_removed" } });
		expect(await call({ ...request, user_id: "nope" }, "owner-a")).toMatchObject({ status: 400 });
	});
});

describe("extra authorization scopes (ADFS allatclaims)", () => {
	it("adds only the configured allow-listed scopes to the authorization request", async () => {
		const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
		const challenge = await sha256Text(verifier);
		const scopeOf = async () => {
			const started = await call({ action: "start", provider_id: PROVIDER_A, binding_challenge: challenge });
			return new URL(String(started.json.authorization_url)).searchParams.get("scope");
		};
		expect(await scopeOf()).toBe("openid email profile");
		const current = ctx.world.store.providers.get(PROVIDER_A);
		if (!current) throw new Error("fixture provider missing");
		ctx.world.store.providers.set(PROVIDER_A, { ...current, extra_scopes: ["allatclaims"] });
		expect(await scopeOf()).toBe("openid email profile allatclaims");
	});

	it("refuses scopes outside the allow-list when saving a provider", async () => {
		const base = {
			action: "put_provider",
			tenant_id: TENANT_A,
			kind: "generic",
			display_name: "ADFS",
			issuer: "https://adfs.corp.example/adfs",
			client_id: "aidr",
			token_auth_method: "none",
		};
		for (const extra_scopes of [["offline_access"], ["allatclaims", "allatclaims"], "allatclaims", ["groups", "roles", "allatclaims", "x"]]) {
			const result = await call({ ...base, extra_scopes }, "owner-a");
			expect(result, JSON.stringify(extra_scopes)).toMatchObject({ status: 400, json: { reason: "invalid_extra_scopes" } });
		}
	});
});

describe("groupClaimValues", () => {
	it("returns exact values, accepts a single string and treats overage or junk as not evaluable", () => {
		expect(groupClaimValues({ groups: ["/a", "/a", "/b"] }, "groups")).toEqual({ evaluable: true, values: ["/a", "/b"] });
		expect(groupClaimValues({ group: "Domain Users" }, "group")).toEqual({ evaluable: true, values: ["Domain Users"] });
		expect(groupClaimValues({}, "groups")).toEqual({ evaluable: true, values: [] });
		expect(groupClaimValues({ groups: ["/a"] }, null)).toEqual({ evaluable: true, values: [] });
		expect(groupClaimValues({ hasgroups: true }, "groups")).toEqual({ evaluable: false, reason: "overage" });
		expect(groupClaimValues({ _claim_names: { groups: "src1" } }, "groups")).toEqual({ evaluable: false, reason: "overage" });
		expect(groupClaimValues({ groups: [""] }, "groups")).toMatchObject({ evaluable: false });
		expect(groupClaimValues({ groups: { a: 1 } }, "groups")).toMatchObject({ evaluable: false });
		expect(groupClaimValues({ groups: Array.from({ length: 1001 }, (_, index) => `g${index}`) }, "groups")).toMatchObject({ evaluable: false });
	});
});

describe("operator-listed internal IdP hosts (AIDR_OIDC_INTERNAL_IDP_HOSTS)", () => {
	const dns = (answers: Record<string, string[]>) => async (host: string, type: "A" | "AAAA") => {
		const list = (answers[host] ?? []).filter((address) => (type === "A" ? !address.includes(":") : address.includes(":")));
		if (list.length === 0) throw new Error("NODATA");
		return list;
	};
	const internal = parseInternalHosts("keycloak.corp.example:8443, adfs.corp.local");
	if (!internal.ok) throw new Error("fixture must parse");
	const hosts = internal.hosts;

	it("parses exact FQDN[:port] entries and rejects anything else as a whole", () => {
		expect([...hosts]).toEqual([["keycloak.corp.example", [8443]], ["adfs.corp.local", [443]]]);
		expect(parseInternalHosts("")).toEqual({ ok: true, hosts: new Map() });
		expect(parseInternalHosts(undefined)).toEqual({ ok: true, hosts: new Map() });
		for (const value of [
			"10.0.0.5",
			"[fd00::1]:443",
			"keycloak",
			"*.corp.example",
			"localhost.",
			"sso.localhost",
			"metadata.google.internal",
			"host.corp.example:0",
			"host.corp.example:70000",
			"https://host.corp.example",
			"good.corp.example, bad_host.corp.example",
			Array.from({ length: 17 }, (_, index) => `h${index}.corp.example`).join(","),
		]) {
			expect(parseInternalHosts(value), value).toEqual({ ok: false, error: "invalid_internal_hosts" });
		}
	});

	it("agrees with the deployment-prepare validator on every input (parity)", () => {
		const corpus = [
			"",
			"keycloak.corp.example",
			"Keycloak.Corp.Example:8443, adfs.corp.local",
			"adfs.corp.local:443 adfs.corp.local",
			"idp.example.com.",
			"10.0.0.5",
			"[fd00::1]:443",
			"keycloak",
			"*.corp.example",
			"sso.localhost",
			"localhost.localdomain",
			"metadata.google.internal",
			"instance-data.ec2.internal",
			"a.corp.example:0",
			"a.corp.example:65535",
			"a.corp.example:65536",
			"https://a.corp.example",
			"a.corp.example:84a3",
			"bad_host.corp.example",
			Array.from({ length: 16 }, (_, index) => `h${index}.corp.example`).join(","),
			Array.from({ length: 17 }, (_, index) => `h${index}.corp.example`).join(","),
		];
		for (const value of corpus) {
			const edge = parseInternalHosts(value);
			let prepared: string | null;
			try {
				prepared = normalizeInternalIdpHosts(value);
			} catch {
				prepared = null;
			}
			expect(prepared === null, value).toBe(!edge.ok);
			if (edge.ok && prepared !== null) expect(parseInternalHosts(prepared), value).toEqual(edge);
		}
	});

	it("classifies only RFC 1918, CGNAT and ULA as operator-private", () => {
		for (const address of ["10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.10.1", "100.64.0.1", "fd12:3456::1", "fc00::1"])
			expect(isOperatorPrivateAddress(address), address).toBe(true);
		for (const address of ["127.0.0.1", "169.254.169.254", "0.0.0.0", "172.32.0.1", "224.0.0.1", "::1", "fe80::1", "::ffff:10.0.0.1", "8.8.8.8"])
			expect(isOperatorPrivateAddress(address), address).toBe(false);
	});

	it("lets a listed host resolve privately on its listed port, and nothing else", async () => {
		const resolveDns = dns({
			"keycloak.corp.example": ["10.20.30.40"],
			"adfs.corp.local": ["192.168.1.10", "fd00::10"],
			"loopback.corp.example": ["127.0.0.1"],
			"other.corp.example": ["10.20.30.41"],
		});
		const ok = await assertSafeUrl("https://keycloak.corp.example:8443/realms/corp/.well-known/openid-configuration", { resolveDns, internalHosts: hosts });
		expect(ok).toMatchObject({ ok: true, addresses: ["10.20.30.40"] });
		expect(await assertSafeUrl("https://adfs.corp.local/adfs/.well-known/openid-configuration", { resolveDns, internalHosts: hosts })).toMatchObject({ ok: true });
		// Same host, port that was not listed.
		expect(await assertSafeUrl("https://keycloak.corp.example:9443/x", { resolveDns, internalHosts: hosts })).toEqual({ ok: false, error: "port_not_allowed" });
		// Never plain http, even for a listed host.
		expect(await assertSafeUrl("http://keycloak.corp.example:8443/x", { resolveDns, internalHosts: hosts })).toEqual({ ok: false, error: "insecure_scheme" });
		// Unlisted hosts keep the public-only policy.
		expect(await assertSafeUrl("https://other.corp.example/x", { resolveDns, internalHosts: hosts })).toEqual({ ok: false, error: "private_address" });
		// Without the exemption the listed host is refused exactly as before.
		expect(await assertSafeUrl("https://keycloak.corp.example/x", { resolveDns })).toEqual({ ok: false, error: "private_address" });
		expect(await assertSafeUrl("https://adfs.corp.local/x", { resolveDns })).toEqual({ ok: false, error: "blocked_host" });
	});

	it("still refuses loopback, link-local and metadata answers for a listed host", async () => {
		const listed = parseInternalHosts("idp.corp.example");
		if (!listed.ok) throw new Error("fixture must parse");
		for (const answer of ["127.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "fe80::1"]) {
			const result = await assertSafeUrl("https://idp.corp.example/x", { resolveDns: dns({ "idp.corp.example": [answer] }), internalHosts: listed.hosts });
			expect(result, answer).toEqual({ ok: false, error: "private_address" });
		}
		const mixed = await assertSafeUrl("https://idp.corp.example/x", { resolveDns: dns({ "idp.corp.example": ["10.0.0.1", "127.0.0.1"] }), internalHosts: listed.hosts });
		expect(mixed).toEqual({ ok: false, error: "private_address" });
	});

	it("keeps refusing redirects from a listed host", async () => {
		const result = await safeFetchJson("https://keycloak.corp.example:8443/x", {}, {
			resolveDns: dns({ "keycloak.corp.example": ["10.20.30.40"] }),
			internalHosts: hosts,
			fetch: async () => new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } }),
		});
		expect(result).toEqual({ ok: false, error: "redirect_blocked", status: 302 });
	});
});
