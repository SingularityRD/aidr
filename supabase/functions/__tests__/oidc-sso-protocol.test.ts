import { describe, expect, it } from "vitest";

import { isPrivateIpAddress as coreIsPrivateIpAddress } from "../../../packages/core/src/mcp-transport.ts";
import { ipVersion, isBlockedHostname, isPrivateIpAddress, isPublicIpAddress } from "../_shared/egress-guard.ts";
import { assertSafeUrl, safeFetchJson } from "../_shared/safe-fetch.ts";
import { resolveClientSecret } from "../oidc-sso/client-secrets.ts";
import { JwksCache, parseJwks } from "../oidc-sso/jwks.ts";
import {
	base64UrlEncode,
	buildAuthorizationUrl,
	constantTimeEqual,
	type IdTokenExpectations,
	type Jwk,
	mapGroupClaims,
	type MappedRole,
	normalizeIssuer,
	type OidcAlgorithm,
	parseJwt,
	pkceChallenge,
	validateDiscovery,
	verifyIdToken,
} from "../oidc-sso/oidc.ts";
import { baseClaims, ISSUER_A, ISSUER_B, makeKey, mintJwt, NOW_MS, NOW_S, sha256Text, TENANT_A, TENANT_B, type TestKey } from "./oidc-test-kit.ts";

const NONCE = "nonce-value-1";

async function expectations(keys: TestKey[], overrides: Partial<IdTokenExpectations> = {}): Promise<IdTokenExpectations> {
	return {
		issuer: ISSUER_A,
		clientId: "client-a",
		nonceHash: await sha256Text(NONCE),
		allowedAlgorithms: ["RS256", "PS256", "ES256"],
		nowSeconds: NOW_S,
		clockSkewSeconds: 60,
		getKey: async (kid, alg) => {
			const match = keys.find((key) => key.alg === alg && (kid === undefined || key.kid === kid));
			return match ? { status: "found", key: match.publicJwk } : { status: "unknown_kid" };
		},
		...overrides,
	};
}

const claims = (overrides: Record<string, unknown> = {}) => baseClaims({ nonce: NONCE, ...overrides });

describe("ID token verification", () => {
	it.each<OidcAlgorithm>(["RS256", "PS256", "ES256"])("accepts a valid %s token", async (alg) => {
		const key = await makeKey(alg, `k-${alg}`);
		const token = await mintJwt({ key, claims: claims() });
		const result = await verifyIdToken(token, await expectations([key]));
		expect(result).toMatchObject({ ok: true, alg });
	});

	it("rejects a wrong audience, including an audience array without this client", async () => {
		const key = await makeKey("RS256", "k1");
		for (const aud of ["someone-else", ["a", "b"], [], 7]) {
			const token = await mintJwt({ key, claims: claims({ aud }) });
			expect(await verifyIdToken(token, await expectations([key]))).toEqual({ ok: false, error: "audience_mismatch" });
		}
	});

	it("requires azp to name this client when there are several audiences", async () => {
		const key = await makeKey("RS256", "k1");
		const multi = await mintJwt({ key, claims: claims({ aud: ["client-a", "other"] }) });
		expect(await verifyIdToken(multi, await expectations([key]))).toEqual({ ok: false, error: "azp_mismatch" });
		const ok = await mintJwt({ key, claims: claims({ aud: ["client-a", "other"], azp: "client-a" }) });
		expect((await verifyIdToken(ok, await expectations([key]))).ok).toBe(true);
		const wrongAzp = await mintJwt({ key, claims: claims({ azp: "other" }) });
		expect(await verifyIdToken(wrongAzp, await expectations([key]))).toEqual({ ok: false, error: "azp_mismatch" });
	});

	it("rejects a wrong issuer, including near-miss and trailing-slash variants", async () => {
		const key = await makeKey("RS256", "k1");
		for (const iss of ["https://evil.example/", `${ISSUER_A}/`, ISSUER_A.toUpperCase(), undefined]) {
			const token = await mintJwt({ key, claims: claims({ iss }) });
			expect(await verifyIdToken(token, await expectations([key]))).toEqual({ ok: false, error: "issuer_mismatch" });
		}
	});

	it("enforces exp with clock skew in both directions", async () => {
		const key = await makeKey("RS256", "k1");
		const run = async (overrides: Record<string, unknown>) =>
			verifyIdToken(await mintJwt({ key, claims: claims(overrides) }), await expectations([key]));
		expect(await run({ exp: NOW_S - 120 })).toEqual({ ok: false, error: "expired" });
		expect(await run({ exp: NOW_S - 61 })).toEqual({ ok: false, error: "expired" });
		expect((await run({ exp: NOW_S - 30 })).ok).toBe(true); // inside the 60 s skew
		expect(await run({ exp: undefined })).toEqual({ ok: false, error: "claims_invalid" });
		expect(await run({ exp: "9999999999" })).toEqual({ ok: false, error: "claims_invalid" });
	});

	it("enforces nbf, iat and a maximum token age", async () => {
		const key = await makeKey("RS256", "k1");
		const run = async (overrides: Record<string, unknown>) =>
			verifyIdToken(await mintJwt({ key, claims: claims(overrides) }), await expectations([key]));
		expect(await run({ nbf: NOW_S + 300 })).toEqual({ ok: false, error: "not_yet_valid" });
		expect((await run({ nbf: NOW_S + 30 })).ok).toBe(true);
		expect(await run({ iat: NOW_S + 300 })).toEqual({ ok: false, error: "iat_invalid" });
		expect(await run({ iat: undefined })).toEqual({ ok: false, error: "iat_invalid" });
		expect(await run({ iat: NOW_S - 3_600, exp: NOW_S + 3_600 })).toEqual({ ok: false, error: "token_too_old" });
	});

	it("caps configured clock skew at two minutes", async () => {
		const key = await makeKey("RS256", "k1");
		const token = await mintJwt({ key, claims: claims({ exp: NOW_S - 600 }) });
		expect(await verifyIdToken(token, await expectations([key], { clockSkewSeconds: 86_400 }))).toEqual({
			ok: false,
			error: "expired",
		});
	});

	it("rejects a nonce mismatch or a missing nonce", async () => {
		const key = await makeKey("RS256", "k1");
		for (const nonce of ["another-nonce", "", undefined, 5]) {
			const token = await mintJwt({ key, claims: claims({ nonce }) });
			expect(await verifyIdToken(token, await expectations([key]))).toEqual({ ok: false, error: "nonce_mismatch" });
		}
	});

	it("rejects alg=none in every spelling, with or without a signature", async () => {
		const key = await makeKey("RS256", "k1");
		for (const alg of ["none", "None", "NONE", "nOnE"]) {
			for (const rawSignature of ["", "AAAA"]) {
				const token = await mintJwt({ key: null, header: { alg }, claims: claims(), rawSignature });
				expect(await verifyIdToken(token, await expectations([key]))).toEqual({ ok: false, error: "alg_not_allowed" });
			}
		}
		// Even if an operator somehow listed it, "none" is not a supported algorithm.
		const token = await mintJwt({ key: null, header: { alg: "none" }, claims: claims(), rawSignature: "" });
		expect(
			await verifyIdToken(token, await expectations([key], { allowedAlgorithms: ["none" as OidcAlgorithm] })),
		).toEqual({ ok: false, error: "alg_not_allowed" });
	});

	it("rejects HMAC algorithms (key-confusion: public key used as the HMAC secret)", async () => {
		const key = await makeKey("RS256", "k1");
		const secret = await crypto.subtle.importKey("raw", new TextEncoder().encode(JSON.stringify(key.publicJwk)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
		const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT", kid: "k1" })));
		const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(claims())));
		const mac = new Uint8Array(await crypto.subtle.sign("HMAC", secret, new TextEncoder().encode(`${header}.${payload}`)));
		const token = `${header}.${payload}.${base64UrlEncode(mac)}`;
		expect(await verifyIdToken(token, await expectations([key]))).toEqual({ ok: false, error: "alg_not_allowed" });
	});

	it("honours the provider's algorithm allow-list, not the token's choice", async () => {
		const rs = await makeKey("RS256", "k-rs");
		const token = await mintJwt({ key: rs, claims: claims() });
		expect(await verifyIdToken(token, await expectations([rs], { allowedAlgorithms: ["ES256"] }))).toEqual({
			ok: false,
			error: "alg_not_allowed",
		});
	});

	it("rejects a tampered payload, a swapped signature and a signature from another key", async () => {
		const key = await makeKey("RS256", "k1");
		const attacker = await makeKey("RS256", "k1");
		const good = await mintJwt({ key, claims: claims() });
		const [header, , signature] = good.split(".") as [string, string, string];
		const forgedPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(claims({ sub: "admin" }))));
		expect(await verifyIdToken(`${header}.${forgedPayload}.${signature}`, await expectations([key]))).toEqual({ ok: false, error: "signature_invalid" });
		const forged = await mintJwt({ key, signWith: attacker.privateKey, claims: claims() });
		expect(await verifyIdToken(forged, await expectations([key]))).toEqual({ ok: false, error: "signature_invalid" });
		const truncated = await mintJwt({ key, claims: claims(), rawSignature: "AAAA" });
		expect(await verifyIdToken(truncated, await expectations([key]))).toEqual({ ok: false, error: "signature_invalid" });
	});

	it("verifies the signature BEFORE trusting any claim", async () => {
		const key = await makeKey("RS256", "k1");
		const attacker = await makeKey("RS256", "k1");
		const forged = await mintJwt({ key, signWith: attacker.privateKey, claims: claims({ iss: "https://evil.example" }) });
		// A claim error would reveal that claims were evaluated first.
		expect(await verifyIdToken(forged, await expectations([key]))).toEqual({ ok: false, error: "signature_invalid" });
	});

	it("never dereferences jku / jwk / x5u header parameters and rejects crit", async () => {
		const trusted = await makeKey("RS256", "k1");
		const attacker = await makeKey("RS256", "k1");
		const embedded = await mintJwt({
			key: trusted,
			signWith: attacker.privateKey,
			header: { jwk: attacker.publicJwk, jku: "https://evil.example/jwks", x5u: "https://evil.example/cert" },
			claims: claims(),
		});
		expect(await verifyIdToken(embedded, await expectations([trusted]))).toEqual({ ok: false, error: "signature_invalid" });
		const crit = await mintJwt({ key: trusted, header: { crit: ["exp"] }, claims: claims() });
		expect(await verifyIdToken(crit, await expectations([trusted]))).toEqual({ ok: false, error: "malformed_token" });
	});

	it("rejects malformed, JWE-shaped and oversized tokens", async () => {
		const key = await makeKey("RS256", "k1");
		for (const token of ["", "a.b", "a.b.c.d", "a.b.c.d.e", "!!.!!.!!", `${"A".repeat(20_000)}.x.y`]) {
			expect(await verifyIdToken(token, await expectations([key]))).toEqual({ ok: false, error: "malformed_token" });
		}
		expect(parseJwt("a.b.c.d.e")).toBeNull();
	});

	it("rejects a missing or oversized subject", async () => {
		const key = await makeKey("RS256", "k1");
		for (const sub of [undefined, "", "x".repeat(256), 12]) {
			const token = await mintJwt({ key, claims: claims({ sub }) });
			expect(await verifyIdToken(token, await expectations([key]))).toEqual({ ok: false, error: "subject_missing" });
		}
	});

	it("rejects weak RSA keys and keys not meant for signatures", async () => {
		const weak = await makeKey("RS256", "weak", 1024);
		const token = await mintJwt({ key: weak, claims: claims() });
		expect(await verifyIdToken(token, await expectations([weak]))).toEqual({ ok: false, error: "signature_invalid" });
		const strong = await makeKey("RS256", "enc");
		const encOnly = { ...strong, publicJwk: { ...strong.publicJwk, use: "enc" } };
		const signed = await mintJwt({ key: strong, claims: claims() });
		expect(await verifyIdToken(signed, await expectations([encOnly], { getKey: async () => ({ status: "found", key: encOnly.publicJwk }) }))).toEqual({
			ok: false,
			error: "signature_invalid",
		});
	});

	it("rejects a key whose declared alg or key type does not match the token", async () => {
		const rs = await makeKey("RS256", "k1");
		const token = await mintJwt({ key: rs, claims: claims() });
		const wrongAlg: Jwk = { ...rs.publicJwk, alg: "PS256" };
		expect(await verifyIdToken(token, await expectations([rs], { getKey: async () => ({ status: "found", key: wrongAlg }) }))).toEqual({ ok: false, error: "signature_invalid" });
		const ec = await makeKey("ES256", "e1");
		expect(await verifyIdToken(token, await expectations([rs], { getKey: async () => ({ status: "found", key: ec.publicJwk }) }))).toEqual({ ok: false, error: "signature_invalid" });
	});

	it("reports unknown kid and unavailable keys distinctly", async () => {
		const key = await makeKey("RS256", "k1");
		const token = await mintJwt({ key, claims: claims() });
		expect(await verifyIdToken(token, await expectations([], { getKey: async () => ({ status: "unknown_kid" }) }))).toEqual({ ok: false, error: "unknown_kid" });
		expect(await verifyIdToken(token, await expectations([], { getKey: async () => ({ status: "unavailable" }) }))).toEqual({ ok: false, error: "key_fetch_failed" });
	});
});

describe("JWKS cache and key rotation", () => {
	function cacheWith(fetchKeys: (uri: string) => Promise<Jwk[] | null>, clock: { now: number }) {
		return new JwksCache({ fetchKeys, now: () => clock.now, ttlMs: 600_000, minRefetchMs: 30_000, maxStaleMs: 3_600_000 });
	}

	it("caches within the TTL and refreshes after it", async () => {
		const key = await makeKey("RS256", "k1");
		const clock = { now: NOW_MS };
		let fetches = 0;
		const cache = cacheWith(async () => (fetches += 1, [key.publicJwk]), clock);
		expect((await cache.getKey("https://i/jwks", "k1", "RS256")).status).toBe("found");
		expect((await cache.getKey("https://i/jwks", "k1", "RS256")).status).toBe("found");
		expect(fetches).toBe(1);
		clock.now += 601_000;
		await cache.getKey("https://i/jwks", "k1", "RS256");
		expect(fetches).toBe(2);
	});

	it("picks up a rotated key on first sight of an unknown kid", async () => {
		const oldKey = await makeKey("RS256", "old");
		const newKey = await makeKey("RS256", "new");
		const clock = { now: NOW_MS };
		let published: Jwk[] = [oldKey.publicJwk];
		const cache = cacheWith(async () => published, clock);
		expect((await cache.getKey("https://i/jwks", "old", "RS256")).status).toBe("found");
		published = [newKey.publicJwk, oldKey.publicJwk];
		clock.now += 31_000;
		const rotated = await cache.getKey("https://i/jwks", "new", "RS256");
		expect(rotated).toMatchObject({ status: "found" });
		// The retired key disappears at the IdP; after the next refresh it stops verifying.
		published = [newKey.publicJwk];
		clock.now += 601_000;
		expect((await cache.getKey("https://i/jwks", "old", "RS256")).status).toBe("unknown_kid");
		expect((await cache.getKey("https://i/jwks", "new", "RS256")).status).toBe("found");
	});

	it("rate-limits refetches so random kids cannot amplify load on the IdP", async () => {
		const key = await makeKey("RS256", "k1");
		const clock = { now: NOW_MS };
		let fetches = 0;
		const cache = cacheWith(async () => (fetches += 1, [key.publicJwk]), clock);
		await cache.getKey("https://i/jwks", "k1", "RS256");
		for (let index = 0; index < 50; index += 1) {
			expect((await cache.getKey("https://i/jwks", `random-${index}`, "RS256")).status).toBe("unknown_kid");
		}
		expect(fetches).toBe(1);
		clock.now += 31_000;
		await cache.getKey("https://i/jwks", "random-x", "RS256");
		expect(fetches).toBe(2);
	});

	it("coalesces concurrent first fetches", async () => {
		const key = await makeKey("RS256", "k1");
		let fetches = 0;
		const cache = cacheWith(async () => {
			fetches += 1;
			await new Promise((resolve) => setTimeout(resolve, 10));
			return [key.publicJwk];
		}, { now: NOW_MS });
		const results = await Promise.all(Array.from({ length: 10 }, () => cache.getKey("https://i/jwks", "k1", "RS256")));
		expect(results.every((result) => result.status === "found")).toBe(true);
		expect(fetches).toBe(1);
	});

	it("keeps verifying known kids from stale data during an IdP outage, but never an unknown kid", async () => {
		const key = await makeKey("RS256", "k1");
		const clock = { now: NOW_MS };
		let down = false;
		const cache = cacheWith(async () => (down ? null : [key.publicJwk]), clock);
		await cache.getKey("https://i/jwks", "k1", "RS256");
		down = true;
		clock.now += 700_000;
		expect((await cache.getKey("https://i/jwks", "k1", "RS256")).status).toBe("found");
		expect((await cache.getKey("https://i/jwks", "unknown", "RS256")).status).not.toBe("found");
		clock.now += 4_000_000; // past maxStale
		expect((await cache.getKey("https://i/jwks", "k1", "RS256")).status).toBe("unavailable");
	});

	it("is unavailable when the very first fetch fails and bounds the key and entry counts", async () => {
		const cache = cacheWith(async () => null, { now: NOW_MS });
		expect((await cache.getKey("https://i/jwks", "k1", "RS256")).status).toBe("unavailable");
		const key = await makeKey("RS256", "k1");
		const crowded = new JwksCache({ fetchKeys: async () => Array.from({ length: 21 }, () => key.publicJwk), maxKeys: 20 });
		expect((await crowded.getKey("https://i/jwks", "k1", "RS256")).status).toBe("unavailable");
	});

	it("selects keys by kid, and a kid-less token needs an unambiguous key", async () => {
		const a = await makeKey("RS256", "a");
		const b = await makeKey("RS256", "b");
		const cache = cacheWith(async () => [a.publicJwk, b.publicJwk], { now: NOW_MS });
		expect((await cache.getKey("https://i/jwks", undefined, "RS256")).status).toBe("unknown_kid");
		const single = cacheWith(async () => [a.publicJwk], { now: NOW_MS });
		expect((await single.getKey("https://i/jwks", undefined, "RS256")).status).toBe("found");
	});

	it("parses JWKS documents defensively", () => {
		expect(parseJwks({ keys: [{ kid: "a" }, 5, null, [], "x"] })).toEqual([{ kid: "a" }]);
		expect(parseJwks({})).toBeNull();
		expect(parseJwks([])).toBeNull();
		expect(parseJwks(null)).toBeNull();
	});
});

describe("discovery validation", () => {
	const good = {
		issuer: ISSUER_A,
		authorization_endpoint: "https://login.example/authorize",
		token_endpoint: "https://login.example/token",
		jwks_uri: "https://login.example/keys",
		response_types_supported: ["code"],
		code_challenge_methods_supported: ["S256"],
		id_token_signing_alg_values_supported: ["RS256"],
	};

	it("accepts a conformant document", () => {
		expect(validateDiscovery(good, ISSUER_A, ["RS256"])).toMatchObject({ ok: true });
	});

	it.each([
		[{ ...good, issuer: `${ISSUER_A}/` }, "issuer_mismatch"],
		[{ ...good, issuer: "https://evil.example" }, "issuer_mismatch"],
		[{ ...good, token_endpoint: "http://login.example/token" }, "endpoint_invalid"],
		[{ ...good, jwks_uri: "https://u:p@login.example/keys" }, "endpoint_invalid"],
		[{ ...good, authorization_endpoint: undefined }, "endpoint_invalid"],
		[{ ...good, code_challenge_methods_supported: ["plain"] }, "pkce_unsupported"],
		[{ ...good, response_types_supported: ["id_token"] }, "code_flow_unsupported"],
		[{ ...good, id_token_signing_alg_values_supported: ["HS256"] }, "no_common_algorithm"],
		[null, "discovery_invalid"],
		[[], "discovery_invalid"],
	])("rejects %j as %s", (document, error) => {
		expect(validateDiscovery(document, ISSUER_A, ["RS256"])).toEqual({ ok: false, error });
	});

	it("validates configured issuers", () => {
		expect(normalizeIssuer("https://tenant.okta.com/oauth2/default")).toBeTruthy();
		for (const bad of ["http://x.example", "https://u@x.example", "https://x.example?a=1", "https://x.example#f", "nope", 5]) {
			expect(normalizeIssuer(bad)).toBeNull();
		}
	});
});

describe("PKCE and authorization URL", () => {
	it("matches the RFC 7636 S256 test vector", async () => {
		expect(await pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
	});

	it("always requests the code flow with S256 and the supplied state and nonce", () => {
		const url = new URL(
			buildAuthorizationUrl({
				authorizationEndpoint: "https://login.example/authorize?tenant=x",
				clientId: "c",
				redirectUri: "https://app.test/auth/oidc/callback",
				state: "s",
				nonce: "n",
				codeChallenge: "ch",
				scopes: ["openid", "email"],
			}),
		);
		expect(Object.fromEntries(url.searchParams)).toMatchObject({
			response_type: "code",
			client_id: "c",
			state: "s",
			nonce: "n",
			code_challenge: "ch",
			code_challenge_method: "S256",
			scope: "openid email",
			tenant: "x",
		});
	});

	it("compares secrets without short-circuiting on content", async () => {
		expect(await constantTimeEqual("abc", "abc")).toBe(true);
		expect(await constantTimeEqual("abc", "abd")).toBe(false);
		expect(await constantTimeEqual("abc", "abcd")).toBe(false);
	});
});

describe("group claim mapping (same rules as the SCIM reconciler)", () => {
	const mappings = new Map<string, MappedRole>([
		["group-admin", "admin"],
		["group-member", "member"],
		["group-viewer", "viewer"],
	]);

	it("grants the most privileged matching role and never owner", () => {
		expect(mapGroupClaims({ groups: ["group-viewer", "group-admin", "x"] }, "groups", mappings)).toEqual({ status: "mapped", role: "admin", matched: 2 });
		expect(mapGroupClaims({ groups: ["group-member", "group-viewer"] }, "groups", mappings)).toMatchObject({ role: "member" });
		expect(mapGroupClaims({ groups: ["owner", "Owners"] }, "groups", mappings)).toEqual({ status: "none" });
	});

	it("matches exact, case-sensitive group ids only (display names never grant)", () => {
		expect(mapGroupClaims({ groups: ["GROUP-ADMIN", "group-admin "] }, "groups", mappings)).toEqual({ status: "none" });
	});

	it("treats Entra group overage as unevaluable instead of empty", () => {
		expect(mapGroupClaims({ _claim_names: { groups: "src1" }, _claim_sources: {} }, "groups", mappings)).toEqual({ status: "overage" });
		expect(mapGroupClaims({ hasgroups: true }, "groups", mappings)).toEqual({ status: "overage" });
		expect(mapGroupClaims({}, "groups", mappings)).toEqual({ status: "none" });
	});

	it("rejects malformed group claims", () => {
		expect(mapGroupClaims({ groups: "group-admin" }, "groups", mappings)).toEqual({ status: "invalid" });
		expect(mapGroupClaims({ groups: [1, 2] }, "groups", mappings)).toEqual({ status: "invalid" });
		expect(mapGroupClaims({ groups: Array.from({ length: 1001 }, (_, index) => `g${index}`) }, "groups", mappings)).toEqual({ status: "invalid" });
	});
});

describe("egress guard", () => {
	const corpus = [
		"127.0.0.1", "10.0.0.1", "172.16.5.5", "172.32.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "100.128.0.1",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "198.51.100.7", "203.0.113.9", "8.8.8.8", "93.184.216.34",
		"1.1.1.1", "192.0.2.1", "192.88.99.1", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1",
		"2606:4700:4700::1111", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "::ffff:7f00:1", "64:ff9b::8.8.8.8", "64:ff9b::7f00:1",
		"2002:7f00:1::1", "2002:0808:0808::1", "[::1]", "::127.0.0.1", "2001::1", "3fff::1", "5f00::1", "fec0::1",
	];

	it("agrees with the core MCP SSRF guard on every address in the corpus", () => {
		for (const address of corpus) {
			expect(isPrivateIpAddress(address), address).toBe(coreIsPrivateIpAddress(address));
		}
	});

	it("is fail-closed for anything that is not a public IP literal", () => {
		for (const bad of ["", "example.com", "999.1.1.1", "1.2.3", "::gggg", "10.0.0.1", "[::1]"]) {
			expect(isPublicIpAddress(bad), bad).toBe(false);
		}
		expect(isPublicIpAddress("8.8.8.8")).toBe(true);
		expect(isPublicIpAddress("2606:4700:4700::1111")).toBe(true);
		expect(ipVersion("1.2.3.4")).toBe(4);
		expect(ipVersion("::1")).toBe(6);
		expect(ipVersion("host")).toBe(0);
	});

	it("blocks internal-looking hostnames", () => {
		for (const host of ["localhost", "LOCALHOST.", "metadata.google.internal", "svc", "db.internal", "printer.local", "x.localhost", "a.home.arpa"]) {
			expect(isBlockedHostname(host), host).toBe(true);
		}
		expect(isBlockedHostname("login.microsoftonline.com")).toBe(false);
	});
});

describe("SSRF-safe fetch", () => {
	const publicDns = async (_host: string, type: "A" | "AAAA") => {
		if (type === "A") return ["93.184.216.34"];
		throw new Error("NODATA");
	};
	const jsonResponse = (body: unknown, init: ResponseInit = {}) =>
		new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" }, ...init });

	it("fetches a public https JSON document and never follows redirects or sends credentials", async () => {
		let seen: RequestInit | undefined;
		const result = await safeFetchJson("https://idp.example.com/.well-known/openid-configuration", {}, {
			resolveDns: publicDns,
			fetch: async (_url, init) => ((seen = init), jsonResponse({ ok: 1 })),
		});
		expect(result).toMatchObject({ ok: true, json: { ok: 1 } });
		expect(seen).toMatchObject({ redirect: "manual", credentials: "omit" });
	});

	it.each([
		["http://idp.example.com/x", "insecure_scheme"],
		["https://user:pw@idp.example.com/x", "url_credentials_forbidden"],
		["https://idp.example.com:8443/x", "port_not_allowed"],
		["https://127.0.0.1/x", "blocked_host"],
		["https://[::1]/x", "blocked_host"],
		["https://8.8.8.8/x", "blocked_host"],
		["https://localhost/x", "blocked_host"],
		["https://metadata.google.internal/x", "blocked_host"],
		["https://intranet/x", "blocked_host"],
		["https://idp.example.com/x#frag", "url_credentials_forbidden"],
		["not a url", "invalid_url"],
		["file:///etc/passwd", "insecure_scheme"],
	])("refuses %s (%s)", async (url, error) => {
		const result = await safeFetchJson(url, {}, { resolveDns: publicDns, fetch: async () => jsonResponse({}) });
		expect(result).toEqual({ ok: false, error });
	});

	it("refuses a name that resolves to a private, link-local or mixed answer (SSRF via DNS)", async () => {
		for (const answers of [["10.0.0.5"], ["169.254.169.254"], ["127.0.0.1"], ["93.184.216.34", "10.0.0.5"], ["::1"], ["::ffff:10.0.0.1"]]) {
			let fetched = false;
			const result = await safeFetchJson("https://idp.example.com/x", {}, {
				resolveDns: async (_h, type) => (type === "A" ? answers.filter((a) => !a.includes(":")) : answers.filter((a) => a.includes(":"))),
				fetch: async () => ((fetched = true), jsonResponse({})),
			});
			expect(result, answers.join()).toEqual({ ok: false, error: "private_address" });
			expect(fetched).toBe(false);
		}
	});

	it("fails closed when DNS fails or returns nothing", async () => {
		const failing = await safeFetchJson("https://idp.example.com/x", {}, { resolveDns: async () => { throw new Error("SERVFAIL"); }, fetch: async () => jsonResponse({}) });
		expect(failing).toEqual({ ok: false, error: "dns_lookup_failed" });
		const empty = await safeFetchJson("https://idp.example.com/x", {}, { resolveDns: async () => [], fetch: async () => jsonResponse({}) });
		expect(empty).toEqual({ ok: false, error: "dns_lookup_failed" });
	});

	it("rejects redirects, error statuses, non-JSON, oversized and invalid bodies", async () => {
		const run = (response: () => Response, options = {}) =>
			safeFetchJson("https://idp.example.com/x", {}, { resolveDns: publicDns, fetch: async () => response(), ...options });
		expect(await run(() => new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } }))).toMatchObject({ ok: false, error: "redirect_blocked" });
		expect(await run(() => jsonResponse({}, { status: 500 }))).toMatchObject({ ok: false, error: "http_status", status: 500 });
		expect(await run(() => new Response("<html>", { headers: { "content-type": "text/html" } }))).toMatchObject({ ok: false, error: "unexpected_content_type" });
		expect(await run(() => new Response("{not json", { headers: { "content-type": "application/json" } }))).toMatchObject({ ok: false, error: "invalid_json" });
		expect(await run(() => jsonResponse({ big: "x".repeat(5_000) }), { maxBytes: 1_000 })).toMatchObject({ ok: false, error: "response_too_large" });
		expect(
			await run(() => new Response("{}", { headers: { "content-type": "application/json", "content-length": "99999999" } })),
		).toMatchObject({ ok: false, error: "response_too_large" });
	});

	it("times out a hanging endpoint and maps transport errors", async () => {
		const hanging = await safeFetchJson("https://idp.example.com/x", {}, {
			resolveDns: publicDns,
			timeoutMs: 20,
			fetch: (_url, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })))),
		});
		expect(hanging).toEqual({ ok: false, error: "timeout" });
		const broken = await safeFetchJson("https://idp.example.com/x", {}, { resolveDns: publicDns, fetch: async () => { throw new TypeError("connection refused"); } });
		expect(broken).toEqual({ ok: false, error: "network_error" });
	});

	it("exposes the validated addresses to callers that need them", async () => {
		const checked = await assertSafeUrl("https://idp.example.com/x", { resolveDns: publicDns });
		expect(checked).toMatchObject({ ok: true, addresses: ["93.184.216.34"] });
		const custom = await assertSafeUrl("https://idp.example.com:8443/x", { resolveDns: publicDns, allowedPorts: [443, 8443] });
		expect(custom.ok).toBe(true);
	});
});


describe("resolveClientSecret (tenant-bound OIDC client secrets)", () => {
	const env = (bindings: unknown, secrets: Record<string, string> = { CONTOSO: "secret-contoso", FABRIKAM: "secret-fabrikam" }) => {
		const reads: string[] = [];
		const readEnv = (name: string) => {
			reads.push(name);
			if (name === "AIDR_OIDC_CLIENT_SECRET_BINDINGS") return typeof bindings === "string" ? bindings : JSON.stringify(bindings);
			const prefix = "AIDR_OIDC_CLIENT_SECRET_";
			return name.startsWith(prefix) ? secrets[name.slice(prefix.length)] : undefined;
		};
		return { readEnv, reads };
	};
	const bindings = {
		CONTOSO: { tenant_id: TENANT_A, issuer: ISSUER_A },
		FABRIKAM: { tenant_id: TENANT_B, issuer: ISSUER_B, client_id: "client-b" },
	};
	const contoso = { tenantId: TENANT_A, issuer: ISSUER_A, clientId: "client-a", ref: "CONTOSO" };

	it("releases a secret only for the bound tenant, issuer and pinned client", () => {
		expect(resolveClientSecret(env(bindings).readEnv, contoso)).toBe("secret-contoso");
		expect(resolveClientSecret(env(bindings).readEnv, { ...contoso, tenantId: TENANT_A.toUpperCase() })).toBe("secret-contoso");
		expect(resolveClientSecret(env(bindings).readEnv, { tenantId: TENANT_B, issuer: ISSUER_B, clientId: "client-b", ref: "FABRIKAM" })).toBe("secret-fabrikam");
	});

	it.each([
		["another tenant's reference", { ...contoso, ref: "FABRIKAM" }],
		["the right reference from another tenant", { ...contoso, tenantId: TENANT_B }],
		["a different issuer", { ...contoso, issuer: "https://idp.attacker.example" }],
		["an issuer differing only by a trailing slash", { ...contoso, issuer: `${ISSUER_A}/` }],
		["an unpinned client on a pinned binding", { tenantId: TENANT_B, issuer: ISSUER_B, clientId: "other", ref: "FABRIKAM" }],
		["an unbound reference", { ...contoso, ref: "UNBOUND" }],
		["the bindings document itself", { ...contoso, ref: "BINDINGS" }],
		["a malformed reference", { ...contoso, ref: "contoso" }],
	])("returns null for %s without reading the secret", (_label, request) => {
		const { readEnv, reads } = env({ ...bindings, BINDINGS: { tenant_id: TENANT_A, issuer: ISSUER_A } });
		expect(resolveClientSecret(readEnv, request)).toBeNull();
		expect(reads.filter((name) => name !== "AIDR_OIDC_CLIENT_SECRET_BINDINGS")).toEqual([]);
	});

	it.each([
		["no bindings", undefined],
		["invalid JSON", "{not json"],
		["an array", [bindings.CONTOSO]],
		["a non-UUID tenant", { CONTOSO: { tenant_id: "tenant-a", issuer: ISSUER_A } }],
		["a non-HTTPS issuer", { CONTOSO: { tenant_id: TENANT_A, issuer: "http://login.example" } }],
		["an empty client pin", { CONTOSO: { tenant_id: TENANT_A, issuer: ISSUER_A, client_id: "" } }],
	])("fails closed on %s", (_label, document) => {
		const { readEnv } = env(document === undefined ? "" : document);
		expect(resolveClientSecret(readEnv, contoso)).toBeNull();
	});

	it("treats a bound but empty secret as not configured", () => {
		expect(resolveClientSecret(env(bindings, { CONTOSO: "   " }).readEnv, contoso)).toBeNull();
	});
});
