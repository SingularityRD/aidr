// OpenID Connect primitives for tenant SSO: PKCE, ID-token verification,
// discovery validation and group-claim mapping.
//
// Pure TypeScript over WebCrypto. Nothing here touches Deno, Supabase or the
// network, so the exact code that runs in the Edge Function is what the vitest
// suite (supabase/functions/__tests__/oidc-sso.test.ts) exercises.

export type OidcAlgorithm = "RS256" | "PS256" | "ES256";
/** Asymmetric algorithms only. `none` and every HMAC algorithm are refused outright. */
export const SUPPORTED_ALGORITHMS: readonly OidcAlgorithm[] = ["RS256", "PS256", "ES256"];

const MAX_JWT_BYTES = 16 * 1024;
const MIN_RSA_MODULUS_BITS = 2048;
const MAX_CLOCK_SKEW_SECONDS = 120;
const MAX_ID_TOKEN_AGE_SECONDS = 10 * 60;

const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// Encoding and PKCE
// ---------------------------------------------------------------------------

export function base64UrlEncode(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> | null {
	if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return null;
	const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
	try {
		const binary = atob(padded);
		return Uint8Array.from(binary, (char) => char.charCodeAt(0));
	} catch {
		return null;
	}
}

export async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Bytes(value: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

/** RFC 7636 S256 challenge. */
export async function pkceChallenge(verifier: string): Promise<string> {
	return base64UrlEncode(await sha256Bytes(verifier));
}

/** Compare two secrets without an early exit on the first differing byte. */
export async function constantTimeEqual(left: string, right: string): Promise<boolean> {
	const [a, b] = await Promise.all([sha256Bytes(left), sha256Bytes(right)]);
	let diff = a.length ^ b.length;
	for (let index = 0; index < a.length; index += 1) diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
	return diff === 0;
}

export function isPkceVerifier(value: unknown): value is string {
	return typeof value === "string" && /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}

// ---------------------------------------------------------------------------
// JWT parsing
// ---------------------------------------------------------------------------

export interface ParsedJwt {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
	signingInput: string;
	signature: Uint8Array<ArrayBuffer>;
}

function decodeJsonObject(segment: string): Record<string, unknown> | null {
	const bytes = base64UrlDecode(segment);
	if (!bytes) return null;
	try {
		const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
		return value && typeof value === "object" && !Array.isArray(value)
			? (value as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

export function parseJwt(token: string): ParsedJwt | null {
	if (typeof token !== "string" || token.length === 0 || token.length > MAX_JWT_BYTES) return null;
	const segments = token.split(".");
	// Five segments is a JWE (encrypted); we never asked for one.
	if (segments.length !== 3) return null;
	const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];
	const header = decodeJsonObject(encodedHeader);
	const payload = decodeJsonObject(encodedPayload);
	const signature = base64UrlDecode(encodedSignature);
	if (!header || !payload || !signature) return null;
	return { header, payload, signingInput: `${encodedHeader}.${encodedPayload}`, signature };
}

// ---------------------------------------------------------------------------
// Keys and signatures
// ---------------------------------------------------------------------------

export interface Jwk {
	kty?: string;
	kid?: string;
	use?: string;
	alg?: string;
	key_ops?: string[];
	n?: string;
	e?: string;
	crv?: string;
	x?: string;
	y?: string;
	[key: string]: unknown;
}

function keyMatchesAlgorithm(jwk: Jwk, alg: OidcAlgorithm): boolean {
	if (jwk.use !== undefined && jwk.use !== "sig") return false;
	if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes("verify")))
		return false;
	if (jwk.alg !== undefined && jwk.alg !== alg) return false;
	if (alg === "ES256") return jwk.kty === "EC" && jwk.crv === "P-256";
	return jwk.kty === "RSA";
}

async function importVerificationKey(jwk: Jwk, alg: OidcAlgorithm): Promise<CryptoKey | null> {
	if (!keyMatchesAlgorithm(jwk, alg)) return null;
	try {
		if (alg === "ES256") {
			if (typeof jwk.x !== "string" || typeof jwk.y !== "string") return null;
			return await crypto.subtle.importKey(
				"jwk",
				{ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
				{ name: "ECDSA", namedCurve: "P-256" },
				false,
				["verify"],
			);
		}
		if (typeof jwk.n !== "string" || typeof jwk.e !== "string") return null;
		const modulus = base64UrlDecode(jwk.n);
		if (!modulus) return null;
		const firstNonZero = modulus.findIndex((byte) => byte !== 0);
		const bits = firstNonZero < 0 ? 0 : (modulus.length - firstNonZero) * 8 - Math.clz32(modulus[firstNonZero] ?? 0) + 24;
		if (bits < MIN_RSA_MODULUS_BITS) return null;
		return await crypto.subtle.importKey(
			"jwk",
			{ kty: "RSA", n: jwk.n, e: jwk.e, alg, ext: true },
			alg === "RS256"
				? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }
				: { name: "RSA-PSS", hash: "SHA-256" },
			false,
			["verify"],
		);
	} catch {
		return null;
	}
}

async function verifySignature(
	alg: OidcAlgorithm,
	jwk: Jwk,
	signingInput: string,
	signature: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
	const key = await importVerificationKey(jwk, alg);
	if (!key) return false;
	const data = encoder.encode(signingInput);
	try {
		if (alg === "ES256") {
			// JWS carries raw r||s, which is WebCrypto's ECDSA format.
			if (signature.length !== 64) return false;
			return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
		}
		if (alg === "RS256") return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
		return await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, signature, data);
	} catch {
		return false;
	}
}

/** Pick the verification key for a token from a JWKS. A kid-less token needs an unambiguous key. */
export function selectKey(keys: readonly Jwk[], kid: string | undefined, alg: OidcAlgorithm): Jwk | null {
	const candidates = keys.filter((key) => keyMatchesAlgorithm(key, alg));
	if (kid !== undefined) return candidates.find((key) => key.kid === kid) ?? null;
	return candidates.length === 1 ? (candidates[0] ?? null) : null;
}

// ---------------------------------------------------------------------------
// ID token verification
// ---------------------------------------------------------------------------

type IdTokenError =
	| "malformed_token"
	| "alg_not_allowed"
	| "unknown_kid"
	| "key_fetch_failed"
	| "signature_invalid"
	| "issuer_mismatch"
	| "audience_mismatch"
	| "azp_mismatch"
	| "expired"
	| "not_yet_valid"
	| "iat_invalid"
	| "token_too_old"
	| "nonce_mismatch"
	| "subject_missing"
	| "claims_invalid";

export type KeyLookup =
	| { status: "found"; key: Jwk }
	| { status: "unknown_kid" }
	| { status: "unavailable" };

export interface IdTokenExpectations {
	issuer: string;
	clientId: string;
	/** SHA-256 hex of the nonce sent in the authorization request. */
	nonceHash: string;
	allowedAlgorithms: readonly OidcAlgorithm[];
	nowSeconds: number;
	clockSkewSeconds: number;
	getKey: (kid: string | undefined, alg: OidcAlgorithm) => Promise<KeyLookup>;
}

export type IdTokenResult =
	| { ok: true; claims: Record<string, unknown>; alg: OidcAlgorithm }
	| { ok: false; error: IdTokenError };

function numericClaim(value: unknown): number | null {
	return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function resolveAlgorithm(
	header: Record<string, unknown>,
	allowed: readonly OidcAlgorithm[],
): OidcAlgorithm | null {
	const alg = header.alg;
	// Exact, case-sensitive allow-list membership: "none", "None", "HS256" and anything unlisted fail.
	if (typeof alg !== "string") return null;
	const match = allowed.find((candidate) => candidate === alg && SUPPORTED_ALGORITHMS.includes(candidate));
	return match ?? null;
}

async function checkClaims(
	claims: Record<string, unknown>,
	expected: IdTokenExpectations,
): Promise<IdTokenError | null> {
	if (claims.iss !== expected.issuer) return "issuer_mismatch";
	const audience = claims.aud;
	const audiences = typeof audience === "string" ? [audience] : audience;
	if (!Array.isArray(audiences) || !audiences.every((value) => typeof value === "string"))
		return "audience_mismatch";
	if (!audiences.includes(expected.clientId)) return "audience_mismatch";
	// OIDC Core 3.1.3.7: with several audiences, azp must name this client.
	if ((audiences.length > 1 || claims.azp !== undefined) && claims.azp !== expected.clientId)
		return "azp_mismatch";

	const skew = Math.min(Math.max(expected.clockSkewSeconds, 0), MAX_CLOCK_SKEW_SECONDS);
	const exp = numericClaim(claims.exp);
	if (exp === null) return "claims_invalid";
	if (exp <= expected.nowSeconds - skew) return "expired";
	const nbf = claims.nbf === undefined ? null : numericClaim(claims.nbf);
	if (claims.nbf !== undefined && nbf === null) return "claims_invalid";
	if (nbf !== null && nbf > expected.nowSeconds + skew) return "not_yet_valid";
	const iat = numericClaim(claims.iat);
	if (iat === null) return "iat_invalid";
	if (iat > expected.nowSeconds + skew) return "iat_invalid";
	if (iat < expected.nowSeconds - MAX_ID_TOKEN_AGE_SECONDS - skew) return "token_too_old";

	if (typeof claims.nonce !== "string" || claims.nonce.length === 0) return "nonce_mismatch";
	if (!(await constantTimeEqual(await sha256Hex(claims.nonce), expected.nonceHash)))
		return "nonce_mismatch";
	if (typeof claims.sub !== "string" || claims.sub.length === 0 || claims.sub.length > 255)
		return "subject_missing";
	return null;
}

/**
 * Verify an ID token: algorithm allow-list, signature against the provider's
 * JWKS, then iss / aud / azp / exp / nbf / iat / nonce / sub. The signature is
 * checked BEFORE any claim is trusted. Keys come only from the configured JWKS;
 * `jku`, `jwk` and `x5u` header parameters are ignored, never dereferenced.
 */
export async function verifyIdToken(token: string, expected: IdTokenExpectations): Promise<IdTokenResult> {
	const parsed = parseJwt(token);
	if (!parsed) return { ok: false, error: "malformed_token" };
	const alg = resolveAlgorithm(parsed.header, expected.allowedAlgorithms);
	if (!alg) return { ok: false, error: "alg_not_allowed" };
	// `crit` extensions are not understood, so RFC 7515 requires rejection.
	if (parsed.header.crit !== undefined) return { ok: false, error: "malformed_token" };
	const kid = typeof parsed.header.kid === "string" ? parsed.header.kid : undefined;
	if (parsed.header.kid !== undefined && kid === undefined) return { ok: false, error: "malformed_token" };

	const lookup = await expected.getKey(kid, alg);
	if (lookup.status === "unavailable") return { ok: false, error: "key_fetch_failed" };
	if (lookup.status === "unknown_kid") return { ok: false, error: "unknown_kid" };
	if (!(await verifySignature(alg, lookup.key, parsed.signingInput, parsed.signature)))
		return { ok: false, error: "signature_invalid" };

	const claimError = await checkClaims(parsed.payload, expected);
	return claimError ? { ok: false, error: claimError } : { ok: true, claims: parsed.payload, alg };
}

// ---------------------------------------------------------------------------
// Discovery document
// ---------------------------------------------------------------------------

export interface OidcDiscovery {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	id_token_signing_alg_values_supported?: string[];
}

export type DiscoveryError =
	| "discovery_invalid"
	| "issuer_mismatch"
	| "endpoint_invalid"
	| "pkce_unsupported"
	| "code_flow_unsupported"
	| "no_common_algorithm";

function httpsUrl(value: unknown): string | null {
	if (typeof value !== "string" || value.length > 2048) return null;
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !url.username && !url.password && !url.hash ? url.toString() : null;
	} catch {
		return null;
	}
}

/** The issuer in the document must equal the configured issuer exactly (OIDC Discovery 4.3). */
export function validateDiscovery(
	document: unknown,
	configuredIssuer: string,
	allowedAlgorithms: readonly OidcAlgorithm[],
): { ok: true; discovery: OidcDiscovery } | { ok: false; error: DiscoveryError } {
	if (!document || typeof document !== "object" || Array.isArray(document))
		return { ok: false, error: "discovery_invalid" };
	const doc = document as Record<string, unknown>;
	if (doc.issuer !== configuredIssuer) return { ok: false, error: "issuer_mismatch" };
	const authorization = httpsUrl(doc.authorization_endpoint);
	const token = httpsUrl(doc.token_endpoint);
	const jwks = httpsUrl(doc.jwks_uri);
	if (!authorization || !token || !jwks) return { ok: false, error: "endpoint_invalid" };
	const methods = doc.code_challenge_methods_supported;
	if (methods !== undefined && !(Array.isArray(methods) && methods.includes("S256")))
		return { ok: false, error: "pkce_unsupported" };
	const responseTypes = doc.response_types_supported;
	if (responseTypes !== undefined && !(Array.isArray(responseTypes) && responseTypes.includes("code")))
		return { ok: false, error: "code_flow_unsupported" };
	const algs = doc.id_token_signing_alg_values_supported;
	const supported = Array.isArray(algs) ? algs.filter((value): value is string => typeof value === "string") : undefined;
	if (supported && !allowedAlgorithms.some((alg) => supported.includes(alg)))
		return { ok: false, error: "no_common_algorithm" };
	return {
		ok: true,
		discovery: {
			issuer: configuredIssuer,
			authorization_endpoint: authorization,
			token_endpoint: token,
			jwks_uri: jwks,
			...(supported ? { id_token_signing_alg_values_supported: supported } : {}),
		},
	};
}

export function discoveryUrlFor(issuer: string): string {
	return `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
}

/** Validate a configured issuer: https, no credentials/query/fragment. */
export function normalizeIssuer(value: unknown): string | null {
	if (typeof value !== "string" || value.length > 512) return null;
	try {
		const url = new URL(value);
		if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return null;
		return value;
	} catch {
		return null;
	}
}

// ---------------------------------------------------------------------------
// Authorization request
// ---------------------------------------------------------------------------

export function buildAuthorizationUrl(input: {
	authorizationEndpoint: string;
	clientId: string;
	redirectUri: string;
	state: string;
	nonce: string;
	codeChallenge: string;
	scopes: readonly string[];
	loginHint?: string;
}): string {
	const url = new URL(input.authorizationEndpoint);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", input.clientId);
	url.searchParams.set("redirect_uri", input.redirectUri);
	url.searchParams.set("scope", input.scopes.join(" "));
	url.searchParams.set("state", input.state);
	url.searchParams.set("nonce", input.nonce);
	url.searchParams.set("code_challenge", input.codeChallenge);
	url.searchParams.set("code_challenge_method", "S256");
	if (input.loginHint) url.searchParams.set("login_hint", input.loginHint);
	return url.toString();
}

// ---------------------------------------------------------------------------
// Claims: email domain and group-role mapping
// ---------------------------------------------------------------------------

export type MappedRole = "admin" | "member" | "viewer";
const ROLE_RANK: Record<MappedRole, number> = { admin: 1, member: 2, viewer: 3 };

/** Domain of a syntactically plain email, lower-cased; null otherwise. */
export function emailDomain(value: unknown): string | null {
	if (typeof value !== "string" || value.length > 254) return null;
	const match = /^[^\s@]+@([^\s@]+\.[^\s@]+)$/.exec(value.trim());
	return match ? (match[1] as string).toLowerCase().replace(/\.$/, "") : null;
}

export function isDnsDomain(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length <= 253 &&
		/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)
	);
}

export type GroupMapping =
	| { status: "mapped"; role: MappedRole; matched: number }
	| { status: "none" }
	| { status: "overage" }
	| { status: "invalid" };

/**
 * Same rules as the SCIM reconciler (migration 20260912000012): exact,
 * case-sensitive, immutable external group ids; display names never grant
 * anything; supported roles are admin/member/viewer (never owner); the most
 * privileged matching group wins.
 */
export function mapGroupClaims(
	claims: Record<string, unknown>,
	claimName: string,
	mappings: ReadonlyMap<string, MappedRole>,
): GroupMapping {
	const value = claims[claimName];
	if (value === undefined) {
		// Entra signals "too many groups" with _claim_names / hasgroups instead of the list.
		const names = claims._claim_names;
		const overage =
			(names && typeof names === "object" && claimName in (names as Record<string, unknown>)) ||
			claims.hasgroups === true;
		return overage ? { status: "overage" } : { status: "none" };
	}
	if (!Array.isArray(value) || value.length > 1000 || !value.every((item) => typeof item === "string"))
		return { status: "invalid" };
	let best: MappedRole | null = null;
	let matched = 0;
	for (const group of new Set(value as string[])) {
		const role = mappings.get(group);
		if (!role) continue;
		matched += 1;
		if (best === null || ROLE_RANK[role] < ROLE_RANK[best]) best = role;
	}
	return best ? { status: "mapped", role: best, matched } : { status: "none" };
}

export type GroupClaimValues = { evaluable: true; values: string[] } | { evaluable: false; reason: "overage" | "invalid" };

const MAX_GROUP_VALUES = 1000;
const MAX_GROUP_LENGTH = 256;

/**
 * Exact group values for JIT provisioning. Unlike mapGroupClaims it returns the
 * values themselves (the role is resolved inside the database transaction) and
 * it accepts a single string, because ADFS emits a one-element multi-valued
 * claim as a plain string. Overage (Entra) and malformed claims are "not
 * evaluable": the caller then changes nothing and denies. No claim name, or a
 * claim the IdP left out, means "no groups".
 */
export function groupClaimValues(claims: Record<string, unknown>, claimName: string | null): GroupClaimValues {
	if (!claimName) return { evaluable: true, values: [] };
	const value = claims[claimName];
	if (value === undefined) {
		const names = claims._claim_names;
		const overage =
			(names && typeof names === "object" && claimName in (names as Record<string, unknown>)) ||
			claims.hasgroups === true;
		return overage ? { evaluable: false, reason: "overage" } : { evaluable: true, values: [] };
	}
	const list: unknown = typeof value === "string" ? [value] : value;
	if (
		!Array.isArray(list) ||
		list.length > MAX_GROUP_VALUES ||
		!list.every((item) => typeof item === "string" && item.length >= 1 && item.length <= MAX_GROUP_LENGTH)
	)
		return { evaluable: false, reason: "invalid" };
	return { evaluable: true, values: [...new Set(list as string[])] };
}
