const DELEGATED_CREDENTIAL_TYPE = "aidr-delegation+jwt";
const DELEGATED_CREDENTIAL_MAX_SECONDS = 900;
const DELEGATED_CREDENTIAL_MAX_DEPTH = 4;

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const SCOPE = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;

export interface BrokerDelegatedClaims {
	version: 1;
	issuer: string;
	subjectUserId: string;
	tenantId: string;
	agentId: string;
	tool: { serverId: string; name: string };
	resource: { type: string; id: string };
	audience: string;
	scopes: string[];
	issuedAt: number;
	notBefore: number;
	expiresAt: number;
	authSessionIssuedAt: number;
	tokenId: string;
	delegationDepth: number;
	parentTokenId?: string;
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== "object") return value;
	const input = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(input).sort()) out[key] = canonicalize(input[key]);
	return out;
}

export function canonicalDelegatedJson(value: unknown): string {
	return JSON.stringify(canonicalize(value));
}

function bytesToBase64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function stringToBase64Url(value: string): string {
	return bytesToBase64Url(new TextEncoder().encode(value));
}

function base64UrlToBytes(value: string): Uint8Array | null {
	if (!value || !BASE64URL.test(value)) return null;
	try {
		const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
		const binary = atob(padded);
		const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
		return bytesToBase64Url(bytes) === value ? bytes : null;
	} catch {
		return null;
	}
}

function exactKeys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function safeName(value: unknown, max = 256): value is string {
	return typeof value === "string" && value.length >= 1 && value.length <= max && SAFE_NAME.test(value);
}

function validClaims(value: unknown): value is BrokerDelegatedClaims {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const claims = value as Record<string, unknown>;
	if (!exactKeys(claims, ["version", "issuer", "subjectUserId", "tenantId", "agentId", "tool", "resource", "audience", "scopes", "issuedAt", "notBefore", "expiresAt", "authSessionIssuedAt", "tokenId", "delegationDepth"], ["parentTokenId"])) return false;
	if (claims.version !== 1 || !safeName(claims.issuer) || !safeName(claims.audience)) return false;
	if (![claims.subjectUserId, claims.tenantId, claims.agentId, claims.tokenId].every((id) => typeof id === "string" && UUID.test(id))) return false;
	if (!claims.tool || typeof claims.tool !== "object" || Array.isArray(claims.tool)) return false;
	const tool = claims.tool as Record<string, unknown>;
	if (!exactKeys(tool, ["serverId", "name"]) || !safeName(tool.serverId) || !safeName(tool.name)) return false;
	if (!claims.resource || typeof claims.resource !== "object" || Array.isArray(claims.resource)) return false;
	const resource = claims.resource as Record<string, unknown>;
	if (!exactKeys(resource, ["type", "id"]) || !safeName(resource.type, 128) || typeof resource.id !== "string" || resource.id.length < 1 || resource.id.length > 2048 || /[\u0000-\u001f\u007f]/.test(resource.id)) return false;
	const claimScopes = claims.scopes;
	if (!Array.isArray(claimScopes) || claimScopes.length < 1 || claimScopes.length > 32 || claimScopes.some((scope) => typeof scope !== "string" || !SCOPE.test(scope))) return false;
	if (new Set(claimScopes).size !== claimScopes.length || ![...claimScopes].sort().every((scope, index) => scope === claimScopes[index])) return false;
	if (typeof claims.issuedAt !== "number" || !Number.isSafeInteger(claims.issuedAt) || typeof claims.notBefore !== "number" || !Number.isSafeInteger(claims.notBefore) || typeof claims.expiresAt !== "number" || !Number.isSafeInteger(claims.expiresAt) || typeof claims.authSessionIssuedAt !== "number" || !Number.isSafeInteger(claims.authSessionIssuedAt) || typeof claims.delegationDepth !== "number" || !Number.isSafeInteger(claims.delegationDepth)) return false;
	if (claims.delegationDepth < 0 || claims.delegationDepth > DELEGATED_CREDENTIAL_MAX_DEPTH || claims.authSessionIssuedAt <= 0 || claims.authSessionIssuedAt > claims.issuedAt || claims.issuedAt > claims.notBefore || claims.notBefore >= claims.expiresAt) return false;
	if (claims.parentTokenId !== undefined && (typeof claims.parentTokenId !== "string" || !UUID.test(claims.parentTokenId))) return false;
	return (claims.delegationDepth === 0) === (claims.parentTokenId === undefined);
}

async function importPrivateKey(pkcs8Base64: string): Promise<CryptoKey> {
	const bytes = Uint8Array.from(atob(pkcs8Base64.trim()), (character) => character.charCodeAt(0));
	return crypto.subtle.importKey("pkcs8", bytes, { name: "Ed25519" }, false, ["sign"]);
}

async function importPublicKey(spkiBase64: string): Promise<CryptoKey> {
	const bytes = Uint8Array.from(atob(spkiBase64.trim()), (character) => character.charCodeAt(0));
	return crypto.subtle.importKey("spki", bytes, { name: "Ed25519" }, false, ["verify"]);
}

async function sha256DelegatedClaims(claims: BrokerDelegatedClaims): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalDelegatedJson(claims))));
	return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function signDelegatedCredential(params: {
	claims: unknown;
	keyId: string;
	privateKeyPkcs8Base64: string;
}): Promise<{ token: string; claims: BrokerDelegatedClaims; claimsSha256: string }> {
	if (!validClaims(params.claims) || !safeName(params.keyId, 128)) throw new Error("invalid_delegated_claims");
	const header = stringToBase64Url(canonicalDelegatedJson({ alg: "EdDSA", typ: DELEGATED_CREDENTIAL_TYPE, kid: params.keyId, version: 1 }));
	const payload = stringToBase64Url(canonicalDelegatedJson(params.claims));
	const signingInput = `${header}.${payload}`;
	const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", await importPrivateKey(params.privateKeyPkcs8Base64), new TextEncoder().encode(signingInput)));
	return {
		token: `${signingInput}.${bytesToBase64Url(signature)}`,
		claims: params.claims,
		claimsSha256: await sha256DelegatedClaims(params.claims),
	};
}

export type BrokerTokenVerification =
	| { ok: true; claims: BrokerDelegatedClaims; claimsSha256: string }
	| { ok: false; error: "invalid_token" | "expired_token" | "not_yet_valid" };

export async function verifyDelegatedCredentialForBroker(params: {
	token: string;
	keyId: string;
	publicKeySpkiBase64: string;
	issuer: string;
	nowSeconds?: number;
}): Promise<BrokerTokenVerification> {
	if (typeof params.token !== "string" || params.token.length < 32 || params.token.length > 16_384) return { ok: false, error: "invalid_token" };
	const segments = params.token.split(".");
	if (segments.length !== 3) return { ok: false, error: "invalid_token" };
	const [headerSegment, payloadSegment, signatureSegment] = segments;
	const headerBytes = headerSegment ? base64UrlToBytes(headerSegment) : null;
	const payloadBytes = payloadSegment ? base64UrlToBytes(payloadSegment) : null;
	const signature = signatureSegment ? base64UrlToBytes(signatureSegment) : null;
	if (!headerBytes || !payloadBytes || !signature || signature.length !== 64) return { ok: false, error: "invalid_token" };
	let header: unknown;
	let claims: unknown;
	try {
		header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(headerBytes));
		claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(payloadBytes));
	} catch {
		return { ok: false, error: "invalid_token" };
	}
	if (!header || typeof header !== "object" || Array.isArray(header) || !exactKeys(header as Record<string, unknown>, ["alg", "typ", "kid", "version"])) return { ok: false, error: "invalid_token" };
	const parsedHeader = header as Record<string, unknown>;
	if (parsedHeader.alg !== "EdDSA" || parsedHeader.typ !== DELEGATED_CREDENTIAL_TYPE || parsedHeader.version !== 1 || parsedHeader.kid !== params.keyId) return { ok: false, error: "invalid_token" };
	if (!validClaims(claims) || claims.issuer !== params.issuer) return { ok: false, error: "invalid_token" };
	if (stringToBase64Url(canonicalDelegatedJson(header)) !== headerSegment || stringToBase64Url(canonicalDelegatedJson(claims)) !== payloadSegment) return { ok: false, error: "invalid_token" };
	try {
		const signatureBytes = signature.slice().buffer as ArrayBuffer;
		const valid = await crypto.subtle.verify("Ed25519", await importPublicKey(params.publicKeySpkiBase64), signatureBytes, new TextEncoder().encode(`${headerSegment}.${payloadSegment}`));
		if (!valid) return { ok: false, error: "invalid_token" };
	} catch {
		return { ok: false, error: "invalid_token" };
	}
	const now = Math.floor(params.nowSeconds ?? Date.now() / 1000);
	if (claims.expiresAt - claims.issuedAt > DELEGATED_CREDENTIAL_MAX_SECONDS) return { ok: false, error: "invalid_token" };
	if (claims.issuedAt > now + 30 || claims.notBefore > now + 30) return { ok: false, error: "not_yet_valid" };
	if (now >= claims.expiresAt) return { ok: false, error: "expired_token" };
	return { ok: true, claims, claimsSha256: await sha256DelegatedClaims(claims) };
}

export function matchesDelegatedContext(claims: BrokerDelegatedClaims, expected: unknown): boolean {
	if (!expected || typeof expected !== "object" || Array.isArray(expected)) return false;
	const value = expected as Record<string, unknown>;
	if (!exactKeys(value, ["tenant_id", "subject_user_id", "agent_id", "audience", "tool", "resource", "required_scopes"])) return false;
	if (value.tenant_id !== claims.tenantId || value.subject_user_id !== claims.subjectUserId || value.agent_id !== claims.agentId) return false;
	if (typeof value.audience !== "string" || value.audience !== claims.audience) return false;
	if (!value.tool || typeof value.tool !== "object" || Array.isArray(value.tool) || !value.resource || typeof value.resource !== "object" || Array.isArray(value.resource)) return false;
	const tool = value.tool as Record<string, unknown>;
	const resource = value.resource as Record<string, unknown>;
	if (!exactKeys(tool, ["server_id", "name"]) || tool.server_id !== claims.tool.serverId || tool.name !== claims.tool.name) return false;
	if (!exactKeys(resource, ["type", "id"]) || resource.type !== claims.resource.type || resource.id !== claims.resource.id) return false;
	if (!Array.isArray(value.required_scopes) || value.required_scopes.length < 1 || value.required_scopes.some((scope) => typeof scope !== "string" || !SCOPE.test(scope) || !claims.scopes.includes(scope))) return false;
	return true;
}
