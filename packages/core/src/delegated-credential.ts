import { createPublicKey, verify as cryptoVerify } from "node:crypto";

export const DELEGATED_CREDENTIAL_TYPE = "aidr-delegation+jwt" as const;
export const DELEGATED_CREDENTIAL_ALGORITHM = "EdDSA" as const;
export const DELEGATED_CREDENTIAL_VERSION = 1 as const;
export const MAX_DELEGATED_CREDENTIAL_SECONDS = 900;
export const MAX_DELEGATION_DEPTH = 4;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const SCOPE = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

export interface DelegatedToolIdentity {
	serverId: string;
	name: string;
}

export interface DelegatedResourceIdentity {
	type: string;
	id: string;
}

/**
 * Canonical identity lineage carried by an AIDR delegated credential.
 *
 * Every authorization-relevant dimension is signed. Consumers must provide
 * the expected context to `verifyDelegatedCredential`; accepting a token
 * without binding it to the current tool call would turn it into a bearer key.
 */
export interface DelegatedCredentialClaimsV1 {
	version: 1;
	issuer: string;
	subjectUserId: string;
	tenantId: string;
	agentId: string;
	tool: DelegatedToolIdentity;
	resource: DelegatedResourceIdentity;
	audience: string;
	scopes: string[];
	issuedAt: number;
	notBefore: number;
	expiresAt: number;
	/** Issuance time of the authenticated identity session that authorized minting. */
	authSessionIssuedAt: number;
	tokenId: string;
	delegationDepth: number;
	parentTokenId?: string;
}

export interface DelegatedCredentialVerificationContext {
	issuer: string;
	audience: string;
	tenantId: string;
	subjectUserId: string;
	agentId: string;
	tool: DelegatedToolIdentity;
	resource: DelegatedResourceIdentity;
	requiredScopes: readonly string[];
	now?: Date | number;
	clockSkewSeconds?: number;
	maxLifetimeSeconds?: number;
	maxDelegationDepth?: number;
	parentClaims?: DelegatedCredentialClaimsV1;
}

export type DelegatedCredentialErrorCode =
	| "malformed_token"
	| "unsupported_header"
	| "unknown_signing_key"
	| "invalid_signature"
	| "invalid_claims"
	| "invalid_context"
	| "token_not_yet_valid"
	| "token_expired"
	| "token_lifetime_exceeded"
	| "delegation_depth_exceeded"
	| "identity_mismatch"
	| "audience_mismatch"
	| "tool_mismatch"
	| "resource_mismatch"
	| "scope_insufficient"
	| "delegation_parent_required"
	| "delegation_escalation";

export type DelegatedCredentialVerificationResult =
	| { ok: true; keyId: string; claims: DelegatedCredentialClaimsV1 }
	| { ok: false; code: DelegatedCredentialErrorCode };

interface DelegatedCredentialHeader {
	alg: "EdDSA";
	typ: "aidr-delegation+jwt";
	kid: string;
	version: 1;
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== "object") return value;
	const object = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(object).sort()) out[key] = canonicalize(object[key]);
	return out;
}

export function canonicalDelegatedCredentialJson(value: unknown): string {
	return JSON.stringify(canonicalize(value));
}

function encodeBase64Url(input: Buffer | string): string {
	return Buffer.from(input).toString("base64url");
}

function decodeJsonSegment(segment: string): unknown {
	if (!segment || !BASE64URL.test(segment)) throw new Error("invalid base64url");
	const bytes = Buffer.from(segment, "base64url");
	if (bytes.length === 0 || encodeBase64Url(bytes) !== segment)
		throw new Error("non-canonical base64url");
	return JSON.parse(bytes.toString("utf8"));
}

function hasExactKeys(
	object: Record<string, unknown>,
	required: string[],
	optional: string[] = [],
): boolean {
	const allowed = new Set([...required, ...optional]);
	return (
		required.every((key) => Object.hasOwn(object, key)) &&
		Object.keys(object).every((key) => allowed.has(key))
	);
}

function safeString(value: unknown, max = 256): value is string {
	return (
		typeof value === "string" && value.length >= 1 && value.length <= max && SAFE_NAME.test(value)
	);
}

function validTool(value: unknown): value is DelegatedToolIdentity {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const tool = value as Record<string, unknown>;
	return (
		hasExactKeys(tool, ["serverId", "name"]) && safeString(tool.serverId) && safeString(tool.name)
	);
}

function validResource(value: unknown): value is DelegatedResourceIdentity {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const resource = value as Record<string, unknown>;
	return (
		hasExactKeys(resource, ["type", "id"]) &&
		safeString(resource.type, 128) &&
		typeof resource.id === "string" &&
		resource.id.length >= 1 &&
		resource.id.length <= 2048 &&
		!/[\u0000-\u001f\u007f]/.test(resource.id)
	);
}

function validScopes(value: unknown): value is string[] {
	if (!Array.isArray(value) || value.length < 1 || value.length > 32) return false;
	if (value.some((scope) => typeof scope !== "string" || !SCOPE.test(scope))) return false;
	return (
		new Set(value).size === value.length &&
		[...value].sort().every((scope, i) => scope === value[i])
	);
}

function validInteger(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value);
}

const REQUIRED_CLAIM_KEYS = [
	"version",
	"issuer",
	"subjectUserId",
	"tenantId",
	"agentId",
	"tool",
	"resource",
	"audience",
	"scopes",
	"issuedAt",
	"notBefore",
	"expiresAt",
	"authSessionIssuedAt",
	"tokenId",
	"delegationDepth",
];

function validClaimIdentities(claims: Record<string, unknown>): boolean {
	return (
		claims.version === DELEGATED_CREDENTIAL_VERSION &&
		safeString(claims.issuer) &&
		safeString(claims.audience) &&
		[claims.subjectUserId, claims.tenantId, claims.agentId, claims.tokenId].every(
			(id) => typeof id === "string" && UUID.test(id),
		) &&
		validTool(claims.tool) &&
		validResource(claims.resource) &&
		validScopes(claims.scopes)
	);
}

function claimTimes(claims: Record<string, unknown>): {
	issuedAt: number;
	notBefore: number;
	expiresAt: number;
	authSessionIssuedAt: number;
	delegationDepth: number;
} | null {
	const { issuedAt, notBefore, expiresAt, authSessionIssuedAt, delegationDepth } = claims;
	if (
		!validInteger(issuedAt) ||
		!validInteger(notBefore) ||
		!validInteger(expiresAt) ||
		!validInteger(authSessionIssuedAt) ||
		!validInteger(delegationDepth)
	)
		return null;
	if (delegationDepth < 0 || delegationDepth > MAX_DELEGATION_DEPTH) return null;
	if (authSessionIssuedAt <= 0 || authSessionIssuedAt > issuedAt) return null;
	if (issuedAt > notBefore || notBefore >= expiresAt) return null;
	return { issuedAt, notBefore, expiresAt, authSessionIssuedAt, delegationDepth };
}

function validParentLineage(claims: Record<string, unknown>, depth: number): boolean {
	const parent = claims.parentTokenId;
	if (parent !== undefined && (typeof parent !== "string" || !UUID.test(parent))) return false;
	return (depth === 0) === (parent === undefined);
}

export function parseDelegatedCredentialClaims(value: unknown): DelegatedCredentialClaimsV1 | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const claims = value as Record<string, unknown>;
	if (!hasExactKeys(claims, REQUIRED_CLAIM_KEYS, ["parentTokenId"])) return null;
	if (!validClaimIdentities(claims)) return null;
	const times = claimTimes(claims);
	if (!times || !validParentLineage(claims, times.delegationDepth)) return null;
	return {
		version: 1,
		issuer: claims.issuer as string,
		subjectUserId: claims.subjectUserId as string,
		tenantId: claims.tenantId as string,
		agentId: claims.agentId as string,
		tool: claims.tool as DelegatedToolIdentity,
		resource: claims.resource as DelegatedResourceIdentity,
		audience: claims.audience as string,
		scopes: claims.scopes as string[],
		issuedAt: times.issuedAt,
		notBefore: times.notBefore,
		expiresAt: times.expiresAt,
		authSessionIssuedAt: times.authSessionIssuedAt,
		tokenId: claims.tokenId as string,
		delegationDepth: times.delegationDepth,
		...(claims.parentTokenId === undefined
			? {}
			: { parentTokenId: claims.parentTokenId as string }),
	};
}

function sameTool(left: DelegatedToolIdentity, right: DelegatedToolIdentity): boolean {
	return left.serverId === right.serverId && left.name === right.name;
}

function sameResource(left: DelegatedResourceIdentity, right: DelegatedResourceIdentity): boolean {
	return left.type === right.type && left.id === right.id;
}

/** Returns false when a child widens or changes any authority signed by its parent. */
export function delegationDoesNotEscalate(
	parent: DelegatedCredentialClaimsV1,
	child: DelegatedCredentialClaimsV1,
): boolean {
	const parentScopes = new Set(parent.scopes);
	return (
		child.parentTokenId === parent.tokenId &&
		child.delegationDepth === parent.delegationDepth + 1 &&
		child.issuer === parent.issuer &&
		child.subjectUserId === parent.subjectUserId &&
		child.tenantId === parent.tenantId &&
		child.agentId === parent.agentId &&
		child.authSessionIssuedAt === parent.authSessionIssuedAt &&
		sameTool(child.tool, parent.tool) &&
		sameResource(child.resource, parent.resource) &&
		child.audience === parent.audience &&
		child.scopes.every((scope) => parentScopes.has(scope)) &&
		child.issuedAt >= parent.issuedAt &&
		child.notBefore >= parent.notBefore &&
		child.expiresAt <= parent.expiresAt
	);
}

function parseHeader(value: unknown): DelegatedCredentialHeader | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const header = value as Record<string, unknown>;
	if (!hasExactKeys(header, ["alg", "typ", "kid", "version"])) return null;
	if (
		header.alg !== DELEGATED_CREDENTIAL_ALGORITHM ||
		header.typ !== DELEGATED_CREDENTIAL_TYPE ||
		header.version !== 1 ||
		!safeString(header.kid, 128)
	)
		return null;
	return header as unknown as DelegatedCredentialHeader;
}

function publicKey(raw: unknown) {
	if (typeof raw !== "string") return null;
	const value = raw.trim();
	if (!value) return null;
	try {
		const key = value.includes("BEGIN PUBLIC KEY")
			? createPublicKey(value)
			: createPublicKey({ key: Buffer.from(value, "base64"), format: "der", type: "spki" });
		return key.asymmetricKeyType === "ed25519" ? key : null;
	} catch {
		return null;
	}
}

function failure(code: DelegatedCredentialErrorCode): DelegatedCredentialVerificationResult {
	return { ok: false, code };
}

interface ParsedCompactCredential {
	header: DelegatedCredentialHeader;
	claims: DelegatedCredentialClaimsV1;
	headerSegment: string;
	payloadSegment: string;
	signatureSegment: string;
}

function parseCompactCredential(
	token: string,
): ParsedCompactCredential | DelegatedCredentialErrorCode {
	if (typeof token !== "string" || token.length < 32 || token.length > 16_384)
		return "malformed_token";
	const segments = token.split(".");
	if (segments.length !== 3) return "malformed_token";
	const [headerSegment, payloadSegment, signatureSegment] = segments;
	if (!headerSegment || !payloadSegment || !signatureSegment || !BASE64URL.test(signatureSegment))
		return "malformed_token";
	let rawHeader: unknown;
	let rawClaims: unknown;
	try {
		rawHeader = decodeJsonSegment(headerSegment);
		rawClaims = decodeJsonSegment(payloadSegment);
	} catch {
		return "malformed_token";
	}
	const header = parseHeader(rawHeader);
	if (!header) return "unsupported_header";
	const claims = parseDelegatedCredentialClaims(rawClaims);
	if (!claims) return "invalid_claims";
	if (
		encodeBase64Url(canonicalDelegatedCredentialJson(rawHeader)) !== headerSegment ||
		encodeBase64Url(canonicalDelegatedCredentialJson(rawClaims)) !== payloadSegment
	)
		return "malformed_token";
	return { header, claims, headerSegment, payloadSegment, signatureSegment };
}

function verifyCompactSignature(
	parsed: ParsedCompactCredential,
	publicKeysById: Readonly<Record<string, string>>,
): DelegatedCredentialErrorCode | null {
	if (!Object.hasOwn(publicKeysById, parsed.header.kid)) return "unknown_signing_key";
	const configuredKey = publicKeysById[parsed.header.kid];
	const key = publicKey(configuredKey);
	if (!key) return "unknown_signing_key";
	try {
		const signature = Buffer.from(parsed.signatureSegment, "base64url");
		if (signature.length !== 64 || encodeBase64Url(signature) !== parsed.signatureSegment)
			return "malformed_token";
		const input = Buffer.from(`${parsed.headerSegment}.${parsed.payloadSegment}`, "ascii");
		return cryptoVerify(null, input, key, signature) ? null : "invalid_signature";
	} catch {
		return "invalid_signature";
	}
}

function verificationTime(context: DelegatedCredentialVerificationContext): number | null {
	const seconds =
		context.now instanceof Date
			? context.now.getTime() / 1000
			: context.now === undefined
				? Date.now() / 1000
				: context.now;
	return typeof seconds === "number" && Number.isSafeInteger(Math.floor(seconds))
		? Math.floor(seconds)
		: null;
}

function finiteOptionalNumber(value: unknown): value is number | undefined {
	return value === undefined || (typeof value === "number" && Number.isFinite(value));
}

function validVerificationOptions(context: DelegatedCredentialVerificationContext): boolean {
	return (
		!!context &&
		typeof context === "object" &&
		safeString(context.issuer) &&
		safeString(context.audience) &&
		[context.tenantId, context.subjectUserId, context.agentId].every(
			(id) => typeof id === "string" && UUID.test(id),
		) &&
		validTool(context.tool) &&
		validResource(context.resource) &&
		finiteOptionalNumber(context.clockSkewSeconds) &&
		finiteOptionalNumber(context.maxLifetimeSeconds) &&
		finiteOptionalNumber(context.maxDelegationDepth) &&
		Array.isArray(context.requiredScopes) &&
		context.requiredScopes.length >= 1 &&
		context.requiredScopes.length <= 32 &&
		context.requiredScopes.every((scope) => typeof scope === "string" && SCOPE.test(scope))
	);
}

function matchesIdentity(
	claims: DelegatedCredentialClaimsV1,
	context: DelegatedCredentialVerificationContext,
): boolean {
	return (
		claims.issuer === context.issuer &&
		claims.tenantId === context.tenantId &&
		claims.subjectUserId === context.subjectUserId &&
		claims.agentId === context.agentId
	);
}

function validateTemporalClaimsContext(
	claims: DelegatedCredentialClaimsV1,
	context: DelegatedCredentialVerificationContext,
): DelegatedCredentialErrorCode | null {
	if (!validVerificationOptions(context)) return "invalid_context";
	const now = verificationTime(context);
	if (now === null) return "invalid_context";
	const clockSkew = Math.max(0, Math.min(300, Math.floor(context.clockSkewSeconds ?? 30)));
	const maxLifetime = Math.max(
		1,
		Math.min(
			MAX_DELEGATED_CREDENTIAL_SECONDS,
			Math.floor(context.maxLifetimeSeconds ?? MAX_DELEGATED_CREDENTIAL_SECONDS),
		),
	);
	const maxDepth = Math.max(
		0,
		Math.min(MAX_DELEGATION_DEPTH, Math.floor(context.maxDelegationDepth ?? MAX_DELEGATION_DEPTH)),
	);
	if (claims.expiresAt - claims.issuedAt > maxLifetime) return "token_lifetime_exceeded";
	if (claims.delegationDepth > maxDepth) return "delegation_depth_exceeded";
	if (claims.issuedAt > now + clockSkew || claims.notBefore > now + clockSkew)
		return "token_not_yet_valid";
	if (now >= claims.expiresAt) return "token_expired";
	return null;
}

function validateClaimsContext(
	claims: DelegatedCredentialClaimsV1,
	context: DelegatedCredentialVerificationContext,
): DelegatedCredentialErrorCode | null {
	const temporalFailure = validateTemporalClaimsContext(claims, context);
	if (temporalFailure) return temporalFailure;
	if (!matchesIdentity(claims, context)) return "identity_mismatch";
	if (claims.audience !== context.audience) return "audience_mismatch";
	if (!sameTool(claims.tool, context.tool)) return "tool_mismatch";
	if (!sameResource(claims.resource, context.resource)) return "resource_mismatch";
	const grantedScopes = new Set(claims.scopes);
	if (!context.requiredScopes.every((scope) => SCOPE.test(scope) && grantedScopes.has(scope)))
		return "scope_insufficient";
	if (claims.delegationDepth > 0 && !context.parentClaims) return "delegation_parent_required";
	// parentClaims must come from the caller's separately verified trusted lineage,
	// never from the same untrusted request as the child token.
	if (context.parentClaims && !delegationDoesNotEscalate(context.parentClaims, claims))
		return "delegation_escalation";
	return null;
}

export function verifyDelegatedCredential(params: {
	token: string;
	publicKeysById: Readonly<Record<string, string>>;
	context: DelegatedCredentialVerificationContext;
}): DelegatedCredentialVerificationResult {
	const parsed = parseCompactCredential(params.token);
	if (typeof parsed === "string") return failure(parsed);
	const signatureFailure = verifyCompactSignature(parsed, params.publicKeysById);
	if (signatureFailure) return failure(signatureFailure);
	const claimsFailure = validateClaimsContext(parsed.claims, params.context);
	if (claimsFailure) return failure(claimsFailure);
	return { ok: true, keyId: parsed.header.kid, claims: parsed.claims };
}
