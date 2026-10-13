/**
 * Signed MCP tool-manifest attestation.
 *
 * A trusted signature proves who published a manifest. It does not mean that an
 * operator approved a new tool description or schema. This module therefore
 * verifies Ed25519 signatures and time bounds, persists replay state, and
 * quarantines every unapproved tool-set change for out-of-band review.
 */

import {
	createHash,
	createHmac,
	createPrivateKey,
	createPublicKey,
	sign as cryptoSign,
	verify as cryptoVerify,
	KeyObject,
	randomBytes,
	randomUUID,
	timingSafeEqual,
} from "node:crypto";
import { link, mkdir, open, readFile, stat, unlink } from "node:fs/promises";
import { basename, isAbsolute, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { atomicWriteJson, getFileContent } from "./file-utils.js";

const SIGNING_DOMAIN = "AIDR-MCP-TOOL-MANIFEST-V1\n";
const DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_MAX_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_LOCK_TIMEOUT_MS = 5_000;
const MAX_APPROVED_TOOLSETS = 256;
const APPROVAL_SIGNING_DOMAIN = "AIDR-MCP-TOOLSET-APPROVAL-V1\n";
const STATE_MAC_DOMAIN = "AIDR-MCP-ATTESTATION-STATE-V1\0";
const STATE_INTEGRITY_KEY_FILE = ".state-integrity.key";
const STATE_INTEGRITY_KEY_BYTES = 32;
const DAY_MS = 24 * 60 * 60 * 1000;
/** Default lifetime of an operator approval; the operator command may shorten or extend it. */
export const DEFAULT_MCP_APPROVAL_LIFETIME_MS = 90 * DAY_MS;
/** Longest operator approval lifetime that is ever signed or honoured. */
export const MAX_MCP_APPROVAL_LIFETIME_MS = 366 * DAY_MS;

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
// MCP tool names are case-sensitive and commonly include underscores. Preserve
// the publisher's exact identifier; policy matching must not case-fold it.
const TOOL_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

export type McpJsonValue =
	| null
	| boolean
	| number
	| string
	| McpJsonValue[]
	| { [key: string]: McpJsonValue };

function isJsonValue(value: unknown, seen = new Set<object>()): value is McpJsonValue {
	if (value === null || typeof value === "string" || typeof value === "boolean") return true;
	if (typeof value === "number") return Number.isFinite(value);
	if (typeof value !== "object") return false;
	if (seen.has(value)) return false;
	seen.add(value);

	if (Array.isArray(value)) {
		const valid = value.every((entry) => isJsonValue(entry, seen));
		seen.delete(value);
		return valid;
	}

	const prototype = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) {
		seen.delete(value);
		return false;
	}
	const valid = Object.values(value as Record<string, unknown>).every((entry) =>
		isJsonValue(entry, seen),
	);
	seen.delete(value);
	return valid;
}

const JsonObjectSchema: z.ZodType<Record<string, McpJsonValue>> = z.custom(
	(value) =>
		value !== null && !Array.isArray(value) && typeof value === "object" && isJsonValue(value),
	{ message: "must be a JSON object with finite values and no cycles" },
);

export const McpToolDefinitionSchema = z
	.object({
		name: z.string().regex(TOOL_NAME_PATTERN),
		description: z.string().max(65_536),
		input_schema: JsonObjectSchema,
		output_schema: JsonObjectSchema.optional(),
		annotations: JsonObjectSchema.optional(),
	})
	.strict();

export type McpToolDefinition = z.infer<typeof McpToolDefinitionSchema>;

export const McpToolManifestV1Schema = z
	.object({
		schema_version: z.literal(1),
		server_id: z.string().regex(ID_PATTERN),
		sequence: z.number().int().nonnegative().safe(),
		issued_at: z.string().datetime({ offset: true }),
		expires_at: z.string().datetime({ offset: true }),
		tools: z.array(McpToolDefinitionSchema).max(4096),
	})
	.strict()
	.superRefine((manifest, context) => {
		const names = new Set<string>();
		for (const [index, tool] of manifest.tools.entries()) {
			if (names.has(tool.name)) {
				context.addIssue({
					code: z.ZodIssueCode.custom,
					path: ["tools", index, "name"],
					message: `duplicate MCP tool name: ${tool.name}`,
				});
			}
			names.add(tool.name);
		}
	});

export type McpToolManifestV1 = z.infer<typeof McpToolManifestV1Schema>;

export const SignedMcpToolManifestV1Schema = z
	.object({
		key_id: z.string().regex(ID_PATTERN),
		manifest: McpToolManifestV1Schema,
		signature_b64: z.string().min(1).max(512),
	})
	.strict();

export type SignedMcpToolManifestV1 = z.infer<typeof SignedMcpToolManifestV1Schema>;

function canonicalize(value: McpJsonValue): McpJsonValue {
	if (Array.isArray(value)) return value.map((entry) => canonicalize(entry));
	if (value === null || typeof value !== "object") return value;
	const output = Object.create(null) as Record<string, McpJsonValue>;
	for (const key of Object.keys(value).sort())
		output[key] = canonicalize(value[key] as McpJsonValue);
	return output;
}

/** Bind an operator approval to the verified signer and the local connection. */
export function mcpApprovalBindingHash(input: {
	serverId: string;
	keyId: string;
	signerKeySha256: string;
	connection: McpJsonValue;
}): string {
	if (!isJsonValue(input.connection)) throw new Error("invalid MCP approval connection");
	return createHash("sha256")
		.update("AIDR-MCP-APPROVAL-BINDING-V1\0")
		.update(
			JSON.stringify(
				canonicalize([input.serverId, input.keyId, input.signerKeySha256, input.connection]),
			),
		)
		.digest("hex");
}

function normalizedManifest(manifest: McpToolManifestV1): McpToolManifestV1 {
	return {
		...manifest,
		tools: [...manifest.tools].sort((left, right) =>
			left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
		),
	};
}

/** Deterministic payload covered by the Ed25519 signature. */
export function canonicalMcpToolManifest(manifest: McpToolManifestV1): string {
	const parsed = McpToolManifestV1Schema.parse(manifest);
	return JSON.stringify(canonicalize(normalizedManifest(parsed) as McpJsonValue));
}

function manifestPayload(manifest: McpToolManifestV1): Buffer {
	return Buffer.from(`${SIGNING_DOMAIN}${canonicalMcpToolManifest(manifest)}`, "utf8");
}

function signingPayload(manifest: McpToolManifestV1, keyId: string): Buffer {
	// The earlier V1 payload omitted key_id. Re-sign existing manifests with the
	// trusted publisher after this upgrade; accepting that payload permits alias substitution.
	return Buffer.from(`${SIGNING_DOMAIN}${keyId}\n${canonicalMcpToolManifest(manifest)}`, "utf8");
}

export function mcpManifestHash(manifest: McpToolManifestV1): string {
	return createHash("sha256").update(manifestPayload(manifest)).digest("hex");
}

export function mcpToolsetHash(tools: McpToolDefinition[]): string {
	const parsed = z.array(McpToolDefinitionSchema).max(4096).parse(tools);
	const names = new Set<string>();
	for (const tool of parsed) {
		if (names.has(tool.name)) throw new Error(`duplicate MCP tool name: ${tool.name}`);
		names.add(tool.name);
	}
	const ordered = [...parsed].sort((left, right) =>
		left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
	);
	return createHash("sha256")
		.update(JSON.stringify(canonicalize(ordered as McpJsonValue)))
		.digest("hex");
}

/** Publisher helper. Private key material is never persisted by this module. */
export function signMcpToolManifest(params: {
	manifest: McpToolManifestV1;
	keyId: string;
	privateKey: string | Buffer | KeyObject;
}): SignedMcpToolManifestV1 {
	if (!ID_PATTERN.test(params.keyId)) throw new Error("invalid MCP signer key id");
	const manifest = McpToolManifestV1Schema.parse(params.manifest);
	const privateKey =
		params.privateKey instanceof KeyObject
			? params.privateKey
			: createPrivateKey(params.privateKey);
	if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
		throw new Error("MCP manifests must be signed with an Ed25519 private key");
	}
	return {
		key_id: params.keyId,
		manifest,
		signature_b64: cryptoSign(null, signingPayload(manifest, params.keyId), privateKey).toString(
			"base64",
		),
	};
}

export interface McpSignerHealthEvidenceV1 {
	schema_version: 1;
	status: "ok";
	last_success_at: string;
	active_key_expires_at: string;
}

/**
 * Atomically publish the fixed-name monitoring contract after a successful
 * signing operation. The caller owns key rotation and supplies its real expiry.
 */
export async function writeMcpSignerHealthEvidence(params: {
	path: string;
	lastSuccessAt: Date;
	activeKeyExpiresAt: Date;
	now?: Date;
}): Promise<McpSignerHealthEvidenceV1> {
	const lastSuccessAt = params.lastSuccessAt.getTime();
	const activeKeyExpiresAt = params.activeKeyExpiresAt.getTime();
	const now = (params.now ?? new Date()).getTime();
	if (!Number.isFinite(lastSuccessAt) || lastSuccessAt > now) {
		throw new Error("invalid MCP signer last-success timestamp");
	}
	if (!Number.isFinite(activeKeyExpiresAt) || activeKeyExpiresAt <= now) {
		throw new Error("active MCP signer key is expired");
	}
	const evidence: McpSignerHealthEvidenceV1 = {
		schema_version: 1,
		status: "ok",
		last_success_at: params.lastSuccessAt.toISOString(),
		active_key_expires_at: params.activeKeyExpiresAt.toISOString(),
	};
	// This fixed schema contains no secrets or identifiers. Owner-write/other-read
	// lets the non-root dashboard consume it through its read-only health mount.
	await atomicWriteJson(params.path, evidence, { mode: 0o644 });
	return evidence;
}

export type McpManifestRejectionReason =
	| "invalid_envelope"
	| "unexpected_server"
	| "untrusted_signer"
	| "revoked_signer"
	| "invalid_public_key"
	| "invalid_signature"
	| "not_yet_valid"
	| "expired"
	| "invalid_time_window"
	| "lifetime_too_long"
	| "sequence_replay"
	| "sequence_conflict"
	| "state_unavailable";

export interface McpManifestVerifierConfig {
	trustedSigners: ReadonlyMap<string, string> | Readonly<Record<string, string>>;
	revokedKeyIds?: ReadonlySet<string>;
	expectedServerId?: string;
	clockSkewMs?: number;
	maxLifetimeMs?: number;
	now?: Date;
}

export type McpCryptographicVerification =
	| {
			valid: true;
			signed: SignedMcpToolManifestV1;
			manifestHash: string;
			toolsetHash: string;
			signerKeySha256: string;
	  }
	| { valid: false; reason: McpManifestRejectionReason };

function trustedSigner(config: McpManifestVerifierConfig, keyId: string): string | undefined {
	const signers = config.trustedSigners;
	if ("get" in signers && typeof signers.get === "function") {
		const value = signers.get(keyId);
		return typeof value === "string" ? value : undefined;
	}
	if (!Object.hasOwn(signers, keyId)) return undefined;
	const value = (signers as Readonly<Record<string, string>>)[keyId];
	return typeof value === "string" ? value : undefined;
}

function decodeEd25519Signature(value: string): Buffer | null {
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) return null;
	const decoded = Buffer.from(value, "base64");
	if (decoded.length !== 64 || decoded.toString("base64") !== value) return null;
	return decoded;
}

function validateManifestTimes(
	manifest: McpToolManifestV1,
	config: McpManifestVerifierConfig,
): McpManifestRejectionReason | null {
	const issuedAt = Date.parse(manifest.issued_at);
	const expiresAt = Date.parse(manifest.expires_at);
	if (expiresAt <= issuedAt) return "invalid_time_window";
	const maxLifetime = config.maxLifetimeMs ?? DEFAULT_MAX_LIFETIME_MS;
	if (!Number.isFinite(maxLifetime) || maxLifetime <= 0 || expiresAt - issuedAt > maxLifetime) {
		return "lifetime_too_long";
	}
	const now = (config.now ?? new Date()).getTime();
	const clockSkew = config.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
	if (!Number.isFinite(now) || !Number.isFinite(clockSkew) || clockSkew < 0) {
		return "invalid_time_window";
	}
	if (issuedAt > now + clockSkew) return "not_yet_valid";
	if (expiresAt <= now) return "expired";
	return null;
}

function verifyManifestSignature(
	manifest: McpToolManifestV1,
	keyId: string,
	publicKeyPem: string,
	signatureBase64: string,
): McpManifestRejectionReason | null {
	const signature = decodeEd25519Signature(signatureBase64);
	if (!signature) return "invalid_signature";
	try {
		const publicKey = createPublicKey(publicKeyPem);
		if (publicKey.asymmetricKeyType !== "ed25519") return "invalid_public_key";
		return cryptoVerify(null, signingPayload(manifest, keyId), publicKey, signature)
			? null
			: "invalid_signature";
	} catch {
		return "invalid_public_key";
	}
}

/** Stateless schema, time-bound, signer allowlist and Ed25519 verification. */
export function verifySignedMcpToolManifest(
	candidate: unknown,
	config: McpManifestVerifierConfig,
): McpCryptographicVerification {
	const parsed = SignedMcpToolManifestV1Schema.safeParse(candidate);
	if (!parsed.success) return { valid: false, reason: "invalid_envelope" };
	const signed = parsed.data;
	if (config.expectedServerId && signed.manifest.server_id !== config.expectedServerId) {
		return { valid: false, reason: "unexpected_server" };
	}
	if (config.revokedKeyIds?.has(signed.key_id)) return { valid: false, reason: "revoked_signer" };
	const publicKeyPem = trustedSigner(config, signed.key_id);
	if (!publicKeyPem) return { valid: false, reason: "untrusted_signer" };

	const timeFailure = validateManifestTimes(signed.manifest, config);
	if (timeFailure) return { valid: false, reason: timeFailure };
	const signatureFailure = verifyManifestSignature(
		signed.manifest,
		signed.key_id,
		publicKeyPem,
		signed.signature_b64,
	);
	if (signatureFailure) return { valid: false, reason: signatureFailure };

	return {
		valid: true,
		signed,
		manifestHash: mcpManifestHash(signed.manifest),
		toolsetHash: mcpToolsetHash(signed.manifest.tools),
		signerKeySha256: createHash("sha256").update(publicKeyPem).digest("hex"),
	};
}

export interface McpToolDrift {
	added: string[];
	removed: string[];
	changed: string[];
}

/**
 * One operator approval. Only an entry signed by a configured operator approval
 * key (`approvalKeyId` + `signatureB64` over every other field and the server id)
 * and still inside its `approvedAt`..`expiresAt` window is ever honoured. The
 * signature fields are optional in the schema so that a legacy or forged entry
 * is read, reported and ignored instead of making the whole state unreadable.
 */
export interface McpToolsetApproval {
	toolsetHash: string;
	keyId?: string;
	signerKeySha256?: string;
	bindingSha256?: string;
	approvedAt: string;
	approvedBy: string;
	reason: string;
	expiresAt?: string;
	approvalKeyId?: string;
	signatureB64?: string;
}

/** Operator approval key ids mapped to Ed25519 public keys (PEM). */
export type McpApprovalKeyring = ReadonlyMap<string, string> | Readonly<Record<string, string>>;

/** Why an approval entry that matched the presented toolset was not honoured. */
export type McpApprovalEntryRejection =
	| "unsigned_approval"
	| "untrusted_approval_key"
	| "invalid_approval_key"
	| "invalid_approval_signature"
	| "approval_not_yet_valid"
	| "approval_expired"
	| "invalid_approval_window";

export interface McpQuarantinedManifest {
	manifestHash: string;
	toolsetHash: string;
	keyId: string;
	signerKeySha256?: string;
	bindingSha256?: string;
	sequence: number;
	detectedAt: string;
	drift: McpToolDrift;
	tools: McpToolDefinition[];
}

export interface McpAttestationStateV1 {
	schemaVersion: 1;
	serverId: string;
	revision: number;
	highestSequence: number;
	highestManifestHash: string;
	activeToolsetHash?: string;
	activeTools: McpToolDefinition[];
	approvedToolsets: McpToolsetApproval[];
	quarantine?: McpQuarantinedManifest;
}

const McpToolDriftSchema = z.object({
	added: z.array(z.string().regex(TOOL_NAME_PATTERN)),
	removed: z.array(z.string().regex(TOOL_NAME_PATTERN)),
	changed: z.array(z.string().regex(TOOL_NAME_PATTERN)),
});

const McpAttestationStateV1Schema: z.ZodType<McpAttestationStateV1> = z.object({
	schemaVersion: z.literal(1),
	serverId: z.string().regex(ID_PATTERN),
	revision: z.number().int().nonnegative().safe(),
	highestSequence: z.number().int().nonnegative().safe(),
	highestManifestHash: z.string().regex(SHA256_PATTERN),
	activeToolsetHash: z.string().regex(SHA256_PATTERN).optional(),
	activeTools: z.array(McpToolDefinitionSchema).max(4096),
	approvedToolsets: z
		.array(
			z.object({
				toolsetHash: z.string().regex(SHA256_PATTERN),
				keyId: z.string().regex(ID_PATTERN).optional(),
				signerKeySha256: z.string().regex(SHA256_PATTERN).optional(),
				bindingSha256: z.string().regex(SHA256_PATTERN).optional(),
				approvedAt: z.string().datetime({ offset: true }),
				approvedBy: z.string().min(1).max(256),
				reason: z.string().min(1).max(2048),
				expiresAt: z.string().datetime({ offset: true }).optional(),
				approvalKeyId: z.string().regex(ID_PATTERN).optional(),
				signatureB64: z.string().min(1).max(512).optional(),
			}),
		)
		.max(MAX_APPROVED_TOOLSETS),
	quarantine: z
		.object({
			manifestHash: z.string().regex(SHA256_PATTERN),
			toolsetHash: z.string().regex(SHA256_PATTERN),
			keyId: z.string().regex(ID_PATTERN),
			signerKeySha256: z.string().regex(SHA256_PATTERN).optional(),
			bindingSha256: z.string().regex(SHA256_PATTERN).optional(),
			sequence: z.number().int().nonnegative().safe(),
			detectedAt: z.string().datetime({ offset: true }),
			drift: McpToolDriftSchema,
			tools: z.array(McpToolDefinitionSchema).max(4096),
		})
		.optional(),
});

function keyringEntry(keyring: McpApprovalKeyring | undefined, keyId: string): string | undefined {
	if (!keyring) return undefined;
	if ("get" in keyring && typeof keyring.get === "function") {
		const value = keyring.get(keyId);
		return typeof value === "string" ? value : undefined;
	}
	if (!Object.hasOwn(keyring, keyId)) return undefined;
	const value = (keyring as Readonly<Record<string, string>>)[keyId];
	return typeof value === "string" ? value : undefined;
}

/** A finite, non-empty approval window no longer than MAX_MCP_APPROVAL_LIFETIME_MS. */
function isValidApprovalWindow(approvedAt: number, expiresAt: number): boolean {
	return (
		Number.isFinite(approvedAt) &&
		Number.isFinite(expiresAt) &&
		expiresAt > approvedAt &&
		expiresAt - approvedAt <= MAX_MCP_APPROVAL_LIFETIME_MS
	);
}

/**
 * Deterministic payload an operator approval key signs. It covers every field
 * of the entry except the signature, plus the server id the entry is stored
 * under, so an entry cannot be moved to another server or re-scoped.
 */
function approvalPayload(serverId: string, entry: McpToolsetApproval): Buffer {
	const covered = canonicalize([
		serverId,
		entry.toolsetHash,
		entry.keyId ?? null,
		entry.signerKeySha256 ?? null,
		entry.bindingSha256 ?? null,
		entry.approvedAt,
		entry.expiresAt ?? null,
		entry.approvedBy,
		entry.reason,
		entry.approvalKeyId ?? null,
	]);
	return Buffer.from(`${APPROVAL_SIGNING_DOMAIN}${JSON.stringify(covered)}`, "utf8");
}

/**
 * Operator-side helper: sign one toolset approval with the operator approval
 * key. The private key belongs to the operator (for the gateway, a
 * passphrase-protected key file read by `aidr-mcp-approve`); it must never be
 * readable by the agent or the serving process.
 */
export function signMcpToolsetApproval(params: {
	serverId: string;
	toolsetHash: string;
	keyId: string;
	signerKeySha256: string;
	bindingSha256: string;
	approvedBy: string;
	reason: string;
	approvedAt: Date;
	expiresAt: Date;
	approvalKeyId: string;
	privateKey: string | Buffer | KeyObject;
}): McpToolsetApproval {
	if (!ID_PATTERN.test(params.serverId)) throw new Error("invalid MCP server id");
	if (!ID_PATTERN.test(params.approvalKeyId)) throw new Error("invalid MCP approval key id");
	if (!ID_PATTERN.test(params.keyId)) throw new Error("invalid MCP signer key id");
	for (const value of [params.toolsetHash, params.signerKeySha256, params.bindingSha256]) {
		if (!SHA256_PATTERN.test(value)) throw new Error("invalid MCP approval hash");
	}
	if (!isValidApprovalWindow(params.approvedAt.getTime(), params.expiresAt.getTime())) {
		throw new Error("invalid MCP approval lifetime");
	}
	const privateKey =
		params.privateKey instanceof KeyObject
			? params.privateKey
			: createPrivateKey(params.privateKey);
	if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
		throw new Error("MCP approvals must be signed with an Ed25519 private key");
	}
	const entry: McpToolsetApproval = {
		toolsetHash: params.toolsetHash,
		keyId: params.keyId,
		signerKeySha256: params.signerKeySha256,
		bindingSha256: params.bindingSha256,
		approvedAt: params.approvedAt.toISOString(),
		approvedBy: params.approvedBy,
		reason: params.reason,
		expiresAt: params.expiresAt.toISOString(),
		approvalKeyId: params.approvalKeyId,
	};
	entry.signatureB64 = cryptoSign(
		null,
		approvalPayload(params.serverId, entry),
		privateKey,
	).toString("base64");
	return entry;
}

/**
 * Verify one stored approval against the configured operator approval keys.
 * Returns null when the entry may be honoured. Without a keyring nothing is
 * ever honoured: an approval the gateway cannot authenticate is no approval.
 */
export function verifyMcpToolsetApproval(
	entry: McpToolsetApproval,
	params: {
		serverId: string;
		approvalKeys: McpApprovalKeyring | undefined;
		now?: Date;
		clockSkewMs?: number;
	},
): McpApprovalEntryRejection | null {
	if (!entry.approvalKeyId || !entry.signatureB64 || !entry.expiresAt) {
		return "unsigned_approval";
	}
	const publicKeyPem = keyringEntry(params.approvalKeys, entry.approvalKeyId);
	if (!publicKeyPem) return "untrusted_approval_key";
	const signature = decodeEd25519Signature(entry.signatureB64);
	if (!signature) return "invalid_approval_signature";
	try {
		const publicKey = createPublicKey(publicKeyPem);
		if (publicKey.asymmetricKeyType !== "ed25519") return "invalid_approval_key";
		if (!cryptoVerify(null, approvalPayload(params.serverId, entry), publicKey, signature)) {
			return "invalid_approval_signature";
		}
	} catch {
		return "invalid_approval_key";
	}
	const approvedAt = Date.parse(entry.approvedAt);
	const expiresAt = Date.parse(entry.expiresAt);
	if (!isValidApprovalWindow(approvedAt, expiresAt)) return "invalid_approval_window";
	const now = (params.now ?? new Date()).getTime();
	const clockSkew = params.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
	if (approvedAt > now + clockSkew) return "approval_not_yet_valid";
	if (expiresAt <= now) return "approval_expired";
	return null;
}

/** The approval-relevant identity of one verified manifest on one connection. */
export interface McpApprovalSubject {
	toolsetHash: string;
	keyId: string;
	signerKeySha256: string;
	bindingSha256: string;
}

function matchesSubject(entry: McpToolsetApproval, subject: McpApprovalSubject): boolean {
	return (
		entry.toolsetHash === subject.toolsetHash &&
		entry.keyId === subject.keyId &&
		entry.signerKeySha256 === subject.signerKeySha256 &&
		entry.bindingSha256 === subject.bindingSha256
	);
}

/**
 * Whether the stored approvals contain a valid, operator-signed, unexpired
 * approval for exactly this toolset, signer and connection. Every matching
 * entry that fails verification is reported through `onIgnored` and never
 * honoured.
 */
export function hasHonouredMcpApproval(
	approvals: readonly McpToolsetApproval[],
	subject: McpApprovalSubject,
	params: {
		serverId: string;
		approvalKeys: McpApprovalKeyring | undefined;
		now?: Date;
		onIgnored?: (reason: McpApprovalEntryRejection, entry: McpToolsetApproval) => void;
	},
): boolean {
	let honoured = false;
	for (const entry of approvals) {
		if (!matchesSubject(entry, subject)) continue;
		const rejection = verifyMcpToolsetApproval(entry, params);
		if (rejection) {
			try {
				params.onIgnored?.(rejection, entry);
			} catch {
				/* A reporting sink cannot turn an ignored entry into an approval. */
			}
			continue;
		}
		honoured = true;
	}
	return honoured;
}

/** A gateway state directory that is not private to the serving user. */
export class McpStateDirectoryError extends Error {
	readonly code: string;
	constructor(code: string, message: string) {
		super(message);
		this.name = "McpStateDirectoryError";
		this.code = code;
	}
}

/**
 * Refuse a state directory that another local user could modify. The path
 * must be absolute (a relative path silently splits state between processes
 * started from different working directories); an existing directory must be
 * a directory owned by the current user with no group or world write bit.
 * A missing directory is created with mode 0700 when `create` is set.
 * Windows ACLs are not inspected here; the operator must restrict them.
 */
export async function assertPrivateMcpStateDirectory(
	path: string,
	options: { create?: boolean } = {},
): Promise<boolean> {
	if (typeof path !== "string" || !isAbsolute(path)) {
		throw new McpStateDirectoryError(
			"state_dir_not_absolute",
			"MCP attestation state directory must be an absolute path",
		);
	}
	let info: Awaited<ReturnType<typeof stat>>;
	try {
		info = await stat(path);
	} catch (error) {
		if (errorCode(error) !== "ENOENT") throw error;
		if (!options.create) return false;
		await mkdir(path, { recursive: true, mode: 0o700 });
		info = await stat(path);
	}
	if (!info.isDirectory()) {
		throw new McpStateDirectoryError(
			"state_dir_not_directory",
			`MCP attestation state path ${path} is not a directory`,
		);
	}
	if (process.platform !== "win32") {
		const uid = process.getuid?.();
		if (uid !== undefined && info.uid !== uid) {
			throw new McpStateDirectoryError(
				"state_dir_not_owned",
				`MCP attestation state directory ${path} is not owned by the current user (uid ${uid})`,
			);
		}
		if ((info.mode & 0o022) !== 0) {
			throw new McpStateDirectoryError(
				"state_dir_group_or_world_writable",
				`MCP attestation state directory ${path} is group- or world-writable; run chmod go-w on it`,
			);
		}
	}
	return true;
}

export interface McpAttestationStateStore {
	/** Execute one atomic read-modify-write operation for a server. */
	transact<T>(
		serverId: string,
		operation: (current: McpAttestationStateV1 | null) => {
			state: McpAttestationStateV1 | null;
			result: T;
		},
	): Promise<T>;
	/**
	 * Read persisted state without mutating it. Read-only surfaces such as
	 * discovery use this instead of a no-op `transact`: replay state (highest
	 * sequence and manifest hash) must never advance because a report was
	 * generated. Stores without it report approval state as unavailable rather
	 * than fabricating a verdict, so a missing reader can never look approved.
	 */
	read?(serverId: string): Promise<McpAttestationStateV1 | null>;
}

/** Useful for embedded runtimes and tests; use FileMcpAttestationStore across restarts. */
export class MemoryMcpAttestationStore implements McpAttestationStateStore {
	private readonly states = new Map<string, McpAttestationStateV1>();
	private queue: Promise<void> = Promise.resolve();

	async transact<T>(
		serverId: string,
		operation: (current: McpAttestationStateV1 | null) => {
			state: McpAttestationStateV1 | null;
			result: T;
		},
	): Promise<T> {
		let resolveResult: (value: T) => void = () => undefined;
		let rejectResult: (reason: unknown) => void = () => undefined;
		const resultPromise = new Promise<T>((resolve, reject) => {
			resolveResult = resolve;
			rejectResult = reject;
		});
		this.queue = this.queue.then(async () => {
			try {
				const current = this.states.get(serverId) ?? null;
				const outcome = operation(current ? structuredClone(current) : null);
				if (outcome.state) this.states.set(serverId, structuredClone(outcome.state));
				else this.states.delete(serverId);
				resolveResult(outcome.result);
			} catch (error) {
				rejectResult(error);
			}
		});
		await this.queue;
		return resultPromise;
	}

	/** Read-only accessor; it never advances replay state. */
	async read(serverId: string): Promise<McpAttestationStateV1 | null> {
		await this.queue;
		const current = this.states.get(serverId);
		return current ? structuredClone(current) : null;
	}
}

function errorCode(error: unknown): string | undefined {
	return typeof error === "object" && error !== null && "code" in error
		? String((error as { code?: unknown }).code)
		: undefined;
}

/** Persisted state whose integrity seal is missing or does not verify. */
export class McpAttestationStateIntegrityError extends Error {
	constructor(message = "MCP attestation state integrity check failed") {
		super(message);
		this.name = "McpAttestationStateIntegrityError";
	}
}

/**
 * Cross-process persistent store. Files are atomic and mutations are guarded by
 * an exclusive lock file. Corrupt state throws, causing callers to fail closed.
 * Existing locks are never reclaimed automatically; recovery requires an
 * operator to verify that no writer remains before removing the lock file.
 *
 * Each state file carries `stateMac`, an HMAC-SHA256 over the file name and the
 * complete state under a random per-directory key (`.state-integrity.key`,
 * mode 0600). A missing, stripped or mismatched seal throws, so an edited file
 * is refused rather than read. The seal key is readable by the account that
 * runs the store, so the seal detects edits by anything that does not hold
 * the key (other accounts, scripts that rewrite the JSON); it is not what
 * stops a same-user process. That is the job of the operator signature on each
 * approval entry, which the serving process cannot produce.
 *
 * The directory must be absolute, owned by the current user and not group or
 * world writable (see assertPrivateMcpStateDirectory); otherwise every read and
 * write throws.
 */
export class FileMcpAttestationStore implements McpAttestationStateStore {
	private integrityKey: Buffer | undefined;

	constructor(
		private readonly directory: string,
		private readonly options: {
			lockTimeoutMs?: number;
			/** @deprecated Stale locks require operator review; they are never auto-reclaimed. */
			staleLockMs?: number;
		} = {},
	) {}

	private statePath(serverId: string): string {
		const id = createHash("sha256").update(serverId, "utf8").digest("hex");
		return join(this.directory, `${id}.json`);
	}

	private async loadIntegrityKey(create: boolean): Promise<Buffer> {
		if (this.integrityKey) return this.integrityKey;
		const path = join(this.directory, STATE_INTEGRITY_KEY_FILE);
		let key: Buffer;
		try {
			key = await readFile(path);
		} catch (error) {
			if (errorCode(error) !== "ENOENT") throw error;
			if (!create)
				throw new McpAttestationStateIntegrityError("MCP attestation state seal key is missing");
			// Write the key under a private name, then hard-link it into place: the
			// link fails when another writer won the race, and no reader ever sees
			// a partially written key.
			const temporary = `${path}.${randomUUID()}.tmp`;
			const handle = await open(temporary, "wx", 0o600);
			try {
				await handle.writeFile(randomBytes(STATE_INTEGRITY_KEY_BYTES));
				await handle.sync();
			} finally {
				await handle.close();
			}
			try {
				await link(temporary, path);
			} catch (linkError) {
				if (errorCode(linkError) !== "EEXIST") throw linkError;
			} finally {
				await unlink(temporary).catch(() => undefined);
			}
			key = await readFile(path);
		}
		if (key.length !== STATE_INTEGRITY_KEY_BYTES) {
			throw new McpAttestationStateIntegrityError("MCP attestation state seal key is malformed");
		}
		this.integrityKey = key;
		return key;
	}

	private seal(key: Buffer, serverId: string, state: unknown): string {
		return createHmac("sha256", key)
			.update(STATE_MAC_DOMAIN)
			.update(basename(this.statePath(serverId)))
			.update("\0")
			.update(JSON.stringify(canonicalize(state as McpJsonValue)))
			.digest("hex");
	}

	private async acquireLock(path: string): Promise<() => Promise<void>> {
		const startedAt = Date.now();
		const timeout = this.options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
		for (;;) {
			try {
				const token = randomUUID();
				const handle = await open(path, "wx", 0o600);
				await handle.writeFile(JSON.stringify({ pid: process.pid, token }), "utf8");
				await handle.close();
				return async () => {
					try {
						const owner = JSON.parse(await readFile(path, "utf8")) as { token?: unknown };
						if (owner.token === token) await unlink(path);
					} catch (error) {
						if (errorCode(error) !== "ENOENT") throw error;
					}
				};
			} catch (error) {
				if (errorCode(error) !== "EEXIST") throw error;
				if (Date.now() - startedAt >= timeout) {
					throw new Error("timed out acquiring MCP attestation state lock");
				}
				await delay(20);
			}
		}
	}

	/**
	 * Read-only accessor. Corrupt, unsealed, tampered or mismatched state throws,
	 * so a read-only caller reports the state as unavailable instead of treating
	 * it as absent.
	 */
	async read(serverId: string): Promise<McpAttestationStateV1 | null> {
		if (!(await assertPrivateMcpStateDirectory(this.directory))) return null;
		let text: string;
		try {
			text = await getFileContent(this.statePath(serverId));
		} catch (error) {
			if (errorCode(error) === "ENOENT") return null;
			throw error;
		}
		const raw = JSON.parse(text) as unknown;
		if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
			throw new McpAttestationStateIntegrityError();
		}
		const { stateMac, ...body } = raw as Record<string, unknown>;
		if (typeof stateMac !== "string" || !SHA256_PATTERN.test(stateMac)) {
			throw new McpAttestationStateIntegrityError();
		}
		const expected = Buffer.from(
			this.seal(await this.loadIntegrityKey(false), serverId, body),
			"hex",
		);
		if (!timingSafeEqual(expected, Buffer.from(stateMac, "hex"))) {
			throw new McpAttestationStateIntegrityError();
		}
		const parsed = McpAttestationStateV1Schema.parse(body);
		if (parsed.serverId !== serverId) throw new Error("MCP attestation state server mismatch");
		return parsed;
	}

	async transact<T>(
		serverId: string,
		operation: (current: McpAttestationStateV1 | null) => {
			state: McpAttestationStateV1 | null;
			result: T;
		},
	): Promise<T> {
		if (!ID_PATTERN.test(serverId)) throw new Error("invalid MCP server id");
		await assertPrivateMcpStateDirectory(this.directory, { create: true });
		const release = await this.acquireLock(`${this.statePath(serverId)}.lock`);
		try {
			const current = await this.read(serverId);
			const outcome = operation(current);
			if (!outcome.state) {
				if (current) throw new Error("persistent MCP state cannot be deleted through transact");
				return outcome.result;
			}
			const state = McpAttestationStateV1Schema.parse(outcome.state);
			if (state.serverId !== serverId) throw new Error("MCP attestation state server mismatch");
			// Seal exactly the JSON that is written (undefined members dropped).
			const body = JSON.parse(JSON.stringify(state)) as Record<string, unknown>;
			const stateMac = this.seal(await this.loadIntegrityKey(true), serverId, body);
			await atomicWriteJson(this.statePath(serverId), { ...body, stateMac });
			return outcome.result;
		} finally {
			await release();
		}
	}
}

function toolMap(tools: McpToolDefinition[]): Map<string, string> {
	return new Map(
		tools.map((tool) => [
			tool.name,
			createHash("sha256")
				.update(JSON.stringify(canonicalize(tool as McpJsonValue)))
				.digest("hex"),
		]),
	);
}

export function diffMcpTools(
	activeTools: McpToolDefinition[],
	candidateTools: McpToolDefinition[],
): McpToolDrift {
	const active = toolMap(activeTools);
	const candidate = toolMap(candidateTools);
	const added = [...candidate.keys()].filter((name) => !active.has(name)).sort();
	const removed = [...active.keys()].filter((name) => !candidate.has(name)).sort();
	const changed = [...candidate.keys()]
		.filter((name) => active.has(name) && active.get(name) !== candidate.get(name))
		.sort();
	return { added, removed, changed };
}

export type McpAttestationDecision =
	| {
			status: "accepted" | "quarantined";
			manifestHash: string;
			toolsetHash: string;
			drift: McpToolDrift;
	  }
	| { status: "rejected"; reason: McpManifestRejectionReason };

/**
 * Verify and inspect one manifest. First-seen and changed toolsets are
 * quarantined until approveQuarantinedMcpToolset records an operator approval
 * signed by one of `approvalKeys`. Without `approvalKeys` no approval is ever
 * honoured, so every toolset stays quarantined.
 */
export async function attestMcpToolManifest(params: {
	candidate: unknown;
	verifier: McpManifestVerifierConfig;
	store: McpAttestationStateStore;
	/** Operator-controlled connection identity; omitted only for schema-only callers. */
	connection?: McpJsonValue;
	/** Operator approval public keys; the only keys whose approvals are honoured. */
	approvalKeys?: McpApprovalKeyring;
	/** Called for each matching approval entry that was ignored (never honoured). */
	onApprovalIgnored?: (reason: McpApprovalEntryRejection) => void;
}): Promise<McpAttestationDecision> {
	const verified = verifySignedMcpToolManifest(params.candidate, params.verifier);
	if (!verified.valid) return { status: "rejected", reason: verified.reason };
	const { signed, manifestHash, toolsetHash, signerKeySha256 } = verified;
	const { manifest } = signed;
	const bindingSha256 = mcpApprovalBindingHash({
		serverId: manifest.server_id,
		keyId: signed.key_id,
		signerKeySha256,
		connection: params.connection ?? null,
	});
	const detectedAt = (params.verifier.now ?? new Date()).toISOString();

	try {
		return await params.store.transact<McpAttestationDecision>(manifest.server_id, (current) => {
			if (current && manifest.sequence < current.highestSequence) {
				return {
					state: current,
					result: { status: "rejected", reason: "sequence_replay" } as const,
				};
			}
			if (
				current &&
				manifest.sequence === current.highestSequence &&
				manifestHash !== current.highestManifestHash
			) {
				return {
					state: current,
					result: { status: "rejected", reason: "sequence_conflict" } as const,
				};
			}

			const drift = diffMcpTools(current?.activeTools ?? [], manifest.tools);
			const approved =
				current !== null &&
				hasHonouredMcpApproval(
					current.approvedToolsets,
					{ toolsetHash, keyId: signed.key_id, signerKeySha256, bindingSha256 },
					{
						serverId: manifest.server_id,
						approvalKeys: params.approvalKeys,
						now: params.verifier.now,
						onIgnored: params.onApprovalIgnored,
					},
				);
			const base: McpAttestationStateV1 = current ?? {
				schemaVersion: 1,
				serverId: manifest.server_id,
				revision: 0,
				highestSequence: manifest.sequence,
				highestManifestHash: manifestHash,
				activeTools: [],
				approvedToolsets: [],
			};
			const next: McpAttestationStateV1 = {
				...base,
				revision: base.revision + 1,
				highestSequence: manifest.sequence,
				highestManifestHash: manifestHash,
			};

			if (approved) {
				next.activeToolsetHash = toolsetHash;
				next.activeTools = normalizedManifest(manifest).tools;
				delete next.quarantine;
				return {
					state: next,
					result: { status: "accepted", manifestHash, toolsetHash, drift } as const,
				};
			}

			next.quarantine = {
				manifestHash,
				toolsetHash,
				keyId: signed.key_id,
				signerKeySha256,
				bindingSha256,
				sequence: manifest.sequence,
				detectedAt,
				drift,
				tools: normalizedManifest(manifest).tools,
			};
			return {
				state: next,
				result: { status: "quarantined", manifestHash, toolsetHash, drift } as const,
			};
		});
	} catch {
		return { status: "rejected", reason: "state_unavailable" };
	}
}

function quarantineIsConsistent(
	quarantine: McpQuarantinedManifest,
	expected: { keyId: string; signerKeySha256: string } | undefined,
): boolean {
	if (
		expected &&
		(expected.keyId !== quarantine.keyId || expected.signerKeySha256 !== quarantine.signerKeySha256)
	) {
		return false;
	}
	try {
		return mcpToolsetHash(quarantine.tools) === quarantine.toolsetHash;
	} catch {
		return false;
	}
}

export type McpApprovalResult =
	| { approved: true; toolsetHash: string }
	| {
			approved: false;
			reason:
				| "no_quarantine"
				| "toolset_mismatch"
				| "binding_mismatch"
				| "signer_unverified"
				| "quarantine_mismatch"
				| "approval_key_untrusted";
	  };

/**
 * Out-of-band operator action; never expose this operation as an agent-callable
 * MCP tool. The approval is signed with the operator approval key, so the
 * serving process (and anything else that can only write the state directory)
 * cannot create one. Pass `approvalKeys` to refuse a key the verifier would not
 * honour, and `expected` (derived from the operator configuration, not from the
 * state file) so a tampered quarantine record cannot redirect the signature.
 */
export async function approveQuarantinedMcpToolset(params: {
	serverId: string;
	toolsetHash: string;
	bindingSha256: string;
	approvedBy: string;
	reason: string;
	store: McpAttestationStateStore;
	approvalKey: { keyId: string; privateKey: string | Buffer | KeyObject };
	approvalKeys?: McpApprovalKeyring;
	expected?: { keyId: string; signerKeySha256: string };
	now?: Date;
	/** Defaults to `now` plus DEFAULT_MCP_APPROVAL_LIFETIME_MS. */
	expiresAt?: Date;
}): Promise<McpApprovalResult> {
	if (!SHA256_PATTERN.test(params.toolsetHash)) throw new Error("invalid MCP toolset hash");
	if (!SHA256_PATTERN.test(params.bindingSha256))
		throw new Error("invalid MCP approval binding hash");
	const approvedBy = params.approvedBy.trim();
	const reason = params.reason.trim();
	if (!approvedBy || approvedBy.length > 256) throw new Error("invalid MCP approval actor");
	if (!reason || reason.length > 2048) throw new Error("invalid MCP approval reason");
	if (!params.approvalKey) throw new Error("MCP approval requires the operator approval key");
	const now = params.now ?? new Date();
	const expiresAt = params.expiresAt ?? new Date(now.getTime() + DEFAULT_MCP_APPROVAL_LIFETIME_MS);

	return params.store.transact<McpApprovalResult>(params.serverId, (current) => {
		if (!current?.quarantine) {
			return { state: current, result: { approved: false, reason: "no_quarantine" } as const };
		}
		const quarantine = current.quarantine;
		if (quarantine.toolsetHash !== params.toolsetHash) {
			return {
				state: current,
				result: { approved: false, reason: "toolset_mismatch" } as const,
			};
		}
		if (quarantine.bindingSha256 !== params.bindingSha256) {
			return { state: current, result: { approved: false, reason: "binding_mismatch" } as const };
		}
		if (!quarantine.signerKeySha256 || !quarantine.bindingSha256) {
			return { state: current, result: { approved: false, reason: "signer_unverified" } as const };
		}
		// The state file is not trusted: the tools that become active must hash to
		// the approved toolset, and the signer must be the configured one.
		if (!quarantineIsConsistent(quarantine, params.expected)) {
			return {
				state: current,
				result: { approved: false, reason: "quarantine_mismatch" } as const,
			};
		}

		const approval = signMcpToolsetApproval({
			serverId: params.serverId,
			toolsetHash: params.toolsetHash,
			keyId: quarantine.keyId,
			signerKeySha256: quarantine.signerKeySha256,
			bindingSha256: quarantine.bindingSha256,
			approvedBy,
			reason,
			approvedAt: now,
			expiresAt,
			approvalKeyId: params.approvalKey.keyId,
			privateKey: params.approvalKey.privateKey,
		});
		if (
			params.approvalKeys &&
			verifyMcpToolsetApproval(approval, {
				serverId: params.serverId,
				approvalKeys: params.approvalKeys,
				now,
			})
		) {
			return {
				state: current,
				result: { approved: false, reason: "approval_key_untrusted" } as const,
			};
		}
		// Unsigned (legacy or forged) entries are dropped; they are never honoured.
		const approvals = current.approvedToolsets.filter(
			(entry) =>
				entry.signatureB64 !== undefined &&
				(entry.toolsetHash !== approval.toolsetHash ||
					entry.keyId !== approval.keyId ||
					entry.signerKeySha256 !== approval.signerKeySha256 ||
					entry.bindingSha256 !== approval.bindingSha256),
		);
		approvals.push(approval);
		const next: McpAttestationStateV1 = {
			...current,
			revision: current.revision + 1,
			activeToolsetHash: params.toolsetHash,
			activeTools: quarantine.tools,
			approvedToolsets: approvals.slice(-MAX_APPROVED_TOOLSETS),
		};
		delete next.quarantine;
		return {
			state: next,
			result: { approved: true, toolsetHash: params.toolsetHash } as const,
		};
	});
}
