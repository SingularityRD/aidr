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
	createPrivateKey,
	createPublicKey,
	sign as cryptoSign,
	verify as cryptoVerify,
	KeyObject,
} from "node:crypto";
import { mkdir, open, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { atomicWriteJson, getFileContent } from "./file-utils.js";

const SIGNING_DOMAIN = "AIDR-MCP-TOOL-MANIFEST-V1\n";
const DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_MAX_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_LOCK_TIMEOUT_MS = 5_000;
const DEFAULT_STALE_LOCK_MS = 30_000;
const MAX_APPROVED_TOOLSETS = 256;

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const TOOL_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
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
	await atomicWriteJson(params.path, evidence);
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
	};
}

export interface McpToolDrift {
	added: string[];
	removed: string[];
	changed: string[];
}

export interface McpToolsetApproval {
	toolsetHash: string;
	approvedAt: string;
	approvedBy: string;
	reason: string;
}

export interface McpQuarantinedManifest {
	manifestHash: string;
	toolsetHash: string;
	keyId: string;
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
				approvedAt: z.string().datetime({ offset: true }),
				approvedBy: z.string().min(1).max(256),
				reason: z.string().min(1).max(2048),
			}),
		)
		.max(MAX_APPROVED_TOOLSETS),
	quarantine: z
		.object({
			manifestHash: z.string().regex(SHA256_PATTERN),
			toolsetHash: z.string().regex(SHA256_PATTERN),
			keyId: z.string().regex(ID_PATTERN),
			sequence: z.number().int().nonnegative().safe(),
			detectedAt: z.string().datetime({ offset: true }),
			drift: McpToolDriftSchema,
			tools: z.array(McpToolDefinitionSchema).max(4096),
		})
		.optional(),
});

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

async function removeStaleLock(path: string, staleAfter: number): Promise<void> {
	try {
		const info = await stat(path);
		if (Date.now() - info.mtimeMs > staleAfter) await unlink(path);
	} catch (error) {
		if (errorCode(error) !== "ENOENT") throw error;
	}
}

/**
 * Cross-process persistent store. Files are atomic and mutations are guarded by
 * an exclusive lock file. Corrupt state throws, causing callers to fail closed.
 */
export class FileMcpAttestationStore implements McpAttestationStateStore {
	constructor(
		private readonly directory: string,
		private readonly options: { lockTimeoutMs?: number; staleLockMs?: number } = {},
	) {}

	private statePath(serverId: string): string {
		const id = createHash("sha256").update(serverId, "utf8").digest("hex");
		return join(this.directory, `${id}.json`);
	}

	private async acquireLock(path: string): Promise<() => Promise<void>> {
		const startedAt = Date.now();
		const timeout = this.options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
		const staleAfter = this.options.staleLockMs ?? DEFAULT_STALE_LOCK_MS;
		for (;;) {
			try {
				const handle = await open(path, "wx", 0o600);
				await handle.writeFile(`${process.pid}\n`, "utf8");
				await handle.close();
				return async () => {
					try {
						await unlink(path);
					} catch (error) {
						if (errorCode(error) !== "ENOENT") throw error;
					}
				};
			} catch (error) {
				if (errorCode(error) !== "EEXIST") throw error;
				await removeStaleLock(path, staleAfter);
				if (Date.now() - startedAt >= timeout) {
					throw new Error("timed out acquiring MCP attestation state lock");
				}
				await delay(20);
			}
		}
	}

	/**
	 * Read-only accessor. Corrupt or mismatched state throws, so a read-only
	 * caller reports the state as unavailable instead of treating it as absent.
	 */
	async read(serverId: string): Promise<McpAttestationStateV1 | null> {
		try {
			const parsed = McpAttestationStateV1Schema.parse(
				JSON.parse(await getFileContent(this.statePath(serverId))),
			);
			if (parsed.serverId !== serverId) throw new Error("MCP attestation state server mismatch");
			return parsed;
		} catch (error) {
			if (errorCode(error) === "ENOENT") return null;
			throw error;
		}
	}

	async transact<T>(
		serverId: string,
		operation: (current: McpAttestationStateV1 | null) => {
			state: McpAttestationStateV1 | null;
			result: T;
		},
	): Promise<T> {
		if (!ID_PATTERN.test(serverId)) throw new Error("invalid MCP server id");
		await mkdir(this.directory, { recursive: true, mode: 0o700 });
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
			await atomicWriteJson(this.statePath(serverId), state);
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
 * quarantined until approveQuarantinedMcpToolset records operator approval.
 */
export async function attestMcpToolManifest(params: {
	candidate: unknown;
	verifier: McpManifestVerifierConfig;
	store: McpAttestationStateStore;
}): Promise<McpAttestationDecision> {
	const verified = verifySignedMcpToolManifest(params.candidate, params.verifier);
	if (!verified.valid) return { status: "rejected", reason: verified.reason };
	const { signed, manifestHash, toolsetHash } = verified;
	const { manifest } = signed;
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
			const approved = current?.approvedToolsets.some((entry) => entry.toolsetHash === toolsetHash);
			const alreadyActive = current?.activeToolsetHash === toolsetHash;
			const shouldAccept = approved || alreadyActive;
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

			if (shouldAccept) {
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

export type McpApprovalResult =
	| { approved: true; toolsetHash: string }
	| { approved: false; reason: "no_quarantine" | "toolset_mismatch" };

/** Out-of-band operator action; never expose this operation as an agent-callable MCP tool. */
export async function approveQuarantinedMcpToolset(params: {
	serverId: string;
	toolsetHash: string;
	approvedBy: string;
	reason: string;
	store: McpAttestationStateStore;
	now?: Date;
}): Promise<McpApprovalResult> {
	if (!SHA256_PATTERN.test(params.toolsetHash)) throw new Error("invalid MCP toolset hash");
	const approvedBy = params.approvedBy.trim();
	const reason = params.reason.trim();
	if (!approvedBy || approvedBy.length > 256) throw new Error("invalid MCP approval actor");
	if (!reason || reason.length > 2048) throw new Error("invalid MCP approval reason");

	return params.store.transact<McpApprovalResult>(params.serverId, (current) => {
		if (!current?.quarantine) {
			return { state: current, result: { approved: false, reason: "no_quarantine" } as const };
		}
		if (current.quarantine.toolsetHash !== params.toolsetHash) {
			return {
				state: current,
				result: { approved: false, reason: "toolset_mismatch" } as const,
			};
		}

		const approval: McpToolsetApproval = {
			toolsetHash: params.toolsetHash,
			approvedAt: (params.now ?? new Date()).toISOString(),
			approvedBy,
			reason,
		};
		const approvals = current.approvedToolsets.filter(
			(entry) => entry.toolsetHash !== params.toolsetHash,
		);
		approvals.push(approval);
		const next: McpAttestationStateV1 = {
			...current,
			revision: current.revision + 1,
			activeToolsetHash: params.toolsetHash,
			activeTools: current.quarantine.tools,
			approvedToolsets: approvals.slice(-MAX_APPROVED_TOOLSETS),
		};
		delete next.quarantine;
		return {
			state: next,
			result: { approved: true, toolsetHash: params.toolsetHash } as const,
		};
	});
}
