/**
 * File-backed, operator-only approval channel for `ask` verdicts.
 *
 * ## Why this exists
 *
 * An `ask` verdict is a block pending out-of-band human approval. Connectors that
 * cannot open a host-native confirmation dialog (OpenClaw, OpenCode, Codex) used
 * to keep approvals in an in-memory `ApprovalStore` with no caller able to fill
 * it, so an `ask` could never be approved at all. This module is the persistent
 * channel between the connector (which records the pending ask) and the operator
 * CLI (`aidr pending`, `aidr approve <actionId>`), which records the approval
 * WITHOUT the agent being involved.
 *
 * ## Flow
 *
 * 1. At ask time the connector calls {@link recordPendingAsk}. The record binds the
 *    `actionId` (a digest of tool, input and session) to a digest of the exact
 *    artifacts and the tool name, plus a redacted summary for the operator.
 * 2. The operator runs `aidr approve <actionId>`. The CLI reads the pending record,
 *    shows it, asks for interactive confirmation and calls
 *    {@link recordOperatorApproval}.
 * 3. When the agent retries the same call, the connector calls
 *    {@link consumeOperatorApproval}. It succeeds only for an unexpired, untampered
 *    approval whose action id, tool and artifact digest all match — and, by
 *    default, only once.
 *
 * ## Integrity and the honest residual risk
 *
 * Every record carries an HMAC-SHA256 under a per-install key kept in the OS
 * credential vault when one is available (see `secret-store.ts`), else in an
 * owner-only key file. A record edited by hand — a later expiry, a different
 * digest, a reset use counter — fails verification and is rejected.
 *
 * This is NOT a boundary against code that runs as the same OS user with full
 * shell access: such code can read the vault entry or key file and mint a valid
 * record, or run `aidr approve` inside a pseudo-terminal. The HMAC, the TTY
 * requirement in the CLI, and the self-defense threat rules that block an agent
 * from touching these files or invoking `aidr approve` raise the bar; they do not
 * make the channel agent-proof. See `docs/configuration.md`.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { closeSync, lstatSync, mkdirSync, openSync, renameSync, writeSync } from "node:fs";
import { lstat, mkdir, open, stat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";
import { toolInputSummaryForAudit } from "./audit-log.js";
import { AIDR_DIR, resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent, getFileContentSync } from "./file-utils.js";
import {
	resolveSecretStore,
	SECRET_STORE_ENV,
	type SecretStore,
	type SecretStoreKind,
} from "./secret-store.js";
import { redactTelemetryString } from "./telemetry-redaction.js";
import type { Artifact, Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** Default lifetime of an operator approval. */
export const OPERATOR_APPROVAL_DEFAULT_TTL_MS = 15 * 60 * 1000;
/** Longest lifetime an operator may grant. */
export const OPERATOR_APPROVAL_MAX_TTL_MS = 24 * 60 * 60 * 1000;
/** Shortest lifetime an operator may grant. */
export const OPERATOR_APPROVAL_MIN_TTL_MS = 60 * 1000;
/** How long an unanswered ask stays approvable. */
export const PENDING_ASK_TTL_MS = 60 * 60 * 1000;

const STORE_VERSION = 1;
const MAX_PENDING = 200;
const MAX_APPROVALS = 200;
const MAX_ARTIFACTS_PER_RECORD = 16;
const MAX_STORE_BYTES = 1024 * 1024;
const LOCK_TIMEOUT_MS = 5_000;
const LOCK_STALE_MS = 15_000;
const KEY_CACHE_MS = 5 * 60 * 1000;
const MAC_DOMAIN = "singularity-aidr/operator-approval/v1";
const ACTION_ID = /^[a-f0-9]{64}$/;
const DIGEST = /^[a-f0-9]{64}$/;

/** Vault account/id under which the per-install approval key is stored. */
export const OPERATOR_APPROVAL_KEY_ID = "aidr-operator-approval-key";
const KEY_FILE = "operator-approval.key";
const KEY_META_FILE = "operator-approval-key.json";

// ── Errors ─────────────────────────────────────────────────────────

export type OperatorApprovalErrorCode =
	| "invalid_action_id"
	| "not_pending"
	| "pending_expired"
	| "tampered"
	| "key_unavailable"
	| "lock_timeout"
	| "unsafe_store"
	| "invalid_ttl";

export class OperatorApprovalError extends Error {
	constructor(
		readonly code: OperatorApprovalErrorCode,
		message: string,
	) {
		super(message);
		this.name = "OperatorApprovalError";
	}
}

// ── Public shapes ─────────────────────────────────────────────────

export interface PendingAskArtifact {
	type: string;
	/** sha256 of `${type}\n${value}`; the raw value is never stored. */
	digest: string;
	/** Redacted, truncated preview for the operator. */
	preview: string;
}

export interface PendingAsk {
	actionId: string;
	artifactDigest: string;
	tool: string;
	connector: string;
	/** Truncated digest of the session id, for correlation only. */
	sessionDigest: string;
	summary: string;
	artifacts: PendingAskArtifact[];
	severity: string;
	category: string;
	reasons: string[];
	threatId: string | null;
	createdAt: string;
	expiresAt: string;
}

export interface OperatorApproval {
	actionId: string;
	artifactDigest: string;
	tool: string;
	artifactDigests: string[];
	approvedAt: string;
	expiresAt: string;
	singleUse: boolean;
	approver: string;
	/** Whether the agent may turn this approval into a permanent allowlist entry. */
	permitAllowlist: boolean;
	uses: number;
	consumedAt: string | null;
	/** Artifact digests already converted into allowlist entries. */
	allowlisted: string[];
}

export type OperatorConsumeReason =
	| "approved"
	| "not_found"
	| "expired"
	| "tampered"
	| "digest_mismatch"
	| "tool_mismatch"
	| "already_used"
	| "key_unavailable"
	| "unavailable";

export interface OperatorConsumeResult {
	approved: boolean;
	reason: OperatorConsumeReason;
	approval?: OperatorApproval;
}

export interface OperatorKeyMaterial {
	key: Buffer;
	location: "os-vault" | "file";
	store: SecretStoreKind | "file";
}

/** Supplies the per-install HMAC key. `create` is false for read-only callers. */
export interface OperatorKeyProvider {
	load(options: { create: boolean }): OperatorKeyMaterial | null;
}

export interface OperatorApprovalStoreOptions {
	/** Store file; defaults to `~/.singularity-aidr/approvals.json`. */
	path?: string;
	keyProvider?: OperatorKeyProvider;
	now?: () => number;
	logger?: Logger;
}

// ── On-disk shapes (snake_case) ─────────────────────────────────────

const PendingDiskSchema = z.object({
	action_id: z.string().regex(ACTION_ID),
	artifact_digest: z.string().regex(DIGEST),
	tool: z.string().max(200),
	connector: z.string().max(64),
	session_digest: z.string().max(64),
	summary: z.string().max(400),
	artifacts: z
		.array(
			z.object({
				type: z.string().max(32),
				digest: z.string().regex(DIGEST),
				preview: z.string().max(400),
			}),
		)
		.max(MAX_ARTIFACTS_PER_RECORD),
	severity: z.string().max(32),
	category: z.string().max(100),
	reasons: z.array(z.string().max(400)).max(5),
	threat_id: z.string().max(100).nullable(),
	created_at: z.string(),
	expires_at: z.string(),
	mac: z.string().regex(DIGEST),
});

const ApprovalDiskSchema = z.object({
	action_id: z.string().regex(ACTION_ID),
	artifact_digest: z.string().regex(DIGEST),
	tool: z.string().max(200),
	artifact_digests: z.array(z.string().regex(DIGEST)).max(MAX_ARTIFACTS_PER_RECORD),
	approved_at: z.string(),
	expires_at: z.string(),
	single_use: z.boolean(),
	approver: z.string().max(200),
	permit_allowlist: z.boolean(),
	uses: z.number().int().min(0),
	consumed_at: z.string().nullable(),
	allowlisted: z.array(z.string().regex(DIGEST)).max(MAX_ARTIFACTS_PER_RECORD),
	mac: z.string().regex(DIGEST),
});

type PendingDisk = z.infer<typeof PendingDiskSchema>;
type ApprovalDisk = z.infer<typeof ApprovalDiskSchema>;

interface StoreDocument {
	version: number;
	pending: PendingDisk[];
	approvals: ApprovalDisk[];
}

function pendingFromDisk(record: PendingDisk): PendingAsk {
	return {
		actionId: record.action_id,
		artifactDigest: record.artifact_digest,
		tool: record.tool,
		connector: record.connector,
		sessionDigest: record.session_digest,
		summary: record.summary,
		artifacts: record.artifacts.map((a) => ({ ...a })),
		severity: record.severity,
		category: record.category,
		reasons: [...record.reasons],
		threatId: record.threat_id,
		createdAt: record.created_at,
		expiresAt: record.expires_at,
	};
}

function approvalFromDisk(record: ApprovalDisk): OperatorApproval {
	return {
		actionId: record.action_id,
		artifactDigest: record.artifact_digest,
		tool: record.tool,
		artifactDigests: [...record.artifact_digests],
		approvedAt: record.approved_at,
		expiresAt: record.expires_at,
		singleUse: record.single_use,
		approver: record.approver,
		permitAllowlist: record.permit_allowlist,
		uses: record.uses,
		consumedAt: record.consumed_at,
		allowlisted: [...record.allowlisted],
	};
}

// ── Digests and MAC ─────────────────────────────────────────────────

function sha256(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

/** Digest of one artifact; the connector and the allowlist tool agree on this. */
export function artifactValueDigest(type: string, value: string): string {
	return sha256(`${type}\n${value}`);
}

/** Order-independent digest of the exact artifact set of a tool call. */
export function artifactSetDigest(artifacts: readonly Pick<Artifact, "type" | "value">[]): string {
	const parts = artifacts.map((a) => artifactValueDigest(a.type, a.value)).sort();
	return sha256(`aidr-artifact-set\n${parts.join("\n")}`);
}

function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	const entries = Object.entries(value as Record<string, unknown>)
		.filter(([, v]) => v !== undefined)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

function computeMac(key: Buffer, kind: "pending" | "approval", record: object): string {
	const { mac: _ignored, ...body } = record as Record<string, unknown>;
	return createHmac("sha256", key)
		.update(`${MAC_DOMAIN}\n${kind}\n${canonicalJson(body)}`)
		.digest("hex");
}

function macMatches(key: Buffer, kind: "pending" | "approval", record: { mac: string }): boolean {
	const expected = Buffer.from(computeMac(key, kind, record), "hex");
	const actual = Buffer.from(record.mac, "hex");
	return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// ── Key provider ─────────────────────────────────────────────────────

const KeyMetaSchema = z.object({
	version: z.literal(1),
	store: z.string(),
});

interface DefaultKeyProviderOptions {
	directory?: string;
	env?: NodeJS.ProcessEnv;
	/** Vault resolver; injectable so tests never touch a real OS vault. */
	resolveVault?: (selection?: string) => SecretStore;
}

function writePrivateFileExclusive(path: string, content: string): void {
	const handle = openSync(path, "wx", 0o600);
	try {
		writeSync(handle, content);
	} finally {
		closeSync(handle);
	}
}

function assertRegularFile(path: string): boolean {
	try {
		const info = lstatSync(path);
		if (info.isSymbolicLink() || !info.isFile()) {
			throw new OperatorApprovalError("unsafe_store", `${path} is not a regular file`);
		}
		return true;
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw error;
	}
}

/**
 * The default key provider: the OS vault when one is available, else an
 * owner-only key file. The choice is recorded next to the store so the CLI and
 * every connector process use the same key.
 */
export function createDefaultOperatorKeyProvider(
	options: DefaultKeyProviderOptions = {},
): OperatorKeyProvider {
	const env = options.env ?? process.env;
	const resolveVault =
		options.resolveVault ?? ((selection?: string) => resolveSecretStore({ selection, env }));
	const directory = () => options.directory ?? resolvePath(AIDR_DIR);

	const readKeyFile = (dir: string): OperatorKeyMaterial | null => {
		const path = join(dir, KEY_FILE);
		if (!assertRegularFile(path)) return null;
		const hex = getFileContentSync(path).trim();
		if (!/^[a-f0-9]{64}$/.test(hex)) return null;
		return { key: Buffer.from(hex, "hex"), location: "file", store: "file" };
	};

	const createKeyFile = (dir: string, hex: string): OperatorKeyMaterial => {
		const path = join(dir, KEY_FILE);
		if (assertRegularFile(path)) {
			// A key file without metadata (or with unreadable content) is replaced,
			// which invalidates every record signed with the previous key.
			const existing = readKeyFile(dir);
			if (existing) return existing;
			throw new OperatorApprovalError(
				"key_unavailable",
				`${path} exists but does not hold a valid approval key; remove it to regenerate.`,
			);
		}
		writePrivateFileExclusive(path, `${hex}\n`);
		return { key: Buffer.from(hex, "hex"), location: "file", store: "file" };
	};

	const writeMeta = (dir: string, store: string) => {
		const path = join(dir, KEY_META_FILE);
		const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
		writePrivateFileExclusive(tmp, `${JSON.stringify({ version: 1, store })}\n`);
		// Synchronous rename keeps the provider synchronous like the vault backends.
		renameSync(tmp, path);
	};

	return {
		load({ create }) {
			const dir = directory();
			mkdirSync(dir, { recursive: true, mode: 0o700 });
			const metaPath = join(dir, KEY_META_FILE);
			let meta: z.infer<typeof KeyMetaSchema> | null = null;
			if (assertRegularFile(metaPath)) {
				try {
					meta = KeyMetaSchema.parse(JSON.parse(getFileContentSync(metaPath)));
				} catch {
					meta = null;
				}
			}

			if (meta) {
				if (meta.store === "file") {
					const material = readKeyFile(dir);
					if (material || !create) return material;
				} else {
					try {
						const vault = resolveVault(meta.store);
						const hex = vault.get(OPERATOR_APPROVAL_KEY_ID);
						if (hex && /^[a-f0-9]{64}$/.test(hex)) {
							return { key: Buffer.from(hex, "hex"), location: "os-vault", store: vault.kind };
						}
					} catch {
						// The recorded vault is gone; records signed with it cannot verify.
					}
					if (!create) return null;
				}
			} else if (!create) {
				return null;
			}

			const hex = randomBytes(32).toString("hex");
			const selection = (env[SECRET_STORE_ENV] ?? "").trim().toLowerCase();
			if (selection !== "file-acl") {
				try {
					const vault = resolveVault();
					if (vault.osProtected) {
						vault.put(OPERATOR_APPROVAL_KEY_ID, hex);
						writeMeta(dir, vault.kind);
						return { key: Buffer.from(hex, "hex"), location: "os-vault", store: vault.kind };
					}
				} catch {
					// No usable vault: fall back to the owner-only key file below.
				}
			}
			const material = createKeyFile(dir, hex);
			writeMeta(dir, "file");
			return material;
		},
	};
}

const keyCache = new Map<OperatorKeyProvider, { material: OperatorKeyMaterial; at: number }>();
let defaultProvider: OperatorKeyProvider | null = null;

function providerFor(options: OperatorApprovalStoreOptions): OperatorKeyProvider {
	if (options.keyProvider) return options.keyProvider;
	defaultProvider ??= createDefaultOperatorKeyProvider();
	return defaultProvider;
}

function loadKey(
	options: OperatorApprovalStoreOptions,
	create: boolean,
): OperatorKeyMaterial | null {
	const provider = providerFor(options);
	const cached = keyCache.get(provider);
	if (cached && Date.now() - cached.at < KEY_CACHE_MS) return cached.material;
	let material: OperatorKeyMaterial | null;
	try {
		material = provider.load({ create });
	} catch (error) {
		(options.logger ?? nullLogger).warn("Operator approval key unavailable", {
			error: String(error),
		});
		return null;
	}
	if (material) keyCache.set(provider, { material, at: Date.now() });
	return material;
}

/** Forget cached key material (tests, key rotation). */
export function clearOperatorApprovalKeyCache(): void {
	keyCache.clear();
	defaultProvider = null;
}

/** Where the key currently lives, for `aidr doctor`; never returns the key. */
export function describeOperatorApprovalKey(options: OperatorApprovalStoreOptions = {}): {
	present: boolean;
	location?: "os-vault" | "file";
	store?: string;
} {
	const material = loadKey(options, false);
	if (!material) return { present: false };
	return { present: true, location: material.location, store: material.store };
}

// ── Store I/O ────────────────────────────────────────────────────────

export function operatorApprovalStorePath(options: OperatorApprovalStoreOptions = {}): string {
	return options.path ?? join(resolvePath(AIDR_DIR), "approvals.json");
}

function nowMs(options: OperatorApprovalStoreOptions): number {
	return options.now ? options.now() : Date.now();
}

function emptyDocument(): StoreDocument {
	return { version: STORE_VERSION, pending: [], approvals: [] };
}

async function readDocument(path: string): Promise<StoreDocument> {
	let info: Awaited<ReturnType<typeof lstat>>;
	try {
		info = await lstat(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return emptyDocument();
		throw error;
	}
	if (info.isSymbolicLink() || !info.isFile()) {
		throw new OperatorApprovalError("unsafe_store", "The approval store is not a regular file.");
	}
	// An oversized or unparsable store holds nothing that can verify, so it reads
	// as empty (no approval) and is replaced on the next write.
	if (info.size > MAX_STORE_BYTES) return emptyDocument();
	let raw: unknown;
	try {
		raw = JSON.parse(await getFileContent(path));
	} catch {
		return emptyDocument();
	}
	if (typeof raw !== "object" || raw === null) return emptyDocument();
	const record = raw as Record<string, unknown>;
	const doc = emptyDocument();
	for (const entry of Array.isArray(record.pending) ? record.pending : []) {
		const parsed = PendingDiskSchema.safeParse(entry);
		if (parsed.success) doc.pending.push(parsed.data);
	}
	for (const entry of Array.isArray(record.approvals) ? record.approvals : []) {
		const parsed = ApprovalDiskSchema.safeParse(entry);
		if (parsed.success) doc.approvals.push(parsed.data);
	}
	return doc;
}

function pruneDocument(doc: StoreDocument, now: number): StoreDocument {
	const alive = <T extends { expires_at: string }>(r: T) => Date.parse(r.expires_at) > now;
	const newestFirst =
		<T>(key: (r: T) => string) =>
		(a: T, b: T) =>
			Date.parse(key(b)) - Date.parse(key(a));
	return {
		version: STORE_VERSION,
		pending: doc.pending
			.filter(alive)
			.sort(newestFirst<PendingDisk>((r) => r.created_at))
			.slice(0, MAX_PENDING),
		approvals: doc.approvals
			.filter(alive)
			.sort(newestFirst<ApprovalDisk>((r) => r.approved_at))
			.slice(0, MAX_APPROVALS),
	};
}

async function writeDocument(path: string, doc: StoreDocument, now: number): Promise<void> {
	await atomicWriteJson(path, pruneDocument(doc, now), { mode: 0o600 });
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Cross-process mutual exclusion around a read-modify-write of the store.
 *
 * An `O_EXCL` lock file works across the CLI and every connector process. A lock
 * older than {@link LOCK_STALE_MS} is treated as left behind by a crashed writer.
 */
async function withStoreLock<T>(path: string, fn: () => Promise<T>): Promise<T> {
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	const lockPath = `${path}.lock`;
	const deadline = Date.now() + LOCK_TIMEOUT_MS;
	for (;;) {
		try {
			const handle = await open(lockPath, "wx", 0o600);
			try {
				await handle.writeFile(`${process.pid}\n`, "utf8");
			} finally {
				await handle.close();
			}
			break;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			try {
				const info = await stat(lockPath);
				if (Date.now() - info.mtimeMs > LOCK_STALE_MS) {
					await unlink(lockPath).catch(() => undefined);
					continue;
				}
			} catch {
				continue;
			}
			if (Date.now() > deadline) {
				throw new OperatorApprovalError(
					"lock_timeout",
					"Timed out waiting for the approval store lock.",
				);
			}
			await sleep(5 + Math.floor(Math.random() * 20));
		}
	}
	try {
		return await fn();
	} finally {
		await unlink(lockPath).catch(() => undefined);
	}
}

function assertActionId(actionId: string): void {
	if (!ACTION_ID.test(actionId)) {
		throw new OperatorApprovalError(
			"invalid_action_id",
			"An approval reference is a 64-character lowercase hex actionId.",
		);
	}
}

// ── Pending asks (connector side) ─────────────────────────────────────

export interface RecordPendingAskInput {
	actionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	artifacts: readonly Artifact[];
	sessionId: string;
	verdict: Pick<Verdict, "severity" | "category" | "reasons" | "matchedThreatId">;
	connector?: string;
}

/**
 * Record an `ask` so an operator can approve it by id. Called by the connector at
 * block time; the stored summary is redacted and raw artifact values are kept
 * only as digests plus a redacted preview.
 */
export async function recordPendingAsk(
	input: RecordPendingAskInput,
	options: OperatorApprovalStoreOptions = {},
): Promise<PendingAsk> {
	assertActionId(input.actionId);
	const path = operatorApprovalStorePath(options);
	return withStoreLock(path, async () => {
		const key = loadKey(options, true);
		if (!key) {
			throw new OperatorApprovalError(
				"key_unavailable",
				"No operator approval key could be loaded or created.",
			);
		}
		const now = nowMs(options);
		const artifacts = input.artifacts.slice(0, MAX_ARTIFACTS_PER_RECORD);
		const unsigned: Omit<PendingDisk, "mac"> = {
			action_id: input.actionId,
			artifact_digest: artifactSetDigest(input.artifacts),
			tool: input.toolName.slice(0, 200),
			connector: (input.connector ?? "unknown").slice(0, 64),
			session_digest: sha256(input.sessionId).slice(0, 16),
			summary: redactTelemetryString(
				toolInputSummaryForAudit(input.toolName, input.toolInput),
				400,
			),
			artifacts: artifacts.map((a) => ({
				type: String(a.type).slice(0, 32),
				digest: artifactValueDigest(a.type, a.value),
				preview: redactTelemetryString(a.value.replaceAll("\n", "\\n"), 160),
			})),
			severity: String(input.verdict.severity).slice(0, 32),
			category: String(input.verdict.category).slice(0, 100),
			reasons: input.verdict.reasons.slice(0, 3).map((r) => redactTelemetryString(r, 300)),
			threat_id: input.verdict.matchedThreatId ? input.verdict.matchedThreatId.slice(0, 100) : null,
			created_at: new Date(now).toISOString(),
			expires_at: new Date(now + PENDING_ASK_TTL_MS).toISOString(),
		};
		const record: PendingDisk = { ...unsigned, mac: computeMac(key.key, "pending", unsigned) };
		const doc = await readDocument(path);
		doc.pending = doc.pending.filter((p) => p.action_id !== input.actionId);
		doc.pending.push(record);
		await writeDocument(path, doc, now);
		return pendingFromDisk(record);
	});
}

export interface ListedPendingAsk extends PendingAsk {
	/** False when the record's HMAC does not verify (edited, or key changed). */
	verified: boolean;
}

/** Unexpired pending asks, newest first. */
export async function listPendingAsks(
	options: OperatorApprovalStoreOptions = {},
): Promise<ListedPendingAsk[]> {
	const doc = await readDocument(operatorApprovalStorePath(options));
	const now = nowMs(options);
	const key = doc.pending.length > 0 ? loadKey(options, false) : null;
	return doc.pending
		.filter((p) => Date.parse(p.expires_at) > now)
		.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
		.map((p) => ({ ...pendingFromDisk(p), verified: !!key && macMatches(key.key, "pending", p) }));
}

/** One pending ask by id, or null. */
export async function getPendingAsk(
	actionId: string,
	options: OperatorApprovalStoreOptions = {},
): Promise<ListedPendingAsk | null> {
	assertActionId(actionId);
	const all = await listPendingAsks(options);
	return all.find((p) => p.actionId === actionId) ?? null;
}

// ── Approvals (operator side) ─────────────────────────────────────────

export interface RecordOperatorApprovalOptions {
	ttlMs?: number;
	singleUse?: boolean;
	approver: string;
	permitAllowlist?: boolean;
}

/**
 * Record an operator approval for a pending ask.
 *
 * OPERATOR ONLY. This must be reached from a human-facing channel (the `aidr
 * approve` CLI with interactive confirmation), never from a tool the policed
 * agent can call. Throws {@link OperatorApprovalError} when there is nothing to
 * approve or the pending record does not verify.
 */
export async function recordOperatorApproval(
	actionId: string,
	approval: RecordOperatorApprovalOptions,
	options: OperatorApprovalStoreOptions = {},
): Promise<OperatorApproval> {
	assertActionId(actionId);
	const ttlMs = approval.ttlMs ?? OPERATOR_APPROVAL_DEFAULT_TTL_MS;
	if (
		!Number.isFinite(ttlMs) ||
		ttlMs < OPERATOR_APPROVAL_MIN_TTL_MS ||
		ttlMs > OPERATOR_APPROVAL_MAX_TTL_MS
	) {
		throw new OperatorApprovalError(
			"invalid_ttl",
			"Approval lifetime must be between 1 minute and 24 hours.",
		);
	}
	const path = operatorApprovalStorePath(options);
	return withStoreLock(path, async () => {
		const now = nowMs(options);
		const doc = await readDocument(path);
		const pending = doc.pending.find((p) => p.action_id === actionId);
		if (!pending) {
			throw new OperatorApprovalError(
				"not_pending",
				"No pending Singularity AIDR ask was recorded for this actionId.",
			);
		}
		if (Date.parse(pending.expires_at) <= now) {
			throw new OperatorApprovalError(
				"pending_expired",
				"The pending ask has expired; have the agent retry to record a fresh one.",
			);
		}
		const key = loadKey(options, false);
		if (!key) {
			throw new OperatorApprovalError(
				"key_unavailable",
				"The operator approval key is unavailable, so the pending record cannot be verified.",
			);
		}
		if (!macMatches(key.key, "pending", pending)) {
			throw new OperatorApprovalError(
				"tampered",
				"The pending record failed integrity verification and was not approved.",
			);
		}
		const unsigned: Omit<ApprovalDisk, "mac"> = {
			action_id: actionId,
			artifact_digest: pending.artifact_digest,
			tool: pending.tool,
			artifact_digests: pending.artifacts.map((a) => a.digest),
			approved_at: new Date(now).toISOString(),
			expires_at: new Date(now + ttlMs).toISOString(),
			single_use: approval.singleUse ?? true,
			approver: approval.approver.slice(0, 200),
			permit_allowlist: approval.permitAllowlist ?? false,
			uses: 0,
			consumed_at: null,
			allowlisted: [],
		};
		const record: ApprovalDisk = { ...unsigned, mac: computeMac(key.key, "approval", unsigned) };
		doc.pending = doc.pending.filter((p) => p.action_id !== actionId);
		doc.approvals = doc.approvals.filter((a) => a.action_id !== actionId);
		doc.approvals.push(record);
		await writeDocument(path, doc, now);
		return approvalFromDisk(record);
	});
}

/** Unexpired approvals with their verification state, newest first. */
export async function listOperatorApprovals(
	options: OperatorApprovalStoreOptions = {},
): Promise<Array<OperatorApproval & { verified: boolean }>> {
	const doc = await readDocument(operatorApprovalStorePath(options));
	const now = nowMs(options);
	const key = doc.approvals.length > 0 ? loadKey(options, false) : null;
	return doc.approvals
		.filter((a) => Date.parse(a.expires_at) > now)
		.sort((a, b) => Date.parse(b.approved_at) - Date.parse(a.approved_at))
		.map((a) => ({
			...approvalFromDisk(a),
			verified: !!key && macMatches(key.key, "approval", a),
		}));
}

// ── Consumption (connector side) ───────────────────────────────────────

export interface ConsumeOperatorApprovalInput {
	actionId: string;
	tool: string;
	artifacts: readonly Pick<Artifact, "type" | "value">[];
}

function checkApproval(
	record: ApprovalDisk,
	key: OperatorKeyMaterial,
	input: ConsumeOperatorApprovalInput,
	now: number,
): OperatorConsumeReason {
	if (!macMatches(key.key, "approval", record)) return "tampered";
	if (Date.parse(record.expires_at) <= now) return "expired";
	if (record.tool !== input.tool) return "tool_mismatch";
	if (record.artifact_digest !== artifactSetDigest(input.artifacts)) return "digest_mismatch";
	if (record.single_use && record.uses > 0) return "already_used";
	return "approved";
}

/**
 * Atomically spend an operator approval for this exact call.
 *
 * Never throws: every failure (missing, expired, edited, mismatched, store or key
 * unavailable) is a refusal, so the `ask` stays blocked.
 */
export async function consumeOperatorApproval(
	input: ConsumeOperatorApprovalInput,
	options: OperatorApprovalStoreOptions = {},
): Promise<OperatorConsumeResult> {
	if (!ACTION_ID.test(input.actionId)) return { approved: false, reason: "not_found" };
	const path = operatorApprovalStorePath(options);
	try {
		// Cheap unlocked look first: almost every ask has no approval waiting.
		const peek = await readDocument(path);
		if (!peek.approvals.some((a) => a.action_id === input.actionId)) {
			return { approved: false, reason: "not_found" };
		}
		return await withStoreLock(path, async () => {
			const now = nowMs(options);
			const doc = await readDocument(path);
			const record = doc.approvals.find((a) => a.action_id === input.actionId);
			if (!record) return { approved: false, reason: "not_found" as const };
			const key = loadKey(options, false);
			if (!key) return { approved: false, reason: "key_unavailable" as const };
			const reason = checkApproval(record, key, input, now);
			if (reason !== "approved") return { approved: false, reason };
			const { mac: _old, ...rest } = record;
			const updatedUnsigned: Omit<ApprovalDisk, "mac"> = {
				...rest,
				uses: record.uses + 1,
				consumed_at: new Date(now).toISOString(),
			};
			const updated: ApprovalDisk = {
				...updatedUnsigned,
				mac: computeMac(key.key, "approval", updatedUnsigned),
			};
			doc.approvals = doc.approvals.map((a) => (a.action_id === input.actionId ? updated : a));
			await writeDocument(path, doc, now);
			return { approved: true, reason: "approved" as const, approval: approvalFromDisk(updated) };
		});
	} catch (error) {
		(options.logger ?? nullLogger).warn("Operator approval store unavailable; ask stays blocked", {
			error: String(error),
		});
		return { approved: false, reason: "unavailable" };
	}
}

// ── Allowlist grant ───────────────────────────────────────────────────

/**
 * Find an unexpired, verified approval the operator explicitly marked as
 * allowlist-eligible (`aidr approve --permit-allowlist`) that covers this exact
 * artifact and has not already been turned into an allowlist entry.
 */
export async function findOperatorAllowlistGrant(
	type: string,
	value: string,
	options: OperatorApprovalStoreOptions = {},
): Promise<string | null> {
	try {
		const digest = artifactValueDigest(type, value);
		const doc = await readDocument(operatorApprovalStorePath(options));
		const now = nowMs(options);
		const candidates = doc.approvals.filter(
			(a) =>
				a.permit_allowlist &&
				Date.parse(a.expires_at) > now &&
				a.artifact_digests.includes(digest) &&
				!a.allowlisted.includes(digest),
		);
		if (candidates.length === 0) return null;
		const key = loadKey(options, false);
		if (!key) return null;
		return candidates.find((a) => macMatches(key.key, "approval", a))?.action_id ?? null;
	} catch {
		return null;
	}
}

/** Mark the artifact of an allowlist grant as used, so one grant yields one entry. */
export async function markOperatorAllowlistGrantUsed(
	actionId: string,
	type: string,
	value: string,
	options: OperatorApprovalStoreOptions = {},
): Promise<boolean> {
	const path = operatorApprovalStorePath(options);
	const digest = artifactValueDigest(type, value);
	try {
		return await withStoreLock(path, async () => {
			const now = nowMs(options);
			const doc = await readDocument(path);
			const record = doc.approvals.find((a) => a.action_id === actionId);
			const key = loadKey(options, false);
			if (!record || !key || !macMatches(key.key, "approval", record)) return false;
			if (!record.permit_allowlist || Date.parse(record.expires_at) <= now) return false;
			if (!record.artifact_digests.includes(digest) || record.allowlisted.includes(digest)) {
				return false;
			}
			const { mac: _old, ...rest } = record;
			const unsigned: Omit<ApprovalDisk, "mac"> = {
				...rest,
				allowlisted: [...record.allowlisted, digest],
			};
			const updated: ApprovalDisk = {
				...unsigned,
				mac: computeMac(key.key, "approval", unsigned),
			};
			doc.approvals = doc.approvals.map((a) => (a.action_id === actionId ? updated : a));
			await writeDocument(path, doc, now);
			return true;
		});
	} catch {
		return false;
	}
}
