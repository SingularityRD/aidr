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
 *    artifacts and the tool name, plus a redacted, control-character-escaped
 *    summary for the operator.
 * 2. The operator runs `aidr approve <actionId>`. The CLI reads the pending record,
 *    shows it, asks for interactive confirmation and calls
 *    {@link recordOperatorApproval}.
 * 3. When the agent retries the same call, the connector calls
 *    {@link consumeOperatorApproval}. It succeeds only for an unexpired, untampered
 *    approval whose action id, tool and artifact digest all match — and, by
 *    default, only once.
 *
 * ## Key custody (fail closed)
 *
 * Every record carries an HMAC-SHA256 under a per-install key. With the default
 * `auto` storage the key lives in the OS credential vault (Windows DPAPI, macOS
 * Keychain, libsecret) whenever one answers. On a Linux/POSIX host with NO vault
 * (headless servers, WSL, containers) it lives in the machine-bound encrypted
 * file store instead (`createEncryptedFileStore`: AES-256-GCM, owner-only files,
 * key derived from the machine id) — the same-user exposure libsecret already
 * has there, without a plaintext key. Windows and macOS always have a vault, so
 * `auto` never leaves it on those platforms, and a host whose key was created in
 * a vault never falls back to a file when that vault later stops answering:
 * approvals are then DISABLED (asks stay blocked) and `aidr approve` / `aidr
 * doctor` say why. `os-vault` makes the vault mandatory everywhere;
 * `encrypted-file` selects the file store explicitly; `file` is the legacy plain
 * key file, an explicit opt-in `aidr doctor` warns about.
 *
 * ## What the HMAC does and does not prove
 *
 * The HMAC proves a record was written by a holder of the key, so a record edited
 * by hand (a later expiry, a different digest, a reset use counter) or forged
 * without the key fails verification. It does NOT prove a record is the latest
 * one: restoring an earlier copy of the whole store (taken before an approval was
 * spent) brings back a validly signed, unspent approval. Single-use is therefore
 * enforced by a consumption ledger kept next to the key in the OS vault (the
 * "anchor", see {@link OperatorConsumptionAnchor}): every spend is recorded there
 * and checked on every consume, and without a working anchor nothing is released.
 *
 * ## Residual risk
 *
 * This is NOT a boundary against code that runs as the same OS user with full
 * shell access: such code can query the vault as that user (unless the vault
 * prompts per access), mint a valid record, or run `aidr approve` inside a
 * pseudo-terminal. The vault custody, the TTY requirement in the CLI and the
 * self-defense rules (CLT-SELF-007..009 deny any agent reference to the AIDR
 * state directory, the vault entries or the approval CLI) raise the bar; they do
 * not make the channel agent-proof. See `docs/configuration.md`.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import {
	closeSync,
	lstatSync,
	mkdirSync,
	openSync,
	renameSync,
	unlinkSync,
	writeSync,
} from "node:fs";
import { lstat, mkdir, open, stat, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";
import { toolInputSummaryText } from "./audit-log.js";
import { AIDR_DIR, resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent, getFileContentSync } from "./file-utils.js";
import {
	createEncryptedFileStore,
	resolveSecretStore,
	type SecretStore,
	type SecretStoreKind,
} from "./secret-store.js";
import { redactTelemetryString } from "./telemetry-redaction.js";
import { boundTerminalText } from "./terminal-text.js";
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
/** Vault account/id of the consumption ledger (the single-use anchor). */
export const OPERATOR_APPROVAL_LEDGER_ID = "aidr-operator-approval-ledger";
/** Selects the key storage explicitly: `auto` (default), `os-vault`, `encrypted-file` or `file`. */
export const OPERATOR_APPROVAL_KEY_STORAGE_ENV = "AIDR_OPERATOR_APPROVAL_KEY_STORAGE";
const KEY_FILE = "operator-approval.key";
const KEY_META_FILE = "operator-approval-key.json";
const LEDGER_FILE = "operator-approval-ledger.json";
/** Spent single-use approvals remembered by the ledger (until their expiry). */
const MAX_LEDGER_ENTRIES = 1024;
const LEDGER_ID = /^[a-f0-9]{32}$/;

/**
 * Where the approval key lives.
 * - `auto` (default): the platform vault when one answers; on a Linux/POSIX
 *   host with no vault, the machine-bound encrypted file store. Never a
 *   plaintext file, never a fallback on Windows/macOS, and never a fallback once
 *   the key was created in a vault.
 * - `os-vault`: the platform vault only. No vault means approvals are disabled.
 * - `encrypted-file`: the machine-bound encrypted file store, explicitly.
 * - `file`: an owner-only PLAIN key file in the AIDR directory. Legacy explicit
 *   opt-in; any process running as the same user can read it.
 */
export type OperatorKeyStorage = "auto" | "os-vault" | "encrypted-file" | "file";

/** Where a key or ledger actually lives. */
type OperatorKeyLocation = "os-vault" | "encrypted-file" | "file";

// ── Errors ─────────────────────────────────────────────────────────

export type OperatorApprovalErrorCode =
	| "invalid_action_id"
	| "not_pending"
	| "pending_expired"
	| "tampered"
	| "key_unavailable"
	| "approvals_disabled"
	| "anchor_unavailable"
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
	/** Redacted, control-character-escaped, bounded; ends with "…(truncated)" when cut. */
	summary: string;
	/** Previews of the first {@link MAX_ARTIFACTS_PER_RECORD} artifacts. */
	artifacts: PendingAskArtifact[];
	/** How many artifacts the call had in total (may exceed `artifacts.length`). */
	artifactCount: number;
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
	| "anchor_unavailable"
	| "unavailable";

export interface OperatorConsumeResult {
	approved: boolean;
	reason: OperatorConsumeReason;
	approval?: OperatorApproval;
}

export interface OperatorKeyMaterial {
	key: Buffer;
	location: OperatorKeyLocation;
	store: SecretStoreKind | "file";
}

/**
 * Where spent single-use approvals are recorded, outside the approval store.
 *
 * The store file can be rolled back by anything that can write it; the anchor is
 * what makes "single use" survive that. The default provider keeps it in the same
 * OS vault as the key. `read` returns null when nothing was recorded yet; both
 * methods throw when the anchor cannot be used, which keeps the call blocked.
 */
export interface OperatorConsumptionAnchor {
	readonly location: OperatorKeyLocation;
	read(): string | null;
	write(value: string): void;
}

/** Supplies the per-install HMAC key. `create` is false for read-only callers. */
export interface OperatorKeyProvider {
	/** Throws {@link OperatorApprovalError} (`approvals_disabled`) when the storage is unusable. */
	load(options: { create: boolean }): OperatorKeyMaterial | null;
	/**
	 * The consumption anchor. A provider without one (or returning null) cannot
	 * release anything: approvals are disabled, fail closed.
	 */
	anchor?(): OperatorConsumptionAnchor | null;
	/** The configured key storage, when the provider knows it (for `aidr doctor`). */
	readonly storage?: OperatorKeyStorage;
}

export interface OperatorApprovalStoreOptions {
	/** Store file; defaults to `~/.singularity-aidr/approvals.json`. */
	path?: string;
	keyProvider?: OperatorKeyProvider;
	/**
	 * Key storage for the default provider; the config's
	 * `operator_approvals.key_storage`. Ignored when `keyProvider` is given.
	 */
	keyStorage?: OperatorKeyStorage;
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
	// Optional so records written before the count was stored still verify.
	artifact_count: z.number().int().min(0).optional(),
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

/**
 * An `ask` a host answered in its OWN confirmation dialog (Claude Code, Cursor /
 * VS Code in the default `operator_approvals.mode: host_dialog`). Kept only so
 * `aidr pending` shows every ask in one place. It is informational: it carries
 * no MAC, is never read by {@link recordOperatorApproval} and therefore can
 * never become an approval, whatever is written into it.
 */
const HostAskDiskSchema = PendingDiskSchema.omit({ mac: true }).extend({
	channel: z.literal("host_dialog"),
});

type PendingDisk = z.infer<typeof PendingDiskSchema>;
type ApprovalDisk = z.infer<typeof ApprovalDiskSchema>;
type HostAskDisk = z.infer<typeof HostAskDiskSchema>;

interface StoreDocument {
	version: number;
	pending: PendingDisk[];
	approvals: ApprovalDisk[];
	host_asks: HostAskDisk[];
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
		artifactCount: Math.max(record.artifact_count ?? 0, record.artifacts.length),
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

/**
 * What a MAC covers. The kind is part of the MAC input, so a record of one kind
 * can never be replayed as another (a detection exception is not an approval).
 */
type MacKind = "pending" | "approval" | OperatorRecordKind;

/** Operator-authored records other modules sign with the approval key. */
export type OperatorRecordKind = "detection-exception";

function computeMac(key: Buffer, kind: MacKind, record: object): string {
	const { mac: _ignored, ...body } = record as Record<string, unknown>;
	return createHmac("sha256", key)
		.update(`${MAC_DOMAIN}\n${kind}\n${canonicalJson(body)}`)
		.digest("hex");
}

function macMatches(key: Buffer, kind: MacKind, record: { mac: string }): boolean {
	const expected = Buffer.from(computeMac(key, kind, record), "hex");
	const actual = Buffer.from(record.mac, "hex");
	return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// ── Key provider ─────────────────────────────────────────────────────

interface DefaultKeyProviderOptions {
	directory?: string;
	env?: NodeJS.ProcessEnv;
	/** Vault resolver; injectable so tests never touch a real OS vault. */
	resolveVault?: (selection?: string) => SecretStore;
	/** The config's `operator_approvals.key_storage`; the env variable overrides it. */
	keyStorage?: OperatorKeyStorage;
	/** Platform deciding whether `auto` may use the file store (tests). */
	platform?: NodeJS.Platform;
	/** Encrypted-file store factory (tests); defaults to `<directory>/sealed`. */
	encryptedStore?: (directory: string) => SecretStore;
}

function writePrivateFileExclusive(path: string, content: string): void {
	const handle = openSync(path, "wx", 0o600);
	try {
		writeSync(handle, content);
	} finally {
		closeSync(handle);
	}
}

/** Write an owner-only file atomically (exclusive temp file, then rename). */
function writePrivateFileAtomic(path: string, content: string): void {
	const tmp = `${path}.${randomBytes(6).toString("hex")}.tmp`;
	writePrivateFileExclusive(tmp, content);
	// Synchronous rename keeps the provider synchronous like the vault backends.
	renameSync(tmp, path);
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

function parseKeyStorage(value: unknown): OperatorKeyStorage | undefined {
	if (typeof value !== "string") return undefined;
	const normalized = value.trim().toLowerCase();
	if (
		normalized === "auto" ||
		normalized === "os-vault" ||
		normalized === "encrypted-file" ||
		normalized === "file"
	) {
		return normalized;
	}
	return undefined;
}

/** `operator_approvals.key_storage` from the config file in `directory`, if set. */
function keyStorageFromConfig(directory: string): OperatorKeyStorage | undefined {
	try {
		const path = join(directory, "config.json");
		if (!assertRegularFile(path)) return undefined;
		const config = JSON.parse(getFileContentSync(path)) as {
			operator_approvals?: { key_storage?: unknown };
		};
		return parseKeyStorage(config?.operator_approvals?.key_storage);
	} catch {
		// An unreadable config never opts into the weaker file storage.
		return undefined;
	}
}

/**
 * The configured key storage. The env variable wins over the config; unset or
 * malformed means `auto`, which never selects the plaintext key file.
 */
export function resolveOperatorKeyStorage(
	options: { keyStorage?: OperatorKeyStorage; env?: NodeJS.ProcessEnv; directory?: string } = {},
): OperatorKeyStorage {
	const env = options.env ?? process.env;
	return (
		parseKeyStorage(env[OPERATOR_APPROVAL_KEY_STORAGE_ENV]) ??
		parseKeyStorage(options.keyStorage) ??
		keyStorageFromConfig(options.directory ?? resolvePath(AIDR_DIR)) ??
		"auto"
	);
}

function approvalsDisabled(detail: string): OperatorApprovalError {
	return new OperatorApprovalError(
		"approvals_disabled",
		`Operator approvals are disabled: ${detail} Asks stay blocked until this is fixed. ` +
			"Install or unlock an OS credential vault (Windows DPAPI, macOS Keychain, or libsecret's " +
			"secret-tool), or, on a host without one, select the machine-bound encrypted file store " +
			'with operator_approvals.key_storage = "encrypted-file" in the config (or ' +
			`${OPERATOR_APPROVAL_KEY_STORAGE_ENV}=encrypted-file).`,
	);
}

/** Platforms where `auto` never leaves the OS vault: one always exists there. */
function platformHasMandatoryVault(platform: NodeJS.Platform): boolean {
	return platform === "win32" || platform === "darwin";
}

function fileAnchor(dir: string): OperatorConsumptionAnchor {
	const path = join(dir, LEDGER_FILE);
	return {
		location: "file",
		read: () => (assertRegularFile(path) ? getFileContentSync(path) : null),
		write: (value) => writePrivateFileAtomic(path, value),
	};
}

/**
 * The default key provider.
 *
 * The key and the consumption ledger live together: in the platform vault, in
 * the machine-bound encrypted file store (`encrypted-file`, or `auto` on a
 * Linux/POSIX host with no vault), or in plain owner-only files (`file`, explicit
 * legacy opt-in). When the selected storage is unusable, `load` and `anchor`
 * throw `approvals_disabled` and nothing can be approved.
 *
 * `operator-approval-key.json` records where the key was created. It never makes
 * the provider read a plain key file (a hand-written `{"store":"file"}` plus a
 * key file of the agent's choosing must not become a signing key); under `auto`
 * it only ever makes the provider STRICTER: a key created in a vault is never
 * replaced by a file-store key when that vault stops answering.
 */
export function createDefaultOperatorKeyProvider(
	options: DefaultKeyProviderOptions = {},
): OperatorKeyProvider {
	const env = options.env ?? process.env;
	const resolveVault =
		options.resolveVault ?? ((selection?: string) => resolveSecretStore({ selection, env }));
	const directory = () => options.directory ?? resolvePath(AIDR_DIR);
	const storage = () =>
		resolveOperatorKeyStorage({ keyStorage: options.keyStorage, env, directory: directory() });

	const readKeyFile = (dir: string): OperatorKeyMaterial | null => {
		const path = join(dir, KEY_FILE);
		if (!assertRegularFile(path)) return null;
		const hex = getFileContentSync(path).trim();
		if (!/^[a-f0-9]{64}$/.test(hex)) return null;
		return { key: Buffer.from(hex, "hex"), location: "file", store: "file" };
	};

	const writeMeta = (dir: string, store: string) => {
		writePrivateFileAtomic(join(dir, KEY_META_FILE), `${JSON.stringify({ version: 1, store })}\n`);
	};

	const vault = (): SecretStore => {
		let store: SecretStore;
		try {
			store = resolveVault();
		} catch (error) {
			throw approvalsDisabled(
				`no OS credential vault is available for the approval key (${error instanceof Error ? error.message : String(error)}).`,
			);
		}
		if (!store.osProtected) {
			throw approvalsDisabled(
				`the selected secret store (${store.kind}) is not an OS credential vault.`,
			);
		}
		return store;
	};

	const sealed = (dir: string): SecretStore =>
		options.encryptedStore
			? options.encryptedStore(dir)
			: createEncryptedFileStore({ directory: join(dir, "sealed") });

	/** The vault kind the key was created in, from the informational record. */
	const recordedVaultKind = (dir: string): string | null => {
		try {
			const path = join(dir, KEY_META_FILE);
			if (!assertRegularFile(path)) return null;
			const meta = JSON.parse(getFileContentSync(path)) as { store?: unknown };
			const store = typeof meta?.store === "string" ? meta.store : null;
			return store && store !== "file" && store !== "encrypted-file" ? store : null;
		} catch {
			return null;
		}
	};

	/** The store that holds the key and ledger for the vault-backed storages. */
	const keyStore = (dir: string): { store: SecretStore; location: OperatorKeyLocation } => {
		const selected = storage();
		if (selected === "encrypted-file") return { store: sealed(dir), location: "encrypted-file" };
		try {
			return { store: vault(), location: "os-vault" };
		} catch (error) {
			if (selected !== "auto" || !(error instanceof OperatorApprovalError)) throw error;
			if (platformHasMandatoryVault(options.platform ?? process.platform)) throw error;
			const recorded = recordedVaultKind(dir);
			if (recorded) {
				throw approvalsDisabled(
					`the approval key was created in the ${recorded} vault, which is not answering now; ` +
						"refusing to replace it with a file-store key.",
				);
			}
			return { store: sealed(dir), location: "encrypted-file" };
		}
	};

	const loadFromFile = (dir: string, create: boolean): OperatorKeyMaterial | null => {
		const existing = readKeyFile(dir);
		if (existing || !create) return existing;
		const path = join(dir, KEY_FILE);
		if (assertRegularFile(path)) {
			throw new OperatorApprovalError(
				"key_unavailable",
				`${path} exists but does not hold a valid approval key; remove it to regenerate.`,
			);
		}
		const hex = randomBytes(32).toString("hex");
		writePrivateFileExclusive(path, `${hex}\n`);
		writeMeta(dir, "file");
		return { key: Buffer.from(hex, "hex"), location: "file", store: "file" };
	};

	const loadFromStore = (dir: string, create: boolean): OperatorKeyMaterial | null => {
		const { store, location } = keyStore(dir);
		const hex = store.get(OPERATOR_APPROVAL_KEY_ID);
		if (hex && /^[a-f0-9]{64}$/.test(hex)) {
			return { key: Buffer.from(hex, "hex"), location, store: store.kind };
		}
		if (!create) return null;
		const fresh = randomBytes(32).toString("hex");
		store.put(OPERATOR_APPROVAL_KEY_ID, fresh);
		writeMeta(dir, store.kind);
		// A key file left by an earlier file-storage install is never read under
		// this storage and only exposes an old key; remove it.
		try {
			unlinkSync(join(dir, KEY_FILE));
		} catch {
			// Absent, or not removable: either way it is not used.
		}
		return { key: Buffer.from(fresh, "hex"), location, store: store.kind };
	};

	return {
		get storage() {
			return storage();
		},
		load({ create }) {
			const dir = directory();
			mkdirSync(dir, { recursive: true, mode: 0o700 });
			return storage() === "file" ? loadFromFile(dir, create) : loadFromStore(dir, create);
		},
		anchor() {
			const dir = directory();
			if (storage() === "file") return fileAnchor(dir);
			const { store, location } = keyStore(dir);
			return {
				location,
				read: () => store.get(OPERATOR_APPROVAL_LEDGER_ID),
				write: (value) => store.put(OPERATOR_APPROVAL_LEDGER_ID, value),
			};
		},
	};
}

const keyCache = new Map<OperatorKeyProvider, { material: OperatorKeyMaterial; at: number }>();
const defaultProviders = new Map<string, OperatorKeyProvider>();

function providerFor(options: OperatorApprovalStoreOptions): OperatorKeyProvider {
	if (options.keyProvider) return options.keyProvider;
	const slot = options.keyStorage ?? "auto";
	let provider = defaultProviders.get(slot);
	if (!provider) {
		provider = createDefaultOperatorKeyProvider({ keyStorage: options.keyStorage });
		defaultProviders.set(slot, provider);
	}
	return provider;
}

/** Load the key or throw an {@link OperatorApprovalError} that says why. */
function requireKey(options: OperatorApprovalStoreOptions, create: boolean): OperatorKeyMaterial {
	const provider = providerFor(options);
	const cached = keyCache.get(provider);
	if (cached && Date.now() - cached.at < KEY_CACHE_MS) return cached.material;
	let material: OperatorKeyMaterial | null;
	try {
		material = provider.load({ create });
	} catch (error) {
		if (error instanceof OperatorApprovalError) throw error;
		throw new OperatorApprovalError(
			"key_unavailable",
			`The operator approval key could not be loaded: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
	if (!material) {
		throw new OperatorApprovalError(
			"key_unavailable",
			"No operator approval key exists yet; one is created when a connector records its first ask.",
		);
	}
	keyCache.set(provider, { material, at: Date.now() });
	return material;
}

/** Load the key, or null (logged) when it is unavailable for any reason. */
function loadKey(
	options: OperatorApprovalStoreOptions,
	create: boolean,
): OperatorKeyMaterial | null {
	try {
		return requireKey(options, create);
	} catch (error) {
		(options.logger ?? nullLogger).warn("Operator approval key unavailable", {
			error: error instanceof Error ? error.message : String(error),
		});
		return null;
	}
}

/** The consumption anchor, or an {@link OperatorApprovalError} that says why not. */
function requireAnchor(options: OperatorApprovalStoreOptions): OperatorConsumptionAnchor {
	const provider = providerFor(options);
	let anchor: OperatorConsumptionAnchor | null | undefined;
	try {
		anchor = provider.anchor?.();
	} catch (error) {
		if (error instanceof OperatorApprovalError) throw error;
		throw new OperatorApprovalError(
			"anchor_unavailable",
			`The approval consumption ledger is unavailable: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
	if (!anchor) {
		throw new OperatorApprovalError(
			"anchor_unavailable",
			"No approval consumption ledger is available, so single-use approvals cannot be enforced.",
		);
	}
	return anchor;
}

/** Forget cached key material (tests, key rotation). */
export function clearOperatorApprovalKeyCache(): void {
	keyCache.clear();
	defaultProviders.clear();
}

export interface OperatorApprovalKeyStatus {
	/** Whether a key exists (never the key itself). */
	present: boolean;
	location?: OperatorKeyLocation;
	store?: string;
	/** Configured storage; undefined for an injected provider that does not say. */
	storage?: OperatorKeyStorage;
	/** False when operator approvals cannot work at all (asks stay blocked). */
	available: boolean;
	/** Why approvals are unavailable. */
	reason?: string;
	/** Where the single-use ledger lives, when it is usable. */
	anchor?: OperatorKeyLocation;
}

/**
 * Where the key and the ledger live and whether approvals can work, for
 * `aidr doctor` and the CLI; never returns the key.
 */
export function describeOperatorApprovalKey(
	options: OperatorApprovalStoreOptions = {},
): OperatorApprovalKeyStatus {
	const provider = providerFor(options);
	let storage: OperatorKeyStorage | undefined;
	try {
		storage = provider.storage;
	} catch {
		storage = undefined;
	}
	const status: OperatorApprovalKeyStatus = { present: false, storage, available: true };
	try {
		const material = requireKey(options, false);
		status.present = true;
		status.location = material.location;
		status.store = material.store;
	} catch (error) {
		// No key yet is normal before the first ask; anything else disables approvals.
		if (!(error instanceof OperatorApprovalError) || error.code !== "key_unavailable") {
			status.available = false;
			status.reason = error instanceof Error ? error.message : String(error);
			return status;
		}
	}
	try {
		const anchor = requireAnchor(options);
		readLedger(anchor);
		status.anchor = anchor.location;
	} catch (error) {
		status.available = false;
		status.reason = error instanceof Error ? error.message : String(error);
	}
	return status;
}

// ── Consumption ledger (the single-use anchor) ───────────────────────

const LedgerSchema = z.object({
	version: z.literal(1),
	/** Monotonic write counter; every spend increments it. */
	seq: z.number().int().min(0),
	/** Consumption id → expiry (epoch seconds) of the approval it spent. */
	consumed: z.record(z.string().regex(LEDGER_ID), z.number().int().min(0)),
});

type Ledger = z.infer<typeof LedgerSchema>;

function readLedger(anchor: OperatorConsumptionAnchor): Ledger {
	const raw = anchor.read();
	if (raw === null || raw.trim() === "") return { version: 1, seq: 0, consumed: {} };
	let parsed: ReturnType<typeof LedgerSchema.safeParse>;
	try {
		parsed = LedgerSchema.safeParse(JSON.parse(raw));
	} catch {
		parsed = { success: false } as ReturnType<typeof LedgerSchema.safeParse>;
	}
	if (!parsed.success) {
		// A ledger that does not parse cannot say what was spent: refuse, never reset.
		throw new OperatorApprovalError(
			"anchor_unavailable",
			"The approval consumption ledger is corrupt; single-use approvals cannot be verified.",
		);
	}
	return parsed.data;
}

/** Stable identity of an approval: the same in every copy of the store it appears in. */
function approvalConsumptionId(record: ApprovalDisk): string {
	return sha256(
		`approval\n${record.action_id}\n${record.approved_at}\n${record.expires_at}\n${record.artifact_digest}`,
	).slice(0, 32);
}

function grantConsumptionId(record: ApprovalDisk, digest: string): string {
	return sha256(`grant\n${approvalConsumptionId(record)}\n${digest}`).slice(0, 32);
}

/**
 * Record one spend in the anchor, or report that it was already spent.
 *
 * Must be called under the store lock, which serialises every ledger writer. The
 * write is read back and checked, so an anchor that silently drops a write cannot
 * turn a single-use approval into a reusable one. Throws when the ledger cannot
 * be read, is full of unexpired entries, or does not persist the spend.
 */
function spendInLedger(
	anchor: OperatorConsumptionAnchor,
	id: string,
	expiresAtMs: number,
	now: number,
): "spent" | "already_used" {
	const ledger = readLedger(anchor);
	if (Object.hasOwn(ledger.consumed, id)) return "already_used";
	const nowSeconds = Math.floor(now / 1000);
	const consumed: Record<string, number> = {};
	for (const [entry, expiry] of Object.entries(ledger.consumed)) {
		if (expiry > nowSeconds) consumed[entry] = expiry;
	}
	if (Object.keys(consumed).length >= MAX_LEDGER_ENTRIES) {
		throw new OperatorApprovalError(
			"anchor_unavailable",
			"The approval consumption ledger is full of unexpired entries; refusing to evict any.",
		);
	}
	consumed[id] = Math.ceil(expiresAtMs / 1000);
	const next: Ledger = { version: 1, seq: ledger.seq + 1, consumed };
	anchor.write(JSON.stringify(next));
	const check = readLedger(anchor);
	if (check.seq !== next.seq || !Object.hasOwn(check.consumed, id)) {
		throw new OperatorApprovalError(
			"anchor_unavailable",
			"The approval consumption ledger did not persist the spend.",
		);
	}
	return "spent";
}

// ── Store I/O ────────────────────────────────────────────────────────

export function operatorApprovalStorePath(options: OperatorApprovalStoreOptions = {}): string {
	return options.path ?? join(resolvePath(AIDR_DIR), "approvals.json");
}

function nowMs(options: OperatorApprovalStoreOptions): number {
	return options.now ? options.now() : Date.now();
}

function emptyDocument(): StoreDocument {
	return { version: STORE_VERSION, pending: [], approvals: [], host_asks: [] };
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
	return parseDocument(raw);
}

function validEntries<T>(value: unknown, schema: z.ZodType<T>): T[] {
	if (!Array.isArray(value)) return [];
	const out: T[] = [];
	for (const entry of value) {
		const parsed = schema.safeParse(entry);
		if (parsed.success) out.push(parsed.data);
	}
	return out;
}

/** The pending asks and approvals that match the disk schema; anything else is dropped. */
function parseDocument(raw: unknown): StoreDocument {
	const doc = emptyDocument();
	if (typeof raw !== "object" || raw === null) return doc;
	const record = raw as Record<string, unknown>;
	doc.pending = validEntries(record.pending, PendingDiskSchema);
	doc.approvals = validEntries(record.approvals, ApprovalDiskSchema);
	doc.host_asks = validEntries(record.host_asks, HostAskDiskSchema);
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
		host_asks: doc.host_asks
			.filter(alive)
			.sort(newestFirst<HostAskDisk>((r) => r.created_at))
			.slice(0, MAX_PENDING),
	};
}

async function writeDocument(path: string, doc: StoreDocument, now: number): Promise<void> {
	await atomicWriteJson(path, pruneDocument(doc, now), { mode: 0o600 });
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * One attempt to create the lock file: "acquired"; "retry" at once when the lock
 * was stale (removed) or vanished meanwhile; "held" while another writer has it.
 */
async function tryAcquireLock(lockPath: string): Promise<"acquired" | "retry" | "held"> {
	try {
		const handle = await open(lockPath, "wx", 0o600);
		try {
			await handle.writeFile(`${process.pid}\n`, "utf8");
		} finally {
			await handle.close();
		}
		return "acquired";
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
	}
	try {
		const info = await stat(lockPath);
		if (Date.now() - info.mtimeMs <= LOCK_STALE_MS) return "held";
		await unlink(lockPath).catch(() => undefined);
		return "retry";
	} catch {
		return "retry";
	}
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
		const attempt = await tryAcquireLock(lockPath);
		if (attempt === "acquired") break;
		if (attempt === "retry") continue;
		if (Date.now() > deadline) {
			throw new OperatorApprovalError(
				"lock_timeout",
				"Timed out waiting for the approval store lock.",
			);
		}
		await sleep(5 + Math.floor(Math.random() * 20));
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
	verdict: Pick<Verdict, "severity" | "category" | "reasons" | "matchedThreatId" | "ruleSeverity">;
	connector?: string;
}

/** Longest raw text redacted for a display field; everything after it is cut anyway. */
const MAX_DISPLAY_SOURCE = 8 * 1024;

/**
 * Operator-facing text: credential-redacted, every control / bidi / format
 * character rendered as a visible escape (so `\x1b[2K\r` cannot repaint the
 * operator's terminal), and bounded with an explicit "(truncated)" marker.
 */
function operatorText(value: string, max: number): string {
	const redacted = redactTelemetryString(
		value.slice(0, MAX_DISPLAY_SOURCE),
		Number.MAX_SAFE_INTEGER,
	);
	return boundTerminalText(redacted, max).text;
}

/** The display fields of a pending ask, shared by approvable and informational records. */
function pendingAskFields(input: RecordPendingAskInput, now: number): Omit<PendingDisk, "mac"> {
	const artifacts = input.artifacts.slice(0, MAX_ARTIFACTS_PER_RECORD);
	return {
		action_id: input.actionId,
		artifact_digest: artifactSetDigest(input.artifacts),
		tool: input.toolName.slice(0, 200),
		connector: operatorText(input.connector ?? "unknown", 64),
		session_digest: sha256(input.sessionId).slice(0, 16),
		summary: operatorText(toolInputSummaryText(input.toolName, input.toolInput), 300),
		artifacts: artifacts.map((a) => ({
			type: operatorText(String(a.type), 32),
			digest: artifactValueDigest(a.type, a.value),
			preview: operatorText(a.value, 160),
		})),
		artifact_count: input.artifacts.length,
		// The matched rule's own severity is what the hook message shows the user
		// ("high" for `cat .env`); the decision-level severity ("warning") is only
		// the fallback, so `aidr pending` names the same severity as the block.
		severity: operatorText(String(input.verdict.ruleSeverity ?? input.verdict.severity), 32),
		category: operatorText(String(input.verdict.category), 100),
		reasons: input.verdict.reasons.slice(0, 3).map((r) => operatorText(r, 300)),
		threat_id: input.verdict.matchedThreatId
			? operatorText(input.verdict.matchedThreatId, 100)
			: null,
		created_at: new Date(now).toISOString(),
		expires_at: new Date(now + PENDING_ASK_TTL_MS).toISOString(),
	};
}

/**
 * Record an `ask` so an operator can approve it by id. Called by the connector at
 * block time; the stored summary is redacted and escaped, and raw artifact values
 * are kept only as digests plus a redacted, escaped preview. Throws (the call
 * stays blocked, but cannot be approved) when approvals are disabled.
 */
export async function recordPendingAsk(
	input: RecordPendingAskInput,
	options: OperatorApprovalStoreOptions = {},
): Promise<PendingAsk> {
	assertActionId(input.actionId);
	const path = operatorApprovalStorePath(options);
	return withStoreLock(path, async () => {
		const key = requireKey(options, true);
		// Without a consumption anchor nothing could ever be released; say so now
		// rather than letting the operator approve something that cannot be spent.
		requireAnchor(options);
		const now = nowMs(options);
		const unsigned = pendingAskFields(input, now);
		const record: PendingDisk = { ...unsigned, mac: computeMac(key.key, "pending", unsigned) };
		const doc = await readDocument(path);
		doc.pending = doc.pending.filter((p) => p.action_id !== input.actionId);
		doc.host_asks = doc.host_asks.filter((p) => p.action_id !== input.actionId);
		doc.pending.push(record);
		await writeDocument(path, doc, now);
		return pendingFromDisk(record);
	});
}

/**
 * Record an `ask` the host answers in its own confirmation dialog, so `aidr
 * pending` lists it. INFORMATIONAL ONLY: no key and no MAC, and the record is
 * kept apart from approvable pending asks, so `aidr approve` refuses it. It needs
 * no OS vault access, which keeps the default hook path fast. Throws when the
 * store cannot be written; callers treat it as best effort.
 */
export async function recordHostDialogAsk(
	input: RecordPendingAskInput,
	options: OperatorApprovalStoreOptions = {},
): Promise<HostDialogAsk> {
	assertActionId(input.actionId);
	const path = operatorApprovalStorePath(options);
	return withStoreLock(path, async () => {
		const now = nowMs(options);
		const record: HostAskDisk = { ...pendingAskFields(input, now), channel: "host_dialog" };
		const doc = await readDocument(path);
		doc.host_asks = doc.host_asks.filter((p) => p.action_id !== input.actionId);
		doc.host_asks.push(record);
		await writeDocument(path, doc, now);
		return hostAskFromDisk(record);
	});
}

/** An informational host-dialog ask (see {@link recordHostDialogAsk}). Never approvable. */
export interface HostDialogAsk extends PendingAsk {
	channel: "host_dialog";
}

function hostAskFromDisk(record: HostAskDisk): HostDialogAsk {
	const { channel: _channel, ...fields } = record;
	return { ...pendingFromDisk({ ...fields, mac: "" }), channel: "host_dialog" };
}

/** Unexpired informational host-dialog asks, newest first. */
export async function listHostDialogAsks(
	options: OperatorApprovalStoreOptions = {},
): Promise<HostDialogAsk[]> {
	const doc = await readDocument(operatorApprovalStorePath(options));
	const now = nowMs(options);
	return doc.host_asks
		.filter((p) => Date.parse(p.expires_at) > now)
		.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
		.map(hostAskFromDisk);
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
		const key = requireKey(options, false);
		// An approval that could never be spent (no working ledger) is refused here,
		// where the operator sees why, instead of silently never releasing the call.
		readLedger(requireAnchor(options));
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
			approver: operatorText(approval.approver, 200),
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
 * Check the consumption ledger for this approval and, for a single-use one, spend
 * it there. Called under the store lock after every other check passed.
 */
function spendApproval(
	record: ApprovalDisk,
	options: OperatorApprovalStoreOptions,
	now: number,
): OperatorConsumeReason {
	try {
		const anchor = requireAnchor(options);
		if (!record.single_use) {
			// Multi-use approvals are not counted, but still need a working anchor:
			// without one, approvals are disabled as a whole.
			readLedger(anchor);
			return "approved";
		}
		const outcome = spendInLedger(
			anchor,
			approvalConsumptionId(record),
			Date.parse(record.expires_at),
			now,
		);
		return outcome === "spent" ? "approved" : "already_used";
	} catch (error) {
		(options.logger ?? nullLogger).warn(
			"Approval consumption ledger unavailable; ask stays blocked",
			{
				error: error instanceof Error ? error.message : String(error),
			},
		);
		return "anchor_unavailable";
	}
}

/**
 * Atomically spend an operator approval for this exact call.
 *
 * Single use holds even against a rollback of the store file: the spend is
 * recorded in the consumption ledger (the OS vault by default) and checked there,
 * so restoring an older copy of `approvals.json` with `uses: 0` does not release
 * the call again.
 *
 * Never throws: every failure (missing, expired, edited, mismatched, already
 * spent, store, key or ledger unavailable) is a refusal, so the `ask` stays
 * blocked.
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
			const checked = checkApproval(record, key, input, now);
			if (checked !== "approved") return { approved: false, reason: checked };
			const spent = spendApproval(record, options, now);
			if (spent !== "approved") return { approved: false, reason: spent };
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

// ── External single-use tokens ─────────────────────────────────────────

export type ExternalSpendResult = "spent" | "already_used" | "unavailable";

/**
 * Spend a single-use token issued OUTSIDE this store (for example the nonce of a
 * dashboard approval token) in the same consumption ledger that makes operator
 * approvals single use.
 *
 * The spend runs under the store lock, is recorded in the ledger anchor (the OS
 * vault by default) and is read back, so it survives a rollback of any file the
 * agent can write and holds across connector processes. `domain` separates the
 * id spaces of different token kinds; `id` is the token's own unique value.
 * `expiresAtMs` is how long the spend must be remembered: after that the token is
 * rejected on its own expiry.
 *
 * Never throws: a missing, corrupt, full or non-persisting ledger is reported as
 * `unavailable`, which the caller must treat as "not approved" (fail closed).
 */
export async function spendExternalApprovalToken(
	domain: string,
	id: string,
	expiresAtMs: number,
	options: OperatorApprovalStoreOptions = {},
): Promise<ExternalSpendResult> {
	if (!domain || !id || !Number.isFinite(expiresAtMs)) return "unavailable";
	const ledgerId = externalLedgerId(domain, id);
	try {
		return await withStoreLock(operatorApprovalStorePath(options), async () =>
			spendInLedger(requireAnchor(options), ledgerId, expiresAtMs, nowMs(options)),
		);
	} catch (error) {
		(options.logger ?? nullLogger).warn(
			"Approval consumption ledger unavailable; external approval not applied",
			{ error: error instanceof Error ? error.message : String(error) },
		);
		return "unavailable";
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
			// Like approvals, a grant is spent in the ledger too, so restoring an older
			// store cannot turn one grant into repeated allowlist entries.
			const spent = spendInLedger(
				requireAnchor(options),
				grantConsumptionId(record, digest),
				Date.parse(record.expires_at),
				now,
			);
			if (spent !== "spent") return false;
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

// ── Other operator-authored records ─────────────────────────────────────

/**
 * Sign an operator-authored record (for example a detection exception) with the
 * per-install approval key, creating the key on first use. OPERATOR ONLY: call
 * it from a TTY-confirmed CLI command, never from a connector. Also requires a
 * working consumption ledger, because revocations of such records are kept
 * there. Throws {@link OperatorApprovalError} when either is unavailable.
 */
export function signOperatorRecord(
	kind: OperatorRecordKind,
	record: object,
	options: OperatorApprovalStoreOptions = {},
): string {
	const key = requireKey(options, true);
	readLedger(requireAnchor(options));
	return computeMac(key.key, kind, record);
}

/**
 * Whether an operator-authored record carries a valid MAC under the approval
 * key. False when the key is unavailable (fail closed: an unverifiable record
 * is never honoured).
 */
export function verifyOperatorRecord(
	kind: OperatorRecordKind,
	record: { mac: string },
	options: OperatorApprovalStoreOptions = {},
): boolean {
	if (!DIGEST.test(record.mac)) return false;
	const key = loadKey(options, false);
	return !!key && macMatches(key.key, kind, record);
}

function externalLedgerId(domain: string, id: string): string {
	return sha256(`external\n${domain}\n${id}`).slice(0, 32);
}

/**
 * Record that an operator revoked the record `id` of `domain`, in the same
 * OS-vault ledger that makes approvals single use. A restored copy of a store
 * file therefore cannot bring a revoked record back. Remembered until
 * `expiresAtMs`, after which the record is void on its own expiry anyway.
 */
export async function recordOperatorRevocation(
	domain: string,
	id: string,
	expiresAtMs: number,
	options: OperatorApprovalStoreOptions = {},
): Promise<ExternalSpendResult> {
	return spendExternalApprovalToken(domain, id, expiresAtMs, options);
}

/**
 * Whether `id` of `domain` was revoked (see {@link recordOperatorRevocation}).
 * Throws {@link OperatorApprovalError} when the ledger cannot be read; callers
 * must then treat the record as not usable.
 */
export function isOperatorRevoked(
	domain: string,
	id: string,
	options: OperatorApprovalStoreOptions = {},
): boolean {
	const ledger = readLedger(requireAnchor(options));
	return Object.hasOwn(ledger.consumed, externalLedgerId(domain, id));
}

/** Run `fn` under the cross-process lock of the store file at `path`. */
export function withOperatorFileLock<T>(path: string, fn: () => Promise<T>): Promise<T> {
	return withStoreLock(path, fn);
}
