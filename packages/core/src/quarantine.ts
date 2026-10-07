/**
 * Auto-quarantine system for Singularity AIDR.
 * Moves suspicious files to a quarantine directory with metadata tracking.
 */

import { createHash, randomUUID } from "node:crypto";
import {
	type BigIntStats,
	constants,
	linkSync,
	lstatSync,
	readFileSync,
	rmdirSync,
	type Stats,
	unlinkSync,
} from "node:fs";
import {
	chmod,
	copyFile,
	link,
	lstat,
	mkdir,
	readdir,
	readFile,
	realpath,
	rename,
	rmdir,
	unlink,
	writeFile,
} from "node:fs/promises";
import { hostname } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { logIncident } from "./audit-log.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContentSync } from "./file-utils.js";
import { preparePrivateLocalDirectory } from "./private-local-file.js";
import type { ResponseAuditor } from "./response-audit.js";
import { normalizeAuthorizedBy } from "./response-worker-contract.js";
import type { Logger, LoggingConfig, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** Notification channel types for security team alerts */
export type NotifyChannel = "email" | "slack" | "webhook";

/**
 * Thrown when a quarantine is REFUSED before anything is moved.
 *
 * `code` is machine-readable: "symlink_refused" means the named path was a link to
 * somewhere else, and moving it would have relocated — or hidden — a file the
 * operator never named.
 */
export class QuarantineRefusedError extends Error {
	readonly code: string;

	constructor(reason: string, message: string) {
		super(message);
		this.name = "QuarantineRefusedError";
		this.code = reason;
	}
}

/**
 * Thrown when a quarantined file could not be deleted.
 *
 * The item deliberately stays in tracking and in the manifest: reporting a file as
 * permanently deleted while it is still on disk is the one outcome a quarantine
 * must never produce.
 */
export class QuarantineDeleteError extends Error {
	readonly code = "delete_failed";

	constructor(
		readonly itemId: string,
		readonly quarantinePath: string,
		detail: string,
	) {
		super(`Failed to delete quarantined file ${quarantinePath}: ${detail}`);
		this.name = "QuarantineDeleteError";
	}
}

/** Configuration for auto-quarantine behavior */
export interface QuarantineConfig {
	/** Directory where quarantined files are stored */
	quarantineDir: string;
	/** Number of days to retain quarantined files before auto-cleanup */
	retentionDays: number;
	/** Channels to notify when items are quarantined */
	notifyChannels: NotifyChannel[];
	/** Optional webhook URL for notifications */
	webhookUrl?: string;
	/** Optional Slack webhook URL */
	slackWebhookUrl?: string;
	/** Optional email configuration */
	emailConfig?: {
		to: string[];
		from: string;
		smtpHost?: string;
	};
}

/** Metadata for a quarantined item */
export interface QuarantinedItem {
	/** Unique identifier for the quarantined item */
	id: string;
	/** Original file path before quarantine */
	originalPath: string;
	/** Current path in quarantine directory */
	quarantinePath: string;
	/** Timestamp when item was quarantined */
	timestamp: Date;
	/** ID of the threat that triggered quarantine */
	threatId: string;
	/** Additional metadata about the quarantine event */
	metadata: Record<string, unknown>;
	/** File hash (SHA-256) for integrity verification */
	fileHash?: string;
	/** Original file size in bytes */
	fileSize?: number;
	/** Operator identity that authorized the quarantine, when one was supplied. */
	authorizedBy?: string;
}

type QuarantineAuditContext = {
	tool?: string;
	input?: string;
	verdict?: Verdict;
	authorizedBy?: string;
};

/** Quarantine manifest stored in the quarantine directory */
interface QuarantineManifest {
	version: number;
	items: QuarantinedItem[];
	lastUpdated: string;
}

const MANIFEST_VERSION = 1;
/** Appended to every payload name so the original extension cannot launch it. */
export const QUARANTINE_PAYLOAD_SUFFIX = ".quarantined";
/** Owner read-only, never executable. */
const QUARANTINE_PAYLOAD_MODE = 0o400;
const MANIFEST_FILENAME = "manifest.json";
const _METADATA_FILENAME = "metadata.json";
const manifestMutationTails = new Map<string, Promise<void>>();
const MANIFEST_LOCK_WAIT_MS = 60_000;
const MANIFEST_LOCK_STALE_MS = 30_000;
const MANIFEST_LOCK_POLL_MS = 25;
const PROCESS_STARTED_AT_MS = Math.max(0, Math.trunc(Date.now() - process.uptime() * 1_000));

interface ManifestLockOwner {
	v: 1;
	token: string;
	pid: number;
	host: string;
	acquiredAt: number;
	processStartedAtMs: number;
}

function isManifestLockOwner(value: unknown): value is ManifestLockOwner {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const owner = value as Partial<ManifestLockOwner>;
	return (
		owner.v === 1 &&
		typeof owner.token === "string" &&
		/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(owner.token) &&
		Number.isSafeInteger(owner.pid) &&
		(owner.pid ?? 0) > 0 &&
		typeof owner.host === "string" &&
		typeof owner.acquiredAt === "number" &&
		Number.isFinite(owner.acquiredAt) &&
		typeof owner.processStartedAtMs === "number" &&
		Number.isFinite(owner.processStartedAtMs)
	);
}

function manifestLockOwnerAlive(owner: ManifestLockOwner): boolean | null {
	if (owner.host !== hostname()) return null;
	if (owner.pid === process.pid) {
		return owner.processStartedAtMs === PROCESS_STARTED_AT_MS;
	}
	try {
		process.kill(owner.pid, 0);
	} catch (error) {
		const code = (error as NodeJS.ErrnoException)?.code;
		if (code === "ESRCH") return false;
		if (code === "EPERM") return true;
		return null;
	}
	return true;
}

function isPathWithin(root: string, target: string): boolean {
	const targetRelative = relative(resolve(root), resolve(target));
	return (
		targetRelative !== "" &&
		targetRelative !== ".." &&
		!targetRelative.startsWith(`..${sep}`) &&
		!isAbsolute(targetRelative)
	);
}

function isExpectedQuarantinePayloadPath(id: string, root: string, target: string): boolean {
	const targetRelative = relative(resolve(root), resolve(target));
	const parts = targetRelative.split(sep);
	return (
		parts.length === 4 &&
		/^\d{4}$/.test(parts[0] ?? "") &&
		/^(?:0[1-9]|1[0-2])$/.test(parts[1] ?? "") &&
		/^(?:0[1-9]|[12]\d|3[01])$/.test(parts[2] ?? "") &&
		parts[3]?.startsWith(`${id}_`) === true &&
		(parts[3]?.length ?? 0) > id.length + 1 &&
		!parts[3].endsWith(".metadata.json")
	);
}

function isValidManifestItem(item: unknown, quarantineRoot: string): item is QuarantinedItem {
	if (!item || typeof item !== "object" || Array.isArray(item)) return false;
	const candidate = item as Partial<QuarantinedItem>;
	const timestamp =
		candidate.timestamp instanceof Date
			? candidate.timestamp.getTime()
			: typeof candidate.timestamp === "string"
				? Date.parse(candidate.timestamp)
				: Number.NaN;
	return (
		typeof candidate.id === "string" &&
		/^[\da-f]{8}-[\da-f]{4}-[1-8][\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/i.test(candidate.id) &&
		typeof candidate.originalPath === "string" &&
		isAbsolute(candidate.originalPath) &&
		typeof candidate.quarantinePath === "string" &&
		isAbsolute(candidate.quarantinePath) &&
		isPathWithin(quarantineRoot, candidate.quarantinePath) &&
		isExpectedQuarantinePayloadPath(candidate.id, quarantineRoot, candidate.quarantinePath) &&
		Number.isFinite(timestamp) &&
		typeof candidate.threatId === "string" &&
		candidate.threatId.length > 0 &&
		!!candidate.metadata &&
		typeof candidate.metadata === "object" &&
		!Array.isArray(candidate.metadata) &&
		(candidate.fileHash === undefined || /^[\da-f]{64}$/i.test(candidate.fileHash)) &&
		(candidate.fileSize === undefined ||
			(Number.isSafeInteger(candidate.fileSize) && candidate.fileSize >= 0)) &&
		(candidate.authorizedBy === undefined || typeof candidate.authorizedBy === "string")
	);
}

function sameFileVersion(expected: BigIntStats, actual: BigIntStats): boolean {
	return (
		actual.isFile() &&
		!actual.isSymbolicLink() &&
		expected.ino > 0n &&
		actual.ino > 0n &&
		expected.dev === actual.dev &&
		expected.ino === actual.ino &&
		expected.size === actual.size &&
		expected.mtimeNs === actual.mtimeNs
	);
}

function sameFileIdentity(expected: BigIntStats, actual: BigIntStats): boolean {
	return (
		expected.isFile() &&
		!expected.isSymbolicLink() &&
		actual.isFile() &&
		!actual.isSymbolicLink() &&
		expected.ino > 0n &&
		actual.ino > 0n &&
		expected.dev === actual.dev &&
		expected.ino === actual.ino
	);
}

function sameStableFileVersion(expected: BigIntStats, actual: BigIntStats): boolean {
	return sameFileVersion(expected, actual) && expected.ctimeNs === actual.ctimeNs;
}

function cloneQuarantinedItem(item: QuarantinedItem): QuarantinedItem {
	return {
		...item,
		timestamp: new Date(item.timestamp),
		metadata: { ...item.metadata },
	};
}

/**
 * Auto-quarantine manager for isolating suspicious files.
 * Provides quarantine, restore, delete, and notification capabilities.
 */
export class AutoQuarantine {
	private items = new Map<string, QuarantinedItem>();
	private manifestPath: string;
	private logger: Logger;
	private loggingConfig?: LoggingConfig;

	/**
	 * Creates an AutoQuarantine instance.
	 * @param config - Quarantine configuration
	 * @param logger - Optional logger for operations
	 * @param loggingConfig - Optional logging configuration for audit events
	 * @param auditor - Optional response auditor for comprehensive response logging
	 */
	constructor(
		private config: QuarantineConfig,
		logger?: Logger,
		loggingConfig?: LoggingConfig,
		private auditor?: ResponseAuditor,
	) {
		this.logger = logger ?? nullLogger;
		this.loggingConfig = loggingConfig;
		this.manifestPath = join(resolvePath(config.quarantineDir), MANIFEST_FILENAME);
		// These MUST complete before the constructor returns. They used to be
		// `async` and called without `await`, so `list()`/`restore()` on a fresh
		// instance observed an empty map until an unrelated microtask happened to
		// run, and a failure surfaced as an unhandled rejection.
		this.ensureQuarantineDirSync();
		this.loadManifestSync();
	}

	/**
	 * Quarantine a suspicious file by moving it to the quarantine directory.
	 * @param filePath - Path to the file to quarantine
	 * @param threatId - ID of the detected threat
	 * @param metadata - Optional additional metadata
	 * @param auditContext - Optional audit context for response logging
	 * @returns The quarantined item metadata
	 */
	quarantine(
		filePath: string,
		threatId: string,
		metadata?: Record<string, unknown>,
		auditContext?: QuarantineAuditContext,
	): Promise<QuarantinedItem> {
		return this.serializeMutations(() =>
			this.quarantineExclusive(filePath, threatId, metadata, auditContext),
		);
	}

	private async quarantineExclusive(
		filePath: string,
		threatId: string,
		metadata?: Record<string, unknown>,
		auditContext?: QuarantineAuditContext,
	): Promise<QuarantinedItem> {
		const resolvedPath = resolvePath(filePath);
		const quarantineDir = resolvePath(this.config.quarantineDir);
		const authorizedBy = normalizeAuthorizedBy(auditContext?.authorizedBy);
		const fileStats = await this.requireQuarantineSource(
			resolvedPath,
			filePath,
			threatId,
			auditContext,
			authorizedBy,
		);

		// Generate unique ID and compute file hash
		const id = randomUUID();
		const fileHash = await this.computeFileHash(resolvedPath);
		const fileSize = Number(fileStats.size);

		// Create quarantine subdirectory structure based on date. Mode 0o700, the same
		// as a snapshot directory: a quarantine vault holds hostile content and must
		// not be world-traversable.
		const now = new Date();
		const dateDir = join(
			quarantineDir,
			now.getFullYear().toString(),
			(now.getMonth() + 1).toString().padStart(2, "0"),
			now.getDate().toString().padStart(2, "0"),
		);
		preparePrivateLocalDirectory(dateDir);

		// Move file to quarantine (using copy + delete for cross-device safety). The
		// `.quarantined` suffix keeps the payload from being launched by its original
		// extension (`.exe`, `.sh`, `.ps1`, ...) from a file manager or a shell glob.
		const quarantineFilename = `${id}_${basename(resolvedPath)}${QUARANTINE_PAYLOAD_SUFFIX}`;
		const quarantinePath = join(dateDir, quarantineFilename);
		await this.assertQuarantinePath(quarantinePath);
		const metadataPath = join(dateDir, `${quarantineFilename}.metadata.json`);
		const item: QuarantinedItem = {
			id,
			originalPath: resolvedPath,
			quarantinePath,
			timestamp: now,
			threatId,
			metadata: { ...(metadata ?? {}), original_mode: Number(fileStats.mode) & 0o777 },
			fileHash,
			fileSize,
			...(authorizedBy ? { authorizedBy } : {}),
		};

		await this.persistQuarantineRecord(item, metadataPath, auditContext, filePath, authorizedBy);
		await this.removeOriginalAfterPersist(item, fileStats, filePath, auditContext, authorizedBy);

		// Log to audit and notify security team
		await this.logQuarantineEvent(item);
		await this.notify(item);

		// Log response action if auditor and context are available
		if (this.auditor && auditContext?.verdict) {
			await this.auditor.log({
				action: "quarantine",
				threatId,
				tool: auditContext.tool ?? "unknown",
				input: auditContext.input ?? filePath,
				verdict: auditContext.verdict,
				responseTaken: "quarantine",
				metadata: {
					quarantineId: id,
					notificationSent: this.config.notifyChannels.length > 0,
				},
				outcome: "success",
				authorizedBy,
			});
		}

		this.logger.info(`File quarantined: ${resolvedPath} -> ${quarantinePath}`, {
			id,
			threatId,
			fileHash,
			fileSize,
		});

		return cloneQuarantinedItem(item);
	}

	private async requireQuarantineSource(
		resolvedPath: string,
		inputPath: string,
		threatId: string,
		auditContext: QuarantineAuditContext | undefined,
		authorizedBy: string | undefined,
	): Promise<BigIntStats> {
		// lstat refuses a link instead of moving its potentially external target.
		const stats = await lstat(resolvedPath, { bigint: true }).catch(() => null);
		if (stats?.isSymbolicLink()) {
			const reason = "symlink_refused";
			const error = `Refusing to quarantine a symlink: ${resolvedPath}`;
			await this.logQuarantineFailure({
				threatId,
				inputPath,
				auditContext,
				authorizedBy,
				error,
				metadata: { quarantineId: undefined, reason },
			});
			throw new QuarantineRefusedError(reason, error);
		}
		if (!stats?.isFile()) {
			const error = `File not found or not accessible: ${resolvedPath}`;
			await this.logQuarantineFailure({
				threatId,
				inputPath,
				auditContext,
				authorizedBy,
				error,
				metadata: { quarantineId: undefined },
			});
			throw new Error(error);
		}
		if (stats.size > BigInt(Number.MAX_SAFE_INTEGER)) {
			const error = `File is too large to represent safely in quarantine metadata: ${resolvedPath}`;
			await this.logQuarantineFailure({
				threatId,
				inputPath,
				auditContext,
				authorizedBy,
				error,
				metadata: { quarantineId: undefined },
			});
			throw new Error(error);
		}
		return stats;
	}

	private async persistQuarantineRecord(
		item: QuarantinedItem,
		metadataPath: string,
		auditContext: QuarantineAuditContext | undefined,
		inputPath: string,
		authorizedBy: string | undefined,
	): Promise<void> {
		let copied = false;
		let metadataWritten = false;
		try {
			try {
				await copyFile(item.originalPath, item.quarantinePath, constants.COPYFILE_EXCL);
			} catch (error) {
				if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") {
					await unlink(item.quarantinePath).catch(() => {});
				}
				throw error;
			}
			copied = true;
			// Never executable, owner read-only. Not on Windows: a read-only attribute
			// would make the later delete fail, and the vault directory ACL already
			// limits it to the owner.
			if (process.platform !== "win32") await chmod(item.quarantinePath, QUARANTINE_PAYLOAD_MODE);
			if ((await this.computeFileHash(item.quarantinePath)) !== item.fileHash) {
				throw new Error("Source file changed while it was being quarantined");
			}
			await atomicWriteJson(metadataPath, { ...item, timestamp: item.timestamp.toISOString() });
			metadataWritten = true;

			// Commit tracking before deleting the source; a failure leaves source intact.
			this.items.set(item.id, item);
			await this.saveManifest();
		} catch (error) {
			this.items.delete(item.id);
			if (metadataWritten) await unlink(metadataPath).catch(() => {});
			if (copied) await unlink(item.quarantinePath).catch(() => {});
			const errorMsg = `Failed to persist quarantine before removing original: ${error instanceof Error ? error.message : String(error)}`;
			await this.logQuarantineFailure({
				threatId: item.threatId,
				inputPath,
				auditContext,
				authorizedBy,
				error: errorMsg,
				metadata: { quarantineId: undefined },
			});
			throw new Error(errorMsg);
		}
	}

	private async removeOriginalAfterPersist(
		item: QuarantinedItem,
		expectedSourceStats: BigIntStats,
		inputPath: string,
		auditContext: QuarantineAuditContext | undefined,
		authorizedBy: string | undefined,
	): Promise<void> {
		// Rename the current directory entry into a fresh, private sibling directory
		// before inspecting it. That closes the copy-then-unlink race: if another
		// process replaced or modified the source after our copy, the staged bytes
		// fail identity/hash verification and are preserved rather than discarded.
		const stagingDir = join(
			dirname(item.originalPath),
			`.${basename(item.originalPath)}.aidr-${item.id}.staging`,
		);
		const stagedPath = join(stagingDir, basename(item.originalPath));
		let staged = false;
		try {
			await mkdir(stagingDir, { mode: 0o700 });
			await rename(item.originalPath, stagedPath);
			staged = true;
			const stagedStats = await lstat(stagedPath, { bigint: true });
			if (!sameFileVersion(expectedSourceStats, stagedStats)) {
				throw new Error("Original file identity changed after it was copied");
			}
			if ((await this.computeFileHash(stagedPath)) !== item.fileHash) {
				throw new Error("Original file contents changed after they were copied");
			}
			const finalStats = await lstat(stagedPath, { bigint: true });
			if (
				!sameStableFileVersion(stagedStats, finalStats) ||
				(await this.computeFileHash(stagedPath)) !== item.fileHash
			) {
				throw new Error("Original file changed during final quarantine verification");
			}
			await unlink(stagedPath);
			staged = false;
			await rmdir(stagingDir).catch(() => {});
		} catch (error) {
			const recovery = staged
				? await this.recoverStagedOriginal(stagedPath, item.originalPath, stagingDir)
				: `original remains at ${item.originalPath}`;
			const errorMsg = `Quarantine ${item.id} is recorded at ${item.quarantinePath}, but ${recovery}: ${error instanceof Error ? error.message : String(error)}`;
			await this.logQuarantineFailure({
				threatId: item.threatId,
				inputPath,
				auditContext,
				authorizedBy,
				error: errorMsg,
				metadata: { quarantineId: item.id },
			});
			throw new Error(errorMsg);
		}
	}

	private async recoverStagedOriginal(
		stagedPath: string,
		originalPath: string,
		stagingDir: string,
	): Promise<string> {
		const stagedStats = await lstat(stagedPath, { bigint: true }).catch(() => null);
		if (!stagedStats?.isFile() || stagedStats.isSymbolicLink()) {
			return `original preserved at ${stagedPath}; recovery requires manual inspection`;
		}
		try {
			await link(stagedPath, originalPath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code === "EEXIST") {
				const originalStats = await lstat(originalPath, { bigint: true }).catch(() => null);
				if (originalStats && sameFileIdentity(stagedStats, originalStats)) {
					await unlink(stagedPath).catch(() => {});
					await rmdir(stagingDir).catch(() => {});
					return `original remains at ${originalPath}`;
				}
			}
			return `original preserved at ${stagedPath}; destination was not overwritten at ${originalPath}`;
		}
		const originalStats = await lstat(originalPath, { bigint: true }).catch(() => null);
		const stagedAfterLink = await lstat(stagedPath, { bigint: true }).catch(() => null);
		if (
			!originalStats ||
			!stagedAfterLink ||
			!sameFileIdentity(stagedStats, originalStats) ||
			!sameFileIdentity(stagedStats, stagedAfterLink)
		) {
			return `recovery copy created at ${originalPath}; staged data preserved at ${stagedPath}`;
		}
		await unlink(stagedPath);
		await rmdir(stagingDir).catch(() => {});
		return `original remains at ${originalPath}`;
	}

	private async logQuarantineFailure(params: {
		threatId: string;
		inputPath: string;
		auditContext: QuarantineAuditContext | undefined;
		authorizedBy: string | undefined;
		error: string;
		metadata: { quarantineId?: string; reason?: string };
	}): Promise<void> {
		if (!this.auditor || !params.auditContext?.verdict) return;
		await this.auditor.log({
			action: "quarantine",
			threatId: params.threatId,
			tool: params.auditContext.tool ?? "unknown",
			input: params.auditContext.input ?? params.inputPath,
			verdict: params.auditContext.verdict,
			responseTaken: "quarantine",
			metadata: params.metadata,
			outcome: "failure",
			error: params.error,
			authorizedBy: params.authorizedBy,
		});
	}

	/**
	 * Restore a quarantined file to its original location.
	 * @param itemId - ID of the quarantined item to restore
	 */
	restore(itemId: string): Promise<void> {
		return this.serializeMutations(() => this.restoreExclusive(itemId));
	}

	private async restoreExclusive(itemId: string): Promise<void> {
		const item = this.items.get(itemId);
		if (!item) {
			throw new Error(`Quarantined item not found: ${itemId}`);
		}

		this.validateItemForUse(item);
		if (!item.fileHash || !/^[0-9a-f]{64}$/i.test(item.fileHash)) {
			throw new Error(`Cannot safely restore quarantined item without a valid hash: ${itemId}`);
		}

		await this.assertQuarantinePath(item.quarantinePath);
		const payload = await this.getRestorePayload(item);
		const currentHash = payload.hash;
		if (currentHash !== item.fileHash) {
			throw new Error(
				`File integrity check failed for quarantined item: ${itemId}. Hash mismatch detected.`,
			);
		}

		// A prior retry may already have restored identical bytes after a manifest
		// failure; unrelated files and symlinks are never treated as that retry.
		try {
			if (payload.exists) {
				await mkdir(dirname(item.originalPath), { recursive: true });
				await this.restoreOriginalCopy(item, currentHash);
			}
		} catch (error) {
			throw new Error(
				`Failed to restore file: ${error instanceof Error ? error.message : String(error)}`,
			);
		}

		// Remove the vault payload while the manifest still tracks the item. If
		// cleanup fails, the restored original and its tracked vault copy both remain.
		if (payload.exists) await this.removeVerifiedRestorePayload(item);

		this.items.delete(itemId);
		try {
			await this.saveManifest();
		} catch (error) {
			this.items.set(itemId, item);
			throw new Error(
				`File was restored but quarantine tracking could not be updated; the restored original remains and retry is safe: ${error instanceof Error ? error.message : String(error)}`,
			);
		}

		// Metadata is auxiliary; the durable manifest and payload are already handled.
		const metadataPath = `${item.quarantinePath}.metadata.json`;
		await unlink(metadataPath).catch(() => {});

		// Log restore event
		if (this.loggingConfig) {
			await logIncident(this.loggingConfig, {
				type: "quarantine_restore",
				timestamp: new Date().toISOString(),
				item_id: itemId,
				original_path: item.originalPath,
				threat_id: item.threatId,
			});
		}

		this.logger.info(`File restored from quarantine: ${item.originalPath}`, { itemId });
	}

	private async getRestorePayload(
		item: QuarantinedItem,
	): Promise<{ exists: boolean; hash: string }> {
		const payload = await this.lstatRegularFileOrMissing(item.quarantinePath);
		const original = await this.lstatRegularFileOrMissing(item.originalPath);
		const hashPath = payload ? item.quarantinePath : original ? item.originalPath : null;
		if (!hashPath) throw new Error(`No restorable copy exists for quarantined item: ${item.id}`);
		return { exists: payload !== null, hash: await this.computeFileHash(hashPath) };
	}

	private async lstatRegularFileOrMissing(filePath: string): Promise<Stats | null> {
		const stats = await lstat(filePath).catch((error) => {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return null;
			throw error;
		});
		if (stats && (!stats.isFile() || stats.isSymbolicLink())) {
			throw new Error(`Refusing to use non-regular file: ${filePath}`);
		}
		return stats;
	}

	private async removeVerifiedRestorePayload(item: QuarantinedItem): Promise<void> {
		const stats = await this.lstatRegularFileOrMissing(item.quarantinePath);
		if (!stats || (await this.computeFileHash(item.quarantinePath)) !== item.fileHash) {
			throw new Error(`Quarantine payload changed during restore: ${item.quarantinePath}`);
		}
		await this.unlinkPayloadFile(item.quarantinePath);
	}

	private async restoreOriginalCopy(item: QuarantinedItem, expectedHash: string): Promise<void> {
		try {
			await copyFile(item.quarantinePath, item.originalPath, constants.COPYFILE_EXCL);
			// The payload was read-only and non-executable in the vault; give the
			// released file back the permission bits it had when it was quarantined.
			const originalMode = item.metadata.original_mode;
			if (
				process.platform !== "win32" &&
				typeof originalMode === "number" &&
				Number.isInteger(originalMode)
			) {
				await chmod(item.originalPath, originalMode & 0o777).catch(() => undefined);
			}
			return;
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") throw error;
			const originalStats = await lstat(item.originalPath).catch(() => null);
			if (!originalStats?.isFile() || originalStats.isSymbolicLink()) throw error;
			if ((await this.computeFileHash(item.originalPath)) !== expectedHash) throw error;
		}
	}

	private async unlinkPayloadFile(filePath: string): Promise<void> {
		await unlink(filePath);
	}

	/**
	 * Permanently delete a quarantined file.
	 *
	 * A failure to remove the file is REPORTED and the item stays tracked. The old
	 * behaviour swallowed any `unlink` error, deleted the tracking entry and logged
	 * the item as permanently deleted — telling the operator a hostile file was gone
	 * while it was still in the vault.
	 *
	 * The one exception is `ENOENT`: the file is provably already absent, so the
	 * item's removal is truthful rather than a claim about something that is still
	 * there.
	 *
	 * @param itemId - ID of the quarantined item to delete
	 * @throws QuarantineDeleteError when the quarantined file could not be removed
	 */
	delete(itemId: string): Promise<void> {
		return this.serializeMutations(() => this.deleteExclusive(itemId));
	}

	private async deleteExclusive(itemId: string): Promise<void> {
		const item = this.items.get(itemId);
		if (!item) {
			throw new Error(`Quarantined item not found: ${itemId}`);
		}

		this.validateItemForUse(item);
		await this.assertQuarantinePath(item.quarantinePath);

		// Refuse symlinks, directories, and other unexpected entries rather than
		// unlinking a path that may have been redirected after the manifest loaded.
		const payloadStats = await lstat(item.quarantinePath).catch((error) => {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return null;
			throw error;
		});
		if (payloadStats && (!payloadStats.isFile() || payloadStats.isSymbolicLink())) {
			throw new QuarantineDeleteError(
				itemId,
				item.quarantinePath,
				"refusing to remove a non-regular filesystem entry",
			);
		}

		// Delete quarantined file
		try {
			await unlink(item.quarantinePath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code !== "ENOENT") {
				this.logger.error(`Could not delete quarantined file: ${item.quarantinePath}`, {
					itemId,
					error: String(error),
				});
				// Nothing is forgotten: the item and its manifest entry are untouched.
				throw new QuarantineDeleteError(
					itemId,
					item.quarantinePath,
					error instanceof Error ? error.message : String(error),
				);
			}
			this.logger.warn(`Quarantined file was already absent: ${item.quarantinePath}`, {
				itemId,
			});
		}

		// Remove from tracking only after deleting the payload, and restore the
		// in-memory entry if the manifest commit fails so a retry remains possible.
		this.items.delete(itemId);
		try {
			await this.saveManifest();
		} catch (error) {
			this.items.set(itemId, item);
			throw new Error(
				`Quarantined payload was removed but tracking could not be updated; retry the delete: ${error instanceof Error ? error.message : String(error)}`,
			);
		}

		const metadataPath = `${item.quarantinePath}.metadata.json`;
		await unlink(metadataPath).catch(() => {});

		// Log deletion event
		if (this.loggingConfig) {
			await logIncident(this.loggingConfig, {
				type: "quarantine_delete",
				timestamp: new Date().toISOString(),
				item_id: itemId,
				original_path: item.originalPath,
				threat_id: item.threatId,
			});
		}

		this.logger.info(`Quarantined file permanently deleted: ${itemId}`, {
			originalPath: item.originalPath,
			threatId: item.threatId,
		});
	}

	/**
	 * Get a list of all quarantined items.
	 * @returns Array of quarantined items
	 */
	list(): QuarantinedItem[] {
		return Array.from(this.items.values())
			.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
			.map(cloneQuarantinedItem);
	}

	/**
	 * Get a specific quarantined item by ID.
	 * @param itemId - ID of the quarantined item
	 * @returns The quarantined item or undefined if not found
	 */
	get(itemId: string): QuarantinedItem | undefined {
		const item = this.items.get(itemId);
		return item ? cloneQuarantinedItem(item) : undefined;
	}

	/**
	 * Clean up expired quarantined items based on retention policy.
	 * @returns Array of IDs that were cleaned up
	 */
	async cleanupExpired(): Promise<string[]> {
		// 0 means "keep everything"; without this every item would be "expired".
		if (!(this.config.retentionDays > 0)) return [];
		const now = new Date();
		const retentionMs = this.config.retentionDays * 24 * 60 * 60 * 1000;
		const expiredIds: string[] = [];

		for (const [id, item] of this.items.entries()) {
			if (now.getTime() - item.timestamp.getTime() > retentionMs) {
				try {
					await this.delete(id);
					expiredIds.push(id);
				} catch (error) {
					this.logger.warn(`Failed to clean up expired quarantined item: ${id}`, {
						error: String(error),
					});
				}
			}
		}

		if (expiredIds.length > 0) {
			this.logger.info(`Cleaned up ${expiredIds.length} expired quarantined items`);
		}

		return expiredIds;
	}

	/** Total size of the tracked payloads, in bytes. */
	totalBytes(): number {
		let total = 0;
		for (const item of this.items.values()) total += item.fileSize ?? 0;
		return total;
	}

	/**
	 * Keep the vault within `maxTotalBytes` by deleting the OLDEST items first.
	 * 0 disables the bound. Returns the deleted ids; an item that cannot be deleted
	 * stays tracked (and is reported by `delete`) rather than being forgotten.
	 */
	async enforceSizeLimit(maxTotalBytes: number): Promise<string[]> {
		if (!(maxTotalBytes > 0)) return [];
		const deleted: string[] = [];
		const oldestFirst = Array.from(this.items.values()).sort(
			(a, b) => a.timestamp.getTime() - b.timestamp.getTime(),
		);
		for (const item of oldestFirst) {
			if (this.totalBytes() <= maxTotalBytes) break;
			try {
				await this.delete(item.id);
				deleted.push(item.id);
			} catch (error) {
				this.logger.warn(`Failed to evict quarantined item over the size bound: ${item.id}`, {
					error: String(error),
				});
			}
		}
		return deleted;
	}

	/**
	 * Ensure the quarantine directory exists (synchronous: must finish before the
	 * constructor returns so the instance is usable immediately).
	 */
	private ensureQuarantineDirSync(): void {
		const quarantineDir = resolvePath(this.config.quarantineDir);
		preparePrivateLocalDirectory(quarantineDir);
	}

	/**
	 * Load the quarantine manifest from disk (synchronous, see above).
	 */
	private loadManifestSync(): void {
		this.items.clear();
		let content: string;
		try {
			content = getFileContentSync(this.manifestPath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return;
			throw new Error(
				`Cannot read quarantine manifest ${this.manifestPath}: ${error instanceof Error ? error.message : String(error)}`,
			);
		}

		let manifest: QuarantineManifest;
		try {
			manifest = JSON.parse(content) as QuarantineManifest;
		} catch (error) {
			throw new Error(
				`Quarantine manifest is corrupt at ${this.manifestPath}: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		if (
			!manifest ||
			typeof manifest !== "object" ||
			manifest.version !== MANIFEST_VERSION ||
			!Array.isArray(manifest.items)
		) {
			throw new Error(
				`Quarantine manifest has an unsupported or invalid format: ${this.manifestPath}`,
			);
		}

		const quarantineRoot = resolve(resolvePath(this.config.quarantineDir));
		for (const item of manifest.items) {
			if (!isValidManifestItem(item, quarantineRoot)) {
				throw new Error(`Quarantine manifest contains an invalid item: ${this.manifestPath}`);
			}
			if (this.items.has(item.id)) {
				throw new Error(`Quarantine manifest contains a duplicate item: ${this.manifestPath}`);
			}
			this.items.set(item.id, {
				...item,
				timestamp: new Date(item.timestamp),
			});
		}
	}

	/**
	 * Quarantine commits its manifest before renaming the source into a private
	 * sibling staging directory. If the process exits between that rename and
	 * final removal, the committed item's id makes the staging path deterministic.
	 * On startup, discard a staged duplicate only when its bytes are already safely
	 * present in the vault; otherwise put the entry back at the original path.
	 */
	private recoverInterruptedSourceMovesSync(): void {
		for (const item of this.items.values()) this.recoverInterruptedSourceMoveSync(item);
	}

	private recoverInterruptedSourceMoveSync(item: QuarantinedItem): void {
		const stagingDir = join(
			dirname(item.originalPath),
			`.${basename(item.originalPath)}.aidr-${item.id}.staging`,
		);
		const stagedPath = join(stagingDir, basename(item.originalPath));
		const stagedStats = this.lstatIfPresentSync(stagedPath);
		if (!stagedStats) return;

		const originalStats = this.lstatIfPresentSync(item.originalPath);
		if (originalStats) {
			if (
				stagedStats.isFile() &&
				!stagedStats.isSymbolicLink() &&
				sameFileIdentity(
					lstatSync(stagedPath, { bigint: true }),
					lstatSync(item.originalPath, { bigint: true }),
				)
			) {
				unlinkSync(stagedPath);
				rmdirSync(stagingDir);
				return;
			}
			throw new Error(
				`Quarantine recovery found both an original and staged source for ${item.id}; preserve and inspect ${stagedPath}`,
			);
		}

		if (this.stagedSourceMatchesVaultSync(item, stagedPath, stagedStats)) {
			unlinkSync(stagedPath);
		} else {
			this.restoreStagedSourceSync(item, stagedPath, stagedStats);
		}
		rmdirSync(stagingDir);
	}

	private lstatIfPresentSync(filePath: string): BigIntStats | null {
		try {
			return lstatSync(filePath, { bigint: true });
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return null;
			throw error;
		}
	}

	private stagedSourceMatchesVaultSync(
		item: QuarantinedItem,
		stagedPath: string,
		stagedStats: BigIntStats,
	): boolean {
		if (!stagedStats.isFile() || stagedStats.isSymbolicLink() || !item.fileHash) return false;
		try {
			const vaultStats = lstatSync(item.quarantinePath, { bigint: true });
			if (!vaultStats.isFile() || vaultStats.isSymbolicLink()) return false;
			const stagedDigest = createHash("sha256").update(readFileSync(stagedPath)).digest("hex");
			const vaultDigest = createHash("sha256")
				.update(readFileSync(item.quarantinePath))
				.digest("hex");
			return (
				stagedDigest === item.fileHash &&
				vaultDigest === item.fileHash &&
				sameStableFileVersion(stagedStats, lstatSync(stagedPath, { bigint: true })) &&
				sameStableFileVersion(vaultStats, lstatSync(item.quarantinePath, { bigint: true }))
			);
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return false;
			throw new Error(
				`Cannot verify interrupted quarantine source ${stagedPath}: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	private restoreStagedSourceSync(
		item: QuarantinedItem,
		stagedPath: string,
		stagedStats: BigIntStats,
	): void {
		if (!stagedStats.isFile() || stagedStats.isSymbolicLink()) {
			throw new Error(
				`Quarantine recovery found a non-regular staged source for ${item.id}; preserve and inspect ${stagedPath}`,
			);
		}
		const stagedIdentity = lstatSync(stagedPath, { bigint: true });
		try {
			linkSync(stagedPath, item.originalPath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") throw error;
			throw new Error(
				`Quarantine recovery could not restore ${item.id} without overwriting ${item.originalPath}; preserve and inspect ${stagedPath}`,
			);
		}
		const originalStats = lstatSync(item.originalPath, { bigint: true });
		const stagedAfterLink = lstatSync(stagedPath, { bigint: true });
		if (
			!sameFileIdentity(stagedIdentity, originalStats) ||
			!sameFileIdentity(stagedIdentity, stagedAfterLink)
		) {
			throw new Error(
				`Quarantine recovery changed during restore; preserve both ${item.originalPath} and ${stagedPath}`,
			);
		}
		unlinkSync(stagedPath);
	}

	/**
	 * Save the quarantine manifest to disk.
	 */
	private async saveManifest(): Promise<void> {
		const manifest: QuarantineManifest = {
			version: MANIFEST_VERSION,
			items: this.list().map((item) => ({
				...item,
				timestamp: item.timestamp,
			})),
			lastUpdated: new Date().toISOString(),
		};

		await atomicWriteJson(this.manifestPath, manifest);
	}

	private validateItemForUse(item: QuarantinedItem): void {
		if (!isValidManifestItem(item, resolve(resolvePath(this.config.quarantineDir)))) {
			throw new Error("Refusing to use invalid quarantine item");
		}
	}

	private async assertQuarantinePath(filePath: string): Promise<void> {
		const root = await realpath(resolve(resolvePath(this.config.quarantineDir)));
		const parent = await realpath(dirname(filePath)).catch((error) => {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return null;
			throw error;
		});
		if (!parent) return;
		const parentRelative = relative(root, parent);
		if (
			parentRelative === ".." ||
			parentRelative.startsWith(`..${sep}`) ||
			isAbsolute(parentRelative)
		) {
			throw new Error(`Quarantine payload resolves outside its vault: ${filePath}`);
		}
	}

	private async acquireManifestLock(): Promise<{
		lockPath: string;
		ownerPath: string;
		token: string;
	}> {
		const lockPath = `${this.manifestPath}.lock`;
		const token = randomUUID();
		const ownerPath = join(lockPath, `owner-${token}.json`);
		const temporary = `${lockPath}.owner-${token}.tmp`;
		const owner: ManifestLockOwner = {
			v: 1,
			token,
			pid: process.pid,
			host: hostname(),
			acquiredAt: Date.now(),
			processStartedAtMs: PROCESS_STARTED_AT_MS,
		};
		const deadline = Date.now() + MANIFEST_LOCK_WAIT_MS;

		for (;;) {
			let directoryCreated = false;
			try {
				await mkdir(lockPath, { mode: 0o700 });
				directoryCreated = true;
				await writeFile(temporary, `${JSON.stringify(owner)}\n`, { flag: "wx", mode: 0o600 });
				await rename(temporary, ownerPath);
				return { lockPath, ownerPath, token };
			} catch (error) {
				await unlink(temporary).catch(() => {});
				if (directoryCreated) {
					await unlink(ownerPath).catch(() => {});
					await rmdir(lockPath).catch(() => {});
					throw error;
				}
				if ((error as NodeJS.ErrnoException)?.code !== "EEXIST") throw error;
				if (await this.recoverAbandonedManifestLock(lockPath)) continue;
				if (Date.now() >= deadline) throw new Error("Quarantine manifest lock is unavailable");
				await delay(MANIFEST_LOCK_POLL_MS);
			}
		}
	}

	private async recoverAbandonedManifestLock(lockPath: string): Promise<boolean> {
		const lockStats = await lstat(lockPath).catch((error) => {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return null;
			throw error;
		});
		if (
			!lockStats ||
			Date.now() - lockStats.mtimeMs <= MANIFEST_LOCK_STALE_MS ||
			!lockStats.isDirectory() ||
			lockStats.isSymbolicLink()
		) {
			return false;
		}

		const entries = await readdir(lockPath);
		if (entries.length === 0) return this.removeManifestLockDirectory(lockPath);
		const marker = entries.length === 1 ? entries[0] : undefined;
		if (!marker || !/^owner-[\da-f-]+\.json$/i.test(marker)) return false;
		const owner = await this.readManifestLockOwner(lockPath, marker);
		if (
			!owner ||
			marker !== `owner-${owner.token}.json` ||
			manifestLockOwnerAlive(owner) !== false
		) {
			return false;
		}
		await unlink(join(lockPath, marker));
		return this.removeManifestLockDirectory(lockPath);
	}

	private async readManifestLockOwner(
		lockPath: string,
		marker: string,
	): Promise<ManifestLockOwner | null> {
		try {
			const owner: unknown = JSON.parse(await readFile(join(lockPath, marker), "utf8"));
			return isManifestLockOwner(owner) ? owner : null;
		} catch {
			return null;
		}
	}

	private async removeManifestLockDirectory(lockPath: string): Promise<boolean> {
		try {
			await rmdir(lockPath);
			return true;
		} catch (error) {
			const code = (error as NodeJS.ErrnoException)?.code;
			if (code === "ENOENT") return true;
			if (code === "ENOTEMPTY" || code === "EEXIST") return false;
			throw error;
		}
	}

	private async releaseManifestLock(lock: {
		lockPath: string;
		ownerPath: string;
		token: string;
	}): Promise<void> {
		let owner: unknown;
		try {
			owner = JSON.parse(await readFile(lock.ownerPath, "utf8"));
		} catch (error) {
			if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return;
			throw error;
		}
		if (!isManifestLockOwner(owner) || owner.token !== lock.token) return;
		await unlink(lock.ownerPath);
		await rmdir(lock.lockPath).catch((error) => {
			const code = (error as NodeJS.ErrnoException)?.code;
			if (code !== "ENOENT" && code !== "ENOTEMPTY" && code !== "EEXIST") throw error;
		});
	}

	private async serializeMutations<T>(operation: () => Promise<T>): Promise<T> {
		// Multiple managers in one process may target the same vault. Serialize by
		// manifest path rather than instance so a concurrent snapshot cannot drop
		// another manager's committed item.
		const queueKey =
			process.platform === "win32" ? this.manifestPath.toLowerCase() : this.manifestPath;
		const previous = manifestMutationTails.get(queueKey) ?? Promise.resolve();
		let release!: () => void;
		const queued = new Promise<void>((resolveQueue) => {
			release = resolveQueue;
		});
		manifestMutationTails.set(queueKey, queued);
		await previous;
		try {
			const lock = await this.acquireManifestLock();
			try {
				// Reload under the cross-process lock so short-lived hook processes
				// cannot overwrite another process's committed manifest item.
				this.loadManifestSync();
				this.recoverInterruptedSourceMovesSync();
				return await operation();
			} finally {
				await this.releaseManifestLock(lock).catch((error) => {
					this.logger.error("Could not release quarantine manifest lock", { error: String(error) });
				});
			}
		} finally {
			release();
			if (manifestMutationTails.get(queueKey) === queued) manifestMutationTails.delete(queueKey);
		}
	}

	/**
	 * Compute SHA-256 hash of a file.
	 */
	private async computeFileHash(filePath: string): Promise<string> {
		const content = await readFile(filePath);
		return createHash("sha256").update(content).digest("hex");
	}

	/**
	 * Log a quarantine event to the audit log.
	 */
	private async logQuarantineEvent(item: QuarantinedItem): Promise<void> {
		if (!this.loggingConfig) return;

		await logIncident(this.loggingConfig, {
			type: "quarantine",
			timestamp: item.timestamp.toISOString(),
			item_id: item.id,
			original_path: item.originalPath,
			quarantine_path: item.quarantinePath,
			threat_id: item.threatId,
			file_hash: item.fileHash,
			file_size: item.fileSize,
			metadata: item.metadata,
		});
	}

	/**
	 * Send notifications to configured channels when a file is quarantined.
	 */
	private async notify(item: QuarantinedItem): Promise<void> {
		const notifications: Promise<void>[] = [];

		for (const channel of this.config.notifyChannels) {
			switch (channel) {
				case "webhook":
					if (this.config.webhookUrl) {
						notifications.push(this.sendWebhookNotification(item));
					}
					break;
				case "slack":
					if (this.config.slackWebhookUrl) {
						notifications.push(this.sendSlackNotification(item));
					}
					break;
				case "email":
					// Email notification would require SMTP setup
					// For now, just log that an email would be sent
					this.logger.info("Email notification would be sent for quarantine", {
						itemId: item.id,
						emailConfig: this.config.emailConfig,
					});
					break;
			}
		}

		// Fire and forget - don't block on notifications
		Promise.all(notifications).catch((error) => {
			this.logger.warn("Notification failed", { error: String(error) });
		});
	}

	/**
	 * Send webhook notification.
	 */
	private async sendWebhookNotification(item: QuarantinedItem): Promise<void> {
		if (!this.config.webhookUrl) return;

		const payload = {
			event: "quarantine",
			timestamp: new Date().toISOString(),
			item: {
				id: item.id,
				original_path: item.originalPath,
				threat_id: item.threatId,
				file_hash: item.fileHash,
				file_size: item.fileSize,
				quarantine_time: item.timestamp.toISOString(),
			},
		};

		try {
			const response = await fetch(this.config.webhookUrl, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(payload),
			});

			if (!response.ok) {
				throw new Error(`HTTP ${response.status}: ${response.statusText}`);
			}
		} catch (error) {
			this.logger.warn("Webhook notification failed", {
				webhookUrl: this.config.webhookUrl,
				error: String(error),
			});
			throw error;
		}
	}

	/**
	 * Send Slack webhook notification.
	 */
	private async sendSlackNotification(item: QuarantinedItem): Promise<void> {
		if (!this.config.slackWebhookUrl) return;

		const payload = {
			text: "🚨 File Quarantined",
			attachments: [
				{
					color: "danger",
					fields: [
						{
							title: "Item ID",
							value: item.id,
							short: true,
						},
						{
							title: "Threat ID",
							value: item.threatId,
							short: true,
						},
						{
							title: "Original Path",
							value: item.originalPath,
							short: false,
						},
						{
							title: "File Hash (SHA-256)",
							value: item.fileHash ?? "unknown",
							short: false,
						},
						{
							title: "File Size",
							value: item.fileSize ? `${item.fileSize} bytes` : "unknown",
							short: true,
						},
						{
							title: "Quarantine Time",
							value: item.timestamp.toISOString(),
							short: true,
						},
					],
				},
			],
		};

		try {
			const response = await fetch(this.config.slackWebhookUrl, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(payload),
			});

			if (!response.ok) {
				throw new Error(`HTTP ${response.status}: ${response.statusText}`);
			}
		} catch (error) {
			this.logger.warn("Slack notification failed", {
				slackWebhookUrl: this.config.slackWebhookUrl,
				error: String(error),
			});
			throw error;
		}
	}
}

/** Default quarantine configuration */
export function getDefaultQuarantineConfig(): QuarantineConfig {
	return {
		quarantineDir: "~/.singularity-aidr/quarantine",
		retentionDays: 30,
		notifyChannels: [],
	};
}
