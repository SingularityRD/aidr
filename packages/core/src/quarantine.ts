/**
 * Auto-quarantine system for Singularity AIDR.
 * Moves suspicious files to a quarantine directory with metadata tracking.
 */

import { createHash, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { copyFile, lstat, mkdir, readFile, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { logIncident } from "./audit-log.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent, getFileContentSync } from "./file-utils.js";
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

/** Quarantine manifest stored in the quarantine directory */
interface QuarantineManifest {
	version: number;
	items: QuarantinedItem[];
	lastUpdated: string;
}

const MANIFEST_VERSION = 1;
const MANIFEST_FILENAME = "manifest.json";
const _METADATA_FILENAME = "metadata.json";

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
	async quarantine(
		filePath: string,
		threatId: string,
		metadata?: Record<string, unknown>,
		auditContext?: {
			tool?: string;
			input?: string;
			verdict?: Verdict;
			/** Operator identity that authorized this response, when one is known. */
			authorizedBy?: string;
		},
	): Promise<QuarantinedItem> {
		const resolvedPath = resolvePath(filePath);
		const quarantineDir = resolvePath(this.config.quarantineDir);
		const authorizedBy = normalizeAuthorizedBy(auditContext?.authorizedBy);

		// lstat, not stat: this is the same rule the rollback module applies to a
		// snapshot target. Following a symlink here would move (and then delete) the
		// LINK TARGET — a file that was never named, and possibly one outside the
		// workspace entirely.
		const fileStats = await lstat(resolvedPath).catch(() => null);
		if (fileStats?.isSymbolicLink()) {
			const error = `Refusing to quarantine a symlink: ${resolvedPath}`;
			// Log the refusal if auditor and context are available. It is reported as
			// a failure: nothing was isolated.
			if (this.auditor && auditContext?.verdict) {
				await this.auditor.log({
					action: "quarantine",
					threatId,
					tool: auditContext.tool ?? "unknown",
					input: auditContext.input ?? filePath,
					verdict: auditContext.verdict,
					responseTaken: "quarantine",
					metadata: { quarantineId: undefined, reason: "symlink_refused" },
					outcome: "failure",
					error,
					authorizedBy,
				});
			}

			throw new QuarantineRefusedError("symlink_refused", error);
		}
		if (!fileStats?.isFile()) {
			const error = `File not found or not accessible: ${resolvedPath}`;

			// Log failure if auditor and context are available
			if (this.auditor && auditContext?.verdict) {
				await this.auditor.log({
					action: "quarantine",
					threatId,
					tool: auditContext.tool ?? "unknown",
					input: auditContext.input ?? filePath,
					verdict: auditContext.verdict,
					responseTaken: "quarantine",
					metadata: { quarantineId: undefined },
					outcome: "failure",
					error,
					authorizedBy,
				});
			}

			throw new Error(error);
		}

		// Generate unique ID and compute file hash
		const id = randomUUID();
		const fileHash = await this.computeFileHash(resolvedPath);
		const fileSize = fileStats.size;

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
		await mkdir(dateDir, { recursive: true, mode: 0o700 });

		// Move file to quarantine (using copy + delete for cross-device safety)
		const quarantineFilename = `${id}_${basename(resolvedPath)}`;
		const quarantinePath = join(dateDir, quarantineFilename);

		try {
			await copyFile(resolvedPath, quarantinePath);
			await unlink(resolvedPath);
		} catch (error) {
			// Clean up partial copy on failure
			await unlink(quarantinePath).catch(() => {});
			const errorMsg = `Failed to quarantine file: ${error instanceof Error ? error.message : String(error)}`;

			// Log failure if auditor and context are available
			if (this.auditor && auditContext?.verdict) {
				await this.auditor.log({
					action: "quarantine",
					threatId,
					tool: auditContext.tool ?? "unknown",
					input: auditContext.input ?? filePath,
					verdict: auditContext.verdict,
					responseTaken: "quarantine",
					metadata: { quarantineId: undefined },
					outcome: "failure",
					error: errorMsg,
					authorizedBy,
				});
			}

			throw new Error(errorMsg);
		}

		// Write metadata file alongside quarantined file
		const metadataPath = join(dateDir, `${quarantineFilename}.metadata.json`);
		const item: QuarantinedItem = {
			id,
			originalPath: resolvedPath,
			quarantinePath,
			timestamp: now,
			threatId,
			metadata: metadata ?? {},
			fileHash,
			fileSize,
			...(authorizedBy ? { authorizedBy } : {}),
		};

		await atomicWriteJson(metadataPath, {
			...item,
			timestamp: now.toISOString(),
		});

		// Track in memory and persist manifest
		this.items.set(id, item);
		await this.saveManifest();

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

		return item;
	}

	/**
	 * Restore a quarantined file to its original location.
	 * @param itemId - ID of the quarantined item to restore
	 */
	async restore(itemId: string): Promise<void> {
		const item = this.items.get(itemId);
		if (!item) {
			throw new Error(`Quarantined item not found: ${itemId}`);
		}

		// Ensure original directory exists
		await mkdir(dirname(item.originalPath), { recursive: true });

		// Verify file integrity before restoring
		const currentHash = await this.computeFileHash(item.quarantinePath);
		if (currentHash !== item.fileHash) {
			throw new Error(
				`File integrity check failed for quarantined item: ${itemId}. Hash mismatch detected.`,
			);
		}

		// Move file back to original location
		try {
			await copyFile(item.quarantinePath, item.originalPath);
			await unlink(item.quarantinePath);
		} catch (error) {
			throw new Error(
				`Failed to restore file: ${error instanceof Error ? error.message : String(error)}`,
			);
		}

		// Clean up metadata file and remove from tracking
		const metadataPath = `${item.quarantinePath}.metadata.json`;
		await unlink(metadataPath).catch(() => {});

		this.items.delete(itemId);
		await this.saveManifest();

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
	async delete(itemId: string): Promise<void> {
		const item = this.items.get(itemId);
		if (!item) {
			throw new Error(`Quarantined item not found: ${itemId}`);
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

		// Delete metadata file
		const metadataPath = `${item.quarantinePath}.metadata.json`;
		await unlink(metadataPath).catch(() => {});

		// Remove from tracking
		this.items.delete(itemId);
		await this.saveManifest();

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
		return Array.from(this.items.values()).sort(
			(a, b) => b.timestamp.getTime() - a.timestamp.getTime(),
		);
	}

	/**
	 * Get a specific quarantined item by ID.
	 * @param itemId - ID of the quarantined item
	 * @returns The quarantined item or undefined if not found
	 */
	get(itemId: string): QuarantinedItem | undefined {
		return this.items.get(itemId);
	}

	/**
	 * Clean up expired quarantined items based on retention policy.
	 * @returns Array of IDs that were cleaned up
	 */
	async cleanupExpired(): Promise<string[]> {
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

	/**
	 * Ensure the quarantine directory exists (synchronous: must finish before the
	 * constructor returns so the instance is usable immediately).
	 */
	private ensureQuarantineDirSync(): void {
		try {
			mkdirSync(resolvePath(this.config.quarantineDir), { recursive: true });
		} catch (error) {
			this.logger.warn("Failed to create quarantine directory", { error: String(error) });
		}
	}

	/**
	 * Load the quarantine manifest from disk (synchronous, see above).
	 */
	private loadManifestSync(): void {
		this.items.clear();
		try {
			// Throws when the manifest does not exist yet, which is the normal
			// first-run case handled by the catch below.
			const content = getFileContentSync(this.manifestPath);
			const manifest: QuarantineManifest = JSON.parse(content);

			if (manifest.version !== MANIFEST_VERSION) {
				this.logger.warn(`Quarantine manifest version mismatch: ${manifest.version}`);
				return;
			}

			for (const item of manifest.items) {
				this.items.set(item.id, {
					...item,
					timestamp: new Date(item.timestamp),
				});
			}
		} catch {
			// Manifest doesn't exist yet, or is unreadable/corrupt: start fresh.
			this.items.clear();
		}
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

		try {
			await atomicWriteJson(this.manifestPath, manifest);
		} catch (error) {
			this.logger.warn("Failed to save quarantine manifest", { error: String(error) });
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
