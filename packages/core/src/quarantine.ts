/**
 * Auto-quarantine system for Singularity AIDR.
 * Moves suspicious files to a quarantine directory with metadata tracking.
 */

import { createHash, randomUUID } from "node:crypto";
import {
	copyFile,
	mkdir,
	readdir,
	readFile,
	rename,
	stat,
	unlink,
	writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { logIncident } from "./audit-log.js";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { ResponseAuditor } from "./response-audit.js";
import type { Logger, LoggingConfig, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** Notification channel types for security team alerts */
export type NotifyChannel = "email" | "slack" | "webhook";

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
}

/** Quarantine manifest stored in the quarantine directory */
interface QuarantineManifest {
	version: number;
	items: QuarantinedItem[];
	lastUpdated: string;
}

const MANIFEST_VERSION = 1;
const MANIFEST_FILENAME = "manifest.json";
const METADATA_FILENAME = "metadata.json";

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
		this.ensureQuarantineDir();
		this.loadManifest();
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
		},
	): Promise<QuarantinedItem> {
		const resolvedPath = resolvePath(filePath);
		const quarantineDir = resolvePath(this.config.quarantineDir);

		// Verify file exists and is accessible
		const fileStats = await stat(resolvedPath).catch(() => null);
		if (!fileStats || !fileStats.isFile()) {
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
				});
			}

			throw new Error(error);
		}

		// Generate unique ID and compute file hash
		const id = randomUUID();
		const fileHash = await this.computeFileHash(resolvedPath);
		const fileSize = fileStats.size;

		// Create quarantine subdirectory structure based on date
		const now = new Date();
		const dateDir = join(
			quarantineDir,
			now.getFullYear().toString(),
			(now.getMonth() + 1).toString().padStart(2, "0"),
			now.getDate().toString().padStart(2, "0"),
		);
		await mkdir(dateDir, { recursive: true });

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
	 * @param itemId - ID of the quarantined item to delete
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
			// File may not exist, continue
			this.logger.warn(`Could not delete quarantined file: ${item.quarantinePath}`);
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
	 * Ensure the quarantine directory exists.
	 */
	private async ensureQuarantineDir(): Promise<void> {
		const quarantineDir = resolvePath(this.config.quarantineDir);
		await mkdir(quarantineDir, { recursive: true });
	}

	/**
	 * Load the quarantine manifest from disk.
	 */
	private async loadManifest(): Promise<void> {
		try {
			const content = await getFileContent(this.manifestPath);
			const manifest: QuarantineManifest = JSON.parse(content);

			if (manifest.version !== MANIFEST_VERSION) {
				this.logger.warn(`Quarantine manifest version mismatch: ${manifest.version}`);
				return;
			}

			this.items.clear();
			for (const item of manifest.items) {
				this.items.set(item.id, {
					...item,
					timestamp: new Date(item.timestamp),
				});
			}
		} catch {
			// Manifest doesn't exist yet, start fresh
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
