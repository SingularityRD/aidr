/**
 * Response audit logging for Singularity AIDR.
 * Provides comprehensive audit logging for all response actions with optional
 * tamper-evident signatures and query capabilities.
 */

import { createHash, createSign, createVerify, generateKeyPairSync, randomUUID } from "node:crypto";
import { appendFile, mkdir, readdir, readFile, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseMode } from "./response-config.js";
import type { Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/**
 * Single response audit entry representing a response action taken.
 */
export interface ResponseAuditEntry {
	/** Unique identifier for this audit entry */
	id: string;
	/** When the action was taken */
	timestamp: Date;
	/** Type of response action taken */
	action: "contain" | "rollback" | "quarantine" | "block" | "notify";
	/** Threat ID that triggered this response */
	threatId: string;
	/** Tool that was being executed */
	tool: string;
	/** Input to the tool */
	input: string;
	/** Verdict that triggered the response */
	verdict: Verdict;
	/** Response mode that was applied */
	responseTaken: ResponseMode;
	/** Additional metadata about the response */
	metadata: {
		/** Container ID for containment actions */
		containerId?: string;
		/** Snapshot ID for rollback actions */
		snapshotId?: string;
		/** Quarantine ID for quarantine actions */
		quarantineId?: string;
		/** Whether notification was sent */
		notificationSent?: boolean;
		/** Whether user was notified */
		userNotified?: boolean;
	};
	/** Outcome of the action */
	outcome: "success" | "failure";
	/** Error message if action failed */
	error?: string;
}

/**
 * Serialized format for storage (snake_case for JSONL compatibility).
 */
interface SerializedAuditEntry {
	id: string;
	timestamp: string;
	action: ResponseAuditEntry["action"];
	threat_id: string;
	tool: string;
	input: string;
	verdict: Verdict;
	response_taken: ResponseMode;
	metadata: ResponseAuditEntry["metadata"];
	outcome: "success" | "failure";
	error?: string;
	/** Signature for tamper evidence (optional) */
	_signature?: string;
}

/**
 * Options for the ResponseAuditor.
 */
export interface ResponseAuditorOptions {
	/** Whether to cryptographically sign entries for tamper evidence */
	signEntries?: boolean;
	/** Number of days to retain audit entries (0 = infinite) */
	retentionDays?: number;
	/** Optional logger for operations */
	logger?: Logger;
}

/**
 * Manages response audit logging with optional signing and querying capabilities.
 */
export class ResponseAuditor {
	private readonly logger: Logger;
	private readonly signEntries: boolean;
	private readonly retentionDays: number;
	private privateKey?: string;
	private publicKey?: string;
	private keyPath: string;

	constructor(
		private auditLogPath: string,
		options: ResponseAuditorOptions = {},
	) {
		this.logger = options.logger ?? nullLogger;
		this.signEntries = options.signEntries ?? false;
		this.retentionDays = options.retentionDays ?? 0;
		this.keyPath = join(dirname(resolvePath(auditLogPath)), ".response-audit-key");

		if (this.signEntries) {
			void this.initializeSigning();
		}
	}

	/**
	 * Initialize signing keys for tamper-evident logging.
	 */
	private async initializeSigning(): Promise<void> {
		try {
			const keyContent = await readFile(this.keyPath, "utf-8");
			const keys = JSON.parse(keyContent);
			this.privateKey = keys.privateKey;
			this.publicKey = keys.publicKey;
			this.logger.debug("Loaded existing signing keys for response audit");
		} catch {
			// Generate new key pair
			const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
				privateKeyEncoding: { type: "pkcs8", format: "pem" },
				publicKeyEncoding: { type: "spki", format: "pem" },
			});
			this.privateKey = privateKey;
			this.publicKey = publicKey;

			// Save keys
			await mkdir(dirname(this.keyPath), { recursive: true });
			await writeFile(this.keyPath, JSON.stringify({ privateKey, publicKey }, null, 2), {
				mode: 0o600,
			});
			this.logger.debug("Generated new signing keys for response audit");
		}
	}

	/**
	 * Sign an entry for tamper evidence.
	 */
	private signEntry(entry: SerializedAuditEntry): string | undefined {
		if (!this.signEntries || !this.privateKey) return undefined;

		try {
			const sign = createSign("SHA256");
			const data = JSON.stringify({
				id: entry.id,
				timestamp: entry.timestamp,
				action: entry.action,
				threat_id: entry.threat_id,
				tool: entry.tool,
				input: entry.input,
				verdict: entry.verdict,
				response_taken: entry.response_taken,
				metadata: entry.metadata,
				outcome: entry.outcome,
			});
			sign.update(data);
			return sign.sign(this.privateKey, "base64");
		} catch (error) {
			this.logger.warn("Failed to sign audit entry", { error: String(error) });
			return undefined;
		}
	}

	/**
	 * Verify a signature on an entry.
	 */
	private verifySignature(entry: SerializedAuditEntry): boolean {
		if (!entry._signature || !this.publicKey) return false;

		try {
			const verify = createVerify("SHA256");
			const data = JSON.stringify({
				id: entry.id,
				timestamp: entry.timestamp,
				action: entry.action,
				threat_id: entry.threat_id,
				tool: entry.tool,
				input: entry.input,
				verdict: entry.verdict,
				response_taken: entry.response_taken,
				metadata: entry.metadata,
				outcome: entry.outcome,
			});
			verify.update(data);
			return verify.verify(this.publicKey, entry._signature, "base64");
		} catch {
			return false;
		}
	}

	/**
	 * Log a response action to the audit log.
	 */
	async log(entry: Omit<ResponseAuditEntry, "id" | "timestamp">): Promise<ResponseAuditEntry> {
		const id = randomUUID();
		const timestamp = new Date();

		const fullEntry: ResponseAuditEntry = {
			...entry,
			id,
			timestamp,
		};

		// Serialize for storage
		const serialized: SerializedAuditEntry = {
			id: fullEntry.id,
			timestamp: fullEntry.timestamp.toISOString(),
			action: fullEntry.action,
			threat_id: fullEntry.threatId,
			tool: fullEntry.tool,
			input: fullEntry.input,
			verdict: fullEntry.verdict,
			response_taken: fullEntry.responseTaken,
			metadata: fullEntry.metadata,
			outcome: fullEntry.outcome,
			error: fullEntry.error,
		};

		// Sign if enabled
		if (this.signEntries) {
			serialized._signature = this.signEntry(serialized);
		}

		// Append to log
		const path = resolvePath(this.auditLogPath);
		await mkdir(dirname(path), { recursive: true });
		await appendFile(path, `${JSON.stringify(serialized)}\n`);

		// Clean up old entries if retention is set
		if (this.retentionDays > 0) {
			void this.enforceRetention();
		}

		this.logger.debug("Logged response action", {
			id,
			action: entry.action,
			threatId: entry.threatId,
			outcome: entry.outcome,
		});

		return fullEntry;
	}

	/**
	 * Query audit log entries with filters.
	 */
	async query(filters: {
		action?: ResponseAuditEntry["action"];
		threatId?: string;
		tool?: string;
		from?: Date;
		to?: Date;
		outcome?: "success" | "failure";
	}): Promise<ResponseAuditEntry[]> {
		const entries = await this.loadAllEntries();

		return entries.filter((entry) => {
			if (filters.action && entry.action !== filters.action) return false;
			if (filters.threatId && entry.threatId !== filters.threatId) return false;
			if (filters.tool && entry.tool !== filters.tool) return false;
			if (filters.outcome && entry.outcome !== filters.outcome) return false;
			if (filters.from && entry.timestamp < filters.from) return false;
			if (filters.to && entry.timestamp > filters.to) return false;
			return true;
		});
	}

	/**
	 * Load all entries from the audit log.
	 */
	private async loadAllEntries(): Promise<ResponseAuditEntry[]> {
		const path = resolvePath(this.auditLogPath);

		try {
			const content = await readFile(path, "utf-8");
			const lines = content.trim().split("\n").filter(Boolean);
			const entries: ResponseAuditEntry[] = [];

			for (const line of lines) {
				try {
					const serialized = JSON.parse(line) as SerializedAuditEntry;
					entries.push({
						id: serialized.id,
						timestamp: new Date(serialized.timestamp),
						action: serialized.action,
						threatId: serialized.threat_id,
						tool: serialized.tool,
						input: serialized.input,
						verdict: serialized.verdict,
						responseTaken: serialized.response_taken,
						metadata: serialized.metadata,
						outcome: serialized.outcome,
						error: serialized.error,
					});
				} catch {
					// Skip invalid lines
				}
			}

			return entries;
		} catch {
			// File doesn't exist or is empty
			return [];
		}
	}

	/**
	 * Verify the integrity of signed entries.
	 */
	async verifyIntegrity(): Promise<{
		valid: boolean;
		tamperedEntries?: string[];
	}> {
		if (!this.signEntries) {
			return { valid: true };
		}

		const path = resolvePath(this.auditLogPath);
		const tamperedEntries: string[] = [];

		try {
			const content = await readFile(path, "utf-8");
			const lines = content.trim().split("\n").filter(Boolean);

			for (const line of lines) {
				try {
					const entry = JSON.parse(line) as SerializedAuditEntry;
					if (entry._signature && !this.verifySignature(entry)) {
						tamperedEntries.push(entry.id);
					}
				} catch {
					// Skip invalid lines
				}
			}

			return {
				valid: tamperedEntries.length === 0,
				tamperedEntries: tamperedEntries.length > 0 ? tamperedEntries : undefined,
			};
		} catch {
			return { valid: true };
		}
	}

	/**
	 * Export all entries as a JSON array string.
	 */
	async exportToJSON(): Promise<string> {
		const entries = await this.loadAllEntries();
		return JSON.stringify(entries, null, 2);
	}

	/**
	 * Enforce retention policy by removing old entries.
	 */
	private async enforceRetention(): Promise<void> {
		if (this.retentionDays <= 0) return;

		const cutoff = new Date();
		cutoff.setDate(cutoff.getDate() - this.retentionDays);

		const entries = await this.loadAllEntries();
		const filtered = entries.filter((e) => e.timestamp >= cutoff);

		if (filtered.length < entries.length) {
			const path = resolvePath(this.auditLogPath);
			const serialized = filtered.map((e) => {
				const entry: SerializedAuditEntry = {
					id: e.id,
					timestamp: e.timestamp.toISOString(),
					action: e.action,
					threat_id: e.threatId,
					tool: e.tool,
					input: e.input,
					verdict: e.verdict,
					response_taken: e.responseTaken,
					metadata: e.metadata,
					outcome: e.outcome,
					error: e.error,
				};
				return JSON.stringify(entry);
			});
			await writeFile(path, serialized.join("\n") + "\n");
			this.logger.debug("Enforced retention policy", {
				removed: entries.length - filtered.length,
				retentionDays: this.retentionDays,
			});
		}
	}

	/**
	 * Get statistics about the audit log.
	 */
	async getStats(): Promise<{
		totalEntries: number;
		actionBreakdown: Record<string, number>;
		outcomeBreakdown: { success: number; failure: number };
		oldestEntry?: Date;
		newestEntry?: Date;
	}> {
		const entries = await this.loadAllEntries();

		const actionBreakdown: Record<string, number> = {};
		let successCount = 0;
		let failureCount = 0;

		let oldest: Date | undefined;
		let newest: Date | undefined;

		for (const entry of entries) {
			// Count actions
			actionBreakdown[entry.action] = (actionBreakdown[entry.action] ?? 0) + 1;

			// Count outcomes
			if (entry.outcome === "success") {
				successCount++;
			} else {
				failureCount++;
			}

			// Track dates
			if (!oldest || entry.timestamp < oldest) {
				oldest = entry.timestamp;
			}
			if (!newest || entry.timestamp > newest) {
				newest = entry.timestamp;
			}
		}

		return {
			totalEntries: entries.length,
			actionBreakdown,
			outcomeBreakdown: { success: successCount, failure: failureCount },
			oldestEntry: oldest,
			newestEntry: newest,
		};
	}
}

/**
 * Factory function to create a ResponseAuditor with default path.
 */
export function createResponseAuditor(options?: ResponseAuditorOptions): ResponseAuditor {
	return new ResponseAuditor("~/.singularity-aidr/response-audit.jsonl", options);
}
