/**
 * Auto-Rollback: File system snapshots for destructive operations.
 * Provides snapshot-based rollback capability for file modifications.
 */

import { randomBytes } from "node:crypto";
import { copyFile, mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseAuditor } from "./response-audit.js";
import type { Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

export interface Snapshot {
	id: string;
	timestamp: Date;
	files: Map<string, string>; // original path -> backup path
}

export interface SnapshotMetadata {
	id: string;
	timestamp: string;
	files: Record<string, string>;
}

export class AutoRollback {
	private snapshots = new Map<string, Snapshot>();
	private readonly snapshotsDir: string;

	constructor(
		private logger: Logger = nullLogger,
		private auditor?: ResponseAuditor,
	) {
		this.snapshotsDir = resolvePath("~/.singularity-aidr/snapshots");
	}

	async createSnapshot(
		paths: string[],
		operationId: string,
		auditContext?: {
			tool?: string;
			input?: string;
			verdict?: Verdict;
			threatId?: string;
		},
	): Promise<Snapshot> {
		const snapshotId = `${operationId}-${randomBytes(4).toString("hex")}`;
		const snapshotDir = join(this.snapshotsDir, snapshotId);

		await mkdir(snapshotDir, { recursive: true });

		const files = new Map<string, string>();
		const timestamp = new Date();

		// Copy each file to the snapshot directory
		for (const filePath of paths) {
			const resolved = resolve(filePath);
			try {
				const stats = await stat(resolved);
				if (!stats.isFile()) {
					this.logger.debug("Skipping non-file path in snapshot", { path: resolved });
					continue;
				}

				// Preserve directory structure relative to the original
				const backupName = this.encodePath(resolved);
				const backupPath = join(snapshotDir, backupName);

				await copyFile(resolved, backupPath);
				files.set(resolved, backupPath);
				this.logger.debug("Backed up file", { original: resolved, backup: backupPath });
			} catch (err) {
				// File may not exist - log and continue
				this.logger.debug("Failed to backup file (may not exist)", {
					path: resolved,
					error: String(err),
				});
			}
		}

		// Write metadata file
		const metadata: SnapshotMetadata = {
			id: snapshotId,
			timestamp: timestamp.toISOString(),
			files: Object.fromEntries(files),
		};

		await writeFile(join(snapshotDir, "metadata.json"), JSON.stringify(metadata, null, 2), {
			mode: 0o600,
		});

		const snapshot: Snapshot = {
			id: snapshotId,
			timestamp,
			files,
		};

		this.snapshots.set(snapshotId, snapshot);
		this.logger.info("Created snapshot", { snapshotId, fileCount: files.size });

		// Log snapshot creation if auditor and audit context are available
		if (this.auditor && auditContext?.verdict && auditContext?.threatId) {
			await this.auditor.log({
				action: "rollback",
				threatId: auditContext.threatId,
				tool: auditContext.tool ?? "unknown",
				input: auditContext.input ?? paths.join(", "),
				verdict: auditContext.verdict,
				responseTaken: "contain",
				metadata: { snapshotId },
				outcome: "success",
			});
		}

		return snapshot;
	}

	async executeWithRollback<T>(
		operation: () => Promise<T>,
		paths: string[],
		options: {
			onFailure: "rollback" | "notify";
			operationId?: string;
			// Audit context
			tool?: string;
			input?: string;
			verdict?: Verdict;
			threatId?: string;
		},
	): Promise<T> {
		const operationId = options.operationId ?? `op-${randomBytes(4).toString("hex")}`;
		const auditContext =
			options.verdict && options.threatId
				? {
						tool: options.tool,
						input: options.input,
						verdict: options.verdict,
						threatId: options.threatId,
					}
				: undefined;

		const snapshot = await this.createSnapshot(paths, operationId, auditContext);

		this.logger.debug("Executing operation with rollback protection", {
			operationId,
			snapshotId: snapshot.id,
			pathCount: paths.length,
		});

		try {
			const result = await operation();
			// Success - clean up snapshot to save space
			await this.cleanup(snapshot.id);
			return result;
		} catch (error) {
			if (options.onFailure === "rollback") {
				this.logger.warn("Operation failed, attempting rollback", {
					operationId,
					snapshotId: snapshot.id,
					error: String(error),
				});

				// Log rollback attempt if auditor is available
				if (this.auditor && options.verdict && options.threatId) {
					await this.auditor.log({
						action: "rollback",
						threatId: options.threatId,
						tool: options.tool ?? "unknown",
						input: options.input ?? paths.join(", "),
						verdict: options.verdict,
						responseTaken: "contain",
						metadata: { snapshotId: snapshot.id },
						outcome: "success",
					});
				}

				await this.rollback(snapshot.id);
			} else {
				this.logger.warn("Operation failed (rollback disabled)", {
					operationId,
					snapshotId: snapshot.id,
					error: String(error),
				});
			}
			throw error;
		}
	}

	async rollback(snapshotId: string): Promise<void> {
		const snapshot = this.snapshots.get(snapshotId);
		if (!snapshot) {
			// Try to load from disk
			const loaded = await this.loadSnapshot(snapshotId);
			if (!loaded) {
				throw new Error(`Snapshot not found: ${snapshotId}`);
			}
			return this.rollbackFromLoaded(loaded);
		}
		return this.rollbackFromLoaded(snapshot);
	}

	private async rollbackFromLoaded(snapshot: Snapshot): Promise<void> {
		this.logger.info("Rolling back to snapshot", { snapshotId: snapshot.id });

		const restored: string[] = [];
		const failed: Array<{ path: string; error: string }> = [];

		// Restore files in reverse order to handle dependencies
		for (const [originalPath, backupPath] of Array.from(snapshot.files).reverse()) {
			try {
				// Ensure parent directory exists
				await mkdir(dirname(originalPath), { recursive: true });
				await copyFile(backupPath, originalPath);
				restored.push(originalPath);
				this.logger.debug("Restored file", { original: originalPath });
			} catch (err) {
				failed.push({ path: originalPath, error: String(err) });
				this.logger.error("Failed to restore file", {
					original: originalPath,
					error: String(err),
				});
			}
		}

		this.logger.info("Rollback completed", {
			snapshotId: snapshot.id,
			restored: restored.length,
			failed: failed.length,
		});

		if (failed.length > 0) {
			throw new Error(`Rollback partially failed. ${failed.length} file(s) could not be restored.`);
		}
	}

	async cleanup(snapshotId: string): Promise<void> {
		const snapshot = this.snapshots.get(snapshotId);
		const snapshotDir = snapshot
			? dirname(Array.from(snapshot.files.values())[0] ?? join(this.snapshotsDir, snapshotId))
			: join(this.snapshotsDir, snapshotId);

		try {
			await rm(snapshotDir, { recursive: true, force: true });
			this.snapshots.delete(snapshotId);
			this.logger.debug("Cleaned up snapshot", { snapshotId });
		} catch (err) {
			this.logger.debug("Failed to cleanup snapshot (may not exist)", {
				snapshotId,
				error: String(err),
			});
		}
	}

	async listSnapshots(): Promise<Array<{ id: string; timestamp: Date; fileCount: number }>> {
		return Array.from(this.snapshots.values()).map((s) => ({
			id: s.id,
			timestamp: s.timestamp,
			fileCount: s.files.size,
		}));
	}

	async prune(olderThanMs: number): Promise<number> {
		const now = Date.now();
		const snapshots = await this.listSnapshots();
		let pruned = 0;

		for (const snapshot of snapshots) {
			if (now - snapshot.timestamp.getTime() > olderThanMs) {
				await this.cleanup(snapshot.id);
				pruned++;
			}
		}

		this.logger.info("Pruned old snapshots", { pruned, olderThanMs });
		return pruned;
	}

	private async loadSnapshot(snapshotId: string): Promise<Snapshot | null> {
		const snapshotDir = join(this.snapshotsDir, snapshotId);
		const metadataPath = join(snapshotDir, "metadata.json");

		try {
			const metadataRaw = await readFile(metadataPath, "utf-8");
			const metadata = JSON.parse(metadataRaw) as SnapshotMetadata;

			const files = new Map<string, string>();
			for (const [original, backup] of Object.entries(metadata.files)) {
				files.set(original, backup);
			}

			const snapshot: Snapshot = {
				id: metadata.id,
				timestamp: new Date(metadata.timestamp),
				files,
			};

			this.snapshots.set(snapshotId, snapshot);
			return snapshot;
		} catch (err) {
			this.logger.debug("Failed to load snapshot", { snapshotId, error: String(err) });
			return null;
		}
	}

	private async loadAllSnapshots(): Promise<void> {
		try {
			const entries = await readdir(this.snapshotsDir, { withFileTypes: true });
			for (const entry of entries) {
				if (entry.isDirectory() && !this.snapshots.has(entry.name)) {
					await this.loadSnapshot(entry.name);
				}
			}
		} catch {
			// Directory may not exist - ignore
		}
	}

	/**
	 * Encode a file path for safe storage as a filename.
	 * Replaces path separators and other special characters.
	 */
	private encodePath(filePath: string): string {
		// Create a safe filename by encoding the path
		// Use base64 encoding to handle special characters
		const encoded = Buffer.from(filePath).toString("base64").replace(/[/+=]/g, "_");
		return encoded;
	}
}

// Factory function for quick usage
export function createAutoRollback(logger?: Logger): AutoRollback {
	return new AutoRollback(logger);
}
