/**
 * Auto-Rollback: pre-operation file snapshots, so a destructive operation that
 * the runtime ALLOWED can still be undone.
 *
 * ## Why this exists (and how it differs from snapshot-on-deny)
 *
 * `response-actions.ts` snapshots the target of a *blocked* call. That copy is
 * evidence, not a rollback: the blocked call never ran, so the file was never
 * modified and there is nothing to restore.
 *
 * The genuinely dangerous case is the mirror image — a destructive operation the
 * runtime decided was **allowed**. It runs, it overwrites or deletes the
 * original, and if it turns out to have been a mistake there is normally no way
 * back. This module is that way back: copy the target *before* the allowed
 * operation runs, and the previous contents stay recoverable.
 *
 * ## Design rules
 *
 * 1. **Off by default, and doubly gated.** Taking a snapshot here copies user
 *    files on a path the runtime already judged safe, so it requires BOTH
 *    `snapshot_before_destructive` and a non-empty `protect_paths` list. An empty
 *    protect list means "protect nothing", which is the shipped default.
 * 2. **Bounded.** Every file is size-checked before it is copied, and a copy that
 *    is refused is *reported* (`SnapshotSkip`) rather than silently dropped. A
 *    snapshot that quietly missed a file would be worse than no snapshot at all,
 *    because the operator would believe the file was recoverable.
 * 3. **Never throws on the response path.** A failed backup must not turn into a
 *    hook failure or, worse, an allow that turns into an unexplained crash.
 * 4. **Discoverable after the fact.** Snapshots are self-describing on disk
 *    (`metadata.json`) and can be rolled back by a *later process* — the runtime
 *    that took the snapshot is usually long gone by the time an operator wants it
 *    back.
 */

import { randomBytes } from "node:crypto";
import { copyFile, lstat, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseAuditor } from "./response-audit.js";
import type { Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** Default location of pre-operation snapshots. */
export const DEFAULT_SNAPSHOTS_DIR = "~/.singularity-aidr/snapshots";

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

/** A path that was deliberately NOT copied, and why. Never silent. */
export interface SnapshotSkip {
	path: string;
	/** "not_found" | "not_a_file" | "too_large" | "copy_failed" */
	reason: string;
	detail?: string;
	bytes?: number;
}

/** Outcome of a snapshot attempt: what is recoverable, and what is not. */
export interface SnapshotResult {
	snapshot: Snapshot;
	/** Paths actually copied into the snapshot. */
	copied: string[];
	/** Paths deliberately not copied, with the reason. */
	skipped: SnapshotSkip[];
	/** Total bytes copied, so a caller can enforce a budget. */
	bytes: number;
}

export interface SnapshotOptions {
	/** Refuse to copy a file larger than this. Default 10 MiB. */
	maxBytesPerFile?: number;
	/** Refuse to copy once this many bytes are already in the snapshot. Default 64 MiB. */
	maxTotalBytes?: number;
}

export const DEFAULT_SNAPSHOT_OPTIONS: Required<SnapshotOptions> = {
	maxBytesPerFile: 10 * 1024 * 1024,
	maxTotalBytes: 64 * 1024 * 1024,
};

export interface SnapshotAuditContext {
	tool?: string;
	input?: string;
	verdict?: Verdict;
	threatId?: string;
}

export interface SnapshotRollbackResult {
	snapshotId: string;
	restored: string[];
	failed: Array<{ path: string; error: string }>;
}

export class AutoRollback {
	private snapshots = new Map<string, Snapshot>();
	private readonly snapshotsDir: string;

	constructor(
		private logger: Logger = nullLogger,
		private auditor?: ResponseAuditor,
		snapshotsDir: string = DEFAULT_SNAPSHOTS_DIR,
	) {
		this.snapshotsDir = resolvePath(snapshotsDir);
	}

	/** Where snapshots are written. Read by callers that report the vault location. */
	get directory(): string {
		return this.snapshotsDir;
	}

	async createSnapshot(
		paths: string[],
		operationId: string,
		auditContext?: SnapshotAuditContext,
		options: SnapshotOptions = {},
	): Promise<Snapshot> {
		const result = await this.createSnapshotDetailed(paths, operationId, auditContext, options);
		return result.snapshot;
	}

	/**
	 * Bounded, self-reporting snapshot.
	 *
	 * The returned `skipped` list is the honest half of the result: a caller can
	 * tell the user "this was protected, that was too large to protect" instead of
	 * implying that everything was captured.
	 */
	async createSnapshotDetailed(
		paths: string[],
		operationId: string,
		auditContext?: SnapshotAuditContext,
		options: SnapshotOptions = {},
	): Promise<SnapshotResult> {
		const opts = { ...DEFAULT_SNAPSHOT_OPTIONS, ...options };
		const snapshotId = `${operationId}-${randomBytes(4).toString("hex")}`;
		const snapshotDir = join(this.snapshotsDir, snapshotId);

		const files = new Map<string, string>();
		const copied: string[] = [];
		const skipped: SnapshotSkip[] = [];
		let bytes = 0;
		const timestamp = new Date();

		const uniquePaths = Array.from(new Set(paths));
		let directoryReady = false;

		for (const filePath of uniquePaths) {
			const resolved = resolve(filePath);
			try {
				// lstat, not stat: a symlink must not be followed, or a snapshot could be
				// talked into copying something that was never named by the operator.
				const stats = await lstat(resolved);
				if (!stats.isFile()) {
					skipped.push({
						path: resolved,
						reason: "not_a_file",
						detail: "only regular files are snapshotted",
					});
					continue;
				}
				if (stats.size > opts.maxBytesPerFile) {
					skipped.push({
						path: resolved,
						reason: "too_large",
						detail: `${stats.size} bytes exceeds the ${opts.maxBytesPerFile} byte per-file limit`,
						bytes: stats.size,
					});
					continue;
				}
				if (bytes + stats.size > opts.maxTotalBytes) {
					skipped.push({
						path: resolved,
						reason: "too_large",
						detail: `adding ${stats.size} bytes would exceed the ${opts.maxTotalBytes} byte snapshot budget`,
						bytes: stats.size,
					});
					continue;
				}

				if (!directoryReady) {
					await mkdir(snapshotDir, { recursive: true, mode: 0o700 });
					directoryReady = true;
				}

				const backupPath = join(snapshotDir, this.encodePath(resolved));
				await copyFile(resolved, backupPath);
				files.set(resolved, backupPath);
				copied.push(resolved);
				bytes += stats.size;
				this.logger.debug("Backed up file", { original: resolved, backup: backupPath });
			} catch (err) {
				// A path that does not exist has nothing to preserve; that is a normal
				// outcome on a create/delete path, but it is still recorded.
				const missing = (err as NodeJS.ErrnoException)?.code === "ENOENT";
				skipped.push({
					path: resolved,
					reason: missing ? "not_found" : "copy_failed",
					detail: missing ? "the path does not exist yet" : String(err),
				});
				this.logger.debug("Failed to backup file", { path: resolved, error: String(err) });
			}
		}

		if (!directoryReady) {
			await mkdir(snapshotDir, { recursive: true, mode: 0o700 });
		}

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
		this.logger.info("Created snapshot", {
			snapshotId,
			fileCount: files.size,
			bytes,
			skipped: skipped.length,
		});

		// Log snapshot creation if auditor and audit context are available. A
		// snapshot is a containment measure: the prior state is preserved so the
		// operation can be undone.
		if (this.auditor && auditContext?.verdict && auditContext?.threatId) {
			await this.auditor
				.log({
					action: "contain",
					threatId: auditContext.threatId,
					tool: auditContext.tool ?? "unknown",
					input: auditContext.input ?? uniquePaths.join(", "),
					verdict: auditContext.verdict,
					responseTaken: "contain",
					metadata: { snapshotId },
					outcome: "success",
				})
				.catch((error) => {
					// The snapshot exists; an audit failure must not undo it or throw.
					this.logger.warn("Failed to log snapshot creation", { error: String(error) });
				});
		}

		return { snapshot, copied, skipped, bytes };
	}

	async executeWithRollback<T>(
		operation: () => Promise<T>,
		paths: string[],
		options: {
			onFailure: "rollback" | "notify";
			operationId?: string;
			/**
			 * Keep the snapshot even when the operation succeeds. Defaults to false
			 * (the historical behaviour: success frees the space). Callers that promise
			 * a later manual rollback must set this, otherwise the snapshot they report
			 * to the user has already been deleted.
			 */
			retainSnapshot?: boolean;
			snapshotOptions?: SnapshotOptions;
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

		const { snapshot } = await this.createSnapshotDetailed(
			paths,
			operationId,
			auditContext,
			options.snapshotOptions ?? {},
		);

		this.logger.debug("Executing operation with rollback protection", {
			operationId,
			snapshotId: snapshot.id,
			pathCount: paths.length,
		});

		try {
			const result = await operation();
			if (options.retainSnapshot !== true) {
				// Success - clean up snapshot to save space
				await this.cleanup(snapshot.id);
			}
			return result;
		} catch (operationError) {
			if (options.onFailure === "rollback") {
				this.logger.warn("Operation failed, attempting rollback", {
					operationId,
					snapshotId: snapshot.id,
					error: String(operationError),
				});

				// Log the attempt BEFORE performing it: if the process dies mid-restore,
				// the signed chain still shows what was being undone.
				await this.logRollback(snapshot.id, paths, options, "success", undefined);

				try {
					await this.rollbackSnapshot(snapshot.id);
				} catch (rollbackError) {
					// A restore that failed is NOT a clean outcome, and must be recorded as
					// a failure rather than inferred from the operation's own error.
					await this.logRollback(snapshot.id, paths, options, "failure", String(rollbackError));
					throw rollbackError;
				}
			} else {
				this.logger.warn("Operation failed (rollback disabled)", {
					operationId,
					snapshotId: snapshot.id,
					error: String(operationError),
				});
			}
			throw operationError;
		}
	}

	async rollback(snapshotId: string): Promise<void> {
		await this.rollbackSnapshot(snapshotId);
	}

	/**
	 * Restore every file captured by a snapshot.
	 *
	 * Unlike the original implementation this looks the snapshot up on disk when it
	 * is not in memory, so a rollback still works from a *different* process than
	 * the one that took the snapshot — which is the normal case for "the agent did
	 * something destructive yesterday".
	 */
	async rollbackSnapshot(snapshotId: string): Promise<SnapshotRollbackResult> {
		let snapshot = this.snapshots.get(snapshotId);
		if (!snapshot) {
			snapshot = (await this.loadSnapshot(snapshotId)) ?? undefined;
		}
		if (!snapshot) {
			throw new Error(`Snapshot not found: ${snapshotId}`);
		}

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

		return { snapshotId: snapshot.id, restored, failed };
	}

	/**
	 * Write a rollback record to the response auditor, if one is configured.
	 *
	 * Never throws: a rollback that already restored the user's file must not be
	 * reported as a failure because the audit write failed.
	 */
	async logRollback(
		snapshotId: string,
		paths: string[],
		context: { tool?: string; input?: string; verdict?: Verdict; threatId?: string },
		outcome: "success" | "failure",
		error?: string,
	): Promise<void> {
		if (!this.auditor || !context.verdict) return;
		try {
			await this.auditor.log({
				action: "rollback",
				threatId: context.threatId ?? context.verdict.matchedThreatId ?? "unknown",
				tool: context.tool ?? "unknown",
				input: context.input ?? paths.join(", "),
				verdict: context.verdict,
				responseTaken: "rollback",
				metadata: { snapshotId },
				outcome,
				error,
			});
		} catch (err) {
			this.logger.warn("Failed to log rollback", { snapshotId, error: String(err) });
		}
	}

	async cleanup(snapshotId: string): Promise<void> {
		const snapshotDir = join(this.snapshotsDir, snapshotId);
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

	/**
	 * In-memory view of snapshots taken by this instance.
	 *
	 * Deliberately NOT backed by a directory scan: a prune would then see (and
	 * delete) snapshots belonging to other runs. Cross-process discovery is done by
	 * `pruneOlderThan` and `rollbackSnapshot`, which read the metadata on disk.
	 */
	async listSnapshots(): Promise<Array<{ id: string; timestamp: Date; fileCount: number }>> {
		return Array.from(this.snapshots.values()).map((s) => ({
			id: s.id,
			timestamp: s.timestamp,
			fileCount: s.files.size,
		}));
	}

	async prune(olderThanMs: number): Promise<number> {
		return this.pruneOlderThan(new Date(Date.now() - olderThanMs));
	}

	/**
	 * Drop snapshots taken before `cutoff`. Returns how many were removed.
	 *
	 * Scans the snapshot directory, so a long-lived install does not accumulate
	 * pre-operation copies forever just because each hook run is a new process.
	 */
	async pruneOlderThan(cutoff: Date): Promise<number> {
		await this.loadAllSnapshots();
		let pruned = 0;

		for (const snapshot of Array.from(this.snapshots.values())) {
			if (snapshot.timestamp < cutoff) {
				await this.cleanup(snapshot.id);
				pruned++;
			}
		}

		if (pruned > 0) {
			this.logger.info("Pruned old snapshots", { pruned, cutoff: cutoff.toISOString() });
		}
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
