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
 * 5. **A restore proves what it is about to overwrite.** Every copied file gets a
 *    SHA-256 recorded at snapshot time, and a restore refuses (`target_changed`)
 *    when the live target no longer matches it: replacing newer content with a
 *    stale copy is a second destructive act, not an undo. Only a caller that
 *    witnessed the change — the wrapper that ran the operation, or an operator
 *    naming themselves — may authorize that overwrite.
 */

import { createHash, randomBytes } from "node:crypto";
import { copyFile, lstat, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseAuditor } from "./response-audit.js";
import { normalizeAuthorizedBy } from "./response-worker-contract.js";
import type { Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** Default location of pre-operation snapshots. */
export const DEFAULT_SNAPSHOTS_DIR = "~/.singularity-aidr/snapshots";

/** Content digest recorded for one copied file, so a restore can prove its provenance. */
export interface SnapshotFileDigest {
	/** SHA-256 of the bytes stored in the vault for this path. */
	sha256: string;
	/** Size in bytes at snapshot time. */
	size: number;
}

export interface Snapshot {
	id: string;
	timestamp: Date;
	files: Map<string, string>; // original path -> backup path
	/** Integrity record for each copied file, keyed by original path. */
	digests: Map<string, SnapshotFileDigest>;
	/** Operator identity that authorized the snapshot, when one was supplied. */
	authorizedBy?: string;
}

export interface SnapshotMetadata {
	id: string;
	timestamp: string;
	files: Record<string, string>;
	/**
	 * Content digest per copied file. Optional on read so a snapshot written by an
	 * older build still loads; such a snapshot has no recorded precondition and the
	 * restore falls back to the digest of its own vault copy.
	 */
	digests?: Record<string, SnapshotFileDigest>;
	/** Operator identity that authorized the snapshot, when one was supplied. */
	authorizedBy?: string;
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
	/** Operator identity that authorized this response, when one is known. */
	authorizedBy?: string;
}

/** A restore that was REFUSED. Nothing was written to the target when one is reported. */
export interface RollbackRefusal {
	path: string;
	/**
	 * "target_changed" | "vault_changed" | "not_a_file".
	 *
	 * Machine-readable on purpose: a caller has to be able to tell "we chose not to
	 * overwrite this" from "we could not", and from "it was restored".
	 */
	reason: string;
	detail: string;
}

/** How a restore is allowed to treat a target that no longer matches the snapshot. */
export interface RollbackOptions {
	/**
	 * The caller vouches that the target's current content came from the very
	 * operation being rolled back, so overwriting it is the intent.
	 *
	 * Off by default. A restore invoked by a *later process* than the one that took
	 * the snapshot cannot know who changed the target, so it refuses with
	 * `target_changed` instead of silently replacing newer content with a stale
	 * copy. `executeWithRollback` sets it because it took the snapshot and ran the
	 * operation itself.
	 */
	expectTargetChanged?: boolean;
	/** Operator identity recorded with the restore, when one is known. */
	authorizedBy?: string;
}

export interface SnapshotRollbackResult {
	snapshotId: string;
	restored: string[];
	failed: Array<{ path: string; error: string }>;
}

/** Reasons a snapshot may skip a path without leaving the operation unprotected. */
const BENIGN_SNAPSHOT_SKIP_REASONS = new Set(["not_found"]);

/**
 * Thrown when a snapshot could not preserve every path it was asked to protect.
 *
 * The operation must NOT run: proceeding would let it destroy a file while the
 * caller believes it is recoverable. The skip report travels on the error so the
 * caller can name the path and the reason.
 */
export class SnapshotIncompleteError extends Error {
	readonly code = "snapshot_incomplete";
	readonly skipped: SnapshotSkip[];

	constructor(skipped: SnapshotSkip[]) {
		super(
			`Snapshot incomplete: ${skipped.map((skip) => `${skip.path} (${skip.reason})`).join(", ")}`,
		);
		this.name = "SnapshotIncompleteError";
		this.skipped = skipped;
	}
}

/**
 * Thrown when a restore refused to overwrite a target it cannot prove it may
 * replace. `code` is the first refusal's reason, so a caller can branch on
 * `target_changed` without parsing the message.
 */
export class RollbackRefusedError extends Error {
	readonly code: string;
	readonly refusals: RollbackRefusal[];
	readonly restored: string[];

	constructor(
		refusals: RollbackRefusal[],
		restored: string[],
		failed: Array<{ path: string; error: string }>,
	) {
		super(
			`Rollback refused: ${refusals.map((refusal) => `${refusal.reason} (${refusal.path})`).join(", ")}. ` +
				`${restored.length} file(s) restored, ${failed.length} failed.`,
		);
		this.name = "RollbackRefusedError";
		this.code = refusals[0]?.reason ?? "rollback_refused";
		this.refusals = refusals;
		this.restored = restored;
	}
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
		const digests = new Map<string, SnapshotFileDigest>();
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
				// Digest the COPY, not the source: the recorded value then describes the
				// exact bytes a restore would write, so a later `vault_changed` refusal can
				// prove the vault itself was altered and `target_changed` can prove the
				// live target moved on since.
				const sha256 = await this.hashFile(backupPath);
				files.set(resolved, backupPath);
				digests.set(resolved, { sha256, size: stats.size });
				copied.push(resolved);
				bytes += stats.size;
				this.logger.debug("Backed up file", {
					original: resolved,
					backup: backupPath,
					sha256,
				});
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

		const authorizedBy = normalizeAuthorizedBy(auditContext?.authorizedBy);
		const metadata: SnapshotMetadata = {
			id: snapshotId,
			timestamp: timestamp.toISOString(),
			files: Object.fromEntries(files),
			digests: Object.fromEntries(digests),
			...(authorizedBy ? { authorizedBy } : {}),
		};

		await writeFile(join(snapshotDir, "metadata.json"), JSON.stringify(metadata, null, 2), {
			mode: 0o600,
		});

		const snapshot: Snapshot = {
			id: snapshotId,
			timestamp,
			files,
			digests,
			...(authorizedBy ? { authorizedBy } : {}),
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
					authorizedBy,
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
			/**
			 * Receives the paths the pre-operation snapshot could NOT preserve, before
			 * the operation runs (empty when every path was copied). The method returns
			 * the operation's own result, so this callback — or the error below — is how
			 * the skip report reaches the caller. It used to be discarded, which made a
			 * file that was never protected look protected.
			 */
			onSnapshotSkipped?: (skipped: SnapshotSkip[]) => void;
			// Audit context
			tool?: string;
			input?: string;
			verdict?: Verdict;
			threatId?: string;
			/** Operator identity that authorized this response, when one is known. */
			authorizedBy?: string;
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
						authorizedBy: options.authorizedBy,
					}
				: undefined;

		const { snapshot, skipped } = await this.createSnapshotDetailed(
			paths,
			operationId,
			auditContext,
			options.snapshotOptions ?? {},
		);

		this.logger.debug("Executing operation with rollback protection", {
			operationId,
			snapshotId: snapshot.id,
			pathCount: paths.length,
			skipped: skipped.length,
		});

		// Report the skip list before anything runs, then fail closed on a skip that
		// is not simply "there was nothing there to protect". Running the operation
		// anyway would let it destroy a file the caller was told is recoverable.
		options.onSnapshotSkipped?.(skipped);

		const unprotected = skipped.filter((skip) => !BENIGN_SNAPSHOT_SKIP_REASONS.has(skip.reason));
		if (unprotected.length > 0) {
			this.logger.error("Refusing to run: the snapshot could not protect every path", {
				operationId,
				snapshotId: snapshot.id,
				skipped: unprotected,
			});
			throw new SnapshotIncompleteError(unprotected);
		}

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
					await this.rollbackSnapshot(snapshot.id, {
						// This wrapper took the snapshot and ran the operation itself, so a
						// target that changed in between changed because of the operation
						// being undone: overwriting it with the snapshot IS the undo.
						expectTargetChanged: true,
						authorizedBy: options.authorizedBy,
					});
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

	async rollback(snapshotId: string, options: RollbackOptions = {}): Promise<void> {
		await this.rollbackSnapshot(snapshotId, options);
	}

	/**
	 * Restore every file captured by a snapshot.
	 *
	 * Unlike the original implementation this looks the snapshot up on disk when it
	 * is not in memory, so a rollback still works from a *different* process than
	 * the one that took the snapshot — which is the normal case for "the agent did
	 * something destructive yesterday".
	 *
	 * That cross-process case is exactly why a target is verified before it is
	 * overwritten: the digest recorded at snapshot time proves what the target held
	 * when it was protected, so a target that has moved on since is refused
	 * (`target_changed`) rather than quietly replaced with stale content. Only the
	 * caller that witnessed the change may pass `expectTargetChanged`.
	 */
	async rollbackSnapshot(
		snapshotId: string,
		options: RollbackOptions = {},
	): Promise<SnapshotRollbackResult> {
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
		const refusals: RollbackRefusal[] = [];

		// Restore files in reverse order to handle dependencies
		for (const [originalPath, backupPath] of Array.from(snapshot.files).reverse()) {
			// 1. The vault copy must still be the copy we recorded. A rewrite of the
			//    vault is reported, not restored over the user's file.
			let vaultDigest: string;
			try {
				const backupStats = await lstat(backupPath);
				if (!backupStats.isFile()) {
					failed.push({
						path: originalPath,
						error: `vault copy is not a regular file: ${backupPath}`,
					});
					continue;
				}
				vaultDigest = await this.hashFile(backupPath);
			} catch (err) {
				failed.push({ path: originalPath, error: String(err) });
				this.logger.error("Failed to read the snapshot copy", {
					original: originalPath,
					backup: backupPath,
					error: String(err),
				});
				continue;
			}

			const recorded = snapshot.digests.get(originalPath);
			if (recorded && recorded.sha256 !== vaultDigest) {
				refusals.push({
					path: originalPath,
					reason: "vault_changed",
					detail: "the stored copy no longer matches the digest recorded at snapshot time",
				});
				this.logger.error("Refusing to restore a snapshot copy that changed", {
					original: originalPath,
					backup: backupPath,
				});
				continue;
			}
			// A snapshot from a build that predates recorded digests still gets the
			// target precondition: the vault copy is the only description of its
			// contents available, and it is what a restore would write.
			const expectedDigest = recorded?.sha256 ?? vaultDigest;

			// 2. The live target is the thing about to be destroyed, so it is checked
			//    with lstat first: a symlink or directory that replaced the file must
			//    never be followed, because copyFile would write THROUGH the link.
			const targetStats = await lstat(originalPath).catch(() => null);
			if (targetStats && !targetStats.isFile()) {
				refusals.push({
					path: originalPath,
					reason: "not_a_file",
					detail: "the target is no longer a regular file; restoring would follow it",
				});
				this.logger.error("Refusing to restore over a non-file target", {
					original: originalPath,
				});
				continue;
			}
			if (targetStats) {
				const liveDigest = await this.hashFile(originalPath).catch(() => null);
				if (liveDigest !== expectedDigest && options.expectTargetChanged !== true) {
					refusals.push({
						path: originalPath,
						reason: "target_changed",
						detail:
							"the target no longer matches the digest recorded at snapshot time; " +
							"refusing to overwrite it with stale content",
					});
					this.logger.error("Refusing to restore a target that changed after the snapshot", {
						original: originalPath,
					});
					continue;
				}
			}

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
			refused: refusals.length,
		});

		if (refusals.length > 0) {
			// Fail closed: a refusal must never be mistaken for a successful no-op.
			throw new RollbackRefusedError(refusals, restored, failed);
		}

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
		context: {
			tool?: string;
			input?: string;
			verdict?: Verdict;
			threatId?: string;
			/** Operator identity that authorized the restore, when one is known. */
			authorizedBy?: string;
		},
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
				authorizedBy: normalizeAuthorizedBy(context.authorizedBy),
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

			// Absent for snapshots written before digests were recorded: those still
			// load, and the restore falls back to the vault copy's own digest.
			const digests = new Map<string, SnapshotFileDigest>();
			for (const [original, digest] of Object.entries(metadata.digests ?? {})) {
				if (typeof digest?.sha256 === "string") {
					digests.set(original, { sha256: digest.sha256, size: digest.size ?? 0 });
				}
			}

			const snapshot: Snapshot = {
				id: metadata.id,
				timestamp: new Date(metadata.timestamp),
				files,
				digests,
				...(metadata.authorizedBy ? { authorizedBy: metadata.authorizedBy } : {}),
			};

			this.snapshots.set(snapshotId, snapshot);
			return snapshot;
		} catch (err) {
			this.logger.debug("Failed to load snapshot", { snapshotId, error: String(err) });
			return null;
		}
	}

	/** SHA-256 of a file's bytes, used to record and re-verify what a snapshot holds. */
	private async hashFile(filePath: string): Promise<string> {
		const content = await readFile(filePath);
		return createHash("sha256").update(content).digest("hex");
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
