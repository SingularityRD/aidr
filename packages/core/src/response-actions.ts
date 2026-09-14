/**
 * Response layer — what the runtime DOES after it decides to block something,
 * and what it preserves before it decides to let something destructive happen.
 *
 * ## Why this exists
 *
 * AIDR was named "Detection & Response" but only ever produced a verdict; the
 * quarantine/contain/rollback modules existed as a closed island that no verdict
 * could reach. This module is the connection: it turns a verdict into a concrete,
 * recorded, reversible action.
 *
 * ## Two verbs, two very different decisions
 *
 * | | trigger | what the copy is for |
 * |---|---|---|
 * | `snapshot_on_deny` | a BLOCKED call | evidence. The call never ran, so nothing needs restoring. |
 * | `snapshot_before_destructive` | an ALLOWED destructive call | rollback. The call is about to run and overwrite the original. |
 *
 * They are separate switches because they carry separate risk. The first copies a
 * file the runtime already decided to protect; the second copies a file on a path
 * the runtime decided was *safe*, which is a much stronger claim and therefore
 * needs a second, independent gate (`protectPaths`).
 *
 * ## Design rules (deliberate, and the reason the surface is small)
 *
 * 1. **Off by default.** Every action must be opted into. A security tool that
 *    silently mutates a user's filesystem on its own initiative is a bigger risk
 *    than the threat it is responding to.
 * 2. **Copy, never move, at pre-execution time.** The connector runs *before* the
 *    tool call, so the blocked write has not happened and the target still holds
 *    its previous contents. Moving or deleting it would destroy the very thing
 *    the user asked to keep. A snapshot is therefore a copy into a vault, and the
 *    original is left byte-identical.
 * 3. **Bounded.** Severity floor and size ceiling keep the vault from filling up;
 *    a refusal is reported, never silently skipped.
 * 4. **Recorded.** Every action (including "attempted and failed") returns a
 *    record the caller puts in the audit log, so a response is never invisible.
 * 5. **Never throws.** A response failure must not turn into a hook failure, and
 *    must never turn a block into an allow. The blocking verdict stands regardless
 *    of whether the response succeeded.
 */

import { copyFile, mkdir, stat } from "node:fs/promises";
import { basename, isAbsolute, join, normalize, resolve, sep } from "node:path";
import { resolvePath } from "./config.js";
import type { ResponseAuditor } from "./response-audit.js";
import { AutoRollback, DEFAULT_SNAPSHOTS_DIR } from "./rollback.js";
import type { Artifact, Logger, Verdict, VerdictSeverity } from "./types.js";
import { nullLogger } from "./types.js";

export interface ResponseActionRecord {
	/**
	 * Which action this is.
	 *
	 * "snapshot" — a copy was preserved.
	 * "rollback" — a previously snapshotted target was RESTORED. Recorded as its own
	 * action because reporting a restore as a snapshot would tell the operator the
	 * opposite of what happened.
	 */
	action: "snapshot" | "rollback";
	/** "success" | "failure" | "skipped" | "unavailable". */
	outcome: "success" | "failure" | "skipped" | "unavailable";
	/** Original path the action applied to. */
	target: string;
	/** Vault path when the snapshot succeeded. */
	vaultPath?: string;
	/** Snapshot id when the copy can be restored later. */
	snapshotId?: string;
	/** Paths that were deliberately NOT preserved, with the reason. Never silent. */
	skipped?: Array<{ path: string; reason: string; detail?: string }>;
	/** Machine-readable reason for a non-success outcome. */
	reason?: string;
	/** Human-readable detail (never contains file contents). */
	detail?: string;
	bytes?: number;
}

export interface ResponseOptions {
	snapshotOnDeny: boolean;
	snapshotDir: string;
	snapshotMinSeverity: VerdictSeverity;
	snapshotMaxBytes: number;
	/**
	 * Copy the target of a destructive operation that is about to be ALLOWED, so the
	 * operation can be rolled back afterwards. Opt-in, and inert while
	 * `protectPaths` is empty.
	 */
	snapshotBeforeDestructive: boolean;
	/** Path prefixes eligible for a pre-operation snapshot. Empty = protect nothing. */
	protectPaths: string[];
	/** Where pre-operation (restorable) snapshots are written. */
	snapshotRootDir: string;
	/** Age at which a pre-operation snapshot is pruned. 0 disables pruning. */
	snapshotRetentionDays: number;
}

export const DEFAULT_RESPONSE_OPTIONS: ResponseOptions = {
	snapshotOnDeny: false,
	snapshotDir: "~/.singularity-aidr/response-vault",
	snapshotMinSeverity: "warning",
	snapshotMaxBytes: 10 * 1024 * 1024,
	snapshotBeforeDestructive: false,
	protectPaths: [],
	snapshotRootDir: DEFAULT_SNAPSHOTS_DIR,
	snapshotRetentionDays: 7,
};

/** Verdict severities, ordered. `VerdictSeverity` is critical|warning|info. */
const SEVERITY_RANK: Record<VerdictSeverity, number> = {
	info: 0,
	warning: 1,
	critical: 2,
};

/** Tools whose target is a file path we can snapshot. */
const FILE_TARGET_TOOLS = new Set([
	"write",
	"edit",
	"multiedit",
	"delete",
	"notebookedit",
	"remove",
	"move",
	"rename",
]);

/**
 * Tools that overwrite or remove an existing file.
 *
 * A subset of `FILE_TARGET_TOOLS`: `Write` to a brand-new path destroys nothing,
 * so it is only destructive when the target already exists (checked at run time).
 */
const DESTRUCTIVE_TOOLS = new Set([
	"write",
	"edit",
	"multiedit",
	"delete",
	"remove",
	"move",
	"rename",
	"notebookedit",
]);

/**
 * Shell commands that destroy the contents of a path named in the command line.
 *
 * Deliberately a small, explicit list of patterns rather than a `Bash`-is-always-
 * destructive shortcut: a pre-operation snapshot is opt-in, and an over-broad
 * trigger would copy files on calls that were never going to touch them.
 */
const DESTRUCTIVE_COMMAND_PATTERNS: RegExp[] = [
	/(?:^|[;&|(]\s*)(?:sudo\s+)?rm\s/,
	/(?:^|[;&|(]\s*)(?:sudo\s+)?(?:rmdir|shred|truncate)\s/,
	/(?:^|[;&|(]\s*)(?:sudo\s+)?(?:mv|move)\s/,
	/(?:^|[;&|(]\s*)(?:sudo\s+)?dd\s+[^;|]*\bof=/,
	/>\s*[^\s;|&]+/, // shell redirection clobbering a file
];

function isDestructiveCommand(command: string): boolean {
	const trimmed = command.trim();
	if (trimmed === "") return false;
	return DESTRUCTIVE_COMMAND_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function severityAtLeast(actual: VerdictSeverity, floor: VerdictSeverity): boolean {
	return (SEVERITY_RANK[actual] ?? 0) >= (SEVERITY_RANK[floor] ?? 0);
}

/** Extract the file path a tool call targets, if any. */
export function targetPathFor(toolName: string, toolInput: Record<string, unknown>): string | null {
	if (!FILE_TARGET_TOOLS.has(toolName.toLowerCase())) return null;
	for (const key of ["file_path", "path", "filePath", "target_file", "filename"]) {
		const value = toolInput[key];
		if (typeof value === "string" && value.trim() !== "") return value.trim();
	}
	return null;
}

/**
 * True when this call would overwrite or remove something that already exists.
 *
 * `stat` (not `lstat`) is intentional here: a symlink pointing at a real file is a
 * real destructive target, and if it cannot be resolved there is nothing to lose.
 * A snapshot taken later still uses `lstat` internally so the link itself is never
 * followed into an unnamed location.
 */
async function destructiveTargetFor(
	toolName: string,
	toolInput: Record<string, unknown>,
): Promise<string | null> {
	const tool = toolName.toLowerCase();

	if (tool === "bash" || tool === "shell" || tool === "execute") {
		// A shell call is only destructive for the paths its command line names, and
		// only file paths qualify — decided by the caller through `protectPaths`.
		const command = typeof toolInput.command === "string" ? toolInput.command : "";
		if (!isDestructiveCommand(command)) return null;
		return commandTargetPath(command);
	}

	if (!DESTRUCTIVE_TOOLS.has(tool)) return null;
	const target = targetPathFor(toolName, toolInput);
	if (!target) return null;
	const resolved = resolvePath(target);
	const stats = await stat(resolved).catch(() => null);
	return stats?.isFile() ? resolved : null;
}

/**
 * Best-effort path named by a destructive shell command.
 *
 * Exported so the limitation is testable and visible: this reads the LAST argument
 * of the destructive command, which is right for the common single-target form
 * (`rm -rf ./build`, `mv a b`, `dd of=image`) and deliberately conservative
 * otherwise. It is a snapshot hint, not a security boundary — an unrecognised
 * command simply gets no pre-operation copy and no false claim of protection.
 */
export function commandTargetPath(command: string): string | null {
	const segments = command.split(/[;&|]/);
	for (const segment of segments.reverse()) {
		const tokens = segment.trim().split(/\s+/).filter(Boolean);
		if (tokens.length === 0) continue;
		const ofArg = tokens.find((token) => token.startsWith("of="));
		if (ofArg) return ofArg.slice(3);
		// Drop the leading `sudo` and the command word, then keep only operands.
		const operands = tokens.slice(1).filter((token) => !token.startsWith("-") && token !== "sudo");
		if (operands.length === 0) continue;
		return operands[operands.length - 1] ?? null;
	}
	return null;
}

/** True when `path` falls under any configured protected prefix. */
export function isProtectedPath(path: string, protectPaths: string[]): boolean {
	if (protectPaths.length === 0) return false;
	const resolved = normalize(isAbsolute(path) ? path : resolve(path));
	return protectPaths.some((entry) => {
		const trimmed = entry.trim();
		if (trimmed === "") return false;
		// Support the natural `dir/**` spelling as well as a plain prefix.
		const prefixInput = trimmed.replace(/[/\\]\*{1,2}$/, "");
		const prefix = normalize(resolvePath(prefixInput));
		if (prefix === "" || prefix === sep) return false;
		if (resolved === prefix) return true;
		return resolved.startsWith(prefix.endsWith(sep) ? prefix : prefix + sep);
	});
}

/**
 * Run the configured response actions for a blocking verdict.
 *
 * Returns the records of what was attempted. An empty array means no action was
 * configured or applicable — callers must be able to tell that apart from a
 * failed action, which is why skips are recorded rather than omitted.
 */
export async function runResponseActions(
	verdict: Verdict,
	request: { toolName: string; toolInput: Record<string, unknown> },
	options: Partial<ResponseOptions> = {},
	logger: Logger = nullLogger,
): Promise<ResponseActionRecord[]> {
	const opts = { ...DEFAULT_RESPONSE_OPTIONS, ...options };
	const records: ResponseActionRecord[] = [];

	// Only a blocking decision is a response trigger.
	if (verdict.decision === "allow") return records;

	if (opts.snapshotOnDeny) {
		records.push(await snapshotTarget(verdict, request, opts, logger));
	}

	return records;
}

/**
 * Response actions for a destructive operation that is ABOUT TO BE ALLOWED.
 *
 * This is the rollback half of the response layer. It runs on the allow path, so
 * it does the opposite of `runResponseActions`: it preserves the target *before*
 * the (allowed) operation can destroy it, and hands back a snapshot id the caller
 * can roll back to.
 *
 * Returns `{ records: [], snapshot: null }` whenever the feature is off, the
 * protect list is empty, the target is unprotected, or the target does not exist.
 * An empty result is never an error — but a snapshot that could not copy a file
 * says so in `records[0].skipped`.
 */
export async function runPreAllowedResponseActions(
	verdict: Verdict,
	request: { toolName: string; toolInput: Record<string, unknown>; sessionId?: string },
	options: Partial<ResponseOptions> = {},
	logger: Logger = nullLogger,
	auditor?: ResponseAuditor,
): Promise<{ records: ResponseActionRecord[]; snapshot: PreOperationSnapshot | null }> {
	const opts = { ...DEFAULT_RESPONSE_OPTIONS, ...options };
	const records: ResponseActionRecord[] = [];

	if (verdict.decision !== "allow") return { records, snapshot: null };
	if (!opts.snapshotBeforeDestructive) return { records, snapshot: null };
	if (opts.protectPaths.length === 0) return { records, snapshot: null };

	const target = await destructiveTargetFor(request.toolName, request.toolInput).catch(() => null);
	if (!target) return { records, snapshot: null };

	if (!isProtectedPath(target, opts.protectPaths)) {
		records.push({
			action: "snapshot",
			outcome: "skipped",
			target,
			reason: "not_protected",
			detail: "the target is not under any configured protect_paths entry",
		});
		return { records, snapshot: null };
	}

	try {
		const rollback = new AutoRollback(logger, auditor, opts.snapshotRootDir);
		const result = await rollback.createSnapshotDetailed(
			[target],
			`allow-${verdict.category}`,
			{
				tool: request.toolName,
				input: request.sessionId ?? "",
				verdict,
				threatId: verdict.matchedThreatId ?? verdict.category,
			},
			{ maxBytesPerFile: opts.snapshotMaxBytes, maxTotalBytes: opts.snapshotMaxBytes },
		);

		if (result.copied.length === 0) {
			// Nothing was preserved. Report the real reason instead of implying that
			// the target is recoverable.
			const first = result.skipped[0];
			records.push({
				action: "snapshot",
				outcome: "skipped",
				target,
				reason: first?.reason ?? "nothing_copied",
				detail: first?.detail ?? "the target could not be copied",
				bytes: first?.bytes,
			});
			return { records, snapshot: null };
		}

		// Opportunistic retention: this path is the only one that creates these
		// copies, so it is the only place that can keep them from accumulating.
		await applySnapshotRetention(rollback, opts.snapshotRetentionDays, logger);

		logger.info?.("Pre-operation snapshot taken before an allowed destructive call", {
			target,
			snapshotId: result.snapshot.id,
			bytes: result.bytes,
		});

		records.push({
			action: "snapshot",
			outcome: "success",
			target,
			snapshotId: result.snapshot.id,
			vaultPath: result.snapshot.files.get(target),
			bytes: result.bytes,
			skipped: result.skipped.map((skip) => ({
				path: skip.path,
				reason: skip.reason,
				detail: skip.detail,
			})),
		});

		return { records, snapshot: { id: result.snapshot.id, target, bytes: result.bytes } };
	} catch (error) {
		// A response failure must never change an allow into a block, and must never
		// crash the hook. It is recorded so the operator knows the call was NOT
		// protected.
		const detail = error instanceof Error ? error.message : String(error);
		logger.warn?.("Pre-operation snapshot failed", { target, error: detail });
		records.push({
			action: "snapshot",
			outcome: "failure",
			target,
			reason: "snapshot_failed",
			detail,
		});
		return { records, snapshot: null };
	}
}

/** A snapshot that exists on disk and can be restored later. */
export interface PreOperationSnapshot {
	id: string;
	target: string;
	bytes: number;
}

async function applySnapshotRetention(
	rollback: AutoRollback,
	retentionDays: number,
	logger: Logger,
): Promise<void> {
	if (retentionDays <= 0) return;
	const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);
	try {
		await rollback.pruneOlderThan(cutoff);
	} catch (error) {
		// Retention is housekeeping; failing it must not fail the response.
		logger.debug?.("Snapshot retention sweep failed", { error: String(error) });
	}
}

/**
 * Restore the target of an allowed destructive operation from its snapshot.
 *
 * `wrapped: false` means the target was already rolled back by a previous call, so
 * there is nothing left to do — not that the restore failed.
 */
export async function rollbackPreOperationSnapshot(
	snapshot: PreOperationSnapshot,
	context: {
		toolName: string;
		toolInput?: Record<string, unknown>;
		sessionId?: string;
		verdict: Verdict;
		/** Operator identity that authorized this response, when one is known. */
		authorizedBy?: string;
	},
	options: Partial<ResponseOptions> = {},
	logger: Logger = nullLogger,
	auditor?: ResponseAuditor,
): Promise<ResponseActionRecord> {
	const opts = { ...DEFAULT_RESPONSE_OPTIONS, ...options };
	const rollback = new AutoRollback(logger, auditor, opts.snapshotRootDir);

	try {
		const result = await rollback.rollbackSnapshot(snapshot.id, {
			// This snapshot was taken by the guard immediately before the allowed call
			// ran, and this restore happens as the call unwinds: a target that changed
			// in between changed because of the operation being undone.
			expectTargetChanged: true,
			authorizedBy: context.authorizedBy,
		});
		logger.info?.("Rolled back an allowed destructive operation", {
			target: snapshot.target,
			snapshotId: snapshot.id,
			restored: result.restored.length,
		});
		return {
			action: "rollback",
			outcome: "success",
			target: snapshot.target,
			snapshotId: snapshot.id,
			bytes: snapshot.bytes,
		};
	} catch (error) {
		const detail = error instanceof Error ? error.message : String(error);
		logger.warn?.("Rollback of an allowed destructive operation failed", {
			target: snapshot.target,
			snapshotId: snapshot.id,
			error: detail,
		});
		return {
			action: "rollback",
			outcome: "failure",
			target: snapshot.target,
			snapshotId: snapshot.id,
			reason: "rollback_failed",
			detail,
		};
	}
}

async function snapshotTarget(
	verdict: Verdict,
	request: { toolName: string; toolInput: Record<string, unknown> },
	opts: ResponseOptions,
	logger: Logger,
): Promise<ResponseActionRecord> {
	const target = targetPathFor(request.toolName, request.toolInput);

	if (!target) {
		return {
			action: "snapshot",
			outcome: "skipped",
			target: "",
			reason: "not_a_file_target",
			detail: `${request.toolName} does not target a file path`,
		};
	}

	const resolved = resolvePath(target);

	if (!severityAtLeast(verdict.severity, opts.snapshotMinSeverity)) {
		return {
			action: "snapshot",
			outcome: "skipped",
			target: resolved,
			reason: "below_severity_floor",
			detail: `severity ${verdict.severity} is below the configured floor ${opts.snapshotMinSeverity}`,
		};
	}

	// A blocked write to a path that does not exist yet has nothing to preserve.
	// That is a normal outcome, not a failure.
	const stats = await stat(resolved).catch(() => null);
	if (!stats) {
		return {
			action: "snapshot",
			outcome: "skipped",
			target: resolved,
			reason: "target_absent",
			detail: "the target does not exist, so there is no prior content to preserve",
		};
	}
	if (!stats.isFile()) {
		return {
			action: "snapshot",
			outcome: "skipped",
			target: resolved,
			reason: "target_not_a_file",
			detail: "only regular files are snapshotted",
		};
	}
	if (stats.size > opts.snapshotMaxBytes) {
		return {
			action: "snapshot",
			outcome: "skipped",
			target: resolved,
			reason: "too_large",
			detail: `${stats.size} bytes exceeds the ${opts.snapshotMaxBytes} byte limit`,
			bytes: stats.size,
		};
	}

	try {
		const vaultDir = resolvePath(opts.snapshotDir);
		const stamp = new Date().toISOString().replace(/[:.]/g, "-");
		const threat = verdict.matchedThreatId ?? verdict.category;
		const safeThreat = threat.replace(/[^A-Za-z0-9._-]/g, "_");
		const destination = join(vaultDir, `${stamp}_${safeThreat}_${basename(resolved)}`);

		await mkdir(vaultDir, { recursive: true, mode: 0o700 });
		await copyFile(resolved, destination);

		logger.info?.("Response snapshot written", {
			target: resolved,
			vaultPath: destination,
			threat: safeThreat,
		});

		return {
			action: "snapshot",
			outcome: "success",
			target: resolved,
			vaultPath: destination,
			bytes: stats.size,
		};
	} catch (error) {
		// Never let a response failure become a hook failure: the block still stands.
		const detail = error instanceof Error ? error.message : String(error);
		logger.warn?.("Response snapshot failed", { target: resolved, error: detail });
		return {
			action: "snapshot",
			outcome: "failure",
			target: resolved,
			reason: "snapshot_failed",
			detail,
		};
	}
}

/** True when any record represents an action that actually changed the vault. */
export function anyActionSucceeded(records: ResponseActionRecord[]): boolean {
	return records.some((record) => record.outcome === "success");
}

/**
 * Compact, user-facing summary of what the runtime did. Never includes contents.
 *
 * Each action is described by what it actually did: reporting a rollback as
 * "preserved a copy" would tell the operator the exact opposite of the truth.
 */
export function summarizeResponseActions(records: ResponseActionRecord[]): string | null {
	const succeeded = records.filter((r) => r.outcome === "success");
	if (succeeded.length === 0) return null;
	return succeeded
		.map((record) => {
			if (record.action === "rollback") {
				return `rollback: restored ${record.target} from snapshot ${record.snapshotId ?? "(unknown)"}`;
			}
			const where =
				record.vaultPath ?? (record.snapshotId ? `snapshot ${record.snapshotId}` : "(vault)");
			return `${record.action}: preserved a copy of ${record.target} at ${where}`;
		})
		.join("; ");
}

/**
 * Artifacts are not used to select a snapshot target: the tool input is the
 * authoritative source. Exported for callers that want to log what was seen.
 */
export function fileArtifacts(artifacts: Artifact[]): string[] {
	return artifacts.filter((a) => a.type === "file_path").map((a) => a.value);
}
