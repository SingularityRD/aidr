import {
	AutoRollback,
	escapeTerminalText,
	loadConfig,
	logIncident,
	openConfiguredQuarantine,
	type QuarantinedItem,
	RollbackRefusedError,
	responseAuditorFromConfig,
	type StoredSnapshotInfo,
} from "@singularityrd/aidr-core";
import {
	type ConfirmationStreams,
	confirmOperatorAction,
	OperatorConfirmationError,
	operatorIdentity,
} from "../utils/operator-confirm.js";

/**
 * `aidr quarantine list|show|release|delete` and `aidr restore`.
 *
 * Release, delete and restore change the user's files, so they are operator-only:
 * an interactive confirmation (or `--yes` with AIDR_OPERATOR_NONINTERACTIVE=1),
 * and the self-defense rule CLT-SELF-007 denies an agent command that runs them.
 * Every path shown here may have been chosen by an agent, so it is printed with
 * control and bidi characters made visible.
 */

/** Test seams; production callers pass nothing. */
export interface QuarantineCommandDeps {
	configPath?: string;
	env?: NodeJS.ProcessEnv;
	streams?: ConfirmationStreams;
}

const safe = escapeTerminalText;

function fail(message: string): void {
	console.error(message);
	process.exitCode = 1;
}

function errorText(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function formatBytes(bytes: number | undefined): string {
	if (bytes === undefined) return "?";
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
	return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function itemJson(item: QuarantinedItem): Record<string, unknown> {
	return {
		id: item.id,
		original_path: item.originalPath,
		quarantine_path: item.quarantinePath,
		quarantined_at: item.timestamp.toISOString(),
		threat_id: item.threatId,
		sha256: item.fileHash ?? null,
		size: item.fileSize ?? null,
		metadata: item.metadata,
	};
}

function describeItem(item: QuarantinedItem): string[] {
	const reason = item.metadata.reason;
	const rules = item.metadata.rule_ids;
	return [
		`id:          ${item.id}`,
		`original:    ${safe(item.originalPath)}`,
		`quarantined: ${item.timestamp.toISOString()}`,
		`threat:      ${safe(item.threatId)}${Array.isArray(rules) ? ` (rules: ${rules.map((r) => safe(String(r))).join(", ")})` : ""}`,
		`reason:      ${typeof reason === "string" ? safe(reason) : "-"}`,
		`sha256:      ${item.fileHash ?? "-"}`,
		`size:        ${formatBytes(item.fileSize)}`,
		`vault copy:  ${safe(item.quarantinePath)}`,
	];
}

async function openStore(deps: QuarantineCommandDeps) {
	try {
		return await openConfiguredQuarantine({ configPath: deps.configPath });
	} catch (error) {
		fail(`Could not open the quarantine vault: ${errorText(error)}`);
		return null;
	}
}

function findItem(items: QuarantinedItem[], id: string): QuarantinedItem | null {
	const needle = id.trim().toLowerCase();
	const exact = items.find((item) => item.id.toLowerCase() === needle);
	if (exact) return exact;
	// A unique prefix of at least 8 characters, as `list` prints the full id.
	if (needle.length < 8) return null;
	const matches = items.filter((item) => item.id.toLowerCase().startsWith(needle));
	return matches.length === 1 ? (matches[0] ?? null) : null;
}

/** `aidr quarantine list [--json]` */
export async function quarantineListCommand(
	options: { json?: boolean } = {},
	deps: QuarantineCommandDeps = {},
): Promise<void> {
	const opened = await openStore(deps);
	if (!opened) return;
	const items = opened.store.list();
	if (options.json) {
		console.log(
			JSON.stringify(
				{
					enabled: opened.settings.enabled,
					total_bytes: opened.store.totalBytes(),
					max_total_bytes: opened.settings.max_total_bytes,
					retention_days: opened.settings.retention_days,
					items: items.map(itemJson),
				},
				null,
				2,
			),
		);
		return;
	}
	if (!opened.settings.enabled) {
		console.error(
			"File quarantine is off (response.quarantine.enabled = false); nothing new is quarantined.",
		);
	}
	if (items.length === 0) {
		console.log("The quarantine vault is empty.");
		return;
	}
	console.log(
		`${items.length} quarantined file(s), ${formatBytes(opened.store.totalBytes())} (newest first):`,
	);
	for (const item of items) {
		console.log(
			`  ${item.id}  ${item.timestamp.toISOString()}  ${safe(item.threatId)}  ${safe(item.originalPath)}`,
		);
	}
	console.log("");
	console.log("Inspect one with: aidr quarantine show <id>");
}

/** `aidr quarantine show <id> [--json]` */
export async function quarantineShowCommand(
	id: string,
	options: { json?: boolean } = {},
	deps: QuarantineCommandDeps = {},
): Promise<void> {
	const opened = await openStore(deps);
	if (!opened) return;
	const item = findItem(opened.store.list(), id);
	if (!item) {
		fail("No quarantined file has this id. Run `aidr quarantine list`.");
		return;
	}
	if (options.json) {
		console.log(JSON.stringify(itemJson(item), null, 2));
		return;
	}
	for (const line of describeItem(item)) console.log(line);
}

async function confirm(
	prompt: string[],
	word: string,
	options: { yes?: boolean },
	deps: QuarantineCommandDeps,
): Promise<string | null> {
	try {
		const mode = await confirmOperatorAction({
			prompt: prompt.join("\n"),
			word,
			yes: options.yes,
			env: deps.env,
			streams: deps.streams,
		});
		return operatorIdentity(mode);
	} catch (error) {
		fail(
			error instanceof OperatorConfirmationError
				? error.message
				: `Not confirmed: ${errorText(error)}`,
		);
		return null;
	}
}

/**
 * `aidr quarantine release <id>` — put a quarantined file back where it was.
 * The vault copy's hash is verified first, and an existing file at the original
 * path is never overwritten.
 */
export async function quarantineReleaseCommand(
	id: string,
	options: { yes?: boolean } = {},
	deps: QuarantineCommandDeps = {},
): Promise<void> {
	const opened = await openStore(deps);
	if (!opened) return;
	const item = findItem(opened.store.list(), id);
	if (!item) {
		fail("No quarantined file has this id. Run `aidr quarantine list`.");
		return;
	}
	const operator = await confirm(
		[
			"Release this quarantined file back to its original path?",
			"It was quarantined because its content matched a malicious-file rule.",
			...describeItem(item).map((line) => `  ${line}`),
		],
		"release",
		options,
		deps,
	);
	if (!operator) return;
	try {
		await opened.store.restore(item.id);
	} catch (error) {
		fail(`Not released: ${errorText(error)}`);
		return;
	}
	console.log(`Released ${safe(item.originalPath)} (confirmed by ${safe(operator)}).`);
}

/** `aidr quarantine delete <id>` — permanently delete a quarantined file. */
export async function quarantineDeleteCommand(
	id: string,
	options: { yes?: boolean } = {},
	deps: QuarantineCommandDeps = {},
): Promise<void> {
	const opened = await openStore(deps);
	if (!opened) return;
	const item = findItem(opened.store.list(), id);
	if (!item) {
		fail("No quarantined file has this id. Run `aidr quarantine list`.");
		return;
	}
	const operator = await confirm(
		[
			"Permanently delete this quarantined file? This cannot be undone.",
			...describeItem(item).map((line) => `  ${line}`),
		],
		"delete",
		options,
		deps,
	);
	if (!operator) return;
	try {
		await opened.store.delete(item.id);
	} catch (error) {
		fail(`Not deleted: ${errorText(error)}`);
		return;
	}
	console.log(`Deleted quarantined file ${item.id} (confirmed by ${safe(operator)}).`);
}

// ── aidr restore ───────────────────────────────────────────────────

async function openRollback(deps: QuarantineCommandDeps) {
	const config = await loadConfig(deps.configPath);
	const { auditor } = responseAuditorFromConfig(config.response.audit);
	return {
		config,
		rollback: new AutoRollback(undefined, auditor, config.response.actions.snapshot_root_dir),
	};
}

function describeSnapshot(snapshot: StoredSnapshotInfo): string[] {
	const lines = [
		`snapshot:  ${snapshot.id}`,
		`taken:     ${snapshot.timestamp.toISOString()}`,
		`size:      ${formatBytes(snapshot.totalBytes)}`,
	];
	for (const file of snapshot.files) {
		lines.push(
			`file:      ${safe(file.path)} (${formatBytes(file.bytes)}, sha256 ${file.sha256 ?? "unrecorded"})`,
		);
	}
	return lines;
}

/**
 * `aidr restore --list` and `aidr restore <snapshot-id>` — restore a protected
 * path from the pre-operation snapshot taken before an allowed destructive call.
 *
 * A target that changed after the snapshot is refused (`target_changed`) unless
 * the operator also passes `--overwrite-changed`: replacing newer content with
 * an older copy is a second destructive act.
 */
export async function restoreCommand(
	snapshotId: string | undefined,
	options: { list?: boolean; json?: boolean; yes?: boolean; overwriteChanged?: boolean } = {},
	deps: QuarantineCommandDeps = {},
): Promise<void> {
	let opened: Awaited<ReturnType<typeof openRollback>>;
	try {
		opened = await openRollback(deps);
	} catch (error) {
		fail(`Could not open the snapshot store: ${errorText(error)}`);
		return;
	}
	const snapshots = await opened.rollback.listStoredSnapshots();

	if (options.list || !snapshotId) {
		if (!snapshotId && !options.list) {
			fail("Name a snapshot to restore, or pass --list.");
			return;
		}
		if (options.json) {
			console.log(
				JSON.stringify(
					snapshots.map((s) => ({ ...s, timestamp: s.timestamp.toISOString() })),
					null,
					2,
				),
			);
			return;
		}
		if (snapshots.length === 0) {
			console.log("No pre-operation snapshots are stored.");
			if (!opened.config.response.actions.snapshot_before_destructive) {
				console.error(
					"Pre-operation snapshots are off (response.actions.snapshot_before_destructive = false).",
				);
			}
			return;
		}
		console.log(`${snapshots.length} snapshot(s) (newest first):`);
		for (const snapshot of snapshots) {
			const paths = snapshot.files.map((file) => safe(file.path)).join(", ");
			console.log(`  ${snapshot.id}  ${snapshot.timestamp.toISOString()}  ${paths}`);
		}
		console.log("");
		console.log("Restore one with: aidr restore <snapshot-id>");
		return;
	}

	const snapshot = snapshots.find((s) => s.id === snapshotId.trim());
	if (!snapshot) {
		fail("No snapshot has this id. Run `aidr restore --list`.");
		return;
	}
	const operator = await confirm(
		[
			options.overwriteChanged
				? "Restore this snapshot, OVERWRITING targets that changed after it was taken?"
				: "Restore this snapshot? A target that changed since it was taken is left alone.",
			...describeSnapshot(snapshot).map((line) => `  ${line}`),
		],
		"restore",
		options,
		deps,
	);
	if (!operator) return;

	let outcome: "success" | "failure" = "success";
	let detail: string | undefined;
	try {
		const result = await opened.rollback.rollbackSnapshot(snapshot.id, {
			authorizedBy: `operator:${operator}`,
			expectTargetChanged: options.overwriteChanged === true,
		});
		for (const path of result.restored) console.log(`Restored ${safe(path)}`);
	} catch (error) {
		outcome = "failure";
		detail = errorText(error);
		if (error instanceof RollbackRefusedError) {
			for (const refusal of error.refusals) {
				console.error(`Refused ${safe(refusal.path)}: ${refusal.reason} — ${refusal.detail}`);
			}
			if (error.code === "target_changed") {
				console.error(
					"Re-run with --overwrite-changed to replace the newer content with the snapshot copy.",
				);
			}
		}
		fail(`Not fully restored: ${detail}`);
	}
	try {
		await logIncident(opened.config.logging, {
			type: "snapshot_restore",
			timestamp: new Date().toISOString(),
			snapshot_id: snapshot.id,
			paths: snapshot.files.map((file) => file.path),
			outcome,
			authorized_by: operator,
			...(detail ? { error: detail } : {}),
		});
	} catch {
		// The restore already happened (or not); the audit append fails open.
	}
}
