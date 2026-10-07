import {
	existsSync,
	lstatSync,
	readFileSync,
	realpathSync,
	renameSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, parse, resolve, sep } from "node:path";
import { escapeTerminalText } from "@singularityrd/aidr-core";
import {
	ManagedHookError,
	recordHooksInstalled,
	removeManagedHooks,
} from "../utils/install-hooks.js";
import {
	confirmOperatorAction,
	type OperatorCommandDeps,
	OperatorConfirmationError,
} from "../utils/operator-confirm.js";

/**
 * `aidr uninstall` — remove the hook registrations AIDR installed.
 *
 * ## Why this exists
 *
 * Removal existed only in the deployment layer: `deploy/fleet/unix/remove-managed-hooks.mjs`
 * and the Windows/Intune uninstall script. A customer who installed with
 * `aidr setup` + the documented connector had no supported local way to remove
 * it, so the managed-hook removal logic that did exist was unreachable for them.
 *
 * ## What this command will and will not do
 *
 *  * It removes ONLY hook registrations whose `statusMessage` is the marker the
 *    connector installer writes (`removeManagedHooks`, which implements the same
 *    filter as the fleet remover). A customer's own hooks, other keys in the
 *    agent settings, the policy/allowlist configuration, the connector files and
 *    the installation receipt are all left alone.
 *  * It refuses to touch anything when the installation receipt is missing or
 *    does not verify, and reports a machine-readable reason code. Removing
 *    "everything that looks like AIDR" without a verified receipt could delete a
 *    registration this tool did not create; failing closed is the safe direction.
 *  * It is idempotent: with no managed hook present it writes nothing at all,
 *    not even a reformatted file or a fresh backup.
 *  * It never reports a removal it did not perform. The report lists each
 *    removed registration verbatim and the same measurement drives the output.
 *  * It deletes no connector bytes, receipts or configuration, so the removal is
 *    recoverable and a reinstall can reuse the existing digest directory.
 */

const RECEIPT_SCHEMA_VERSION = 1;
const SUPPORTED_CONNECTOR = "claude-code";
const RECEIPT_RELATIVE_PATH = join(".singularity-aidr", "installation.json");
const CONNECTOR_ROOT_RELATIVE = join(".singularity-aidr", "connectors", "claude");
const SETTINGS_RELATIVE_PATH = join(".claude", "settings.json");
const SHA256_PATTERN = /^[a-fA-F0-9]{64}$/;
const MAX_RECEIPT_BYTES = 65536;

/** Every reason the command can refuse to remove anything, machine-readable. */
export type UninstallRefusalCode =
	| "home_invalid"
	| "receipt_missing"
	| "receipt_unreadable"
	| "receipt_invalid_json"
	| "receipt_not_an_object"
	| "receipt_unsupported_schema"
	| "receipt_connector_unsupported"
	| "receipt_canary_not_passed"
	| "receipt_digest_invalid"
	| "receipt_digest_path_mismatch"
	| "receipt_settings_path_missing"
	| "receipt_settings_path_mismatch"
	| "receipt_path_outside_managed_root"
	| "receipt_connector_missing"
	| "settings_not_a_regular_file"
	| "settings_unreadable"
	| "settings_invalid_json"
	| "settings_invalid_shape"
	| "settings_write_failed";

export interface UninstallReport {
	schema_version: 1;
	action: "uninstall";
	outcome: "removed" | "nothing_to_remove" | "refused";
	home: string;
	settings_path: string;
	receipt_path: string;
	/** The verified receipt facts, or null when the receipt did not verify. */
	receipt: {
		connector: string;
		artifact_sha256: string;
		path: string;
		local_canary: string;
	} | null;
	/** Exactly the registrations removed by this run (empty when nothing ran). */
	removed: { event: string; command: string | null }[];
	/** What was deliberately left in place. */
	preserved: { entries: number; hooks: number; events: string[] };
	/** Backup of the untouched agent settings, written only when a change was made. */
	backup_path: string | null;
	/** Whether the local `hooksInstalled` flag was updated for this user's config. */
	state_recorded: boolean;
	/** True only when the agent settings file was actually rewritten. */
	changed: boolean;
	reason?: { code: UninstallRefusalCode; detail: string };
}

export interface UninstallAidrOptions {
	/**
	 * Target an explicit home directory instead of the current user's. The fleet
	 * and verification tooling passes this; the CLI never escalates privileges,
	 * so the caller must already be allowed to write the target settings file.
	 */
	home?: string;
}

/** Windows path spellings are case-insensitive; POSIX ones are not. */
function samePath(left: string, right: string): boolean {
	const a = resolve(left);
	const b = resolve(right);
	return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/** True only when `child` is strictly below `parent` (never `parent` itself). */
function isStrictlyInside(child: string, parent: string): boolean {
	const base = `${resolve(parent)}${sep}`;
	const target = `${resolve(child)}${sep}`;
	if (process.platform === "win32")
		return target.toLowerCase().startsWith(base.toLowerCase()) && target !== base;
	return target.startsWith(base) && target !== base;
}

/**
 * Validate an explicit `--home` the same way the fleet scripts validate
 * `-TargetHome`: absolute, an existing directory, and never a filesystem root or
 * a shared operating-system directory. This is a safety rail, not a privilege
 * check — the process still needs ordinary filesystem permission to write.
 */
function validateHome(home: string): string | null {
	if (!isAbsolute(home)) return "Home must be an explicit absolute path.";
	const target = resolve(home);
	let stats: ReturnType<typeof statSync>;
	try {
		stats = statSync(target);
	} catch {
		return "Home does not exist.";
	}
	if (!stats.isDirectory()) return "Home is not a directory.";
	if (target === parse(target).root) return "Home cannot be a filesystem root.";
	if (process.platform === "win32") {
		const forbidden = [
			process.env.windir,
			process.env.SystemRoot,
			process.env.ProgramData,
			process.env.ProgramFiles,
			process.env["ProgramFiles(x86)"],
		];
		const actual = realpathSync(target);
		for (const entry of forbidden) {
			if (entry && existsSync(entry)) {
				const protectedPath = realpathSync(entry);
				if (samePath(protectedPath, actual) || isStrictlyInside(actual, protectedPath)) {
					return "Home cannot be within a shared operating-system directory.";
				}
			}
		}
	}
	return null;
}

interface ReceiptFacts {
	connector: string;
	artifact_sha256: string;
	path: string;
	local_canary: string;
	settings_path: string;
}

/**
 * Verify the installation receipt written by `scripts/endpoint-install.mjs`
 * (line 121). Every field checked here is one the installer wrote, so a receipt
 * that fails any check is either absent, truncated or edited after the fact —
 * in all three cases the command refuses and changes nothing.
 */
function verifyReceipt(
	receiptPath: string,
	settingsPath: string,
	connectorRoot: string,
): { ok: true; facts: ReceiptFacts } | { ok: false; code: UninstallRefusalCode; detail: string } {
	if (!existsSync(receiptPath)) {
		return {
			ok: false,
			code: "receipt_missing",
			detail: `No AIDR installation receipt at ${receiptPath}; the installation cannot be attributed and nothing was removed.`,
		};
	}
	let stats: ReturnType<typeof statSync>;
	let raw: string;
	try {
		stats = statSync(receiptPath);
		if (!stats.isFile() || lstatSync(receiptPath).isSymbolicLink()) {
			return {
				ok: false,
				code: "receipt_unreadable",
				detail: "The installation receipt is not a regular file.",
			};
		}
		if (stats.size > MAX_RECEIPT_BYTES) {
			return {
				ok: false,
				code: "receipt_unreadable",
				detail: "The installation receipt is implausibly large.",
			};
		}
		raw = readFileSync(receiptPath, "utf8");
	} catch (error) {
		return {
			ok: false,
			code: "receipt_unreadable",
			detail: `The installation receipt could not be read: ${error instanceof Error ? error.message : String(error)}`,
		};
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return {
			ok: false,
			code: "receipt_invalid_json",
			detail: "The installation receipt is not valid JSON.",
		};
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		return {
			ok: false,
			code: "receipt_not_an_object",
			detail: "The installation receipt is not a JSON object.",
		};
	}
	const receipt = parsed as Record<string, unknown>;
	if (receipt.schema_version !== RECEIPT_SCHEMA_VERSION) {
		return {
			ok: false,
			code: "receipt_unsupported_schema",
			detail: `Unsupported installation receipt schema ${JSON.stringify(receipt.schema_version)}.`,
		};
	}
	if (receipt.connector !== SUPPORTED_CONNECTOR) {
		return {
			ok: false,
			code: "receipt_connector_unsupported",
			detail: `The receipt describes connector ${JSON.stringify(receipt.connector)}; this command only removes ${SUPPORTED_CONNECTOR} hooks.`,
		};
	}
	if (receipt.local_canary !== "deny") {
		return {
			ok: false,
			code: "receipt_canary_not_passed",
			detail:
				"The receipt does not record a passing local deny canary; the installation is unverified.",
		};
	}
	if (
		typeof receipt.artifact_sha256 !== "string" ||
		!SHA256_PATTERN.test(receipt.artifact_sha256)
	) {
		return {
			ok: false,
			code: "receipt_digest_invalid",
			detail: "The receipt's connector digest is missing or not a SHA-256 hex digest.",
		};
	}
	if (typeof receipt.path !== "string" || receipt.path === "") {
		return {
			ok: false,
			code: "receipt_path_outside_managed_root",
			detail: "The receipt names no connector path.",
		};
	}
	// The connector lives at connectors/claude/<digest> (endpoint-install.mjs
	// line 33), so a receipt pointing elsewhere is not this installation.
	if (!isStrictlyInside(receipt.path, connectorRoot)) {
		return {
			ok: false,
			code: "receipt_path_outside_managed_root",
			detail: `The receipt names a connector path outside ${connectorRoot}.`,
		};
	}
	if (
		resolve(receipt.path).split(sep).pop()?.toLowerCase() !== receipt.artifact_sha256.toLowerCase()
	) {
		return {
			ok: false,
			code: "receipt_digest_path_mismatch",
			detail: "The receipt's connector directory name does not match its recorded digest.",
		};
	}
	if (typeof receipt.settings_path !== "string" || receipt.settings_path === "") {
		return {
			ok: false,
			code: "receipt_settings_path_missing",
			detail: "The receipt does not record which agent settings file it changed.",
		};
	}
	if (!samePath(receipt.settings_path, settingsPath)) {
		return {
			ok: false,
			code: "receipt_settings_path_mismatch",
			detail: `The receipt records ${receipt.settings_path}, not ${settingsPath}; refusing to edit a file it does not name.`,
		};
	}
	if (!existsSync(receipt.path) || !statSync(receipt.path).isDirectory()) {
		return {
			ok: false,
			code: "receipt_connector_missing",
			detail: `The receipt's connector directory ${receipt.path} is missing.`,
		};
	}
	return {
		ok: true,
		facts: {
			connector: receipt.connector,
			artifact_sha256: receipt.artifact_sha256,
			path: receipt.path,
			local_canary: receipt.local_canary,
			settings_path: receipt.settings_path,
		},
	};
}

function emptyReport(home: string, settingsPath: string, receiptPath: string): UninstallReport {
	return {
		schema_version: 1,
		action: "uninstall",
		outcome: "nothing_to_remove",
		home,
		settings_path: settingsPath,
		receipt_path: receiptPath,
		receipt: null,
		removed: [],
		preserved: { entries: 0, hooks: 0, events: [] },
		backup_path: null,
		state_recorded: false,
		changed: false,
	};
}

function refuse(
	report: UninstallReport,
	code: UninstallRefusalCode,
	detail: string,
): UninstallReport {
	report.outcome = "refused";
	report.reason = { code, detail };
	report.changed = false;
	return report;
}

/**
 * Measure the installation and remove only the hooks AIDR registered.
 *
 * Pure with respect to process state: it reads and writes exactly the files
 * under `home`, never reads the ambient configuration, and never exits.
 */
export async function uninstallAidr(options: UninstallAidrOptions = {}): Promise<UninstallReport> {
	const requested = options.home ?? homedir();
	const home = resolve(requested);
	const settingsPath = join(home, SETTINGS_RELATIVE_PATH);
	const receiptPath = join(home, RECEIPT_RELATIVE_PATH);
	const report = emptyReport(home, settingsPath, receiptPath);

	if (options.home !== undefined) {
		const problem = validateHome(options.home);
		if (problem) return refuse(report, "home_invalid", problem);
	}

	const connectorRoot = join(home, CONNECTOR_ROOT_RELATIVE);
	const verified = verifyReceipt(receiptPath, settingsPath, connectorRoot);
	if (!verified.ok) return refuse(report, verified.code, verified.detail);
	report.receipt = verified.facts;

	if (!existsSync(settingsPath)) {
		// The receipt verified and there is no hook file to clean: nothing to do,
		// and nothing to claim.
		return report;
	}
	try {
		if (lstatSync(settingsPath).isSymbolicLink() || !statSync(settingsPath).isFile()) {
			return refuse(
				report,
				"settings_not_a_regular_file",
				`${settingsPath} is not a regular file.`,
			);
		}
	} catch (error) {
		return refuse(
			report,
			"settings_unreadable",
			`${settingsPath} could not be inspected: ${error instanceof Error ? error.message : String(error)}`,
		);
	}

	let original: Buffer;
	try {
		original = readFileSync(settingsPath);
	} catch (error) {
		return refuse(
			report,
			"settings_unreadable",
			`${settingsPath} could not be read: ${error instanceof Error ? error.message : String(error)}`,
		);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(original.toString("utf8"));
	} catch {
		return refuse(
			report,
			"settings_invalid_json",
			`${settingsPath} is not valid JSON; it was not rewritten.`,
		);
	}

	let removal: ReturnType<typeof removeManagedHooks>;
	try {
		removal = removeManagedHooks(parsed);
	} catch (error) {
		if (error instanceof ManagedHookError)
			return refuse(report, "settings_invalid_shape", error.message);
		throw error;
	}
	report.preserved = {
		entries: removal.preservedEntries,
		hooks: removal.preservedHooks,
		events: removal.emptiedEvents,
	};
	if (!removal.changed) {
		// Idempotent by construction: no change means no write, no backup and no
		// reformatting of the customer's file.
		return report;
	}

	const backupPath = `${settingsPath}.aidr-uninstall-backup-${Date.now()}`;
	const temporary = `${settingsPath}.aidr-${process.pid}.tmp`;
	let backupWritten = false;
	try {
		writeFileSync(backupPath, original, { flag: "wx", mode: 0o600 });
		backupWritten = true;
		writeFileSync(temporary, `${JSON.stringify(removal.settings, null, 2)}\n`, {
			flag: "wx",
			mode: 0o600,
		});
		// ponytail: Claude has no atomic compare-and-swap; check again immediately before replacement.
		if (!readFileSync(settingsPath).equals(original)) {
			throw new Error(
				"Agent settings changed during uninstall; retry after closing other settings editors.",
			);
		}
		renameSync(temporary, settingsPath);
	} catch (error) {
		// Leave no half-written state behind, and do not claim a removal that did
		// not land.
		for (const path of backupWritten ? [temporary, backupPath] : [temporary]) {
			try {
				unlinkSync(path);
			} catch {
				// Best effort: the report already says the removal did not complete.
			}
		}
		return refuse(
			report,
			"settings_write_failed",
			`The agent settings could not be rewritten, so no removal was completed: ${error instanceof Error ? error.message : String(error)}`,
		);
	}

	report.removed = removal.removed.map((record) => ({
		event: record.event,
		command: record.command,
	}));
	report.backup_path = backupPath;
	report.outcome = "removed";
	report.changed = true;
	return report;
}

/** Human-readable line per refusal, pointing at the supported recovery step. */
function refusalRemedy(code: UninstallRefusalCode): string {
	switch (code) {
		case "receipt_missing":
		case "receipt_unreadable":
			return "Run 'aidr status' to see what is registered. A Claude Code marketplace install has no receipt: remove it with '/plugin uninstall aidr@aidr' and '/plugin marketplace remove aidr'. If AIDR was installed by hand or by an MDM, remove it with the same tool that installed it.";
		case "settings_invalid_json":
		case "settings_invalid_shape":
			return "Repair or restore your agent settings file first; it was left untouched.";
		default:
			return "Run 'aidr status' for the measured installation state before retrying.";
	}
}

export function printUninstallReport(report: UninstallReport): void {
	console.log("Singularity AIDR — uninstall (managed hooks only)");
	console.log(`Target home: ${report.home}`);
	if (report.receipt) {
		console.log(
			`Installation receipt verified: ${report.receipt_path} (connector ${report.receipt.connector}, digest ${report.receipt.artifact_sha256.slice(0, 12)}…)`,
		);
	}

	if (report.outcome === "refused") {
		console.log(`Refused: ${report.reason?.detail ?? "the installation could not be verified."}`);
		console.log(`Reason code: ${report.reason?.code ?? "unknown"}`);
		console.log("No configuration was changed.");
		if (report.reason) console.log(refusalRemedy(report.reason.code));
		return;
	}

	if (report.outcome === "nothing_to_remove") {
		console.log("No AIDR-managed hook entries found; agent settings were left untouched.");
		console.log(
			`Left alone: ${report.preserved.entries} hook entr${report.preserved.entries === 1 ? "y" : "ies"} and ${report.preserved.hooks} non-AIDR hook registration(s).`,
		);
		return;
	}

	console.log(`Removed ${report.removed.length} AIDR-managed hook registration(s):`);
	for (const record of report.removed) {
		console.log(`  ${record.event.padEnd(12)} ${record.command ?? "(no command recorded)"}`);
	}
	console.log(
		`Left alone: ${report.preserved.entries} hook entr${report.preserved.entries === 1 ? "y" : "ies"} and ${report.preserved.hooks} non-AIDR hook registration(s).`,
	);
	if (report.preserved.events.length > 0) {
		console.log(
			`Hook events left empty and therefore deleted: ${report.preserved.events.join(", ")}`,
		);
	}
	console.log(`Backup of the previous settings: ${report.backup_path}`);
	console.log(
		"Preserved: AIDR policy/allowlist configuration, connector files, the installation receipt and every non-AIDR hook.",
	);
	console.log(
		"The local CLI credential and its vault item are also preserved; use 'aidr config revoke-key' to remove that credential. Managed endpoint API keys are unchanged.",
	);
	console.log(
		"Protection is NOT active for this agent now: AIDR no longer inspects its tool calls.",
	);
	console.log(
		"Re-enable it with 'aidr setup' and the connector install for your agent (docs/getting-started.md).",
	);
}

async function uninstallCommand(
	options: { home?: string; json?: boolean; yes?: boolean } = {},
	deps: OperatorCommandDeps = {},
): Promise<void> {
	// Removing the hooks switches inspection off for the agent, so it is an
	// operator-only action confirmed like `aidr allowlist add`: an agent tool
	// call has no TTY and cannot set AIDR_OPERATOR_NONINTERACTIVE (CLT-SELF-007).
	try {
		await confirmOperatorAction({
			prompt: [
				"Singularity AIDR — uninstall the managed agent hooks",
				`  Target home: ${escapeTerminalText(resolve(options.home ?? homedir()))}`,
				"AIDR will no longer inspect this agent's tool calls.",
			].join("\n"),
			word: "uninstall",
			yes: options.yes,
			env: deps.env,
			streams: deps.streams,
		});
	} catch (error) {
		console.error(
			`${error instanceof OperatorConfirmationError ? error.message : String(error)} Nothing was removed.`,
		);
		process.exitCode = 1;
		return;
	}
	const report = await uninstallAidr({ home: options.home });
	if (report.outcome === "removed" && options.home === undefined) {
		// Record the measured state in the invoking user's config, the same flag
		// `aidr setup` writes (see install-hooks.ts). This is intentionally skipped
		// for an explicit --home target: the config manager is bound to the current
		// user's home, so recording it there would describe the wrong machine.
		try {
			recordHooksInstalled(false);
			report.state_recorded = true;
		} catch {
			report.state_recorded = false;
		}
	}
	if (options.json) console.log(JSON.stringify(report, null, 2));
	else printUninstallReport(report);
	if (report.outcome === "refused") process.exitCode = 1;
}

export default uninstallCommand;
