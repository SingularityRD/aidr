import {
	existsSync,
	lstatSync,
	readdirSync,
	readFileSync,
	realpathSync,
	renameSync,
	rmSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, parse, resolve, sep } from "node:path";
import {
	AUDIT_CHAIN_ROOT_VAULT_PREFIX,
	escapeTerminalText,
	OPERATOR_APPROVAL_KEY_ID,
	OPERATOR_APPROVAL_LEDGER_ID,
	resolveSecretStore,
	type SecretStore,
	VERSION,
} from "@singularityrd/aidr-core";
import {
	type ConnectorDeps,
	type HostCommandRunner,
	type HostId,
	type HostRemovalResult,
	removeConnectors,
} from "../utils/connector-install.js";
import { detectConnectorStatuses } from "../utils/connector-status.js";
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
import {
	STANDALONE_ARTIFACT_ID,
	STANDALONE_INSTALL_KIND,
	STANDALONE_MANIFEST,
} from "../utils/standalone.js";
import { parseHosts } from "./setup.js";

/**
 * `aidr uninstall` — remove AIDR: every connector, the AIDR-managed hooks, the
 * data directory and the AIDR vault items ({@link uninstallEverything}, PRD-9).
 * `--hooks-only` runs only {@link uninstallAidr}, described below, which is also
 * the first step of the full removal.
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
 * A standalone (desktop installer) receipt names the installed bundle instead
 * of a per-user digest directory. It is attributable when that path is an
 * absolute directory holding a standalone bundle manifest. The manifest digest
 * is not compared: an upgrade replaces the bundle in place, and the receipt of
 * a user who did not rerun setup still names the same, upgraded bundle.
 */
function verifyStandaloneReceiptPath(
	path: string,
): { ok: false; code: UninstallRefusalCode; detail: string } | null {
	if (!isAbsolute(path)) {
		return {
			ok: false,
			code: "receipt_path_outside_managed_root",
			detail: "The receipt's bundle path is not absolute.",
		};
	}
	try {
		const manifest = JSON.parse(readFileSync(join(path, STANDALONE_MANIFEST), "utf8"));
		if (manifest?.artifact_id === STANDALONE_ARTIFACT_ID) return null;
	} catch {
		// Reported below.
	}
	return {
		ok: false,
		code: "receipt_connector_missing",
		detail: `The receipt's AIDR bundle ${path} is missing or has no bundle manifest. Run 'aidr uninstall' before removing the installer package, or reinstall it first.`,
	};
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
	if (receipt.install_kind === STANDALONE_INSTALL_KIND) {
		const standalone = verifyStandaloneReceiptPath(receipt.path);
		if (standalone) return standalone;
	} else {
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
			resolve(receipt.path).split(sep).pop()?.toLowerCase() !==
			receipt.artifact_sha256.toLowerCase()
		) {
			return {
				ok: false,
				code: "receipt_digest_path_mismatch",
				detail: "The receipt's connector directory name does not match its recorded digest.",
			};
		}
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

// ── Full removal: every connector, the data directory and vault items ────

const DATA_DIR_NAME = ".singularity-aidr";
const MAX_SCANNED_JSON_BYTES = 1024 * 1024;

export interface FullUninstallOptions {
	home?: string;
	/** Keep `~/.singularity-aidr` and the vault items. */
	keepData?: boolean;
	dryRun?: boolean;
	/** Connector hosts to remove; default all. */
	hosts?: readonly HostId[];
	/** PATH etc. for host CLIs (tests). */
	env?: NodeJS.ProcessEnv;
	run?: HostCommandRunner;
	/** Vault resolver (tests); defaults to the platform vault. */
	resolveVault?: (selection?: string) => SecretStore;
}

export interface FullUninstallReport {
	schema_version: 2;
	action: "uninstall";
	outcome: "removed" | "nothing_to_remove" | "partial" | "refused" | "dry_run";
	home: string;
	/** Receipt-managed Claude Code hooks (the `--hooks-only` report). */
	claude_hooks: UninstallReport;
	connectors: HostRemovalResult[];
	data: {
		path: string;
		action: "deleted" | "kept" | "would_delete" | "absent" | "failed";
		reason?: string;
	};
	vault: { revoked: string[]; failed: string[]; note?: string };
	reason?: { code: UninstallRefusalCode; detail: string };
}

/** Managed hooks (installer marker) still present in Claude Code settings. */
function claudeManagedHookCount(settingsPath: string): number {
	try {
		return removeManagedHooks(JSON.parse(readFileSync(settingsPath, "utf8"))).removed.length;
	} catch {
		return 0;
	}
}

interface VaultReference {
	store: string | null;
	id: string;
}

const SAFE_VAULT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const VAULT_STORES = new Set(["windows-dpapi", "macos-keychain", "linux-secret-service"]);

/** `{store, id}` secret references anywhere in a JSON value (config, managed state, ...). */
function collectReferences(value: unknown, out: VaultReference[], depth = 0): void {
	if (depth > 8 || typeof value !== "object" || value === null) return;
	if (Array.isArray(value)) {
		for (const entry of value) collectReferences(entry, out, depth + 1);
		return;
	}
	const record = value as Record<string, unknown>;
	if (
		typeof record.store === "string" &&
		VAULT_STORES.has(record.store) &&
		typeof record.id === "string" &&
		SAFE_VAULT_ID.test(record.id)
	) {
		out.push({ store: record.store, id: record.id });
	}
	for (const entry of Object.values(record)) collectReferences(entry, out, depth + 1);
}

/**
 * Every vault item AIDR can attribute to this installation: the approval key
 * and ledger, the audit-chain root keys named in `audit-chain/keys.json`, and
 * every secret reference held by a JSON file in the data directory.
 */
export function collectAidrVaultItems(dataDir: string): VaultReference[] {
	const items: VaultReference[] = [
		{ store: null, id: OPERATOR_APPROVAL_KEY_ID },
		{ store: null, id: OPERATOR_APPROVAL_LEDGER_ID },
	];
	const jsonFiles: string[] = [];
	for (const directory of [dataDir, join(dataDir, "audit-chain")]) {
		let names: string[];
		try {
			names = readdirSync(directory);
		} catch {
			continue;
		}
		for (const name of names) {
			if (name.endsWith(".json")) jsonFiles.push(join(directory, name));
		}
	}
	for (const path of jsonFiles) {
		try {
			const info = lstatSync(path);
			if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_SCANNED_JSON_BYTES) continue;
			const parsed = JSON.parse(readFileSync(path, "utf8")) as unknown;
			collectReferences(parsed, items);
			if (path.endsWith(join("audit-chain", "keys.json"))) {
				const kids = new Set<string>();
				const visit = (node: unknown): void => {
					if (typeof node !== "object" || node === null) return;
					for (const [key, entry] of Object.entries(node as Record<string, unknown>)) {
						if ((key === "kid" || key === "root_kid") && typeof entry === "string") kids.add(entry);
						else visit(entry);
					}
				};
				visit(parsed);
				for (const kid of kids) {
					const id = `${AUDIT_CHAIN_ROOT_VAULT_PREFIX}${kid}`;
					if (SAFE_VAULT_ID.test(id)) items.push({ store: null, id });
				}
			}
		} catch {
			// An unreadable or non-JSON file holds no reference we can act on.
		}
	}
	const seen = new Set<string>();
	return items.filter((item) => {
		const key = `${item.store ?? "*"}\0${item.id}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

function revokeVaultItems(
	items: VaultReference[],
	resolveVault: (selection?: string) => SecretStore,
): FullUninstallReport["vault"] {
	const vault: FullUninstallReport["vault"] = { revoked: [], failed: [] };
	const stores = new Map<string, SecretStore | null>();
	const storeFor = (selection: string | null): SecretStore | null => {
		const key = selection ?? "auto";
		if (!stores.has(key)) {
			try {
				const store = resolveVault(selection ?? undefined);
				stores.set(key, store.osProtected ? store : null);
			} catch {
				stores.set(key, null);
			}
		}
		return stores.get(key) ?? null;
	};
	for (const item of items) {
		const store = storeFor(item.store);
		if (!store) continue;
		try {
			store.revoke(item.id);
			vault.revoked.push(`${store.kind}:${item.id}`);
		} catch {
			vault.failed.push(`${store.kind}:${item.id}`);
		}
	}
	if (!storeFor(null)) {
		vault.note =
			"No OS credential vault answers on this host, so AIDR kept nothing there; keys sealed in the encrypted file store are deleted with the data directory.";
	}
	return vault;
}

function isRegistered(state: string): boolean {
	return state === "installed" || state === "installed_but_degraded";
}

/**
 * Remove AIDR completely: receipt-managed Claude Code hooks, the connector of
 * every host, then — unless `keepData` — the AIDR vault items and the data
 * directory. The data directory is deleted only when nothing that runs from it
 * is still registered, so a failed host removal never leaves a hook pointing at
 * deleted files.
 */
export async function uninstallEverything(
	options: FullUninstallOptions = {},
): Promise<FullUninstallReport> {
	const home = resolve(options.home ?? homedir());
	const dataDir = join(home, DATA_DIR_NAME);
	const settingsPath = join(home, SETTINGS_RELATIVE_PATH);
	const report: FullUninstallReport = {
		schema_version: 2,
		action: "uninstall",
		outcome: "nothing_to_remove",
		home,
		claude_hooks: emptyReport(home, settingsPath, join(home, RECEIPT_RELATIVE_PATH)),
		connectors: [],
		data: { path: dataDir, action: existsSync(dataDir) ? "kept" : "absent" },
		vault: { revoked: [], failed: [] },
	};
	if (options.home !== undefined) {
		const problem = validateHome(options.home);
		if (problem) {
			report.outcome = "refused";
			report.reason = { code: "home_invalid", detail: problem };
			return report;
		}
	}

	const claudeSelected = !options.hosts || options.hosts.includes("claude-code");
	const managedHooks = claudeSelected ? claudeManagedHookCount(settingsPath) : 0;
	if (options.dryRun) {
		report.claude_hooks.removed = Array.from({ length: managedHooks }, () => ({
			event: "(managed)",
			command: null,
		}));
	} else if (managedHooks > 0) {
		report.claude_hooks = await uninstallAidr({ home: options.home });
	}

	const deps: ConnectorDeps = {
		home,
		env: options.env,
		run: options.run,
		version: VERSION,
	};
	report.connectors = removeConnectors(deps, { hosts: options.hosts, dryRun: options.dryRun });

	// Measured across ALL hosts, not only the selected ones: data used by a host
	// that was not selected must not be deleted under it.
	const hooksLeft = options.dryRun ? 0 : claudeManagedHookCount(settingsPath);
	const stillRegistered = options.dryRun
		? []
		: [
				...detectConnectorStatuses(home, options.env ?? process.env)
					.filter((status) => isRegistered(status.state))
					.map((status) => status.label),
				...(hooksLeft > 0 ? ["Claude Code managed hooks"] : []),
			];
	const ownHome = samePath(home, homedir());

	if (report.data.action === "absent") {
		// Nothing to delete.
	} else if (options.keepData) {
		report.data.reason = "--keep-data";
	} else if (stillRegistered.length > 0) {
		report.data.reason = `kept because ${stillRegistered.join(", ")} ${stillRegistered.length === 1 ? "is" : "are"} still registered and may run from it; remove ${stillRegistered.length === 1 ? "it" : "them"} and rerun`;
	} else if (options.dryRun) {
		report.data.action = "would_delete";
	} else {
		if (ownHome) {
			report.vault = revokeVaultItems(
				collectAidrVaultItems(dataDir),
				options.resolveVault ?? ((selection) => resolveSecretStore({ selection })),
			);
		} else {
			report.vault.note =
				"Vault items belong to the account that owns the target home; run the uninstall as that user to remove them.";
		}
		try {
			if (lstatSync(dataDir).isSymbolicLink()) {
				unlinkSync(dataDir);
			} else {
				rmSync(dataDir, { recursive: true, force: true });
			}
			report.data.action = "deleted";
		} catch (error) {
			report.data.action = "failed";
			report.data.reason = error instanceof Error ? error.message : String(error);
		}
	}

	const removedSomething =
		report.claude_hooks.outcome === "removed" ||
		report.connectors.some((entry) => entry.action === "removed") ||
		report.data.action === "deleted" ||
		report.vault.revoked.length > 0;
	const incomplete =
		stillRegistered.length > 0 ||
		report.connectors.some((entry) => entry.action === "failed") ||
		report.data.action === "failed" ||
		report.vault.failed.length > 0;
	if (options.dryRun) report.outcome = "dry_run";
	else if (incomplete) report.outcome = "partial";
	else report.outcome = removedSomething ? "removed" : "nothing_to_remove";
	return report;
}

const REMOVAL_TEXT: Record<HostRemovalResult["action"], string> = {
	removed: "removed",
	nothing_to_remove: "nothing to remove",
	would_remove: "would remove",
	manual: "manual step needed",
	failed: "FAILED",
};

function printFullUninstallReport(report: FullUninstallReport): void {
	console.log("Singularity AIDR — uninstall");
	console.log(`Target home: ${report.home}`);
	if (report.outcome === "refused") {
		console.log(`Refused: ${report.reason?.detail ?? "the target could not be verified."}`);
		console.log("Nothing was changed.");
		return;
	}
	const hooks = report.claude_hooks;
	if (hooks.outcome === "removed") {
		console.log(
			`Claude Code managed hooks: removed ${hooks.removed.length} (backup: ${hooks.backup_path}).`,
		);
	} else if (hooks.outcome === "refused") {
		console.log(`Claude Code managed hooks: NOT removed — ${hooks.reason?.detail ?? "refused"}`);
	} else if (report.outcome === "dry_run" && hooks.removed.length > 0) {
		console.log(`Claude Code managed hooks: would remove ${hooks.removed.length}.`);
	}
	console.log("Connectors:");
	for (const entry of report.connectors) {
		console.log(`  ${entry.label.padEnd(12)} ${REMOVAL_TEXT[entry.action]} — ${entry.detail}`);
		for (const change of entry.changes) console.log(`               ${change}`);
	}
	const data = report.data;
	const dataLine: Record<FullUninstallReport["data"]["action"], string> = {
		deleted: `deleted ${data.path} (configuration, allowlist, audit log, approvals, quarantine, keys)`,
		kept: `kept ${data.path}${data.reason ? ` (${data.reason})` : ""}`,
		would_delete: `would delete ${data.path} and the AIDR vault items`,
		absent: `${data.path} does not exist`,
		failed: `FAILED to delete ${data.path}: ${data.reason ?? "unknown error"}`,
	};
	console.log(`Local data: ${dataLine[data.action]}`);
	if (report.vault.revoked.length > 0) {
		console.log(`Vault items removed: ${report.vault.revoked.join(", ")}`);
	}
	if (report.vault.failed.length > 0) {
		console.log(`Vault items that could NOT be removed: ${report.vault.failed.join(", ")}`);
	}
	if (report.vault.note) console.log(report.vault.note);
	const pending = report.connectors.filter((entry) => entry.followUp.length > 0);
	if (pending.length > 0) {
		console.log("Still to do by hand:");
		for (const entry of pending) for (const line of entry.followUp) console.log(line);
	}
	if (report.outcome === "dry_run") console.log("Dry run: nothing was changed.");
	else if (report.outcome === "partial") {
		console.log(
			"Uninstall is INCOMPLETE: see the lines above. AIDR may still inspect some agents.",
		);
	} else if (report.outcome === "removed") {
		console.log("AIDR was removed. Restart the agent hosts so they unload it.");
		console.log(
			"Browser Guard is a browser extension: remove it from the browser (or the enterprise policy) separately.",
		);
	} else {
		console.log("Nothing to remove.");
	}
}

interface UninstallCommandOptions {
	home?: string;
	json?: boolean;
	yes?: boolean;
	/** Keep ~/.singularity-aidr and the vault items. */
	keepData?: boolean;
	dryRun?: boolean;
	/** Comma-separated hosts (default: all). */
	host?: string;
	/** Legacy: remove only the receipt-managed Claude Code hooks. */
	hooksOnly?: boolean;
}

interface UninstallCommandDeps extends OperatorCommandDeps {
	run?: HostCommandRunner;
	resolveVault?: (selection?: string) => SecretStore;
}

function confirmationPrompt(options: UninstallCommandOptions): string {
	const target = escapeTerminalText(resolve(options.home ?? homedir()));
	if (options.hooksOnly) {
		return [
			"Singularity AIDR — uninstall the managed agent hooks",
			`  Target home: ${target}`,
			"AIDR will no longer inspect this agent's tool calls.",
		].join("\n");
	}
	return [
		"Singularity AIDR — uninstall",
		`  Target home: ${target}`,
		"  Removes the AIDR connector from every agent host and the AIDR-managed hooks.",
		options.keepData
			? "  Keeps ~/.singularity-aidr and the AIDR vault items (--keep-data)."
			: "  DELETES ~/.singularity-aidr (configuration, allowlist, audit log, approvals,\n  quarantined files, keys) and the AIDR items in the OS credential vault.",
		"AIDR will no longer inspect any agent's tool calls.",
	].join("\n");
}

async function uninstallCommand(
	options: UninstallCommandOptions = {},
	deps: UninstallCommandDeps = {},
): Promise<void> {
	// Removing the hooks switches inspection off for the agent, so it is an
	// operator-only action confirmed like `aidr allowlist add`: an agent tool
	// call has no TTY and cannot set AIDR_OPERATOR_NONINTERACTIVE (CLT-SELF-007).
	if (!options.dryRun) {
		try {
			await confirmOperatorAction({
				prompt: confirmationPrompt(options),
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
	}
	if (!options.hooksOnly) {
		let hosts: HostId[] | undefined;
		try {
			hosts = parseHosts(options.host);
		} catch (error) {
			console.error(error instanceof Error ? error.message : String(error));
			process.exitCode = 1;
			return;
		}
		const report = await uninstallEverything({
			home: options.home,
			keepData: options.keepData,
			dryRun: options.dryRun,
			hosts,
			env: deps.env ?? process.env,
			run: deps.run,
			resolveVault: deps.resolveVault,
		});
		if (options.keepData && !options.dryRun && options.home === undefined) {
			try {
				recordHooksInstalled(false);
			} catch {
				// The report already states what was measured.
			}
		}
		if (options.json) console.log(JSON.stringify(report, null, 2));
		else printFullUninstallReport(report);
		if (report.outcome === "partial" || report.outcome === "refused") process.exitCode = 1;
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
