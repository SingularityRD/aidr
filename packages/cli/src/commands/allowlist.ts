import {
	type Allowlist,
	type AllowlistEntry,
	addCommand,
	addFilePath,
	addUrl,
	escapeTerminalText,
	hashCommand,
	isInvalidConfig,
	loadAllowlist,
	loadConfig,
	normalizeFilePath,
	normalizeUrl,
	removeCommand,
	removeFilePath,
	removeUrl,
	resolvePath,
	saveAllowlist,
} from "@singularityrd/aidr-core";
import {
	type ConfirmationStreams,
	confirmOperatorAction,
	OperatorConfirmationError,
	operatorIdentity,
} from "../utils/operator-confirm.js";

type AllowlistType = "url" | "command" | "file_path";
const TYPES: readonly AllowlistType[] = ["url", "command", "file_path"];

/** Test seams; production callers pass nothing. */
export interface AllowlistCommandDeps {
	configPath?: string;
	env?: NodeJS.ProcessEnv;
	streams?: ConfirmationStreams;
}

function fail(message: string): void {
	console.error(message);
	process.exitCode = 1;
}

function parseType(value: string): AllowlistType | null {
	const normalized = value.trim().toLowerCase().replace("-", "_");
	if (normalized === "file" || normalized === "path") return "file_path";
	return (TYPES as readonly string[]).includes(normalized) ? (normalized as AllowlistType) : null;
}

/** Parses the type argument; reports an unknown type and returns null. */
function requireType(typeArg: string): AllowlistType | null {
	const type = parseType(typeArg);
	if (!type) {
		fail(
			`Unknown allowlist type "${escapeTerminalText(typeArg)}". Use one of: ${TYPES.join(", ")}.`,
		);
	}
	return type;
}

async function loadCurrent(deps: AllowlistCommandDeps) {
	const config = await loadConfig(deps.configPath);
	if (isInvalidConfig(config)) {
		throw new Error(
			"The AIDR configuration file is invalid; fix it (aidr doctor) before changing the allowlist.",
		);
	}
	const allowlist = await loadAllowlist(config.allowlist);
	return { config, allowlist, path: resolvePath(config.allowlist.path) };
}

type Current = Awaited<ReturnType<typeof loadCurrent>>;

/** Loads the config and allowlist; reports a failure and returns null. */
async function tryLoadCurrent(deps: AllowlistCommandDeps): Promise<Current | null> {
	try {
		return await loadCurrent(deps);
	} catch (error) {
		fail(error instanceof Error ? error.message : String(error));
		return null;
	}
}

/** The value as the allowlist will store and match it (commands are shown as typed). */
function normalizedValue(type: AllowlistType, value: string): string {
	if (type === "url") return normalizeUrl(value);
	return type === "file_path" ? normalizeFilePath(value) : value;
}

function addEntry(allowlist: Allowlist, type: AllowlistType, value: string, reason: string): void {
	if (type === "url") addUrl(allowlist, value, reason, "operator");
	else if (type === "command") addCommand(allowlist, value, reason, "operator");
	else addFilePath(allowlist, value, reason, "operator");
}

function removeEntry(allowlist: Allowlist, type: AllowlistType, value: string): boolean {
	if (type === "url") return removeUrl(allowlist, value);
	if (type === "file_path") return removeFilePath(allowlist, value);
	// Accept the command text or the stored hash (as `list` shows it).
	const hash = value.replace(/^sha256:/, "").replace(/…$/, "");
	return (
		removeCommand(allowlist, hashCommand(value)) ||
		removeCommand(allowlist, hash) ||
		removeCommandByPrefix(allowlist, hash)
	);
}

function rows(allowlist: Allowlist) {
	const section = (type: AllowlistType, entries: Record<string, AllowlistEntry>) =>
		Object.entries(entries).map(([key, entry]) => ({
			type,
			// Commands are stored only as a hash of the normalized command text.
			// Reasons can come from the agent's allowlist tool, so every field is
			// rendered terminal-safe (control and bidi characters escaped).
			value: escapeTerminalText(key),
			added_at: escapeTerminalText(String(entry.addedAt)),
			reason: escapeTerminalText(String(entry.reason)),
			original_verdict: escapeTerminalText(String(entry.originalVerdict)),
		}));
	return [
		...section("url", allowlist.urls),
		...section("command", allowlist.commands),
		...section("file_path", allowlist.filePaths),
	];
}

/** `aidr allowlist list` */
export async function allowlistListCommand(
	options: { json?: boolean } = {},
	deps: AllowlistCommandDeps = {},
): Promise<void> {
	const current = await tryLoadCurrent(deps);
	if (!current) return;
	const entries = rows(current.allowlist);
	if (options.json) {
		console.log(JSON.stringify({ path: current.path, entries }, null, 2));
		return;
	}
	if (entries.length === 0) {
		console.log(`The allowlist is empty (${current.path}).`);
		return;
	}
	console.log(`Allowlist (${current.path}):`);
	for (const entry of entries) {
		const shown = entry.type === "command" ? `sha256:${entry.value.slice(0, 16)}…` : entry.value;
		console.log(`  ${entry.type.padEnd(9)} ${shown}  — ${entry.reason} (${entry.added_at})`);
	}
}

/**
 * `aidr allowlist add <type> <value>` — operator-only. A permanent allowlist
 * entry disables detection for that artifact, so it takes the same human
 * confirmation as `aidr approve`.
 */
export async function allowlistAddCommand(
	typeArg: string,
	value: string,
	options: { reason?: string; yes?: boolean } = {},
	deps: AllowlistCommandDeps = {},
): Promise<void> {
	const type = requireType(typeArg);
	if (!type) return;
	if (value.trim().length === 0) {
		fail("The value to allowlist is empty.");
		return;
	}
	const current = await tryLoadCurrent(deps);
	if (!current) return;
	// The value may have been pasted from an agent's message: show it with control
	// and bidi characters escaped, so what the operator confirms is what is added.
	const shown = escapeTerminalText(normalizedValue(type, value));

	let mode: Awaited<ReturnType<typeof confirmOperatorAction>>;
	try {
		mode = await confirmOperatorAction({
			relaxesProtection: true,
			prompt: [
				"Singularity AIDR — add a permanent allowlist entry",
				`  ${type}: ${shown}`,
				"Detection will no longer ask about or block this artifact.",
			].join("\n"),
			word: "allow",
			yes: options.yes,
			env: deps.env,
			streams: deps.streams,
		});
	} catch (error) {
		fail(error instanceof OperatorConfirmationError ? error.message : String(error));
		return;
	}

	const reason = options.reason?.trim() || `Added by operator ${operatorIdentity(mode)}`;
	addEntry(current.allowlist, type, value, reason);

	if (!(await saveAllowlist(current.allowlist, current.config.allowlist))) {
		fail(`Could not write the allowlist at ${current.path}; nothing was added.`);
		return;
	}
	const stored = type === "command" ? `sha256:${hashCommand(value).slice(0, 16)}…` : shown;
	console.log(`Added ${type} ${stored} to the allowlist.`);
}

/**
 * `aidr allowlist remove <type> <value>` — narrowing the allowlist never needs
 * confirmation: it can only make detection stricter.
 */
export async function allowlistRemoveCommand(
	typeArg: string,
	value: string,
	_options: Record<string, unknown> = {},
	deps: AllowlistCommandDeps = {},
): Promise<void> {
	const type = requireType(typeArg);
	if (!type) return;
	const current = await tryLoadCurrent(deps);
	if (!current) return;
	if (!removeEntry(current.allowlist, type, value)) {
		fail(`No ${type} entry matching that value is on the allowlist.`);
		return;
	}
	if (!(await saveAllowlist(current.allowlist, current.config.allowlist))) {
		fail(`Could not write the allowlist at ${current.path}; nothing was removed.`);
		return;
	}
	console.log(`Removed ${type} from the allowlist.`);
}

/** A unique hash prefix of at least 12 hex characters, as `list` prints it. */
function removeCommandByPrefix(allowlist: Allowlist, prefix: string): boolean {
	if (!/^[a-f0-9]{12,}$/.test(prefix)) return false;
	const matches = Object.keys(allowlist.commands).filter((key) => key.startsWith(prefix));
	return matches.length === 1 && removeCommand(allowlist, matches[0] as string);
}
