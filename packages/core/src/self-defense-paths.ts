/**
 * The files and directories a tool call removes, moves, overwrites or
 * re-permissions, for the self-defense rules that protect AIDR's own
 * installation and the host hook configuration that loads it.
 *
 * ## Why
 *
 * An agent does not need `aidr uninstall` to switch AIDR off. Deleting or
 * moving `~/.codex/hooks.json`, `~/.cursor/hooks.json` or `~/.claude/plugins`,
 * overwriting the `aidr-codex-hook` binary, or editing the host's settings
 * removes the hook for every later session. A rule on the literal command text
 * cannot tell `cat ~/.claude/settings.json` (harmless) from
 * `mv ~/.claude/settings.json /tmp` (AIDR gone), and it cannot see a path built
 * in an interpreter (`os.remove(os.path.join(home, '.codex', 'hooks.json'))`).
 *
 * This module answers "which paths does this call change?" and hands them, in
 * one canonical spelling, to the rules that declare `match_on: modified_path`
 * (see `threats/self-defense.yaml`). Reads produce no paths.
 *
 * ## Canonical spelling
 *
 * Separators are `/`; the current user's home directory (and any
 * `/home/<user>`, `/Users/<user>`, `/root` or `<drive>:/Users/<user>`) is `~`;
 * `$HOME`, `${HOME}`, `%USERPROFILE%`, `$env:USERPROFILE`, `%APPDATA%` and
 * `$XDG_CONFIG_HOME` are expanded; a relative path is resolved against the
 * last `cd` in the same command, else the host-reported working directory; and
 * `.`/`..` segments are folded. A glob segment that the shell would expand to a
 * protected name (`~/.codex/hook*`, `~/.co?ex/*`) is also reported with that
 * name, so the rules see what the shell would touch.
 *
 * ## What it is — and is not
 *
 * An over-approximation for matching, never executed: a string literal in an
 * interpreter one-liner that also calls a file-mutating API is reported as a
 * changed path even when the code only reads it. Work is linear in the input
 * (every regex is bounded) and the output is capped. It cannot see a path
 * computed at run time from data it does not have.
 */

import { homedir } from "node:os";
import { posix } from "node:path";
import { commandFromValue } from "./command-argv.js";
import { agentWriteTargets, shellWriteTargets } from "./context-poisoning.js";
import { globMatches, normalizeShellText } from "./shell-normalize.js";

const MAX_COMMAND_CHARS = 256 * 1024;
const MAX_PATHS = 256;
const MAX_PATH_CHARS = 1024;
const MAX_GLOB_VARIANTS = 64;
const MAX_LITERALS = 512;
/** Interpreter code scanned for path literals (a prefix of the command). */
const MAX_CODE_CHARS = 64 * 1024;

/**
 * Path segments a glob is resolved against: the host configuration directories
 * and files that load AIDR, and AIDR's own executables. Only names that the
 * self-defense rules look for are listed; resolving to anything else would not
 * change a verdict.
 */
const PROTECTED_SEGMENTS = [
	".singularity-aidr",
	".claude",
	".claude.json",
	".codex",
	".cursor",
	".openclaw",
	".config",
	".vscode",
	".vscode-insiders",
	".windsurf",
	"opencode",
	"plugins",
	"extensions",
	"marketplaces",
	"cache",
	"hooks",
	"hooks.json",
	"settings.json",
	"settings.local.json",
	"installed_plugins.json",
	"known_marketplaces.json",
	"config.toml",
	"openclaw.json",
	"opencode.json",
	"opencode.jsonc",
	"aidr",
	"aidr-openclaw",
	"aidr-codex-hook",
	"aidr-codex-hook.cmd",
	"aidr-codex-hook.ps1",
	"aidr-mcp-approve",
	"aidr-mcp-approve.mjs",
] as const;

/** Commands whose every non-option operand is removed, moved or re-permissioned. */
const ALL_OPERANDS_CHANGED = new Set([
	"rm",
	"rmdir",
	"unlink",
	"shred",
	"srm",
	"wipe",
	"trash",
	"trash-put",
	"gio",
	"del",
	"erase",
	"rd",
	"remove-item",
	"ri",
	"mv",
	"gmv",
	"move",
	"move-item",
	"mi",
	"rename",
	"rename-item",
	"rni",
	"ren",
	"chmod",
	"chown",
	"chgrp",
	"chattr",
	"chflags",
	"setfacl",
	"icacls",
	"attrib",
	"truncate",
	"clear-content",
	"clc",
	"ln",
]);

const COMMAND_WRAPPERS = new Set([
	"sudo",
	"doas",
	"env",
	"command",
	"exec",
	"nice",
	"nohup",
	"time",
	"busybox",
	"xargs",
]);

const CHANGE_DIRECTORY = new Set(["cd", "pushd", "set-location", "sl", "chdir"]);

/** A file-changing API call in interpreter code (Python, Node, Ruby, Perl, PHP, PowerShell, .NET). */
const FILE_MUTATION_API =
	/\b(?:os\.(?:remove|unlink|rmdir|removedirs|rename|renames|replace|truncate|chmod|chown|symlink|link)|shutil\.(?:rmtree|move|copy\w{0,10})|send2trash|unlinkSync|rmSync|rmdirSync|renameSync|writeFileSync|appendFileSync|truncateSync|copyFileSync|cpSync|chmodSync|symlinkSync|createWriteStream|writeFile|appendFile|copyFile|File\.(?:delete|unlink|rename|write|open)|FileUtils\.(?:rm\w{0,10}|mv|cp\w{0,5}|touch)|Remove-Item|Move-Item|Rename-Item|Set-Content|Add-Content|Clear-Content|Out-File|(?:IO\.)?File\]::(?:Delete|Move|Replace|WriteAll\w{0,10}|AppendAll\w{0,10}|Copy)|Directory\]::(?:Delete|Move)|unlink\s{0,4}\(|rename\s{0,4}\(|rmtree|open\s{0,4}\([^)\n]{0,512},\s{0,4}["'`][^"'`\n]{0,8}[wax+])|\.(?:unlink|rename|replace|rmdir|chmod|touch|write_text|write_bytes)\s{0,4}\(/;

/** A reference to the user's home directory in interpreter code. */
const CODE_HOME_REFERENCE =
	/homedir\s{0,4}\(|expanduser|Path\.home\s{0,4}\(|os\.environ(?:\.get)?\s{0,4}[[(]\s{0,4}["'](?:HOME|USERPROFILE)|process\.env\.(?:HOME|USERPROFILE)|ENV\[\s{0,4}["']HOME|getenv\s{0,4}\(\s{0,4}["'](?:HOME|USERPROFILE)|GetFolderPath|\$HOME|\$env:USERPROFILE/;

/**
 * A quoted string literal of each quote kind (bounded, no newlines). Each kind
 * is scanned on its own: a shell `-c "…"` wraps code whose own literals use the
 * other quote, and a single pass would swallow them into the outer string.
 */
const STRING_LITERALS = [
	/"((?:[^"\\\n]|\\.){1,512})"/g,
	/'((?:[^'\\\n]|\\.){1,512})'/g,
	/`((?:[^`\\\n]|\\.){1,512})`/g,
];
/** Two literals joined by a path operator (`,` in a join call, `/` on a Path, `+`). */
const LITERAL_JOIN = /^\s{0,8}(?:,|\/|\+|\+\s{0,4}(?:os\.sep|path\.sep|sep)\s{0,4}\+)\s{0,8}$/;
/** `'a' + 'b'` concatenations, joined before quote removal (as the shell view does). */
const LITERAL_CONCATENATION = /(['"`])[ \t]{0,20}\+[ \t]{0,20}(['"`])/g;

const TOKEN = /\d*>>?\|?|&>>?|<<-?|<|"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"'<>]+/g;
const REDIRECT_OR_HEREDOC = /^(?:\d*>>?\|?|&>>?|<<-?|<)$/;

export interface ModifiedPathOptions {
	/** Directory relative paths resolve against: the host-reported working directory. */
	cwd?: string;
	/** The user's home directory. Defaults to `os.homedir()`. */
	home?: string;
}

function unquote(token: string): string {
	if (token.length >= 2 && (token[0] === '"' || token[0] === "'") && token.at(-1) === token[0]) {
		return token.slice(1, -1);
	}
	return token;
}

function basename(word: string): string {
	return (
		word
			.split(/[\\/]/)
			.pop()
			?.toLowerCase()
			.replace(/\.exe$/, "") ?? ""
	);
}

function toSlashes(path: string): string {
	return path.replace(/\\/g, "/");
}

/** Expand home and config-directory variables at the start of a path. */
function expandVariables(path: string): string {
	return path
		.replace(
			/^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|%HOMEDRIVE%%HOMEPATH%)(?=\/|$)/i,
			"~",
		)
		.replace(/^(?:%APPDATA%|\$env:APPDATA)(?=\/|$)/i, "~/AppData/Roaming")
		.replace(/^(?:\$XDG_CONFIG_HOME|\$\{XDG_CONFIG_HOME\})(?=\/|$)/, "~/.config");
}

/** The current user's home, plus any conventional home directory, collapsed to `~`. */
function collapseHome(path: string, home: string): string {
	const lowerPath = path.toLowerCase();
	const lowerHome = home.toLowerCase();
	if (home && home !== "/" && (lowerPath === lowerHome || lowerPath.startsWith(`${lowerHome}/`))) {
		return `~${path.slice(home.length)}`;
	}
	return path.replace(
		/^(?:\/home\/[^/]{1,64}|\/Users\/[^/]{1,64}|\/root|[A-Za-z]:\/Users\/[^/]{1,64})(?=\/|$)/i,
		"~",
	);
}

function isAbsolutePath(path: string): boolean {
	return path.startsWith("/") || path.startsWith("~") || /^[A-Za-z]:\//.test(path);
}

/** Fold `.` and `..` segments, keeping a `~` or drive anchor. */
function foldSegments(path: string): string {
	const drive = /^[A-Za-z]:/.exec(path)?.[0] ?? "";
	const rest = path.slice(drive.length);
	if (rest.startsWith("~")) {
		const folded = posix.normalize(`/${rest.slice(1)}`);
		return `~${folded === "/" ? "" : folded}`;
	}
	return `${drive}${posix.normalize(rest)}`;
}

function canonicalPath(raw: string, base: string | undefined, home: string): string | null {
	let path = toSlashes(unquote(raw.trim()));
	if (!path || path.length > MAX_PATH_CHARS || path.startsWith("-")) return null;
	path = expandVariables(path);
	if (!isAbsolutePath(path)) {
		if (!base) return null;
		path = `${base.replace(/\/+$/, "")}/${path}`;
	}
	path = foldSegments(collapseHome(path, toSlashes(home)));
	return path.replace(/\/+$/, "") || path;
}

function isGlob(segment: string): boolean {
	return /[*?[]/.test(segment);
}

/** The shell does not expand a leading `*` or `?` to a dot-file name. */
function globNames(segment: string): string[] {
	return PROTECTED_SEGMENTS.filter(
		(name) => (!name.startsWith(".") || segment.startsWith(".")) && globMatches(segment, name),
	);
}

/** `path` plus the variants the shell would produce for its glob segments. */
function globVariants(path: string): string[] {
	const segments = path.split("/");
	if (!segments.some(isGlob)) return [path];
	let variants: string[][] = [[]];
	for (const segment of segments) {
		// Resolved names first, so the cap never drops them for the raw glob.
		const options = isGlob(segment) ? [...globNames(segment), segment] : [segment];
		const next: string[][] = [];
		for (const prefix of variants) {
			for (const option of options) {
				if (next.length >= MAX_GLOB_VARIANTS) break;
				next.push([...prefix, option]);
			}
		}
		variants = next;
	}
	return variants.map((parts) => parts.join("/"));
}

/** Words of one simple command, quotes removed, redirections dropped. */
function words(segment: string): string[] {
	const tokens = (segment.match(TOKEN) ?? []).slice(0, 512);
	const out: string[] = [];
	for (let index = 0; index < tokens.length; index++) {
		const token = tokens[index] as string;
		if (REDIRECT_OR_HEREDOC.test(token)) {
			index++;
			continue;
		}
		out.push(unquote(token));
	}
	return out;
}

/** Index of the command word after assignments, wrappers and their options. */
function commandIndex(argv: readonly string[]): number {
	let index = 0;
	while (index < argv.length) {
		const word = argv[index] as string;
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word) || COMMAND_WRAPPERS.has(basename(word))) {
			index++;
			continue;
		}
		if (index > 0 && word.startsWith("-")) {
			index++;
			continue;
		}
		return index;
	}
	return index;
}

/** `find <roots> … -delete | -exec …`: the roots are changed. */
function findRoots(operands: readonly string[]): string[] {
	const roots: string[] = [];
	for (const arg of operands) {
		if (/^-[HLP]$/.test(arg)) continue;
		if (arg.startsWith("-") || arg === "(" || arg === "!") break;
		roots.push(arg);
	}
	const acts = operands.some((arg) =>
		/^-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/.test(arg),
	);
	return acts ? roots : [];
}

/** A path as written, and the directory a relative one resolves against. */
interface FoundPath {
	path: string;
	base: string | undefined;
}

/** The directory a `cd`/`pushd` target moves to, from the current `base`. */
function changeDirectory(base: string | undefined, target: string | undefined): string | undefined {
	if (!target) return base;
	if (!base || isAbsolutePath(toSlashes(expandVariables(target)))) return target;
	return `${base}/${target}`;
}

/** Operands of one simple command that it removes, moves or re-permissions. */
function changedOperands(word: string, operands: readonly string[]): string[] {
	if (ALL_OPERANDS_CHANGED.has(word)) {
		return operands.filter((arg) => !arg.startsWith("-") || arg === "-");
	}
	return word === "find" ? findRoots(operands) : [];
}

/** Changed paths of every simple command in `command`, with the directory each resolves against. */
function shellChangedPaths(command: string, cwd: string | undefined): FoundPath[] {
	const out: FoundPath[] = [];
	let base = cwd;
	for (const segment of command.split(/\|\||&&|[;|\n]|&(?!>)/)) {
		const argv = words(segment);
		const index = commandIndex(argv);
		const word = basename(argv[index] ?? "");
		const operands = argv.slice(index + 1);
		if (CHANGE_DIRECTORY.has(word)) {
			base = changeDirectory(
				base,
				operands.find((arg) => !arg.startsWith("-")),
			);
			continue;
		}
		for (const path of [...changedOperands(word, operands), ...shellWriteTargets(segment)]) {
			out.push({ path, base });
		}
	}
	return out;
}

/**
 * Path-like string literals of interpreter code that calls a file-changing API:
 * each literal, each run of literals joined by a path operator, and those runs
 * under `~` when the code refers to the home directory.
 */
function interpreterPaths(command: string): string[] {
	const code = command.slice(0, MAX_CODE_CHARS);
	if (!FILE_MUTATION_API.test(code)) return [];
	const homeRelative = CODE_HOME_REFERENCE.test(code);
	// Concatenations joined; `\"` escapes of an enclosing shell string removed.
	const joined = code.replace(LITERAL_CONCATENATION, "");
	const candidates: string[] = [];
	for (const view of [joined, joined.replace(/\\(["'`])/g, "$1")]) {
		for (const pattern of STRING_LITERALS) candidates.push(...literalPaths(view, pattern));
	}
	return candidates.flatMap((value) => {
		const path = toSlashes(value).replace(/\/{2,}/g, "/");
		if (!/[/.]/.test(path) && !/aidr/i.test(path)) return [];
		// `homedir() + '/.codex/…'` joins a home reference to an absolute-looking literal.
		return homeRelative && !path.startsWith("~") ? [path, `~/${path.replace(/^\/+/, "")}`] : [path];
	});
}

/** Each literal of one quote kind, and each run of literals joined by a path operator. */
function literalPaths(code: string, pattern: RegExp): string[] {
	const literals: Array<{ value: string; start: number; end: number }> = [];
	for (const match of code.matchAll(pattern)) {
		if (literals.length >= MAX_LITERALS) break;
		const start = match.index ?? 0;
		literals.push({ value: match[1] as string, start, end: start + match[0].length });
	}
	const out = literals.map((literal) => literal.value);
	let run: string[] = [];
	for (const [index, literal] of literals.entries()) {
		const previous = literals[index - 1];
		if (previous && LITERAL_JOIN.test(code.slice(previous.end, literal.start))) {
			run.push(literal.value);
			continue;
		}
		if (run.length > 1) out.push(run.join("/"));
		run = [literal.value];
	}
	if (run.length > 1) out.push(run.join("/"));
	return out;
}

/**
 * Every path the call removes, moves, overwrites, truncates, links over or
 * re-permissions, in canonical form (see the module comment). `toolName` and
 * `toolInput` are the normalized request (canonical `Bash`/`Write`/`Edit`/
 * `Delete`, other tools unchanged).
 */
export function modifiedPaths(
	toolName: string,
	toolInput: Record<string, unknown>,
	options: ModifiedPathOptions = {},
): string[] {
	const home = options.home ?? homedir();
	const cwd = options.cwd ? toSlashes(options.cwd) : undefined;
	const found =
		toolName === "Bash"
			? bashPaths(toolInput.command, cwd)
			: fileToolPaths(toolName, toolInput, cwd);
	const paths = new Set<string>();
	for (const { path, base } of found) {
		const resolvedBase = base ? (canonicalPath(base, cwd, home) ?? undefined) : undefined;
		const canonical = canonicalPath(path, resolvedBase, home);
		if (!canonical) continue;
		for (const variant of globVariants(canonical)) {
			if (paths.size >= MAX_PATHS) return [...paths];
			paths.add(variant);
		}
	}
	return [...paths];
}

/**
 * Paths a shell command changes. The literal command and its shell-normalized
 * view (quotes, variables, `$(which …)` and concatenations peeled off) are both
 * read, plus the path literals of interpreter code in it.
 */
function bashPaths(value: unknown, cwd: string | undefined): FoundPath[] {
	const parsed = commandFromValue(value);
	const raw = parsed.ok ? (parsed.command ?? "") : "";
	const command = raw.slice(0, MAX_COMMAND_CHARS);
	if (!command) return [];
	return [
		...shellChangedPaths(command, cwd),
		...shellChangedPaths(normalizeShellText(command), cwd),
		...interpreterPaths(command).map((path) => ({ path, base: cwd })),
	];
}

/** Paths a file tool (Write, Edit, Delete, apply_patch, a writer MCP tool) changes. */
function fileToolPaths(
	toolName: string,
	toolInput: Record<string, unknown>,
	cwd: string | undefined,
): FoundPath[] {
	return agentWriteTargets(toolName, toolInput)
		.filter((target) => target.via === "file_tool")
		.map((target) => ({ path: target.path, base: cwd }));
}
