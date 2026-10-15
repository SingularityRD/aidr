/**
 * Extract security-relevant artifacts from tool inputs.
 */

import { commandFromArgv, commandFromValue } from "./command-argv.js";
import {
	CREDENTIAL_READ_CONTEXT,
	credentialReadsInCommand,
	credentialReadsInSearchTool,
	type GlobBudget,
	newGlobBudget,
} from "./credential-reads.js";
import type { Artifact } from "./types.js";

/** Regex for extracting URLs — matches http/https followed by non-whitespace, non-quote chars. */
const URL_PATTERN = /https?:\/\/[^\s"')<>[\]{}]+/g;

/** Trailing punctuation that's likely not part of the URL. */
const TRAILING_PUNCT = /[.,;:!?]+$/;

/**
 * Maximum number of characters of any single artifact handed to the detection
 * pipeline (64KB).
 *
 * Why a hard bound exists: matching is synchronous, and a PreToolUse hook that
 * exceeds its 15s budget (hooks/hooks.json) is killed before it can emit a
 * verdict — which the host reads as "no objection". Unbounded input therefore
 * turns any super-linear pattern into a detection-evasion primitive. Bounding
 * the input is the half of the fix that holds even if a threat rule regresses.
 *
 * Why 64KB: it is the size already used for file/content artifacts, so commands
 * now follow the same policy; it is ~1000x the longest command artifact in the
 * local audit log (57 chars) and far above any hand-written shell command. The
 * long commands that do occur are dominated by heredoc bodies, which are data
 * and are stripped before matching. Truncation keeps the *prefix* — where the
 * executable, flags and pipes live — so intent near the start is still caught.
 */
export const MAX_ARTIFACT_SIZE = 64 * 1024;

/** Alias kept for readability at the file/content call sites. */
const MAX_CONTENT_SIZE = MAX_ARTIFACT_SIZE;

/**
 * Inspection limits for one tool call.
 *
 * Every limit is fail-closed: when an input exceeds one of them the extractor
 * appends an `input_not_fully_inspected` marker artifact (see
 * {@link inspectionLimitsHit}) and the evaluator denies the call, because a
 * verdict over part of the input is not a verdict over the call. Silently
 * stopping at a limit let `curl … | bash` hide five levels deep, after 200
 * filler strings, or behind 64 KiB of padding in an MCP argument.
 *
 * - Nesting depth (16) and string count (1024) are far above realistic tool
 *   arguments; depth also bounds recursion.
 * - A free-text string longer than {@link MAX_ARTIFACT_SIZE} is scanned in full
 *   as overlapping windows instead of being cut. Command, URL and path fields
 *   are not windowed: a window of a command is not the command, so an oversized
 *   one fails closed exactly like an oversized `Bash` command does.
 * - {@link MAX_INSPECTED_CHARS} (4 MiB) caps the total text scanned per call so
 *   the synchronous matcher stays well inside the PreToolUse hook budget.
 */
const MAX_GENERIC_STRINGS = 1024;
const MAX_GENERIC_DEPTH = 16;
const MAX_GENERIC_ARTIFACTS = 2048;
export const MAX_INSPECTED_CHARS = 4 * 1024 * 1024;

/**
 * Overlap between consecutive content windows. Threat rules bound every gap to
 * 300 characters (see MAX_GAP), so a match that straddles a window boundary is
 * still wholly contained in one window.
 */
const WINDOW_OVERLAP = 4 * 1024;

/** Which inspection limit an input exceeded. */
export type InspectionLimit =
	| "depth"
	| "string_count"
	| "string_size"
	| "artifact_count"
	| "total_size";

/** Reason code and marker-artifact context for an input that was not fully inspected. */
export const INPUT_NOT_FULLY_INSPECTED = "input_not_fully_inspected";
const INPUT_NOT_FULLY_INSPECTED_CONTEXT = `aidr:${INPUT_NOT_FULLY_INSPECTED}`;

const INSPECTION_LIMITS: readonly InspectionLimit[] = [
	"depth",
	"string_count",
	"string_size",
	"artifact_count",
	"total_size",
];

function inspectionLimitMarker(limit: InspectionLimit): Artifact {
	return {
		type: "content",
		value: `${INPUT_NOT_FULLY_INSPECTED}:${limit}`,
		context: INPUT_NOT_FULLY_INSPECTED_CONTEXT,
	};
}

/**
 * The inspection limits an extraction reported, read from its marker
 * artifacts. Empty when the whole input was inspected. The marker travels in
 * the artifact list itself so every connector that forwards extractor output to
 * the evaluator carries it without any connector-specific plumbing.
 */
export function inspectionLimitsHit(artifacts: readonly Artifact[]): InspectionLimit[] {
	const limits = new Set<InspectionLimit>();
	for (const artifact of artifacts) {
		if (artifact.context !== INPUT_NOT_FULLY_INSPECTED_CONTEXT) continue;
		const limit = artifact.value.slice(INPUT_NOT_FULLY_INSPECTED.length + 1) as InspectionLimit;
		limits.add(INSPECTION_LIMITS.includes(limit) ? limit : "total_size");
	}
	return [...limits];
}

/**
 * Split free text into overlapping windows of at most {@link MAX_ARTIFACT_SIZE}
 * characters that together cover the whole string. Each later window starts at
 * a line start when one lies inside the overlap, so line-anchored rules do not
 * see a mid-line fragment as a line start.
 */
export function contentWindows(value: string): string[] {
	if (value.length <= MAX_CONTENT_SIZE) return [value];
	const windows: string[] = [];
	let start = 0;
	for (;;) {
		const end = Math.min(start + MAX_CONTENT_SIZE, value.length);
		windows.push(value.slice(start, end));
		if (end === value.length) return windows;
		let next = end - WINDOW_OVERLAP;
		const lineBreak = value.lastIndexOf("\n", next);
		if (lineBreak >= end - 2 * WINDOW_OVERLAP) next = lineBreak + 1;
		start = next;
	}
}

/**
 * Maximum gap (in characters) allowed between two parts of a shell construct,
 * e.g. between a URL and the pipe that feeds it to a shell.
 *
 * These patterns run per artifact inside the 15s PreToolUse hook, so an
 * unbounded gap is O(gap) work per occurrence and O(n * occurrences) overall:
 * measured 1.7s of pure extraction for a 64KB command made of nothing but
 * `http://a/`. The same bound is applied to the threat rules in `threats/*.yaml`
 * (see the comments there), and 300 characters is several times any realistic
 * `curl -fsSL <long-url>` or path argument.
 */
const MAX_GAP = 300;

/** Detect base64-decode piped to execution: echo "..." | base64 -d | bash */
const BASE64_DECODE_EXEC =
	/\b(echo|printf|cat)\b[^|]{0,300}\|\s*base64\s+(-d|--decode)[^|]{0,300}\|\s*(bash|sh|zsh|ksh|dash|python|perl|ruby|node)\b/;

/** Detect hex/octal printf piped to shell: printf '\x41\x42' | bash */
const PRINTF_ENCODE_EXEC =
	/\bprintf\b\s+['"](\\x[0-9a-fA-F]{2}|\\[0-7]{3})[^|]{0,300}\|\s*(bash|sh|zsh|ksh|dash)\b/;

/** Detect shell variable interpolation hiding a domain: $HOST.$DOMAIN or ${HOST}.${DOMAIN} */
const VAR_INTERPOLATION_URL =
	/\b(curl|wget|fetch)\b[^|;]{0,300}(\$\{?\w+\}?\.\$\{?\w+\}?|\$\{?\w+\}?:\/\/)/;

/** Shell names used as pipe targets */
const SHELLS = "bash|sh|zsh|ksh|dash";

const EXECUTABLE_HEREDOC_CONSUMER = new RegExp(
	`(?:^|[|;&]\\s*)(?:(?:sudo|timeout|xargs|env|command)\\s+(?:\\S+\\s+){0,2})?(?:/\\S+/)?(?:${SHELLS}|python(?:\\d+(?:\\.\\d+)*)?|perl|ruby|node(?:js)?)\\b`,
	"i",
);

export function extractUrls(text: string): string[] {
	const seen = new Set<string>();
	const urls: string[] = [];
	for (const match of text.matchAll(URL_PATTERN)) {
		const url = match[0].replace(TRAILING_PUNCT, "");
		if (!seen.has(url)) {
			seen.add(url);
			urls.push(url);
		}
	}
	return urls;
}

function escapeRegExp(str: string): string {
	const regExpEscape = (RegExp as unknown as { escape?: (s: string) => string }).escape;
	if (regExpEscape) {
		return regExpEscape(str);
	}
	return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Report that an artifact was only partially inspected. Truncation must never
 * be silent: a partial evaluation that reports "allow" would otherwise be
 * indistinguishable from a full clean result.
 */
function warnTruncatedInput(source: string, originalLength: number, evaluatedLength: number): void {
	console.warn(
		`AIDR: ${source} truncated for inspection — ${originalLength} chars reduced to the first ` +
			`${evaluatedLength} chars. The trailing text was NOT inspected; the verdict covers the ` +
			"retained prefix only and is not a full-input result.",
	);
}

/** Bound an artifact before it reaches pattern matching. */
export function boundArtifact(
	source: string,
	value: string,
	max: number = MAX_ARTIFACT_SIZE,
): string {
	if (value.length <= max) return value;
	warnTruncatedInput(source, value.length, max);
	return value.slice(0, max);
}

/**
 * Heredoc opener: `<<`, an optional `-`, optional whitespace, an optionally
 * quoted delimiter word, then a newline. Same grammar as the previous
 * `/<<-?\s*['"]?(\w+)['"]?\n/` scan.
 */
const HEREDOC_OPENER = /<<-?\s*['"]?(\w+)['"]?\n/g;

/** A line that can close a heredoc: `\n` + `[ \t]*` + word. */
interface HeredocTerminator {
	/** Index of the `\n` that precedes the line. */
	nlIndex: number;
	/** Index of the first character of the word. */
	wordStart: number;
}

function isWordCharCode(code: number): boolean {
	return (
		(code >= 97 && code <= 122) || // a-z
		(code >= 65 && code <= 90) || // A-Z
		(code >= 48 && code <= 57) || // 0-9
		code === 95 // _
	);
}

/**
 * Index every line whose first word (after leading spaces/tabs) could close a
 * heredoc, in a single left-to-right pass.
 *
 * A line closes a heredoc for delimiter `D` exactly when its first word is `D`:
 * `\w+` is greedy, so a longer first word (`EOFx`) does not satisfy the `\b`
 * that follows the delimiter, and a shorter one cannot either.
 */
function indexHeredocTerminators(command: string): Map<string, HeredocTerminator[]> {
	const index = new Map<string, HeredocTerminator[]>();
	let nl = command.indexOf("\n");
	while (nl !== -1) {
		let p = nl + 1;
		while (p < command.length) {
			const code = command.charCodeAt(p);
			if (code !== 32 /* space */ && code !== 9 /* tab */) break;
			p++;
		}
		const wordStart = p;
		while (p < command.length && isWordCharCode(command.charCodeAt(p))) p++;
		if (p > wordStart) {
			const word = command.slice(wordStart, p);
			const entry: HeredocTerminator = { nlIndex: nl, wordStart };
			const existing = index.get(word);
			if (existing) {
				existing.push(entry);
			} else {
				index.set(word, [entry]);
			}
		}
		nl = command.indexOf("\n", nl + 1);
	}
	return index;
}

/**
 * Strip heredoc bodies from a command string. Heredoc content is inline text
 * data (commit messages, config files, etc.), not executable shell commands.
 *
 * Behaviourally identical to the original
 *   command.replace(/<<-?\s*['"]?(\w+)['"]?\n[\s\S]*?\n[ \t]*\1\b/g, "<<$1")
 * but linear-time. That regex restarted a lazy `[\s\S]*?` tail scan at every
 * `<<`, so a command containing many unclosed `<<` sequences cost O(n^2) — e.g.
 * 4.7s for a 60KB command, which alone blew the 15s hook budget on larger
 * input. Here openers are found with one global scan and the closing line is
 * looked up in a pre-built index, so every character is visited a bounded
 * number of times.
 */
function stripHeredocs(command: string): string {
	const terminators = indexHeredocTerminators(command);
	/** Per-delimiter cursor; searches run left-to-right, so it only advances. */
	const cursors = new Map<string, number>();

	const findTerminator = (word: string, from: number): HeredocTerminator | null => {
		const list = terminators.get(word);
		if (!list) return null;
		let cursor = cursors.get(word) ?? 0;
		while (cursor < list.length && (list[cursor] as HeredocTerminator).nlIndex < from) {
			cursor++;
		}
		cursors.set(word, cursor);
		return cursor < list.length ? (list[cursor] as HeredocTerminator) : null;
	};

	let out = "";
	/** Everything before this index is already copied into `out`. */
	let copiedUpTo = 0;
	let scanFrom = 0;

	for (;;) {
		HEREDOC_OPENER.lastIndex = scanFrom;
		const opener = HEREDOC_OPENER.exec(command);
		if (!opener) break;

		const word = opener[1] as string;
		const bodyStart = opener.index + opener[0].length;
		const terminator = findTerminator(word, bodyStart);
		if (!terminator) {
			// No closing line: not a heredoc. Resume one character later, which
			// is exactly how the global regex advanced on a failed attempt.
			scanFrom = opener.index + 1;
			continue;
		}

		// A heredoc can be source code for an interpreter, not just inline data.
		// Keep the full command whenever one is fed to a shell or script runtime.
		const lineStart = command.lastIndexOf("\n", opener.index - 1) + 1;
		const lineEnd = command.indexOf("\n", opener.index);
		if (EXECUTABLE_HEREDOC_CONSUMER.test(command.slice(lineStart, lineEnd))) {
			return command;
		}

		// The whole heredoc (dash and quotes included) collapses to `<<word`.
		out += command.slice(copiedUpTo, opener.index) + "<<" + word;
		copiedUpTo = terminator.wordStart + word.length;
		scanFrom = copiedUpTo;
	}

	return out + command.slice(copiedUpTo);
}

/**
 * @param globBudget shared by every command of one tool call, so a call made
 * of many commands cannot multiply the glob-matching work (see
 * credential-reads.ts).
 */
export function extractFromBash(
	command: string,
	globBudget: GlobBudget = newGlobBudget(),
): Artifact[] {
	const artifacts: Artifact[] = [];

	// Bound the raw command before anything scans it. Everything below — heredoc
	// stripping, bypass detection, URL extraction, heuristic matching — sees the
	// same retained prefix, so the pipeline stays consistent about what was
	// inspected. Truncation is reported (never silent).
	const bounded = boundArtifact("Bash command", command);

	// Strip heredoc bodies — they're data, not executable commands
	const effective = stripHeredocs(bounded);

	// Include the effective command for heuristic matching
	artifacts.push({ type: "command", value: effective });

	// Detect encoding bypass techniques
	if (BASE64_DECODE_EXEC.test(effective)) {
		artifacts.push({ type: "command", value: effective, context: "base64_decode_exec" });
	}
	if (PRINTF_ENCODE_EXEC.test(effective)) {
		artifacts.push({ type: "command", value: effective, context: "printf_encode_exec" });
	}
	if (VAR_INTERPOLATION_URL.test(effective)) {
		artifacts.push({ type: "command", value: effective, context: "variable_interpolation_url" });
	}

	// Extract URLs from the FULL (bounded) command — heredoc content may contain relevant URLs.
	// The "piped to shell" context needs a pipe to exist at all, and every
	// pattern below scans forward from each URL occurrence, so check that first
	// (exact, not heuristic) and keep each gap bounded.
	const hasPipe = bounded.includes("|");
	for (const url of extractUrls(bounded)) {
		let context: string | undefined;
		if (hasPipe) {
			const escaped = escapeRegExp(url);
			// Direct pipe to shell: curl URL | sh
			const directPipe = new RegExp(escaped + String.raw`[^|]{0,${MAX_GAP}}\|\s*(${SHELLS})\b`);
			// Pipe through wrapper to shell: curl URL | timeout 5 bash, curl URL | xargs sh -c
			const wrappedPipe = new RegExp(
				escaped + String.raw`[^|]{0,${MAX_GAP}}\|\s*\S+\s+(\S+\s+)?(${SHELLS})\b`,
			);
			// Subshell/backtick execution: $(curl URL | sh) or `curl URL | sh`
			const subshellExec = new RegExp(
				`${String.raw`(\$\(|`}\`)${escaped}[^)\`]{0,${MAX_GAP}}${String.raw`\|\s*(${SHELLS})\b`}`,
			);
			if (directPipe.test(bounded) || wrappedPipe.test(bounded) || subshellExec.test(bounded)) {
				context = "piped to shell";
			}
		}
		artifacts.push({ type: "url", value: url, context });
	}

	// Credential files the command reads without naming them literally
	// (`cd ~/.ssh && cat id_rsa`, `cat ~/.ss?/id_*`, `grep -r . ~/.aws`): the
	// canonical paths are judged by the file rules in threats/.
	for (const path of credentialReadsInCommand(effective, globBudget)) {
		artifacts.push({ type: "file_path", value: path, context: CREDENTIAL_READ_CONTEXT });
	}

	return artifacts;
}

export function extractFromWebFetch(toolInput: Record<string, unknown>): Artifact[] {
	const url = toolInput.url;
	if (url && typeof url === "string") {
		return [{ type: "url", value: url, context: "webfetch" }];
	}
	return [];
}

function extractFileArtifacts(
	toolInput: Record<string, unknown>,
	filePathKey: string,
	contentKey: string,
	contextName: string,
	urlContextName: string,
): Artifact[] {
	const artifacts: Artifact[] = [];

	const filePath = toolInput[filePathKey];
	if (filePath && typeof filePath === "string") {
		artifacts.push({ type: "file_path", value: filePath, context: contextName });
	}

	const content = toolInput[contentKey];
	if (content && typeof content === "string" && content.trim()) {
		// File content is scanned in full (as overlapping windows) up to the
		// per-call budget. Content beyond the budget fails closed like every
		// other inspection limit; no agent emits 4 MiB in one tool call, so
		// ordinary large writes and edits are unaffected.
		const inspected = content.slice(0, MAX_INSPECTED_CHARS);
		const urls = new Set<string>();
		for (const window of contentWindows(inspected)) {
			artifacts.push({ type: "content", value: window, context: contextName });
			for (const url of extractUrls(window)) urls.add(url);
		}
		for (const url of urls) {
			artifacts.push({ type: "url", value: url, context: urlContextName });
		}
		if (content.length > MAX_INSPECTED_CHARS) {
			artifacts.push(inspectionLimitMarker("total_size"));
		}
	}

	return artifacts;
}

export function extractFromWrite(toolInput: Record<string, unknown>): Artifact[] {
	return extractFileArtifacts(toolInput, "file_path", "content", "write", "from_file_content");
}

export function extractFromEdit(toolInput: Record<string, unknown>): Artifact[] {
	return extractFileArtifacts(toolInput, "file_path", "new_string", "edit", "from_edit_content");
}

export function extractFromRead(toolInput: Record<string, unknown>): Artifact[] {
	return extractFileArtifacts(toolInput, "file_path", "content", "read", "from_read_content");
}

export function extractFromDelete(toolInput: Record<string, unknown>): Artifact[] {
	const filePath = toolInput.file_path;
	if (filePath && typeof filePath === "string") {
		return [{ type: "file_path", value: filePath, context: "delete" }];
	}
	return [];
}

function looksLikePath(value: string): boolean {
	if (!value) return false;
	if (value.startsWith("/") || value.startsWith("./") || value.startsWith("../")) return true;
	// Windows absolute paths, UNC paths
	if (/^[a-zA-Z]:[\\/]/.test(value) || value.startsWith("\\\\")) return true;
	// Home-relative or env var-ish
	if (value.startsWith("~/") || value.startsWith("$HOME/")) return true;
	return false;
}

/**
 * Keys whose string value a tool runs as a shell command or script. MCP
 * servers that execute commands name the field in many ways; `code` and
 * `script` bodies are executed too, so they are matched as commands.
 */
const COMMAND_KEYS = new Set([
	"command",
	"cmd",
	"cmdline",
	"command_line",
	"commandline",
	"script",
	"code",
	"shell",
	"bash",
	"sh",
	"powershell",
	"pwsh",
]);

function fieldTypeForKey(key: string): Artifact["type"] | null {
	const k = key.toLowerCase();
	if (k === "url" || k.endsWith("_url")) return "url";
	if (COMMAND_KEYS.has(k) || k.endsWith("_command") || k.endsWith("_cmd") || k.endsWith("_script"))
		return "command";
	if (
		k === "file_path" ||
		k === "filepath" ||
		k === "file" ||
		k === "path" ||
		k.endsWith("_path") ||
		k.endsWith("_file") ||
		k.endsWith("_filename") ||
		k === "filename" ||
		k === "target_file"
	)
		return "file_path";
	if (k === "content" || k.endsWith("_content") || k === "patch" || k === "diff" || k === "text")
		return "content";
	return null;
}

interface StringField {
	path: string;
	key: string;
	value: string;
}

/** Walk state shared by one generic extraction. */
interface GenericWalk {
	fields: StringField[];
	chars: number;
	limits: Set<InspectionLimit>;
}

/**
 * Object keys that are plain identifiers carry no payload of their own. Any
 * other key (whitespace, shell metacharacters, very long) is inspected like a
 * value, because a server may act on it.
 */
const PLAIN_KEY = /^[\w.$@:-]{1,64}$/;

function hasInspectableContent(value: unknown): boolean {
	if (typeof value === "string") return value.trim() !== "";
	if (Array.isArray(value)) return value.length > 0;
	return value !== null && typeof value === "object" && Object.keys(value).length > 0;
}

function addStringField(walk: GenericWalk, field: StringField): boolean {
	if (field.value.trim() === "") return true;
	if (walk.fields.length >= MAX_GENERIC_STRINGS) {
		walk.limits.add("string_count");
		return false;
	}
	if (walk.chars + field.value.length > MAX_INSPECTED_CHARS) {
		walk.limits.add("total_size");
		return false;
	}
	walk.chars += field.value.length;
	walk.fields.push(field);
	return true;
}

function collectObjectFields(
	value: Record<string, unknown>,
	path: string,
	depth: number,
	walk: GenericWalk,
): boolean {
	for (const [key, child] of Object.entries(value)) {
		const childPath = path ? `${path}.${key}` : key;
		if (
			!PLAIN_KEY.test(key) &&
			!addStringField(walk, { path: `${childPath}#key`, key: "", value: key })
		) {
			return false;
		}
		if (!collectStringFields(child, childPath, depth + 1, walk)) return false;
	}
	return true;
}

/**
 * Collect every string in the tool input. Returns false once a limit stops the
 * walk; the limit is recorded in `walk.limits` so the caller can fail closed.
 */
function collectStringFields(
	value: unknown,
	path: string,
	depth: number,
	walk: GenericWalk,
): boolean {
	if (depth > MAX_GENERIC_DEPTH) {
		if (hasInspectableContent(value)) walk.limits.add("depth");
		return true;
	}
	if (typeof value === "string") {
		return addStringField(walk, { path, key: path.split(".").slice(-1)[0] ?? "", value });
	}
	if (Array.isArray(value)) {
		return value.every((item, i) => collectStringFields(item, `${path}[${i}]`, depth + 1, walk));
	}
	if (value && typeof value === "object") {
		return collectObjectFields(value as Record<string, unknown>, path, depth, walk);
	}
	return true;
}

/** Deduplicating artifact list for one generic extraction, capped at MAX_GENERIC_ARTIFACTS. */
class GenericArtifacts {
	readonly items: Artifact[] = [];
	/** Glob evaluations shared by every command found in this tool input. */
	readonly globBudget = newGlobBudget();
	private readonly seen = new Set<string>();

	private readonly limits: Set<InspectionLimit>;

	constructor(limits: Set<InspectionLimit>) {
		this.limits = limits;
	}

	/** Add an artifact and the URLs embedded in it; false once the cap is reached. */
	add(artifact: Artifact): boolean {
		if (!this.push(artifact)) return false;
		for (const url of extractUrls(artifact.value)) {
			if (!this.push({ type: "url", value: url, context: `${artifact.context}:embedded_url` })) {
				return false;
			}
		}
		return true;
	}

	private push(artifact: Artifact): boolean {
		const key = `${artifact.type}:${artifact.value}`;
		if (this.seen.has(key)) return true;
		if (this.items.length >= MAX_GENERIC_ARTIFACTS) {
			this.limits.add("artifact_count");
			return false;
		}
		this.seen.add(key);
		this.items.push(artifact);
		return true;
	}
}

/** Turn one collected string into artifacts; false once the artifact cap is reached. */
function addFieldArtifacts(
	toolName: string,
	field: StringField,
	out: GenericArtifacts,
	limits: Set<InspectionLimit>,
): boolean {
	const value = field.value.trim();
	const context = `tool:${toolName}:${field.path || field.key || "value"}`;
	const type = fieldTypeForKey(field.key) ?? (looksLikePath(value) ? "file_path" : "content");

	if (type === "content") {
		return contentWindows(value).every((window) => out.add({ type, value: window, context }));
	}
	// A window of a command, URL or path is not that value; an oversized one
	// cannot be judged and fails closed.
	if (value.length > MAX_ARTIFACT_SIZE) {
		limits.add("string_size");
		return true;
	}
	if (type === "command") return addCommandArtifacts(value, context, out);
	return out.add({ type, value, context });
}

/**
 * A command found in an unknown tool's input is inspected exactly like a Bash
 * command: heredoc data is set aside, piped URLs are flagged and credential
 * reads are resolved.
 */
function addCommandArtifacts(command: string, context: string, out: GenericArtifacts): boolean {
	return extractFromBash(command, out.globBudget).every((artifact) =>
		out.add(artifact.context === undefined ? { ...artifact, context } : artifact),
	);
}

/** Keys that may hold a program's argument vector. */
const ARGV_KEYS = new Set([
	"command",
	"cmd",
	"argv",
	"exec",
	"run",
	"entrypoint",
	"entry_point",
	"script",
	"cmdline",
	"command_line",
]);

/** Keys that hold the argument list of a sibling program key. */
const ARGS_KEYS = new Set(["args", "arguments", "params", "parameters"]);

/** Keys naming the program that an argument list is passed to. */
const PROGRAM_KEYS = [
	"command",
	"cmd",
	"program",
	"executable",
	"exe",
	"binary",
	"bin",
	"shell",
	"interpreter",
] as const;

interface CommandCandidate {
	path: string;
	command: string;
}

function programOf(value: Record<string, unknown>): string | undefined {
	for (const key of PROGRAM_KEYS) {
		const program = value[key];
		if (typeof program === "string" && program.trim() && !/\s/.test(program.trim())) {
			return program.trim();
		}
	}
	return undefined;
}

function isStringArray(value: unknown): value is string[] {
	return (
		Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string")
	);
}

/**
 * Shell lines an object's argv-shaped fields run: an argv array under a
 * command key (`command: ["bash", "-c", "…"]`), a program plus its argument
 * list (`cmd: "bash", args: ["-c", "…"]`), and any argument that is itself a
 * shell line (a remote command handed to `ssh`, a `-c` script).
 */
function argvCommandsOf(value: Record<string, unknown>, path: string): CommandCandidate[] {
	const program = programOf(value);
	return Object.entries(value).flatMap(([key, child]) => {
		const k = key.toLowerCase();
		const isArgs = ARGS_KEYS.has(k);
		if (!isArgs && !ARGV_KEYS.has(k)) return [];
		const childPath = path ? `${path}.${key}` : key;
		const prefix = isArgs && program !== undefined ? [program] : [];
		return argvFieldCommands(child, prefix, isArgs).map((command) => ({
			path: childPath,
			command,
		}));
	});
}

/** Command lines one argv-shaped field runs, with `prefix` as its program. */
function argvFieldCommands(child: unknown, prefix: string[], isArgs: boolean): string[] {
	if (isStringArray(child)) {
		const command = commandFromArgv([...prefix, ...child]);
		const shellLines = child.filter((arg) => /\s/.test(arg.trim()));
		return command === undefined ? shellLines : [command, ...shellLines];
	}
	if (isArgs && prefix.length > 0 && typeof child === "string" && child.trim()) {
		return [`${prefix[0]} ${child}`];
	}
	return [];
}

/** Walk the input for argv-shaped commands, bounded like the string walk. */
function collectArgvCommands(
	value: unknown,
	path: string,
	depth: number,
	found: CommandCandidate[],
): void {
	if (depth > MAX_GENERIC_DEPTH || found.length >= MAX_GENERIC_STRINGS) return;
	if (Array.isArray(value)) {
		value.forEach((item, i) => {
			collectArgvCommands(item, `${path}[${i}]`, depth + 1, found);
		});
		return;
	}
	if (!value || typeof value !== "object") return;
	const record = value as Record<string, unknown>;
	found.push(...argvCommandsOf(record, path));
	for (const [key, child] of Object.entries(record)) {
		collectArgvCommands(child, path ? `${path}.${key}` : key, depth + 1, found);
	}
}

/**
 * Best-effort extraction for unknown / MCP tool calls.
 * Recursively scans the tool input for string fields, extracting:
 * - explicit URLs / commands / file paths based on common key names; command
 *   strings are inspected like a Bash command
 * - command lines rebuilt from argv arrays (`command: ["bash", "-c", …]`,
 *   `cmd` + `args`)
 * - credential files reached through a search/list tool's root or filter
 * - URLs found inside any collected strings
 * - generic content strings for heuristic matching (windowed, never cut)
 *
 * When the input exceeds an inspection limit the result ends with an
 * `input_not_fully_inspected` marker artifact (see {@link inspectionLimitsHit});
 * the evaluator denies such a call instead of judging only the inspected part.
 */
export function extractFromUnknownTool(
	toolName: string,
	toolInput: Record<string, unknown>,
): Artifact[] {
	const walk: GenericWalk = { fields: [], chars: 0, limits: new Set() };
	collectStringFields(toolInput, "", 0, walk);

	const out = new GenericArtifacts(walk.limits);
	let open = walk.fields.every((field) => addFieldArtifacts(toolName, field, out, walk.limits));

	// Argv arrays are walked element by element above, where no element is a
	// command on its own; rebuild the command line they run.
	const argvCommands: CommandCandidate[] = [];
	if (open) collectArgvCommands(toolInput, "", 0, argvCommands);
	for (const candidate of argvCommands) {
		if (!open) break;
		if (candidate.command.length > MAX_ARTIFACT_SIZE) {
			walk.limits.add("string_size");
			continue;
		}
		open = addCommandArtifacts(candidate.command, `tool:${toolName}:${candidate.path}:argv`, out);
	}

	// Grep/Glob/list-style tools read below a root or match file names: a
	// root or filter that reaches a credential location is a credential read.
	const searchReads = open ? (credentialReadsInSearchTool(toolName, toolInput) ?? []) : [];
	for (const path of searchReads) {
		if (!out.add({ type: "file_path", value: path, context: CREDENTIAL_READ_CONTEXT })) break;
	}
	return [...out.items, ...[...walk.limits].map(inspectionLimitMarker)];
}

/**
 * Normalize extraction across connectors: handles known tool shapes and
 * falls back to extractFromUnknownTool for MCP/unknown tools.
 */
export function extractFromToolCall(
	toolName: string,
	toolInput: Record<string, unknown>,
): Artifact[] {
	switch (toolName) {
		case "Bash":
		case "Shell": {
			// Hosts may send an argv array (`["bash", "-lc", "curl … | sh"]`)
			// instead of a command line; both shapes are inspected.
			const result = commandFromValue(toolInput.command);
			return result.ok && result.command ? extractFromBash(result.command) : [];
		}
		case "WebFetch":
			return extractFromWebFetch(toolInput);
		case "Write":
			return extractFromWrite(toolInput);
		case "Edit":
			return extractFromEdit(toolInput);
		case "Read":
			return extractFromRead(toolInput);
		case "Delete":
			return extractFromDelete(toolInput);
		default:
			return extractFromUnknownTool(toolName || "Unknown", toolInput);
	}
}
