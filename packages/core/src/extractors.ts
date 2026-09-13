/**
 * Extract security-relevant artifacts from tool inputs.
 */

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

const MAX_GENERIC_STRINGS = 200;
const MAX_GENERIC_DEPTH = 4;
const MAX_GENERIC_ARTIFACTS = 250;

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
export function warnTruncatedInput(
	source: string,
	originalLength: number,
	evaluatedLength: number,
): void {
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

		// The whole heredoc (dash and quotes included) collapses to `<<word`.
		out += command.slice(copiedUpTo, opener.index) + "<<" + word;
		copiedUpTo = terminator.wordStart + word.length;
		scanFrom = copiedUpTo;
	}

	return out + command.slice(copiedUpTo);
}

export function extractFromBash(command: string): Artifact[] {
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
		const capped = content.slice(0, MAX_CONTENT_SIZE);
		artifacts.push({ type: "content", value: capped, context: contextName });

		for (const url of extractUrls(capped)) {
			artifacts.push({ type: "url", value: url, context: urlContextName });
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

function asString(value: unknown): string | null {
	return typeof value === "string" ? value : null;
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

function fieldTypeForKey(key: string): Artifact["type"] | null {
	const k = key.toLowerCase();
	if (k === "url" || k.endsWith("_url")) return "url";
	if (k === "command" || k === "cmd" || k.endsWith("_command") || k.endsWith("_cmd"))
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

function collectStringFields(
	value: unknown,
	path: string,
	depth: number,
	out: Array<{ path: string; key: string; value: string }>,
): void {
	if (out.length >= MAX_GENERIC_STRINGS) return;
	if (depth > MAX_GENERIC_DEPTH) return;

	if (typeof value === "string") {
		out.push({
			path,
			key: path.split(".").slice(-1)[0] ?? "",
			value: value.slice(0, MAX_CONTENT_SIZE),
		});
		return;
	}

	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) {
			collectStringFields(value[i], `${path}[${i}]`, depth + 1, out);
			if (out.length >= MAX_GENERIC_STRINGS) return;
		}
		return;
	}

	if (value && typeof value === "object") {
		for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
			collectStringFields(v, path ? `${path}.${k}` : k, depth + 1, out);
			if (out.length >= MAX_GENERIC_STRINGS) return;
		}
	}
}

/**
 * Best-effort extraction for unknown / MCP tool calls.
 * Recursively scans the tool input for string fields, extracting:
 * - explicit URLs / commands / file paths based on common key names
 * - URLs found inside any collected strings
 * - generic content strings for heuristic matching (capped)
 */
export function extractFromUnknownTool(
	toolName: string,
	toolInput: Record<string, unknown>,
): Artifact[] {
	const artifacts: Artifact[] = [];
	const fields: Array<{ path: string; key: string; value: string }> = [];
	collectStringFields(toolInput, "", 0, fields);

	for (const field of fields) {
		const raw = field.value;
		const trimmed = raw.trim();
		if (!trimmed) continue;

		const keyType = fieldTypeForKey(field.key);
		const context = `tool:${toolName}:${field.path || field.key || "value"}`;

		if (keyType === "url") {
			artifacts.push({ type: "url", value: trimmed, context });
		} else if (keyType === "command") {
			artifacts.push({ type: "command", value: trimmed, context });
		} else if (keyType === "file_path") {
			artifacts.push({ type: "file_path", value: trimmed, context });
		} else if (keyType === "content") {
			artifacts.push({ type: "content", value: trimmed.slice(0, MAX_CONTENT_SIZE), context });
		} else {
			// Heuristic: promote obvious paths to file_path
			if (looksLikePath(trimmed)) {
				artifacts.push({ type: "file_path", value: trimmed, context });
			} else {
				artifacts.push({ type: "content", value: trimmed.slice(0, MAX_CONTENT_SIZE), context });
			}
		}

		for (const url of extractUrls(trimmed)) {
			artifacts.push({ type: "url", value: url, context: `${context}:embedded_url` });
		}

		if (artifacts.length >= MAX_GENERIC_ARTIFACTS) break;
	}

	const seen = new Set<string>();
	const deduped: Artifact[] = [];
	for (const a of artifacts) {
		const key = `${a.type}:${a.value}`;
		if (seen.has(key)) continue;
		seen.add(key);
		deduped.push(a);
		if (deduped.length >= MAX_GENERIC_ARTIFACTS) break;
	}
	return deduped;
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
			const command = asString(toolInput.command) ?? "";
			return command ? extractFromBash(command) : [];
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
