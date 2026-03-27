/**
 * Extract security-relevant artifacts from tool inputs.
 */

import type { Artifact } from "./types.js";

/** Regex for extracting URLs — matches http/https followed by non-whitespace, non-quote chars. */
const URL_PATTERN = /https?:\/\/[^\s"')<>[\]{}]+/g;

/** Trailing punctuation that's likely not part of the URL. */
const TRAILING_PUNCT = /[.,;:!?]+$/;

/** Maximum content size to scan (64KB). */
const MAX_CONTENT_SIZE = 64 * 1024;

const MAX_GENERIC_STRINGS = 200;
const MAX_GENERIC_DEPTH = 4;
const MAX_GENERIC_ARTIFACTS = 250;

/** Detect base64-decode piped to execution: echo "..." | base64 -d | bash */
const BASE64_DECODE_EXEC =
	/\b(echo|printf|cat)\b[^|]*\|\s*base64\s+(-d|--decode)[^|]*\|\s*(bash|sh|zsh|ksh|dash|python|perl|ruby|node)\b/;

/** Detect hex/octal printf piped to shell: printf '\x41\x42' | bash */
const PRINTF_ENCODE_EXEC =
	/\bprintf\b\s+['"](\\x[0-9a-fA-F]{2}|\\[0-7]{3})[^|]*\|\s*(bash|sh|zsh|ksh|dash)\b/;

/** Detect shell variable interpolation hiding a domain: $HOST.$DOMAIN or ${HOST}.${DOMAIN} */
const VAR_INTERPOLATION_URL =
	/\b(curl|wget|fetch)\b[^|;]*(\$\{?\w+\}?\.\$\{?\w+\}?|\$\{?\w+\}?:\/\/)/;

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
 * Strip heredoc bodies from a command string. Heredoc content is inline text
 * data (commit messages, config files, etc.), not executable shell commands.
 */
function stripHeredocs(command: string): string {
	return command.replace(/<<-?\s*['"]?(\w+)['"]?\n[\s\S]*?\n[ \t]*\1\b/g, "<<$1");
}

export function extractFromBash(command: string): Artifact[] {
	const artifacts: Artifact[] = [];

	// Strip heredoc bodies — they're data, not executable commands
	const effective = stripHeredocs(command);

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

	// Extract URLs from the FULL command (heredoc content may contain relevant URLs)
	for (const url of extractUrls(command)) {
		let context: string | undefined;
		const escaped = escapeRegExp(url);
		// Direct pipe to shell: curl URL | sh
		const directPipe = new RegExp(escaped + String.raw`[^|]*\|\s*(${SHELLS})\b`);
		// Pipe through wrapper to shell: curl URL | timeout 5 bash, curl URL | xargs sh -c
		const wrappedPipe = new RegExp(escaped + String.raw`[^|]*\|\s*\S+\s+(\S+\s+)?(${SHELLS})\b`);
		// Subshell/backtick execution: $(curl URL | sh) or `curl URL | sh`
		const subshellExec = new RegExp(
			`${String.raw`(\$\(|`}\`)${escaped}[^)\`]*${String.raw`\|\s*(${SHELLS})\b`}`,
		);
		if (directPipe.test(command) || wrappedPipe.test(command) || subshellExec.test(command)) {
			context = "piped to shell";
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
	if (k === "command" || k === "cmd" || k.endsWith("_command") || k.endsWith("_cmd")) return "command";
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
		out.push({ path, key: path.split(".").slice(-1)[0] ?? "", value: value.slice(0, MAX_CONTENT_SIZE) });
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
export function extractFromUnknownTool(toolName: string, toolInput: Record<string, unknown>): Artifact[] {
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
export function extractFromToolCall(toolName: string, toolInput: Record<string, unknown>): Artifact[] {
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
