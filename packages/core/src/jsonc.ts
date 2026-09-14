/**
 * Tolerant reader for host MCP configuration files.
 *
 * The `.vscode/mcp.json` family (and several other host configs registered in
 * `mcp-inventory.ts`) is JSONC: it allows `//` and block comments as well as
 * trailing commas. Feeding those files to `JSON.parse` throws, which made an
 * existing-but-unreadable configuration indistinguishable from an absent one.
 *
 * This module is the single implementation used by both the inventory reader
 * (`mcp-inventory.ts`) and the runtime policy check (`policy.ts`) so the two
 * cannot drift on what "unreadable" means.
 *
 * The scanner is string-aware: a comment delimiter or a `,` that appears inside
 * a quoted string is data, never syntax. It deliberately does NOT attempt JSON5
 * features (single quotes, unquoted keys, hex/NaN literals) — those stay
 * unreadable on purpose, because guessing at a config's meaning is exactly the
 * coverage lie this reader removes.
 */

export type JsoncParseStatus = "ok" | "invalid";

export interface JsoncParseResult {
	status: JsoncParseStatus;
	/** Present only when `status` is `"ok"`. */
	value?: unknown;
	/** Present only when `status` is `"invalid"`; safe to log, never user data. */
	error?: string;
}

/** Emits every character of real JSON text, in order, with its source index. */
type JsoncEmitter = (ch: string, index: number) => void;

/**
 * Emits a quoted string literal starting at `start` and returns the index just
 * past its closing quote (or the end of input when unterminated).
 */
function consumeString(content: string, start: number, emit: JsoncEmitter): number {
	emit(content[start] as string, start);
	let escaped = false;
	for (let i = start + 1; i < content.length; i++) {
		const ch = content[i] as string;
		emit(ch, i);
		if (escaped) escaped = false;
		else if (ch === "\\") escaped = true;
		else if (ch === '"') return i + 1;
	}
	return content.length;
}

/**
 * Returns the index just past a `//` comment starting at `start`.
 *
 * The newline itself is not part of the comment, so line structure survives.
 */
function endOfLineComment(content: string, start: number): number {
	let i = start;
	while (i + 1 < content.length && content[i + 1] !== "\n" && content[i + 1] !== "\r") {
		i++;
	}
	return i + 1;
}

/**
 * Emits the newlines of a block comment starting at `start` so a later JSON
 * syntax error still points at its line, then returns the index just past the
 * comment terminator.
 *
 * An unterminated block comment throws: that is malformed input, not a comment.
 */
function endOfBlockComment(content: string, start: number, emit: JsoncEmitter): number {
	const end = content.indexOf("*/", start + 2);
	if (end === -1) throw new Error("unterminated_block_comment");
	for (let i = start + 2; i < end; i++) {
		const inner = content[i] as string;
		if (inner === "\n" || inner === "\r") emit(inner, i);
	}
	return end + 2;
}

/** Single string-aware walk over `content` that never emits a comment. */
function walkJsonc(content: string, emit: JsoncEmitter): void {
	let index = 0;
	while (index < content.length) {
		const ch = content[index] as string;

		if (ch === '"') {
			index = consumeString(content, index, emit);
			continue;
		}

		if (ch === "/" && content[index + 1] === "/") {
			index = endOfLineComment(content, index);
			continue;
		}

		if (ch === "/" && content[index + 1] === "*") {
			index = endOfBlockComment(content, index, emit);
			continue;
		}

		emit(ch, index);
		index++;
	}
}

/** Removes `//` and block comments, leaving every string literal untouched. */
export function stripJsonComments(content: string): string {
	let out = "";
	walkJsonc(content, (ch) => {
		out += ch;
	});
	return out;
}

/** True when the next non-whitespace character closes an object or array. */
function isFollowedByCloser(content: string, start: number): boolean {
	for (let i = start; i < content.length; i++) {
		const ch = content[i] as string;
		if (ch === "}" || ch === "]") return true;
		if (!/\s/.test(ch)) return false;
	}
	return false;
}

/** Removes commas that are immediately followed by `}` or `]`, outside strings. */
function stripTrailingCommas(content: string): string {
	let out = "";
	walkJsonc(content, (ch, index) => {
		if (ch === "," && isFollowedByCloser(content, index + 1)) return;
		out += ch;
	});
	return out;
}

/**
 * Parses JSON or JSONC content and reports an explicit status.
 *
 * Never throws: callers must branch on `status` so an unreadable file becomes a
 * visible coverage gap instead of an empty result.
 */
export function parseJsonc(content: string): JsoncParseResult {
	try {
		const withoutBom = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
		const stripped = stripTrailingCommas(stripJsonComments(withoutBom));
		return { status: "ok", value: JSON.parse(stripped) as unknown };
	} catch (error) {
		return { status: "invalid", error: error instanceof Error ? error.message : String(error) };
	}
}
