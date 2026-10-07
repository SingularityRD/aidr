/**
 * Field-aware masking of common PII inside a tool input.
 *
 * Used only when the effective DLP policy says `redact` for a built-in PII
 * type and the connector executes the rewritten input (Claude Code
 * `updatedInput`, OpenCode `output.args`). Each detected value is replaced with
 * a stable typed placeholder (`[EMAIL_1]`, `[TCKN_1]`, ...; the same value maps
 * to the same placeholder within one call), matching Browser Guard's style.
 *
 * Rewriting is refused (the caller denies) whenever it could change what the
 * tool does rather than only what data it carries:
 *
 * - Locator fields (`file_path`, `path`, `url`, `pattern`, `old_string`, ...)
 *   name a target. Replacing a value there points the tool somewhere else, and
 *   `[`/`]` are glob / regex syntax.
 * - A free-text field whose whole value is one PII value is the call's operand
 *   (a recipient, a lookup key); masking it changes the call's meaning.
 * - Shell command fields (`command`, `cmd`, `script`) are masked only inside
 *   plain quoted literals: `'...'`, or `"..."` containing no `$` or backtick.
 *   A value anywhere else (bare words, `$'...'`, expansions, comments, heredoc
 *   bodies outside quotes) would change execution meaning when rewritten.
 * - Non-string values (a card or TCKN sent as a JSON number) and object keys
 *   are never rewritten; the caller's residual re-scan denies them.
 */

export interface PiiMaskSpan {
	readonly start: number;
	readonly end: number;
	/** Placeholder prefix, e.g. `EMAIL`. */
	readonly label: string;
	/** Normalized value used to give repeats the same placeholder. */
	readonly key: string;
}

/**
 * Finds the spans in `text` that must be masked. Returns null when detection
 * could not inspect the text completely.
 */
export type PiiSpanFinder = (text: string) => PiiMaskSpan[] | null;

export interface PiiMaskResult {
	input: Record<string, unknown>;
	/** Masked occurrences per placeholder label; never the values themselves. */
	counts: Record<string, number>;
}

type FieldKind = "text" | "shell" | "locator";

const SHELL_KEYS = new Set(["command", "cmd", "script"]);
const LOCATOR_KEYS = new Set([
	"file_path",
	"filepath",
	"file",
	"filename",
	"path",
	"paths",
	"notebook_path",
	"cwd",
	"workdir",
	"directory",
	"dir",
	"url",
	"uri",
	"href",
	"pattern",
	"glob",
	"old_string",
	"oldstring",
]);

function fieldKind(key: string | undefined): FieldKind {
	const normalized = key?.toLowerCase();
	if (normalized === undefined) return "text";
	if (SHELL_KEYS.has(normalized)) return "shell";
	if (LOCATOR_KEYS.has(normalized)) return "locator";
	return "text";
}

/** Characters that, inside a matched value, could alter shell quoting. */
const SHELL_UNSAFE_VALUE = /['"\\$`]/;

/**
 * The closing quote of the quoted string opened at `open`, and whether its
 * content is passed verbatim. Null when the string is unterminated.
 */
function readQuoted(command: string, open: number): { close: number; literal: boolean } | null {
	const quote = command[open];
	// `$'...'` is ANSI-C quoting (escape-processed); `$"..."` a locale translation.
	const prefixed = command[open - 1] === "$";
	// Inside plain single quotes a backslash is literal and nothing expands.
	const escapes = quote === '"' || prefixed;
	let literal = !prefixed;
	let close = open + 1;
	while (close < command.length && command[close] !== quote) {
		const inner = command[close];
		if (quote === '"' && (inner === "$" || inner === "`")) literal = false;
		close += escapes && inner === "\\" ? 2 : 1;
	}
	return close < command.length ? { close, literal } : null;
}

function startsComment(command: string, index: number): boolean {
	return command[index] === "#" && (index === 0 || /[\s;&|()]/.test(command[index - 1] ?? ""));
}

/**
 * Content ranges of quoted literals in a shell command whose text is passed
 * verbatim. Returns null for a command that does not tokenize cleanly.
 */
export function shellLiteralSpans(command: string): Array<[number, number]> | null {
	const spans: Array<[number, number]> = [];
	let i = 0;
	while (i < command.length) {
		const next = nextToken(command, i, spans);
		if (next === null) return null;
		i = next;
	}
	return spans;
}

/** Index after the token at `i`, recording a literal span; null when unterminated. */
function nextToken(command: string, i: number, spans: Array<[number, number]>): number | null {
	const char = command[i];
	if (char === "\\") return i + 2;
	if (startsComment(command, i)) {
		const newline = command.indexOf("\n", i);
		return newline === -1 ? command.length : newline + 1;
	}
	if (char !== "'" && char !== '"') return i + 1;
	const quoted = readQuoted(command, i);
	if (!quoted) return null;
	if (quoted.literal) spans.push([i + 1, quoted.close]);
	return quoted.close + 1;
}

/** Earlier start wins; on a tie the longer span. Overlaps are left for the re-scan. */
function nonOverlapping(spans: PiiMaskSpan[]): PiiMaskSpan[] {
	const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
	const kept: PiiMaskSpan[] = [];
	for (const span of sorted) {
		const last = kept[kept.length - 1];
		if (!last || span.start >= last.end) kept.push(span);
	}
	return kept;
}

class PlaceholderBook {
	private readonly assigned = new Map<string, string>();
	private readonly next = new Map<string, number>();
	readonly counts: Record<string, number> = {};

	constructor(private readonly original: string) {}

	placeholder(span: PiiMaskSpan): string {
		this.counts[span.label] = (this.counts[span.label] ?? 0) + 1;
		const id = `${span.label}\u0000${span.key}`;
		const existing = this.assigned.get(id);
		if (existing) return existing;
		let n = this.next.get(span.label) ?? 1;
		// Never reuse a placeholder that already appears in the original input.
		while (this.original.includes(`[${span.label}_${n}]`)) n += 1;
		this.next.set(span.label, n + 1);
		const placeholder = `[${span.label}_${n}]`;
		this.assigned.set(id, placeholder);
		return placeholder;
	}
}

class UnsafeRewrite extends Error {}

function assertNotSoleOperand(value: string, spans: PiiMaskSpan[]): void {
	const only = spans.length === 1 ? spans[0] : undefined;
	if (only && value.slice(only.start, only.end) === value.trim()) {
		throw new UnsafeRewrite("field is a single PII operand");
	}
}

function assertInsideShellLiterals(command: string, spans: PiiMaskSpan[]): void {
	const literals = shellLiteralSpans(command);
	if (literals === null) throw new UnsafeRewrite("command does not tokenize");
	for (const span of spans) {
		const inside = literals.some(([start, end]) => span.start >= start && span.end <= end);
		if (!inside || SHELL_UNSAFE_VALUE.test(command.slice(span.start, span.end))) {
			throw new UnsafeRewrite("value outside a plain quoted literal");
		}
	}
}

function maskString(
	value: string,
	kind: FieldKind,
	find: PiiSpanFinder,
	book: PlaceholderBook,
): string {
	const found = find(value);
	if (found === null) throw new UnsafeRewrite("incomplete detection");
	if (found.length === 0) return value;
	if (kind === "locator") throw new UnsafeRewrite("value in a locator field");
	const spans = nonOverlapping(found);
	if (kind === "text") assertNotSoleOperand(value, spans);
	else assertInsideShellLiterals(value, spans);
	let out = "";
	let cursor = 0;
	for (const span of spans) {
		out += value.slice(cursor, span.start) + book.placeholder(span);
		cursor = span.end;
	}
	return out + value.slice(cursor);
}

function maskValue(
	value: unknown,
	key: string | undefined,
	find: PiiSpanFinder,
	book: PlaceholderBook,
): unknown {
	if (typeof value === "string") return maskString(value, fieldKind(key), find, book);
	if (Array.isArray(value)) return value.map((item) => maskValue(item, key, find, book));
	if (value !== null && typeof value === "object") {
		const out: Record<string, unknown> = {};
		for (const [childKey, child] of Object.entries(value)) {
			out[childKey] = maskValue(child, childKey, find, book);
		}
		return out;
	}
	return value;
}

/**
 * Mask every span `find` reports in the string fields of `input`. Returns null
 * when any field cannot be rewritten without changing the call's meaning. The
 * caller must re-scan the result: values this function leaves alone (numbers,
 * keys, overlaps) are still in it.
 */
export function maskPiiInToolInput(
	input: Record<string, unknown>,
	find: PiiSpanFinder,
): PiiMaskResult | null {
	const book = new PlaceholderBook(JSON.stringify(input));
	try {
		const masked = maskValue(input, undefined, find, book) as Record<string, unknown>;
		return { input: masked, counts: book.counts };
	} catch (error) {
		if (error instanceof UnsafeRewrite) return null;
		throw error;
	}
}
