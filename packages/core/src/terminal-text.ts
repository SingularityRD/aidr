/**
 * Make untrusted text safe to print on an operator's terminal.
 *
 * The operator approval channel shows the operator text that originates from the
 * policed agent: the command it tried to run, file paths, artifact previews. A
 * raw ESC, CR or backspace in that text can rewrite what the terminal displays
 * (`\x1b[2K\r` erases the line and prints something harmless in its place), and
 * Unicode bidi and format controls (U+202E RIGHT-TO-LEFT OVERRIDE, zero-width
 * characters, U+FEFF) can reorder or hide characters. Either lets an attacker
 * show the operator a different call from the one being approved.
 *
 * {@link escapeTerminalText} renders every such character as a visible escape
 * (`\x1b`, `\r`, `‮`), so the text an operator reads is the text that runs.
 * It is idempotent: its output contains no characters it would escape.
 */

/** C0/C1 controls, DEL, Unicode format (Cf) and line/paragraph separators. */
const UNSAFE_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const UNSAFE_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/** Appended when text was cut to fit its display bound. */
export const TRUNCATION_MARKER = " …(truncated)";

const NAMED_ESCAPES: Record<string, string> = {
	"\n": "\\n",
	"\r": "\\r",
	"\t": "\\t",
};

function escapeCharacter(character: string): string {
	const named = NAMED_ESCAPES[character];
	if (named) return named;
	const code = character.codePointAt(0) ?? 0;
	if (code <= 0xff) return `\\x${code.toString(16).padStart(2, "0")}`;
	if (code <= 0xffff) return `\\u${code.toString(16).padStart(4, "0")}`;
	return `\\u{${code.toString(16)}}`;
}

/** Whether the text holds any character {@link escapeTerminalText} would rewrite. */
export function hasUnsafeTerminalCharacters(value: string): boolean {
	return UNSAFE_CHARACTER.test(value);
}

/** Render every control, bidi and format character as a visible escape sequence. */
export function escapeTerminalText(value: string): string {
	return value.replace(UNSAFE_CHARACTERS, escapeCharacter);
}

export interface BoundedTerminalText {
	text: string;
	truncated: boolean;
}

/**
 * Escape `value` and bound the result to `max` characters, marker included.
 *
 * The cut never splits an escape sequence or a surrogate pair, and a cut text
 * always ends with {@link TRUNCATION_MARKER}, so the operator can tell that they
 * are not looking at the whole call.
 */
export function boundTerminalText(value: string, max: number): BoundedTerminalText {
	const escaped = escapeTerminalText(value);
	if (escaped.length <= max) return { text: escaped, truncated: false };
	const budget = Math.max(0, max - TRUNCATION_MARKER.length);
	let text = "";
	for (const character of value) {
		const token = UNSAFE_CHARACTER.test(character) ? escapeCharacter(character) : character;
		if (text.length + token.length > budget) break;
		text += token;
	}
	return { text: `${text}${TRUNCATION_MARKER}`, truncated: true };
}
