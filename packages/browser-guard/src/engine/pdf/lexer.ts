/**
 * PDF object syntax (ISO 32000-1 §7.2-7.3) over a byte-per-char ("binary") string.
 *
 * The lexer is shared by the file-level object parser and the content-stream interpreter.
 * It never throws on odd input: malformed tokens become `PdfCmd`s or are skipped, and nesting
 * is bounded so a hostile file cannot exhaust the stack.
 */

export class PdfName {
	constructor(readonly name: string) {}
}

export class PdfRef {
	constructor(
		readonly num: number,
		readonly gen: number,
	) {}
}

/** A string object; `bytes` holds one byte per char (0..255). */
export class PdfString {
	constructor(readonly bytes: string) {}
}

export class PdfCmd {
	constructor(readonly op: string) {}
}

export class PdfDict {
	constructor(readonly map: Map<string, PdfValue>) {}
	get(key: string): PdfValue | undefined {
		return this.map.get(key);
	}
}

export class PdfStream {
	constructor(
		readonly dict: PdfDict,
		/** Raw (still encoded) data span in the source. */
		readonly start: number,
		readonly end: number,
	) {}
}

export type PdfValue =
	| number
	| boolean
	| null
	| PdfName
	| PdfRef
	| PdfString
	| PdfCmd
	| PdfDict
	| PdfStream
	| PdfValue[];

const MAX_NESTING = 64;

/** Converts bytes to a string with exactly one char per byte (Latin-1). */
export function binaryString(bytes: Uint8Array): string {
	let out = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		out += String.fromCharCode(...bytes.subarray(i, Math.min(bytes.length, i + CHUNK)));
	}
	return out;
}

export function isWhite(c: number): boolean {
	return c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09 || c === 0x0c || c === 0x00;
}

function isDelimiter(c: number): boolean {
	return (
		c === 0x28 || // (
		c === 0x29 || // )
		c === 0x3c || // <
		c === 0x3e || // >
		c === 0x5b || // [
		c === 0x5d || // ]
		c === 0x7b || // {
		c === 0x7d || // }
		c === 0x2f || // /
		c === 0x25 // %
	);
}

function isOctal(c: number): boolean {
	return c >= 0x30 && c <= 0x37;
}

const ESCAPES: Readonly<Record<string, string>> = {
	n: "\n",
	r: "\r",
	t: "\t",
	b: "\b",
	f: "\f",
	"\n": "",
};

/** The escape sequence after a backslash at `at`: its text and the index after it. */
function readEscape(src: string, at: number): [string, number] {
	const n = src[at];
	if (n === undefined) return ["", at];
	const mapped = ESCAPES[n];
	if (mapped !== undefined) return [mapped, at + 1];
	if (n === "\r") return ["", src[at + 1] === "\n" ? at + 2 : at + 1]; // line continuation
	if (!isOctal(n.charCodeAt(0))) return [n, at + 1];
	let code = 0;
	let i = at;
	for (let k = 0; k < 3 && isOctal(src.charCodeAt(i)); k++)
		code = code * 8 + (src.charCodeAt(i++) - 48);
	return [String.fromCharCode(code & 0xff), i];
}

const END_ARRAY = Symbol("]");
const END_DICT = Symbol(">>");
type Token = PdfValue | typeof END_ARRAY | typeof END_DICT;

export class Lexer {
	pos: number;

	constructor(
		readonly src: string,
		start = 0,
		readonly end = src.length,
		/** Recognise `n g R` references (off for content streams, which have none). */
		private readonly refs = true,
	) {
		this.pos = start;
	}

	skipWhite(): void {
		const { src } = this;
		while (this.pos < this.end) {
			const c = src.charCodeAt(this.pos);
			if (isWhite(c)) this.pos++;
			else if (c === 0x25) {
				while (this.pos < this.end && src[this.pos] !== "\n" && src[this.pos] !== "\r") this.pos++;
			} else break;
		}
	}

	/** Reads one object (arrays and dictionaries recursively). Undefined at end of input. */
	readObject(depth = 0): PdfValue | undefined {
		const token = this.readToken(depth);
		if (token === END_ARRAY || token === END_DICT)
			return new PdfCmd(token === END_ARRAY ? "]" : ">>");
		return token;
	}

	private readToken(depth: number): Token | undefined {
		this.skipWhite();
		if (this.pos >= this.end) return undefined;
		const { src } = this;
		const c = src[this.pos];
		switch (c) {
			case "[":
				this.pos++;
				return this.readArray(depth + 1);
			case "]":
				this.pos++;
				return END_ARRAY;
			case "(":
				return this.readLiteral();
			case "/":
				return this.readName();
			case "<":
				if (src[this.pos + 1] === "<") {
					this.pos += 2;
					return this.readDict(depth + 1);
				}
				return this.readHex();
			case ">":
				this.pos += src[this.pos + 1] === ">" ? 2 : 1;
				return END_DICT;
			default:
				return this.readAtom();
		}
	}

	private readArray(depth: number): PdfValue[] {
		const out: PdfValue[] = [];
		if (depth > MAX_NESTING) return out;
		for (;;) {
			const t = this.readToken(depth);
			if (t === undefined || t === END_ARRAY) return out;
			if (t === END_DICT) continue;
			out.push(t);
		}
	}

	private readDict(depth: number): PdfDict {
		const map = new Map<string, PdfValue>();
		if (depth > MAX_NESTING) return new PdfDict(map);
		for (;;) {
			const key = this.readToken(depth);
			if (key === undefined || key === END_DICT) return new PdfDict(map);
			if (!(key instanceof PdfName)) continue;
			const value = this.readToken(depth);
			if (value === undefined || value === END_DICT) {
				map.set(key.name, null);
				return new PdfDict(map);
			}
			if (value === END_ARRAY) continue;
			map.set(key.name, value);
		}
	}

	private readLiteral(): PdfString {
		const { src } = this;
		let i = this.pos + 1;
		let depth = 1;
		let out = "";
		while (i < this.end) {
			const ch = src[i] as string;
			if (ch === "\\") {
				const [text, next] = readEscape(src, i + 1);
				out += text;
				i = next;
				continue;
			}
			if (ch === "(") depth++;
			else if (ch === ")" && --depth === 0) {
				i++;
				break;
			}
			// A raw end-of-line in a literal string reads as a single LF.
			if (ch === "\r" && src[i + 1] === "\n") i++;
			out += ch === "\r" ? "\n" : ch;
			i++;
		}
		this.pos = i;
		return new PdfString(out);
	}

	private readHex(): PdfString {
		const { src } = this;
		let i = this.pos + 1;
		let digits = "";
		while (i < this.end && src[i] !== ">") {
			const ch = src[i] as string;
			if (/[0-9A-Fa-f]/.test(ch)) digits += ch;
			i++;
		}
		this.pos = Math.min(this.end, i + 1);
		if (digits.length % 2) digits += "0";
		let out = "";
		for (let k = 0; k < digits.length; k += 2)
			out += String.fromCharCode(Number.parseInt(digits.slice(k, k + 2), 16));
		return new PdfString(out);
	}

	private readName(): PdfName {
		const { src } = this;
		let i = this.pos + 1;
		let name = "";
		while (i < this.end) {
			const c = src.charCodeAt(i);
			if (isWhite(c) || isDelimiter(c)) break;
			if (c === 0x23 && /^[0-9A-Fa-f]{2}$/.test(src.slice(i + 1, i + 3))) {
				name += String.fromCharCode(Number.parseInt(src.slice(i + 1, i + 3), 16));
				i += 3;
			} else {
				name += src[i];
				i++;
			}
		}
		this.pos = i;
		return new PdfName(name);
	}

	private readAtom(): PdfValue {
		const { src } = this;
		const start = this.pos;
		let i = start;
		while (i < this.end) {
			const c = src.charCodeAt(i);
			if (isWhite(c) || isDelimiter(c)) break;
			i++;
		}
		if (i === start) {
			// A stray delimiter such as "{" or ")": consume it as a command.
			this.pos = start + 1;
			return new PdfCmd(src[start] as string);
		}
		this.pos = i;
		const word = src.slice(start, i);
		if (/^[+-]?(?:\d+\.?\d*|\.\d+)$/.test(word)) {
			const num = Number.parseFloat(word);
			return this.refs && /^\d+$/.test(word) ? this.maybeRef(num) : num;
		}
		if (word === "true") return true;
		if (word === "false") return false;
		if (word === "null") return null;
		return new PdfCmd(word);
	}

	/** `12 0 R` -> PdfRef; otherwise leaves the position after the first integer. */
	private maybeRef(num: number): PdfValue {
		const save = this.pos;
		const m = /^[\0\t\n\f\r ]+(\d+)[\0\t\n\f\r ]+R(?=[\0\t\n\f\r ()<>[\]{}/%]|$)/.exec(
			this.src.slice(save, Math.min(this.end, save + 32)),
		);
		if (m?.[1] !== undefined) {
			this.pos = save + m[0].length;
			return new PdfRef(num, Number.parseInt(m[1], 10));
		}
		return num;
	}
}
