/**
 * CMap parsing (ToUnicode maps and the code-space ranges of embedded encoding CMaps),
 * ISO 32000-1 §9.10.3 and Adobe Technical Note #5014. Bounded: at most
 * {@link MAX_MAPPINGS} code mappings are kept per CMap.
 */
import { Lexer, PdfCmd, PdfName, PdfString, type PdfValue } from "./lexer.js";

const MAX_MAPPINGS = 131_072;
const MAX_RANGE = 65_536;

export interface CodeRange {
	readonly bytes: number;
	readonly low: number;
	readonly high: number;
}

export interface CMap {
	readonly codespace: readonly CodeRange[];
	/** (byte length, code) key -> Unicode text. */
	readonly map: ReadonlyMap<number, string>;
}

export function codeKey(bytes: number, code: number): number {
	return bytes * 0x1_0000_0000 + code;
}

function stringCode(s: PdfString): number {
	let code = 0;
	for (let i = 0; i < s.bytes.length; i++) code = code * 256 + s.bytes.charCodeAt(i);
	return code;
}

/** UTF-16BE destination bytes -> string (odd trailing byte ignored). */
function utf16be(bytes: string): string {
	let out = "";
	for (let i = 0; i + 1 < bytes.length; i += 2)
		out += String.fromCharCode((bytes.charCodeAt(i) << 8) | bytes.charCodeAt(i + 1));
	if (bytes.length === 1) out += bytes;
	return out;
}

/** Adds `offset` to the last UTF-16 code unit of `dst` (bfrange with a string destination). */
function incremented(dst: string, offset: number): string {
	if (!dst) return dst;
	const last = dst.charCodeAt(dst.length - 1) + offset;
	return dst.slice(0, -1) + String.fromCharCode(last & 0xffff);
}

class CMapBuilder {
	readonly codespace: CodeRange[] = [];
	readonly map = new Map<number, string>();

	set(bytes: number, code: number, text: string): boolean {
		if (this.map.size >= MAX_MAPPINGS) return false;
		this.map.set(codeKey(bytes, code), text);
		return true;
	}
}

function readUntil(lexer: Lexer, endOp: string): PdfValue[] {
	const out: PdfValue[] = [];
	for (;;) {
		const v = lexer.readObject();
		if (v === undefined) return out;
		if (v instanceof PdfCmd && v.op === endOp) return out;
		out.push(v);
		if (out.length > MAX_MAPPINGS * 3) return out;
	}
}

function bfchar(values: readonly PdfValue[], b: CMapBuilder): void {
	for (let i = 0; i + 1 < values.length; i += 2) {
		const src = values[i];
		const dst = values[i + 1];
		if (!(src instanceof PdfString)) continue;
		const text =
			dst instanceof PdfString ? utf16be(dst.bytes) : dst instanceof PdfName ? dst.name : null;
		if (text !== null && !b.set(src.bytes.length, stringCode(src), text)) return;
	}
}

/** Destination text for `offset` within a bfrange (string: incremented; array: indexed). */
function rangeText(dst: PdfValue | undefined, offset: number): string | null {
	if (dst instanceof PdfString) return incremented(utf16be(dst.bytes), offset);
	const item = Array.isArray(dst) ? dst[offset] : undefined;
	return item instanceof PdfString ? utf16be(item.bytes) : null;
}

function bfrange(values: readonly PdfValue[], b: CMapBuilder): void {
	for (let i = 0; i + 2 < values.length; i += 3) {
		const lo = values[i];
		const hi = values[i + 1];
		if (!(lo instanceof PdfString) || !(hi instanceof PdfString)) continue;
		const low = stringCode(lo);
		const high = stringCode(hi);
		if (high < low || high - low >= MAX_RANGE) continue;
		for (let code = low; code <= high; code++) {
			const text = rangeText(values[i + 2], code - low);
			if (text !== null && !b.set(lo.bytes.length, code, text)) return;
		}
	}
}

function codespace(values: readonly PdfValue[], b: CMapBuilder): void {
	for (let i = 0; i + 1 < values.length; i += 2) {
		const lo = values[i];
		const hi = values[i + 1];
		if (!(lo instanceof PdfString) || !(hi instanceof PdfString)) continue;
		const bytes = lo.bytes.length;
		if (bytes < 1 || bytes > 4 || hi.bytes.length !== bytes) continue;
		b.codespace.push({ bytes, low: stringCode(lo), high: stringCode(hi) });
	}
}

/** Parses a CMap program (decoded stream text, one char per byte). */
export function parseCMap(src: string): CMap {
	const lexer = new Lexer(src, 0, src.length, false);
	const builder = new CMapBuilder();
	for (;;) {
		const v = lexer.readObject();
		if (v === undefined) break;
		if (!(v instanceof PdfCmd)) continue;
		if (v.op === "begincodespacerange") codespace(readUntil(lexer, "endcodespacerange"), builder);
		else if (v.op === "beginbfchar") bfchar(readUntil(lexer, "endbfchar"), builder);
		else if (v.op === "beginbfrange") bfrange(readUntil(lexer, "endbfrange"), builder);
	}
	return { codespace: builder.codespace, map: builder.map };
}

/**
 * Splits a shown string into character codes using code-space ranges (longest match of
 * 1..4 bytes); without ranges every code is `fallbackBytes` long.
 */
/** Length (1..4) of the code-space range matching the bytes at `i`, or 0. */
function matchLength(bytes: string, i: number, ranges: readonly CodeRange[]): number {
	let value = 0;
	for (let n = 1; n <= 4 && i + n <= bytes.length; n++) {
		value = value * 256 + bytes.charCodeAt(i + n - 1);
		if (ranges.some((r) => r.bytes === n && value >= r.low && value <= r.high)) return n;
	}
	return 0;
}

export function splitCodes(
	bytes: string,
	ranges: readonly CodeRange[],
	fallbackBytes: number,
): Array<{ code: number; bytes: number }> {
	const out: Array<{ code: number; bytes: number }> = [];
	let i = 0;
	while (i < bytes.length) {
		const length = matchLength(bytes, i, ranges) || Math.min(fallbackBytes, bytes.length - i);
		let code = 0;
		for (let n = 0; n < length; n++) code = code * 256 + bytes.charCodeAt(i + n);
		out.push({ code, bytes: length });
		i += length;
	}
	return out;
}
