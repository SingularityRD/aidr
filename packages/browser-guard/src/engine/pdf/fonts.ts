/**
 * Font decoding for text extraction (ISO 32000-1 §9.6-9.10): shown string bytes -> glyphs
 * with Unicode text and advance widths.
 *
 *   - ToUnicode CMaps first, for every font type;
 *   - simple fonts (Type1, TrueType, Type3): WinAnsi / MacRoman / Standard base encodings
 *     with `/Differences` glyph names; `/Widths` + `/FirstChar` (Type3 scaled by FontMatrix);
 *   - Type0 fonts: code lengths from the embedded encoding CMap's code-space ranges (or
 *     2 bytes for Identity-H/V); widths from the descendant's `/W` and `/DW`; text only
 *     through ToUnicode (glyphs without a mapping are reported as unmapped).
 * Symbol-type fonts (Symbol, ZapfDingbats, Wingdings...) produce no text.
 */
import { type CMap, codeKey, parseCMap, splitCodes } from "./cmap.js";
import type { PdfDocument } from "./document.js";
import { type BaseEncoding, baseEncoding, glyphToUnicode } from "./encodings.js";
import { binaryString, PdfDict, PdfName, PdfStream, type PdfValue } from "./lexer.js";

export interface Glyph {
	readonly text: string | undefined;
	/** Advance in text-space units per 1 unit of font size (glyph width / 1000). */
	readonly width: number;
	readonly space: boolean;
}

export interface Font {
	decode(bytes: string): Glyph[];
	/** Glyphs deliberately not reported as text (symbol fonts). */
	readonly symbolic: boolean;
}

/** Used when a content stream selects a font that does not exist. */
export const DEFAULT_FONT: Font = {
	symbolic: false,
	decode(bytes) {
		const table = baseEncoding("StandardEncoding");
		return [...bytes].map((ch) => {
			const code = ch.charCodeAt(0);
			return { text: table[code], width: 0.5, space: code === 32 };
		});
	},
};

const MAX_CID_WIDTHS = 65_536;

async function toUnicode(doc: PdfDocument, dict: PdfDict): Promise<CMap | null> {
	const stream = doc.resolve(dict.get("ToUnicode"));
	if (!(stream instanceof PdfStream)) return null;
	const decoded = await doc.stream(stream);
	return decoded ? parseCMap(binaryString(decoded.data)) : null;
}

function baseName(name: string | undefined, fallback: BaseEncoding): BaseEncoding {
	return name === "WinAnsiEncoding" || name === "MacRomanEncoding" || name === "StandardEncoding"
		? name
		: fallback;
}

function simpleEncoding(
	doc: PdfDocument,
	dict: PdfDict,
	subtype: string | undefined,
): Array<string | undefined> {
	const encoding = doc.resolve(dict.get("Encoding"));
	const fallback: BaseEncoding = subtype === "TrueType" ? "WinAnsiEncoding" : "StandardEncoding";
	if (encoding instanceof PdfName) return [...baseEncoding(baseName(encoding.name, fallback))];
	const encDict = doc.dict(encoding);
	const table = [...baseEncoding(baseName(doc.name(encDict?.get("BaseEncoding")), fallback))];
	let code = 0;
	for (const item of doc.array(encDict?.get("Differences")) ?? []) {
		const v = doc.resolve(item);
		if (typeof v === "number") code = v;
		else if (v instanceof PdfName && code >= 0 && code < 256)
			table[code++] = glyphToUnicode(v.name);
	}
	return table;
}

function simpleWidths(doc: PdfDocument, dict: PdfDict, scale: number): (code: number) => number {
	const first = doc.num(dict.get("FirstChar")) ?? 0;
	const widths = (doc.array(dict.get("Widths")) ?? []).map((w) => doc.num(w) ?? 0);
	const missing = doc.num(doc.dict(dict.get("FontDescriptor"))?.get("MissingWidth"));
	const fallback = missing && missing > 0 ? missing : 500;
	return (code) => ((widths[code - first] ?? fallback) * scale) / 1000;
}

/** Reads one `/W` item at `i` (`c [w1 w2 ...]` or `c1 c2 w`); returns the next index or -1. */
function cidWidthItem(
	doc: PdfDocument,
	w: readonly PdfValue[],
	i: number,
	table: Map<number, number>,
	dw: number,
): number {
	const first = doc.num(w[i]);
	if (first === undefined) return -1;
	const next = doc.resolve(w[i + 1]);
	if (Array.isArray(next)) {
		next.slice(0, MAX_CID_WIDTHS).forEach((v, k) => {
			table.set(first + k, doc.num(v) ?? dw);
		});
		return i + 2;
	}
	const last = doc.num(next);
	const width = doc.num(w[i + 2]);
	if (last === undefined || width === undefined) return -1;
	for (let c = first; c <= Math.min(last, first + MAX_CID_WIDTHS); c++) table.set(c, width);
	return i + 3;
}

function cidWidths(doc: PdfDocument, descendant: PdfDict | undefined): (cid: number) => number {
	const dw = doc.num(descendant?.get("DW")) ?? 1000;
	const table = new Map<number, number>();
	const w = doc.array(descendant?.get("W")) ?? [];
	for (let i = 0; i >= 0 && i < w.length && table.size < MAX_CID_WIDTHS; )
		i = cidWidthItem(doc, w, i, table, dw);
	return (cid) => (table.get(cid) ?? dw) / 1000;
}

async function type0Font(doc: PdfDocument, dict: PdfDict, unicode: CMap | null): Promise<Font> {
	const descendant = doc.dict(doc.array(dict.get("DescendantFonts"))?.[0]);
	const widths = cidWidths(doc, descendant);
	const encoding = doc.resolve(dict.get("Encoding"));
	let ranges = unicode?.codespace ?? [];
	if (encoding instanceof PdfStream) {
		const decoded = await doc.stream(encoding);
		const cmap = decoded ? parseCMap(binaryString(decoded.data)) : null;
		if (cmap?.codespace.length) ranges = cmap.codespace;
	}
	return {
		symbolic: false,
		decode: (bytes) =>
			splitCodes(bytes, ranges, 2).map(({ code, bytes: n }) => ({
				text: unicode?.map.get(codeKey(n, code)),
				width: widths(code),
				space: n === 1 && code === 32,
			})),
	};
}

function simpleFont(doc: PdfDocument, dict: PdfDict, unicode: CMap | null): Font {
	const subtype = doc.name(dict.get("Subtype"));
	const baseFont = doc.name(dict.get("BaseFont")) ?? "";
	const table = simpleEncoding(doc, dict, subtype);
	const matrix = doc.array(dict.get("FontMatrix"));
	const scale = subtype === "Type3" ? (doc.num(matrix?.[0]) ?? 0.001) * 1000 : 1;
	const widths = simpleWidths(doc, dict, scale);
	return {
		symbolic: /Symbol|Dingbats|Wingdings|Webdings/i.test(baseFont),
		decode: (bytes) =>
			[...bytes].map((ch) => {
				const code = ch.charCodeAt(0);
				return {
					text: unicode?.map.get(codeKey(1, code)) ?? table[code],
					width: widths(code),
					space: code === 32,
				};
			}),
	};
}

export async function loadFont(doc: PdfDocument, dict: PdfDict): Promise<Font> {
	const unicode = await toUnicode(doc, dict);
	return doc.name(dict.get("Subtype")) === "Type0"
		? type0Font(doc, dict, unicode)
		: simpleFont(doc, dict, unicode);
}
