/**
 * PDF file structure: object table, trailers and stream decoding.
 *
 * Parsing is xref-independent (the approach PDF readers use to recover damaged files): the
 * file is scanned once for `n g obj` definitions (later definitions win, which also covers
 * incremental updates) and object streams (`/Type /ObjStm`) are expanded. Every definition
 * is kept (`definitions`), including the ones a later definition shadows, so content a
 * xref-following reader would see is never lost to a dead redefinition. Trailers come from
 * `trailer` dictionaries and cross-reference streams (`/Type /XRef`); the cross-reference
 * itself is only read on demand ({@link crossReference}) to spot redefinitions that disagree
 * with it.
 *
 * Stream decoding is bounded per stream and in total (`PdfLimits`); anything over budget,
 * an unsupported filter or a predictor marks the document as partially read.
 */
import { InflateLimitError, inflateBounded } from "../office/deflate.js";
import {
	ascii85Decode,
	asciiHexDecode,
	type Decoded,
	lzwDecode,
	runLengthDecode,
	unpredictPngRows,
} from "./filters.js";
import {
	binaryString,
	isWhite,
	Lexer,
	PdfDict,
	PdfName,
	PdfRef,
	PdfStream,
	type PdfValue,
} from "./lexer.js";

export interface PdfLimits {
	readonly maxObjects: number;
	readonly maxPages: number;
	readonly maxStreamBytes: number;
	readonly maxInflatedTotal: number;
	readonly maxTextChars: number;
	readonly maxFormDepth: number;
	readonly maxOperators: number;
}

const MIB = 1024 * 1024;

export const DEFAULT_PDF_LIMITS: PdfLimits = Object.freeze({
	maxObjects: 500_000,
	maxPages: 2_000,
	maxStreamBytes: 32 * MIB,
	maxInflatedTotal: 96 * MIB,
	maxTextChars: 4_000_000,
	maxFormDepth: 8,
	maxOperators: 5_000_000,
});

export interface Entry {
	readonly value: PdfValue;
	/** Offset of the definition (for an object-stream member: of its object stream). */
	readonly pos: number;
	/** Number of the object stream holding this definition (absent for a direct one). */
	readonly container?: number;
}

type Filter = (doc: PdfDocument, data: Uint8Array) => Promise<Decoded | null> | Decoded | null;

const FILTERS: Readonly<Record<string, Filter>> = {
	FlateDecode: (doc, data) => doc.inflate(data),
	LZWDecode: (doc, data) => lzwDecode(data, doc.budget()),
	ASCIIHexDecode: (_doc, data) => ({ data: asciiHexDecode(data), complete: true }),
	ASCII85Decode: (_doc, data) => ({ data: ascii85Decode(data), complete: true }),
	RunLengthDecode: (doc, data) => runLengthDecode(data, doc.budget()),
};

/** Abbreviated filter names (inline images and some producers). */
export const FILTER_ALIASES: Readonly<Record<string, string>> = {
	Fl: "FlateDecode",
	LZW: "LZWDecode",
	AHx: "ASCIIHexDecode",
	A85: "ASCII85Decode",
	RL: "RunLengthDecode",
};

export class PdfDocument {
	/** The definition in effect for each object number (the last one in the file). */
	readonly objects = new Map<number, Entry>();
	/** Every definition of each object number, in file order (shadowed ones included). */
	readonly definitions = new Map<number, Entry[]>();
	definitionCount = 0;
	readonly trailers: Array<{ dict: PdfDict; pos: number }> = [];
	inflated = 0;
	/** Set whenever something could not be read completely. */
	partial = false;
	operators = 0;

	constructor(
		readonly bytes: Uint8Array,
		readonly src: string,
		readonly limits: PdfLimits,
	) {}

	resolve(v: PdfValue | undefined, depth = 0): PdfValue | undefined {
		if (!(v instanceof PdfRef)) return v;
		return depth > 16 ? undefined : this.resolve(this.objects.get(v.num)?.value, depth + 1);
	}

	dict(v: PdfValue | undefined): PdfDict | undefined {
		const r = this.resolve(v);
		if (r instanceof PdfDict) return r;
		return r instanceof PdfStream ? r.dict : undefined;
	}

	name(v: PdfValue | undefined): string | undefined {
		const r = this.resolve(v);
		return r instanceof PdfName ? r.name : undefined;
	}

	num(v: PdfValue | undefined): number | undefined {
		const r = this.resolve(v);
		return typeof r === "number" && Number.isFinite(r) ? r : undefined;
	}

	array(v: PdfValue | undefined): PdfValue[] | undefined {
		const r = this.resolve(v);
		return Array.isArray(r) ? r : undefined;
	}

	/** The latest trailer that has `key`. */
	trailer(key: string): PdfDict | undefined {
		for (let i = this.trailers.length - 1; i >= 0; i--) {
			const dict = this.trailers[i]?.dict;
			if (dict?.get(key) !== undefined) return dict;
		}
		return undefined;
	}

	/** Decoded stream data; null when a filter is unsupported or the budget is spent. */
	async stream(stream: PdfStream): Promise<Decoded | null> {
		const filterValue = this.resolve(stream.dict.get("Filter"));
		const filters = Array.isArray(filterValue) ? filterValue : filterValue ? [filterValue] : [];
		const parmsValue = this.resolve(stream.dict.get("DecodeParms"));
		const parms = Array.isArray(parmsValue) ? parmsValue : [parmsValue];
		let decoded: Decoded = { data: this.bytes.subarray(stream.start, stream.end), complete: true };
		for (let i = 0; i < filters.length; i++) {
			const predictor = this.num(this.dict(parms[i] ?? undefined)?.get("Predictor")) ?? 1;
			const next =
				predictor > 1 ? null : await this.applyFilter(this.name(filters[i]), decoded.data);
			if (!next) return null;
			decoded = { data: next.data, complete: decoded.complete && next.complete };
		}
		return decoded;
	}

	/** Records a definition of `num`; `current` makes it the one in effect. */
	define(num: number, entry: Entry, current: boolean): void {
		const list = this.definitions.get(num);
		if (list) list.push(entry);
		else this.definitions.set(num, [entry]);
		this.definitionCount++;
		if (current) this.objects.set(num, entry);
	}

	budget(): number {
		return Math.min(this.limits.maxStreamBytes, this.limits.maxInflatedTotal - this.inflated);
	}

	/** True for the filters {@link applyFilter} decodes (full or abbreviated name). */
	static knownFilter(name: string): boolean {
		return FILTERS[FILTER_ALIASES[name] ?? name] !== undefined;
	}

	/** One filter, counted against the inflate budget; null when unsupported or over budget. */
	async applyFilter(name: string | undefined, data: Uint8Array): Promise<Decoded | null> {
		const filter = name ? FILTERS[FILTER_ALIASES[name] ?? name] : undefined;
		const out = filter ? await filter(this, data) : null;
		if (!out) return null;
		this.inflated += out.data.length;
		if (this.inflated <= this.limits.maxInflatedTotal) return out;
		this.partial = true;
		return null;
	}

	async inflate(data: Uint8Array): Promise<Decoded | null> {
		const limit = this.budget();
		try {
			if (limit <= 0) throw new InflateLimitError();
			const zlib = await inflateBounded(data, "deflate", limit);
			if (zlib.complete || data.length <= 2) return { data: zlib.bytes, complete: zlib.complete };
			// Some producers write raw deflate or a broken zlib trailer: try without the header.
			const raw = await inflateBounded(data.subarray(2), "deflate-raw", limit);
			const best = raw.bytes.length > zlib.bytes.length ? raw : zlib;
			return { data: best.bytes, complete: best.complete };
		} catch (error) {
			if (!(error instanceof InflateLimitError)) throw error;
			this.partial = true;
			return null;
		}
	}
}

const OBJ_RE = /(\d{1,10})[\0\t\n\f\r ]+(\d{1,5})[\0\t\n\f\r ]+obj(?=[\0\t\n\f\r ()<>[\]{}/%]|$)/g;

/** Data span of a stream whose keyword ends at `after`. */
function streamSpan(src: string, after: number, length: number | undefined): [number, number] {
	let start = after;
	if (src[start] === "\r") start++;
	if (src[start] === "\n") start++;
	if (length !== undefined && length >= 0 && start + length <= src.length) {
		let k = start + length;
		while (k < src.length && isWhite(src.charCodeAt(k))) k++;
		if (src.startsWith("endstream", k)) return [start, start + length];
	}
	const found = src.indexOf("endstream", start);
	if (found < 0) return [start, src.length];
	let end = found;
	if (src[end - 1] === "\n") end--;
	if (src[end - 1] === "\r") end--;
	return [start, Math.max(start, end)];
}

/** Parses the object at `m`; returns where scanning continues. */
function parseObjectAt(doc: PdfDocument, m: RegExpExecArray): number {
	const { src } = doc;
	const lexer = new Lexer(src, m.index + m[0].length);
	let value = lexer.readObject();
	let next = lexer.pos;
	lexer.skipWhite();
	if (value instanceof PdfDict && src.startsWith("stream", lexer.pos)) {
		const [start, end] = streamSpan(src, lexer.pos + 6, doc.num(value.get("Length")));
		value = new PdfStream(value, start, end);
		next = end;
		if (doc.name(value.dict.get("Type")) === "XRef")
			doc.trailers.push({ dict: value.dict, pos: m.index });
	}
	if (value !== undefined)
		doc.define(Number.parseInt(m[1] as string, 10), { value, pos: m.index }, true);
	return Math.max(next, m.index + m[0].length);
}

export function parseObjects(doc: PdfDocument): void {
	const { src } = doc;
	const re = new RegExp(OBJ_RE.source, "g");
	for (let m = re.exec(src); m; m = re.exec(src)) {
		if (doc.definitionCount >= doc.limits.maxObjects) {
			doc.partial = true;
			break;
		}
		re.lastIndex = parseObjectAt(doc, m);
	}
	const tr = /trailer(?=[\0\t\n\f\r <])/g;
	for (let t = tr.exec(src); t; t = tr.exec(src)) {
		const value = new Lexer(src, t.index + 7).readObject();
		if (value instanceof PdfDict) doc.trailers.push({ dict: value, pos: t.index });
	}
	doc.trailers.sort((a, b) => a.pos - b.pos);
}

/**
 * Adds the objects of one object stream; a member becomes current unless a later definition
 * exists. Shadowed object streams are expanded too (their members only as definitions).
 */
async function expandObjectStream(doc: PdfDocument, num: number, entry: Entry): Promise<void> {
	const stream = entry.value as PdfStream;
	const current = doc.objects.get(num) === entry;
	const n = doc.num(stream.dict.get("N")) ?? 0;
	const first = doc.num(stream.dict.get("First")) ?? 0;
	if (n <= 0 || n > 100_000) return;
	const decoded = await doc.stream(stream);
	if (!decoded) {
		doc.partial = true;
		return;
	}
	const text = binaryString(decoded.data);
	const header = new Lexer(text, 0, Math.min(text.length, first), false);
	for (let i = 0; i < n; i++) {
		if (doc.definitionCount >= doc.limits.maxObjects) {
			doc.partial = true;
			return;
		}
		const objNum = header.readObject();
		const offset = header.readObject();
		if (typeof objNum !== "number" || typeof offset !== "number") return;
		const value = new Lexer(text, first + offset).readObject();
		if (value === undefined) continue;
		const existing = doc.objects.get(objNum);
		const shadowed = !current || (existing !== undefined && existing.pos > entry.pos);
		doc.define(objNum, { value, pos: entry.pos, container: num }, !shadowed);
	}
}

/** Every direct stream definition (shadowed ones included) of the given `/Type`. */
function directStreams(
	doc: PdfDocument,
	type: string,
): Array<{ num: number; entry: Entry; value: PdfStream; pos: number }> {
	const out: Array<{ num: number; entry: Entry; value: PdfStream; pos: number }> = [];
	for (const [num, defs] of doc.definitions)
		for (const entry of defs) {
			const { value, pos } = entry;
			if (value instanceof PdfStream && doc.name(value.dict.get("Type")) === type)
				out.push({ num, entry, value, pos });
		}
	return out.sort((a, b) => a.pos - b.pos);
}

export async function expandObjectStreams(doc: PdfDocument): Promise<void> {
	for (const { num, entry } of directStreams(doc, "ObjStm"))
		await expandObjectStream(doc, num, entry);
}

// ---------------------------------------------------------------------------------------------
// Cross-reference (consistency checks only)
// ---------------------------------------------------------------------------------------------

/** Where the cross-reference says an object lives: a file offset or an object stream. */
export type XrefEntry =
	| { readonly kind: "offset"; readonly pos: number }
	| { readonly kind: "compressed"; readonly stream: number };

/** Decoded rows of a cross-reference stream (`entryLength` bytes each); null when unreadable. */
async function xrefStreamData(
	doc: PdfDocument,
	stream: PdfStream,
	entryLength: number,
): Promise<Uint8Array | null> {
	const filterValue = doc.resolve(stream.dict.get("Filter"));
	const filters = Array.isArray(filterValue) ? filterValue : filterValue ? [filterValue] : [];
	const parmsValue = doc.resolve(stream.dict.get("DecodeParms"));
	const parms = doc.dict(Array.isArray(parmsValue) ? parmsValue[filters.length - 1] : parmsValue);
	let data: Uint8Array = doc.bytes.subarray(stream.start, stream.end);
	for (const filter of filters) {
		const next = await doc.applyFilter(doc.name(filter), data);
		if (!next?.complete) return null;
		data = next.data;
	}
	const predictor = doc.num(parms?.get("Predictor")) ?? 1;
	if (predictor < 10) return predictor > 1 ? null : data;
	const columns = doc.num(parms?.get("Columns")) ?? 1;
	return columns === entryLength ? unpredictPngRows(data, columns, 1) : null;
}

/** Big-endian unsigned field of `width` bytes at `at`. */
function field(data: Uint8Array, at: number, width: number): number {
	let v = 0;
	for (let i = 0; i < width; i++) v = v * 256 + (data[at + i] as number);
	return v;
}

/** Records the rows of one `/Index` subsection (`start`, `count`) read from `at`. */
function xrefRows(
	rows: { data: Uint8Array; widths: readonly [number, number, number]; at: number },
	start: number,
	count: number,
	out: Map<number, XrefEntry>,
	max: number,
): void {
	const [w0, w1, w2] = rows.widths;
	const length = w0 + w1 + w2;
	for (let k = 0; k < count && rows.at + length <= rows.data.length && out.size < max; k++) {
		const type = w0 === 0 ? 1 : field(rows.data, rows.at, w0);
		const second = field(rows.data, rows.at + w0, w1);
		if (type === 1) out.set(start + k, { kind: "offset", pos: second });
		else if (type === 2) out.set(start + k, { kind: "compressed", stream: second });
		else out.delete(start + k);
		rows.at += length;
	}
}

/** The entries of a cross-reference stream (ISO 32000-1 §7.5.8). */
async function xrefStreamEntries(
	doc: PdfDocument,
	stream: PdfStream,
	out: Map<number, XrefEntry>,
): Promise<void> {
	const widths = (doc.array(stream.dict.get("W")) ?? []).map((w) => doc.num(w) ?? -1);
	if (widths.length !== 3 || widths.some((w) => w < 0 || w > 8)) return;
	const entryLength = widths.reduce((a, b) => a + b, 0);
	const data = entryLength > 0 ? await xrefStreamData(doc, stream, entryLength) : null;
	if (!data) return;
	const index = (
		doc.array(stream.dict.get("Index")) ?? [0, doc.num(stream.dict.get("Size")) ?? 0]
	).map((v) => doc.num(v) ?? -1);
	const rows = { data, widths: widths as [number, number, number], at: 0 };
	for (let i = 0; i + 1 < index.length; i += 2) {
		const start = index[i] as number;
		if (start >= 0) xrefRows(rows, start, index[i + 1] as number, out, doc.limits.maxObjects);
	}
}

const XREF_SUBSECTION = /[\0\t\n\f\r ]*(\d{1,10})[\0\t ]+(\d{1,10})[\0\t ]*[\r\n]/y;
const XREF_ROW = /[\0\t\n\f\r ]*(\d{1,10})[\0\t ]+\d{1,5}[\0\t ]+([nf])/y;

/** The entries of a classic `xref` table starting at `at` (just after the keyword). */
function xrefTableEntries(doc: PdfDocument, at: number, out: Map<number, XrefEntry>): void {
	const { src } = doc;
	for (;;) {
		XREF_SUBSECTION.lastIndex = at;
		const head = XREF_SUBSECTION.exec(src);
		if (!head) return;
		at = XREF_SUBSECTION.lastIndex;
		const start = Number(head[1]);
		const count = Number(head[2]);
		for (let k = 0; k < count; k++) {
			if (out.size >= doc.limits.maxObjects) return;
			XREF_ROW.lastIndex = at;
			const row = XREF_ROW.exec(src);
			if (!row) return;
			at = XREF_ROW.lastIndex;
			if (row[2] === "n") out.set(start + k, { kind: "offset", pos: Number(row[1]) });
			else out.delete(start + k);
		}
	}
}

/**
 * The cross-reference as an xref-following reader sees it: every classic table and xref
 * stream in file order, later sections overriding earlier ones (incremental updates). Damaged
 * or unreadable sections are skipped; the result is only used to detect inconsistencies.
 */
export async function crossReference(doc: PdfDocument): Promise<Map<number, XrefEntry>> {
	const sections: Array<{ pos: number; read: (out: Map<number, XrefEntry>) => unknown }> = [];
	const table = /(?<![A-Za-z])xref(?=[\0\t\n\f\r ])/g;
	for (let t = table.exec(doc.src); t; t = table.exec(doc.src)) {
		const at = t.index + 4;
		sections.push({ pos: t.index, read: (out) => xrefTableEntries(doc, at, out) });
	}
	for (const { value, pos } of directStreams(doc, "XRef"))
		sections.push({ pos, read: (out) => xrefStreamEntries(doc, value, out) });
	sections.sort((a, b) => a.pos - b.pos);
	const out = new Map<number, XrefEntry>();
	for (const section of sections) await section.read(out);
	return out;
}

/**
 * True when `num` is defined more than once and the definition the cross-reference points to
 * is not the one in effect here (e.g. a redefinition appended after the last xref section,
 * which xref-following readers ignore). A cross-reference that points at no definition at all
 * (a damaged table) is not evidence either way.
 */
export function xrefConflict(doc: PdfDocument, num: number, xref: Map<number, XrefEntry>): boolean {
	const defs = doc.definitions.get(num);
	const entry = xref.get(num);
	if (!defs || defs.length < 2 || !entry) return false;
	const referenced =
		entry.kind === "compressed"
			? defs.find((d) => d.container === entry.stream)
			: defs.find(
					(d) =>
						d.container === undefined &&
						d.pos >= entry.pos &&
						d.pos - entry.pos <= 16 &&
						!doc.src.slice(entry.pos, d.pos).trim(),
				);
	return referenced !== undefined && referenced !== doc.objects.get(num);
}
