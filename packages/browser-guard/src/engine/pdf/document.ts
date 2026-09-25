/**
 * PDF file structure: object table, trailers and stream decoding.
 *
 * Parsing is xref-independent (the approach PDF readers use to recover damaged files): the
 * file is scanned once for `n g obj` definitions (later definitions win, which also covers
 * incremental updates) and object streams (`/Type /ObjStm`) are expanded. Trailers come from
 * `trailer` dictionaries and cross-reference streams (`/Type /XRef`).
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

interface Entry {
	readonly value: PdfValue;
	readonly pos: number;
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
const FILTER_ALIASES: Readonly<Record<string, string>> = {
	Fl: "FlateDecode",
	LZW: "LZWDecode",
	AHx: "ASCIIHexDecode",
	A85: "ASCII85Decode",
	RL: "RunLengthDecode",
};

export class PdfDocument {
	readonly objects = new Map<number, Entry>();
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

	budget(): number {
		return Math.min(this.limits.maxStreamBytes, this.limits.maxInflatedTotal - this.inflated);
	}

	private async applyFilter(name: string | undefined, data: Uint8Array): Promise<Decoded | null> {
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
		doc.objects.set(Number.parseInt(m[1] as string, 10), { value, pos: m.index });
	return Math.max(next, m.index + m[0].length);
}

export function parseObjects(doc: PdfDocument): void {
	const { src } = doc;
	const re = new RegExp(OBJ_RE.source, "g");
	for (let m = re.exec(src); m; m = re.exec(src)) {
		if (doc.objects.size >= doc.limits.maxObjects) {
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

/** Adds the objects of one object stream (unless a later direct definition exists). */
async function expandObjectStream(doc: PdfDocument, stream: PdfStream, pos: number): Promise<void> {
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
		const objNum = header.readObject();
		const offset = header.readObject();
		if (typeof objNum !== "number" || typeof offset !== "number") return;
		const existing = doc.objects.get(objNum);
		if (existing && existing.pos > pos) continue;
		const value = new Lexer(text, first + offset).readObject();
		if (value !== undefined) doc.objects.set(objNum, { value, pos });
	}
}

export async function expandObjectStreams(doc: PdfDocument): Promise<void> {
	const streams = [...doc.objects.values()]
		.filter((e) => e.value instanceof PdfStream && doc.name(e.value.dict.get("Type")) === "ObjStm")
		.sort((a, b) => a.pos - b.pos);
	for (const entry of streams) await expandObjectStream(doc, entry.value as PdfStream, entry.pos);
}
