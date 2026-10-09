/**
 * Word 97-2003 (.doc/.dot) text ([MS-DOC]): the `WordDocument` stream's FIB locates the CLX in
 * the `0Table`/`1Table` stream; its piece table (PlcPcd) maps every character position of the
 * document to either a "compressed" 8-bit (windows-1252) run or a UTF-16LE run in the
 * `WordDocument` stream. All pieces are read, so the main text, footnotes, headers/footers,
 * comments, endnotes and text boxes (all part of the same CP space) are covered, including
 * field codes (e.g. `HYPERLINK "mailto:..."`).
 *
 * Encrypted or XOR-obfuscated files are refused; Word 6/95 files (nFib < 193) are reported as
 * unsupported; a FIB or piece table that does not fit its stream makes the extraction partial.
 */
import { DocumentRefused } from "../office/ooxml.js";
import { type CfbEntry, type CompoundFile, childEntry } from "./cfb.js";
import { Bytes, type Collector, decodeCp1252, decodeUtf16le } from "./text.js";

const WORD_IDENT = 0xa5ec;
const NFIB_WORD97 = 0x00c1;
const F_HAS_PIC = 0x0008;
const F_ENCRYPTED = 0x0100;
const F_WHICH_TBL_STM = 0x0200;
const F_OBFUSCATED = 0x8000;
/** FibRgFcLcb97 pair indexes. */
const FC_CLX = 33;
const FC_DGG_INFO = 50;

interface Fib {
	readonly tableStream: string;
	readonly fcClx: number;
	readonly lcbClx: number;
	readonly pictures: boolean;
}

function readFib(doc: Bytes): Fib | "unsupported" | null {
	if (doc.length < 34 || doc.u16(0) !== WORD_IDENT) return null;
	if (doc.u16(2) < NFIB_WORD97) return "unsupported";
	const flags = doc.u16(0x0a);
	if (flags & (F_ENCRYPTED | F_OBFUSCATED)) throw new DocumentRefused(["DOCUMENT_ENCRYPTED"]);
	const csw = doc.u16(32);
	const cslwAt = 34 + csw * 2;
	const cslw = doc.u16(cslwAt);
	const cbAt = cslwAt + 2 + cslw * 4;
	const pairs = doc.u16(cbAt);
	const blob = cbAt + 2;
	if (pairs <= FC_CLX) return null;
	const pair = (index: number): [number, number] =>
		index < pairs ? [doc.u32(blob + index * 8), doc.u32(blob + index * 8 + 4)] : [0, 0];
	const [fcClx, lcbClx] = pair(FC_CLX);
	const [, lcbDgg] = pair(FC_DGG_INFO);
	return {
		tableStream: flags & F_WHICH_TBL_STM ? "1Table" : "0Table",
		fcClx,
		lcbClx,
		pictures: (flags & F_HAS_PIC) !== 0 || lcbDgg > 0,
	};
}

/** The PlcPcd inside the CLX (skipping any leading Prc property records). */
function findPlcPcd(table: Bytes, fc: number, lcb: number): { at: number; size: number } | null {
	let pos = fc;
	const end = fc + lcb;
	if (end > table.length) return null;
	while (pos < end) {
		const clxt = table.u8(pos);
		if (clxt === 0x01) {
			const cb = table.i16(pos + 1);
			if (cb < 0) return null;
			pos += 3 + cb;
		} else if (clxt === 0x02) {
			const size = table.u32(pos + 1);
			if (pos + 5 + size > end) return null;
			return { at: pos + 5, size };
		} else return null;
	}
	return null;
}

/** Extracts the text of a Word binary document stored in `storage`. */
export function extractWord(cfb: CompoundFile, storage: CfbEntry, out: Collector): void {
	const docEntry = childEntry(storage, "WordDocument");
	if (!docEntry || docEntry.type !== "stream") return out.gap("LEGACY_OFFICE_PARTIAL");
	const doc = new Bytes(cfb.read(docEntry));
	const fib = guarded(out, () => readFib(doc));
	if (fib === "unsupported") return out.gap("LEGACY_OFFICE_UNSUPPORTED");
	if (!fib) return out.gap("LEGACY_OFFICE_PARTIAL");
	const dataStream = childEntry(storage, "Data");
	if (fib.pictures || (dataStream && dataStream.size > 0)) out.images = true;
	const tableEntry = childEntry(storage, fib.tableStream);
	if (!tableEntry || tableEntry.type !== "stream" || fib.lcbClx === 0)
		return out.gap("LEGACY_OFFICE_PARTIAL");
	const table = new Bytes(cfb.read(tableEntry));
	const text = guarded(out, () => readPieces(doc, table, fib, out));
	if (text) out.addText(text);
}

/** One piece's characters; a piece outside the stream is skipped (the result is partial). */
function pieceText(doc: Bytes, raw: number, count: number, out: Collector): string {
	const compressed = (raw & 0x40000000) !== 0;
	const fc = raw & 0x3fffffff;
	try {
		return compressed
			? decodeCp1252(doc.slice(fc >>> 1, count))
			: decodeUtf16le(doc.slice(fc, count * 2));
	} catch (error) {
		if (!(error instanceof RangeError)) throw error;
		out.gap("LEGACY_OFFICE_PARTIAL");
		return "";
	}
}

/** The document text, piece by piece in CP order (stops, partial, at an inconsistency). */
function readPieces(doc: Bytes, table: Bytes, fib: Fib, out: Collector): string {
	const plc = findPlcPcd(table, fib.fcClx, fib.lcbClx);
	if (!plc || plc.size < 4 || (plc.size - 4) % 12 !== 0) {
		out.gap("LEGACY_OFFICE_PARTIAL");
		return "";
	}
	const pieces = (plc.size - 4) / 12;
	const pcdBase = plc.at + 4 * (pieces + 1);
	let text = "";
	let previous = 0;
	for (let i = 0; i < pieces; i++) {
		const cpStart = table.u32(plc.at + i * 4);
		const cpEnd = table.u32(plc.at + (i + 1) * 4);
		const count = cpEnd - cpStart;
		if (count < 0 || cpStart < previous || text.length + count > out.limits.maxChars) {
			out.gap("LEGACY_OFFICE_PARTIAL");
			break;
		}
		previous = cpEnd;
		text += pieceText(doc, table.u32(pcdBase + i * 8 + 2), count, out);
		if (i % 256 === 255) out.checkDeadline();
	}
	return text;
}

/** Runs `read`, turning an out-of-range read into a partial extraction (null). */
function guarded<T>(out: Collector, read: () => T): T | null {
	try {
		return read();
	} catch (error) {
		if (!(error instanceof RangeError)) throw error;
		out.gap("LEGACY_OFFICE_PARTIAL");
		return null;
	}
}
