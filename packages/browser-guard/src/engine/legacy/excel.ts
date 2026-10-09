/**
 * Excel 97-2003 (.xls/.xlt/.xla) text ([MS-XLS], BIFF8) from the `Workbook` stream.
 *
 * Read: the shared string table (SST, across CONTINUE records, rich-text runs and phonetic
 * blocks skipped), cells (LABELSST, LABEL, NUMBER, RK, MULRK, FORMULA cached numbers and
 * strings), sheet names, header/footer text, comment authors and comment / text-box text
 * (TXO + CONTINUE), external-workbook paths and sheet names (SUPBOOK) and hyperlink targets
 * (HLINK). Like the XLSX handler, the first row of each sheet supplies column headers:
 * data cells are scanned with their header as context (a sensitive header such as "TCKN"
 * makes the whole cell a finding). Shared strings no cell refers to are scanned on their own.
 *
 * Refused: FILEPASS (encrypted / password protected) and Excel 4.0 macro sheets. BIFF5 and
 * older (`Book` stream, or a BOF version below BIFF8) is unsupported. Pivot caches
 * (`_SX_DB_CUR`) are not parsed and make the extraction partial; a drawing group with a BLIP
 * store marks the workbook as containing pictures (not inspected).
 */
import { DocumentRefused } from "../office/ooxml.js";
import { type CfbEntry, type CompoundFile, childEntry } from "./cfb.js";
import { Bytes, type Collector, decodeLatin1, decodeUtf16le } from "./text.js";

const BOF = 0x0809;
const EOF = 0x000a;
const CONTINUE = 0x003c;
const FILEPASS = 0x002f;
const SST = 0x00fc;
const LABELSST = 0x00fd;
const LABEL = 0x0204;
const NUMBER = 0x0203;
const RK = 0x027e;
const MULRK = 0x00bd;
const FORMULA = 0x0006;
const STRING = 0x0207;
const HEADER = 0x0014;
const FOOTER = 0x0015;
const BOUNDSHEET = 0x0085;
const NOTE = 0x001c;
const TXO = 0x01b6;
const HLINK = 0x01b8;
const SUPBOOK = 0x01ae;
const MSODRAWINGGROUP = 0x00eb;
const BIFF8 = 0x0600;
const DT_MACRO_SHEET = 0x0040;

interface BiffRecord {
	readonly type: number;
	readonly data: Uint8Array;
	readonly continues: Uint8Array[];
}

/** Splits the stream into records, attaching each record's CONTINUE records to it. */
function records(stream: Uint8Array, out: Collector): BiffRecord[] {
	const view = new Bytes(stream);
	const list: BiffRecord[] = [];
	let pos = 0;
	while (pos + 4 <= stream.length) {
		const type = view.u16(pos);
		const length = view.u16(pos + 2);
		if (pos + 4 + length > stream.length) {
			out.gap("LEGACY_OFFICE_PARTIAL");
			break;
		}
		const data = stream.subarray(pos + 4, pos + 4 + length);
		pos += 4 + length;
		const last = list[list.length - 1];
		if (type === CONTINUE && last) last.continues.push(data);
		else list.push({ type, data, continues: [] });
		// Stream padding after the final EOF is common: stop at a zero record type.
		if (type === 0 && length === 0) break;
	}
	return list;
}

/** Reads across a record and its CONTINUE records, following BIFF8's string-split rule. */
class Continued {
	private part = 0;
	private pos = 0;

	constructor(private readonly parts: readonly Uint8Array[]) {}

	private current(): Uint8Array {
		let data = this.parts[this.part];
		while (data && this.pos >= data.length) {
			this.part++;
			this.pos = 0;
			data = this.parts[this.part];
		}
		if (!data) throw new RangeError("out of range");
		return data;
	}

	u8(): number {
		const data = this.current();
		return data[this.pos++] as number;
	}

	u16(): number {
		return this.u8() | (this.u8() << 8);
	}

	u32(): number {
		return (this.u16() | (this.u16() << 16)) >>> 0;
	}

	skip(n: number): void {
		let left = n;
		while (left > 0) {
			const data = this.current();
			const take = Math.min(left, data.length - this.pos);
			this.pos += take;
			left -= take;
		}
	}

	/** `cch` characters; a split at a record boundary re-reads the high-byte flag. */
	chars(cch: number, highByte: boolean): string {
		let out = "";
		let high = highByte;
		while (out.length < cch) {
			const data = this.parts[this.part];
			if (!data) throw new RangeError("out of range");
			if (this.pos >= data.length) {
				// The characters continue in the next CONTINUE record, behind a new flag byte.
				this.part++;
				this.pos = 0;
				const next = this.parts[this.part];
				if (!next || next.length === 0) throw new RangeError("out of range");
				high = ((next[this.pos++] as number) & 0x01) !== 0;
				continue;
			}
			const width = high ? 2 : 1;
			const available = Math.floor((data.length - this.pos) / width);
			if (available === 0) throw new RangeError("split character");
			const take = Math.min(available, cch - out.length);
			const bytes = data.subarray(this.pos, this.pos + take * width);
			out += high ? decodeUtf16le(bytes) : decodeLatin1(bytes);
			this.pos += take * width;
		}
		return out;
	}

	/** XLUnicodeString: cch (u16), flags, characters. */
	unicodeString(): string {
		const cch = this.u16();
		return this.chars(cch, (this.u8() & 0x01) !== 0);
	}

	/** XLUnicodeRichExtendedString (shared string table entry). */
	richString(): string {
		const cch = this.u16();
		const flags = this.u8();
		const runs = flags & 0x08 ? this.u16() : 0;
		const ext = flags & 0x04 ? this.u32() : 0;
		const text = this.chars(cch, (flags & 0x01) !== 0);
		this.skip(runs * 4);
		this.skip(ext);
		return text;
	}
}

function formatNumber(n: number): string {
	if (!Number.isFinite(n)) return "";
	return Number.isInteger(n) && Math.abs(n) < 1e21 ? n.toFixed(0) : String(n);
}

function rkValue(rk: number): number {
	let n: number;
	if (rk & 0x02) n = rk >> 2;
	else {
		const buf = new DataView(new ArrayBuffer(8));
		buf.setUint32(4, rk & 0xfffffffc, true);
		n = buf.getFloat64(0, true);
	}
	return rk & 0x01 ? n / 100 : n;
}

/** UTF-16LE runs of printable text (hyperlink monikers carry their URLs this way). */
function utf16Runs(bytes: Uint8Array): string[] {
	const runs: string[] = [];
	for (const parity of [0, 1]) {
		let run = "";
		for (let i = parity; i + 1 < bytes.length; i += 2) {
			const code = (bytes[i] as number) | ((bytes[i + 1] as number) << 8);
			const printable = code >= 0x20 && code !== 0x7f && !(code >= 0xd800 && code <= 0xdfff);
			if (printable && code < 0xfffe) run += String.fromCharCode(code);
			else {
				if (run.length >= 4) runs.push(run);
				run = "";
			}
		}
		if (run.length >= 4) runs.push(run);
	}
	return runs;
}

/** True when an OfficeArt record tree contains a BLIP store entry (FBSE: a picture). */
function hasBlip(data: Uint8Array, depth = 0): boolean {
	const view = new Bytes(data);
	let pos = 0;
	while (pos + 8 <= data.length) {
		const ver = view.u16(pos) & 0x0f;
		const type = view.u16(pos + 2);
		const length = view.u32(pos + 4);
		const end = Math.min(data.length, pos + 8 + length);
		if (type === 0xf007) return true;
		if (ver === 0x0f && depth < 16 && hasBlip(data.subarray(pos + 8, end), depth + 1)) return true;
		pos = end;
	}
	return false;
}

interface Sheet {
	firstRow: number | null;
	readonly headers: Map<number, string>;
}

class Workbook {
	private readonly sst: string[] = [];
	private readonly referenced = new Set<number>();
	private sheet: Sheet | null = null;
	private pendingFormula: { row: number; col: number } | null = null;

	constructor(private readonly out: Collector) {}

	private cell(row: number, col: number, value: string): void {
		const sheet = this.sheet;
		if (!sheet) return this.out.add(value);
		if (sheet.firstRow === null) sheet.firstRow = row;
		if (row === sheet.firstRow) {
			sheet.headers.set(col, value);
			return this.out.add(value);
		}
		this.out.add(value, sheet.headers.get(col) ?? "");
	}

	private readSst(rec: BiffRecord): void {
		const reader = new Continued([rec.data, ...rec.continues]);
		reader.u32();
		const unique = reader.u32();
		for (let i = 0; i < unique; i++) {
			this.sst.push(reader.richString());
			if (i % 4096 === 4095) this.out.checkDeadline();
		}
	}

	private readTxo(rec: BiffRecord): void {
		const view = new Bytes(rec.data);
		const cch = view.u16(10);
		if (cch === 0 || rec.continues.length === 0) return;
		const reader = new Continued(rec.continues);
		const high = (reader.u8() & 0x01) !== 0;
		this.out.add(reader.chars(cch, high));
	}

	private readSupbook(rec: BiffRecord): void {
		const reader = new Continued([rec.data, ...rec.continues]);
		const sheets = reader.u16();
		const cch = reader.u16();
		if (cch === 0x0401 || cch === 0x3a01) return;
		this.out.add(reader.chars(cch, (reader.u8() & 0x01) !== 0));
		for (let i = 0; i < sheets; i++) this.out.add(reader.unicodeString());
	}

	record(rec: BiffRecord): void {
		const view = new Bytes(rec.data);
		switch (rec.type) {
			case FILEPASS:
				throw new DocumentRefused(["DOCUMENT_ENCRYPTED"]);
			case BOF: {
				if (view.u16(0) !== BIFF8) {
					this.out.gap("LEGACY_OFFICE_UNSUPPORTED");
					return;
				}
				const dt = view.u16(2);
				if (dt === DT_MACRO_SHEET) throw new DocumentRefused(["DOCUMENT_MACROS"]);
				this.sheet = dt === 0x0005 ? null : { firstRow: null, headers: new Map() };
				return;
			}
			case EOF:
				this.sheet = null;
				return;
			case SST:
				return this.readSst(rec);
			case LABELSST: {
				const index = view.u32(6);
				this.referenced.add(index);
				const text = this.sst[index];
				if (text === undefined) return this.out.gap("LEGACY_OFFICE_PARTIAL");
				return this.cell(view.u16(0), view.u16(2), text);
			}
			case LABEL:
				return this.cell(
					view.u16(0),
					view.u16(2),
					new Continued([rec.data.subarray(6), ...rec.continues]).unicodeString(),
				);
			case NUMBER:
				return this.cell(view.u16(0), view.u16(2), formatNumber(view.f64(6)));
			case RK:
				return this.cell(view.u16(0), view.u16(2), formatNumber(rkValue(view.u32(6))));
			case MULRK: {
				const row = view.u16(0);
				const first = view.u16(2);
				const count = Math.floor((rec.data.length - 6) / 6);
				for (let i = 0; i < count; i++)
					this.cell(row, first + i, formatNumber(rkValue(view.u32(4 + i * 6 + 2))));
				return;
			}
			case FORMULA: {
				const row = view.u16(0);
				const col = view.u16(2);
				if (view.u16(12) !== 0xffff) return this.cell(row, col, formatNumber(view.f64(6)));
				if (view.u8(6) === 0x00) this.pendingFormula = { row, col };
				return;
			}
			case STRING: {
				const target = this.pendingFormula;
				this.pendingFormula = null;
				const text = new Continued([rec.data, ...rec.continues]).unicodeString();
				return target ? this.cell(target.row, target.col, text) : this.out.add(text);
			}
			case HEADER:
			case FOOTER:
				if (rec.data.length > 0)
					this.out.add(new Continued([rec.data, ...rec.continues]).unicodeString());
				return;
			case BOUNDSHEET: {
				if (view.u8(5) === 0x01 || view.u8(5) === 0x06)
					throw new DocumentRefused(["DOCUMENT_MACROS"]);
				const cch = view.u8(6);
				this.out.add(new Continued([rec.data.subarray(8)]).chars(cch, (view.u8(7) & 1) !== 0));
				return;
			}
			case NOTE:
				if (this.sheet && rec.data.length > 8)
					this.out.add(new Continued([rec.data.subarray(8)]).unicodeString());
				return;
			case TXO:
				return this.readTxo(rec);
			case SUPBOOK:
				return this.readSupbook(rec);
			case HLINK:
				for (const run of utf16Runs(rec.data.subarray(8))) this.out.add(run);
				return;
			case MSODRAWINGGROUP: {
				const total = rec.continues.reduce((n, c) => n + c.length, rec.data.length);
				const all = new Uint8Array(total);
				let offset = 0;
				for (const part of [rec.data, ...rec.continues]) {
					all.set(part, offset);
					offset += part.length;
				}
				if (hasBlip(all)) this.out.images = true;
				return;
			}
			default:
				return;
		}
	}

	/** Shared strings that no LABELSST cell used (they are still in the file). */
	finish(): void {
		this.sst.forEach((text, index) => {
			if (!this.referenced.has(index)) this.out.add(text);
		});
	}
}

/** Extracts the text of an Excel BIFF8 workbook stored in `storage`. */
export function extractExcel(cfb: CompoundFile, storage: CfbEntry, out: Collector): void {
	const entry = childEntry(storage, "Workbook");
	if (!entry || entry.type !== "stream") return out.gap("LEGACY_OFFICE_UNSUPPORTED");
	const pivot = childEntry(storage, "_SX_DB_CUR");
	if (pivot && pivot.children.length > 0) out.gap("LEGACY_OFFICE_PARTIAL");
	const list = records(cfb.read(entry), out);
	const first = list[0];
	if (!first || first.type !== BOF) return out.gap("LEGACY_OFFICE_UNSUPPORTED");
	const book = new Workbook(out);
	for (let i = 0; i < list.length; i++) {
		try {
			book.record(list[i] as BiffRecord);
		} catch (error) {
			// A record that does not fit its declared layout: skipped, extraction partial.
			if (!(error instanceof RangeError)) throw error;
			out.gap("LEGACY_OFFICE_PARTIAL");
		}
		if (i % 4096 === 4095) out.checkDeadline();
	}
	book.finish();
}
