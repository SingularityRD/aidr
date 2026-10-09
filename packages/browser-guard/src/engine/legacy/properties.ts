/**
 * Document properties of a compound file ([MS-OLEPS] property set streams
 * `\u0005SummaryInformation` and `\u0005DocumentSummaryInformation`): title, subject, author,
 * keywords, comments, last author, company, manager, custom string properties and the
 * "titles of parts" list. Only string values (VT_LPSTR, VT_LPWSTR and vectors of them) are
 * read; a property set that does not fit its stream makes the extraction partial.
 */
import type { CfbEntry, CompoundFile } from "./cfb.js";
import { Bytes, type Collector, decodeCodePage, decodeUtf16le } from "./text.js";

const VT_I2 = 0x0002;
const VT_LPSTR = 0x001e;
const VT_LPWSTR = 0x001f;
const VT_VECTOR = 0x1000;
const PID_CODEPAGE = 0x0001;
const PID_DICTIONARY = 0x0000;
const MAX_PROPERTIES = 1024;
const MAX_VECTOR = 4096;

const PROPERTY_STREAMS = ["\u0005SummaryInformation", "\u0005DocumentSummaryInformation"];

/** One string value at `at`; returns it and the offset after it. */
function readString(
	set: Bytes,
	at: number,
	type: number,
	codePage: number,
): { text: string; next: number } {
	const count = set.u32(at);
	const width = type === VT_LPWSTR ? 2 : 1;
	const bytes = set.slice(at + 4, count * width);
	const end = at + 4 + count * width;
	return {
		text: width === 2 ? decodeUtf16le(bytes) : decodeCodePage(bytes, codePage),
		// Values are padded to a multiple of 4 bytes.
		next: end + ((4 - (end % 4)) % 4),
	};
}

function readSet(set: Bytes, out: Collector): void {
	const properties = set.u32(4);
	if (properties > MAX_PROPERTIES) throw new RangeError("too many properties");
	const offsets: Array<[number, number]> = [];
	for (let i = 0; i < properties; i++) offsets.push([set.u32(8 + i * 8), set.u32(8 + i * 8 + 4)]);
	let codePage = 1252;
	for (const [id, offset] of offsets)
		if (id === PID_CODEPAGE && set.u16(offset) === VT_I2) codePage = set.u16(offset + 4);
	for (const [id, offset] of offsets)
		if (id !== PID_DICTIONARY && id !== PID_CODEPAGE) readValue(set, offset, codePage, out);
}

/** One property value: a string or a vector of strings is collected, other types skipped. */
function readValue(set: Bytes, offset: number, codePage: number, out: Collector): void {
	const type = set.u16(offset);
	const base = type & ~VT_VECTOR;
	if (base !== VT_LPSTR && base !== VT_LPWSTR) return;
	if (!(type & VT_VECTOR)) {
		out.add(readString(set, offset + 4, base, codePage).text);
		return;
	}
	const n = set.u32(offset + 4);
	if (n > MAX_VECTOR) throw new RangeError("vector too long");
	let at = offset + 8;
	for (let i = 0; i < n; i++) {
		const { text, next } = readString(set, at, base, codePage);
		out.add(text);
		at = next;
	}
}

/** Reads every property set of one property set stream. */
function readStream(data: Uint8Array, out: Collector): void {
	const stream = new Bytes(data);
	if (stream.u16(0) !== 0xfffe) throw new RangeError("bad byte order");
	const sets = stream.u32(24);
	if (sets > 2) throw new RangeError("too many property sets");
	for (let i = 0; i < sets; i++) {
		const offset = stream.u32(28 + i * 20 + 16);
		const size = stream.u32(offset);
		readSet(new Bytes(stream.slice(offset, size)), out);
	}
}

/** Collects the string properties of `storage`'s property set streams. */
export function extractProperties(cfb: CompoundFile, storage: CfbEntry, out: Collector): void {
	for (const name of PROPERTY_STREAMS) {
		const entry = storage.children.find((c) => c.name === name);
		if (!entry || entry.type !== "stream" || entry.size === 0) continue;
		try {
			readStream(cfb.read(entry), out);
		} catch (error) {
			if (!(error instanceof RangeError)) throw error;
			out.gap("LEGACY_OFFICE_PARTIAL");
		}
	}
}
