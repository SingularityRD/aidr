/**
 * PowerPoint 97-2003 (.ppt/.pps/.pot/.ppa) text ([MS-PPT]) from the `PowerPoint Document`
 * stream: the record tree is walked (containers are entered, atoms read) and every
 * TextCharsAtom (UTF-16LE), TextBytesAtom (8-bit) and CString (UTF-16LE: comments and their
 * authors, hyperlink targets, names...) is collected. Slides, notes, masters, handouts and
 * the outline text in SlideListWithText all live in this stream; older copies of edited text
 * kept by incremental saves are read too (scanning more, never less).
 *
 * Refused: CryptSession10Container (encrypted) and a VBAInfoContainer whose atom has fHasMacros. Embedded OLE
 * objects (ExOleObjStg, optionally zlib-compressed) are returned to the caller, which opens
 * and scans them as compound files. A `Pictures` stream marks the deck as containing pictures.
 */
import { DocumentRefused } from "../office/ooxml.js";
import { type CfbEntry, type CompoundFile, childEntry } from "./cfb.js";
import { Bytes, type Collector, decodeLatin1, decodeUtf16le } from "./text.js";

const TEXT_CHARS_ATOM = 0x0fa0;
const TEXT_BYTES_ATOM = 0x0fa8;
const CSTRING = 0x0fba;
const EX_OLE_OBJ_STG = 0x1011;
const VBA_INFO = 0x03ff;
const VBA_INFO_ATOM = 0x0400;
const CRYPT_SESSION = 0x2f14;
const MAX_DEPTH = 32;

/** An embedded OLE object: the bytes of a compound file, possibly zlib-compressed. */
export interface PptEmbedded {
	readonly compressed: boolean;
	readonly data: Uint8Array;
}

/**
 * VBAInfoContainer: writers (LibreOffice among them) may emit one without a project; only a
 * VBAInfoAtom with fHasMacros set (or one that cannot be read) counts as macros.
 */
function hasMacros(stream: Bytes, start: number, end: number): boolean {
	let pos = start;
	while (pos + 8 <= end) {
		const type = stream.u16(pos + 2);
		const length = stream.u32(pos + 4);
		if (type === VBA_INFO_ATOM) return length < 8 || stream.u32(pos + 12) !== 0;
		pos += 8 + length;
	}
	return true;
}

class Walker {
	readonly embedded: PptEmbedded[] = [];
	private count = 0;

	constructor(
		private readonly stream: Bytes,
		private readonly out: Collector,
	) {}

	/** Walks the records in [start, end); a record that overruns its parent stops the level. */
	walk(start: number, end: number, depth: number): void {
		const { stream } = this;
		let pos = start;
		while (pos + 8 <= end) {
			const verInstance = stream.u16(pos);
			const type = stream.u16(pos + 2);
			const body = pos + 8;
			const bodyEnd = body + stream.u32(pos + 4);
			if (bodyEnd > end) return this.out.gap("LEGACY_OFFICE_PARTIAL");
			if ((verInstance & 0x0f) === 0x0f) this.container(type, body, bodyEnd, depth);
			else this.atom(verInstance, type, body, bodyEnd);
			pos = bodyEnd;
			if (++this.count % 4096 === 0) this.out.checkDeadline();
		}
	}

	private container(type: number, body: number, end: number, depth: number): void {
		if (type === VBA_INFO && hasMacros(this.stream, body, end))
			throw new DocumentRefused(["DOCUMENT_MACROS"]);
		if (type === CRYPT_SESSION) throw new DocumentRefused(["DOCUMENT_ENCRYPTED"]);
		if (depth >= MAX_DEPTH) this.out.gap("LEGACY_OFFICE_PARTIAL");
		else this.walk(body, end, depth + 1);
	}

	private atom(verInstance: number, type: number, body: number, end: number): void {
		const data = () => this.stream.slice(body, end - body);
		if (type === TEXT_CHARS_ATOM || type === CSTRING) this.out.add(decodeUtf16le(data()));
		else if (type === TEXT_BYTES_ATOM) this.out.add(decodeLatin1(data()));
		else if (type === EX_OLE_OBJ_STG)
			this.embedded.push({ compressed: verInstance >> 4 === 1, data: data() });
	}
}

/** Extracts the text of a PowerPoint binary deck; returns its embedded OLE objects. */
export function extractPowerPoint(
	cfb: CompoundFile,
	storage: CfbEntry,
	out: Collector,
): PptEmbedded[] {
	const entry = childEntry(storage, "PowerPoint Document");
	if (!entry || entry.type !== "stream") {
		out.gap("LEGACY_OFFICE_UNSUPPORTED");
		return [];
	}
	const pictures = childEntry(storage, "Pictures");
	if (pictures && pictures.size > 0) out.images = true;
	const stream = new Bytes(cfb.read(entry));
	const walker = new Walker(stream, out);
	walker.walk(0, stream.length, 0);
	return walker.embedded;
}
