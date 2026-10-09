/**
 * Builders for small synthetic legacy Office files (OLE2 compound files) used by the tests:
 * a minimal CFB writer (version 3, 512-byte sectors, mini stream for streams under 4096
 * bytes), plus Word (FIB + piece table), Excel (BIFF8 records) and PowerPoint (record tree)
 * streams and a SummaryInformation property set. All content is synthetic test data.
 */

export interface CfbNode {
	readonly name: string;
	/** Stream content; omit (and give `children`) for a storage. */
	readonly data?: Uint8Array;
	readonly children?: readonly CfbNode[];
}

export interface CfbLayout {
	/** Byte offset of the FAT (its first sector). */
	readonly fatOffset: number;
	/** Byte offset of the directory (its first sector). */
	readonly dirOffset: number;
	/** First regular sector of each large (>= 4096 bytes) stream, by name. */
	readonly largeStart: ReadonlyMap<string, number>;
	readonly sectorSize: 512;
}

const SECTOR = 512;
const MINI = 64;
const CUTOFF = 4096;
const END = 0xfffffffe;
const FREE = 0xffffffff;
const FATSECT = 0xfffffffd;
const NONE = 0xffffffff;

class Out {
	private chunks: number[] = [];

	get length(): number {
		return this.chunks.length;
	}

	u8(v: number): this {
		this.chunks.push(v & 0xff);
		return this;
	}

	u16(v: number): this {
		return this.u8(v).u8(v >> 8);
	}

	u32(v: number): this {
		return this.u16(v & 0xffff).u16(v >>> 16);
	}

	i16(v: number): this {
		return this.u16(v < 0 ? v + 0x10000 : v);
	}

	f64(v: number): this {
		const b = new DataView(new ArrayBuffer(8));
		b.setFloat64(0, v, true);
		for (let i = 0; i < 8; i++) this.u8(b.getUint8(i));
		return this;
	}

	bytes(data: ArrayLike<number>): this {
		for (let i = 0; i < data.length; i++) this.u8(data[i] as number);
		return this;
	}

	utf16(s: string): this {
		for (let i = 0; i < s.length; i++) this.u16(s.charCodeAt(i));
		return this;
	}

	latin1(s: string): this {
		for (let i = 0; i < s.length; i++) this.u8(s.charCodeAt(i));
		return this;
	}

	pad(to: number): this {
		while (this.chunks.length < to) this.u8(0);
		return this;
	}

	done(): Uint8Array {
		return Uint8Array.from(this.chunks);
	}
}

export const out = (): Out => new Out();

interface FlatEntry {
	readonly name: string;
	readonly type: 1 | 2 | 5;
	readonly data: Uint8Array;
	child: number;
	right: number;
	start: number;
	size: number;
}

/** Writes a compound file holding `nodes` under the root entry. */
export function buildCfb(nodes: readonly CfbNode[]): { bytes: Uint8Array; layout: CfbLayout } {
	const entries: FlatEntry[] = [
		{
			name: "Root Entry",
			type: 5,
			data: new Uint8Array(0),
			child: NONE,
			right: NONE,
			start: END,
			size: 0,
		},
	];
	const add = (list: readonly CfbNode[]): number => {
		let first = NONE;
		let previous: FlatEntry | null = null;
		for (const node of list) {
			const index = entries.length;
			const entry: FlatEntry = {
				name: node.name,
				type: node.data ? 2 : 1,
				data: node.data ?? new Uint8Array(0),
				child: NONE,
				right: NONE,
				start: END,
				size: node.data?.length ?? 0,
			};
			entries.push(entry);
			if (node.children) entry.child = add(node.children);
			if (previous) previous.right = index;
			else first = index;
			previous = entry;
		}
		return first;
	};
	(entries[0] as FlatEntry).child = add(nodes);

	// Mini stream: streams under the cutoff, 64-byte mini sectors.
	const mini = new Out();
	const miniFat: number[] = [];
	for (const e of entries) {
		if (e.type !== 2 || e.size === 0 || e.size >= CUTOFF) continue;
		e.start = mini.length / MINI;
		const sectors = Math.ceil(e.size / MINI);
		for (let i = 0; i < sectors; i++) miniFat.push(i === sectors - 1 ? END : e.start + i + 1);
		mini.bytes(e.data).pad(mini.length + ((MINI - (e.size % MINI)) % MINI));
	}
	const miniBytes = mini.done();

	const sectorsFor = (n: number) => Math.ceil(n / SECTOR);
	const dirSectors = sectorsFor(entries.length * 128);
	const miniFatSectors = sectorsFor(miniFat.length * 4);
	const miniStreamSectors = sectorsFor(miniBytes.length);
	const large = entries.filter((e) => e.type === 2 && e.size >= CUTOFF);
	const largeSectors = large.reduce((n, e) => n + sectorsFor(e.size), 0);
	const payload = dirSectors + miniFatSectors + miniStreamSectors + largeSectors;
	let fatSectors = 1;
	while (fatSectors * 128 < fatSectors + payload) fatSectors++;

	const fat: number[] = [];
	const chain = (count: number): number => {
		if (count === 0) return END;
		const start = fat.length;
		for (let i = 0; i < count; i++) fat.push(i === count - 1 ? END : start + i + 1);
		return start;
	};
	for (let i = 0; i < fatSectors; i++) fat.push(FATSECT);
	const dirStart = chain(dirSectors);
	const miniFatStart = chain(miniFatSectors);
	const miniStreamStart = chain(miniStreamSectors);
	const largeStart = new Map<string, number>();
	for (const e of large) {
		e.start = chain(sectorsFor(e.size));
		largeStart.set(e.name, e.start);
	}
	const root = entries[0] as FlatEntry;
	root.start = miniBytes.length ? miniStreamStart : END;
	root.size = miniBytes.length;
	while (fat.length < fatSectors * 128) fat.push(FREE);

	const file = new Out();
	file.bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).pad(0x18);
	file.u16(0x3e).u16(3).u16(0xfffe).u16(9).u16(6).pad(0x2c);
	file.u32(fatSectors).u32(dirStart).u32(0).u32(CUTOFF);
	file.u32(miniFat.length ? miniFatStart : END).u32(miniFatSectors);
	file.u32(END).u32(0);
	for (let i = 0; i < 109; i++) file.u32(i < fatSectors ? i : FREE);
	for (const word of fat) file.u32(word);
	const dirOffset = file.length;
	for (const e of entries) {
		const start = file.length;
		file
			.utf16(e.name)
			.u16(0)
			.pad(start + 64);
		file
			.u16((e.name.length + 1) * 2)
			.u8(e.type)
			.u8(1);
		file.u32(NONE).u32(e.right).u32(e.child);
		file
			.pad(start + 0x74)
			.u32(e.start)
			.u32(e.size)
			.u32(0);
	}
	file.pad(SECTOR + (fatSectors + dirSectors) * SECTOR);
	if (miniFat.length) {
		for (const word of miniFat) file.u32(word);
		while ((file.length - SECTOR) % SECTOR) file.u32(FREE);
	}
	file
		.bytes(miniBytes)
		.pad(SECTOR + (fatSectors + dirSectors + miniFatSectors + miniStreamSectors) * SECTOR);
	for (const e of large) file.bytes(e.data).pad(SECTOR + (e.start + sectorsFor(e.size)) * SECTOR);
	return {
		bytes: file.done(),
		layout: { fatOffset: SECTOR, dirOffset, largeStart, sectorSize: SECTOR },
	};
}

export const cfbBytes = (nodes: readonly CfbNode[]): Uint8Array => buildCfb(nodes).bytes;

// ---------------------------------------------------------------------------------------------
// Word
// ---------------------------------------------------------------------------------------------

export interface WordPiece {
	readonly text: string;
	/** UTF-16 piece; otherwise a "compressed" 8-bit (windows-1252) piece. */
	readonly unicode?: boolean;
}

export interface WordOptions {
	readonly nFib?: number;
	readonly flags?: number;
	/** Byte offset override for a piece (e.g. outside the stream). */
	readonly badPiece?: number;
	readonly extra?: readonly CfbNode[];
}

/** WordDocument + 1Table streams holding `pieces` (plus optional extra entries). */
export function wordNodes(pieces: readonly WordPiece[], opts: WordOptions = {}): CfbNode[] {
	const TEXT_AT = 1024;
	const doc = new Out();
	doc
		.u16(0xa5ec)
		.u16(opts.nFib ?? 0x00c1)
		.u16(0)
		.u16(0x0409)
		.u16(0);
	doc.u16(opts.flags ?? 0x0200).pad(32);
	doc
		.u16(14)
		.pad(34 + 28)
		.u16(22);
	const lwAt = doc.length;
	const total = pieces.reduce((n, p) => n + p.text.length, 0);
	doc
		.pad(lwAt + 12)
		.u32(total)
		.pad(lwAt + 88);
	doc.u16(93);
	const blob = doc.length;
	doc.pad(blob + 93 * 8);
	doc.pad(TEXT_AT);
	const offsets: number[] = [];
	for (const piece of pieces) {
		offsets.push(doc.length);
		if (piece.unicode) doc.utf16(piece.text);
		else doc.bytes(cp1252(piece.text));
	}
	const docBytes = doc.done();
	const table = new Out();
	const lcb = 4 * (pieces.length + 1) + 8 * pieces.length;
	table.u8(0x01).i16(2).u16(0); // a Prc to skip
	const clxAt = 0;
	table.u8(0x02).u32(lcb);
	let cp = 0;
	table.u32(0);
	for (const piece of pieces) {
		cp += piece.text.length;
		table.u32(cp);
	}
	pieces.forEach((piece, i) => {
		const at = opts.badPiece !== undefined && i === 0 ? opts.badPiece : (offsets[i] as number);
		table
			.u16(0)
			.u32(piece.unicode ? at : (at * 2) | 0x40000000)
			.u16(0);
	});
	const tableBytes = table.done();
	// fcClx / lcbClx (pair 33).
	const view = new DataView(docBytes.buffer);
	view.setUint32(blob + 33 * 8, clxAt, true);
	view.setUint32(blob + 33 * 8 + 4, tableBytes.length, true);
	return [
		{ name: "WordDocument", data: docBytes },
		{ name: "1Table", data: tableBytes },
		...(opts.extra ?? []),
	];
}

function cp1252(text: string): Uint8Array {
	const special: Record<number, number> = { 0x20ac: 0x80, 0x2019: 0x92, 0x2013: 0x96 };
	return Uint8Array.from(text, (c) => {
		const code = c.charCodeAt(0);
		return code < 0x100 ? code : (special[code] ?? 0x3f);
	});
}

// ---------------------------------------------------------------------------------------------
// Excel (BIFF8)
// ---------------------------------------------------------------------------------------------

export type Cell = string | number;

export interface ExcelOptions {
	/** Largest record body before the SST spills into CONTINUE records. */
	readonly sstChunk?: number;
	/** Extra records appended to the globals substream: [type, body]. */
	readonly globals?: ReadonlyArray<readonly [number, Uint8Array]>;
	/** BOF substream type of the sheets (0x0010 worksheet, 0x0040 macro sheet). */
	readonly sheetType?: number;
	readonly extra?: readonly CfbNode[];
}

function record(o: Out, type: number, body: Uint8Array): void {
	o.u16(type).u16(body.length).bytes(body);
}

function bof(dt: number): Uint8Array {
	return out().u16(0x0600).u16(dt).u16(0).u16(0).u32(0).u32(0).done();
}

/** Writes the SST across CONTINUE records, re-emitting the high-byte flag at string splits. */
function sstRecords(o: Out, strings: readonly string[], chunk: number): void {
	const bodies: number[][] = [[]];
	const cur = () => bodies[bodies.length - 1] as number[];
	const push = (...b: number[]) => cur().push(...b);
	const u32 = (v: number) => push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff);
	u32(strings.length);
	u32(strings.length);
	for (const s of strings) {
		const high = [...s].some((c) => c.charCodeAt(0) > 0xff);
		if (cur().length + 3 > chunk) bodies.push([]);
		push(s.length & 0xff, s.length >> 8, high ? 1 : 0);
		const width = high ? 2 : 1;
		for (let i = 0; i < s.length; i++) {
			if (cur().length + width > chunk) {
				bodies.push([]);
				push(high ? 1 : 0);
			}
			const code = s.charCodeAt(i);
			if (high) push(code & 0xff, code >> 8);
			else push(code);
		}
	}
	bodies.forEach((body, i) => {
		record(o, i === 0 ? 0x00fc : 0x003c, Uint8Array.from(body));
	});
}

/** A Workbook stream with one or more sheets of strings (LABELSST) and numbers (NUMBER). */
function workbookStream(
	sheets: ReadonlyArray<{ name: string; rows: readonly (readonly Cell[])[] }>,
	opts: ExcelOptions = {},
): Uint8Array {
	const strings: string[] = [];
	const index = (s: string) => {
		const i = strings.indexOf(s);
		if (i >= 0) return i;
		strings.push(s);
		return strings.length - 1;
	};
	for (const sheet of sheets)
		for (const row of sheet.rows) for (const c of row) if (typeof c === "string") index(c);
	const o = out();
	record(o, 0x0809, bof(0x0005));
	for (const [type, body] of opts.globals ?? []) record(o, type, body);
	for (const sheet of sheets) {
		const name = out()
			.u32(0)
			.u8(0)
			.u8(opts.sheetType === 0x0040 ? 1 : 0);
		const wide = [...sheet.name].some((c) => c.charCodeAt(0) > 0xff);
		name.u8(sheet.name.length).u8(wide ? 1 : 0);
		if (wide) name.utf16(sheet.name);
		else name.latin1(sheet.name);
		record(o, 0x0085, name.done());
	}
	sstRecords(o, strings, opts.sstChunk ?? 8224);
	record(o, 0x000a, new Uint8Array(0));
	for (const sheet of sheets) {
		record(o, 0x0809, bof(opts.sheetType ?? 0x0010));
		sheet.rows.forEach((row, r) => {
			row.forEach((c, col) => {
				if (typeof c === "string")
					record(o, 0x00fd, out().u16(r).u16(col).u16(0).u32(index(c)).done());
				else record(o, 0x0203, out().u16(r).u16(col).u16(0).f64(c).done());
			});
		});
		record(o, 0x000a, new Uint8Array(0));
	}
	return o.done();
}

export function excelNodes(
	sheets: ReadonlyArray<{ name: string; rows: readonly (readonly Cell[])[] }>,
	opts: ExcelOptions = {},
): CfbNode[] {
	return [{ name: "Workbook", data: workbookStream(sheets, opts) }, ...(opts.extra ?? [])];
}

// ---------------------------------------------------------------------------------------------
// PowerPoint
// ---------------------------------------------------------------------------------------------

export function pptRecord(
	type: number,
	body: Uint8Array,
	opts: { container?: boolean; instance?: number } = {},
): Uint8Array {
	const verInstance = ((opts.instance ?? 0) << 4) | (opts.container ? 0x0f : 0);
	return out().u16(verInstance).u16(type).u32(body.length).bytes(body).done();
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
	const o = out();
	for (const p of parts) o.bytes(p);
	return o.done();
}

export const textChars = (s: string) => pptRecord(0x0fa0, out().utf16(s).done());
export const textBytes = (s: string) => pptRecord(0x0fa8, out().latin1(s).done());
export const cString = (s: string) => pptRecord(0x0fba, out().utf16(s).done());

/** A PowerPoint Document stream: DocumentContainer > SlideListWithText > `records`. */
export function pptNodes(
	records: readonly Uint8Array[],
	extra: readonly CfbNode[] = [],
): CfbNode[] {
	const slideList = pptRecord(0x0ff0, concatBytes(...records), { container: true });
	const document = pptRecord(0x03e8, slideList, { container: true });
	return [{ name: "PowerPoint Document", data: document }, ...extra];
}

// ---------------------------------------------------------------------------------------------
// Property sets
// ---------------------------------------------------------------------------------------------

/** A SummaryInformation stream with string properties (id -> value, code page 65001: UTF-8). */
export function summaryInformation(props: Record<number, string>): CfbNode {
	const ids = Object.keys(props).map(Number);
	const values: Uint8Array[] = [out().u16(2).u16(0).u16(65001).u16(0).done()];
	for (const id of ids) {
		const s = new TextEncoder().encode(`${props[id]}\u0000`);
		const v = out().u16(0x1e).u16(0).u32(s.length).bytes(s);
		v.pad(v.length + ((4 - (v.length % 4)) % 4));
		values.push(v.done());
	}
	const allIds = [1, ...ids];
	const headerSize = 8 + allIds.length * 8;
	const set = out();
	const size = headerSize + values.reduce((n, v) => n + v.length, 0);
	set.u32(size).u32(allIds.length);
	let offset = headerSize;
	allIds.forEach((id, i) => {
		set.u32(id).u32(offset);
		offset += (values[i] as Uint8Array).length;
	});
	for (const v of values) set.bytes(v);
	const stream = out().u16(0xfffe).u16(0).u32(0x00020006).pad(24).u32(1);
	stream.bytes(new Uint8Array(16)).u32(48);
	stream.bytes(set.done());
	return { name: "\u0005SummaryInformation", data: stream.done() };
}
