/**
 * Minimal, defensive ZIP reader/writer for Office Open XML packages (DOCX/XLSX/PPTX).
 *
 * Reading trusts only the central directory and refuses anything a document scanner should
 * not try to open:
 *   - ZIP64 (sentinel sizes/offsets/counts), multi-disk archives, encrypted entries;
 *   - more than `maxEntries` entries, a declared uncompressed total above
 *     `maxDeclaredTotal`, or an entry whose declared compression ratio exceeds `maxRatio`
 *     (entries under `ratioFloorBytes` are exempt: tiny XML parts compress extremely well);
 *   - unsafe entry names (absolute paths, drive letters, `..`/`.` segments, backslashes,
 *     NUL/control characters) and duplicate names (case-insensitive, as OPC part names are);
 *   - local headers that disagree with the central directory, entries that overlap each
 *     other or the central directory (the "overlapping files" zip bomb).
 * Entry data is inflated with a hard byte budget (`maxEntryBytes` per entry and a shared
 * total), must match the declared size exactly and must pass its CRC-32.
 *
 * Writing rebuilds the archive from the central directory: every entry keeps its name,
 * timestamps, attributes and comment; untouched entries keep their compressed bytes
 * byte-for-byte; replaced entries are deflated afresh. Local headers are regenerated
 * (no data descriptors, no extra fields), and bytes that are not reachable from the central
 * directory (prepended data, hidden local entries, archive comment) are dropped.
 */
import { deflateRaw, InflateLimitError, inflateBounded } from "./deflate.js";

export type ArchiveErrorCode =
	| "NOT_A_ZIP"
	| "MALFORMED"
	| "ZIP64_UNSUPPORTED"
	| "MULTI_DISK"
	| "TOO_MANY_ENTRIES"
	| "LIMIT_EXCEEDED"
	| "RATIO_EXCEEDED"
	| "UNSAFE_PATH"
	| "DUPLICATE_ENTRY"
	| "ENTRY_ENCRYPTED"
	| "UNSUPPORTED_METHOD"
	| "CRC_MISMATCH";

/** Structured refusal; `code` is stable and safe to show (never contains entry data). */
export class ArchiveError extends Error {
	constructor(readonly code: ArchiveErrorCode) {
		super(`ARCHIVE_${code}`);
		this.name = "ArchiveError";
	}
}

export interface ZipLimits {
	readonly maxEntries: number;
	/** Sum of declared uncompressed sizes of all entries. */
	readonly maxDeclaredTotal: number;
	/** Largest single entry that may be inflated. */
	readonly maxEntryBytes: number;
	/** Total bytes that may be inflated across all reads of one archive. */
	readonly maxReadTotal: number;
	readonly maxRatio: number;
	readonly ratioFloorBytes: number;
}

const MIB = 1024 * 1024;

export const DEFAULT_ZIP_LIMITS: ZipLimits = Object.freeze({
	maxEntries: 4096,
	maxDeclaredTotal: 512 * MIB,
	maxEntryBytes: 48 * MIB,
	maxReadTotal: 64 * MIB,
	maxRatio: 200,
	ratioFloorBytes: 1 * MIB,
});

export interface ZipEntry {
	readonly name: string;
	readonly nameBytes: Uint8Array;
	readonly flags: number;
	readonly method: number;
	readonly modTime: number;
	readonly modDate: number;
	readonly crc32: number;
	readonly compressedSize: number;
	readonly uncompressedSize: number;
	readonly versionMadeBy: number;
	readonly versionNeeded: number;
	readonly internalAttrs: number;
	readonly externalAttrs: number;
	readonly comment: Uint8Array;
	readonly localOffset: number;
	/** Offset of the compressed data (after the local header). */
	readonly dataOffset: number;
}

export interface ZipArchive {
	readonly bytes: Uint8Array;
	readonly entries: readonly ZipEntry[];
	readonly limits: ZipLimits;
	/** Bytes inflated so far (shared budget, see `maxReadTotal`). */
	readBytes: number;
}

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const FLAG_ENCRYPTED = 0x0001;
const FLAG_UTF8 = 0x0800;
const FLAG_STRONG_ENCRYPTION = 0x0040;
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;

// ---------------------------------------------------------------------------------------------
// CRC-32 (IEEE 802.3, reflected, as used by ZIP)
// ---------------------------------------------------------------------------------------------

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

export function crc32(data: Uint8Array): number {
	let crc = 0xffffffff;
	for (let i = 0; i < data.length; i++)
		crc = (CRC_TABLE[(crc ^ (data[i] as number)) & 0xff] as number) ^ (crc >>> 8);
	return (crc ^ 0xffffffff) >>> 0;
}

// ---------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------

function u16(b: Uint8Array, o: number): number {
	return (b[o] as number) | ((b[o + 1] as number) << 8);
}
function u32(b: Uint8Array, o: number): number {
	return (
		((b[o] as number) | ((b[o + 1] as number) << 8) | ((b[o + 2] as number) << 16)) +
		(b[o + 3] as number) * 0x1000000
	);
}

/** True when the bytes start like a ZIP (local header or empty-archive EOCD). */
export function looksLikeZip(bytes: Uint8Array): boolean {
	return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && u16(bytes, 2) === 0x0403;
}

function findEocd(bytes: Uint8Array): number {
	const min = Math.max(0, bytes.length - 22 - 0xffff);
	for (let i = bytes.length - 22; i >= min; i--) {
		if (u32(bytes, i) === SIG_EOCD && i + 22 + u16(bytes, i + 20) === bytes.length) return i;
	}
	return -1;
}

/** Where a ZIP's central directory lies, as its end-of-central-directory record says. */
export interface ZipDirectory {
	readonly offset: number;
	readonly size: number;
	readonly count: number;
}

/**
 * The central directory location from the EOCD record in `tail`, the last bytes of a file
 * (at least the last 64 KiB + 22 for an archive comment of any length); null when there is
 * no EOCD there or the archive is ZIP64 / multi-disk.
 */
export function zipDirectory(tail: Uint8Array): ZipDirectory | null {
	const eocd = tail.length >= 22 ? findEocd(tail) : -1;
	if (eocd < 0 || (eocd >= 20 && u32(tail, eocd - 20) === SIG_ZIP64_LOCATOR)) return null;
	const count = u16(tail, eocd + 10);
	const size = u32(tail, eocd + 12);
	const offset = u32(tail, eocd + 16);
	const multiDisk = u16(tail, eocd + 4) !== 0 || u16(tail, eocd + 6) !== 0;
	if (multiDisk || count !== u16(tail, eocd + 8)) return null;
	if (count === 0xffff || size === 0xffffffff || offset === 0xffffffff) return null;
	return { offset, size, count };
}

/** Entry names of the `count` records of a central directory; null when it is malformed. */
export function centralDirectoryNames(directory: Uint8Array, count: number): string[] | null {
	const names: string[] = [];
	const decoder = new TextDecoder("utf-8");
	let offset = 0;
	for (let i = 0; i < count; i++) {
		if (offset + 46 > directory.length || u32(directory, offset) !== SIG_CENTRAL) return null;
		const nameLen = u16(directory, offset + 28);
		const next = offset + 46 + nameLen + u16(directory, offset + 30) + u16(directory, offset + 32);
		if (next > directory.length) return null;
		names.push(decoder.decode(directory.subarray(offset + 46, offset + 46 + nameLen)));
		offset = next;
	}
	return names;
}

const DECODER_UTF8 = new TextDecoder("utf-8", { fatal: true });

function decodeName(raw: Uint8Array, utf8: boolean): string {
	if (utf8) {
		try {
			return DECODER_UTF8.decode(raw);
		} catch {
			throw new ArchiveError("MALFORMED");
		}
	}
	// CP437 names: OOXML producers only ever write ASCII here; map bytes 1:1 so that a
	// non-ASCII byte still yields a stable (and later refused, if unsafe) name.
	let out = "";
	for (const b of raw) out += String.fromCharCode(b);
	return out;
}

/** Refuses names that could escape an extraction directory or confuse part lookup. */
export function isSafeEntryName(name: string): boolean {
	if (!name || name.length > 1024) return false;
	if (/[\u0000-\u001f\u007f\\]/.test(name)) return false;
	if (name.startsWith("/") || /^[A-Za-z]:/.test(name)) return false;
	const segments = name.split("/");
	// A trailing "/" (directory entry) yields one empty last segment; any other empty is refused.
	for (let i = 0; i < segments.length; i++) {
		const s = segments[i] as string;
		if (s === "." || s === "..") return false;
		if (s === "" && i !== segments.length - 1) return false;
	}
	return true;
}

function parseCentral(bytes: Uint8Array, offset: number, cdEnd: number): [ZipEntry, number] {
	if (offset + 46 > cdEnd || u32(bytes, offset) !== SIG_CENTRAL)
		throw new ArchiveError("MALFORMED");
	const flags = u16(bytes, offset + 8);
	const compressedSize = u32(bytes, offset + 20);
	const uncompressedSize = u32(bytes, offset + 24);
	const nameLen = u16(bytes, offset + 28);
	const extraLen = u16(bytes, offset + 30);
	const commentLen = u16(bytes, offset + 32);
	const disk = u16(bytes, offset + 34);
	const localOffset = u32(bytes, offset + 42);
	const next = offset + 46 + nameLen + extraLen + commentLen;
	if (next > cdEnd) throw new ArchiveError("MALFORMED");
	if (
		compressedSize === 0xffffffff ||
		uncompressedSize === 0xffffffff ||
		localOffset === 0xffffffff ||
		disk === 0xffff
	)
		throw new ArchiveError("ZIP64_UNSUPPORTED");
	if (disk !== 0) throw new ArchiveError("MULTI_DISK");
	if (flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION)) throw new ArchiveError("ENTRY_ENCRYPTED");
	const nameBytes = bytes.slice(offset + 46, offset + 46 + nameLen);
	const name = decodeName(nameBytes, (flags & FLAG_UTF8) !== 0);
	if (!isSafeEntryName(name)) throw new ArchiveError("UNSAFE_PATH");
	const entry: ZipEntry = {
		name,
		nameBytes,
		flags,
		method: u16(bytes, offset + 10),
		modTime: u16(bytes, offset + 12),
		modDate: u16(bytes, offset + 14),
		crc32: u32(bytes, offset + 16),
		compressedSize,
		uncompressedSize,
		versionMadeBy: u16(bytes, offset + 4),
		versionNeeded: u16(bytes, offset + 6),
		internalAttrs: u16(bytes, offset + 36),
		externalAttrs: u32(bytes, offset + 38),
		comment: bytes.slice(offset + 46 + nameLen + extraLen, next),
		localOffset,
		dataOffset: localDataOffset(bytes, localOffset, nameBytes),
	};
	return [entry, next];
}

/** Validates the local header against the central record; returns where the data starts. */
function localDataOffset(bytes: Uint8Array, offset: number, nameBytes: Uint8Array): number {
	if (offset + 30 > bytes.length || u32(bytes, offset) !== SIG_LOCAL)
		throw new ArchiveError("MALFORMED");
	const nameLen = u16(bytes, offset + 26);
	const extraLen = u16(bytes, offset + 28);
	if (nameLen !== nameBytes.length) throw new ArchiveError("MALFORMED");
	for (let i = 0; i < nameLen; i++)
		if (bytes[offset + 30 + i] !== nameBytes[i]) throw new ArchiveError("MALFORMED");
	return offset + 30 + nameLen + extraLen;
}

function checkEntryBounds(entries: readonly ZipEntry[], cdOffset: number, limits: ZipLimits): void {
	let declared = 0;
	const seen = new Set<string>();
	for (const e of entries) {
		const key = e.name.toLowerCase();
		if (seen.has(key)) throw new ArchiveError("DUPLICATE_ENTRY");
		seen.add(key);
		declared += e.uncompressedSize;
		if (declared > limits.maxDeclaredTotal) throw new ArchiveError("LIMIT_EXCEEDED");
		if (
			e.uncompressedSize > limits.ratioFloorBytes &&
			e.uncompressedSize > Math.max(1, e.compressedSize) * limits.maxRatio
		)
			throw new ArchiveError("RATIO_EXCEEDED");
		if (e.method === METHOD_STORED && e.compressedSize !== e.uncompressedSize)
			throw new ArchiveError("MALFORMED");
	}
	// Overlap check: every entry's local record must end before the next one starts.
	const byOffset = [...entries].sort((a, b) => a.localOffset - b.localOffset);
	for (let i = 0; i < byOffset.length; i++) {
		const e = byOffset[i] as ZipEntry;
		const end = e.dataOffset + e.compressedSize;
		const nextStart = byOffset[i + 1]?.localOffset ?? cdOffset;
		if (end > nextStart) throw new ArchiveError("MALFORMED");
	}
}

/** Parses and validates the archive structure (no entry data is inflated here). */
export function readZip(bytes: Uint8Array, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipArchive {
	const eocd = bytes.length >= 22 ? findEocd(bytes) : -1;
	if (eocd < 0) {
		if (looksLikeZip(bytes)) throw new ArchiveError("MALFORMED");
		throw new ArchiveError("NOT_A_ZIP");
	}
	if (eocd >= 20 && u32(bytes, eocd - 20) === SIG_ZIP64_LOCATOR)
		throw new ArchiveError("ZIP64_UNSUPPORTED");
	const diskNo = u16(bytes, eocd + 4);
	const cdDisk = u16(bytes, eocd + 6);
	const countDisk = u16(bytes, eocd + 8);
	const count = u16(bytes, eocd + 10);
	const cdSize = u32(bytes, eocd + 12);
	const cdOffset = u32(bytes, eocd + 16);
	if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff)
		throw new ArchiveError("ZIP64_UNSUPPORTED");
	if (diskNo !== 0 || cdDisk !== 0 || countDisk !== count) throw new ArchiveError("MULTI_DISK");
	if (count > limits.maxEntries) throw new ArchiveError("TOO_MANY_ENTRIES");
	const cdEnd = cdOffset + cdSize;
	if (cdEnd > eocd) throw new ArchiveError("MALFORMED");
	const entries: ZipEntry[] = [];
	let offset = cdOffset;
	for (let i = 0; i < count; i++) {
		const [entry, next] = parseCentral(bytes, offset, cdEnd);
		entries.push(entry);
		offset = next;
	}
	if (offset !== cdEnd) throw new ArchiveError("MALFORMED");
	checkEntryBounds(entries, cdOffset, limits);
	return { bytes, entries, limits, readBytes: 0 };
}

export function findEntry(archive: ZipArchive, name: string): ZipEntry | undefined {
	const key = name.toLowerCase();
	return archive.entries.find((e) => e.name.toLowerCase() === key);
}

/** Inflates one entry within the archive's budgets and verifies its size and CRC-32. */
export async function readEntry(archive: ZipArchive, entry: ZipEntry): Promise<Uint8Array> {
	const { limits } = archive;
	if (entry.uncompressedSize > limits.maxEntryBytes) throw new ArchiveError("LIMIT_EXCEEDED");
	if (archive.readBytes + entry.uncompressedSize > limits.maxReadTotal)
		throw new ArchiveError("LIMIT_EXCEEDED");
	const raw = archive.bytes.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize);
	let data: Uint8Array;
	if (entry.method === METHOD_STORED) data = raw.slice();
	else if (entry.method === METHOD_DEFLATE) {
		try {
			// One byte over the declared size proves the declaration false without inflating more.
			const result = await inflateBounded(raw, "deflate-raw", entry.uncompressedSize);
			if (!result.complete) throw new ArchiveError("MALFORMED");
			data = result.bytes;
		} catch (error) {
			if (error instanceof InflateLimitError) throw new ArchiveError("MALFORMED");
			throw error;
		}
	} else throw new ArchiveError("UNSUPPORTED_METHOD");
	if (data.length !== entry.uncompressedSize) throw new ArchiveError("MALFORMED");
	if (crc32(data) !== entry.crc32) throw new ArchiveError("CRC_MISMATCH");
	archive.readBytes += data.length;
	return data;
}

// ---------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------

class ByteWriter {
	private chunks: Uint8Array[] = [];
	length = 0;
	bytes(data: Uint8Array): void {
		this.chunks.push(data);
		this.length += data.length;
	}
	u16(v: number): void {
		this.bytes(new Uint8Array([v & 0xff, (v >>> 8) & 0xff]));
	}
	u32(v: number): void {
		this.bytes(new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]));
	}
	finish(): Uint8Array {
		const out = new Uint8Array(this.length);
		let o = 0;
		for (const c of this.chunks) {
			out.set(c, o);
			o += c.length;
		}
		return out;
	}
}

interface OutEntry {
	readonly meta: Omit<
		ZipEntry,
		| "localOffset"
		| "dataOffset"
		| "compressedSize"
		| "uncompressedSize"
		| "crc32"
		| "method"
		| "name"
	>;
	readonly method: number;
	readonly crc32: number;
	readonly uncompressedSize: number;
	readonly data: Uint8Array;
}

function writeArchive(entries: readonly OutEntry[]): Uint8Array {
	if (entries.length > 0xfffe) throw new ArchiveError("TOO_MANY_ENTRIES");
	const w = new ByteWriter();
	const offsets: number[] = [];
	for (const e of entries) {
		offsets.push(w.length);
		const flags = e.meta.flags & FLAG_UTF8;
		w.u32(SIG_LOCAL);
		w.u16(Math.max(e.meta.versionNeeded & 0xff, e.method === METHOD_DEFLATE ? 20 : 10));
		w.u16(flags);
		w.u16(e.method);
		w.u16(e.meta.modTime);
		w.u16(e.meta.modDate);
		w.u32(e.crc32);
		w.u32(e.data.length);
		w.u32(e.uncompressedSize);
		w.u16(e.meta.nameBytes.length);
		w.u16(0);
		w.bytes(e.meta.nameBytes);
		w.bytes(e.data);
	}
	const cdOffset = w.length;
	entries.forEach((e, i) => {
		w.u32(SIG_CENTRAL);
		w.u16(e.meta.versionMadeBy);
		w.u16(Math.max(e.meta.versionNeeded & 0xff, e.method === METHOD_DEFLATE ? 20 : 10));
		w.u16(e.meta.flags & FLAG_UTF8);
		w.u16(e.method);
		w.u16(e.meta.modTime);
		w.u16(e.meta.modDate);
		w.u32(e.crc32);
		w.u32(e.data.length);
		w.u32(e.uncompressedSize);
		w.u16(e.meta.nameBytes.length);
		w.u16(0);
		w.u16(e.meta.comment.length);
		w.u16(0);
		w.u16(e.meta.internalAttrs);
		w.u32(e.meta.externalAttrs);
		w.u32(offsets[i] as number);
		w.bytes(e.meta.nameBytes);
		w.bytes(e.meta.comment);
	});
	const cdSize = w.length - cdOffset;
	if (w.length > 0xfffffffe) throw new ArchiveError("LIMIT_EXCEEDED");
	w.u32(SIG_EOCD);
	w.u16(0);
	w.u16(0);
	w.u16(entries.length);
	w.u16(entries.length);
	w.u32(cdSize);
	w.u32(cdOffset);
	w.u16(0);
	return w.finish();
}

async function compressed(data: Uint8Array): Promise<{ method: number; data: Uint8Array }> {
	if (data.length === 0) return { method: METHOD_STORED, data };
	const deflated = await deflateRaw(data);
	return deflated.length < data.length
		? { method: METHOD_DEFLATE, data: deflated }
		: { method: METHOD_STORED, data };
}

/**
 * Rebuilds `archive` with the entries named in `replacements` (exact entry names) swapped for
 * new content. Every other entry's compressed bytes are copied unchanged.
 */
export async function rewriteZip(
	archive: ZipArchive,
	replacements: ReadonlyMap<string, Uint8Array>,
): Promise<Uint8Array> {
	const out: OutEntry[] = [];
	for (const entry of archive.entries) {
		const replacement = replacements.get(entry.name);
		if (replacement) {
			const packed = await compressed(replacement);
			out.push({
				meta: entry,
				method: packed.method,
				crc32: crc32(replacement),
				uncompressedSize: replacement.length,
				data: packed.data,
			});
		} else {
			out.push({
				meta: entry,
				method: entry.method,
				crc32: entry.crc32,
				uncompressedSize: entry.uncompressedSize,
				data: archive.bytes.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize),
			});
		}
	}
	return writeArchive(out);
}

/** Builds a new archive (UTF-8 names, deflated where it helps). Used for tests and fixtures. */
export async function createZip(
	files: ReadonlyArray<{ readonly name: string; readonly data: Uint8Array | string }>,
): Promise<Uint8Array> {
	const encoder = new TextEncoder();
	const out: OutEntry[] = [];
	for (const file of files) {
		const data = typeof file.data === "string" ? encoder.encode(file.data) : file.data;
		const packed = await compressed(data);
		out.push({
			meta: {
				nameBytes: encoder.encode(file.name),
				flags: FLAG_UTF8,
				modTime: 0,
				modDate: 0x21, // 1980-01-01
				versionMadeBy: 20,
				versionNeeded: 20,
				internalAttrs: 0,
				externalAttrs: 0,
				comment: new Uint8Array(0),
			},
			method: packed.method,
			crc32: crc32(data),
			uncompressedSize: data.length,
			data: packed.data,
		});
	}
	return writeArchive(out);
}
