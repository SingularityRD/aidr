/**
 * Minimal deterministic ZIP writer (PKWARE APPNOTE 6.3, no ZIP64).
 *
 * Browser stores accept ordinary deflate ZIPs. We write our own instead of
 * shelling out to `zip` so that the archive is byte-identical on every host:
 * entries are sorted, every timestamp is the DOS epoch (1980-01-01 00:00), no
 * extra fields, no platform-specific attributes beyond a fixed 0644 mode.
 */
import { deflateRawSync, inflateRawSync } from "node:zlib";

const CRC_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let n = 0; n < 256; n++) {
		let c = n;
		for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
		table[n] = c >>> 0;
	}
	return table;
})();

/** CRC-32 (IEEE 802.3), as used by ZIP and PNG. */
export function crc32(bytes, seed = 0) {
	let crc = (seed ^ 0xffffffff) >>> 0;
	for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
	return (crc ^ 0xffffffff) >>> 0;
}

const DOS_TIME = 0; // 00:00:00
const DOS_DATE = (0 << 9) | (1 << 5) | 1; // 1980-01-01
const VERSION_NEEDED = 20; // 2.0: deflate
const VERSION_MADE_BY = (3 << 8) | VERSION_NEEDED; // UNIX host, so external attrs carry a mode
const FLAG_UTF8 = 0x0800;
const REGULAR_FILE_0644 = (0o100644 << 16) >>> 0;
const MAX_U32 = 0xffffffff;

function assertEntryName(name) {
	if (
		typeof name !== "string" ||
		name.length === 0 ||
		name.startsWith("/") ||
		name.includes("\\") ||
		name.split("/").some((part) => part === "" || part === "." || part === "..")
	) {
		throw new Error(`ZIP_INVALID_ENTRY_NAME: ${JSON.stringify(name)}`);
	}
}

/**
 * Builds a ZIP archive.
 * @param {ReadonlyArray<{ name: string; data: Uint8Array }>} entries
 * @returns {Buffer}
 */
export function createZip(entries) {
	const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
	const seen = new Set();
	const localParts = [];
	const centralParts = [];
	let offset = 0;

	for (const entry of sorted) {
		assertEntryName(entry.name);
		if (seen.has(entry.name)) throw new Error(`ZIP_DUPLICATE_ENTRY: ${entry.name}`);
		seen.add(entry.name);

		const data = Buffer.from(entry.data);
		const name = Buffer.from(entry.name, "utf8");
		const crc = crc32(data);
		const deflated = deflateRawSync(data, { level: 9 });
		const useDeflate = deflated.length < data.length;
		const payload = useDeflate ? deflated : data;
		const method = useDeflate ? 8 : 0;
		if (data.length > MAX_U32 || offset > MAX_U32) throw new Error("ZIP_TOO_LARGE");

		const local = Buffer.alloc(30);
		local.writeUInt32LE(0x04034b50, 0);
		local.writeUInt16LE(VERSION_NEEDED, 4);
		local.writeUInt16LE(FLAG_UTF8, 6);
		local.writeUInt16LE(method, 8);
		local.writeUInt16LE(DOS_TIME, 10);
		local.writeUInt16LE(DOS_DATE, 12);
		local.writeUInt32LE(crc, 14);
		local.writeUInt32LE(payload.length, 18);
		local.writeUInt32LE(data.length, 22);
		local.writeUInt16LE(name.length, 26);
		local.writeUInt16LE(0, 28);
		localParts.push(local, name, payload);

		const central = Buffer.alloc(46);
		central.writeUInt32LE(0x02014b50, 0);
		central.writeUInt16LE(VERSION_MADE_BY, 4);
		central.writeUInt16LE(VERSION_NEEDED, 6);
		central.writeUInt16LE(FLAG_UTF8, 8);
		central.writeUInt16LE(method, 10);
		central.writeUInt16LE(DOS_TIME, 12);
		central.writeUInt16LE(DOS_DATE, 14);
		central.writeUInt32LE(crc, 16);
		central.writeUInt32LE(payload.length, 20);
		central.writeUInt32LE(data.length, 24);
		central.writeUInt16LE(name.length, 28);
		central.writeUInt16LE(0, 30); // extra length
		central.writeUInt16LE(0, 32); // comment length
		central.writeUInt16LE(0, 34); // disk number
		central.writeUInt16LE(0, 36); // internal attrs
		central.writeUInt32LE(REGULAR_FILE_0644, 38);
		central.writeUInt32LE(offset, 42);
		centralParts.push(central, name);

		offset += local.length + name.length + payload.length;
	}

	if (sorted.length > 0xffff) throw new Error("ZIP_TOO_MANY_ENTRIES");
	const centralDirectory = Buffer.concat(centralParts);
	const end = Buffer.alloc(22);
	end.writeUInt32LE(0x06054b50, 0);
	end.writeUInt16LE(0, 4);
	end.writeUInt16LE(0, 6);
	end.writeUInt16LE(sorted.length, 8);
	end.writeUInt16LE(sorted.length, 10);
	end.writeUInt32LE(centralDirectory.length, 12);
	end.writeUInt32LE(offset, 16);
	end.writeUInt16LE(0, 20);
	return Buffer.concat([...localParts, centralDirectory, end]);
}

/**
 * Reads the central directory of an archive written by {@link createZip} (or any
 * non-ZIP64 archive without a comment). Used by the build self-check and tests.
 * @returns {Map<string, Buffer>} entry name -> uncompressed bytes
 */
export function readZip(buffer) {
	const endOffset = buffer.length - 22;
	if (endOffset < 0 || buffer.readUInt32LE(endOffset) !== 0x06054b50) throw new Error("ZIP_NO_EOCD");
	const count = buffer.readUInt16LE(endOffset + 10);
	let cursor = buffer.readUInt32LE(endOffset + 16);
	const files = new Map();
	for (let i = 0; i < count; i++) {
		if (buffer.readUInt32LE(cursor) !== 0x02014b50) throw new Error("ZIP_BAD_CENTRAL_HEADER");
		const method = buffer.readUInt16LE(cursor + 10);
		const crc = buffer.readUInt32LE(cursor + 16);
		const compressedSize = buffer.readUInt32LE(cursor + 20);
		const nameLength = buffer.readUInt16LE(cursor + 28);
		const extraLength = buffer.readUInt16LE(cursor + 30);
		const commentLength = buffer.readUInt16LE(cursor + 32);
		const localOffset = buffer.readUInt32LE(cursor + 42);
		const name = buffer.toString("utf8", cursor + 46, cursor + 46 + nameLength);
		const localNameLength = buffer.readUInt16LE(localOffset + 26);
		const localExtraLength = buffer.readUInt16LE(localOffset + 28);
		const start = localOffset + 30 + localNameLength + localExtraLength;
		const raw = buffer.subarray(start, start + compressedSize);
		const data = method === 8 ? inflateRawSync(raw) : Buffer.from(raw);
		if (crc32(data) !== crc) throw new Error(`ZIP_CRC_MISMATCH: ${name}`);
		files.set(name, data);
		cursor += 46 + nameLength + extraLength + commentLength;
	}
	return files;
}
