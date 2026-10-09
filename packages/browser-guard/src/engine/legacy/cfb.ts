/**
 * Minimal, defensive reader for OLE2 / Compound File Binary containers ([MS-CFB]), the
 * container of the legacy binary Office formats (.doc/.xls/.ppt). Read-only, dependency-free
 * and browser-safe (no `node:` imports).
 *
 * Everything is bounded and every inconsistency is an error, never a guess:
 *   - header: signature, byte order, version 3 (512-byte sectors) or 4 (4096-byte sectors),
 *     mini sector shift 6, mini stream cutoff 4096;
 *   - FAT / DIFAT / mini FAT / directory chains: every sector index must lie inside the file,
 *     a chain may not visit a sector twice (cyclic FAT) and may not be shorter than the
 *     stream it holds (truncated file);
 *   - directory: at most `maxDirectoryEntries`, sibling/child links must point at valid,
 *     not-yet-visited entries (no cycles), names must be well-formed;
 *   - streams are only materialised on request and never above `maxStreamBytes`.
 *
 * `CfbError` carries a stable code: NOT_CFB (no CFB signature: not this format at all),
 * MALFORMED (corrupt or adversarial structure), LIMIT (a bound was reached).
 */

export type CfbErrorCode = "NOT_CFB" | "MALFORMED" | "LIMIT";

export class CfbError extends Error {
	constructor(readonly code: CfbErrorCode) {
		super(`CFB_${code}`);
		this.name = "CfbError";
	}
}

export interface CfbLimits {
	/** Largest file accepted (the container is read whole). */
	readonly maxFileBytes: number;
	readonly maxDirectoryEntries: number;
	/** Largest single stream that may be read. */
	readonly maxStreamBytes: number;
}

const MIB = 1024 * 1024;

export const DEFAULT_CFB_LIMITS: CfbLimits = {
	maxFileBytes: 64 * MIB,
	maxDirectoryEntries: 16_384,
	maxStreamBytes: 48 * MIB,
};

const CFB_SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] as const;

const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const MAXREGSECT = 0xfffffffa;
const NOSTREAM = 0xffffffff;
const HEADER_DIFAT_ENTRIES = 109;
const MINI_SECTOR_SIZE = 64;
const MINI_STREAM_CUTOFF = 4096;
const DIR_ENTRY_SIZE = 128;

type CfbEntryType = "storage" | "stream" | "root";

export interface CfbEntry {
	/** Entry name as stored (e.g. "WordDocument", "\u0005SummaryInformation"). */
	readonly name: string;
	/** Slash-joined path from the root, excluding the root's own name. */
	readonly path: string;
	readonly type: CfbEntryType;
	readonly size: number;
	/** Child entries (storages and the root only). */
	readonly children: readonly CfbEntry[];
	/** @internal */
	readonly start: number;
}

export interface CompoundFile {
	readonly root: CfbEntry;
	/** Every storage and stream below the root, in directory-tree order. */
	readonly entries: readonly CfbEntry[];
	/** Top-level child of the root by name (case-insensitive, as CFB names compare), or null. */
	child(name: string): CfbEntry | null;
	/** The bytes of a stream entry (bounded by `maxStreamBytes`). */
	read(entry: CfbEntry): Uint8Array;
}

/** A storage's child by name (case-insensitive, as CFB names compare), or null. */
export function childEntry(storage: CfbEntry, name: string): CfbEntry | null {
	const wanted = name.toUpperCase();
	return storage.children.find((c) => c.name.toUpperCase() === wanted) ?? null;
}

function isCompoundFile(bytes: Uint8Array): boolean {
	return CFB_SIGNATURE.every((b, i) => bytes[i] === b);
}

class Reader {
	readonly view: DataView;
	readonly sectorSize: number;
	readonly sectorCount: number;
	fat: Uint32Array = new Uint32Array(0);
	miniFat: Uint32Array = new Uint32Array(0);
	miniStream: Uint8Array = new Uint8Array(0);

	constructor(
		readonly bytes: Uint8Array,
		readonly limits: CfbLimits,
	) {
		this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
		const major = this.u16(0x1a);
		const shift = this.u16(0x1e);
		if (this.u16(0x1c) !== 0xfffe) throw new CfbError("MALFORMED");
		if (!((major === 3 && shift === 9) || (major === 4 && shift === 12)))
			throw new CfbError("MALFORMED");
		if (this.u16(0x20) !== 6 || this.u32(0x38) !== MINI_STREAM_CUTOFF)
			throw new CfbError("MALFORMED");
		this.sectorSize = 1 << shift;
		if (bytes.length < this.sectorSize) throw new CfbError("MALFORMED");
		// Sector n starts at (n + 1) * sectorSize; a final partial sector still counts.
		this.sectorCount = Math.ceil(bytes.length / this.sectorSize) - 1;
	}

	u16(offset: number): number {
		return this.view.getUint16(offset, true);
	}

	u32(offset: number): number {
		return this.view.getUint32(offset, true);
	}

	/** A sector's bytes (a final sector may be cut short by the end of the file). */
	sector(index: number): Uint8Array {
		if (index > MAXREGSECT || index >= this.sectorCount) throw new CfbError("MALFORMED");
		const start = (index + 1) * this.sectorSize;
		return this.bytes.subarray(start, Math.min(start + this.sectorSize, this.bytes.length));
	}

	/** A full sector read as little-endian u32 values; a truncated sector is an error. */
	sectorWords(index: number): Uint32Array {
		const data = this.sector(index);
		if (data.length !== this.sectorSize) throw new CfbError("MALFORMED");
		const words = new Uint32Array(this.sectorSize / 4);
		const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
		for (let i = 0; i < words.length; i++) words[i] = view.getUint32(i * 4, true);
		return words;
	}

	/**
	 * Follows a FAT (or mini FAT) chain from `start`. With `need` set, stops after that many
	 * sectors and fails when the chain ends earlier; without it, follows to ENDOFCHAIN.
	 * A repeated sector (cycle) or an index outside the table is MALFORMED.
	 */
	chain(start: number, table: Uint32Array, maxIndex: number, need?: number): number[] {
		const out: number[] = [];
		const seen = new Set<number>();
		let current = start;
		while (current !== ENDOFCHAIN) {
			if (need !== undefined && out.length >= need) break;
			if (current > MAXREGSECT || current >= maxIndex || current >= table.length)
				throw new CfbError("MALFORMED");
			if (seen.has(current)) throw new CfbError("MALFORMED");
			seen.add(current);
			out.push(current);
			current = table[current] ?? FREESECT;
		}
		if (need !== undefined && out.length < need) throw new CfbError("MALFORMED");
		return out;
	}

	/** Concatenates regular sectors into exactly `size` bytes (or all of them when unsized). */
	gather(sectors: readonly number[], size?: number): Uint8Array {
		const total = size ?? sectors.length * this.sectorSize;
		if (total > this.limits.maxStreamBytes) throw new CfbError("LIMIT");
		const out = new Uint8Array(total);
		let offset = 0;
		for (const index of sectors) {
			if (offset >= total) break;
			const data = this.sector(index);
			const take = Math.min(data.length, total - offset);
			// A short (final, truncated) sector in the middle of the stream: missing data.
			if (take < Math.min(this.sectorSize, total - offset)) throw new CfbError("MALFORMED");
			out.set(data.subarray(0, take), offset);
			offset += take;
		}
		if (offset < total) throw new CfbError("MALFORMED");
		return out;
	}

	loadFat(): void {
		const fatSectors = this.u32(0x2c);
		const difatStart = this.u32(0x44);
		const difatCount = this.u32(0x48);
		// Each FAT sector describes sectorSize/4 sectors; more FAT than the file needs is bogus.
		const perSector = this.sectorSize / 4;
		if (fatSectors === 0 || fatSectors > Math.ceil(this.sectorCount / perSector) + 1)
			throw new CfbError("MALFORMED");
		const locations: number[] = [];
		for (let i = 0; i < HEADER_DIFAT_ENTRIES && locations.length < fatSectors; i++)
			locations.push(this.u32(0x4c + i * 4));
		let next = difatStart;
		const seen = new Set<number>();
		for (let d = 0; locations.length < fatSectors; d++) {
			if (d >= difatCount || next > MAXREGSECT || seen.has(next)) throw new CfbError("MALFORMED");
			seen.add(next);
			const words = this.sectorWords(next);
			for (let i = 0; i < perSector - 1 && locations.length < fatSectors; i++)
				locations.push(words[i] ?? FREESECT);
			next = words[perSector - 1] ?? ENDOFCHAIN;
		}
		const fat = new Uint32Array(fatSectors * perSector);
		const used = new Set<number>();
		locations.forEach((location, i) => {
			if (used.has(location)) throw new CfbError("MALFORMED");
			used.add(location);
			fat.set(this.sectorWords(location), i * perSector);
		});
		this.fat = fat;
	}

	readDirectory(): Uint8Array {
		const start = this.u32(0x30);
		const sectors = this.chain(start, this.fat, this.sectorCount);
		if (sectors.length * (this.sectorSize / DIR_ENTRY_SIZE) > this.limits.maxDirectoryEntries)
			throw new CfbError("LIMIT");
		return this.gather(sectors);
	}

	loadMini(root: { start: number; size: number }): void {
		const miniFatStart = this.u32(0x3c);
		const miniFatCount = this.u32(0x40);
		if (root.size === 0) return;
		if (miniFatCount === 0 || miniFatStart === ENDOFCHAIN) throw new CfbError("MALFORMED");
		const sectors = this.chain(miniFatStart, this.fat, this.sectorCount, miniFatCount);
		const words: number[] = [];
		for (const s of sectors) for (const w of this.sectorWords(s)) words.push(w);
		this.miniFat = Uint32Array.from(words);
		const need = Math.ceil(root.size / this.sectorSize);
		this.miniStream = this.gather(
			this.chain(root.start, this.fat, this.sectorCount, need),
			root.size,
		);
	}

	readStream(start: number, size: number): Uint8Array {
		if (size > this.limits.maxStreamBytes) throw new CfbError("LIMIT");
		if (size === 0) return new Uint8Array(0);
		if (size >= MINI_STREAM_CUTOFF) {
			const need = Math.ceil(size / this.sectorSize);
			return this.gather(this.chain(start, this.fat, this.sectorCount, need), size);
		}
		const need = Math.ceil(size / MINI_SECTOR_SIZE);
		const miniSectors = Math.ceil(this.miniStream.length / MINI_SECTOR_SIZE);
		const sectors = this.chain(start, this.miniFat, miniSectors, need);
		const out = new Uint8Array(size);
		sectors.forEach((index, i) => {
			const from = index * MINI_SECTOR_SIZE;
			const take = Math.min(MINI_SECTOR_SIZE, size - i * MINI_SECTOR_SIZE);
			if (from + take > this.miniStream.length) throw new CfbError("MALFORMED");
			out.set(this.miniStream.subarray(from, from + take), i * MINI_SECTOR_SIZE);
		});
		return out;
	}
}

interface RawEntry {
	readonly name: string;
	readonly type: number;
	readonly left: number;
	readonly right: number;
	readonly child: number;
	readonly start: number;
	readonly size: number;
}

function parseEntries(dir: Uint8Array, major: number): RawEntry[] {
	const view = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
	const entries: RawEntry[] = [];
	for (let offset = 0; offset + DIR_ENTRY_SIZE <= dir.length; offset += DIR_ENTRY_SIZE) {
		const type = dir[offset + 0x42] ?? 0;
		const nameBytes = view.getUint16(offset + 0x40, true);
		let name = "";
		if (type !== 0) {
			if (nameBytes < 2 || nameBytes > 64 || nameBytes % 2 !== 0) throw new CfbError("MALFORMED");
			for (let i = 0; i < nameBytes / 2 - 1; i++)
				name += String.fromCharCode(view.getUint16(offset + i * 2, true));
		}
		const low = view.getUint32(offset + 0x78, true);
		const high = view.getUint32(offset + 0x7c, true);
		// Version 3 files may leave garbage in the high word; version 4 sizes must fit.
		if (major === 4 && high !== 0 && type !== 0) throw new CfbError("LIMIT");
		entries.push({
			name,
			type,
			left: view.getUint32(offset + 0x44, true),
			right: view.getUint32(offset + 0x48, true),
			child: view.getUint32(offset + 0x4c, true),
			start: view.getUint32(offset + 0x74, true),
			size: low,
		});
	}
	return entries;
}

const ENTRY_TYPES: Record<number, CfbEntryType> = { 1: "storage", 2: "stream", 5: "root" };

/** Builds the storage tree; every entry may be reached once (cycles and shared nodes fail). */
function buildTree(raw: readonly RawEntry[]): { root: CfbEntry; entries: CfbEntry[] } {
	const visited = new Set<number>();
	const all: CfbEntry[] = [];
	const rootRaw = raw[0];
	if (!rootRaw || rootRaw.type !== 5) throw new CfbError("MALFORMED");
	visited.add(0);

	const childrenOf = (first: number, parentPath: string, depth: number): CfbEntry[] => {
		const out: CfbEntry[] = [];
		// In-order walk of the red-black sibling tree, iterative to bound the stack.
		const stack: number[] = [];
		let current = first;
		while (current !== NOSTREAM || stack.length > 0) {
			while (current !== NOSTREAM) {
				const node = raw[current];
				if (!node || node.type === 0 || node.type === 5 || visited.has(current))
					throw new CfbError("MALFORMED");
				visited.add(current);
				stack.push(current);
				current = node.left;
			}
			const index = stack.pop() as number;
			const node = raw[index] as RawEntry;
			const type = ENTRY_TYPES[node.type];
			if (!type) throw new CfbError("MALFORMED");
			const path = parentPath ? `${parentPath}/${node.name}` : node.name;
			const children: CfbEntry[] = [];
			const entry: CfbEntry = {
				name: node.name,
				path,
				type,
				size: type === "stream" ? node.size : 0,
				children,
				start: node.start,
			};
			all.push(entry);
			out.push(entry);
			if (type === "storage" && node.child !== NOSTREAM) {
				if (depth >= 32) throw new CfbError("LIMIT");
				children.push(...childrenOf(node.child, path, depth + 1));
			}
			current = node.right;
		}
		return out;
	};

	const children = childrenOf(rootRaw.child, "", 0);
	const root: CfbEntry = {
		name: rootRaw.name,
		path: "",
		type: "root",
		size: rootRaw.size,
		children,
		start: rootRaw.start,
	};
	return { root, entries: all };
}

/** Parses a compound file's header, FAT and directory. Throws `CfbError`. */
export function readCompoundFile(
	bytes: Uint8Array,
	limits: CfbLimits = DEFAULT_CFB_LIMITS,
): CompoundFile {
	if (!isCompoundFile(bytes)) throw new CfbError("NOT_CFB");
	if (bytes.length > limits.maxFileBytes) throw new CfbError("LIMIT");
	if (bytes.length < 512) throw new CfbError("MALFORMED");
	const reader = new Reader(bytes, limits);
	reader.loadFat();
	const raw = parseEntries(reader.readDirectory(), reader.u16(0x1a));
	const rootRaw = raw[0];
	if (!rootRaw) throw new CfbError("MALFORMED");
	reader.loadMini(rootRaw);
	const { root, entries } = buildTree(raw);
	return {
		root,
		entries,
		child: (name) => childEntry(root, name),
		read(entry) {
			if (entry.type !== "stream") throw new CfbError("MALFORMED");
			return reader.readStream(entry.start, entry.size);
		},
	};
}
