/**
 * PDF stream filters other than FlateDecode (which uses ../office/deflate.ts): LZWDecode,
 * ASCIIHexDecode, ASCII85Decode and RunLengthDecode (ISO 32000-1 §7.4). Output is bounded by
 * the caller's byte limit; a decoder returns null once it would exceed it.
 */

export interface Decoded {
	readonly data: Uint8Array;
	/** False when the input ended before its end-of-data marker or was corrupt. */
	readonly complete: boolean;
}

function hexValue(c: number): number {
	if (c >= 0x30 && c <= 0x39) return c - 48;
	const lower = c | 0x20;
	return lower >= 0x61 && lower <= 0x66 ? lower - 87 : -1;
}

export function asciiHexDecode(data: Uint8Array): Uint8Array {
	const out: number[] = [];
	let high = -1;
	for (const c of data) {
		if (c === 0x3e) break; // ">" end of data
		const v = hexValue(c);
		if (v < 0) continue;
		if (high < 0) high = v;
		else {
			out.push(high * 16 + v);
			high = -1;
		}
	}
	if (high >= 0) out.push(high * 16);
	return Uint8Array.from(out);
}

/** Appends the first `n` bytes of a base-85 group. */
function push85(group: readonly number[], out: number[], n: number): void {
	let v = 0;
	for (const g of group) v = v * 85 + g;
	const bytes = [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
	out.push(...bytes.slice(0, n));
}

export function ascii85Decode(data: Uint8Array): Uint8Array {
	const out: number[] = [];
	const group: number[] = [];
	for (const c of data) {
		if (c === 0x7e) break; // "~>" end of data
		if (c === 0x7a && group.length === 0) {
			out.push(0, 0, 0, 0); // "z"
			continue;
		}
		if (c < 0x21 || c > 0x75) continue; // whitespace and invalid bytes
		group.push(c - 33);
		if (group.length === 5) {
			push85(group, out, 4);
			group.length = 0;
		}
	}
	if (group.length > 1) {
		const n = group.length - 1;
		while (group.length < 5) group.push(84);
		push85(group, out, n);
	}
	return Uint8Array.from(out);
}

export function runLengthDecode(data: Uint8Array, limit: number): Decoded | null {
	const out: number[] = [];
	let i = 0;
	while (i < data.length && data[i] !== 128) {
		const len = data[i] as number;
		if (len < 128) {
			out.push(...data.subarray(i + 1, Math.min(data.length, i + len + 2)));
			i += len + 2;
		} else {
			const byte = data[i + 1];
			if (byte === undefined) return { data: Uint8Array.from(out), complete: false };
			for (let k = 0; k < 257 - len; k++) out.push(byte);
			i += 2;
		}
		if (out.length > limit) return null;
	}
	return { data: Uint8Array.from(out), complete: i < data.length };
}

const LZW_CLEAR = 256;
const LZW_EOD = 257;

/** LZW with 9..12-bit codes, EarlyChange = 1 (the PDF default). */
class LzwDecoder {
	private table: number[][] = [];
	private codeLength = 9;
	private prev: number[] | null = null;
	readonly out: number[] = [];

	constructor() {
		this.reset();
	}

	private reset(): void {
		this.table = [];
		for (let i = 0; i < 256; i++) this.table.push([i]);
		this.table.push([], []);
		this.codeLength = 9;
		this.prev = null;
	}

	get width(): number {
		return this.codeLength;
	}

	/** Handles one code; returns "done" at end of data, "error" for an invalid code. */
	code(code: number): "more" | "done" | "error" {
		if (code === LZW_CLEAR) {
			this.reset();
			return "more";
		}
		if (code === LZW_EOD) return "done";
		const entry = this.entry(code);
		if (!entry) return "error";
		this.out.push(...entry);
		if (this.prev && this.table.length < 4096) this.table.push([...this.prev, entry[0] as number]);
		this.prev = entry;
		if (this.table.length + 1 >= 1 << this.codeLength && this.codeLength < 12) this.codeLength++;
		return "more";
	}

	private entry(code: number): number[] | null {
		const known = code < this.table.length ? this.table[code] : undefined;
		if (known && (code < 258 || known.length > 0)) return known;
		// The KwKwK case: the code being defined right now.
		if (code === this.table.length && this.prev) return [...this.prev, this.prev[0] as number];
		return null;
	}
}

export function lzwDecode(data: Uint8Array, limit: number): Decoded | null {
	const decoder = new LzwDecoder();
	let buffer = 0;
	let bits = 0;
	for (const byte of data) {
		buffer = ((buffer << 8) | byte) & 0xffffff;
		bits += 8;
		while (bits >= decoder.width) {
			const width = decoder.width;
			const code = (buffer >>> (bits - width)) & ((1 << width) - 1);
			bits -= width;
			const state = decoder.code(code);
			if (state !== "more")
				return { data: Uint8Array.from(decoder.out), complete: state === "done" };
			if (decoder.out.length > limit) return null;
		}
	}
	return { data: Uint8Array.from(decoder.out), complete: false };
}

// ---------------------------------------------------------------------------------------------
// PNG predictors (ISO 32000-1 §7.4.4.4)
// ---------------------------------------------------------------------------------------------

function paeth(a: number, b: number, c: number): number {
	const p = a + b - c;
	const pa = Math.abs(p - a);
	const pb = Math.abs(p - b);
	const pc = Math.abs(p - c);
	return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/** PNG filter types 0-4: the prediction added back to each byte. */
const PNG_PREDICTORS: ReadonlyArray<(left: number, up: number, upLeft: number) => number> = [
	() => 0,
	(left) => left,
	(_left, up) => up,
	(left, up) => (left + up) >> 1,
	paeth,
];

/**
 * Reverses PNG row predictors: each row is a filter-type byte plus `rowBytes` bytes, `bpp`
 * bytes per pixel. A trailing partial row is dropped; null on an unknown filter type.
 */
export function unpredictPngRows(
	data: Uint8Array,
	rowBytes: number,
	bpp: number,
): Uint8Array | null {
	const rows = Math.floor(data.length / (rowBytes + 1));
	const out = new Uint8Array(rows * rowBytes);
	for (let r = 0; r < rows; r++) {
		const predict = PNG_PREDICTORS[data[r * (rowBytes + 1)] as number];
		if (!predict) return null;
		const src = r * (rowBytes + 1) + 1;
		const dst = r * rowBytes;
		const prev = dst - rowBytes;
		for (let i = 0; i < rowBytes; i++) {
			const left = i >= bpp ? (out[dst + i - bpp] as number) : 0;
			const up = r > 0 ? (out[prev + i] as number) : 0;
			const upLeft = r > 0 && i >= bpp ? (out[prev + i - bpp] as number) : 0;
			out[dst + i] = ((data[src + i] as number) + predict(left, up, upLeft)) & 0xff;
		}
	}
	return out;
}
