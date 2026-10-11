/**
 * Shared plumbing for the legacy Office extractors: byte readers, the 8-bit/UTF-16 decoders
 * the binary formats use, and the collector that accumulates text segments under a budget.
 */
import { decodeSingleByte } from "../codepages.js";

/** A text segment for detection; `context` is a spreadsheet column header ("" otherwise). */
export interface LegacySegment {
	readonly context: string;
	readonly value: string;
}

/** Why an extraction is not complete (codes are stable and never contain document data). */
export type LegacyGap = "LEGACY_OFFICE_PARTIAL" | "LEGACY_OFFICE_UNSUPPORTED";

export interface LegacyLimits {
	/** Characters extracted across the whole file (embedded objects included). */
	readonly maxChars: number;
	/** Nesting depth of embedded objects that are opened and scanned. */
	readonly maxEmbedDepth: number;
	/** Embedded objects opened per file. */
	readonly maxEmbedded: number;
	/** Bytes a compressed embedded object may inflate to. */
	readonly maxEmbeddedBytes: number;
}

export const DEFAULT_LEGACY_LIMITS: LegacyLimits = {
	maxChars: 8_000_000,
	maxEmbedDepth: 3,
	maxEmbedded: 32,
	maxEmbeddedBytes: 32 * 1024 * 1024,
};

/** Segments are grouped up to this many characters (detection runs over all of them). */
const SEGMENT_CHARS = 4000;

export class Collector {
	readonly segments: LegacySegment[] = [];
	readonly gaps = new Set<LegacyGap>();
	images = false;
	embedded = 0;
	private chars = 0;

	constructor(
		readonly limits: LegacyLimits,
		readonly checkDeadline: () => void,
	) {}

	/** True once the character budget is spent (further text is dropped, extraction partial). */
	get full(): boolean {
		return this.chars >= this.limits.maxChars;
	}

	gap(reason: LegacyGap): void {
		this.gaps.add(reason);
	}

	/** Adds one value (a cell, a string) as its own segment. */
	add(value: string, context = ""): void {
		const clean = cleanText(value);
		if (!clean.trim()) return;
		if (this.chars + clean.length > this.limits.maxChars) {
			this.gap("LEGACY_OFFICE_PARTIAL");
			return;
		}
		this.chars += clean.length;
		this.segments.push({ context, value: clean });
	}

	/** Adds running text (a document body), grouped by lines into bounded segments. */
	addText(text: string): void {
		let group = "";
		for (const line of cleanText(text).split("\n")) {
			if (group && group.length + line.length + 1 > SEGMENT_CHARS) {
				this.add(group);
				group = "";
			}
			group = group ? `${group}\n${line}` : line;
			while (group.length > SEGMENT_CHARS) {
				this.add(group.slice(0, SEGMENT_CHARS));
				group = group.slice(SEGMENT_CHARS);
			}
		}
		this.add(group);
		this.checkDeadline();
	}
}

/**
 * Normalises binary-format control characters: paragraph/line/page/section marks become
 * newlines, Word cell marks tabs, other C0 controls (field marks, object anchors) spaces.
 */
function cleanText(text: string): string {
	return text
		.replace(/\r\n?|[\u000b\u000c]/g, "\n")
		.replace(/[\u0000-\u0008\u000e-\u001f\u007f]/g, (c) => (c === "\u0007" ? "\t" : " "));
}

/** Single-byte text as windows-1252 (Word's "compressed" pieces). */
export function decodeCp1252(bytes: Uint8Array): string {
	return decodeSingleByte(bytes, "windows-1252");
}

/** Single-byte text whose high byte was dropped (BIFF8 / PowerPoint "8-bit" strings). */
export function decodeLatin1(bytes: Uint8Array): string {
	let out = "";
	for (let i = 0; i < bytes.length; i += 8192)
		out += String.fromCharCode(...bytes.subarray(i, i + 8192));
	return out;
}

export function decodeUtf16le(bytes: Uint8Array): string {
	let out = "";
	const n = bytes.length >> 1;
	for (let i = 0; i < n; i += 8192) {
		const codes: number[] = [];
		for (let j = i; j < Math.min(n, i + 8192); j++)
			codes.push((bytes[j * 2] ?? 0) | ((bytes[j * 2 + 1] ?? 0) << 8));
		out += String.fromCharCode(...codes);
	}
	return out;
}

/** Text in a Windows code page (property sets); unknown code pages fall back to windows-1252. */
export function decodeCodePage(bytes: Uint8Array, codePage: number): string {
	if (codePage === 1200) return decodeUtf16le(bytes);
	// Fixed tables for the Western/Turkish code pages (TextDecoder may decode 1252 as Latin-1).
	if (codePage === 1252) return decodeSingleByte(bytes, "windows-1252");
	if (codePage === 1254) return decodeSingleByte(bytes, "windows-1254");
	const label = codePage === 65001 ? "utf-8" : `windows-${codePage}`;
	try {
		return new TextDecoder(label).decode(bytes);
	} catch {
		return decodeCp1252(bytes);
	}
}

/** Bounds-checked little-endian reads; out-of-range reads throw `RangeError`. */
export class Bytes {
	readonly view: DataView;

	constructor(readonly data: Uint8Array) {
		this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	}

	get length(): number {
		return this.data.length;
	}

	u8(offset: number): number {
		return this.view.getUint8(offset);
	}

	u16(offset: number): number {
		return this.view.getUint16(offset, true);
	}

	i16(offset: number): number {
		return this.view.getInt16(offset, true);
	}

	u32(offset: number): number {
		return this.view.getUint32(offset, true);
	}

	f64(offset: number): number {
		return this.view.getFloat64(offset, true);
	}

	/** `length` bytes from `offset`; throws when they are not all present. */
	slice(offset: number, length: number): Uint8Array {
		if (offset < 0 || length < 0 || offset + length > this.data.length)
			throw new RangeError("out of range");
		return this.data.subarray(offset, offset + length);
	}
}
