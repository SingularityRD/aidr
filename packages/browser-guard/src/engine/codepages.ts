/**
 * Explicit windows-1252 / windows-1254 decoders (WHATWG Encoding Standard indexes).
 *
 * `TextDecoder` is not a dependable source for these code pages: some runtimes decode
 * "windows-1252" (and its aliases "latin1"/"iso-8859-1") with a Latin-1 fast path that turns
 * 0x80..0x9F into C1 controls instead of `€ ‚ ƒ … Š Œ Ž ‘ ’ “ ” – — ˜ ™ š œ ž Ÿ` (seen on
 * Node 22.22). The detection result must not depend on the runtime, so the two single-byte
 * code pages the engine reads are decoded from fixed tables here.
 *
 * Both code pages are ISO-8859-1 outside 0x80..0x9F, except six Turkish letters in
 * windows-1254. Positions a code page leaves undefined decode to the C1 control of the same
 * value (WHATWG behaviour), which callers count as "undefined bytes".
 */

/** windows-1252 code points for 0x80..0x9F (undefined positions stay as C1 controls). */
const CP1252_HIGH: readonly number[] = [
	0x20ac, 0x81, 0x201a, 0x192, 0x201e, 0x2026, 0x2020, 0x2021, 0x2c6, 0x2030, 0x160, 0x2039, 0x152,
	0x8d, 0x17d, 0x8f, 0x90, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013, 0x2014, 0x2dc, 0x2122,
	0x161, 0x203a, 0x153, 0x9d, 0x17e, 0x178,
];

/** windows-1254 differs from windows-1252 at these bytes (Ž/ž are undefined in 1254). */
const CP1254_DIFF: Readonly<Record<number, number>> = {
	0x8e: 0x8e,
	0x9e: 0x9e,
	0xd0: 0x11e, // Ğ
	0xdd: 0x130, // İ
	0xde: 0x15e, // Ş
	0xf0: 0x11f, // ğ
	0xfd: 0x131, // ı
	0xfe: 0x15f, // ş
};

export type SingleByteCodePage = "windows-1252" | "windows-1254";

function buildTable(codePage: SingleByteCodePage): Uint16Array {
	const table = new Uint16Array(256);
	for (let b = 0; b < 256; b++)
		table[b] = b >= 0x80 && b <= 0x9f ? (CP1252_HIGH[b - 0x80] ?? b) : b;
	if (codePage === "windows-1254")
		for (const [b, cp] of Object.entries(CP1254_DIFF)) table[Number(b)] = cp;
	return table;
}

const TABLES: Readonly<Record<SingleByteCodePage, Uint16Array>> = {
	"windows-1252": buildTable("windows-1252"),
	"windows-1254": buildTable("windows-1254"),
};

/** Code point of `byte` in `codePage`. */
export function codePageChar(codePage: SingleByteCodePage, byte: number): number {
	return TABLES[codePage][byte & 0xff] as number;
}

/** Decodes single-byte text (never throws; every byte maps to one UTF-16 unit). */
export function decodeSingleByte(bytes: Uint8Array, codePage: SingleByteCodePage): string {
	const table = TABLES[codePage];
	let out = "";
	for (let i = 0; i < bytes.length; i += 8192) {
		const chunk = bytes.subarray(i, i + 8192);
		out += String.fromCharCode(...Array.from(chunk, (b) => table[b] as number));
	}
	return out;
}
