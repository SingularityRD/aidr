/**
 * Simple-font encodings (ISO 32000-1 Annex D) and a glyph-name -> Unicode subset.
 *
 * The glyph list covers ASCII, Latin-1, Latin Extended-A (all Turkish letters: ğ Ğ ı İ ş Ş
 * ç Ç ö Ö ü Ü) and common punctuation/ligatures, plus the algorithmic `uniXXXX` / `uXXXX[XX]`
 * forms and `.suffix` / `_ligature` names. That is what Latin-script text needs; glyph names
 * outside it are reported as unmapped so the extractor can flag the page as unreliable.
 */
import { codePageChar } from "../codepages.js";

const ASCII_NAMES =
	"space exclam quotedbl numbersign dollar percent ampersand quotesingle parenleft parenright asterisk plus comma hyphen period slash zero one two three four five six seven eight nine colon semicolon less equal greater question at A B C D E F G H I J K L M N O P Q R S T U V W X Y Z bracketleft backslash bracketright asciicircum underscore grave a b c d e f g h i j k l m n o p q r s t u v w x y z braceleft bar braceright asciitilde";

/** U+00A0..U+00FF. */
const LATIN1_NAMES =
	"nbspace exclamdown cent sterling currency yen brokenbar section dieresis copyright ordfeminine guillemotleft logicalnot sfthyphen registered macron degree plusminus twosuperior threesuperior acute mu paragraph periodcentered cedilla onesuperior ordmasculine guillemotright onequarter onehalf threequarters questiondown Agrave Aacute Acircumflex Atilde Adieresis Aring AE Ccedilla Egrave Eacute Ecircumflex Edieresis Igrave Iacute Icircumflex Idieresis Eth Ntilde Ograve Oacute Ocircumflex Otilde Odieresis multiply Oslash Ugrave Uacute Ucircumflex Udieresis Yacute Thorn germandbls agrave aacute acircumflex atilde adieresis aring ae ccedilla egrave eacute ecircumflex edieresis igrave iacute icircumflex idieresis eth ntilde ograve oacute ocircumflex otilde odieresis divide oslash ugrave uacute ucircumflex udieresis yacute thorn ydieresis";

/** U+0100..U+017F. */
const LATIN_EXT_A_NAMES =
	"Amacron amacron Abreve abreve Aogonek aogonek Cacute cacute Ccircumflex ccircumflex Cdotaccent cdotaccent Ccaron ccaron Dcaron dcaron Dcroat dcroat Emacron emacron Ebreve ebreve Edotaccent edotaccent Eogonek eogonek Ecaron ecaron Gcircumflex gcircumflex Gbreve gbreve Gdotaccent gdotaccent Gcommaaccent gcommaaccent Hcircumflex hcircumflex Hbar hbar Itilde itilde Imacron imacron Ibreve ibreve Iogonek iogonek Idotaccent dotlessi IJ ij Jcircumflex jcircumflex Kcommaaccent kcommaaccent kgreenlandic Lacute lacute Lcommaaccent lcommaaccent Lcaron lcaron Ldot ldot Lslash lslash Nacute nacute Ncommaaccent ncommaaccent Ncaron ncaron napostrophe Eng eng Omacron omacron Obreve obreve Ohungarumlaut ohungarumlaut OE oe Racute racute Rcommaaccent rcommaaccent Rcaron rcaron Sacute sacute Scircumflex scircumflex Scedilla scedilla Scaron scaron Tcommaaccent tcommaaccent Tcaron tcaron Tbar tbar Utilde utilde Umacron umacron Ubreve ubreve Uring uring Uhungarumlaut uhungarumlaut Uogonek uogonek Wcircumflex wcircumflex Ycircumflex ycircumflex Ydieresis Zacute zacute Zdotaccent zdotaccent Zcaron zcaron longs";

const EXTRA_GLYPHS: Readonly<Record<string, string>> = {
	quoteleft: "‘",
	quoteright: "’",
	quotesinglbase: "‚",
	quotedblleft: "“",
	quotedblright: "”",
	quotedblbase: "„",
	endash: "–",
	emdash: "—",
	bullet: "•",
	ellipsis: "…",
	dagger: "†",
	daggerdbl: "‡",
	perthousand: "‰",
	guilsinglleft: "‹",
	guilsinglright: "›",
	fraction: "⁄",
	Euro: "€",
	trademark: "™",
	minus: "−",
	florin: "ƒ",
	circumflex: "ˆ",
	caron: "ˇ",
	breve: "˘",
	dotaccent: "˙",
	ring: "˚",
	ogonek: "˛",
	tilde: "˜",
	hungarumlaut: "˝",
	fi: "fi",
	fl: "fl",
	ff: "ff",
	ffi: "ffi",
	ffl: "ffl",
	Tcedilla: "Ţ",
	tcedilla: "ţ",
	Gcedilla: "Ģ",
	gcedilla: "ģ",
	dotlessj: "ȷ",
	nonbreakingspace: " ",
	uni00A0: " ",
	middot: "·",
	registerserif: "®",
	copyrightserif: "©",
	lira: "₤",
	liraturkish: "₺",
	Lira: "₺",
	numero: "№",
	space2: " ",
};

function buildGlyphTable(): Map<string, string> {
	const table = new Map<string, string>();
	ASCII_NAMES.split(" ").forEach((n, i) => {
		table.set(n, String.fromCharCode(0x20 + i));
	});
	LATIN1_NAMES.split(" ").forEach((n, i) => {
		table.set(n, String.fromCharCode(0xa0 + i));
	});
	LATIN_EXT_A_NAMES.split(" ").forEach((n, i) => {
		table.set(n, String.fromCharCode(0x100 + i));
	});
	for (const [n, v] of Object.entries(EXTRA_GLYPHS)) table.set(n, v);
	table.set("hyphen", "-");
	table.set("sfthyphen", "­");
	return table;
}

const GLYPHS = buildGlyphTable();

function codePoints(hex: string): string | undefined {
	const cp = Number.parseInt(hex, 16);
	if (!(cp >= 0 && cp <= 0x10ffff) || (cp >= 0xd800 && cp <= 0xdfff)) return undefined;
	return String.fromCodePoint(cp);
}

/** Unicode text for a glyph name, or undefined when the name is not known. */
export function glyphToUnicode(name: string): string | undefined {
	const direct = GLYPHS.get(name);
	if (direct !== undefined) return direct;
	const base = name.includes(".") ? name.slice(0, name.indexOf(".")) : name;
	if (base !== name && base) return glyphToUnicode(base);
	if (base.includes("_")) {
		const parts = base.split("_").map(glyphToUnicode);
		return parts.every((p) => p !== undefined) ? parts.join("") : undefined;
	}
	let m = /^uni((?:[0-9A-F]{4})+)$/.exec(base);
	if (m?.[1]) {
		let out = "";
		for (let i = 0; i < m[1].length; i += 4) {
			const ch = codePoints(m[1].slice(i, i + 4));
			if (ch === undefined) return undefined;
			out += ch;
		}
		return out;
	}
	m = /^u([0-9A-F]{4,6})$/.exec(base);
	if (m?.[1]) return codePoints(m[1]);
	return undefined;
}

export type BaseEncoding =
	| "WinAnsiEncoding"
	| "MacRomanEncoding"
	| "StandardEncoding"
	| "PDFDocEncoding";

/** StandardEncoding codes above 0x7F (and the two ASCII differences). */
const STANDARD_HIGH: Readonly<Record<number, string>> = {
	0x27: "quoteright",
	0x60: "quoteleft",
	0xa1: "exclamdown",
	0xa2: "cent",
	0xa3: "sterling",
	0xa4: "fraction",
	0xa5: "yen",
	0xa6: "florin",
	0xa7: "section",
	0xa8: "currency",
	0xa9: "quotesingle",
	0xaa: "quotedblleft",
	0xab: "guillemotleft",
	0xac: "guilsinglleft",
	0xad: "guilsinglright",
	0xae: "fi",
	0xaf: "fl",
	0xb1: "endash",
	0xb2: "dagger",
	0xb3: "daggerdbl",
	0xb4: "periodcentered",
	0xb6: "paragraph",
	0xb7: "bullet",
	0xb8: "quotesinglbase",
	0xb9: "quotedblbase",
	0xba: "quotedblright",
	0xbb: "guillemotright",
	0xbc: "ellipsis",
	0xbd: "perthousand",
	0xbf: "questiondown",
	0xc1: "grave",
	0xc2: "acute",
	0xc3: "circumflex",
	0xc4: "tilde",
	0xc5: "macron",
	0xc6: "breve",
	0xc7: "dotaccent",
	0xc8: "dieresis",
	0xca: "ring",
	0xcb: "cedilla",
	0xcd: "hungarumlaut",
	0xce: "ogonek",
	0xcf: "caron",
	0xd0: "emdash",
	0xe1: "AE",
	0xe3: "ordfeminine",
	0xe8: "Lslash",
	0xe9: "Oslash",
	0xea: "OE",
	0xeb: "ordmasculine",
	0xf1: "ae",
	0xf5: "dotlessi",
	0xf8: "lslash",
	0xf9: "oslash",
	0xfa: "oe",
	0xfb: "germandbls",
};

/** PDFDocEncoding differences from Latin-1 (0x18..0x1F and 0x80..0x9F). */
const PDFDOC_DIFF: Readonly<Record<number, string>> = {
	0x18: "˘",
	0x19: "ˇ",
	0x1a: "ˆ",
	0x1b: "˙",
	0x1c: "˝",
	0x1d: "˛",
	0x1e: "˚",
	0x1f: "˜",
	0x80: "•",
	0x81: "†",
	0x82: "‡",
	0x83: "…",
	0x84: "—",
	0x85: "–",
	0x86: "ƒ",
	0x87: "⁄",
	0x88: "‹",
	0x89: "›",
	0x8a: "−",
	0x8b: "‰",
	0x8c: "„",
	0x8d: "“",
	0x8e: "”",
	0x8f: "‘",
	0x90: "’",
	0x91: "‚",
	0x92: "™",
	0x93: "ﬁ",
	0x94: "ﬂ",
	0x95: "Ł",
	0x96: "Œ",
	0x97: "Š",
	0x98: "Ÿ",
	0x99: "Ž",
	0x9a: "ı",
	0x9b: "ł",
	0x9c: "œ",
	0x9d: "š",
	0x9e: "ž",
	0xa0: "€",
};

function singleByteTable(label: string): Array<string | undefined> {
	const table: Array<string | undefined> = new Array(256).fill(undefined);
	let decoder: TextDecoder | null = null;
	try {
		decoder = new TextDecoder(label);
	} catch {
		decoder = null;
	}
	for (let code = 0x20; code < 256; code++) {
		if (code === 0x7f) continue;
		const ch = decoder ? decoder.decode(new Uint8Array([code])) : String.fromCharCode(code);
		// WHATWG maps undefined bytes to C1 controls: leave those unmapped.
		if (ch.length === 1 && ch.charCodeAt(0) >= 0x80 && ch.charCodeAt(0) <= 0x9f) continue;
		table[code] = ch;
	}
	return table;
}

/** WinAnsiEncoding from a fixed windows-1252 table (TextDecoder may decode it as Latin-1). */
function winAnsiTable(): Array<string | undefined> {
	const table: Array<string | undefined> = new Array(256).fill(undefined);
	for (let code = 0x20; code < 256; code++) {
		if (code === 0x7f) continue;
		const cp = codePageChar("windows-1252", code);
		// Bytes windows-1252 leaves undefined decode to C1 controls: leave those unmapped.
		if (cp >= 0x80 && cp <= 0x9f) continue;
		table[code] = String.fromCharCode(cp);
	}
	return table;
}

function standardTable(): Array<string | undefined> {
	const table: Array<string | undefined> = new Array(256).fill(undefined);
	for (let code = 0x20; code < 0x7f; code++) table[code] = String.fromCharCode(code);
	for (const [code, name] of Object.entries(STANDARD_HIGH))
		table[Number(code)] = glyphToUnicode(name);
	return table;
}

function pdfDocTable(): Array<string | undefined> {
	const table: Array<string | undefined> = new Array(256).fill(undefined);
	for (let code = 0x20; code < 256; code++) {
		if (code === 0x7f || (code >= 0x80 && code <= 0xa0)) continue;
		table[code] = String.fromCharCode(code);
	}
	for (const [code, ch] of Object.entries(PDFDOC_DIFF)) table[Number(code)] = ch;
	for (const ws of [0x09, 0x0a, 0x0d]) table[ws] = String.fromCharCode(ws);
	return table;
}

const TABLES = new Map<BaseEncoding, Array<string | undefined>>();

/** Code -> Unicode table for a named base encoding (built once, lazily). */
export function baseEncoding(name: BaseEncoding): ReadonlyArray<string | undefined> {
	let table = TABLES.get(name);
	if (!table) {
		if (name === "WinAnsiEncoding") table = winAnsiTable();
		else if (name === "MacRomanEncoding") table = singleByteTable("macintosh");
		else if (name === "PDFDocEncoding") table = pdfDocTable();
		else table = standardTable();
		TABLES.set(name, table);
	}
	return table;
}

/**
 * Decodes a PDF text string (document info, annotation contents, form values):
 * UTF-16BE or UTF-8 with a byte-order mark, otherwise PDFDocEncoding.
 */
export function decodeTextString(bytes: string): string {
	if (bytes.startsWith("þÿ")) {
		let out = "";
		for (let i = 2; i + 1 < bytes.length; i += 2)
			out += String.fromCharCode((bytes.charCodeAt(i) << 8) | bytes.charCodeAt(i + 1));
		return out;
	}
	if (bytes.startsWith("ï»¿")) {
		const raw = new Uint8Array(bytes.length - 3);
		for (let i = 3; i < bytes.length; i++) raw[i - 3] = bytes.charCodeAt(i);
		return new TextDecoder("utf-8").decode(raw);
	}
	const table = baseEncoding("PDFDocEncoding");
	let out = "";
	for (let i = 0; i < bytes.length; i++) out += table[bytes.charCodeAt(i)] ?? "";
	return out;
}
