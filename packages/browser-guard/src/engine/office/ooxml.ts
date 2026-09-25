/**
 * Office Open XML (DOCX / XLSX / PPTX and their macro/template variants) sanitisation.
 *
 * `sanitizeOoxml` opens the package with the defensive ZIP reader, refuses packages that
 * cannot be shared safely, masks text in place and re-zips the package:
 *
 *   Refused (`DocumentRefused`, the caller blocks):
 *     DOCUMENT_ENCRYPTED        password-protected package (an OLE compound file holding an
 *                               `EncryptedPackage` stream instead of a ZIP);
 *     DOCUMENT_MACROS           VBA projects (`vbaProject.bin`, `vbaData.xml`, macro-enabled
 *                               content types) or ActiveX controls;
 *     DOCUMENT_EXTERNAL_LINKS   external workbook links, data connections, remote templates,
 *                               linked OLE objects, sub-documents, frames, mail-merge sources
 *                               (plain hyperlinks are allowed; their targets are scanned);
 *     DOCUMENT_EMBEDDED_OBJECT  embedded objects that are not themselves OOXML packages
 *                               (embedded DOCX/XLSX/PPTX, e.g. chart data, are sanitised
 *                               recursively, up to {@link MAX_DEPTH} levels);
 *     ARCHIVE_*                 unsafe ZIP structure (see ./zip.ts);
 *     DOCUMENT_MALFORMED        a text part that is not well-formed XML or cannot be rewritten.
 *   Unreadable (`DocumentUnreadable`, the caller treats the file as an unscanned binary):
 *     DOCUMENT_UNPARSEABLE      not a ZIP / OLE file, or a ZIP without an Office main part.
 *
 * Text handled (everything else is copied byte-for-byte):
 *   DOCX  document, headers, footers, footnotes, endnotes, comments, glossary: `w:p`
 *         paragraphs over `w:t` / `w:delText` / `w:instrText` / `m:t` runs, so text split
 *         across runs is detected and masked as a whole; tracked-change and comment authors;
 *         alt text (`descr`/`title`); `people.xml` identities.
 *   XLSX  shared strings (rich text runs), inline strings, formula string results and
 *         numeric/date cell values (a masked number becomes an inline string; a formula
 *         cell keeps its formula and gets a string result), header/footer text, comments,
 *         threaded comments, persons, pivot cache strings. A column whose header names a
 *         sensitive field (same dictionary as CSV) is masked wholesale.
 *   PPTX  slides, notes, layouts, masters, comments, comment authors.
 *   All   DrawingML text in charts/diagrams/drawings, document properties, external
 *         relationship targets (e.g. `mailto:` hyperlinks), and every other XML part
 *         generically (each text node on its own), except purely structural parts.
 */
import type { EntityType, Finding, SignalCode } from "../../types.js";
import { type Counts, countFindings, mergeCounts } from "../counts.js";
import {
	blankThumbnail,
	emptyImageSummary,
	type ImageSummary,
	inspectImages,
	isImageEntry,
	isThumbnail,
	OCR_BUDGET_MS,
} from "./images.js";
import type { DocScanner } from "./scanner.js";
import {
	applyReplacements,
	assertWellFormed,
	type Edit,
	escapeXmlText,
	extractText,
	type Leaf,
	LeafTracker,
	localName,
	type Piece,
	piecesSegment,
	type RawReplacement,
	spliceEdits,
	type TextSegment,
	type TextSpec,
	walkXml,
	XmlError,
	type XmlTag,
} from "./xml.js";
import {
	ArchiveError,
	DEFAULT_ZIP_LIMITS,
	findEntry,
	readEntry,
	readZip,
	rewriteZip,
	type ZipArchive,
	type ZipEntry,
	type ZipLimits,
} from "./zip.js";

/** Nesting levels of embedded packages that are opened (the outer document is level 0). */
const MAX_DEPTH = 2;

/** The package must be blocked; `reasons` are stable codes. */
export class DocumentRefused extends Error {
	constructor(readonly reasons: readonly string[]) {
		super(reasons.join(","));
		this.name = "DocumentRefused";
	}
}

/** The package could not be read at all; the caller applies its unscanned-binary rule. */
export class DocumentUnreadable extends Error {
	constructor(readonly reason: string) {
		super(reason);
		this.name = "DocumentUnreadable";
	}
}

export interface DocumentOutcome {
	/** The rewritten package, or null when nothing was changed. */
	readonly bytes: Uint8Array | null;
	readonly findings: number;
	readonly findingCounts: Counts;
	readonly signals: ReadonlySet<SignalCode>;
	/** Pictures in the package (see ./images.ts). */
	readonly images: ImageSummary;
}

export const OOXML_EXTENSIONS: ReadonlySet<string> = new Set([
	"docx",
	"docm",
	"dotx",
	"dotm",
	"xlsx",
	"xlsm",
	"xltx",
	"xltm",
	"xlam",
	"pptx",
	"pptm",
	"potx",
	"potm",
	"ppsx",
	"ppsm",
	"ppam",
]);

const CFB_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] as const;

export function isCompoundFile(bytes: Uint8Array): boolean {
	return CFB_MAGIC.every((b, i) => bytes[i] === b);
}

/** UTF-16LE "EncryptedPackage" (the stream name of an encrypted OOXML package). */
function containsEncryptedPackage(bytes: Uint8Array): boolean {
	const name = "EncryptedPackage";
	const needle = new Uint8Array(name.length * 2);
	for (let i = 0; i < name.length; i++) needle[i * 2] = name.charCodeAt(i);
	outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
		for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
		return true;
	}
	return false;
}

// ---------------------------------------------------------------------------------------------
// Part classification
// ---------------------------------------------------------------------------------------------

const MACRO_PART =
	/(?:^|\/)(?:vbaproject\.bin|vbadata\.xml|vbaprojectsignature[a-z]*\.bin)$|(?:^|\/)activex\//i;
const MACRO_CONTENT_TYPE = /vbaProject|macroEnabled|ms-office\.activeX/i;
const EXTERNAL_PART = /^xl\/(?:externallinks\/|connections\.xml$)/i;
const EXTERNAL_REL_TYPES: ReadonlySet<string> = new Set([
	"externallink",
	"externallinkpath",
	"attachedtemplate",
	"oleobject",
	"subdocument",
	"frame",
	"mailmergesource",
	"mailmergeheadersource",
	"recipientdata",
	"xlexternallinkpath",
	"xlpathmissing",
	"connections",
]);
const EMBEDDING = /(?:^|\/)embeddings\/[^/]+$/i;
const MAIN_PARTS = ["word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"] as const;

/** Parts that carry structure only (styles, themes, settings...): never rewritten. */
const STRUCTURAL =
	/^\[content_types\]\.xml$|(?:^|\/)(?:styles|styleswitheffects|settings|fonttable|websettings|numbering|calcchain|presprops|viewprops|tablestyles|workbook|presentation)\.xml$|(?:^|\/)theme\/|^xl\/tables\/|^customxml\/itemprops\d*\.xml$|(?:^|\/)(?:commentsids|commentsextended|commentsextensible)\.xml$/i;

type PartKind =
	| "word"
	| "people"
	| "sst"
	| "sheet"
	| "xlComments"
	| "threaded"
	| "persons"
	| "pivot"
	| "drawing"
	| "pptAuthors"
	| "rels"
	| "generic";

function partKind(name: string): PartKind | null {
	const n = name.toLowerCase();
	if (n.endsWith(".rels")) return "rels";
	if (!n.endsWith(".xml")) return null;
	if (STRUCTURAL.test(n)) return null;
	if (
		/^word\/(?:glossary\/)?(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml$/.test(
			n,
		)
	)
		return "word";
	if (n === "word/people.xml") return "people";
	if (n === "xl/sharedstrings.xml") return "sst";
	if (/^xl\/worksheets\/[^/]+\.xml$/.test(n)) return "sheet";
	if (/^xl\/comments[^/]*\.xml$/.test(n)) return "xlComments";
	if (/^xl\/threadedcomments\/[^/]+\.xml$/.test(n)) return "threaded";
	if (/^xl\/persons\/[^/]+\.xml$/.test(n)) return "persons";
	if (/^xl\/pivotcache\/[^/]+\.xml$/.test(n)) return "pivot";
	if (/^ppt\/(?:commentauthors|authors)\.xml$/.test(n)) return "pptAuthors";
	if (
		/^(?:word|xl|ppt)\/(?:charts|diagrams|drawings)\/[^/]+\.xml$/.test(n) ||
		/^ppt\/(?:slides|notesslides|slidelayouts|slidemasters|notesmasters|handoutmasters|comments)\/[^/]+\.xml$/.test(
			n,
		)
	)
		return "drawing";
	return "generic";
}

const ALT_TEXT_ATTRS = ["descr", "title"] as const;

function altText(tag: XmlTag): readonly string[] {
	const local = localName(tag.name);
	return local === "cNvPr" || local === "docPr" ? ALT_TEXT_ATTRS : [];
}

const WORD_SPEC: TextSpec = {
	paragraphs: new Set(["w:p"]),
	leaves: new Set(["w:t", "w:delText", "w:instrText", "w:delInstrText", "m:t"]),
	breaks: new Map([
		["w:tab", ["\t", "w:r"]],
		["w:br", ["\n", "w:r"]],
		["w:cr", ["\n", "w:r"]],
		["w:noBreakHyphen", ["-", "w:r"]],
	]),
	preserveSpace: new Set(["w:t", "w:delText", "w:instrText", "w:delInstrText"]),
	attributes(tag) {
		if (tag.name === "w:fldSimple") return ["w:instr"];
		if (tag.attrs.some((a) => a.name === "w:author")) return ["w:author", "w:initials"];
		return altText(tag);
	},
};

const DRAWING_SPEC: TextSpec = {
	paragraphs: new Set(["a:p"]),
	leaves: new Set(["a:t", "c:v", "cx:v", "p:text"]),
	breaks: new Map([["a:br", ["\n", "a:p"]]]),
	attributes: altText,
};

const SPECS: Readonly<Record<Exclude<PartKind, "sst" | "sheet">, TextSpec>> = {
	word: WORD_SPEC,
	drawing: DRAWING_SPEC,
	people: {
		paragraphs: new Set(),
		leaves: new Set(),
		attributes: (tag) =>
			localName(tag.name) === "person" || localName(tag.name) === "presenceInfo"
				? ["w15:author", "w15:userId"]
				: [],
	},
	xlComments: {
		paragraphs: new Set(["text"]),
		leaves: new Set(["t", "author"]),
		preserveSpace: new Set(["t"]),
		localNames: true,
	},
	threaded: { paragraphs: new Set(), leaves: new Set(["text"]), localNames: true },
	persons: {
		paragraphs: new Set(),
		leaves: new Set(),
		attributes: (tag) => (localName(tag.name) === "person" ? ["displayName", "userId"] : []),
	},
	pivot: {
		paragraphs: new Set(),
		leaves: new Set(),
		attributes: (tag) => (localName(tag.name) === "s" ? ["v"] : []),
	},
	pptAuthors: {
		paragraphs: new Set(),
		leaves: new Set(),
		attributes: (tag) =>
			localName(tag.name) === "cmAuthor" || localName(tag.name) === "author"
				? ["name", "initials", "userId"]
				: [],
	},
	rels: {
		paragraphs: new Set(),
		leaves: new Set(),
		attributes: (tag) =>
			localName(tag.name) === "Relationship" &&
			tag.attrs.some((a) => a.name === "TargetMode" && a.value === "External")
				? ["Target"]
				: [],
	},
	generic: { paragraphs: new Set(), leaves: new Set(), allText: true },
};

// ---------------------------------------------------------------------------------------------
// Part text decoding
// ---------------------------------------------------------------------------------------------

export type PartEncoding = "utf-8" | "utf-8-bom" | "utf-16le" | "utf-16be";

export function decodePart(bytes: Uint8Array): { xml: string; encoding: PartEncoding } {
	try {
		if (bytes[0] === 0xff && bytes[1] === 0xfe)
			return {
				xml: new TextDecoder("utf-16le", { fatal: true }).decode(bytes),
				encoding: "utf-16le",
			};
		if (bytes[0] === 0xfe && bytes[1] === 0xff)
			return {
				xml: new TextDecoder("utf-16be", { fatal: true }).decode(bytes),
				encoding: "utf-16be",
			};
		const bom = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
		return {
			xml: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
			encoding: bom ? "utf-8-bom" : "utf-8",
		};
	} catch {
		throw new DocumentRefused(["DOCUMENT_MALFORMED"]);
	}
}

export function encodePart(xml: string, encoding: PartEncoding): Uint8Array {
	if (encoding === "utf-8") return new TextEncoder().encode(xml);
	if (encoding === "utf-8-bom") return new TextEncoder().encode(`﻿${xml}`);
	const out = new Uint8Array(2 + xml.length * 2);
	const le = encoding === "utf-16le";
	out[0] = le ? 0xff : 0xfe;
	out[1] = le ? 0xfe : 0xff;
	for (let i = 0; i < xml.length; i++) {
		const c = xml.charCodeAt(i);
		out[2 + i * 2] = le ? c & 0xff : c >>> 8;
		out[3 + i * 2] = le ? c >>> 8 : c & 0xff;
	}
	return out;
}

// ---------------------------------------------------------------------------------------------
// XLSX: shared strings and worksheets
// ---------------------------------------------------------------------------------------------

const SST_PRESERVE: ReadonlySet<string> = new Set(["t"]);

/** One segment (or null for an empty item) per `<si>`, in index order. */
function sharedStrings(xml: string): Array<TextSegment | null> {
	const items: Array<TextSegment | null> = [];
	const leaves = new LeafTracker(xml);
	let pieces: Piece[] | null = null;
	walkXml(xml, {
		start(tag) {
			if (leaves.open) return leaves.child();
			const local = localName(tag.name);
			if (local === "si") {
				pieces = [];
				if (tag.selfClosing) {
					items.push(null);
					pieces = null;
				}
			} else if (local === "t" && pieces && !tag.selfClosing) leaves.begin(tag);
		},
		text: (start, end, cdata) => leaves.text(start, end, cdata),
		end(name, start) {
			const leaf = leaves.open ? leaves.end(start) : null;
			if (leaf) {
				pieces?.push({ leaf, text: leaf.text });
				return;
			}
			if (localName(name) === "si" && pieces) {
				items.push(pieces.some((p) => p.text) ? piecesSegment(pieces, SST_PRESERVE) : null);
				pieces = null;
			}
		},
	});
	return items;
}

/** "AB12" -> 27 (0-based column index), or -1. */
function columnIndex(ref: string): number {
	const m = /^\$?([A-Za-z]{1,3})\$?\d*$/.exec(ref);
	if (!m?.[1]) return -1;
	let col = 0;
	for (const ch of m[1].toUpperCase()) col = col * 26 + (ch.charCodeAt(0) - 64);
	return col - 1;
}

interface Cell {
	readonly tag: XmlTag;
	readonly type: string;
	readonly row: number;
	readonly col: number;
	hasFormula: boolean;
	value: Leaf | null;
	inline: Piece[] | null;
	endEnd: number;
}

const HEADER_FOOTER: ReadonlySet<string> = new Set([
	"oddHeader",
	"oddFooter",
	"evenHeader",
	"evenFooter",
	"firstHeader",
	"firstFooter",
]);

function attr(tag: XmlTag, name: string): string | undefined {
	return tag.attrs.find((a) => a.name === name)?.value;
}

/** The start tag of `tag` with its `t` attribute set to `type` (other attributes kept raw). */
function retypedStartTag(xml: string, tag: XmlTag, type: string): string {
	const kept = tag.attrs
		.filter((a) => a.name !== "t")
		.map((a) => ` ${a.name}=${a.quote}${xml.slice(a.valueStart, a.valueEnd)}${a.quote}`)
		.join("");
	return `<${tag.name}${kept} t="${type}">`;
}

/** Segment over a numeric/date cell value: a masked value turns the cell into a string. */
function numericCellSegment(xml: string, cell: Cell, value: Leaf): TextSegment {
	return {
		text: value.text,
		context: "",
		apply(edits: readonly Edit[]): RawReplacement[] {
			if (!edits.length) return [];
			const text = spliceEdits(value.text, edits);
			if (cell.hasFormula) {
				return [
					{ start: cell.tag.start, end: cell.tag.end, raw: retypedStartTag(xml, cell.tag, "str") },
					{ start: value.tag.end, end: value.contentEnd, raw: escapeXmlText(text) },
				];
			}
			const colon = cell.tag.name.indexOf(":");
			const p = colon < 0 ? "" : cell.tag.name.slice(0, colon + 1);
			const raw = `${retypedStartTag(xml, cell.tag, "inlineStr")}<${p}is><${p}t xml:space="preserve">${escapeXmlText(text)}</${p}t></${p}is></${cell.tag.name}>`;
			return [{ start: cell.tag.start, end: cell.endEnd, raw }];
		},
	};
}

/**
 * Worksheet cells. The first row supplies column headers: data cells get the header as
 * detection context, and a sensitive header forces whole-value masking (shared strings used
 * in such a column are recorded in `sstForced`).
 */
class WorksheetReader {
	readonly segments: TextSegment[] = [];
	private readonly headers = new Map<number, string>();
	private readonly leaves: LeafTracker;
	private firstRow: number | undefined;
	private row = 0;
	private nextCol = 0;
	private cell: Cell | null = null;
	private inHeaderFooter = false;

	constructor(
		private readonly xml: string,
		private readonly sst: ReadonlyArray<TextSegment | null>,
		private readonly scanner: DocScanner,
		private readonly sstForced: Map<number, EntityType>,
	) {
		this.leaves = new LeafTracker(xml);
	}

	start(tag: XmlTag): void {
		if (this.leaves.open) return this.leaves.child();
		const local = localName(tag.name);
		if (local === "row") this.startRow(tag);
		else if (local === "c") this.startCell(tag);
		else if (this.cell) this.startCellChild(this.cell, local, tag);
		else if (HEADER_FOOTER.has(local) && !tag.selfClosing) {
			this.inHeaderFooter = true;
			this.leaves.begin(tag);
		}
	}

	text(start: number, end: number, cdata: boolean): void {
		this.leaves.text(start, end, cdata);
	}

	end(name: string, start: number, end: number): void {
		const leaf = this.leaves.open ? this.leaves.end(start) : null;
		if (leaf) return this.endLeaf(name, leaf);
		const cell = this.cell;
		if (!cell || localName(name) !== "c") return;
		cell.endEnd = end;
		this.cell = null;
		this.finish(cell);
	}

	private startRow(tag: XmlTag): void {
		const r = Number.parseInt(attr(tag, "r") ?? "", 10);
		this.row = Number.isInteger(r) && r > 0 ? r : this.row + 1;
		this.firstRow ??= this.row;
		this.nextCol = 0;
	}

	private startCell(tag: XmlTag): void {
		const ref = attr(tag, "r");
		const col = ref ? columnIndex(ref) : -1;
		const cell: Cell = {
			tag,
			type: attr(tag, "t") ?? "n",
			row: this.row,
			col: col >= 0 ? col : this.nextCol,
			hasFormula: false,
			value: null,
			inline: null,
			endEnd: tag.end,
		};
		this.cell = cell;
		this.nextCol = cell.col + 1;
	}

	private startCellChild(cell: Cell, local: string, tag: XmlTag): void {
		if (local === "f") cell.hasFormula = true;
		else if (local === "is") cell.inline = [];
		else if ((local === "v" || (local === "t" && cell.inline)) && !tag.selfClosing)
			this.leaves.begin(tag);
	}

	private endLeaf(name: string, leaf: Leaf): void {
		if (this.inHeaderFooter) {
			this.inHeaderFooter = false;
			if (leaf.text.trim()) this.segments.push(piecesSegment([{ leaf, text: leaf.text }]));
		} else if (this.cell && localName(name) === "v") this.cell.value = leaf;
		else this.cell?.inline?.push({ leaf, text: leaf.text });
	}

	private header(cell: Cell, text: string): void {
		if (cell.row === this.firstRow) this.headers.set(cell.col, text);
	}

	private add(cell: Cell, segment: TextSegment): void {
		const header = cell.row === this.firstRow ? undefined : this.headers.get(cell.col);
		segment.context = header ?? "";
		const forced = header ? this.scanner.headerType(header) : undefined;
		if (forced) segment.forced = forced;
		if (segment.text.trim()) this.segments.push(segment);
	}

	private finish(cell: Cell): void {
		const value = cell.value;
		if (cell.type === "s") this.sharedStringCell(cell, value?.text ?? "");
		else if (cell.type === "inlineStr" && cell.inline?.length) {
			const segment = piecesSegment(cell.inline, SST_PRESERVE);
			this.header(cell, segment.text);
			this.add(cell, segment);
		} else if (cell.type === "str" && value) {
			this.header(cell, value.text);
			this.add(cell, piecesSegment([{ leaf: value, text: value.text }]));
		} else if ((cell.type === "n" || cell.type === "d") && value) {
			this.add(cell, numericCellSegment(this.xml, cell, value));
		}
		// Booleans and errors carry no text.
	}

	private sharedStringCell(cell: Cell, valueText: string): void {
		const index = Number.parseInt(valueText.trim(), 10);
		if (!Number.isInteger(index) || index < 0) return;
		if (cell.row === this.firstRow) {
			this.headers.set(cell.col, this.sst[index]?.text ?? "");
			return;
		}
		const header = this.headers.get(cell.col);
		const forced = header ? this.scanner.headerType(header) : undefined;
		if (forced && !this.sstForced.has(index)) this.sstForced.set(index, forced);
	}
}

function worksheet(
	xml: string,
	sst: ReadonlyArray<TextSegment | null>,
	scanner: DocScanner,
	sstForced: Map<number, EntityType>,
): TextSegment[] {
	const reader = new WorksheetReader(xml, sst, scanner, sstForced);
	walkXml(xml, {
		start: (tag) => reader.start(tag),
		text: (start, end, cdata) => reader.text(start, end, cdata),
		end: (name, start, end) => reader.end(name, start, end),
	});
	return reader.segments;
}

// ---------------------------------------------------------------------------------------------
// Package checks
// ---------------------------------------------------------------------------------------------

interface Relationship {
	readonly type: string;
	readonly external: boolean;
}

function relationships(xml: string): Relationship[] {
	const out: Relationship[] = [];
	walkXml(xml, {
		start(tag) {
			if (localName(tag.name) !== "Relationship") return;
			const type = attr(tag, "Type") ?? "";
			out.push({
				type: type.slice(type.lastIndexOf("/") + 1).toLowerCase(),
				external: attr(tag, "TargetMode") === "External",
			});
		},
	});
	return out;
}

function isOoxmlName(name: string): boolean {
	const dot = name.lastIndexOf(".");
	return dot >= 0 && OOXML_EXTENSIONS.has(name.slice(dot + 1).toLowerCase());
}

async function readText(
	archive: ZipArchive,
	entry: ZipEntry,
): Promise<{ xml: string; encoding: PartEncoding }> {
	return decodePart(await readEntry(archive, entry));
}

/** Refusals implied by one entry's name (and, for relationship parts, its content). */
async function entryRefusals(
	archive: ZipArchive,
	entry: ZipEntry,
	depth: number,
	reasons: Set<string>,
): Promise<void> {
	if (MACRO_PART.test(entry.name)) reasons.add("DOCUMENT_MACROS");
	if (EXTERNAL_PART.test(entry.name)) reasons.add("DOCUMENT_EXTERNAL_LINKS");
	if (EMBEDDING.test(entry.name) && (!isOoxmlName(entry.name) || depth + 1 >= MAX_DEPTH))
		reasons.add("DOCUMENT_EMBEDDED_OBJECT");
	if (!entry.name.toLowerCase().endsWith(".rels")) return;
	const rels = relationships((await readText(archive, entry)).xml);
	if (rels.some((rel) => rel.external && EXTERNAL_REL_TYPES.has(rel.type)))
		reasons.add("DOCUMENT_EXTERNAL_LINKS");
}

/** Policy refusals that apply to the package as a whole (checked before any text is masked). */
async function packageRefusals(archive: ZipArchive, depth: number): Promise<string[]> {
	const types = findEntry(archive, "[Content_Types].xml");
	if (!types || !MAIN_PARTS.some((p) => findEntry(archive, p)))
		throw new DocumentUnreadable("DOCUMENT_UNPARSEABLE");
	const reasons = new Set<string>();
	if (MACRO_CONTENT_TYPE.test((await readText(archive, types)).xml)) reasons.add("DOCUMENT_MACROS");
	for (const entry of archive.entries) await entryRefusals(archive, entry, depth, reasons);
	return [...reasons].sort();
}

// ---------------------------------------------------------------------------------------------
// Sanitisation
// ---------------------------------------------------------------------------------------------

interface PartModel {
	readonly entry: ZipEntry;
	readonly xml: string;
	readonly encoding: PartEncoding;
	readonly segments: readonly TextSegment[];
}

export interface Totals {
	findings: number;
	readonly findingCounts: Counts;
	readonly signals: Set<SignalCode>;
	readonly images: ImageSummary;
	/** End of the OCR time budget for the whole document. */
	readonly ocrDeadline: number;
}

export function newTotals(): Totals {
	return {
		findings: 0,
		findingCounts: {},
		signals: new Set(),
		images: emptyImageSummary(),
		ocrDeadline: Date.now() + OCR_BUDGET_MS,
	};
}

/**
 * Pictures of a package that is about to be rewritten (`replacements` non-empty) or kept: a
 * thumbnail of a rewritten package is blanked; every other picture is OCR'd or counted as not
 * inspected. `skip` excludes entries handled elsewhere (embedded packages).
 */
export async function handleImages(
	archive: ZipArchive,
	replacements: Map<string, Uint8Array>,
	scanner: DocScanner,
	totals: Totals,
	skip: (name: string) => boolean = () => false,
): Promise<void> {
	const pending: ZipEntry[] = [];
	for (const entry of archive.entries) {
		if (skip(entry.name) || !isImageEntry(entry.name) || replacements.has(entry.name)) continue;
		const blank = replacements.size && isThumbnail(entry.name) ? blankThumbnail(entry.name) : null;
		if (blank) replacements.set(entry.name, blank);
		else pending.push(entry);
	}
	await inspectImages(archive, pending, scanner, totals.images, totals.ocrDeadline);
}

function editsFor(segment: TextSegment, findings: readonly Finding[], scanner: DocScanner): Edit[] {
	return findings.map((f) => ({
		start: f.start,
		end: f.end,
		text: scanner.replace(segment.text.slice(f.start, f.end), f),
	}));
}

/**
 * Masks each segment's findings (counted into `totals`) and returns the part re-encoded as it
 * was read, or null when nothing changed. Shared by the OOXML and OpenDocument sanitisers.
 */
export function rewritePart(
	part: { readonly xml: string; readonly encoding: PartEncoding },
	segments: readonly TextSegment[],
	perSegment: readonly (readonly Finding[] | undefined)[],
	scanner: DocScanner,
	totals: Totals,
): Uint8Array | null {
	const replacements: RawReplacement[] = [];
	segments.forEach((segment, i) => {
		const findings = perSegment[i] ?? [];
		if (!findings.length) return;
		totals.findings += findings.length;
		mergeCounts(totals.findingCounts, countFindings(findings));
		replacements.push(...segment.apply(editsFor(segment, findings, scanner)));
	});
	if (!replacements.length) return null;
	const xml = applyReplacements(part.xml, replacements);
	if (xml === part.xml) return null;
	assertWellFormed(xml);
	return encodePart(xml, part.encoding);
}

/** Scans one part's segments and returns the rewritten part, or null when unchanged. */
async function maskPart(
	part: PartModel,
	scanner: DocScanner,
	totals: Totals,
): Promise<Uint8Array | null> {
	if (!part.segments.length) return null;
	scanner.checkDeadline();
	const scan = await scanner.scan(
		part.segments.map((s) => ({ context: s.context, value: s.text, forced: s.forced })),
	);
	for (const signal of scan.signals) totals.signals.add(signal);
	return rewritePart(part, part.segments, scan.perSegment, scanner, totals);
}

/** An archive or XML failure as the refusal the caller blocks on; any other error unchanged. */
export function asDocumentRefusal(error: unknown): unknown {
	if (error instanceof ArchiveError) return new DocumentRefused([`ARCHIVE_${error.code}`]);
	if (error instanceof XmlError) return new DocumentRefused(["DOCUMENT_MALFORMED"]);
	return error;
}

async function buildModels(archive: ZipArchive, scanner: DocScanner): Promise<PartModel[]> {
	const models: PartModel[] = [];
	const sstEntry = findEntry(archive, "xl/sharedStrings.xml");
	const sst = sstEntry ? await readText(archive, sstEntry) : null;
	const sstItems = sst ? sharedStrings(sst.xml) : [];
	const sstForced = new Map<number, EntityType>();
	for (const entry of archive.entries) {
		const kind = partKind(entry.name);
		if (!kind || kind === "sst") continue;
		scanner.checkDeadline();
		const { xml, encoding } = await readText(archive, entry);
		const segments =
			kind === "sheet"
				? worksheet(xml, sstItems, scanner, sstForced)
				: extractText(xml, SPECS[kind]);
		models.push({ entry, xml, encoding, segments });
	}
	if (sst && sstEntry) {
		sstItems.forEach((item, index) => {
			const forced = sstForced.get(index);
			if (item && forced) item.forced = forced;
		});
		const segments = sstItems.filter((s): s is TextSegment => s !== null && !!s.text.trim());
		models.push({ entry: sstEntry, xml: sst.xml, encoding: sst.encoding, segments });
	}
	return models;
}

async function sanitizeArchive(
	archive: ZipArchive,
	scanner: DocScanner,
	depth: number,
	totals: Totals,
): Promise<Uint8Array | null> {
	const refusals = await packageRefusals(archive, depth);
	if (refusals.length) throw new DocumentRefused(refusals);
	const replacements = new Map<string, Uint8Array>();
	for (const part of await buildModels(archive, scanner)) {
		const masked = await maskPart(part, scanner, totals);
		if (masked) replacements.set(part.entry.name, masked);
	}
	for (const entry of archive.entries) {
		if (!EMBEDDING.test(entry.name)) continue;
		const inner = await readEntry(archive, entry);
		const remaining = archive.limits.maxReadTotal - archive.readBytes;
		const nested = await openEmbedded(inner, { ...archive.limits, maxReadTotal: remaining });
		const masked = await sanitizeArchive(nested, scanner, depth + 1, totals);
		archive.readBytes += nested.readBytes;
		if (masked) replacements.set(entry.name, masked);
	}
	await handleImages(archive, replacements, scanner, totals, (name) => EMBEDDING.test(name));
	if (!replacements.size) return null;
	const out = await rewriteZip(archive, replacements);
	readZip(out, archive.limits); // structural self-check of what is handed to the page
	return out;
}

async function openArchive(bytes: Uint8Array, limits: ZipLimits): Promise<ZipArchive> {
	if (isCompoundFile(bytes)) {
		if (containsEncryptedPackage(bytes)) throw new DocumentRefused(["DOCUMENT_ENCRYPTED"]);
		throw new DocumentUnreadable("DOCUMENT_UNPARSEABLE");
	}
	try {
		return readZip(bytes, limits);
	} catch (error) {
		if (error instanceof ArchiveError && error.code === "NOT_A_ZIP")
			throw new DocumentUnreadable("DOCUMENT_UNPARSEABLE");
		throw error;
	}
}

/** An embedded package that cannot be opened is refused, never passed through unscanned. */
async function openEmbedded(bytes: Uint8Array, limits: ZipLimits): Promise<ZipArchive> {
	try {
		return await openArchive(bytes, limits);
	} catch (error) {
		if (error instanceof DocumentUnreadable)
			throw new DocumentRefused(["DOCUMENT_EMBEDDED_OBJECT"]);
		throw error;
	}
}

/** True when `bytes` look like an OOXML package (used to sniff mislabelled uploads). */
export function sniffOoxml(bytes: Uint8Array): boolean {
	try {
		const archive = readZip(bytes);
		return (
			!!findEntry(archive, "[Content_Types].xml") && MAIN_PARTS.some((p) => findEntry(archive, p))
		);
	} catch {
		return false;
	}
}

/**
 * Masks the text of an OOXML package. Throws {@link DocumentRefused} (block),
 * {@link DocumentUnreadable} (treat as unscanned binary); scan/vault errors propagate.
 */
export async function sanitizeOoxml(
	bytes: Uint8Array,
	scanner: DocScanner,
	limits: ZipLimits = DEFAULT_ZIP_LIMITS,
): Promise<DocumentOutcome> {
	const totals = newTotals();
	try {
		const archive = await openArchive(bytes, limits);
		const out = await sanitizeArchive(archive, scanner, 0, totals);
		return { bytes: out, ...totals };
	} catch (error) {
		throw asDocumentRefusal(error);
	}
}
