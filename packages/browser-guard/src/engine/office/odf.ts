/**
 * OpenDocument (ODT / ODS / ODP / ODG and their templates) sanitisation.
 *
 * An OpenDocument package is a ZIP of XML parts like OOXML, so it goes through the same
 * defensive ZIP reader/writer (./zip.ts: zip-bomb, ZIP64, path and CRC checks), the same strict
 * XML scanner (./xml.ts: no DOCTYPE, no external entities) and the same budgets. Text is masked
 * in place and the package re-zipped; the `mimetype` entry keeps its position and stored method.
 *
 *   Refused (`DocumentRefused`, the caller blocks):
 *     DOCUMENT_ENCRYPTED        an encrypted package (`manifest:encryption-data` in the manifest);
 *     DOCUMENT_MACROS           Basic/script libraries (`Basic/`, `Scripts/`) or event listeners
 *                               bound to scripts (`script:event-listener`);
 *     DOCUMENT_EXTERNAL_LINKS   DDE links, linked sections/sheets, objects linked from outside the
 *                               package, plugins, applets, floating frames;
 *     DOCUMENT_EMBEDDED_OBJECT  OLE objects (`draw:object-ole`) and any binary entry that is not an
 *                               image or the Writer `layout-cache` (e.g. embedded media);
 *     ARCHIVE_* / DOCUMENT_MALFORMED as for OOXML.
 *   Unreadable (`DocumentUnreadable`): not a ZIP, or no `content.xml`.
 *
 * Element and attribute names are matched namespace-aware (./xml.ts canonical names), so a
 * document that binds the ODF namespaces to other prefixes (or a default namespace) is read
 * and refused exactly like one that uses the conventional prefixes.
 *
 * Text handled: every XML part except the manifest, `settings.xml` and UI configuration, in
 * the package and in embedded objects (`Object 1/content.xml`...):
 *   - paragraphs (`text:p`, `text:h`) as one segment over their mixed content (spans, links,
 *     fields; `text:s`/`text:tab`/`text:line-break` stand for their characters), so a value
 *     split across formatting spans is detected whole; nested paragraphs (notes, annotations,
 *     text boxes) are segments of their own;
 *   - character data outside paragraphs (document metadata, annotation authors, titles and
 *     descriptions of frames) as standalone segments;
 *   - hyperlink targets and cell/field value attributes (`office:value`, `office:date-value`,
 *     `office:string-value`, `table:formula`, `text:string-value`).
 * Tables (spreadsheets, and tables in text documents) use their first row as column headers:
 * data cells get the header as detection context, and a header that names a sensitive field
 * (same dictionary as CSV/XLSX) masks the column wholesale. A cell is masked as a unit: when
 * its value, formula or text holds a finding, the rest of the cell is masked with it, and a
 * masked numeric/date value becomes a string cell (the formatted text could otherwise still
 * show the number).
 * Pictures: see ./images.ts (thumbnail blanked when the package is rewritten; OCR or reported).
 */
import type { EntityType, Finding } from "../../types.js";
import { isImageEntry } from "./images.js";
import {
	asDocumentRefusal,
	type DocumentOutcome,
	DocumentRefused,
	DocumentUnreadable,
	decodePart,
	handleImages,
	isCompoundFile,
	newTotals,
	type PartEncoding,
	rewritePart,
	type Totals,
} from "./ooxml.js";
import type { DocScanner } from "./scanner.js";
import {
	attributeSegment,
	decodeXmlText,
	type Edit,
	escapeXmlAttr,
	type Leaf,
	type Piece,
	piecesSegment,
	type RawReplacement,
	STRICT_NAMESPACES,
	spliceEdits,
	type TextSegment,
	walkXml,
	type XmlAttr,
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

export const ODF_EXTENSIONS: ReadonlySet<string> = new Set([
	"odt",
	"ods",
	"odp",
	"odg",
	"ott",
	"ots",
	"otp",
	"otg",
]);

export const ODF_MIME = /^application\/vnd\.oasis\.opendocument\.[\w.-]+\s*(?:;|$)/i;

const MACRO_ENTRY = /(?:^|\/)(?:Basic|Scripts)\//i;
/** Parts that carry no document text: never rewritten. */
const SKIPPED_PART = /^META-INF\/manifest\.xml$|(?:^|\/)settings\.xml$|^Configurations2\//i;
const XML_PART = /\.(?:xml|rdf)$/i;
/** Binary entries allowed besides images: Writer's paragraph layout cache holds no text. */
const LAYOUT_CACHE = /(?:^|\/)layout-cache$/i;

/** Elements whose mere presence links outside the package or runs active content. */
const ALWAYS_EXTERNAL: ReadonlySet<string> = new Set([
	"office:dde-source",
	"text:dde-connection-decl",
	"table:dde-link",
	"draw:plugin",
	"draw:applet",
	"draw:floating-frame",
]);
/** Elements that are external links when their `xlink:href` points outside the package. */
const LINKABLE: ReadonlySet<string> = new Set([
	"draw:object",
	"text:section-source",
	"table:table-source",
]);
const PARAGRAPHS: ReadonlySet<string> = new Set(["text:p", "text:h"]);
const HYPERLINKS: ReadonlySet<string> = new Set(["text:a", "draw:a"]);
/**
 * Elements anchored inside a paragraph that are not part of its running text (notes,
 * annotations, frames): their text is separated from the words around it by a line break.
 */
const INLINE_BOUNDARIES: ReadonlySet<string> = new Set([
	"text:note",
	"text:note-citation",
	"text:note-body",
	"office:annotation",
	"office:annotation-end",
	"dc:creator",
	"dc:date",
	"meta:creator-initials",
	"draw:frame",
	"draw:text-box",
	"svg:title",
	"svg:desc",
	"text:ruby-text",
]);
/** Value attributes scanned as text (on cells, fields and form controls). */
const VALUE_ATTRS = [
	"office:value",
	"office:date-value",
	"office:string-value",
	"table:formula",
	"text:string-value",
] as const;
/** Largest `text:c` / repeat count honoured (bounds the work, not the document). */
const MAX_REPEAT = 16_384;

function isExternalHref(href: string): boolean {
	const h = href.trim();
	return /^[a-z][a-z0-9+.-]*:/i.test(h) || /^[\\/]/.test(h) || /^\.\.(?:[\\/]|$)/.test(h);
}

/** The attribute whose canonical (namespace-resolved) name is `name`. */
function attr(tag: XmlTag, name: string): XmlAttr | undefined {
	return tag.attrs.find((a) => a.cname === name);
}

function repeat(tag: XmlTag, name: string): number {
	const n = Number.parseInt(attr(tag, name)?.value ?? "1", 10);
	return Number.isInteger(n) && n > 0 ? Math.min(n, MAX_REPEAT) : 1;
}

/** Start of the attribute name whose value starts at `valueStart` (`name = "value"`). */
function attributeNameStart(xml: string, a: XmlAttr): number {
	let i = a.valueStart - 2; // before the opening quote
	while (i >= 0 && /\s/.test(xml[i] as string)) i--;
	if (xml[i] !== "=") throw new XmlError("BAD_ATTRIBUTE");
	i--;
	while (i >= 0 && /\s/.test(xml[i] as string)) i--;
	const start = i + 1 - a.name.length;
	if (xml.slice(start, i + 1) !== a.name) throw new XmlError("BAD_ATTRIBUTE");
	return start;
}

/** A text node as a rewritable pseudo leaf (a CDATA section is rewritten as escaped text). */
function textLeaf(start: number, end: number, text: string, cdata: boolean): Leaf {
	const from = cdata ? start - 9 : start;
	return {
		tag: { name: "#text", cname: "#text", start: from, end: from, selfClosing: false, attrs: [] },
		open: "",
		contentEnd: cdata ? end + 3 : end,
		text,
		rewritable: true,
	};
}

/** An ODF segment; segments with the same `group` (one table cell) are masked together. */
interface OdfSegment {
	readonly segment: TextSegment;
	readonly group?: number;
}

interface TableState {
	headerRow: boolean;
	seenRow: boolean;
	col: number;
	readonly headers: Map<number, string>;
}

interface CellState {
	readonly group: number;
	readonly col: number;
	readonly span: number;
	readonly header: boolean;
	readonly table: TableState;
}

interface Paragraph {
	readonly pieces: Piece[];
	readonly cell: CellState | undefined;
}

/** Walks one XML part: paragraphs, loose text, value attributes, tables and refusals. */
class OdfReader {
	readonly segments: OdfSegment[] = [];
	readonly refusals = new Set<string>();
	private readonly paragraphs: Paragraph[] = [];
	private readonly tables: TableState[] = [];
	private readonly cells: CellState[] = [];
	private groups = 0;

	constructor(
		private readonly xml: string,
		private readonly scanner: DocScanner,
	) {}

	start(tag: XmlTag): void {
		this.checkRefusals(tag);
		const name = tag.cname;
		if (name === "table:table") {
			this.tables.push({ headerRow: false, seenRow: false, col: 0, headers: new Map() });
		} else if (name === "table:table-row") this.startRow();
		else if (name === "table:table-cell" || name === "table:covered-table-cell")
			this.startCell(tag);
		this.addAttributes(tag);
		const paragraph = this.paragraphs[this.paragraphs.length - 1];
		if (paragraph && INLINE_BOUNDARIES.has(name)) paragraph.pieces.push({ leaf: null, text: "\n" });
		if (PARAGRAPHS.has(name)) {
			this.paragraphs.push({ pieces: [], cell: this.cells[this.cells.length - 1] });
		} else if (paragraph && tag.selfClosing) {
			if (name === "text:tab") paragraph.pieces.push({ leaf: null, text: "\t" });
			else if (name === "text:line-break") paragraph.pieces.push({ leaf: null, text: "\n" });
			else if (name === "text:s")
				paragraph.pieces.push({ leaf: null, text: " ".repeat(repeat(tag, "text:c")) });
		}
	}

	text(start: number, end: number, cdata: boolean): void {
		const raw = this.xml.slice(start, end);
		const decoded = cdata ? raw : decodeXmlText(raw);
		const paragraph = this.paragraphs[this.paragraphs.length - 1];
		if (paragraph) {
			// Whitespace inside a paragraph is collapsed by ODF: newlines are spaces.
			const text = cdata ? decoded : decoded.replace(/[\t\r\n]/g, " ");
			paragraph.pieces.push({ leaf: textLeaf(start, end, text, cdata), text });
		} else if (decoded.trim()) {
			this.push(piecesSegment([{ leaf: textLeaf(start, end, decoded, cdata), text: decoded }]));
		}
	}

	end(name: string): void {
		if (INLINE_BOUNDARIES.has(name))
			this.paragraphs[this.paragraphs.length - 1]?.pieces.push({ leaf: null, text: "\n" });
		if (PARAGRAPHS.has(name)) this.endParagraph();
		else if (name === "table:table-cell" || name === "table:covered-table-cell") {
			const cell = this.cells.pop();
			if (cell) cell.table.col = cell.col + cell.span;
		} else if (name === "table:table") this.tables.pop();
	}

	private push(segment: TextSegment, cell?: CellState): void {
		if (!segment.text.trim()) return;
		if (cell && !cell.header) {
			const header = cell.table.headers.get(cell.col) ?? "";
			segment.context = header;
			const forced = header ? this.scanner.headerType(header) : undefined;
			if (forced) segment.forced = forced;
		}
		this.segments.push(cell ? { segment, group: cell.group } : { segment });
	}

	private checkRefusals(tag: XmlTag): void {
		const href = attr(tag, "xlink:href")?.value;
		const name = tag.cname;
		if (name === "script:event-listener") this.refusals.add("DOCUMENT_MACROS");
		else if (name === "draw:object-ole") this.refusals.add("DOCUMENT_EMBEDDED_OBJECT");
		else if (ALWAYS_EXTERNAL.has(name)) this.refusals.add("DOCUMENT_EXTERNAL_LINKS");
		else if (LINKABLE.has(name) && href !== undefined && isExternalHref(href))
			this.refusals.add("DOCUMENT_EXTERNAL_LINKS");
	}

	private startRow(): void {
		const table = this.tables[this.tables.length - 1];
		if (!table) return;
		table.headerRow = !table.seenRow;
		table.seenRow = true;
		table.col = 0;
	}

	private startCell(tag: XmlTag): void {
		const table = this.tables[this.tables.length - 1];
		if (!table) return;
		const cell: CellState = {
			group: ++this.groups,
			col: table.col,
			span: repeat(tag, "table:number-columns-repeated"),
			header: table.headerRow,
			table,
		};
		this.cells.push(cell);
		// A self-closing cell gets its end() right after start(); the column advances there.
	}

	private addAttributes(tag: XmlTag): void {
		const cell = tag.cname === "table:table-cell" ? this.cells[this.cells.length - 1] : undefined;
		if (HYPERLINKS.has(tag.cname)) {
			const href = attr(tag, "xlink:href");
			if (href) this.push(attributeSegment(href));
		}
		for (const name of VALUE_ATTRS) {
			const a = attr(tag, name);
			if (!a) continue;
			const numeric = cell && (name === "office:value" || name === "office:date-value");
			this.push(numeric ? this.retypingSegment(tag, a) : attributeSegment(a), cell);
		}
	}

	/** A numeric/date cell value that, once masked, turns the cell into a string cell. */
	private retypingSegment(tag: XmlTag, value: XmlAttr): TextSegment {
		const xml = this.xml;
		const types = ["office:value-type", "calcext:value-type"]
			.map((n) => attr(tag, n))
			.filter((a): a is XmlAttr => a !== undefined);
		const hasString = attr(tag, "office:string-value") !== undefined;
		return {
			text: value.value,
			context: "",
			apply(edits: readonly Edit[]): RawReplacement[] {
				if (!edits.length) return [];
				const masked = escapeXmlAttr(spliceEdits(value.value, edits), value.quote);
				const out: RawReplacement[] = types.map((t) => ({
					start: t.valueStart,
					end: t.valueEnd,
					raw: "string",
				}));
				if (hasString) {
					// The cell already has a string value: keep its name, mask this one in place.
					out.push({ start: value.valueStart, end: value.valueEnd, raw: masked });
				} else {
					// Same prefix as the value attribute: bound to the office namespace on this tag.
					const nameStart = attributeNameStart(xml, value);
					const prefix = value.name.slice(0, value.name.indexOf(":") + 1);
					out.push({
						start: nameStart,
						end: value.valueEnd,
						raw: `${prefix}string-value=${value.quote}${masked}`,
					});
				}
				return out;
			},
		};
	}

	private endParagraph(): void {
		const paragraph = this.paragraphs.pop();
		if (!paragraph || !paragraph.pieces.some((p) => p.leaf && p.text.trim())) return;
		const segment = piecesSegment(paragraph.pieces);
		const cell = paragraph.cell;
		if (cell?.header) {
			const previous = cell.table.headers.get(cell.col);
			cell.table.headers.set(cell.col, previous ? `${previous} ${segment.text}` : segment.text);
		}
		this.push(segment, cell);
	}
}

interface PartModel {
	readonly entry: ZipEntry;
	readonly xml: string;
	readonly encoding: PartEncoding;
	readonly segments: readonly OdfSegment[];
}

/** Adds, per cell, a whole-value finding to every segment of a cell that has a finding elsewhere. */
function linkCells(
	segments: readonly OdfSegment[],
	perSegment: readonly (readonly Finding[])[],
): Finding[][] {
	const groupType = new Map<number, EntityType>();
	segments.forEach(({ group }, i) => {
		const first = perSegment[i]?.[0];
		if (group !== undefined && first && !groupType.has(group)) groupType.set(group, first.type);
	});
	return segments.map(({ segment, group }, i) => {
		const own = [...(perSegment[i] ?? [])];
		const type = group === undefined ? undefined : groupType.get(group);
		if (!own.length && type && segment.text.trim())
			own.push({ type, start: 0, end: segment.text.length, score: 1, source: "rule" });
		return own;
	});
}

async function maskPart(
	part: PartModel,
	scanner: DocScanner,
	totals: Totals,
): Promise<Uint8Array | null> {
	if (!part.segments.length) return null;
	scanner.checkDeadline();
	const scan = await scanner.scan(
		part.segments.map(({ segment: s }) => ({
			context: s.context,
			value: s.text,
			forced: s.forced,
		})),
	);
	for (const signal of scan.signals) totals.signals.add(signal);
	return rewritePart(
		part,
		part.segments.map(({ segment }) => segment),
		linkCells(part.segments, scan.perSegment),
		scanner,
		totals,
	);
}

/** Entry-level refusals: macros, encryption, and binary entries that are not pictures. */
async function entryRefusals(archive: ZipArchive, reasons: Set<string>): Promise<void> {
	const manifest = findEntry(archive, "META-INF/manifest.xml");
	if (manifest) {
		const { xml } = decodePart(await readEntry(archive, manifest));
		if (/<(?:[\w.-]+:)?encryption-data[\s/>]/.test(xml)) reasons.add("DOCUMENT_ENCRYPTED");
	}
	for (const entry of archive.entries) {
		const name = entry.name;
		if (MACRO_ENTRY.test(name)) reasons.add("DOCUMENT_MACROS");
		else if (
			!name.endsWith("/") &&
			name !== "mimetype" &&
			!XML_PART.test(name) &&
			!LAYOUT_CACHE.test(name) &&
			!isImageEntry(name) &&
			!/^Configurations2\//i.test(name)
		)
			reasons.add("DOCUMENT_EMBEDDED_OBJECT");
	}
}

async function buildModels(
	archive: ZipArchive,
	scanner: DocScanner,
	refusals: Set<string>,
): Promise<PartModel[]> {
	const models: PartModel[] = [];
	for (const entry of archive.entries) {
		// Macro libraries are refused by entryRefusals whatever they contain: not parsed.
		if (!XML_PART.test(entry.name) || SKIPPED_PART.test(entry.name) || MACRO_ENTRY.test(entry.name))
			continue;
		scanner.checkDeadline();
		const { xml, encoding } = decodePart(await readEntry(archive, entry));
		const reader = new OdfReader(xml, scanner);
		walkXml(
			xml,
			{
				start: (tag) => reader.start(tag),
				text: (start, end, cdata) => reader.text(start, end, cdata),
				end: (name) => reader.end(name),
			},
			STRICT_NAMESPACES,
		);
		for (const reason of reader.refusals) refusals.add(reason);
		models.push({ entry, xml, encoding, segments: reader.segments });
	}
	return models;
}

async function openOdf(bytes: Uint8Array, limits: ZipLimits): Promise<ZipArchive> {
	if (isCompoundFile(bytes)) throw new DocumentUnreadable("DOCUMENT_UNPARSEABLE");
	let archive: ZipArchive;
	try {
		archive = readZip(bytes, limits);
	} catch (error) {
		if (error instanceof ArchiveError && error.code === "NOT_A_ZIP")
			throw new DocumentUnreadable("DOCUMENT_UNPARSEABLE");
		throw error;
	}
	if (!findEntry(archive, "content.xml")) throw new DocumentUnreadable("DOCUMENT_UNPARSEABLE");
	return archive;
}

/** True when `bytes` look like an OpenDocument package (used to sniff mislabelled uploads). */
export function sniffOdf(bytes: Uint8Array): boolean {
	try {
		const archive = readZip(bytes);
		return !!findEntry(archive, "mimetype") && !!findEntry(archive, "content.xml");
	} catch {
		return false;
	}
}

/**
 * Masks the text of an OpenDocument package. Throws {@link DocumentRefused} (block),
 * {@link DocumentUnreadable} (treat as unscanned binary); scan/vault errors propagate.
 */
export async function sanitizeOdf(
	bytes: Uint8Array,
	scanner: DocScanner,
	limits: ZipLimits = DEFAULT_ZIP_LIMITS,
): Promise<DocumentOutcome> {
	const totals = newTotals();
	try {
		const archive = await openOdf(bytes, limits);
		const refusals = new Set<string>();
		await entryRefusals(archive, refusals);
		// An encrypted package's parts are ciphertext: refuse before trying to parse them.
		if (refusals.has("DOCUMENT_ENCRYPTED")) throw new DocumentRefused(["DOCUMENT_ENCRYPTED"]);
		const models = await buildModels(archive, scanner, refusals);
		if (refusals.size) throw new DocumentRefused([...refusals].sort());
		const replacements = new Map<string, Uint8Array>();
		for (const part of models) {
			const masked = await maskPart(part, scanner, totals);
			if (masked) replacements.set(part.entry.name, masked);
		}
		await handleImages(archive, replacements, scanner, totals);
		if (!replacements.size) return { bytes: null, ...totals };
		const out = await rewriteZip(archive, replacements);
		readZip(out, archive.limits); // structural self-check of what is handed to the page
		return { bytes: out, ...totals };
	} catch (error) {
		throw asDocumentRefusal(error);
	}
}
