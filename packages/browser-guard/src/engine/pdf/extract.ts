/**
 * Text extraction from text-based PDFs, for detection only (the file is never rewritten).
 *
 *   ./document.ts  object table, trailers, object streams, stream filters (bounded);
 *   ./fonts.ts     ToUnicode CMaps, base encodings + /Differences, Type0 code lengths, widths;
 *   ./content.ts   text operators, graphics state, Form XObjects, inline images.
 *
 * Pages come from the trailer's `/Root` page tree (falling back to every `/Type /Page`
 * object). Also extracted: annotation contents, link URIs, form field values, document
 * info (title, author, subject, keywords), XMP metadata streams (`/Type /Metadata`, the
 * catalog's and any other: text nodes and attribute values) and embedded files - the
 * `/EmbeddedFiles` name tree, `FileAttachment` annotations, associated files, i.e. every file
 * specification's `/EF` stream and every `/Type /EmbeddedFile` stream - whose content is plain
 * text (strict UTF-8 / BOM-marked UTF-16, no NUL or binary control bytes, no document or archive
 * signature). None of that is drawn on a page, but all of it travels with the file.
 *
 * Completeness (`complete: false` plus a reason) is reported when text may be missing:
 *   PDF_NO_TEXT   no text at all (scanned / image-only document);
 *   PDF_PARTIAL   a page that only draws images, a content stream that could not be decoded
 *                 (unsupported filter, corrupt data), glyphs that could not be mapped to
 *                 Unicode (more than 5%), an XMP stream that could not be decoded, or a
 *                 size/count budget that was reached;
 *   PDF_EMBEDDED_FILES_NOT_INSPECTED
 *                 an embedded file that is not plain text (a nested PDF, an Office document,
 *                 an image, an archive...), could not be decoded, is missing, or is over the
 *                 limits: its content was not scanned, so the PDF is never reported as clean
 *                 (OCR of the page images does not lift this reason).
 * Embedded raster images are collected for the caller's OCR (./images.ts); `reasonsWithImages`
 * is the completeness verdict that applies once every image has been read.
 * `PdfUnreadable` is thrown for files that are not PDFs or cannot be parsed at all
 * (PDF_UNPARSEABLE) and for encrypted files (PDF_ENCRYPTED).
 */

import { decodeXmlText, walkXml } from "../office/xml.js";
import { type ContentContext, interpretContent, PageText } from "./content.js";
import {
	DEFAULT_PDF_LIMITS,
	expandObjectStreams,
	PdfDocument,
	type PdfLimits,
	parseObjects,
} from "./document.js";
import { decodeTextString } from "./encodings.js";
import type { Font } from "./fonts.js";
import { type PdfImage, PdfImageCollector } from "./images.js";
import { binaryString, PdfDict, PdfName, PdfStream, PdfString, type PdfValue } from "./lexer.js";

export { DEFAULT_PDF_LIMITS, type PdfLimits } from "./document.js";

export class PdfUnreadable extends Error {
	constructor(readonly reason: "PDF_UNPARSEABLE" | "PDF_ENCRYPTED") {
		super(reason);
		this.name = "PdfUnreadable";
	}
}

export interface PdfExtraction {
	/** One text per page (in page order), then annotation/form/document-info strings. */
	readonly segments: readonly string[];
	readonly pages: number;
	readonly complete: boolean;
	/** Why the extraction is incomplete (empty when complete). */
	readonly reasons: readonly string[];
	/**
	 * Why the text would still be incomplete if every image were OCR'd: `reasons` without the
	 * image-only causes (`PDF_NO_TEXT` when the document draws images, image-only pages).
	 */
	readonly reasonsWithImages: readonly string[];
	/** Distinct embedded raster images (drawn ones first), for OCR. See ./images.ts. */
	readonly images: readonly PdfImage[];
	/** Images beyond the tracking limit (never inspected). */
	readonly imageOverflow: number;
}

const UNMAPPED_TOLERANCE = 0.05;

// ---------------------------------------------------------------------------------------------
// Pages, annotations, forms, info
// ---------------------------------------------------------------------------------------------

interface PageRef {
	readonly dict: PdfDict;
	readonly resources: PdfDict | undefined;
}

class PageCollector {
	readonly pages: PageRef[] = [];
	private readonly visited = new Set<PdfDict>();

	constructor(private readonly doc: PdfDocument) {}

	walk(node: PdfDict | undefined, inherited: PdfDict | undefined, depth: number): void {
		const { doc } = this;
		if (!node || this.visited.has(node) || depth > 64) return;
		if (this.pages.length >= doc.limits.maxPages) {
			doc.partial = true;
			return;
		}
		this.visited.add(node);
		const resources = doc.dict(node.get("Resources")) ?? inherited;
		const kids = doc.array(node.get("Kids"));
		if (doc.name(node.get("Type")) === "Page" || (!kids && node.get("Contents") !== undefined)) {
			this.pages.push({ dict: node, resources });
			return;
		}
		for (const kid of kids ?? []) this.walk(doc.dict(kid), resources, depth + 1);
	}
}

function collectPages(doc: PdfDocument): PageRef[] {
	const collector = new PageCollector(doc);
	collector.walk(doc.dict(doc.dict(doc.trailer("Root")?.get("Root"))?.get("Pages")), undefined, 0);
	if (collector.pages.length) return collector.pages;
	const byNumber = [...doc.objects.entries()].sort((a, b) => a[0] - b[0]);
	for (const [, entry] of byNumber) {
		const dict = doc.dict(entry.value);
		if (dict && doc.name(dict.get("Type")) === "Page") collector.walk(dict, undefined, 0);
	}
	return collector.pages;
}

function textValue(doc: PdfDocument, v: PdfValue | undefined): string[] {
	const r = doc.resolve(v);
	if (r instanceof PdfString) return [decodeTextString(r.bytes)];
	if (r instanceof PdfName) return [r.name];
	if (Array.isArray(r)) return r.slice(0, 256).flatMap((x) => textValue(doc, x));
	return [];
}

function annotationTexts(doc: PdfDocument, page: PdfDict): string[] {
	const out: string[] = [];
	for (const annot of (doc.array(page.get("Annots")) ?? []).slice(0, 4096)) {
		const dict = doc.dict(annot);
		if (!dict) continue;
		out.push(...textValue(doc, dict.get("Contents")));
		if (doc.name(dict.get("Subtype")) === "Widget") out.push(...textValue(doc, dict.get("V")));
		out.push(...textValue(doc, doc.dict(dict.get("A"))?.get("URI")));
	}
	return out;
}

function formTexts(doc: PdfDocument, catalog: PdfDict | undefined): string[] {
	const out: string[] = [];
	const visited = new Set<PdfDict>();
	const walk = (field: PdfDict | undefined, depth: number): void => {
		if (!field || visited.has(field) || depth > 32 || visited.size > 20_000) return;
		visited.add(field);
		out.push(...textValue(doc, field.get("V")));
		for (const kid of doc.array(field.get("Kids")) ?? []) walk(doc.dict(kid), depth + 1);
	};
	for (const f of doc.array(doc.dict(catalog?.get("AcroForm"))?.get("Fields")) ?? [])
		walk(doc.dict(f), 0);
	return out;
}

function infoTexts(doc: PdfDocument): string[] {
	const info = doc.dict(doc.trailer("Info")?.get("Info"));
	if (!info) return [];
	return ["Title", "Author", "Subject", "Keywords"].flatMap((k) => textValue(doc, info.get(k)));
}

// ---------------------------------------------------------------------------------------------
// Embedded files and XMP metadata
// ---------------------------------------------------------------------------------------------

/** Embedded files read per document; any beyond are reported as not inspected. */
const MAX_EMBEDDED_FILES = 64;
/** Nesting walked inside one object while looking for file specifications. */
const MAX_VALUE_DEPTH = 32;

interface HiddenStreams {
	readonly embedded: Set<PdfStream>;
	readonly metadata: Set<PdfStream>;
	/** A file specification's `/EF` entry that does not resolve to a stream. */
	missing: boolean;
}

/** Records the streams of a file specification's `/EF` dictionary. */
function addEmbeddedStreams(doc: PdfDocument, ef: PdfValue, out: HiddenStreams): void {
	const dict = doc.dict(ef);
	if (!dict) {
		out.missing = true;
		return;
	}
	for (const entry of dict.map.values()) {
		const stream = doc.resolve(entry);
		if (stream instanceof PdfStream) out.embedded.add(stream);
		else out.missing = true;
	}
}

/** Records the `/EF` streams of every file specification nested in `value` (refs not followed). */
function findFileSpecs(doc: PdfDocument, value: PdfValue, out: HiddenStreams, depth: number): void {
	if (depth > MAX_VALUE_DEPTH) {
		out.missing = true; // cannot prove there is no file specification deeper down
		return;
	}
	if (Array.isArray(value)) {
		for (const item of value) findFileSpecs(doc, item, out, depth + 1);
		return;
	}
	const dict = value instanceof PdfStream ? value.dict : value instanceof PdfDict ? value : null;
	for (const [key, item] of dict?.map ?? []) {
		if (key === "EF") addEmbeddedStreams(doc, item, out);
		else findFileSpecs(doc, item, out, depth + 1);
	}
}

/** Embedded-file and metadata streams anywhere in the document. */
function hiddenStreams(doc: PdfDocument): HiddenStreams {
	const out: HiddenStreams = { embedded: new Set(), metadata: new Set(), missing: false };
	for (const entry of doc.objects.values()) {
		const value = entry.value;
		if (value instanceof PdfStream) {
			const type = doc.name(value.dict.get("Type"));
			if (type === "EmbeddedFile") out.embedded.add(value);
			else if (type === "Metadata") out.metadata.add(value);
		}
		findFileSpecs(doc, value, out, 0);
	}
	// A name tree of embedded files that resolves to nothing readable is not "no files".
	const names = doc.dict(doc.dict(doc.trailer("Root")?.get("Root"))?.get("Names"));
	if (names?.get("EmbeddedFiles") !== undefined && out.embedded.size === 0) out.missing = true;
	return out;
}

const NOT_TEXT_SIGNATURES: readonly (readonly number[])[] = [
	[0x25, 0x50, 0x44, 0x46, 0x2d], // %PDF-
	[0x50, 0x4b, 0x03, 0x04], // ZIP (OOXML, ODF, archives)
	[0x50, 0x4b, 0x05, 0x06],
	[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], // OLE compound file (legacy Office)
	[0x7b, 0x5c, 0x72, 0x74, 0x66], // {\rtf (control words, not plain text)
];

/** Strict text decode of an embedded file, or null when it is not plain text. */
function plainText(bytes: Uint8Array): string | null {
	const head = bytes.subarray(0, 1024);
	for (const sig of NOT_TEXT_SIGNATURES) {
		for (let i = 0; i + sig.length <= head.length; i++)
			if (sig.every((b, j) => head[i + j] === b)) return null;
	}
	let encoding = "utf-8";
	if (bytes[0] === 0xff && bytes[1] === 0xfe) encoding = "utf-16le";
	else if (bytes[0] === 0xfe && bytes[1] === 0xff) encoding = "utf-16be";
	let text: string;
	try {
		text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
	} catch {
		return null;
	}
	// NUL and other C0 controls (besides tab/newlines/form feed) mean binary data.
	return /[\u0000-\u0008\u000e-\u001a\u001c-\u001f]/.test(text) ? null : text;
}

/** Text nodes and attribute values (namespace declarations excepted) of an XMP packet. */
function xmpText(xml: string): string {
	const out: string[] = [];
	try {
		walkXml(xml, {
			start(tag) {
				for (const a of tag.attrs)
					if (a.name !== "xmlns" && !a.name.startsWith("xmlns:") && a.value.trim())
						out.push(a.value);
			},
			text(start, end, cdata) {
				const raw = xml.slice(start, end);
				const text = cdata ? raw : decodeXmlText(raw);
				if (text.trim()) out.push(text.trim());
			},
		});
	} catch {
		return xml; // not well-formed: scan the packet as it is
	}
	return out.join("\n");
}

interface Hidden {
	readonly texts: string[];
	/** An embedded file whose content was not scanned. */
	readonly uninspected: boolean;
}

/** Text of XMP metadata and plain-text embedded files; see the module comment. */
async function hiddenTexts(doc: PdfDocument, checkDeadline: () => void): Promise<Hidden> {
	const streams = hiddenStreams(doc);
	const texts: string[] = [];
	let uninspected = streams.missing || streams.embedded.size > MAX_EMBEDDED_FILES;
	let chars = 0;
	const keep = (text: string): boolean => {
		chars += text.length;
		if (chars > doc.limits.maxTextChars) return false;
		texts.push(text);
		return true;
	};
	for (const stream of streams.metadata) {
		checkDeadline();
		const decoded = await doc.stream(stream);
		const text = decoded?.complete ? plainText(decoded.data) : null;
		if (text === null || !keep(xmpText(text))) doc.partial = true;
	}
	for (const stream of [...streams.embedded].slice(0, MAX_EMBEDDED_FILES)) {
		checkDeadline();
		const decoded = await doc.stream(stream);
		const text = decoded?.complete ? plainText(decoded.data) : null;
		if (text === null || !keep(text)) uninspected = true;
	}
	return { texts, uninspected };
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

function looksLikePdf(bytes: Uint8Array): boolean {
	return binaryString(bytes.subarray(0, 1024)).includes("%PDF-");
}

/** The page's content streams, decoded and joined (as the spec concatenates them). */
async function pageContent(doc: PdfDocument, page: PageRef): Promise<string> {
	const contents = doc.resolve(page.dict.get("Contents"));
	const parts: string[] = [];
	for (const item of Array.isArray(contents) ? contents : [contents]) {
		const stream = doc.resolve(item);
		if (!(stream instanceof PdfStream)) continue;
		const decoded = await doc.stream(stream);
		if (!decoded?.complete) doc.partial = true;
		if (decoded) parts.push(binaryString(decoded.data));
	}
	return parts.join("\n");
}

interface Tally {
	textChars: number;
	glyphs: number;
	unmapped: number;
	imageOnlyPages: number;
	images: number;
}

/** Completeness reasons; `withImages`: as if every image had been read (OCR). */
function completeness(
	doc: PdfDocument,
	segments: readonly string[],
	tally: Tally,
	withImages: boolean,
): string[] {
	const imagesCover = withImages && tally.images > 0;
	if (!segments.some((s) => s.trim()) && !imagesCover) return ["PDF_NO_TEXT"];
	const unreliable = tally.glyphs > 0 && tally.unmapped / tally.glyphs > UNMAPPED_TOLERANCE;
	const imageOnly = tally.imageOnlyPages > 0 && !imagesCover;
	return doc.partial || imageOnly || unreliable ? ["PDF_PARTIAL"] : [];
}

/**
 * Extracts the text of a PDF. `checkDeadline` is called between pages and periodically while
 * interpreting; it throws to abort (the caller fails closed).
 */
export async function extractPdfText(
	bytes: Uint8Array,
	checkDeadline: () => void = () => undefined,
	limits: PdfLimits = DEFAULT_PDF_LIMITS,
): Promise<PdfExtraction> {
	if (!looksLikePdf(bytes)) throw new PdfUnreadable("PDF_UNPARSEABLE");
	const doc = new PdfDocument(bytes, binaryString(bytes), limits);
	parseObjects(doc);
	if (doc.trailer("Encrypt")) throw new PdfUnreadable("PDF_ENCRYPTED");
	await expandObjectStreams(doc);
	const pages = collectPages(doc);
	if (!pages.length) throw new PdfUnreadable("PDF_UNPARSEABLE");

	const fonts = new Map<PdfDict, Font>();
	const segments: string[] = [];
	const extras: string[] = [];
	const tally: Tally = { textChars: 0, glyphs: 0, unmapped: 0, imageOnlyPages: 0, images: 0 };
	const images = new PdfImageCollector(doc);
	for (const page of pages) {
		checkDeadline();
		const ctx: ContentContext = {
			doc,
			fonts,
			page: new PageText(),
			checkDeadline,
			forms: 0,
			images,
		};
		await interpretContent(ctx, await pageContent(doc, page), page.resources);
		const { text, glyphs, unmapped, images: pageImages } = ctx.page;
		if (!text.trim() && pageImages > 0) tally.imageOnlyPages++;
		tally.images += pageImages;
		tally.textChars += text.length;
		tally.glyphs += glyphs;
		tally.unmapped += unmapped;
		segments.push(text);
		extras.push(...annotationTexts(doc, page.dict));
		if (tally.textChars > limits.maxTextChars) {
			doc.partial = true;
			break;
		}
	}
	extras.push(...formTexts(doc, doc.dict(doc.trailer("Root")?.get("Root"))), ...infoTexts(doc));
	const hidden = await hiddenTexts(doc, checkDeadline);
	extras.push(...hidden.texts);
	images.addUndrawn();
	const attachments = hidden.uninspected ? ["PDF_EMBEDDED_FILES_NOT_INSPECTED"] : [];
	const reasons = [...completeness(doc, segments, tally, false), ...attachments];
	return {
		segments: [...segments, ...extras.filter((s) => s.trim())],
		pages: pages.length,
		complete: reasons.length === 0,
		reasons,
		reasonsWithImages: [...completeness(doc, segments, tally, true), ...attachments],
		images: images.images(),
		imageOverflow: images.overflow,
	};
}
