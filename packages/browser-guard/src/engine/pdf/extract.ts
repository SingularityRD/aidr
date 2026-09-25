/**
 * Text extraction from text-based PDFs, for detection only (the file is never rewritten).
 *
 *   ./document.ts  object table, trailers, object streams, stream filters (bounded);
 *   ./fonts.ts     ToUnicode CMaps, base encodings + /Differences, Type0 code lengths, widths;
 *   ./content.ts   text operators, graphics state, Form XObjects, inline images.
 *
 * Pages come from the trailer's `/Root` page tree (falling back to every `/Type /Page`
 * object). Also extracted: annotation contents, link URIs, form field values and document
 * info (title, author, subject, keywords).
 *
 * Completeness (`complete: false` plus a reason) is reported when text may be missing:
 *   PDF_NO_TEXT   no text at all (scanned / image-only document);
 *   PDF_PARTIAL   a page that only draws images, a content stream that could not be decoded
 *                 (unsupported filter, corrupt data), glyphs that could not be mapped to
 *                 Unicode (more than 5%), or a size/count budget that was reached.
 * `PdfUnreadable` is thrown for files that are not PDFs or cannot be parsed at all
 * (PDF_UNPARSEABLE) and for encrypted files (PDF_ENCRYPTED).
 */
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
import {
	binaryString,
	type PdfDict,
	PdfName,
	PdfStream,
	PdfString,
	type PdfValue,
} from "./lexer.js";

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
// Entry point
// ---------------------------------------------------------------------------------------------

export function looksLikePdf(bytes: Uint8Array): boolean {
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
}

function completeness(doc: PdfDocument, segments: readonly string[], tally: Tally): string[] {
	if (!segments.some((s) => s.trim())) return ["PDF_NO_TEXT"];
	const unreliable = tally.glyphs > 0 && tally.unmapped / tally.glyphs > UNMAPPED_TOLERANCE;
	return doc.partial || tally.imageOnlyPages > 0 || unreliable ? ["PDF_PARTIAL"] : [];
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
	const tally: Tally = { textChars: 0, glyphs: 0, unmapped: 0, imageOnlyPages: 0 };
	for (const page of pages) {
		checkDeadline();
		const ctx: ContentContext = { doc, fonts, page: new PageText(), checkDeadline, forms: 0 };
		await interpretContent(ctx, await pageContent(doc, page), page.resources);
		const { text, glyphs, unmapped, images } = ctx.page;
		if (!text.trim() && images > 0) tally.imageOnlyPages++;
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
	const reasons = completeness(doc, segments, tally);
	return {
		segments: [...segments, ...extras.filter((s) => s.trim())],
		pages: pages.length,
		complete: reasons.length === 0,
		reasons,
	};
}
