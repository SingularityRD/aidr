/**
 * Images inside Office packages (OOXML and OpenDocument).
 *
 * Text is masked in place, but pictures are copied byte-for-byte, so an image is never
 * reported as clean just because the text around it was:
 *   - a document thumbnail (`docProps/thumbnail.*`, `Thumbnails/thumbnail.png`) is a rendering
 *     of the first page taken before masking; when the package is rewritten it is replaced by a
 *     blank image of the same format (PNG/JPEG), otherwise it is handled like any other image;
 *   - with the optional native host (OCR), PNG/JPEG/WebP images are inspected: sensitive text
 *     blocks the upload (pixels are not masked); an image that was not fully inspected is
 *     counted as such;
 *   - without OCR (or beyond the limits below, or in a format OCR does not read: EMF/WMF/GIF/
 *     SVG/...) images are counted as not inspected, and the caller reports
 *     `DOCUMENT_IMAGES_NOT_INSPECTED`.
 * Reads stay inside the archive's inflate budget: an image that does not fit is not inspected
 * (never a reason to refuse a document that was acceptable before).
 */
import type { ImageInspection } from "../../types.js";
import { type Counts, mergeCounts } from "../counts.js";
import type { DocScanner } from "./scanner.js";
import { crc32, readEntry, type ZipArchive, type ZipEntry } from "./zip.js";

/** Most images OCR'd per document; the rest count as not inspected. */
export const MAX_OCR_IMAGES = 16;
/** Largest image sent to the native host (its `image-scan` limit). */
export const MAX_OCR_IMAGE_BYTES = 8_388_608;
/** OCR time per document; images not reached in time count as not inspected. */
export const OCR_BUDGET_MS = 90_000;

const IMAGE_EXTENSION =
	/\.(?:png|apng|jpe?g|jfif|jpe|gif|bmp|dib|tiff?|webp|emf|wmf|emz|wmz|svg|svgz|ico|heic|heif|avif|wdp|jxr|pict?|pcx|tga|eps)$/i;
/** OpenDocument object replacement images carry no extension (`ObjectReplacements/Object 1`). */
const ODF_REPLACEMENT = /(?:^|\/)ObjectReplacements\/[^/]+$/i;
const THUMBNAIL = /^(?:docProps\/thumbnail\.(?:png|jpe?g|emf|wmf)|Thumbnails\/thumbnail\.png)$/i;

export function isImageEntry(name: string): boolean {
	return IMAGE_EXTENSION.test(name) || ODF_REPLACEMENT.test(name);
}

export function isThumbnail(name: string): boolean {
	return THUMBNAIL.test(name);
}

export interface ImageSummary {
	/** Images OCR'd without sensitive text. */
	inspected: number;
	/** Images not (fully) inspected: no OCR, unsupported format, limits, incomplete OCR. */
	notInspected: number;
	/** Images whose text holds sensitive data. */
	sensitive: number;
	readonly counts: Counts;
}

export function emptyImageSummary(): ImageSummary {
	return { inspected: 0, notInspected: 0, sensitive: 0, counts: {} };
}

type OcrFormat = "png" | "jpeg" | "webp";

/** Image formats the native host OCR reads, by content (the name is not trusted). */
export function ocrFormat(bytes: Uint8Array): OcrFormat | null {
	const at = (i: number, ...values: number[]) => values.every((v, j) => bytes[i + j] === v);
	if (at(0, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return "png";
	if (at(0, 0xff, 0xd8, 0xff)) return "jpeg";
	if (at(0, 0x52, 0x49, 0x46, 0x46) && at(8, 0x57, 0x45, 0x42, 0x50)) return "webp";
	return null;
}

// ---------------------------------------------------------------------------------------------
// Blank thumbnails
// ---------------------------------------------------------------------------------------------

function u32be(n: number): number[] {
	return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

function pngChunk(type: string, data: readonly number[]): number[] {
	const body = new Uint8Array([...[...type].map((c) => c.charCodeAt(0)), ...data]);
	return [...u32be(data.length), ...body, ...u32be(crc32(body))];
}

function adler32(data: readonly number[]): number {
	let a = 1;
	let b = 0;
	for (const d of data) {
		a = (a + d) % 65521;
		b = (b + a) % 65521;
	}
	return ((b << 16) | a) >>> 0;
}

/** A 1x1 white RGB PNG (zlib stream with one stored block). */
function blankPng(): Uint8Array {
	const raw = [0, 255, 255, 255];
	const zlib = [
		0x78,
		0x01,
		0x01,
		raw.length,
		0,
		~raw.length & 0xff,
		0xff,
		...raw,
		...u32be(adler32(raw)),
	];
	const header = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
	return new Uint8Array([
		0x89,
		0x50,
		0x4e,
		0x47,
		0x0d,
		0x0a,
		0x1a,
		0x0a,
		...pngChunk("IHDR", header),
		...pngChunk("IDAT", zlib),
		...pngChunk("IEND", []),
	]);
}

/**
 * An 8x8 mid-grey baseline JPEG: one grayscale block whose DCT coefficients are all zero,
 * with one-symbol Huffman tables (DC category 0, AC end-of-block), each coded as the bit 0.
 */
function blankJpeg(): Uint8Array {
	const segment = (marker: number, body: readonly number[]) => [
		0xff,
		marker,
		((body.length + 2) >> 8) & 0xff,
		(body.length + 2) & 0xff,
		...body,
	];
	const oneSymbolTable = (classAndId: number) => [classAndId, 1, ...new Array(15).fill(0), 0x00];
	return new Uint8Array([
		0xff,
		0xd8,
		...segment(0xdb, [0x00, ...new Array(64).fill(1)]),
		...segment(0xc0, [8, 0, 8, 0, 8, 1, 1, 0x11, 0]),
		...segment(0xc4, oneSymbolTable(0x00)),
		...segment(0xc4, oneSymbolTable(0x10)),
		...segment(0xda, [1, 1, 0x00, 0, 63, 0]),
		// DC "0" + EOB "0", padded with one bits.
		0x3f,
		0xff,
		0xd9,
	]);
}

/** Blank replacement for a thumbnail entry, or null when its format cannot be blanked. */
export function blankThumbnail(name: string): Uint8Array | null {
	if (/\.png$/i.test(name)) return blankPng();
	if (/\.jpe?g$/i.test(name)) return blankJpeg();
	return null;
}

// ---------------------------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------------------------

function fitsBudget(archive: ZipArchive, entry: ZipEntry): boolean {
	return (
		entry.uncompressedSize > 0 &&
		entry.uncompressedSize <= MAX_OCR_IMAGE_BYTES &&
		entry.uncompressedSize <= archive.limits.maxEntryBytes &&
		archive.readBytes + entry.uncompressedSize <= archive.limits.maxReadTotal
	);
}

function record(summary: ImageSummary, inspection: ImageInspection | null): void {
	if (inspection?.result === "sensitive") {
		summary.sensitive++;
		mergeCounts(summary.counts, inspection.counts);
	} else if (inspection?.result === "clean") summary.inspected++;
	else summary.notInspected++;
}

/**
 * Inspects `entries` (images of `archive`) with the scanner's OCR, accumulating into `summary`.
 * Stops OCR at the first sensitive image (the document is blocked anyway).
 */
export async function inspectImages(
	archive: ZipArchive,
	entries: readonly ZipEntry[],
	scanner: DocScanner,
	summary: ImageSummary,
	deadline: number,
): Promise<void> {
	let ocrCalls = 0;
	for (const entry of entries) {
		const inspect = scanner.inspectImage;
		const eligible =
			inspect !== undefined &&
			summary.sensitive === 0 &&
			ocrCalls < MAX_OCR_IMAGES &&
			Date.now() < deadline &&
			fitsBudget(archive, entry);
		if (!eligible) {
			summary.notInspected++;
			continue;
		}
		const bytes = await readEntry(archive, entry);
		if (!ocrFormat(bytes)) {
			summary.notInspected++;
			continue;
		}
		ocrCalls++;
		record(summary, await inspect.call(scanner, bytes).catch(() => null));
	}
}
