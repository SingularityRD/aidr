/**
 * Raster images inside PDFs, prepared for the native host's OCR (which reads PNG/JPEG/WebP).
 *
 * Collected (see {@link PdfImageCollector}): every image XObject drawn by a page (directly or
 * through Form XObjects), every inline image (`BI ... ID ... EI`), then every other image
 * XObject in the file (annotation appearances, patterns, leftovers of incremental updates) that
 * is not merely a soft mask / stencil mask of another image. Each distinct stream is collected
 * once. Over-collection is the safe direction: an extra image costs an OCR call or makes the PDF
 * "not inspected", a missed one would let its pixels through unchecked.
 *
 * Conversion ({@link rasterForOcr}), browser-safe (no canvas, no `node:` imports):
 *   - DCTDecode (JPEG), after any preceding filters, is passed on as is;
 *   - other images are decoded (Flate/LZW/ASCIIHex/ASCII85/RunLength, PNG predictors) and
 *     re-encoded as an 8-bit greyscale or RGB PNG: DeviceGray/CalGray/ICCBased(1), DeviceRGB/
 *     CalRGB/ICCBased(3), DeviceCMYK/ICCBased(4) (naive CMYK->RGB), Indexed over those,
 *     Separation (rendered as ink density) and image masks, 1/2/4/8/16 bits per component;
 *   - JPXDecode (JPEG 2000), JBIG2Decode, CCITTFaxDecode, DeviceN, Lab, TIFF predictors and
 *     anything else are `PDF_IMAGE_UNSUPPORTED`; truncated or corrupt data is
 *     `PDF_IMAGE_UNDECODABLE`; images over the host's size limits are `PDF_IMAGE_LIMIT`.
 *   - Images smaller than {@link MIN_TEXT_IMAGE_DIMENSION} pixels in either direction cannot
 *     hold legible text and are not sent to OCR (`no-text`).
 * The caller treats every failure as "not inspected" (fail closed), never as clean.
 */
import { deflateZlib } from "../office/deflate.js";
import { crc32 } from "../office/zip.js";
import { FILTER_ALIASES, PdfDocument } from "./document.js";
import { PdfDict, PdfName, PdfStream, PdfString, type PdfValue } from "./lexer.js";

/** Host OCR limits (vision worker: 12 Mpx, 8192 px per side). */
export const MAX_OCR_IMAGE_PIXELS = 12_000_000;
export const MAX_OCR_IMAGE_DIMENSION = 8192;
/** Below this many pixels in width or height an image cannot carry legible text. */
export const MIN_TEXT_IMAGE_DIMENSION = 8;
/** Distinct images tracked per PDF; any beyond count as not inspected. */
export const MAX_PDF_IMAGES = 1024;

export type RasterFailure = "PDF_IMAGE_UNSUPPORTED" | "PDF_IMAGE_UNDECODABLE" | "PDF_IMAGE_LIMIT";

export type OcrRaster =
	/** PNG or JPEG bytes the native host can OCR. */
	| { readonly kind: "image"; readonly bytes: Uint8Array }
	/** Too small to hold legible text: nothing to OCR. */
	| { readonly kind: "no-text" }
	| { readonly kind: "failed"; readonly reason: RasterFailure };

interface ImageSource {
	readonly dict: PdfDict;
	readonly data: Uint8Array;
	/** Resources for named colour spaces (inline images only). */
	readonly resources: PdfDict | undefined;
}

/** One embedded image; `raster` decodes it on demand (bounded by the document's budgets). */
export interface PdfImage {
	/**
	 * False only for an image whose declared size is too small to hold legible text (no
	 * decoding needed to tell); such an image is not sent to OCR.
	 */
	readonly mayHoldText: boolean;
	raster(maxBytes: number): Promise<OcrRaster>;
}

// ---------------------------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------------------------

/** Inline image keys and names (ISO 32000-1 Table 93/94) mapped to their full forms. */
const INLINE_KEYS: Readonly<Record<string, string>> = {
	BPC: "BitsPerComponent",
	CS: "ColorSpace",
	D: "Decode",
	DP: "DecodeParms",
	F: "Filter",
	H: "Height",
	IM: "ImageMask",
	I: "Interpolate",
	W: "Width",
};
const INLINE_NAMES: Readonly<Record<string, string>> = {
	G: "DeviceGray",
	RGB: "DeviceRGB",
	CMYK: "DeviceCMYK",
	I: "Indexed",
	DCT: "DCTDecode",
	CCF: "CCITTFaxDecode",
	...FILTER_ALIASES,
};

function expandInlineValue(key: string, v: PdfValue): PdfValue {
	if (key !== "ColorSpace" && key !== "Filter") return v;
	if (v instanceof PdfName) return new PdfName(INLINE_NAMES[v.name] ?? v.name);
	if (Array.isArray(v)) return v.map((x) => expandInlineValue(key, x));
	return v;
}

/** An inline image dictionary (`BI` operands) with abbreviations expanded. */
export function inlineImageDict(entries: ReadonlyArray<readonly [string, PdfValue]>): PdfDict {
	const map = new Map<string, PdfValue>();
	for (const [rawKey, value] of entries) {
		const key = INLINE_KEYS[rawKey] ?? rawKey;
		map.set(key, expandInlineValue(key, value));
	}
	return new PdfDict(map);
}

/** Collects the distinct images of a document (see the module comment). */
export class PdfImageCollector {
	readonly sources: ImageSource[] = [];
	/** Images seen beyond {@link MAX_PDF_IMAGES}. */
	overflow = 0;
	private readonly seen = new Set<PdfStream>();

	constructor(private readonly doc: PdfDocument) {}

	addStream(stream: PdfStream): void {
		if (this.seen.has(stream)) return;
		this.seen.add(stream);
		this.push({
			dict: stream.dict,
			data: this.doc.bytes.subarray(stream.start, stream.end),
			resources: undefined,
		});
	}

	addInline(dict: PdfDict, data: Uint8Array, resources: PdfDict | undefined): void {
		this.push({ dict, data, resources });
	}

	/** Image XObjects not drawn by any page, except soft masks / stencil masks of other images. */
	addUndrawn(): void {
		const { doc } = this;
		const images: PdfStream[] = [];
		const masks = new Set<PdfValue | undefined>();
		for (const { value } of doc.objects.values()) {
			if (!(value instanceof PdfStream) || doc.name(value.dict.get("Subtype")) !== "Image")
				continue;
			images.push(value);
			masks.add(doc.resolve(value.dict.get("SMask")));
			masks.add(doc.resolve(value.dict.get("Mask")));
		}
		for (const image of images) if (!masks.has(image)) this.addStream(image);
	}

	private push(source: ImageSource): void {
		if (this.sources.length >= MAX_PDF_IMAGES) this.overflow++;
		else this.sources.push(source);
	}

	images(): PdfImage[] {
		const { doc } = this;
		return this.sources.map((source) => ({
			mayHoldText: !tooSmallForText(doc, source.dict),
			raster: (maxBytes: number) => rasterForOcr(doc, source, maxBytes),
		}));
	}
}

// ---------------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------------

class RasterError extends Error {
	constructor(readonly reason: RasterFailure) {
		super(reason);
	}
}

const fail = (reason: RasterFailure): never => {
	throw new RasterError(reason);
};

const UNSUPPORTED_FILTERS: ReadonlySet<string> = new Set([
	"JPXDecode",
	"JBIG2Decode",
	"CCITTFaxDecode",
	"Crypt",
]);

interface Encoded {
	/** True: `data` is a JPEG (DCTDecode); false: decoded samples. */
	readonly jpeg: boolean;
	readonly data: Uint8Array;
}

function asList(v: PdfValue | undefined): PdfValue[] {
	if (Array.isArray(v)) return v;
	return v === undefined || v === null ? [] : [v];
}

/** Applies the image's filter chain: JPEG bytes (DCTDecode last) or decoded samples. */
async function decodeFilters(doc: PdfDocument, source: ImageSource): Promise<Encoded> {
	const filters = asList(doc.resolve(source.dict.get("Filter")));
	const parms = asList(doc.resolve(source.dict.get("DecodeParms")));
	let data = source.data;
	for (let i = 0; i < filters.length; i++) {
		const raw = doc.name(filters[i]) ?? fail("PDF_IMAGE_UNSUPPORTED");
		const name = FILTER_ALIASES[raw] ?? raw;
		if (name === "DCTDecode" || name === "DCT") {
			if (i !== filters.length - 1) fail("PDF_IMAGE_UNSUPPORTED");
			return { jpeg: true, data };
		}
		data = await applyImageFilter(doc, name, data, doc.dict(parms[i] ?? undefined));
	}
	return { jpeg: false, data };
}

/** One non-JPEG filter, then its PNG predictor (if any). */
async function applyImageFilter(
	doc: PdfDocument,
	name: string,
	data: Uint8Array,
	parm: PdfDict | undefined,
): Promise<Uint8Array> {
	if (UNSUPPORTED_FILTERS.has(name) || !PdfDocument.knownFilter(name))
		fail("PDF_IMAGE_UNSUPPORTED");
	// A known filter only yields null over the stream/inflate budget.
	const decoded = (await doc.applyFilter(name, data)) ?? fail("PDF_IMAGE_LIMIT");
	if (!decoded.complete) fail("PDF_IMAGE_UNDECODABLE");
	const predictor = doc.num(parm?.get("Predictor")) ?? 1;
	if (parm && predictor >= 10) return unpredictPng(doc, decoded.data, parm);
	if (predictor > 1) fail("PDF_IMAGE_UNSUPPORTED");
	return decoded.data;
}

function paeth(a: number, b: number, c: number): number {
	const p = a + b - c;
	const pa = Math.abs(p - a);
	const pb = Math.abs(p - b);
	const pc = Math.abs(p - c);
	return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/** Reverses PNG row predictors (ISO 32000-1 §7.4.4.4); each row carries its own filter type. */
function unpredictPng(doc: PdfDocument, data: Uint8Array, parm: PdfDict): Uint8Array {
	const colors = doc.num(parm.get("Colors")) ?? 1;
	const bpc = doc.num(parm.get("BitsPerComponent")) ?? 8;
	const columns = doc.num(parm.get("Columns")) ?? 1;
	if (!(colors >= 1 && colors <= 32 && [1, 2, 4, 8, 16].includes(bpc) && columns >= 1))
		fail("PDF_IMAGE_UNSUPPORTED");
	const bpp = Math.max(1, Math.ceil((colors * bpc) / 8));
	const rowBytes = Math.ceil((colors * bpc * columns) / 8);
	const rows = Math.floor(data.length / (rowBytes + 1));
	const out = new Uint8Array(rows * rowBytes);
	for (let r = 0; r < rows; r++) unfilterRow(data, out, r, rowBytes, bpp);
	return out;
}

/** Restores row `r` of `out` from its filtered form (filter type byte + bytes) in `data`. */
function unfilterRow(
	data: Uint8Array,
	out: Uint8Array,
	r: number,
	rowBytes: number,
	bpp: number,
): void {
	const predict =
		PNG_PREDICTORS[data[r * (rowBytes + 1)] as number] ?? fail("PDF_IMAGE_UNDECODABLE");
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

/** PNG filter types 0-4: the prediction added back to each byte. */
const PNG_PREDICTORS: ReadonlyArray<(left: number, up: number, upLeft: number) => number> = [
	() => 0,
	(left) => left,
	(_left, up) => up,
	(left, up) => (left + up) >> 1,
	paeth,
];

// ---------------------------------------------------------------------------------------------
// Colour spaces
// ---------------------------------------------------------------------------------------------

type BaseSpace = "gray" | "rgb" | "cmyk";
type Space =
	| { readonly kind: BaseSpace }
	/** Separation: one tint component, 1 = full ink (dark). */
	| { readonly kind: "ink" }
	| {
			readonly kind: "indexed";
			readonly base: BaseSpace;
			readonly hival: number;
			readonly lookup: Uint8Array;
	  };

const COMPONENTS: Readonly<Record<BaseSpace, number>> = { gray: 1, rgb: 3, cmyk: 4 };
/** ICCBased spaces by their component count `N`. */
const ICC_SPACES: Readonly<Record<number, BaseSpace>> = { 1: "gray", 3: "rgb", 4: "cmyk" };

const DEVICE_SPACES: Readonly<Record<string, BaseSpace>> = {
	DeviceGray: "gray",
	CalGray: "gray",
	G: "gray",
	DeviceRGB: "rgb",
	CalRGB: "rgb",
	RGB: "rgb",
	DeviceCMYK: "cmyk",
	CMYK: "cmyk",
};

async function colorSpace(
	doc: PdfDocument,
	value: PdfValue | undefined,
	resources: PdfDict | undefined,
	depth = 0,
): Promise<Space> {
	if (depth > 4) return fail("PDF_IMAGE_UNSUPPORTED");
	const v = doc.resolve(value);
	if (v instanceof PdfName) {
		const device = DEVICE_SPACES[v.name];
		if (device) return { kind: device };
		const named = doc.dict(resources?.get("ColorSpace"))?.get(v.name);
		if (named !== undefined) return colorSpace(doc, named, undefined, depth + 1);
		return fail("PDF_IMAGE_UNSUPPORTED");
	}
	if (!Array.isArray(v) || !v.length) return fail("PDF_IMAGE_UNSUPPORTED");
	return arraySpace(doc, v, resources, depth);
}

/** A colour space array (`[/ICCBased ...]`, `[/Indexed ...]`, ...). */
function arraySpace(
	doc: PdfDocument,
	v: PdfValue[],
	resources: PdfDict | undefined,
	depth: number,
): Promise<Space> | Space {
	const family = doc.name(v[0]) ?? "";
	const device = DEVICE_SPACES[family];
	if (device) return { kind: device };
	if (family === "ICCBased") {
		const n = doc.num(doc.dict(v[1])?.get("N")) ?? 0;
		return { kind: ICC_SPACES[n] ?? fail("PDF_IMAGE_UNSUPPORTED") };
	}
	if (family === "Separation") return { kind: "ink" };
	if (family === "Indexed" || family === "I") return indexedSpace(doc, v, resources, depth);
	return fail("PDF_IMAGE_UNSUPPORTED");
}

async function indexedSpace(
	doc: PdfDocument,
	v: PdfValue[],
	resources: PdfDict | undefined,
	depth: number,
): Promise<Space> {
	const base = await colorSpace(doc, v[1], resources, depth + 1);
	if (base.kind === "indexed" || base.kind === "ink") return fail("PDF_IMAGE_UNSUPPORTED");
	const hival = doc.num(v[2]);
	if (hival === undefined || !Number.isInteger(hival) || hival < 0 || hival > 255)
		return fail("PDF_IMAGE_UNDECODABLE");
	const table = doc.resolve(v[3]);
	let lookup: Uint8Array;
	if (table instanceof PdfString) lookup = Uint8Array.from(table.bytes, (c) => c.charCodeAt(0));
	else if (table instanceof PdfStream) {
		const decoded = await doc.stream(table);
		if (!decoded?.complete) return fail("PDF_IMAGE_UNDECODABLE");
		lookup = decoded.data;
	} else return fail("PDF_IMAGE_UNDECODABLE");
	if (lookup.length < (hival + 1) * COMPONENTS[base.kind]) return fail("PDF_IMAGE_UNDECODABLE");
	return { kind: "indexed", base: base.kind, hival, lookup };
}

// ---------------------------------------------------------------------------------------------
// Rasterisation
// ---------------------------------------------------------------------------------------------

/** Reads sample `i` of a row at `offset` with `bpc` bits per sample (16-bit: high byte). */
function sample(data: Uint8Array, offset: number, i: number, bpc: number): number {
	if (bpc === 8) return data[offset + i] as number;
	if (bpc === 16) return data[offset + 2 * i] as number;
	const bit = i * bpc;
	const byte = data[offset + (bit >> 3)] as number;
	return (byte >> (8 - bpc - (bit & 7))) & ((1 << bpc) - 1);
}

function cmykToRgb(c: number, m: number, y: number, k: number, out: Uint8Array, at: number): void {
	out[at] = ((255 - c) * (255 - k)) / 255;
	out[at + 1] = ((255 - m) * (255 - k)) / 255;
	out[at + 2] = ((255 - y) * (255 - k)) / 255;
}

interface Geometry {
	readonly width: number;
	readonly height: number;
	readonly bpc: number;
	/** Decode array [1 0]: the single component is inverted. */
	readonly inverted: boolean;
}

/** Writes one pixel (8-bit gray or RGB) from base-space components scaled to 0..255. */
function writeBase(kind: BaseSpace, c: readonly number[], out: Uint8Array, at: number): void {
	if (kind === "gray") out[at] = c[0] as number;
	else if (kind === "rgb") {
		out[at] = c[0] as number;
		out[at + 1] = c[1] as number;
		out[at + 2] = c[2] as number;
	} else cmykToRgb(c[0] as number, c[1] as number, c[2] as number, c[3] as number, out, at);
}

/** Filtered PNG scanlines (filter byte 0 + 8-bit pixels); `channels` is 1 (gray) or 3 (RGB). */
function scanlines(
	data: Uint8Array,
	space: Space,
	g: Geometry,
): { rows: Uint8Array; channels: number } {
	const comps = space.kind === "indexed" || space.kind === "ink" ? 1 : COMPONENTS[space.kind];
	const rowBytes = Math.ceil((g.width * comps * g.bpc) / 8);
	if (data.length < rowBytes * g.height) fail("PDF_IMAGE_UNDECODABLE");
	const base: BaseSpace =
		space.kind === "indexed" ? space.base : space.kind === "ink" ? "gray" : space.kind;
	const channels = base === "gray" ? 1 : 3;
	const stride = 1 + g.width * channels;
	const rows = new Uint8Array(stride * g.height);
	const components = pixelReader(space, g, comps);
	for (let y = 0; y < g.height; y++) {
		const src = y * rowBytes;
		const dst = y * stride + 1;
		for (let x = 0; x < g.width; x++)
			writeBase(base, components(data, src, x), rows, dst + x * channels);
	}
	return { rows, channels };
}

/** Reads pixel `x` of the row at `src` as base-space components scaled to 0..255. */
function pixelReader(
	space: Space,
	g: Geometry,
	comps: number,
): (data: Uint8Array, src: number, x: number) => readonly number[] {
	const c = [0, 0, 0, 0];
	if (space.kind === "indexed") {
		const n = COMPONENTS[space.base];
		return (data, src, x) => {
			const index = Math.min(sample(data, src, x, g.bpc), space.hival);
			for (let k = 0; k < n; k++) c[k] = space.lookup[index * n + k] as number;
			return c;
		};
	}
	const max = (1 << Math.min(g.bpc, 8)) - 1;
	// Separation tint 1 is full ink (dark); a single-component Decode [1 0] flips it again.
	const invert = (space.kind === "ink") !== (g.inverted && comps === 1);
	return (data, src, x) => {
		for (let k = 0; k < comps; k++)
			c[k] = Math.round((sample(data, src, x * comps + k, g.bpc) * 255) / max);
		if (invert) c[0] = 255 - (c[0] as number);
		return c;
	};
}

function u32(n: number): Uint8Array {
	return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function chunk(type: string, data: Uint8Array): Uint8Array[] {
	const body = new Uint8Array(4 + data.length);
	for (let i = 0; i < 4; i++) body[i] = type.charCodeAt(i);
	body.set(data, 4);
	return [u32(data.length), body, u32(crc32(body))];
}

const PNG_SIGNATURE = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

/** An 8-bit greyscale (1 channel) or RGB (3 channels) PNG from filtered scanlines. */
export async function encodePng(
	width: number,
	height: number,
	channels: 1 | 3,
	rows: Uint8Array,
): Promise<Uint8Array> {
	const header = new Uint8Array(13);
	header.set(u32(width), 0);
	header.set(u32(height), 4);
	header[8] = 8;
	header[9] = channels === 1 ? 0 : 2;
	const parts = [
		PNG_SIGNATURE,
		...chunk("IHDR", header),
		...chunk("IDAT", await deflateZlib(rows)),
		...chunk("IEND", new Uint8Array(0)),
	];
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let offset = 0;
	for (const p of parts) {
		out.set(p, offset);
		offset += p.length;
	}
	return out;
}

function isJpeg(data: Uint8Array): boolean {
	return data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
}

/** Dimensions and sample depth from the image dictionary; fails for nonsense values. */
function dimension(doc: PdfDocument, value: PdfValue | undefined): number | null {
	const n = doc.num(value);
	return n !== undefined && Number.isInteger(n) && n > 0 ? n : null;
}

/** Valid declared dimensions below {@link MIN_TEXT_IMAGE_DIMENSION} in either direction. */
function tooSmallForText(doc: PdfDocument, dict: PdfDict): boolean {
	const width = dimension(doc, dict.get("Width"));
	const height = dimension(doc, dict.get("Height"));
	return (
		width !== null &&
		height !== null &&
		(width < MIN_TEXT_IMAGE_DIMENSION || height < MIN_TEXT_IMAGE_DIMENSION)
	);
}

function geometry(doc: PdfDocument, dict: PdfDict, imageMask: boolean): Geometry {
	const width = dimension(doc, dict.get("Width")) ?? fail("PDF_IMAGE_UNDECODABLE");
	const height = dimension(doc, dict.get("Height")) ?? fail("PDF_IMAGE_UNDECODABLE");
	const bpc = imageMask ? 1 : (doc.num(dict.get("BitsPerComponent")) ?? 8);
	const decode = doc.array(dict.get("Decode"));
	return {
		width,
		height,
		bpc,
		inverted: doc.num(decode?.[0]) === 1 && doc.num(decode?.[1]) === 0,
	};
}

async function rasterize(
	doc: PdfDocument,
	source: ImageSource,
	maxBytes: number,
): Promise<OcrRaster> {
	const { dict } = source;
	const imageMask = doc.resolve(dict.get("ImageMask")) === true;
	if (tooSmallForText(doc, dict)) return { kind: "no-text" };
	const g = geometry(doc, dict, imageMask);
	if (
		g.width > MAX_OCR_IMAGE_DIMENSION ||
		g.height > MAX_OCR_IMAGE_DIMENSION ||
		g.width * g.height > MAX_OCR_IMAGE_PIXELS
	)
		fail("PDF_IMAGE_LIMIT");
	const encoded = await decodeFilters(doc, source);
	if (encoded.jpeg) {
		if (!isJpeg(encoded.data)) fail("PDF_IMAGE_UNDECODABLE");
		if (encoded.data.length > maxBytes) fail("PDF_IMAGE_LIMIT");
		return { kind: "image", bytes: encoded.data };
	}
	if (![1, 2, 4, 8, 16].includes(g.bpc)) fail("PDF_IMAGE_UNSUPPORTED");
	const space: Space = imageMask
		? { kind: "gray" }
		: await colorSpace(doc, dict.get("ColorSpace"), source.resources);
	if (space.kind === "indexed" && g.bpc > 8) fail("PDF_IMAGE_UNSUPPORTED");
	const { rows, channels } = scanlines(encoded.data, space, g);
	const png = await encodePng(g.width, g.height, channels as 1 | 3, rows);
	if (png.length > maxBytes) fail("PDF_IMAGE_LIMIT");
	return { kind: "image", bytes: png };
}

/**
 * The image as PNG/JPEG bytes for OCR (at most `maxBytes`), `no-text` for images too small to
 * hold text, or why it could not be prepared. Never throws.
 */
export async function rasterForOcr(
	doc: PdfDocument,
	source: ImageSource,
	maxBytes: number,
): Promise<OcrRaster> {
	try {
		return await rasterize(doc, source, maxBytes);
	} catch (error) {
		return {
			kind: "failed",
			reason: error instanceof RasterError ? error.reason : "PDF_IMAGE_UNDECODABLE",
		};
	}
}
