/**
 * Images embedded in PDFs: extracted (JPEG passed through, raw samples re-encoded as PNG),
 * OCR'd through the native host path (`inspectImage`) and combined with the text layer.
 * Anything short of a complete OCR verdict for an image that may hold text fails closed
 * exactly like an uninspected standalone image. All PDFs are built in the test.
 */
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { blankThumbnail } from "../engine/office/images.js";
import { extractPdfText } from "../engine/pdf/extract.js";
import type { ImageInspection } from "../types.js";
import { type PdfObject, pdfString, sanitize, simplePdf } from "./helpers/documents.js";

const EMAIL = "ali.veli@ornek.com.tr";

const clean: ImageInspection = { result: "clean", counts: {}, reasons: [] };
const sensitive: ImageInspection = {
	result: "sensitive",
	counts: { IBAN: 1, TC_KIMLIK: 1 },
	reasons: [],
};

function textPage(lines: readonly string[]): string {
	const body = lines.map((l, i) => `${i === 0 ? "72 720 Td" : "0 -16 Td"} ${pdfString(l)} Tj`);
	return `BT /F1 12 Tf ${body.join(" ")} ET`;
}

/** An OCR stub that records what it was sent. */
function ocr(result: ImageInspection | null): {
	inspect: (bytes: Uint8Array) => Promise<ImageInspection | null>;
	calls: Uint8Array[];
} {
	const calls: Uint8Array[] = [];
	return {
		calls,
		inspect: async (bytes) => {
			calls.push(bytes);
			return result;
		},
	};
}

/** A 16x16 8-bit greyscale gradient (Flate-compressed by the PDF builder). */
const GRAY = Uint8Array.from({ length: 256 }, (_, i) => i);
const grayImage = (extra = ""): PdfObject => ({
	dict: `/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceGray /BitsPerComponent 8 ${extra}`,
	data: GRAY,
});

/** One page drawing /Im1 (object 7) next to `text`. */
function pdfWithImage(image: PdfObject, text: string[] = ["Ekli görsel"]): Promise<Uint8Array> {
	return simplePdf([`${textPage(text)} q 160 0 0 160 72 400 cm /Im1 Do Q`], {
		resourcesExtra: "/XObject << /Im1 7 0 R >>",
		extraObjects: [image],
	});
}

/** Decodes an 8-bit, non-interlaced PNG produced by the extractor (filter type 0 rows). */
function readPng(bytes: Uint8Array): {
	width: number;
	height: number;
	colorType: number;
	pixels: Uint8Array;
} {
	expect([...bytes.subarray(0, 8)]).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	let offset = 8;
	let width = 0;
	let height = 0;
	let colorType = -1;
	const idat: Uint8Array[] = [];
	while (offset < bytes.length) {
		const length = view.getUint32(offset);
		const type = String.fromCharCode(...bytes.subarray(offset + 4, offset + 8));
		const data = bytes.subarray(offset + 8, offset + 8 + length);
		if (type === "IHDR") {
			width = view.getUint32(offset + 8);
			height = view.getUint32(offset + 12);
			expect(data[8]).toBe(8);
			colorType = data[9] as number;
		} else if (type === "IDAT") idat.push(data);
		offset += 12 + length;
	}
	const raw = inflateSync(Buffer.concat(idat));
	const channels = colorType === 2 ? 3 : 1;
	const stride = 1 + width * channels;
	const pixels = new Uint8Array(width * height * channels);
	for (let y = 0; y < height; y++) {
		expect(raw[y * stride]).toBe(0);
		pixels.set(raw.subarray(y * stride + 1, (y + 1) * stride), y * width * channels);
	}
	return { width, height, colorType, pixels };
}

async function zlib(data: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([new Uint8Array(data)])
		.stream()
		.pipeThrough(new CompressionStream("deflate"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

describe("PDF images: extraction for OCR", () => {
	it("re-encodes a Flate greyscale image XObject as a PNG with the same pixels", async () => {
		const { images, reasons } = await extractPdfText(await pdfWithImage(grayImage()));
		expect(reasons).toEqual([]);
		expect(images).toHaveLength(1);
		const raster = await images[0]?.raster(8 * 1024 * 1024);
		expect(raster?.kind).toBe("image");
		const png = readPng((raster as { bytes: Uint8Array }).bytes);
		expect(png).toMatchObject({ width: 16, height: 16, colorType: 0 });
		expect([...png.pixels]).toEqual([...GRAY]);
	});

	it("passes DCTDecode (JPEG) data through unchanged", async () => {
		const jpeg = blankThumbnail("thumb.jpg") as Uint8Array;
		const pdf = await pdfWithImage({
			dict: "/Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /DCTDecode",
			data: jpeg,
			compress: false,
		});
		const { images } = await extractPdfText(pdf);
		const raster = await images[0]?.raster(8 * 1024 * 1024);
		expect(raster).toEqual({ kind: "image", bytes: jpeg });
	});

	it("undoes PNG predictors and converts RGB, CMYK and Indexed samples", async () => {
		// 8x8 RGB, every row Sub-filtered (type 1) as producers write with /Predictor 15.
		const rgb = Uint8Array.from({ length: 8 * 8 * 3 }, (_, i) => (i * 7) & 0xff);
		const predicted: number[] = [];
		for (let y = 0; y < 8; y++) {
			predicted.push(1);
			for (let x = 0; x < 24; x++) {
				const v = rgb[y * 24 + x] as number;
				const left = x >= 3 ? (rgb[y * 24 + x - 3] as number) : 0;
				predicted.push((v - left) & 0xff);
			}
		}
		const pdf = await simplePdf([`${textPage(["Renkler"])} q /Im1 Do Q q /Im2 Do Q q /Im3 Do Q`], {
			resourcesExtra: "/XObject << /Im1 7 0 R /Im2 8 0 R /Im3 9 0 R >>",
			extraObjects: [
				{
					dict: "/Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceRGB /BitsPerComponent 8 /DecodeParms << /Predictor 15 /Colors 3 /Columns 8 >>",
					data: Uint8Array.from(predicted),
				},
				{
					dict: "/Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace /DeviceCMYK /BitsPerComponent 8",
					data: new Uint8Array(8 * 8 * 4).fill(0),
				},
				{
					// 1 bit per pixel, palette [red, blue], alternating columns.
					dict: "/Type /XObject /Subtype /Image /Width 8 /Height 8 /ColorSpace [/Indexed /DeviceRGB 1 <FF00000000FF>] /BitsPerComponent 1",
					data: new Uint8Array(8).fill(0b01010101),
				},
			],
		});
		const { images } = await extractPdfText(pdf);
		expect(images).toHaveLength(3);
		const [first, second, third] = await Promise.all(
			images.map(async (img) =>
				readPng(((await img.raster(1 << 23)) as { bytes: Uint8Array }).bytes),
			),
		);
		expect(first?.colorType).toBe(2);
		expect([...(first?.pixels ?? [])]).toEqual([...rgb]);
		expect(second?.pixels.every((v) => v === 255)).toBe(true);
		expect([...(third?.pixels.subarray(0, 6) ?? [])]).toEqual([255, 0, 0, 0, 0, 255]);
	});

	it("collects inline images and image XObjects no page draws, but not soft masks", async () => {
		const inline = `BI /W 8 /H 8 /BPC 8 /CS /G ID ${"\u0080".repeat(64)} EI`;
		const pdf = await simplePdf([`${textPage(["Satır içi"])} q ${inline} Q`], {
			extraObjects: [
				grayImage("/SMask 8 0 R"), // 7: not drawn, but an image: collected
				{
					dict: "/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceGray /BitsPerComponent 8",
					data: GRAY,
				}, // 8: soft mask of 7: skipped
			],
		});
		const { images } = await extractPdfText(pdf);
		expect(images).toHaveLength(2);
		const inlinePng = readPng(((await images[0]?.raster(1 << 23)) as { bytes: Uint8Array }).bytes);
		expect(inlinePng.pixels.every((v) => v === 0x80)).toBe(true);
	});
});

describe("PDF images: sanitizeFile with the native host's OCR", () => {
	it.each(["auto", "confirm", "block"] as const)(
		"blocks a PDF whose image shows sensitive data in %s mode",
		async (mode) => {
			const host = ocr(sensitive);
			const pdf = await pdfWithImage(grayImage());
			const d = await sanitize("fatura.pdf", pdf, { policy: { mode }, inspectImage: host.inspect });
			expect(d).toEqual({
				action: "block",
				counts: { IBAN: 1, TC_KIMLIK: 1 },
				reasons: ["SENSITIVE_DATA_IN_IMAGE"],
			});
			expect(host.calls).toHaveLength(1);
			expect(readPng(host.calls[0] as Uint8Array)).toMatchObject({ width: 16, height: 16 });
		},
	);

	it("records (allows) a sensitive PDF image in monitor mode", async () => {
		const host = ocr(sensitive);
		const d = await sanitize("fatura.pdf", await pdfWithImage(grayImage()), {
			policy: { mode: "monitor" },
			inspectImage: host.inspect,
		});
		expect(d).toEqual({
			action: "allow",
			counts: { IBAN: 1, TC_KIMLIK: 1 },
			reasons: ["SENSITIVE_DATA_IN_IMAGE"],
		});
	});

	it("still blocks on text-layer findings (OCR is not needed then)", async () => {
		const host = ocr(clean);
		const d = await sanitize("karma.pdf", await pdfWithImage(grayImage(), [`E-posta: ${EMAIL}`]), {
			inspectImage: host.inspect,
		});
		expect(d.action).toBe("block");
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_PDF"]);
		expect(host.calls).toHaveLength(0);
	});

	it("allows a PDF whose text and images are clean", async () => {
		const host = ocr(clean);
		const pdf = await pdfWithImage(grayImage());
		for (const mode of ["auto", "block"] as const) {
			expect(
				await sanitize("temiz.pdf", pdf, { policy: { mode }, inspectImage: host.inspect }),
			).toEqual({ action: "allow", counts: {}, reasons: ["PDF_IMAGES_OCR_CLEAN"] });
		}
	});

	it("treats a scanned PDF whose every image was OCR'd clean as fully read", async () => {
		const host = ocr(clean);
		const pdf = await simplePdf(
			["q 595 0 0 842 0 0 cm /Im1 Do Q", "q 595 0 0 842 0 0 cm /Im2 Do Q"],
			{
				resourcesExtra: "/XObject << /Im1 9 0 R /Im2 10 0 R >>",
				extraObjects: [grayImage(), grayImage()],
			},
		);
		expect(await sanitize("tarama.pdf", pdf, { inspectImage: host.inspect })).toEqual({
			action: "allow",
			counts: {},
			reasons: ["PDF_IMAGES_OCR_CLEAN"],
		});
		expect(host.calls).toHaveLength(2);
	});

	it("fails closed when OCR is unavailable (no host, or a host without OCR)", async () => {
		const pdf = await pdfWithImage(grayImage());
		const expected = ["PDF_IMAGES_NOT_INSPECTED", "PDF_IMAGE_OCR_UNAVAILABLE"];
		expect(await sanitize("ekli.pdf", pdf)).toEqual({
			action: "allow",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNED", ...expected],
		});
		expect(await sanitize("ekli.pdf", pdf, { policy: { mode: "block" } })).toEqual({
			action: "block",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNABLE", ...expected],
		});
		const noOcr = ocr(null);
		expect(
			await sanitize("ekli.pdf", pdf, { policy: { mode: "block" }, inspectImage: noOcr.inspect }),
		).toEqual({ action: "block", counts: {}, reasons: ["BINARY_FILE_UNSCANNABLE", ...expected] });
		const throwing = async (): Promise<ImageInspection | null> => {
			throw new Error("port closed");
		};
		expect(
			(await sanitize("ekli.pdf", pdf, { policy: { mode: "block" }, inspectImage: throwing }))
				.action,
		).toBe("block");
	});

	it("keeps a scanned PDF's text-layer reason next to the image reasons when OCR is missing", async () => {
		const pdf = await simplePdf(["q 595 0 0 842 0 0 cm /Im1 Do Q"], {
			resourcesExtra: "/XObject << /Im1 7 0 R >>",
			extraObjects: [grayImage()],
		});
		expect((await sanitize("tarama.pdf", pdf, { policy: { mode: "block" } })).reasons).toEqual([
			"BINARY_FILE_UNSCANNABLE",
			"PDF_IMAGES_NOT_INSPECTED",
			"PDF_IMAGE_OCR_UNAVAILABLE",
			"PDF_NO_TEXT",
		]);
	});

	it.each([
		[
			"a truncated Flate image",
			async (): Promise<PdfObject> => ({
				dict: "/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode",
				data: (await zlib(Uint8Array.from({ length: 4096 }, (_, i) => (i * 31) & 0xff))).subarray(
					0,
					40,
				),
				compress: false,
			}),
			"PDF_IMAGE_UNDECODABLE",
		],
		[
			"too few samples for the declared size",
			async (): Promise<PdfObject> => ({
				dict: "/Type /XObject /Subtype /Image /Width 64 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 8",
				data: GRAY,
			}),
			"PDF_IMAGE_UNDECODABLE",
		],
		[
			"DCTDecode data that is not a JPEG",
			async (): Promise<PdfObject> => ({
				dict: "/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode",
				data: "definitely not a jpeg",
				compress: false,
			}),
			"PDF_IMAGE_UNDECODABLE",
		],
		[
			"a JPEG 2000 image",
			async (): Promise<PdfObject> => ({
				dict: "/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /JPXDecode",
				data: "\u0000\u0000\u0000\u000cjP  ",
				compress: false,
			}),
			"PDF_IMAGE_UNSUPPORTED",
		],
		[
			"a DeviceN image",
			async (): Promise<PdfObject> => ({
				dict: "/Type /XObject /Subtype /Image /Width 16 /Height 16 /ColorSpace [/DeviceN [/A /B] /DeviceCMYK 0 0 R] /BitsPerComponent 8",
				data: new Uint8Array(512),
			}),
			"PDF_IMAGE_UNSUPPORTED",
		],
		[
			"an image over the OCR pixel limit",
			async (): Promise<PdfObject> => ({
				dict: "/Type /XObject /Subtype /Image /Width 8192 /Height 8192 /ColorSpace /DeviceGray /BitsPerComponent 8",
				data: GRAY,
			}),
			"PDF_IMAGE_LIMIT",
		],
	])("fails closed on %s without calling OCR", async (_label, image, reason) => {
		const host = ocr(clean);
		const pdf = await pdfWithImage(await image());
		const d = await sanitize("bozuk.pdf", pdf, {
			policy: { mode: "block" },
			inspectImage: host.inspect,
		});
		expect(d).toEqual({
			action: "block",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNABLE", "PDF_IMAGES_NOT_INSPECTED", reason],
		});
		expect(host.calls).toHaveLength(0);
		expect((await sanitize("bozuk.pdf", pdf, { inspectImage: host.inspect })).reasons).toEqual([
			"BINARY_FILE_UNSCANNED",
			"PDF_IMAGES_NOT_INSPECTED",
			reason,
		]);
	});

	it("fails closed when the host cannot read an image fully, passing its reason on", async () => {
		const host = ocr({
			result: "incomplete",
			counts: {},
			reasons: ["IMAGE_NO_TEXT", "free text!"],
		});
		const d = await sanitize("logo.pdf", await pdfWithImage(grayImage()), {
			policy: { mode: "block" },
			inspectImage: host.inspect,
		});
		expect(d.reasons).toEqual([
			"BINARY_FILE_UNSCANNABLE",
			"PDF_IMAGES_NOT_INSPECTED",
			"PDF_IMAGE_OCR_INCOMPLETE",
			"IMAGE_NO_TEXT",
		]);
	});

	it("caps OCR at 16 images per PDF; the rest fail closed", async () => {
		const n = 17;
		const names = Array.from({ length: n }, (_, i) => `/Im${i} ${7 + i} 0 R`).join(" ");
		const draws = Array.from({ length: n }, (_, i) => `q /Im${i} Do Q`).join(" ");
		const pdf = await simplePdf([`${textPage(["Albüm"])} ${draws}`], {
			resourcesExtra: `/XObject << ${names} >>`,
			extraObjects: Array.from({ length: n }, () => grayImage()),
		});
		const host = ocr(clean);
		const d = await sanitize("album.pdf", pdf, {
			policy: { mode: "block" },
			inspectImage: host.inspect,
		});
		expect(host.calls).toHaveLength(16);
		expect(d.reasons).toEqual([
			"BINARY_FILE_UNSCANNABLE",
			"PDF_IMAGES_NOT_INSPECTED",
			"PDF_IMAGE_LIMIT",
		]);
	});

	it("does not send images too small to hold text to OCR", async () => {
		const host = ocr(clean);
		const pdf = await pdfWithImage({
			dict: "/Type /XObject /Subtype /Image /Width 4 /Height 64 /ColorSpace /DeviceGray /BitsPerComponent 8",
			data: new Uint8Array(256),
		});
		expect(await sanitize("ikon.pdf", pdf, { inspectImage: host.inspect })).toEqual({
			action: "allow",
			counts: {},
			reasons: [],
		});
		expect(host.calls).toHaveLength(0);
	});
});
