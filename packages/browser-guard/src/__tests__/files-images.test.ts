import { describe, expect, it, vi } from "vitest";
import { blankThumbnail, MAX_OCR_IMAGES, ocrFormat } from "../engine/office/images.js";
import { readEntry, readZip } from "../engine/office/zip.js";
import type { ImageInspection } from "../types.js";
import { docx, odf, para, pptx, run, sanitize, slide } from "./helpers/documents.js";

// Images are never masked: with the native host's OCR an image showing sensitive text blocks the
// upload; anything short of a complete, clean OCR result is reported as not inspected.

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 5, 6, 7, 8, 0xff, 0xd9]);
const WEBP = new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50, 1]);
const GIF = new TextEncoder().encode("GIF89a....");
const EMAIL = "ali.veli@ornek.com.tr";

const sensitive: ImageInspection = {
	result: "sensitive",
	counts: { EMAIL: 1, TC_KIMLIK: 1 },
	reasons: ["IMAGE_SENSITIVE_TEXT"],
};
const clean: ImageInspection = { result: "clean", counts: {}, reasons: [] };
const incomplete: ImageInspection = {
	result: "incomplete",
	counts: {},
	reasons: ["IMAGE_OCR_UNCERTAIN", "not a code"],
};
const ocr = (answer: ImageInspection | null) => vi.fn(async (_bytes: Uint8Array) => answer);

describe("standalone images", () => {
	it("blocks a screenshot whose text holds sensitive data (counts only)", async () => {
		const inspectImage = ocr(sensitive);
		expect(await sanitize("ekran.png", PNG, { inspectImage })).toEqual({
			action: "block",
			counts: { EMAIL: 1, TC_KIMLIK: 1 },
			reasons: ["SENSITIVE_DATA_IN_IMAGE"],
		});
		expect(inspectImage).toHaveBeenCalledWith(PNG);
	});

	it("records instead of blocking in monitor mode", async () => {
		expect(
			await sanitize("ekran.png", PNG, {
				inspectImage: ocr(sensitive),
				policy: { mode: "monitor" },
			}),
		).toEqual({ action: "allow", counts: sensitive.counts, reasons: ["SENSITIVE_DATA_IN_IMAGE"] });
	});

	it("allows an image OCR found clean, in every mode", async () => {
		for (const mode of ["auto", "block"] as const) {
			expect(
				await sanitize("foto.jpg", JPEG, { inspectImage: ocr(clean), policy: { mode } }),
			).toEqual({ action: "allow", counts: {}, reasons: ["IMAGE_OCR_CLEAN"] });
		}
	});

	it("reports an incompletely inspected image as not inspected, with static host codes only", async () => {
		expect(await sanitize("a.webp", WEBP, { inspectImage: ocr(incomplete) })).toEqual({
			action: "allow",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNED", "IMAGE_NOT_INSPECTED", "IMAGE_OCR_UNCERTAIN"],
		});
		expect(
			(await sanitize("a.webp", WEBP, { inspectImage: ocr(incomplete), policy: { mode: "block" } }))
				.action,
		).toBe("block");
	});

	it("treats an unavailable or failing OCR as not inspected, never clean", async () => {
		const failing = vi.fn(async () => {
			throw new Error("host crashed");
		});
		for (const inspectImage of [ocr(null), failing, undefined]) {
			const d = await sanitize("a.png", PNG, inspectImage ? { inspectImage } : {});
			expect(d).toEqual({
				action: "allow",
				counts: {},
				reasons: ["BINARY_FILE_UNSCANNED", "IMAGE_NOT_INSPECTED"],
			});
		}
	});

	it("does not send formats the OCR cannot read, or oversized images", async () => {
		const inspectImage = ocr(clean);
		expect((await sanitize("anim.gif", GIF, { inspectImage })).reasons).toEqual([
			"BINARY_FILE_UNSCANNED",
			"IMAGE_NOT_INSPECTED",
		]);
		const huge = new Uint8Array(8_388_609);
		huge.set(PNG);
		expect((await sanitize("big.png", huge, { inspectImage })).reasons).toContain(
			"IMAGE_NOT_INSPECTED",
		);
		expect(inspectImage).not.toHaveBeenCalled();
	});

	it("recognises an image by content when it has no extension, but not a named text file", async () => {
		const inspectImage = ocr(sensitive);
		expect((await sanitize("upload", PNG, { inspectImage })).action).toBe("block");
		const text = await sanitize("notes.txt", new TextEncoder().encode("hello"), {
			type: "image/png",
			inspectImage,
		});
		expect(text).toEqual({ action: "allow", counts: {}, reasons: [] });
	});

	describe("uninspectedImages", () => {
		const barcodeOnly: ImageInspection = {
			result: "incomplete",
			counts: {},
			reasons: ["IMAGE_BARCODE_NOT_CHECKED"],
		};

		it("block: an image no helper app inspected is not uploaded", async () => {
			for (const inspectImage of [ocr(null), undefined]) {
				const d = await sanitize("a.png", PNG, {
					...(inspectImage ? { inspectImage } : {}),
					policy: { uninspectedImages: "block" },
				});
				expect(d).toEqual({ action: "block", counts: {}, reasons: ["IMAGE_NOT_INSPECTED"] });
			}
		});

		it("block: an image the host could not read to a verdict is not uploaded (host codes kept)", async () => {
			const d = await sanitize("a.webp", WEBP, {
				inspectImage: ocr(incomplete),
				policy: { uninspectedImages: "block" },
			});
			expect(d).toEqual({
				action: "block",
				counts: {},
				reasons: ["IMAGE_NOT_INSPECTED", "IMAGE_OCR_UNCERTAIN"],
			});
		});

		it("block: monitor mode records instead of blocking", async () => {
			const d = await sanitize("a.png", PNG, {
				policy: { uninspectedImages: "block", mode: "monitor" },
			});
			expect(d).toEqual({ action: "allow", counts: {}, reasons: ["IMAGE_NOT_INSPECTED"] });
		});

		it("block: clean text without a barcode decoder is only warned about", async () => {
			const d = await sanitize("a.png", PNG, {
				inspectImage: ocr(barcodeOnly),
				policy: { uninspectedImages: "block" },
			});
			expect(d).toEqual({
				action: "allow",
				counts: {},
				reasons: ["BINARY_FILE_UNSCANNED", "IMAGE_NOT_INSPECTED", "IMAGE_BARCODE_NOT_CHECKED"],
			});
		});

		it("warn (default): uploaded with a warning; sensitive images stay blocked", async () => {
			expect((await sanitize("a.png", PNG, { policy: { uninspectedImages: "warn" } })).action).toBe(
				"allow",
			);
			expect(
				(
					await sanitize("a.png", PNG, {
						inspectImage: ocr(sensitive),
						policy: { uninspectedImages: "warn" },
					})
				).action,
			).toBe("block");
		});
	});

	it("sniffs PNG, JPEG and WebP by magic bytes only", () => {
		expect([ocrFormat(PNG), ocrFormat(JPEG), ocrFormat(WEBP), ocrFormat(GIF)]).toEqual([
			"png",
			"jpeg",
			"webp",
			null,
		]);
	});
});

describe("pictures inside Office documents", () => {
	const withImages = (count: number, bytes = PNG) =>
		Object.fromEntries(
			Array.from({ length: count }, (_, i) => [`word/media/image${i + 1}.png`, bytes] as const),
		);

	it("blocks a DOCX whose picture shows sensitive data", async () => {
		const input = await docx(para(run(`E-posta: ${EMAIL}`)), withImages(1));
		const d = await sanitize("r.docx", input, { inspectImage: ocr(sensitive) });
		expect(d.action).toBe("block");
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_IMAGE"]);
		expect(d.counts).toEqual({ EMAIL: 2, TC_KIMLIK: 1 });
	});

	it("reports pictures it could not inspect, masked or not", async () => {
		const masked = await sanitize("r.docx", await docx(para(run(EMAIL)), withImages(1)));
		expect(masked.action).toBe("mask");
		expect(masked.reasons).toEqual(["SENSITIVE_DATA", "DOCUMENT_IMAGES_NOT_INSPECTED"]);
		const plain = await sanitize("p.docx", await docx(para(run("temiz")), withImages(1)));
		expect(plain).toEqual({
			action: "allow",
			counts: {},
			reasons: ["DOCUMENT_IMAGES_NOT_INSPECTED"],
		});
		const emf = await sanitize(
			"e.docx",
			await docx(para(run("temiz")), { "word/media/image1.emf": new Uint8Array([1, 0, 0, 0]) }),
			{ inspectImage: ocr(clean) },
		);
		expect(emf.reasons).toEqual(["DOCUMENT_IMAGES_NOT_INSPECTED"]);
	});

	it("passes a document whose pictures OCR found clean without a warning", async () => {
		const d = await sanitize("p.docx", await docx(para(run("temiz")), withImages(2)), {
			inspectImage: ocr(clean),
		});
		expect(d).toEqual({ action: "allow", counts: {}, reasons: [] });
	});

	it("bounds the number of OCR calls and stops at the first sensitive picture", async () => {
		const many = ocr(clean);
		const d = await sanitize("m.docx", await docx(para(run("x")), withImages(MAX_OCR_IMAGES + 3)), {
			inspectImage: many,
		});
		expect(many).toHaveBeenCalledTimes(MAX_OCR_IMAGES);
		expect(d.reasons).toEqual(["DOCUMENT_IMAGES_NOT_INSPECTED"]);
		const first = ocr(sensitive);
		await sanitize("s.docx", await docx(para(run("x")), withImages(5)), { inspectImage: first });
		expect(first).toHaveBeenCalledTimes(1);
	});

	it("blocks an OpenDocument whose picture shows sensitive data", async () => {
		const input = await odf("text", "<text:p>temiz</text:p>", {
			extra: { "Pictures/1000000.png": PNG },
		});
		expect((await sanitize("r.odt", input, { inspectImage: ocr(sensitive) })).reasons).toEqual([
			"SENSITIVE_DATA_IN_IMAGE",
		]);
	});

	it("blanks the JPEG thumbnail of a rewritten PPTX", async () => {
		const input = await pptx([slide(`<a:p><a:r><a:t>E-posta: ${EMAIL}</a:t></a:r></a:p>`)], {
			"docProps/thumbnail.jpeg": JPEG,
		});
		const d = await sanitize("s.pptx", input, { inspectImage: ocr(sensitive) });
		// The thumbnail of a masked package is replaced, not sent to OCR (it shows pre-mask text).
		expect(d.action).toBe("mask");
		expect(d.reasons).toEqual(["SENSITIVE_DATA"]);
		const archive = readZip(d.masked?.bytes ?? new Uint8Array());
		const entry = archive.entries.find((e) => e.name === "docProps/thumbnail.jpeg");
		if (!entry) throw new Error("thumbnail missing");
		const thumb = await readEntry(archive, entry);
		expect(thumb).toEqual(blankThumbnail("thumbnail.jpeg"));
		expect([...thumb.subarray(0, 2)]).toEqual([0xff, 0xd8]);
		expect([...thumb.subarray(-2)]).toEqual([0xff, 0xd9]);
	});

	it("inspects the thumbnail of a package that is not rewritten", async () => {
		const input = await pptx([slide("<a:p><a:r><a:t>Yol haritası</a:t></a:r></a:p>")], {
			"docProps/thumbnail.jpeg": JPEG,
		});
		const inspectImage = ocr(clean);
		expect(await sanitize("s.pptx", input, { inspectImage })).toEqual({
			action: "allow",
			counts: {},
			reasons: [],
		});
		expect(inspectImage).toHaveBeenCalledWith(JPEG);
	});
});

describe("blank thumbnails", () => {
	it("builds a baseline JPEG with one grey block", () => {
		const jpeg = blankThumbnail("x.jpg") as Uint8Array;
		const markers: number[] = [];
		for (let i = 2; i < jpeg.length - 2; ) {
			expect(jpeg[i]).toBe(0xff);
			const marker = jpeg[i + 1] as number;
			markers.push(marker);
			const length = ((jpeg[i + 2] as number) << 8) | (jpeg[i + 3] as number);
			i += 2 + length;
			if (marker === 0xda) {
				expect([...jpeg.subarray(i)]).toEqual([0x3f, 0xff, 0xd9]);
				break;
			}
		}
		expect(markers).toEqual([0xdb, 0xc0, 0xc4, 0xc4, 0xda]);
		expect(blankThumbnail("x.emf")).toBeNull();
	});
});
