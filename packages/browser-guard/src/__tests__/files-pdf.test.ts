import { describe, expect, it } from "vitest";
import { parseCMap, splitCodes } from "../engine/pdf/cmap.js";
import { decodeTextString, glyphToUnicode } from "../engine/pdf/encodings.js";
import { DEFAULT_PDF_LIMITS, extractPdfText, PdfUnreadable } from "../engine/pdf/extract.js";
import {
	ascii85Decode,
	asciiHexDecode,
	lzwDecode,
	runLengthDecode,
} from "../engine/pdf/filters.js";
import { type PdfObject, pdfFile, pdfString, sanitize, simplePdf } from "./helpers/documents.js";

const EMAIL = "ali.veli@ornek.com.tr";
const TCKN = "10000000146";

const latin1 = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);

function textPage(lines: readonly string[], font = "F1"): string {
	const body = lines.map((l, i) => `${i === 0 ? "72 720 Td" : "0 -16 Td"} ${pdfString(l)} Tj`);
	return `BT /${font} 12 Tf ${body.join(" ")} ET`;
}

async function text(bytes: Uint8Array): Promise<string> {
	return (await extractPdfText(bytes)).segments.join("\n");
}

/** A Type0 (Identity-H) font whose ToUnicode maps code i+1 to the i-th distinct char. */
function type0(content: string, withToUnicode = true): { page: string; objects: PdfObject[] } {
	const chars = [...new Set(content)];
	const hex = [...content]
		.map((c) => (chars.indexOf(c) + 1).toString(16).padStart(4, "0"))
		.join("");
	const bfchar = chars
		.map(
			(c, i) =>
				`<${(i + 1).toString(16).padStart(4, "0")}> <${c.charCodeAt(0).toString(16).padStart(4, "0")}>`,
		)
		.join("\n");
	const cmap = `/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CMapName /Adobe-Identity-UCS def 1 begincodespacerange <0000> <FFFF> endcodespacerange ${chars.length} beginbfchar\n${bfchar}\nendbfchar endcmap CMapName currentdict /CMap defineresource pop end end`;
	return {
		page: `BT /F3 11 Tf 72 700 Td <${hex}> Tj ET`,
		objects: [
			`<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEF+Arial /Encoding /Identity-H /DescendantFonts [8 0 R]${withToUnicode ? " /ToUnicode 9 0 R" : ""} >>`,
			"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEF+Arial /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /DW 500 >>",
			{ dict: "", data: cmap },
		],
	};
}

describe("PDF text extraction", () => {
	it("extracts WinAnsi text, keeping lines apart", async () => {
		const pdf = await simplePdf([textPage(["Merhaba Dünya", `E-posta: ${EMAIL}`])]);
		expect(await text(pdf)).toBe(`Merhaba Dünya\nE-posta: ${EMAIL}`);
	});

	it("maps Turkish letters through /Differences glyph names", async () => {
		// 128..133 = ğ ş ı İ Ş Ğ
		const pdf = await simplePdf([
			"BT /F2 12 Tf 72 720 Td (A\u0080a\u0081 \u0082l\u0083k \u0084ule \u0085) Tj ET",
		]);
		expect(await text(pdf)).toBe("Ağaş ılİk Şule Ğ");
	});

	it("reconstructs words from TJ spacing and positioned fragments", async () => {
		const pdf = await simplePdf([
			"BT /F1 12 Tf 72 720 Td [(Ahmet)-600(Y)80(ilmaz)] TJ ET BT /F1 12 Tf 72 700 Td (10000) Tj (000146) Tj ET BT /F1 12 Tf 72 680 Td (Ad:) Tj 120 0 Td (Ayse) Tj ET",
		]);
		const lines = (await text(pdf)).split("\n");
		expect(lines[0]).toBe("Ahmet Yilmaz");
		expect(lines[1]).toBe(TCKN);
		expect(lines[2]).toBe("Ad: Ayse");
	});

	it("uses ToUnicode CMaps for Type0 (Identity-H) fonts", async () => {
		const t = type0(`Kimlik ${TCKN} İşçi ğüş`);
		expect(await text(await simplePdfWithF3(t.page, t.objects))).toBe(`Kimlik ${TCKN} İşçi ğüş`);
	});

	it("reports PDF_PARTIAL when Type0 glyphs cannot be mapped (no ToUnicode)", async () => {
		const t = type0("gizli metin", false);
		const result = await extractPdfText(await simplePdfWithF3(t.page, t.objects));
		expect(result.complete).toBe(false);
		expect(result.reasons).toEqual(["PDF_NO_TEXT"]);
		const mixed = await simplePdfWithF3(
			`${t.page} BT /F1 12 Tf 72 600 Td (Görünür metin) Tj ET`,
			t.objects,
		);
		const r2 = await extractPdfText(mixed);
		expect(r2.reasons).toEqual(["PDF_PARTIAL"]);
	});

	it("reads text inside Form XObjects", async () => {
		const pdf = await simplePdf(["q 1 0 0 1 50 50 cm /Fm1 Do Q"], {
			resourcesExtra: "/XObject << /Fm1 7 0 R >>",
			extraObjects: [
				{
					dict: "/Type /XObject /Subtype /Form /BBox [0 0 500 500] /Resources << /Font << /F1 3 0 R >> >>",
					data: `BT /F1 10 Tf 0 0 Td ${pdfString(`Form: ${EMAIL}`)} Tj ET`,
				},
			],
		});
		expect(await text(pdf)).toContain(`Form: ${EMAIL}`);
	});

	it("reads annotation contents, form field values and document info", async () => {
		const pdf = await simplePdf([textPage(["Başvuru"])], {
			pageExtra: "/Annots [7 0 R]",
			catalogExtra: "/AcroForm << /Fields [8 0 R] >>",
			trailerExtra: "/Info 9 0 R",
			extraObjects: [
				`<< /Type /Annot /Subtype /Text /Rect [0 0 10 10] /Contents ${pdfString("not: ayse@firma.com")} >>`,
				`<< /FT /Tx /T (tckn) /V (${TCKN}) >>`,
				// Author in UTF-16BE with a BOM: "Şule"
				"<< /Author <FEFF015E0075006C0065> /Title (Rapor) >>",
			],
		});
		const all = await text(pdf);
		expect(all).toContain("ayse@firma.com");
		expect(all).toContain(TCKN);
		expect(all).toContain("Şule");
	});

	it("expands object streams referenced from an xref stream trailer", async () => {
		const objs = [
			[10, "<< /Type /Catalog /Pages 11 0 R >>"],
			[11, "<< /Type /Pages /Kids [12 0 R] /Count 1 >>"],
			[
				12,
				"<< /Type /Page /Parent 11 0 R /Resources << /Font << /F1 13 0 R >> >> /Contents 2 0 R >>",
			],
			[13, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"],
		] as const;
		let body = "";
		const header: string[] = [];
		for (const [num, src] of objs) {
			header.push(`${num} ${body.length}`);
			body += `${src}\n`;
		}
		const head = `${header.join(" ")}\n`;
		// No classic trailer: the catalog is only reachable through the xref stream's /Root.
		const pdf = await pdfFile(
			[
				{ dict: `/Type /ObjStm /N ${objs.length} /First ${head.length}`, data: head + body },
				{ dict: "", data: textPage([`ObjStm ${EMAIL}`]) },
				{ dict: "/Type /XRef /Size 14 /Root 10 0 R /W [1 2 1]", data: "", compress: false },
			],
			null,
		);
		expect(await text(pdf)).toContain(`ObjStm ${EMAIL}`);
	});

	it("decodes ASCIIHex and uncompressed content streams", async () => {
		const content = textPage([`Hex ${EMAIL}`]);
		const hex = [...latin1(content)].map((b) => b.toString(16).padStart(2, "0")).join("");
		const custom = await pdfFile([
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>",
			"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 4 0 R >>",
			{ dict: "/Filter /ASCIIHexDecode", data: `${hex}>`, compress: false },
			"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>",
			{ dict: "", data: textPage(["Raw stream"]), compress: false },
			"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		]);
		const result = await extractPdfText(custom);
		expect(result.segments[0]).toBe(`Hex ${EMAIL}`);
		expect(result.segments[1]).toBe("Raw stream");
		expect(result.complete).toBe(true);
	});

	it("skips inline image data", async () => {
		const pdf = await simplePdf([
			`BI /W 4 /H 1 /BPC 8 /CS /G ID \u0000ÿ() EI ${textPage(["Sonra"])}`,
		]);
		expect(await text(pdf)).toBe("Sonra");
	});

	it("flags image-only pages and documents without text", async () => {
		const image = {
			dict: "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8",
			data: "\u0000",
			compress: false,
		} as const;
		const scanned = await simplePdf(["q 200 0 0 200 100 500 cm /Im1 Do Q"], {
			resourcesExtra: "/XObject << /Im1 7 0 R >>",
			extraObjects: [image],
		});
		expect(await extractPdfText(scanned)).toMatchObject({
			complete: false,
			reasons: ["PDF_NO_TEXT"],
		});
		const mixed = await simplePdf([textPage(["Kapak"]), "q 200 0 0 200 100 500 cm /Im1 Do Q"], {
			resourcesExtra: "/XObject << /Im1 9 0 R >>",
			extraObjects: [image],
		});
		expect(await extractPdfText(mixed)).toMatchObject({
			complete: false,
			reasons: ["PDF_PARTIAL"],
		});
	});

	it("refuses encrypted and non-PDF input", async () => {
		const encrypted = await simplePdf([textPage(["x"])], { trailerExtra: "/Encrypt 99 0 R" });
		await expect(extractPdfText(encrypted)).rejects.toEqual(new PdfUnreadable("PDF_ENCRYPTED"));
		await expect(extractPdfText(latin1("not a pdf"))).rejects.toEqual(
			new PdfUnreadable("PDF_UNPARSEABLE"),
		);
		await expect(extractPdfText(latin1("%PDF-1.7\n%%EOF\n"))).rejects.toEqual(
			new PdfUnreadable("PDF_UNPARSEABLE"),
		);
	});

	it("marks a truncated Flate stream as partial", async () => {
		const good = await simplePdf([textPage([`Kesik ${EMAIL}`])]);
		const src = String.fromCharCode(...good);
		const start = src.indexOf("stream\n", src.indexOf("/FlateDecode")) + 7;
		const end = src.indexOf("\nendstream", start);
		// Drop the adler32 trailer and the end of the deflate data.
		const cut = new Uint8Array([...good.subarray(0, end - 6), ...good.subarray(end)]);
		const result = await extractPdfText(cut);
		expect(result.complete).toBe(false);
		expect(start).toBeGreaterThan(0);
	});

	it("stops at the inflate budget (decompression bomb) instead of exhausting memory", async () => {
		const bomb = await simplePdf([`${textPage(["Önce"])}${" ".repeat(4 * 1024 * 1024)}`]);
		const started = Date.now();
		const result = await extractPdfText(bomb, undefined, {
			...DEFAULT_PDF_LIMITS,
			maxStreamBytes: 64 * 1024,
		});
		expect(Date.now() - started).toBeLessThan(5_000);
		expect(result.complete).toBe(false);
	});
});

/** A one-page PDF with F1 = Helvetica and F3 = the Type0 font objects (numbered 7, 8, 9). */
function simplePdfWithF3(page: string, objects: PdfObject[]): Promise<Uint8Array> {
	return pdfFile([
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [5 0 R] /Count 1 >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		"null",
		"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R /F3 7 0 R >> >> /Contents 6 0 R >>",
		{ dict: "", data: page },
		...objects,
	]);
}

describe("PDF sanitizeFile decisions", () => {
	it.each(["auto", "confirm", "block"] as const)(
		"blocks a PDF with sensitive data in %s mode (SENSITIVE_DATA_IN_PDF)",
		async (mode) => {
			const pdf = await simplePdf([textPage([`E-posta: ${EMAIL}`, `TCKN: ${TCKN}`])]);
			const d = await sanitize("rapor.pdf", pdf, { type: "application/pdf", policy: { mode } });
			expect(d.action).toBe("block");
			expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_PDF"]);
			expect(d.counts).toMatchObject({ EMAIL: 1, TC_KIMLIK: 1 });
			expect(d.masked).toBeUndefined();
		},
	);

	it("records (allows) a PDF with sensitive data in monitor mode", async () => {
		const pdf = await simplePdf([textPage([`E-posta: ${EMAIL}`])]);
		const d = await sanitize("rapor.pdf", pdf, { policy: { mode: "monitor" } });
		expect(d).toEqual({
			action: "allow",
			counts: { EMAIL: 1 },
			reasons: ["SENSITIVE_DATA_IN_PDF"],
		});
	});

	it("allows a clean, fully readable PDF", async () => {
		const pdf = await simplePdf([textPage(["Toplantı gündemi", "Bütçe ve planlama"])]);
		expect(await sanitize("gundem.pdf", pdf)).toEqual({ action: "allow", counts: {}, reasons: [] });
		expect(await sanitize("gundem.pdf", pdf, { policy: { mode: "block" } })).toEqual({
			action: "allow",
			counts: {},
			reasons: [],
		});
	});

	it("treats scanned (image-only) PDFs as unscanned binaries", async () => {
		const pdf = await simplePdf(["q 200 0 0 200 100 500 cm /Im1 Do Q"], {
			resourcesExtra: "/XObject << /Im1 7 0 R >>",
			extraObjects: [
				{
					dict: "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8",
					data: "\u0000",
					compress: false,
				},
			],
		});
		expect(await sanitize("tarama.pdf", pdf)).toEqual({
			action: "allow",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNED", "PDF_NO_TEXT"],
		});
		expect(await sanitize("tarama.pdf", pdf, { policy: { mode: "block" } })).toEqual({
			action: "block",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNABLE", "PDF_NO_TEXT"],
		});
	});

	it("blocks a partially readable PDF when the readable part has findings", async () => {
		const pdf = await simplePdf(
			[textPage([`E-posta: ${EMAIL}`]), "q 200 0 0 200 100 500 cm /Im1 Do Q"],
			{
				resourcesExtra: "/XObject << /Im1 9 0 R >>",
				extraObjects: [
					{
						dict: "/Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray /BitsPerComponent 8",
						data: "\u0000",
						compress: false,
					},
				],
			},
		);
		const d = await sanitize("karma.pdf", pdf);
		expect(d.action).toBe("block");
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_PDF"]);
	});

	it("treats encrypted and unparseable PDFs as unscanned binaries", async () => {
		const encrypted = await simplePdf([textPage([EMAIL])], { trailerExtra: "/Encrypt 99 0 R" });
		expect((await sanitize("sifreli.pdf", encrypted)).reasons).toEqual([
			"BINARY_FILE_UNSCANNED",
			"PDF_ENCRYPTED",
		]);
		expect((await sanitize("bozuk.pdf", latin1("%PDF-1.7\nâã"))).reasons).toEqual([
			"BINARY_FILE_UNSCANNED",
			"PDF_UNPARSEABLE",
		]);
	});

	it("honours documentHandling block/allow for PDFs", async () => {
		const pdf = await simplePdf([textPage([EMAIL])]);
		expect(await sanitize("a.pdf", pdf, { policy: { documentHandling: "block" } })).toEqual({
			action: "block",
			counts: {},
			reasons: ["DOCUMENT_BLOCKED_BY_POLICY"],
		});
		expect(
			(await sanitize("a.pdf", pdf, { policy: { documentHandling: "allow" } })).reasons,
		).toEqual(["BINARY_FILE_UNSCANNED"]);
	});

	it("recognises a PDF without an extension by its header", async () => {
		const pdf = await simplePdf([textPage([EMAIL])]);
		expect((await sanitize("scan0001", pdf)).reasons).toEqual(["SENSITIVE_DATA_IN_PDF"]);
	});

	it("extracts a 300-page PDF within the time budget", async () => {
		const pages = Array.from({ length: 300 }, (_, i) =>
			textPage(
				Array.from(
					{ length: 40 },
					(_, j) => `Sayfa ${i + 1} satır ${j + 1}: rapor metni ve açıklama`,
				),
			),
		);
		pages[299] = textPage([`Son sayfa: ${EMAIL}`]);
		const pdf = await simplePdf(pages);
		const started = Date.now();
		const d = await sanitize("uzun.pdf", pdf);
		expect(Date.now() - started).toBeLessThan(20_000);
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_PDF"]);
	}, 30_000);
});

describe("PDF stream filters", () => {
	it("decodes the ISO 32000 LZW example (EarlyChange 1)", () => {
		const encoded = Uint8Array.from([0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01]);
		const decoded = lzwDecode(encoded, 1000);
		expect(decoded?.complete).toBe(true);
		expect([...(decoded?.data ?? [])]).toEqual([45, 45, 45, 45, 45, 65, 45, 45, 45, 66]);
		expect(lzwDecode(encoded, 3)).toBeNull();
	});

	it("decodes ASCII85 (including z groups and partial final groups) and ASCIIHex", () => {
		expect(new TextDecoder().decode(ascii85Decode(latin1('87cURD_*"s8OQH"~>')))).toBe(
			"Hello, AIDR!",
		);
		expect([...ascii85Decode(latin1("z@:E^~>"))]).toEqual([0, 0, 0, 0, 97, 98, 99]);
		expect(new TextDecoder().decode(asciiHexDecode(latin1("48 65 6c6C 6F7>")))).toBe("Hellop");
	});

	it("decodes RunLength data and stops at the limit", () => {
		const data = Uint8Array.from([2, 0x41, 0x42, 0x43, 0xfe, 0x2d, 128]);
		const decoded = runLengthDecode(data, 100);
		expect(new TextDecoder().decode(decoded?.data)).toBe("ABC---");
		expect(decoded?.complete).toBe(true);
		expect(runLengthDecode(Uint8Array.from([0x81, 0x30]), 10)).toBeNull();
	});
});

describe("PDF encoding helpers", () => {
	it("maps glyph names, uniXXXX forms, suffixes and ligatures", () => {
		expect(glyphToUnicode("gbreve")).toBe("ğ");
		expect(glyphToUnicode("Idotaccent")).toBe("İ");
		expect(glyphToUnicode("dotlessi")).toBe("ı");
		expect(glyphToUnicode("scedilla")).toBe("ş");
		expect(glyphToUnicode("uni011F")).toBe("ğ");
		expect(glyphToUnicode("u1F600")).toBe("😀");
		expect(glyphToUnicode("a.sc")).toBe("a");
		expect(glyphToUnicode("f_f_i")).toBe("ffi");
		expect(glyphToUnicode("g123")).toBeUndefined();
	});

	it("decodes PDF text strings (UTF-16BE BOM, UTF-8 BOM, PDFDocEncoding)", () => {
		expect(decodeTextString("þÿ\u0001^\u0000a")).toBe("Şa");
		expect(decodeTextString("ï»¿Å\u009f")).toBe("ş");
		expect(decodeTextString("café \u0093")).toBe("café ﬁ");
	});

	it("parses bfrange CMaps and splits codes by code-space ranges", () => {
		const cmap = parseCMap(
			"1 begincodespacerange <00> <7F> endcodespacerange 1 begincodespacerange <8000> <FFFF> endcodespacerange 2 beginbfrange <41> <43> <0061> <8001> <8002> [<011F> <015F>] endbfrange",
		);
		const codes = splitCodes("AB\u0080\u0001C\u0080\u0002", cmap.codespace, 1);
		expect(codes.map((c) => c.bytes)).toEqual([1, 1, 2, 1, 2]);
		const out = codes.map((c) => cmap.map.get(c.bytes * 0x1_0000_0000 + c.code)).join("");
		expect(out).toBe("abğcş");
	});
});
