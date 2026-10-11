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

describe("PDF recognised by content, whatever the name or MIME type", () => {
	/** Uncompressed PDF whose page draws `line` as a hex string (no NUL byte anywhere). */
	function hexPdf(line: string): Promise<Uint8Array> {
		const hex = [...latin1(line)].map((b) => b.toString(16).padStart(2, "0")).join("");
		return pdfFile([
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [4 0 R] /Count 1 >>",
			"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R >>",
			{ dict: "", data: `BT /F1 12 Tf 72 720 Td <${hex}> Tj ET`, compress: false },
		]);
	}
	const NAMES: ReadonlyArray<readonly [string, string]> = [
		["report.pdf", "application/pdf"],
		["report.txt", "text/plain"],
		["report.txt", "application/pdf"],
		["report.csv", "text/csv"],
		["report.json", "application/json"],
		["report.md", ""],
		["report", ""],
		["report.png", "image/png"],
		["report.zip", "application/zip"],
		["report.docx", ""],
	];

	it("reaches the same decision for the same PDF bytes under every name / MIME type", async () => {
		const pdf = await hexPdf(`E-posta: ${EMAIL}`);
		expect(pdf.includes(0)).toBe(false);
		for (const [name, type] of NAMES) {
			const d = await sanitize(name, pdf, { type });
			expect({ name, type, d }).toEqual({
				name,
				type,
				d: { action: "block", counts: { EMAIL: 1 }, reasons: ["SENSITIVE_DATA_IN_PDF"] },
			});
		}
	});

	it("applies documentHandling to the real type of a renamed PDF", async () => {
		const pdf = await hexPdf("Toplantı gündemi");
		for (const [name, type] of NAMES) {
			expect(await sanitize(name, pdf, { type, policy: { documentHandling: "block" } })).toEqual({
				action: "block",
				counts: {},
				reasons: ["DOCUMENT_BLOCKED_BY_POLICY"],
			});
			expect(await sanitize(name, pdf, { type })).toEqual({
				action: "allow",
				counts: {},
				reasons: [],
			});
		}
	});

	it("recognises a PDF header after leading junk when the file ends like a PDF", async () => {
		const pdf = await hexPdf(`E-posta: ${EMAIL}`);
		const junk = new Uint8Array([...latin1("garbage line\n"), ...pdf]);
		expect((await sanitize("notes.txt", junk, { type: "text/plain" })).reasons).toEqual([
			"SENSITIVE_DATA_IN_PDF",
		]);
	});

	it("does not mistake a text file that mentions %PDF- for a PDF", async () => {
		const note = latin1(`Notes: a PDF starts with %PDF-1.7. Contact ${EMAIL}\n`);
		const d = await sanitize("notes.txt", note, { type: "text/plain" });
		expect(d.action).toBe("mask");
		expect(d.reasons).toEqual(["SENSITIVE_DATA"]);
	});
});

describe("PDF embedded files, attachments and XMP metadata", () => {
	const CLEAN_PAGE = textPage(["Toplantı gündemi", "Bütçe ve planlama"]);
	const filespec = (ef: string) =>
		`<< /Type /Filespec /F (secret.txt) /UF (secret.txt) /EF << /F ${ef} >> >>`;
	const embedded = (data: string | Uint8Array, compress = true): PdfObject => ({
		dict: "/Type /EmbeddedFile /Subtype /text#2Fplain",
		data,
		compress,
	});
	/** Clean visible page; `secret.txt` in the catalog's /EmbeddedFiles name tree (objects 7-9). */
	const withEmbeddedFile = (data: string | Uint8Array, compress = true) =>
		simplePdf([CLEAN_PAGE], {
			catalogExtra: "/Names << /EmbeddedFiles 7 0 R >>",
			extraObjects: [
				"<< /Names [(secret.txt) 8 0 R] >>",
				filespec("9 0 R"),
				embedded(data, compress),
			],
		});

	it("scans a plain-text file in the /EmbeddedFiles name tree behind a clean page", async () => {
		const pdf = await withEmbeddedFile(`kullanici: ali\ne-posta: ${EMAIL}\n`);
		const extraction = await extractPdfText(pdf);
		expect(extraction.segments.join("\n")).toContain(EMAIL);
		expect(extraction.complete).toBe(true);
		for (const mode of ["auto", "block", "confirm"] as const)
			expect(await sanitize("temiz.pdf", pdf, { policy: { mode } })).toEqual({
				action: "block",
				counts: { EMAIL: 1 },
				reasons: ["SENSITIVE_DATA_IN_PDF"],
			});
	});

	it("scans a FileAttachment annotation's embedded file (no /Type on the stream)", async () => {
		const pdf = await simplePdf([CLEAN_PAGE], {
			pageExtra: "/Annots [7 0 R]",
			extraObjects: [
				"<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] /FS 8 0 R /Contents (ek) >>",
				filespec("9 0 R"),
				{ dict: "", data: `TCKN ${TCKN}` },
			],
		});
		const d = await sanitize("ek.pdf", pdf);
		expect(d.action).toBe("block");
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_PDF"]);
		expect(d.counts).toMatchObject({ TC_KIMLIK: 1 });
	});

	it("allows a clean page with a clean plain-text attachment (fully read)", async () => {
		const pdf = await withEmbeddedFile(
			new TextEncoder().encode("Toplantı notları: bütçe onaylandı.\n"),
		);
		expect(await sanitize("temiz.pdf", pdf)).toEqual({ action: "allow", counts: {}, reasons: [] });
	});

	it.each([
		["a nested PDF", latin1(`%PDF-1.4\n1 0 obj << >> endobj\n(${EMAIL})\n%%EOF\n`)],
		["a ZIP / Office package", new Uint8Array([0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 8, 0])],
		["binary data", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0])],
		["non-UTF-8 text", latin1(`e-posta: ${EMAIL} \u00fc\u00e7`)],
	])("never reports a clean page with %s attached as clean", async (_name, data) => {
		const pdf = await withEmbeddedFile(data);
		const extraction = await extractPdfText(pdf);
		expect(extraction.complete).toBe(false);
		expect(extraction.reasons).toEqual(["PDF_EMBEDDED_FILES_NOT_INSPECTED"]);
		expect(extraction.reasonsWithImages).toEqual(["PDF_EMBEDDED_FILES_NOT_INSPECTED"]);
		expect(await sanitize("ekli.pdf", pdf)).toEqual({
			action: "allow",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNED", "PDF_EMBEDDED_FILES_NOT_INSPECTED"],
		});
		expect(await sanitize("ekli.pdf", pdf, { policy: { mode: "block" } })).toEqual({
			action: "block",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNABLE", "PDF_EMBEDDED_FILES_NOT_INSPECTED"],
		});
	});

	it("does not treat a missing or undecodable embedded file as clean", async () => {
		const missing = await simplePdf([CLEAN_PAGE], {
			catalogExtra: "/Names << /EmbeddedFiles 7 0 R >>",
			extraObjects: ["<< /Names [(secret.txt) 8 0 R] >>", filespec("99 0 R")],
		});
		const undecodable = await simplePdf([CLEAN_PAGE], {
			catalogExtra: "/Names << /EmbeddedFiles 7 0 R >>",
			extraObjects: [
				"<< /Names [(secret.txt) 8 0 R] >>",
				filespec("9 0 R"),
				{ dict: "/Type /EmbeddedFile /Filter /JBIG2Decode", data: "xx", compress: false },
			],
		});
		for (const pdf of [missing, undecodable])
			expect((await extractPdfText(pdf)).reasons).toEqual(["PDF_EMBEDDED_FILES_NOT_INSPECTED"]);
	});

	describe("object redefinitions (last definition in the file vs the cross-reference)", () => {
		const IBAN = "TR330006100519786457841326";
		/** Clean page with a FileAttachment annotation (7) -> filespec 8 -> untyped stream 9. */
		const attachment = (trailerExtra: string | null = "") =>
			simplePdf([CLEAN_PAGE], {
				pageExtra: "/Annots [7 0 R]",
				trailerExtra: trailerExtra ?? undefined,
				extraObjects: [
					"<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 10 10] /FS 8 0 R >>",
					filespec("9 0 R"),
					{ dict: "", data: `Customer TCKN ${TCKN} IBAN ${IBAN}\n`, compress: false },
				],
			});
		const append = (pdf: Uint8Array, tail: string): Uint8Array => {
			const out = new Uint8Array(pdf.length + tail.length);
			out.set(pdf);
			out.set(latin1(tail), pdf.length);
			return out;
		};
		const DEAD_FILESPEC = "8 0 obj\n<< /Type /Filespec /F (x.txt) >>\nendobj\n";
		const offsetOf = (pdf: Uint8Array, num: number): number =>
			new TextDecoder("latin1").decode(pdf).indexOf(`\n${num} 0 obj`) + 1;
		/** `pdf` plus object 10: an xref stream (W [1 4 1], PNG "Up" predictor) of `offsets`. */
		const xrefStream = async (pdf: Uint8Array, offsets: number[]): Promise<Uint8Array> => {
			const rows: number[] = [];
			let prev = [0, 0, 0, 0, 0, 0];
			offsets.forEach((pos, n) => {
				const row = [
					n === 0 ? 0 : 1,
					pos >>> 24,
					(pos >>> 16) & 255,
					(pos >>> 8) & 255,
					pos & 255,
					0,
				];
				rows.push(2, ...row.map((b, i) => (b - (prev[i] as number)) & 255));
				prev = row;
			});
			const deflated = new Uint8Array(
				await new Response(
					new Blob([new Uint8Array(rows)]).stream().pipeThrough(new CompressionStream("deflate")),
				).arrayBuffer(),
			);
			const head = append(
				pdf,
				`10 0 obj\n<< /Type /XRef /Size ${offsets.length} /Root 1 0 R /W [1 4 1] /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 6 >> /Length ${deflated.length} >>\nstream\n`,
			);
			const out = new Uint8Array(head.length + deflated.length);
			out.set(head);
			out.set(deflated, head.length);
			return append(out, "\nendstream\nendobj\n");
		};

		it("still scans a file specification shadowed by a dead redefinition after %%EOF", async () => {
			const pdf = append(await attachment(), DEAD_FILESPEC);
			const extraction = await extractPdfText(pdf);
			expect(extraction.segments.join("\n")).toContain(TCKN);
			expect(extraction.complete).toBe(false);
			expect(extraction.reasons).toEqual(["PDF_EMBEDDED_FILES_NOT_INSPECTED"]);
			const d = await sanitize("ek.pdf", pdf);
			expect(d.action).toBe("block");
			expect(d.counts).toMatchObject({ TC_KIMLIK: 1, IBAN: 1 });
		});

		it("flags the same disagreement when the xref is a predicted cross-reference stream", async () => {
			const base = await attachment(null); // no classic xref table: one xref stream instead
			const size = 11;
			const xrefAt = base.length;
			const offsets = Array.from({ length: size }, (_, n) =>
				n === 10 ? xrefAt : n === 0 ? 0 : offsetOf(base, n),
			);
			const consistent = append(await xrefStream(base, offsets), `startxref\n${xrefAt}\n%%EOF\n`);
			expect((await extractPdfText(consistent)).complete).toBe(true);
			const extraction = await extractPdfText(append(consistent, DEAD_FILESPEC));
			expect(extraction.segments.join("\n")).toContain(IBAN);
			expect(extraction.reasons).toEqual(["PDF_EMBEDDED_FILES_NOT_INSPECTED"]);
		});

		it("accepts an incremental update the xref records, and scans the superseded file too", async () => {
			const base = await attachment();
			const prevXref = new TextDecoder("latin1").decode(base).lastIndexOf("xref\n0 ");
			const update = base.length;
			const xrefAt = update + DEAD_FILESPEC.length;
			const pdf = append(
				base,
				`${DEAD_FILESPEC}xref\n8 1\n${String(update).padStart(10, "0")} 00000 n \ntrailer\n<< /Size 10 /Root 1 0 R /Prev ${prevXref} >>\nstartxref\n${xrefAt}\n%%EOF\n`,
			);
			const extraction = await extractPdfText(pdf);
			// The superseded attachment still travels with the file: it is scanned, not hidden.
			expect(extraction.segments.join("\n")).toContain(TCKN);
			expect(extraction.complete).toBe(true);
			expect((await sanitize("ek.pdf", pdf)).action).toBe("block");
		});

		it("scans an untyped stream carrying embedded-file /Params or a MIME /Subtype", async () => {
			for (const dict of [
				"/Params << /Size 40 /ModDate (D:20260101) >>",
				"/Subtype /text#2Fplain",
			]) {
				const pdf = await simplePdf([CLEAN_PAGE], {
					extraObjects: [{ dict, data: `e-posta: ${EMAIL}`, compress: false }],
				});
				expect(await text(pdf)).toContain(EMAIL);
			}
		});
	});

	it("scans XMP metadata (text nodes and attributes) and flags an unreadable packet", async () => {
		const xmp = `<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:pdf="http://ns.adobe.com/pdf/1.3/" pdf:Keywords="iletişim ${EMAIL}"><dc:creator><rdf:Seq><rdf:li>TCKN ${TCKN}</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`;
		const meta = (data: string | Uint8Array, dict = "/Type /Metadata /Subtype /XML") =>
			simplePdf([CLEAN_PAGE], {
				catalogExtra: "/Metadata 7 0 R",
				extraObjects: [{ dict, data, compress: false }],
			});
		const d = await sanitize("meta.pdf", await meta(new TextEncoder().encode(xmp)));
		expect(d.action).toBe("block");
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_PDF"]);
		expect(d.counts).toMatchObject({ EMAIL: 1, TC_KIMLIK: 1 });
		const unreadable = await meta("xx", "/Type /Metadata /Subtype /XML /Filter /JBIG2Decode");
		expect((await extractPdfText(unreadable)).reasons).toEqual(["PDF_PARTIAL"]);
		expect((await sanitize("meta.pdf", unreadable)).reasons).toEqual([
			"BINARY_FILE_UNSCANNED",
			"PDF_PARTIAL",
		]);
	});
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
