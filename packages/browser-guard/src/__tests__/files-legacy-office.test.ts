import { describe, expect, it } from "vitest";
import { CfbError, DEFAULT_CFB_LIMITS, readCompoundFile } from "../engine/legacy/cfb.js";
import { extractLegacyOffice } from "../engine/legacy/extract.js";
import { deflateRaw } from "../engine/office/deflate.js";
import { DocumentRefused, DocumentUnreadable } from "../engine/office/ooxml.js";
import { docx, para, run, sanitize } from "./helpers/documents.js";
import {
	buildCfb,
	type CfbNode,
	cfbBytes,
	concatBytes,
	cString,
	excelNodes,
	out,
	pptNodes,
	pptRecord,
	summaryInformation,
	textBytes,
	textChars,
	wordNodes,
} from "./helpers/legacy-office.js";

// Synthetic test data only (example.invalid-style addresses, checksum-valid fake TCKN).
const EMAIL = "ali.veli@ornek.com.tr";
const TCKN = "10000000146";

const bytesOf = (n: number, fill = 0x41) => new Uint8Array(n).fill(fill);

async function text(bytes: Uint8Array): Promise<string> {
	return (await extractLegacyOffice(bytes)).segments.map((s) => s.value).join("\n");
}

async function refusal(bytes: Uint8Array): Promise<readonly string[]> {
	try {
		await extractLegacyOffice(bytes);
	} catch (error) {
		if (error instanceof DocumentRefused) return error.reasons;
		throw error;
	}
	throw new Error("not refused");
}

function cfbCode(fn: () => unknown): string {
	try {
		fn();
	} catch (error) {
		if (error instanceof CfbError) return error.code;
		throw error;
	}
	return "OK";
}

describe("compound file reader", () => {
	it("reads mini-stream and regular streams and nested storages", () => {
		const small = bytesOf(100, 0x61);
		const large = bytesOf(5000, 0x62);
		const cfb = readCompoundFile(
			cfbBytes([
				{ name: "Small", data: small },
				{ name: "Big", data: large },
				{ name: "Store", children: [{ name: "Inner", data: bytesOf(10, 0x63) }] },
			]),
		);
		expect(cfb.entries.map((e) => e.path)).toEqual(["Small", "Big", "Store", "Store/Inner"]);
		expect(cfb.read(cfb.child("small") as never)).toEqual(small);
		expect(cfb.read(cfb.child("Big") as never)).toEqual(large);
		const inner = cfb.child("Store")?.children[0];
		expect(cfb.read(inner as never)).toEqual(bytesOf(10, 0x63));
	});

	it("rejects files that are not compound files", () => {
		expect(cfbCode(() => readCompoundFile(new TextEncoder().encode("plain text")))).toBe("NOT_CFB");
	});

	it("fails closed on a cyclic FAT chain", () => {
		const { bytes, layout } = buildCfb([{ name: "Big", data: bytesOf(5000) }]);
		const start = layout.largeStart.get("Big") as number;
		// Point the stream's third sector back at its first.
		new DataView(bytes.buffer).setUint32(layout.fatOffset + (start + 2) * 4, start, true);
		const cfb = readCompoundFile(bytes);
		expect(cfbCode(() => cfb.read(cfb.child("Big") as never))).toBe("MALFORMED");
	});

	it("fails closed on a self-referencing directory chain and a cyclic sibling tree", () => {
		const { bytes, layout } = buildCfb([{ name: "A", data: bytesOf(10) }]);
		const dirSector = (layout.dirOffset - 512) / 512;
		const looped = bytes.slice();
		new DataView(looped.buffer).setUint32(layout.fatOffset + dirSector * 4, dirSector, true);
		expect(cfbCode(() => readCompoundFile(looped))).toBe("MALFORMED");
		const sibling = bytes.slice();
		// Entry 1 ("A") names itself as its right sibling.
		new DataView(sibling.buffer).setUint32(layout.dirOffset + 128 + 0x48, 1, true);
		expect(cfbCode(() => readCompoundFile(sibling))).toBe("MALFORMED");
	});

	it("fails closed on a truncated file and on sectors outside the file", () => {
		const { bytes, layout } = buildCfb([{ name: "Big", data: bytesOf(5000) }]);
		const truncated = bytes.subarray(0, bytes.length - 1500);
		const cfb = readCompoundFile(truncated);
		expect(cfbCode(() => cfb.read(cfb.child("Big") as never))).toBe("MALFORMED");
		const outside = bytes.slice();
		const start = layout.largeStart.get("Big") as number;
		new DataView(outside.buffer).setUint32(layout.fatOffset + start * 4, 0x00ffffff, true);
		const c2 = readCompoundFile(outside);
		expect(cfbCode(() => c2.read(c2.child("Big") as never))).toBe("MALFORMED");
		expect(cfbCode(() => readCompoundFile(bytes.subarray(0, 300)))).toBe("MALFORMED");
	});

	it("rejects a corrupt header", () => {
		const bytes = cfbBytes([{ name: "A", data: bytesOf(10) }]);
		const order = bytes.slice();
		order[0x1c] = 0;
		expect(cfbCode(() => readCompoundFile(order))).toBe("MALFORMED");
		const shift = bytes.slice();
		shift[0x1e] = 20;
		expect(cfbCode(() => readCompoundFile(shift))).toBe("MALFORMED");
		const fatCount = bytes.slice();
		new DataView(fatCount.buffer).setUint32(0x2c, 100_000, true);
		expect(cfbCode(() => readCompoundFile(fatCount))).toBe("MALFORMED");
		const magicOnly = new Uint8Array(1024);
		magicOnly.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
		expect(cfbCode(() => readCompoundFile(magicOnly))).toBe("MALFORMED");
	});

	it("enforces size limits", () => {
		const bytes = cfbBytes([{ name: "Big", data: bytesOf(6000) }]);
		expect(
			cfbCode(() => readCompoundFile(bytes, { ...DEFAULT_CFB_LIMITS, maxFileBytes: 4096 })),
		).toBe("LIMIT");
		const cfb = readCompoundFile(bytes, { ...DEFAULT_CFB_LIMITS, maxStreamBytes: 5000 });
		expect(cfbCode(() => cfb.read(cfb.child("Big") as never))).toBe("LIMIT");
		// A declared stream size far beyond the file.
		const huge = bytes.slice();
		const dirOffset = buildCfb([{ name: "Big", data: bytesOf(6000) }]).layout.dirOffset;
		new DataView(huge.buffer).setUint32(dirOffset + 128 + 0x78, 0x7fffffff, true);
		const c2 = readCompoundFile(huge);
		expect(cfbCode(() => c2.read(c2.child("Big") as never))).toBe("LIMIT");
	});
});

describe("legacy Office text extraction", () => {
	it("reads Word compressed (8-bit) and UTF-16 pieces in CP order", async () => {
		const doc = cfbBytes(
			wordNodes([
				{ text: "Sözleşme tarafı\r" },
				{ text: `İletişim: ${EMAIL}\rKimlik ğüşıöç ${TCKN}\r`, unicode: true },
				{ text: "Fiyat 100 €\u0007Toplam\u0007\r" },
			]),
		);
		const extraction = await extractLegacyOffice(doc);
		expect(extraction.format).toBe("word");
		expect(extraction.complete).toBe(true);
		const all = extraction.segments.map((s) => s.value).join("\n");
		expect(all).toContain(EMAIL);
		expect(all).toContain(`Kimlik ğüşıöç ${TCKN}`);
		expect(all).toContain("Fiyat 100 €\tToplam");
	});

	it("reads Excel shared strings across CONTINUE records, with column headers as context", async () => {
		const long = `Not: ${"x".repeat(40)} İletişim ${EMAIL}`;
		const book = cfbBytes(
			excelNodes(
				[
					{
						name: "Müşteriler",
						rows: [
							["Ad", "Şifre", "TCKN"],
							["Ayşe", "Gizli123!", Number(TCKN)],
							[long, "x", 42.5],
						],
					},
				],
				{ sstChunk: 24 },
			),
		);
		const extraction = await extractLegacyOffice(book);
		expect(extraction.format).toBe("excel");
		expect(extraction.complete).toBe(true);
		const values = extraction.segments.map((s) => s.value);
		expect(values).toContain(long);
		expect(values).toContain("Müşteriler");
		expect(extraction.segments).toContainEqual({ context: "Şifre", value: "Gizli123!" });
		expect(extraction.segments).toContainEqual({ context: "TCKN", value: TCKN });
		expect(extraction.segments).toContainEqual({ context: "TCKN", value: "42.5" });
		expect(extraction.segments).toContainEqual({ context: "", value: "Şifre" });
	});

	it("reads PowerPoint text atoms, 8-bit atoms and CStrings", async () => {
		const deck = cfbBytes(
			pptNodes([
				textChars(`Sunan: ${EMAIL}\rTeşekkürler`),
				textBytes("Kimlik No"),
				cString("Yorum yazarı"),
			]),
		);
		const all = await text(deck);
		expect(all).toContain(`Sunan: ${EMAIL}\nTeşekkürler`);
		expect(all).toContain("Kimlik No");
		expect(all).toContain("Yorum yazarı");
	});

	it("reads document properties", async () => {
		const doc = cfbBytes([
			...wordNodes([{ text: "Gövde\r" }]),
			summaryInformation({ 4: `Yazar ${EMAIL}`, 2: "Başlık" }),
		]);
		const all = await text(doc);
		expect(all).toContain(`Yazar ${EMAIL}`);
		expect(all).toContain("Başlık");
	});

	it("opens embedded Word/Excel objects and refuses other embedded objects", async () => {
		const embeddedBook: CfbNode = {
			name: "_1234567890",
			children: excelNodes([{ name: "Sayfa1", rows: [["E-posta"], [EMAIL]] }]),
		};
		const doc = cfbBytes(
			wordNodes([{ text: "Ek tablo\r" }], {
				extra: [{ name: "ObjectPool", children: [embeddedBook] }],
			}),
		);
		expect(await text(doc)).toContain(EMAIL);
		const pkg = cfbBytes(
			wordNodes([{ text: "Ek\r" }], {
				extra: [
					{
						name: "ObjectPool",
						children: [
							{ name: "_1", children: [{ name: "\u0001Ole10Native", data: bytesOf(20) }] },
						],
					},
				],
			}),
		);
		expect(await refusal(pkg)).toEqual(["DOCUMENT_EMBEDDED_OBJECT"]);
	});

	it("opens a zlib-compressed embedded workbook in a PowerPoint deck", async () => {
		const inner = cfbBytes(excelNodes([{ name: "Veri", rows: [["Kişi"], [EMAIL]] }]));
		const raw = await deflateRaw(inner);
		// zlib wrapper: header 78 9C, raw deflate, Adler-32 (checked by DecompressionStream).
		let a = 1;
		let b = 0;
		for (const byte of inner) {
			a = (a + byte) % 65521;
			b = (b + a) % 65521;
		}
		const adler = ((b << 16) | a) >>> 0;
		const zlib = concatBytes(
			Uint8Array.of(0x78, 0x9c),
			raw,
			Uint8Array.of(adler >>> 24, (adler >> 16) & 0xff, (adler >> 8) & 0xff, adler & 0xff),
		);
		const stg = pptRecord(0x1011, concatBytes(out().u32(inner.length).done(), zlib), {
			instance: 1,
		});
		const deck = cfbBytes([
			{
				name: "PowerPoint Document",
				data: concatBytes(pptRecord(0x03e8, textChars("Grafik"), { container: true }), stg),
			},
		]);
		expect(await text(deck)).toContain(EMAIL);
		const junk = pptRecord(0x1011, bytesOf(64));
		const deck2 = cfbBytes([{ name: "PowerPoint Document", data: junk }]);
		expect(await refusal(deck2)).toEqual(["DOCUMENT_EMBEDDED_OBJECT"]);
	});

	it("refuses encryption and macros", async () => {
		expect(await refusal(cfbBytes(wordNodes([{ text: "x" }], { flags: 0x0300 })))).toEqual([
			"DOCUMENT_ENCRYPTED",
		]);
		const filepass = excelNodes([{ name: "S", rows: [["x"]] }], {
			globals: [[0x002f, out().u16(1).done()]],
		});
		expect(await refusal(cfbBytes(filepass))).toEqual(["DOCUMENT_ENCRYPTED"]);
		const crypt = pptNodes([pptRecord(0x2f14, new Uint8Array(0), { container: true })]);
		expect(await refusal(cfbBytes(crypt))).toEqual(["DOCUMENT_ENCRYPTED"]);
		expect(
			await refusal(
				cfbBytes([
					{ name: "EncryptionInfo", data: bytesOf(8) },
					{ name: "EncryptedPackage", data: bytesOf(8) },
				]),
			),
		).toEqual(["DOCUMENT_ENCRYPTED"]);
		const vba = wordNodes([{ text: "x" }], {
			extra: [
				{
					name: "Macros",
					children: [{ name: "VBA", children: [{ name: "dir", data: bytesOf(4) }] }],
				},
			],
		});
		expect(await refusal(cfbBytes(vba))).toEqual(["DOCUMENT_MACROS"]);
		const xlm = excelNodes([{ name: "Makro1", rows: [["=HALT()"]] }], { sheetType: 0x0040 });
		expect(await refusal(cfbBytes(xlm))).toEqual(["DOCUMENT_MACROS"]);
		const vbaInfo = (hasMacros: number) =>
			pptRecord(0x03ff, pptRecord(0x0400, out().u32(1).u32(hasMacros).u32(2).done()), {
				container: true,
			});
		expect(await refusal(cfbBytes(pptNodes([vbaInfo(1)])))).toEqual(["DOCUMENT_MACROS"]);
		// LibreOffice writes a VBAInfoContainer without a project: not macros.
		const noProject = await extractLegacyOffice(cfbBytes(pptNodes([vbaInfo(0), textChars("x")])));
		expect(noProject.complete).toBe(true);
	});

	it("reports partial and unsupported files instead of passing them as complete", async () => {
		const word95 = await extractLegacyOffice(
			cfbBytes(wordNodes([{ text: "x" }], { nFib: 0x0065 })),
		);
		expect(word95).toMatchObject({ complete: false, reasons: ["LEGACY_OFFICE_UNSUPPORTED"] });
		const biff5 = await extractLegacyOffice(cfbBytes([{ name: "Book", data: bytesOf(64) }]));
		expect(biff5).toMatchObject({ complete: false, reasons: ["LEGACY_OFFICE_UNSUPPORTED"] });
		const other = await extractLegacyOffice(cfbBytes([{ name: "Contents", data: bytesOf(64) }]));
		expect(other).toMatchObject({
			format: "unknown",
			complete: false,
			reasons: ["LEGACY_OFFICE_UNSUPPORTED"],
		});
		// One piece points outside the stream: the other pieces are still read.
		const bad = await extractLegacyOffice(
			cfbBytes(
				wordNodes([{ text: "kayıp" }, { text: EMAIL, unicode: true }], { badPiece: 1 << 20 }),
			),
		);
		expect(bad.complete).toBe(false);
		expect(bad.reasons).toEqual(["LEGACY_OFFICE_PARTIAL"]);
		expect(bad.segments.map((s) => s.value).join("")).toContain(EMAIL);
		// A PowerPoint record that overruns its container.
		const overrun = concatBytes(textChars("ok"), out().u16(0).u16(0x0fa0).u32(1_000_000).done());
		const ppt = await extractLegacyOffice(
			cfbBytes([{ name: "PowerPoint Document", data: overrun }]),
		);
		expect(ppt).toMatchObject({ complete: false, reasons: ["LEGACY_OFFICE_PARTIAL"] });
	});

	it("maps container errors to refusals and non-CFB input to unreadable", async () => {
		await expect(
			extractLegacyOffice(new TextEncoder().encode("{\\rtf1 x}")),
		).rejects.toBeInstanceOf(DocumentUnreadable);
		const magicOnly = new Uint8Array(1024);
		magicOnly.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
		expect(await refusal(magicOnly)).toEqual(["DOCUMENT_MALFORMED"]);
		const { bytes, layout } = buildCfb(wordNodes([{ text: "x".repeat(5000) }]));
		const start = layout.largeStart.get("WordDocument") as number;
		new DataView(bytes.buffer).setUint32(layout.fatOffset + (start + 1) * 4, start, true);
		expect(await refusal(bytes)).toEqual(["DOCUMENT_MALFORMED"]);
	});

	it("honours the caller's deadline", async () => {
		const doc = cfbBytes(wordNodes([{ text: "x\r" }]));
		await expect(
			extractLegacyOffice(doc, () => {
				throw new Error("deadline");
			}),
		).rejects.toThrow("deadline");
	});
});

describe("legacy Office sanitizeFile decisions", () => {
	const wordWith = (body: string) => cfbBytes(wordNodes([{ text: body, unicode: true }]));

	it.each(["auto", "confirm", "block"] as const)(
		"blocks a .doc with sensitive data in %s mode (SENSITIVE_DATA_IN_LEGACY_OFFICE)",
		async (mode) => {
			const d = await sanitize("sozlesme.doc", wordWith(`E-posta: ${EMAIL}\rTCKN: ${TCKN}\r`), {
				policy: { mode },
			});
			expect(d.action).toBe("block");
			expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_LEGACY_OFFICE"]);
			expect(d.counts).toMatchObject({ EMAIL: 1, TC_KIMLIK: 1 });
			expect(d.masked).toBeUndefined();
		},
	);

	it("records (allows) findings in monitor mode", async () => {
		const d = await sanitize("sozlesme.doc", wordWith(`E-posta: ${EMAIL}\r`), {
			policy: { mode: "monitor" },
		});
		expect(d).toEqual({
			action: "allow",
			counts: { EMAIL: 1 },
			reasons: ["SENSITIVE_DATA_IN_LEGACY_OFFICE"],
		});
	});

	it("allows a clean, completely read .doc/.xls/.ppt", async () => {
		const clean = { action: "allow", counts: {}, reasons: [] };
		expect(await sanitize("gundem.doc", wordWith("Toplantı gündemi\rBütçe\r"))).toEqual(clean);
		const xls = cfbBytes(
			excelNodes([
				{
					name: "Plan",
					rows: [
						["Ay", "Tutar"],
						["Ocak", 1200],
					],
				},
			]),
		);
		expect(await sanitize("plan.xls", xls, { policy: { mode: "block" } })).toEqual(clean);
		const ppt = cfbBytes(pptNodes([textChars("Yol haritası")]));
		expect(await sanitize("sunum.ppt", ppt)).toEqual(clean);
	});

	it("blocks a sensitive column by its header (.xls)", async () => {
		const xls = cfbBytes(
			excelNodes([
				{
					name: "S",
					rows: [
						["Müşteri No", "Şifre"],
						["M-1001", "Gizli123!"],
					],
				},
			]),
		);
		const d = await sanitize("liste.xls", xls);
		expect(d.action).toBe("block");
		expect(d.counts).toMatchObject({ SECRET: 1 });
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_LEGACY_OFFICE"]);
	});

	it("blocks findings in a PowerPoint deck and its properties", async () => {
		const ppt = cfbBytes(pptNodes([textChars("Sunum")], [summaryInformation({ 4: EMAIL })]));
		const d = await sanitize("sunum.pps", ppt);
		expect(d).toEqual({
			action: "block",
			counts: { EMAIL: 1 },
			reasons: ["SENSITIVE_DATA_IN_LEGACY_OFFICE"],
		});
	});

	it("reports pictures as not inspected", async () => {
		const doc = cfbBytes(wordNodes([{ text: "Rapor\r" }], { flags: 0x0208 }));
		expect(await sanitize("rapor.doc", doc)).toEqual({
			action: "allow",
			counts: {},
			reasons: ["DOCUMENT_IMAGES_NOT_INSPECTED"],
		});
		const ppt = cfbBytes(pptNodes([textChars("x")], [{ name: "Pictures", data: bytesOf(32) }]));
		expect((await sanitize("a.ppt", ppt)).reasons).toEqual(["DOCUMENT_IMAGES_NOT_INSPECTED"]);
	});

	it("never passes a partly read or unsupported file off as checked", async () => {
		const word95 = cfbBytes(wordNodes([{ text: "x" }], { nFib: 0x0065 }));
		expect(await sanitize("eski.doc", word95)).toEqual({
			action: "allow",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNED", "LEGACY_OFFICE_FORMAT", "LEGACY_OFFICE_UNSUPPORTED"],
		});
		expect(await sanitize("eski.doc", word95, { policy: { mode: "block" } })).toEqual({
			action: "block",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNABLE", "LEGACY_OFFICE_FORMAT", "LEGACY_OFFICE_UNSUPPORTED"],
		});
		// Findings in the readable part still block.
		const partial = cfbBytes(
			wordNodes([{ text: "kayıp" }, { text: EMAIL, unicode: true }], { badPiece: 1 << 20 }),
		);
		expect((await sanitize("yarim.doc", partial)).reasons).toEqual([
			"SENSITIVE_DATA_IN_LEGACY_OFFICE",
		]);
		const clean = cfbBytes(
			wordNodes([{ text: "kayıp" }, { text: "temiz", unicode: true }], { badPiece: 1 << 20 }),
		);
		expect((await sanitize("yarim.doc", clean)).reasons).toEqual([
			"BINARY_FILE_UNSCANNED",
			"LEGACY_OFFICE_FORMAT",
			"LEGACY_OFFICE_PARTIAL",
		]);
	});

	it("refuses malformed, encrypted and macro files (recorded in monitor mode)", async () => {
		const magicOnly = new Uint8Array(1024);
		magicOnly.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
		expect(await sanitize("bozuk.xls", magicOnly)).toEqual({
			action: "block",
			counts: {},
			reasons: ["DOCUMENT_MALFORMED"],
		});
		expect(await sanitize("bozuk.xls", magicOnly, { policy: { mode: "monitor" } })).toEqual({
			action: "allow",
			counts: {},
			reasons: ["DOCUMENT_MALFORMED"],
		});
		const encrypted = cfbBytes(wordNodes([{ text: "x" }], { flags: 0x0300 }));
		expect((await sanitize("sifreli.doc", encrypted)).reasons).toEqual(["DOCUMENT_ENCRYPTED"]);
	});

	it("treats a non-CFB file with a legacy name as unparseable, and OOXML content as OOXML", async () => {
		const rtf = new TextEncoder().encode(`{\\rtf1 ${EMAIL}}`);
		expect(await sanitize("not.doc", rtf)).toEqual({
			action: "allow",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNED", "LEGACY_OFFICE_FORMAT", "DOCUMENT_UNPARSEABLE"],
		});
		const ooxml = await docx(para(run(`E-posta ${EMAIL}`)));
		const d = await sanitize("yeniden-adlandirilmis.doc", ooxml);
		expect(d.action).toBe("mask");
		expect(d.reasons).toEqual(["SENSITIVE_DATA"]);
	});

	it("recognises a legacy file without an extension by its signature", async () => {
		const d = await sanitize("upload", wordWith(`E-posta: ${EMAIL}\r`));
		expect(d.reasons).toEqual(["SENSITIVE_DATA_IN_LEGACY_OFFICE"]);
	});
});
