import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { isDocumentFile } from "../engine/files.js";
import { sanitizeOdf } from "../engine/office/odf.js";
import { DocumentRefused } from "../engine/office/ooxml.js";
import type { DocScanner } from "../engine/office/scanner.js";
import { DEFAULT_ZIP_LIMITS, readZip } from "../engine/office/zip.js";
import type { FileDecision } from "../types.js";
import {
	isWellFormed,
	ODF_MIME_TYPES,
	odf,
	realEngine,
	realVault,
	sanitize,
	unzipText,
} from "./helpers/documents.js";

const EMAIL = "ali.veli@ornek.com.tr";
const TCKN = "10000000146";
const IBAN = "TR33 0006 1005 1978 6457 8413 26";
const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const THUMBNAIL = new Uint8Array([...PNG_MAGIC, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 9, 9, 9, 9]);

function maskedBytes(d: FileDecision): Uint8Array {
	expect(d.action).toBe("mask");
	if (!d.masked) throw new Error("no masked output");
	return d.masked.bytes;
}

async function allText(bytes: Uint8Array): Promise<string> {
	return [...(await unzipText(bytes)).values()].join("\n");
}

describe("ODT masking", () => {
	it("masks a name, TCKN and e-mail split across spans, footer and author; keeps structure", async () => {
		const body =
			`<text:p text:style-name="P1">Ad Soyad: <text:span text:style-name="T1">Ayşe</text:span> Yılmaz,<text:s/>TCKN <text:span>100000</text:span><text:span>00146</text:span></text:p>` +
			`<text:h text:outline-level="1">İletişim: <text:a xlink:href="mailto:${EMAIL}">${EMAIL}</text:a></text:h>` +
			"<text:p>Bu paragraf temiz: çalışma planı.<text:tab/>Ankara</text:p>";
		const input = await odf("text", body, {
			footer: `Hazırlayan ${EMAIL}`,
			creator: EMAIL,
			extra: { "Thumbnails/thumbnail.png": THUMBNAIL },
		});
		const d = await sanitize("rapor.odt", input, { type: ODF_MIME_TYPES.text });
		expect(d.reasons).toEqual(["SENSITIVE_DATA"]);
		expect(d.counts).toMatchObject({ PERSON: 1, TC_KIMLIK: 1 });
		expect(d.masked?.name).toBe("rapor.odt");
		expect(d.masked?.type).toBe(ODF_MIME_TYPES.text);

		const out = maskedBytes(d);
		const parts = await unzipText(out);
		const content = parts.get("content.xml") ?? "";
		expect(isWellFormed(content)).toBe(true);
		expect(content).toMatch(/\[PERSON_\d+\]/);
		expect(content).toMatch(/\[TCKN_\d+\]/);
		expect(content).toMatch(/\[EMAIL_\d+\]/);
		expect(content).toContain('<text:span text:style-name="T1">');
		expect(content).toContain("Bu paragraf temiz: çalışma planı.<text:tab/>Ankara");
		const everything = await allText(out);
		for (const secret of [EMAIL, TCKN, "100000", "00146", "Ayşe"]) {
			expect(everything).not.toContain(secret);
		}
		expect(parts.get("styles.xml")).toMatch(/Hazırlayan \[EMAIL_\d+\]/);
		expect(parts.get("meta.xml")).toMatch(/<dc:creator>\[EMAIL_\d+\]<\/dc:creator>/);
		// The package layout is kept: mimetype first, same entries.
		const archive = readZip(out);
		expect(archive.entries[0]?.name).toBe("mimetype");
		expect(archive.entries.map((e) => e.name)).toEqual(readZip(input).entries.map((e) => e.name));
		expect(parts.get("mimetype")).toBe(ODF_MIME_TYPES.text);
	});

	it("replaces the first-page thumbnail of a rewritten package with a valid blank PNG", async () => {
		const input = await odf("text", `<text:p>E-posta: ${EMAIL}</text:p>`, {
			extra: { "Thumbnails/thumbnail.png": THUMBNAIL },
		});
		const out = maskedBytes(await sanitize("a.odt", input));
		const archive = readZip(out);
		const entry = archive.entries.find((e) => e.name === "Thumbnails/thumbnail.png");
		if (!entry) throw new Error("thumbnail missing");
		const { readEntry } = await import("../engine/office/zip.js");
		const png = await readEntry(archive, entry);
		expect([...png.subarray(0, 8)]).toEqual(PNG_MAGIC);
		expect(png).not.toEqual(THUMBNAIL);
		// IHDR 1x1, IDAT inflates to one filtered RGB row.
		const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
		expect([view.getUint32(16), view.getUint32(20)]).toEqual([1, 1]);
		const idatLength = view.getUint32(33);
		const idat = png.subarray(41, 41 + idatLength);
		expect([...inflateSync(idat)]).toEqual([0, 255, 255, 255]);
	});

	it("allows a clean document untouched and reports its uninspected thumbnail", async () => {
		const input = await odf("text", "<text:p>Toplantı notları: yol haritası.</text:p>", {
			extra: { "Thumbnails/thumbnail.png": THUMBNAIL },
		});
		expect(await sanitize("clean.odt", input)).toEqual({
			action: "allow",
			counts: {},
			reasons: ["DOCUMENT_IMAGES_NOT_INSPECTED"],
		});
		const plain = await odf("text", "<text:p>Toplantı notları.</text:p>");
		expect(await sanitize("clean.odt", plain)).toEqual({
			action: "allow",
			counts: {},
			reasons: [],
		});
	});

	it("scans notes and annotations as their own paragraphs", async () => {
		const body = `<text:p>Metin<text:note text:note-class="footnote"><text:note-body><text:p>IBAN ${IBAN}</text:p></text:note-body></text:note> devam.<office:annotation><dc:creator>${EMAIL}</dc:creator><text:p>Kontrol et</text:p></office:annotation></text:p>`;
		const out = maskedBytes(await sanitize("n.odt", await odf("text", body)));
		const content = (await unzipText(out)).get("content.xml") ?? "";
		expect(content).toMatch(/IBAN \[IBAN_\d+\]/);
		expect(content).toMatch(/<dc:creator>\[EMAIL_\d+\]<\/dc:creator>/);
		expect(content).toContain("Metin");
		expect(content).not.toContain("0006 1005");
	});
});

describe("ODS masking", () => {
	const cell = (text: string, attrs = 'office:value-type="string" calcext:value-type="string"') =>
		`<table:table-cell ${attrs}><text:p>${text}</text:p></table:table-cell>`;
	const row = (...cells: string[]) => `<table:table-row>${cells.join("")}</table:table-row>`;
	const sheet = (...rows: string[]) =>
		`<table:table table:name="Sayfa1"><table:table-column table:number-columns-repeated="3"/>${rows.join("")}</table:table>`;

	it("masks a sensitive column by its header and turns masked numbers into string cells", async () => {
		const numeric = (n: string, shown = n) =>
			cell(shown, `office:value-type="float" office:value="${n}" calcext:value-type="float"`);
		const body = sheet(
			row(cell("Müşteri"), cell("Kimlik No"), cell("Not")),
			row(cell("Ayşe Yılmaz"), numeric("12345678901"), cell("sorun yok")),
			row(cell("Mehmet Kaya"), numeric(TCKN, "10.000.000.146"), cell(`E-posta: ${EMAIL}`)),
		);
		const d = await sanitize("liste.ods", await odf("spreadsheet", body));
		const out = maskedBytes(d);
		const content = (await unzipText(out)).get("content.xml") ?? "";
		expect(isWellFormed(content)).toBe(true);
		for (const secret of ["12345678901", TCKN, "10.000.000.146", EMAIL]) {
			expect(content).not.toContain(secret);
		}
		expect(content).not.toMatch(/office:value="/);
		expect(content).not.toMatch(/value-type="float"/);
		expect(content).toMatch(/office:string-value="\[(?:NATIONAL_ID|TCKN)_\d+\]"/);
		expect(content).toContain("sorun yok");
		expect(content).toContain("Kimlik No");
	});

	it("masks a whole cell when its formula or value holds a finding", async () => {
		const body = sheet(
			row(cell("A"), cell("B")),
			row(
				`<table:table-cell table:formula="of:=${TCKN}" office:value-type="float" office:value="${TCKN}"><text:p>${TCKN}</text:p></table:table-cell>`,
				cell("temiz"),
			),
		);
		const content =
			(await unzipText(maskedBytes(await sanitize("f.ods", await odf("spreadsheet", body))))).get(
				"content.xml",
			) ?? "";
		expect(content).not.toContain(TCKN);
		expect(content).toMatch(/table:formula="of:=\[TCKN_\d+\]"/);
		expect(content).toContain("temiz");
	});

	it("honours repeated columns when mapping headers", async () => {
		const body = sheet(
			row(
				`<table:table-cell table:number-columns-repeated="2" office:value-type="string"><text:p>Açıklama</text:p></table:table-cell>`,
				cell("IBAN"),
			),
			row(cell("x"), cell("y"), cell("TR00 BOZUK DEGER")),
		);
		const content =
			(await unzipText(maskedBytes(await sanitize("r.ods", await odf("spreadsheet", body))))).get(
				"content.xml",
			) ?? "";
		expect(content).not.toContain("BOZUK");
		expect(content).toMatch(/\[IBAN_\d+\]/);
	});
});

describe("ODP masking", () => {
	it("masks text boxes and speaker notes", async () => {
		const body = `<draw:page draw:name="page1"><draw:frame><draw:text-box><text:p>Sunum: ${EMAIL}</text:p></draw:text-box></draw:frame><presentation:notes><draw:frame><draw:text-box><text:p>TCKN ${TCKN}</text:p></draw:text-box></draw:frame></presentation:notes></draw:page>`;
		const out = maskedBytes(await sanitize("sunum.odp", await odf("presentation", body)));
		const everything = await allText(out);
		expect(everything).not.toContain(EMAIL);
		expect(everything).not.toContain(TCKN);
	});
});

describe("OpenDocument refusals", () => {
	it.each([
		[
			"an encrypted package",
			{
				manifestExtra:
					'<manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"><manifest:encryption-data manifest:checksum-type="SHA1/1K"/></manifest:file-entry>',
			},
			["DOCUMENT_ENCRYPTED"],
		],
		[
			"a Basic macro library",
			{ extra: { "Basic/Standard/Module1.xml": "<script:module/>" } },
			["DOCUMENT_MACROS"],
		],
		[
			"embedded media",
			{ extra: { "Media/clip.mp4": new Uint8Array([0, 0, 0, 24, 0x66, 0x74, 0x79, 0x70]) } },
			["DOCUMENT_EMBEDDED_OBJECT"],
		],
	] as const)("blocks %s", async (_name, opts, reasons) => {
		const input = await odf("text", `<text:p>${EMAIL}</text:p>`, opts);
		expect(await sanitize("r.odt", input)).toEqual({ action: "block", counts: {}, reasons });
	});

	it.each([
		[
			"a script event listener",
			'<text:p><draw:frame><office:event-listeners><script:event-listener script:language="ooo:script" script:event-name="dom:click" xlink:href="vnd.sun.star.script:Standard.Module1.Main"/></office:event-listeners></draw:frame></text:p>',
			"DOCUMENT_MACROS",
		],
		[
			"an OLE object",
			'<text:p><draw:frame><draw:object-ole xlink:href="./Object 1"/></draw:frame></text:p>',
			"DOCUMENT_EMBEDDED_OBJECT",
		],
		[
			"a linked section",
			'<text:section text:name="S"><text:section-source xlink:href="file:///srv/gizli.odt"/></text:section>',
			"DOCUMENT_EXTERNAL_LINKS",
		],
		[
			"a DDE link",
			'<text:p><text:dde-connection-decls><text:dde-connection-decl office:name="d" office:dde-application="soffice" office:dde-topic="x" office:dde-item="y"/></text:dde-connection-decls></text:p>',
			"DOCUMENT_EXTERNAL_LINKS",
		],
		[
			"an object linked from outside the package",
			'<text:p><draw:frame><draw:object xlink:href="../other.ods"/></draw:frame></text:p>',
			"DOCUMENT_EXTERNAL_LINKS",
		],
	])("blocks %s", async (_name, body, reason) => {
		expect((await sanitize("r.odt", await odf("text", body))).reasons).toEqual([reason]);
	});

	it("masks an embedded object's own content instead of refusing it", async () => {
		const input = await odf(
			"text",
			'<text:p><draw:frame><draw:object xlink:href="./Object 1"/></draw:frame></text:p>',
			{
				extra: {
					"Object 1/content.xml": `<?xml version="1.0"?><office:document-content xmlns:office="o" xmlns:text="t"><office:body><office:chart><text:p>${EMAIL}</text:p></office:chart></office:body></office:document-content>`,
					"ObjectReplacements/Object 1": new Uint8Array([1, 2, 3]),
				},
			},
		);
		const d = await sanitize("c.odt", input);
		expect(d.action).toBe("mask");
		expect(d.reasons).toEqual(["SENSITIVE_DATA", "DOCUMENT_IMAGES_NOT_INSPECTED"]);
		expect(await allText(maskedBytes(d))).not.toContain(EMAIL);
	});

	it("refuses malformed XML and unsafe archives", async () => {
		const broken = await odf("text", "<text:p>unterminated");
		expect((await sanitize("b.odt", broken)).reasons).toEqual(["DOCUMENT_MALFORMED"]);
		const scanner: DocScanner = {
			scan: async (inputs) => ({ perSegment: inputs.map(() => []), signals: new Set() }),
			replace: (value) => value,
			headerType: () => undefined,
			checkDeadline: () => {},
		};
		const input = await odf("text", `<text:p>${"x".repeat(5000)}</text:p>`);
		await expect(
			sanitizeOdf(input, scanner, { ...DEFAULT_ZIP_LIMITS, maxReadTotal: 1024 }),
		).rejects.toEqual(new DocumentRefused(["ARCHIVE_LIMIT_EXCEEDED"]));
	});
});

describe("OpenDocument and legacy Office policy and classification", () => {
	const cfb = () => {
		const bytes = new Uint8Array(1024);
		bytes.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
		return bytes;
	};

	it("recognises OpenDocument by extension, MIME type and content", async () => {
		const input = await odf("text", `<text:p>${EMAIL}</text:p>`);
		expect((await sanitize("upload", input)).action).toBe("mask");
		expect((await sanitize("upload.bin2", input, { type: ODF_MIME_TYPES.text })).action).toBe(
			"mask",
		);
		expect(isDocumentFile({ name: "a.ODS", type: "" })).toBe(true);
		expect(isDocumentFile({ name: "x", type: ODF_MIME_TYPES.presentation })).toBe(true);
	});

	it("documentHandling=block rejects OpenDocument and legacy Office files", async () => {
		const policy = { documentHandling: "block" as const };
		const expected = { action: "block", counts: {}, reasons: ["DOCUMENT_BLOCKED_BY_POLICY"] };
		expect(await sanitize("a.odt", await odf("text", "<text:p>x</text:p>"), { policy })).toEqual(
			expected,
		);
		for (const name of ["a.doc", "a.xls", "a.ppt", "a.pps", "a.xlt"]) {
			expect(await sanitize(name, cfb(), { policy })).toEqual(expected);
			expect(isDocumentFile({ name, type: "" })).toBe(true);
		}
		expect(isDocumentFile({ name: "x", type: "application/msword" })).toBe(true);
		expect(isDocumentFile({ name: "x", type: "application/vnd.ms-excel" })).toBe(true);
	});

	it("never passes a legacy Office file off as checked", async () => {
		// A bare OLE signature with no valid header: a corrupt container is refused.
		for (const name of ["eski.doc", "eski.xls", "eski.ppt"]) {
			expect(await sanitize(name, cfb())).toEqual({
				action: "block",
				counts: {},
				reasons: ["DOCUMENT_MALFORMED"],
			});
		}
		// Without an extension, by MIME type or by the OLE signature (see
		// files-legacy-office.test.ts for parsed files).
		expect((await sanitize("upload", cfb())).reasons).toEqual(["DOCUMENT_MALFORMED"]);
		const text = new TextEncoder().encode("x");
		expect(await sanitize("upload", text, { type: "application/msword" })).toEqual({
			action: "allow",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNED", "LEGACY_OFFICE_FORMAT", "DOCUMENT_UNPARSEABLE"],
		});
		expect(
			await sanitize("upload", text, { type: "application/msword", policy: { mode: "block" } }),
		).toEqual({
			action: "block",
			counts: {},
			reasons: ["BINARY_FILE_UNSCANNABLE", "LEGACY_OFFICE_FORMAT", "DOCUMENT_UNPARSEABLE"],
		});
	});

	it("treats a non-ZIP file named .odt as an unscanned binary", async () => {
		const bytes = new TextEncoder().encode(`plain ${EMAIL}`);
		expect((await sanitize("fake.odt", bytes)).reasons).toEqual([
			"BINARY_FILE_UNSCANNED",
			"DOCUMENT_UNPARSEABLE",
		]);
	});

	it("masks through the real engine and vault so placeholders restore", async () => {
		const vault = realVault();
		const input = await odf("text", `<text:p>E-posta: ${EMAIL}</text:p>`);
		const d = await sanitize("v.odt", input, { vault, engine: realEngine() });
		const content = (await unzipText(maskedBytes(d))).get("content.xml") ?? "";
		const placeholder = /\[EMAIL_\d+\]/.exec(content)?.[0] ?? "";
		expect(vault.unmask(placeholder)).toBe(EMAIL);
	});
});

describe("OpenDocument namespace-aware matching (prefixes are not trusted)", () => {
	const NS = {
		office: "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
		script: "urn:oasis:names:tc:opendocument:xmlns:script:1.0",
		draw: "urn:oasis:names:tc:opendocument:xmlns:drawing:1.0",
		text: "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
		table: "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
		xlink: "http://www.w3.org/1999/xlink",
	};
	const listener = (el: string, at: string, decl: string) =>
		`<text:p><draw:frame><office:event-listeners><${el} ${decl} ${at}language="ooo:script" ${at}event-name="dom:click" xlink:href="vnd.sun.star.script:Standard.Module1.Main"/></office:event-listeners></draw:frame></text:p>`;

	it.each([
		["script:event-listener", listener("script:event-listener", "script:", ""), "DOCUMENT_MACROS"],
		[
			"s:event-listener",
			listener("s:event-listener", "s:", `xmlns:s="${NS.script}"`),
			"DOCUMENT_MACROS",
		],
		[
			"default-namespace event-listener",
			listener("event-listener", "script:", `xmlns="${NS.script}"`),
			"DOCUMENT_MACROS",
		],
		[
			"o:object-ole",
			`<text:p><draw:frame><o:object-ole xmlns:o="${NS.draw}" xlink:href="./Object 1"/></draw:frame></text:p>`,
			"DOCUMENT_EMBEDDED_OBJECT",
		],
		[
			"default-namespace object-ole",
			`<text:p><frame xmlns="${NS.draw}"><object-ole xlink:href="./Object 1"/></frame></text:p>`,
			"DOCUMENT_EMBEDDED_OBJECT",
		],
		[
			"a linked section with a re-bound xlink prefix",
			`<text:section text:name="S"><text:section-source xmlns:l="${NS.xlink}" l:href="file:///srv/gizli.odt"/></text:section>`,
			"DOCUMENT_EXTERNAL_LINKS",
		],
		[
			"an outside object in a default namespace",
			`<text:p><frame xmlns="${NS.draw}"><object xmlns:l="${NS.xlink}" l:href="../other.ods"/></frame></text:p>`,
			"DOCUMENT_EXTERNAL_LINKS",
		],
		[
			"a DDE link under another prefix",
			`<text:p><z:dde-connection-decls xmlns:z="${NS.text}"><z:dde-connection-decl office:name="d"/></z:dde-connection-decls></text:p>`,
			"DOCUMENT_EXTERNAL_LINKS",
		],
	])("refuses %s the same way", async (_name, body, reason) => {
		expect(await sanitize("r.odt", await odf("text", body))).toEqual({
			action: "block",
			counts: {},
			reasons: [reason],
		});
	});

	it("masks a hyperlink target whose xlink prefix is re-bound", async () => {
		const body = `<text:p>Yazın: <text:a xmlns:l="${NS.xlink}" l:href="mailto:${EMAIL}">bize</text:a></text:p>`;
		const content =
			(await unzipText(maskedBytes(await sanitize("h.odt", await odf("text", body))))).get(
				"content.xml",
			) ?? "";
		expect(content).not.toContain(EMAIL);
		expect(content).toMatch(/l:href="mailto:\[EMAIL_\d+\]"/);
		expect(isWellFormed(content)).toBe(true);
	});

	it("retypes a masked numeric cell using the document's own office prefix", async () => {
		const cell = (inner: string, attrs: string) =>
			`<t:table-cell ${attrs}><text:p>${inner}</text:p></t:table-cell>`;
		const body =
			`<t:table xmlns:t="${NS.table}" xmlns:o="${NS.office}" t:name="S">` +
			`<t:table-row>${cell("Ad", 'o:value-type="string"')}${cell("Kimlik No", 'o:value-type="string"')}</t:table-row>` +
			`<t:table-row>${cell("Ayşe", 'o:value-type="string"')}${cell(TCKN, `o:value-type="float" o:value="${TCKN}"`)}</t:table-row>` +
			"</t:table>";
		const content =
			(await unzipText(maskedBytes(await sanitize("n.ods", await odf("spreadsheet", body))))).get(
				"content.xml",
			) ?? "";
		expect(isWellFormed(content)).toBe(true);
		expect(content).not.toContain(TCKN);
		expect(content).not.toMatch(/o:value="/);
		expect(content).toMatch(/o:value-type="string" o:string-value="\[(?:NATIONAL_ID|TCKN)_\d+\]"/);
	});
});
