/**
 * Test fixtures: Office Open XML packages and PDFs built programmatically (no binary fixtures
 * in the repository), plus readers to re-open sanitised output.
 */
import { DEFAULT_POLICY } from "../../background/policy.js";
import { createDetectionEngine } from "../../engine/detect.js";
import { type GuardFile, sanitizeFile } from "../../engine/files.js";
import { walkXml } from "../../engine/office/xml.js";
import { createZip, readEntry, readZip } from "../../engine/office/zip.js";
import { createVault } from "../../engine/vault.js";
import type {
	DetectionEngine,
	FileDecision,
	GuardPolicy,
	ImageInspection,
	PlaceholderVault,
} from "../../types.js";

const W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships";
const OFFICE_DOC_REL =
	"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";
const XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';

export type Files = Record<string, string | Uint8Array>;

function contentTypes(overrides: Record<string, string>, extra = ""): string {
	const parts = Object.entries(overrides)
		.map(([part, type]) => `<Override PartName="${part}" ContentType="${type}"/>`)
		.join("");
	return `${XML_DECL}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>${parts}${extra}</Types>`;
}

function rootRels(target: string): string {
	return `${XML_DECL}<Relationships xmlns="${REL_NS}"><Relationship Id="rId1" Type="${OFFICE_DOC_REL}" Target="${target}"/></Relationships>`;
}

export function rels(
	items: ReadonlyArray<{ id: string; type: string; target: string; external?: boolean }>,
): string {
	const body = items
		.map(
			(r) =>
				`<Relationship Id="${r.id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${r.type}" Target="${r.target}"${r.external ? ' TargetMode="External"' : ""}/>`,
		)
		.join("");
	return `${XML_DECL}<Relationships xmlns="${REL_NS}">${body}</Relationships>`;
}

export const STYLES_XML = `${XML_DECL}<w:styles xmlns:w="${W_NS}"><w:style w:type="paragraph" w:styleId="Normal"><w:name w:val="Normal"/></w:style></w:styles>`;

/** A DOCX whose body is `bodyXml` (paragraph markup inside `<w:body>`). */
export function docx(
	bodyXml: string,
	extra: Files = {},
	contentTypeExtra = "",
): Promise<Uint8Array> {
	return createZip(
		Object.entries({
			"[Content_Types].xml": contentTypes(
				{
					"/word/document.xml":
						"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
					"/word/styles.xml":
						"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
				},
				contentTypeExtra,
			),
			"_rels/.rels": rootRels("word/document.xml"),
			"word/document.xml": `${XML_DECL}<w:document xmlns:w="${W_NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>${bodyXml}<w:sectPr/></w:body></w:document>`,
			"word/styles.xml": STYLES_XML,
			"docProps/core.xml": `${XML_DECL}<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Rapor</dc:title><dc:creator>Muhasebe</dc:creator></cp:coreProperties>`,
			...extra,
		}).map(([name, data]) => ({ name, data })),
	);
}

/** A run with optional bold formatting. */
export function run(text: string, bold = false): string {
	const space = /^\s|\s$/.test(text) ? ' xml:space="preserve"' : "";
	return `<w:r>${bold ? "<w:rPr><w:b/></w:rPr>" : ""}<w:t${space}>${text}</w:t></w:r>`;
}

export function para(...runs: string[]): string {
	return `<w:p>${runs.join("")}</w:p>`;
}

const SS_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

/** An XLSX with one sheet. */
export function xlsx(
	sheetData: string,
	sharedStrings: string[] | null,
	extra: Files = {},
): Promise<Uint8Array> {
	const files: Files = {
		"[Content_Types].xml": contentTypes({
			"/xl/workbook.xml":
				"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
			"/xl/worksheets/sheet1.xml":
				"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
			"/xl/sharedStrings.xml":
				"application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
		}),
		"_rels/.rels": rootRels("xl/workbook.xml"),
		"xl/workbook.xml": `${XML_DECL}<workbook xmlns="${SS_NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Müşteriler" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/_rels/workbook.xml.rels": rels([
			{ id: "rId1", type: "worksheet", target: "worksheets/sheet1.xml" },
			{ id: "rId2", type: "sharedStrings", target: "sharedStrings.xml" },
		]),
		"xl/worksheets/sheet1.xml": `${XML_DECL}<worksheet xmlns="${SS_NS}"><sheetData>${sheetData}</sheetData></worksheet>`,
		...extra,
	};
	if (sharedStrings) {
		files["xl/sharedStrings.xml"] =
			`${XML_DECL}<sst xmlns="${SS_NS}" count="${sharedStrings.length}" uniqueCount="${sharedStrings.length}">${sharedStrings.map((s) => (s.startsWith("<") ? `<si>${s}</si>` : `<si><t>${s}</t></si>`)).join("")}</sst>`;
	}
	return createZip(Object.entries(files).map(([name, data]) => ({ name, data })));
}

const A_NS = "http://schemas.openxmlformats.org/drawingml/2006/main";
const P_NS = "http://schemas.openxmlformats.org/presentationml/2006/main";

export function slide(paragraphs: string): string {
	return `${XML_DECL}<p:sld xmlns:a="${A_NS}" xmlns:p="${P_NS}"><p:cSld><p:spTree><p:sp><p:nvSpPr><p:cNvPr id="2" name="Title 1"/></p:nvSpPr><p:txBody><a:bodyPr/>${paragraphs}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`;
}

/** A PPTX with the given slide XML documents. */
export function pptx(slides: string[], extra: Files = {}): Promise<Uint8Array> {
	const files: Files = {
		"[Content_Types].xml": contentTypes({
			"/ppt/presentation.xml":
				"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
		}),
		"_rels/.rels": rootRels("ppt/presentation.xml"),
		"ppt/presentation.xml": `${XML_DECL}<p:presentation xmlns:p="${P_NS}"/>`,
		...extra,
	};
	slides.forEach((s, i) => {
		files[`ppt/slides/slide${i + 1}.xml`] = s;
	});
	return createZip(Object.entries(files).map(([name, data]) => ({ name, data })));
}

/** Every entry of a ZIP, decoded as UTF-8 text (binary entries too; tests only read XML). */
export async function unzipText(bytes: Uint8Array): Promise<Map<string, string>> {
	const archive = readZip(bytes);
	const out = new Map<string, string>();
	for (const entry of archive.entries)
		out.set(entry.name, new TextDecoder().decode(await readEntry(archive, entry)));
	return out;
}

export function isWellFormed(xml: string): boolean {
	try {
		walkXml(xml, {});
		return true;
	} catch {
		return false;
	}
}

// ---------------------------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------------------------

export type PdfObject =
	| string
	| { readonly dict: string; readonly data: string | Uint8Array; readonly compress?: boolean };

const latin1 = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);

async function zlib(data: Uint8Array): Promise<Uint8Array> {
	const stream = new Blob([new Uint8Array(data)])
		.stream()
		.pipeThrough(new CompressionStream("deflate"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Serialises numbered objects (1-based, in order) with a classic xref table.
 * `trailerExtra` is appended inside the trailer dictionary (e.g. `/Encrypt 9 0 R`).
 */
export async function pdfFile(
	objects: readonly PdfObject[],
	trailerExtra: string | null = "",
): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [latin1("%PDF-1.7\n%âãÏÓ\n")];
	let length = chunks[0]?.length ?? 0;
	const offsets: number[] = [];
	const push = (b: Uint8Array): void => {
		chunks.push(b);
		length += b.length;
	};
	for (let i = 0; i < objects.length; i++) {
		offsets.push(length);
		const obj = objects[i] as PdfObject;
		if (typeof obj === "string") {
			push(latin1(`${i + 1} 0 obj\n${obj}\nendobj\n`));
			continue;
		}
		const raw = typeof obj.data === "string" ? latin1(obj.data) : obj.data;
		const data = obj.compress === false ? raw : await zlib(raw);
		const filter = obj.compress === false ? "" : " /Filter /FlateDecode";
		push(latin1(`${i + 1} 0 obj\n<< ${obj.dict} /Length ${data.length}${filter} >>\nstream\n`));
		push(data);
		push(latin1("\nendstream\nendobj\n"));
	}
	const xrefAt = length;
	if (trailerExtra === null) push(latin1("%%EOF\n"));
	else {
		let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
		for (const o of offsets) xref += `${String(o).padStart(10, "0")} 00000 n \n`;
		push(
			latin1(
				`${xref}trailer\n<< /Size ${objects.length + 1} /Root 1 0 R ${trailerExtra}>>\nstartxref\n${xrefAt}\n%%EOF\n`,
			),
		);
	}
	const out = new Uint8Array(length);
	let o = 0;
	for (const c of chunks) {
		out.set(c, o);
		o += c.length;
	}
	return out;
}

/** Escapes a JS string for a PDF literal string (Latin-1 range only). */
export function pdfString(s: string): string {
	return `(${s.replace(/[\\()]/g, (c) => `\\${c}`)})`;
}

/**
 * A PDF whose pages have the given content streams and a shared resource dictionary with
 * F1 = Helvetica/WinAnsi and F2 = Helvetica with Turkish /Differences (128..133 = ğ ş ı İ Ş Ğ).
 */
export function simplePdf(
	pages: readonly string[],
	opts: {
		trailerExtra?: string;
		pageExtra?: string;
		resourcesExtra?: string;
		extraObjects?: PdfObject[];
		catalogExtra?: string;
	} = {},
): Promise<Uint8Array> {
	const n = pages.length;
	const firstPage = 5;
	const kids = pages.map((_, i) => `${firstPage + i * 2} 0 R`).join(" ");
	const objects: PdfObject[] = [
		`<< /Type /Catalog /Pages 2 0 R ${opts.catalogExtra ?? ""}>>`,
		`<< /Type /Pages /Kids [${kids}] /Count ${n} >>`,
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences [128 /gbreve /scedilla /dotlessi /Idotaccent /Scedilla /Gbreve] >> >>",
	];
	pages.forEach((content, i) => {
		objects.push(
			`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> ${opts.resourcesExtra ?? ""}>> /Contents ${firstPage + i * 2 + 1} 0 R ${opts.pageExtra ?? ""}>>`,
			{ dict: "", data: content },
		);
	});
	objects.push(...(opts.extraObjects ?? []));
	return pdfFile(objects, opts.trailerExtra);
}

// ---------------------------------------------------------------------------------------------
// Sanitising with the real engine and vault
// ---------------------------------------------------------------------------------------------

function realEngine(): DetectionEngine {
	return createDetectionEngine({
		enabledEntities: DEFAULT_POLICY.enabledEntities,
		literals: [],
		exactData: [],
		detectSignals: true,
		maxInputChars: 200_000,
		maxScanMs: 5_000,
	});
}

function realVault(): PlaceholderVault {
	return createVault({ neverRestore: DEFAULT_POLICY.neverRestore });
}

export function sanitize(
	name: string,
	bytes: Uint8Array,
	opts: {
		type?: string;
		policy?: Partial<GuardPolicy>;
		engine?: DetectionEngine;
		vault?: PlaceholderVault;
		inspectImage?: (bytes: Uint8Array) => Promise<ImageInspection | null>;
	} = {},
): Promise<FileDecision> {
	const file: GuardFile = { name, type: opts.type ?? "", bytes };
	return sanitizeFile(file, {
		engine: opts.engine ?? realEngine(),
		vault: opts.vault ?? realVault(),
		policy: { ...DEFAULT_POLICY, maxFileBytes: 50 * 1024 * 1024, ...opts.policy },
		...(opts.inspectImage ? { inspectImage: opts.inspectImage } : {}),
	});
}

// ---------------------------------------------------------------------------------------------
// OpenDocument
// ---------------------------------------------------------------------------------------------

const ODF_NS =
	'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" xmlns:calcext="urn:org:documentfoundation:names:experimental:calc:xmlns:calcext:1.0" office:version="1.3"';

export type OdfKind = "text" | "spreadsheet" | "presentation";

export const ODF_MIME_TYPES: Record<OdfKind, string> = {
	text: "application/vnd.oasis.opendocument.text",
	spreadsheet: "application/vnd.oasis.opendocument.spreadsheet",
	presentation: "application/vnd.oasis.opendocument.presentation",
};

/**
 * An OpenDocument package: `mimetype` first (stored), `content.xml` with `bodyXml` inside
 * `<office:{kind}>`, `styles.xml` (footer `footer`), `meta.xml` (author `creator`), a manifest.
 */
export function odf(
	kind: OdfKind,
	bodyXml: string,
	opts: { extra?: Files; footer?: string; creator?: string; manifestExtra?: string } = {},
): Promise<Uint8Array> {
	const footer = opts.footer ?? "Sayfa";
	return createZip(
		Object.entries({
			mimetype: ODF_MIME_TYPES[kind],
			"META-INF/manifest.xml": `${XML_DECL}<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3"><manifest:file-entry manifest:full-path="/" manifest:media-type="${ODF_MIME_TYPES[kind]}"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>${opts.manifestExtra ?? ""}</manifest:manifest>`,
			"content.xml": `${XML_DECL}<office:document-content ${ODF_NS}><office:body><office:${kind}>${bodyXml}</office:${kind}></office:body></office:document-content>`,
			"styles.xml": `${XML_DECL}<office:document-styles ${ODF_NS}><office:master-styles><style:master-page style:name="Standard"><style:footer><text:p>${footer}</text:p></style:footer></style:master-page></office:master-styles></office:document-styles>`,
			"meta.xml": `${XML_DECL}<office:document-meta ${ODF_NS}><office:meta><dc:creator>${opts.creator ?? "Editor"}</dc:creator><meta:generator>LibreOffice</meta:generator></office:meta></office:document-meta>`,
			"settings.xml": `${XML_DECL}<office:document-settings ${ODF_NS}><office:settings/></office:document-settings>`,
			...opts.extra,
		}).map(([name, data]) => ({ name, data })),
	);
}
