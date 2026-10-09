// Office/PDF fixtures for the E2E suite, built in memory (no binary files in the repo),
// plus a minimal ZIP reader to inspect what the page actually uploaded.

import zlib from "node:zlib";

const W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';

function u16(n) {
	const b = Buffer.alloc(2);
	b.writeUInt16LE(n);
	return b;
}
function u32(n) {
	const b = Buffer.alloc(4);
	b.writeUInt32LE(n >>> 0);
	return b;
}

/** A ZIP with deflated entries (what Word writes); values may be strings or Buffers. */
function zip(files) {
	const locals = [];
	const centrals = [];
	let offset = 0;
	for (const [name, content] of Object.entries(files)) {
		const nameBytes = Buffer.from(name, "utf8");
		const data = Buffer.isBuffer(content) ? content : Buffer.from(content, "utf8");
		const packed = zlib.deflateRawSync(data);
		const crc = zlib.crc32(data);
		const common = [u16(20), u16(0x0800), u16(8), u16(0), u16(0x21), u32(crc), u32(packed.length), u32(data.length), u16(nameBytes.length), u16(0)];
		const local = Buffer.concat([u32(0x04034b50), ...common, nameBytes, packed]);
		centrals.push(
			Buffer.concat([u32(0x02014b50), u16(20), ...common, u16(0), u16(0), u16(0), u32(0), u32(offset), nameBytes]),
		);
		locals.push(local);
		offset += local.length;
	}
	const cd = Buffer.concat(centrals);
	const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(centrals.length), u16(centrals.length), u32(cd.length), u32(offset), u16(0)]);
	return Buffer.concat([...locals, cd, eocd]);
}

/** Entry name -> UTF-8 text, from the central directory. */
export function unzip(bytes) {
	return new Map([...unzipBytes(bytes)].map(([name, data]) => [name, data.toString("utf8")]));
}

/** Entry name -> raw bytes (Buffer), from the central directory. */
export function unzipBytes(bytes) {
	const buf = Buffer.from(bytes);
	let eocd = buf.length - 22;
	while (eocd >= 0 && buf.readUInt32LE(eocd) !== 0x06054b50) eocd--;
	if (eocd < 0) throw new Error("not a zip");
	const count = buf.readUInt16LE(eocd + 10);
	let p = buf.readUInt32LE(eocd + 16);
	const out = new Map();
	for (let i = 0; i < count; i++) {
		const method = buf.readUInt16LE(p + 10);
		const size = buf.readUInt32LE(p + 20);
		const nameLen = buf.readUInt16LE(p + 28);
		const extraLen = buf.readUInt16LE(p + 30);
		const commentLen = buf.readUInt16LE(p + 32);
		const local = buf.readUInt32LE(p + 42);
		const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
		const dataStart = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
		const raw = buf.subarray(dataStart, dataStart + size);
		out.set(name, method === 8 ? zlib.inflateRawSync(raw) : Buffer.from(raw));
		p += 46 + nameLen + extraLen + commentLen;
	}
	return out;
}

const run = (text, bold = false) =>
	`<w:r>${bold ? "<w:rPr><w:b/></w:rPr>" : ""}<w:t xml:space="preserve">${text}</w:t></w:r>`;

/**
 * A DOCX whose paragraph splits `email` and `tckn` across differently formatted runs, the
 * way Word does after spell-check or a formatting change.
 */
export function splitRunDocx(email, tckn) {
	const at = email.indexOf("@");
	const body =
		`<w:p>${run("Müşteri e-postası: ")}${run(email.slice(0, at + 1), true)}${run(email.slice(at + 1))}</w:p>` +
		`<w:p>${run("TC Kimlik No: ")}${run(tckn.slice(0, 5))}${run(tckn.slice(5), true)}</w:p>` +
		`<w:p>${run("Bu satır temiz: çalışma planı.")}</w:p>`;
	return zip({
		"[Content_Types].xml": `${DECL}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
		"_rels/.rels": `${DECL}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
		"word/document.xml": `${DECL}<w:document xmlns:w="${W_NS}"><w:body>${body}<w:sectPr/></w:body></w:document>`,
	});
}

/** A stand-in first-page thumbnail (PNG signature + junk): replaced when the package is masked. */
export const FAKE_PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]);
export const FAKE_JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4, 0xff, 0xd9]);

const ODF_NS =
	'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.3"';

/** An ODT whose paragraph splits `email` and `tckn` across spans, with a PNG thumbnail. */
export function splitSpanOdt(email, tckn) {
	const at = email.indexOf("@");
	const body =
		`<text:p>Müşteri e-postası: <text:span text:style-name="T1">${email.slice(0, at + 1)}</text:span>${email.slice(at + 1)}</text:p>` +
		`<text:p>TC Kimlik No: ${tckn.slice(0, 5)}<text:span text:style-name="T1">${tckn.slice(5)}</text:span></text:p>` +
		"<text:p>Bu satır temiz: çalışma planı.</text:p>";
	return zip({
		mimetype: "application/vnd.oasis.opendocument.text",
		"META-INF/manifest.xml": `${DECL}<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/></manifest:manifest>`,
		"content.xml": `${DECL}<office:document-content ${ODF_NS}><office:body><office:text>${body}</office:text></office:body></office:document-content>`,
		"Thumbnails/thumbnail.png": FAKE_PNG,
	});
}

/** A PPTX with one slide showing `email` and a JPEG first-slide thumbnail. */
export function thumbnailPptx(email) {
	const P = "http://schemas.openxmlformats.org/presentationml/2006/main";
	const A = "http://schemas.openxmlformats.org/drawingml/2006/main";
	return zip({
		"[Content_Types].xml": `${DECL}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="jpeg" ContentType="image/jpeg"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/></Types>`,
		"_rels/.rels": `${DECL}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail" Target="docProps/thumbnail.jpeg"/></Relationships>`,
		"ppt/presentation.xml": `${DECL}<p:presentation xmlns:p="${P}"/>`,
		"ppt/slides/slide1.xml": `${DECL}<p:sld xmlns:a="${A}" xmlns:p="${P}"><p:cSld><p:spTree><p:sp><p:txBody><a:bodyPr/><a:p><a:r><a:t>İletişim: ${email}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`,
		"docProps/thumbnail.jpeg": FAKE_JPEG,
	});
}

/**
 * A minimal Word 97-2003 .doc (OLE compound file, version 3) whose single UTF-16 piece holds
 * `text`. Both streams are padded to 4096 bytes so they live in regular sectors (no mini
 * stream). `nFib` below 193 makes it a Word 6/95 file, which AIDR reports as unsupported.
 */
export function legacyDoc(text = "Toplanti notlari", { nFib = 0x00c1 } = {}) {
	const STREAM = 4096;
	const doc = Buffer.alloc(STREAM);
	doc.writeUInt16LE(0xa5ec, 0);
	doc.writeUInt16LE(nFib, 2);
	doc.writeUInt16LE(0x0200, 0x0a); // fWhichTblStm: the 1Table stream
	doc.writeUInt16LE(14, 32); // csw
	doc.writeUInt16LE(22, 62); // cslw
	doc.writeUInt32LE(text.length, 64 + 12); // ccpText
	doc.writeUInt16LE(93, 152); // cbRgFcLcb
	const TEXT_AT = 1024;
	doc.write(text, TEXT_AT, "utf16le");
	const table = Buffer.alloc(STREAM);
	// Clx: Pcdt with one piece [0, text.length) -> UTF-16 at TEXT_AT.
	table.writeUInt8(0x02, 0);
	table.writeUInt32LE(4 * 2 + 8, 1);
	table.writeUInt32LE(0, 5);
	table.writeUInt32LE(text.length, 9);
	table.writeUInt32LE(TEXT_AT, 13 + 2);
	doc.writeUInt32LE(0, 154 + 33 * 8); // fcClx
	doc.writeUInt32LE(5 + 16, 154 + 33 * 8 + 4); // lcbClx

	const SECTOR = 512;
	const END = 0xfffffffe;
	const per = STREAM / SECTOR; // 8 sectors per stream
	// Sector 0: FAT, 1: directory, 2..9: WordDocument, 10..17: 1Table.
	const fat = Buffer.alloc(SECTOR, 0xff);
	fat.writeUInt32LE(0xfffffffd, 0);
	fat.writeUInt32LE(END, 4);
	for (const start of [2, 2 + per])
		for (let i = 0; i < per; i++) fat.writeUInt32LE(i === per - 1 ? END : start + i + 1, (start + i) * 4);
	const dir = Buffer.alloc(SECTOR);
	const entry = (index, name, type, child, right, start, size) => {
		const at = index * 128;
		dir.write(name, at, "utf16le");
		dir.writeUInt16LE((name.length + 1) * 2, at + 0x40);
		dir.writeUInt8(type, at + 0x42);
		dir.writeUInt8(1, at + 0x43);
		dir.writeUInt32LE(0xffffffff, at + 0x44);
		dir.writeUInt32LE(right, at + 0x48);
		dir.writeUInt32LE(child, at + 0x4c);
		dir.writeUInt32LE(start, at + 0x74);
		dir.writeUInt32LE(size, at + 0x78);
	};
	entry(0, "Root Entry", 5, 1, 0xffffffff, END, 0);
	entry(1, "WordDocument", 2, 0xffffffff, 2, 2, STREAM);
	entry(2, "1Table", 2, 0xffffffff, 0xffffffff, 2 + per, STREAM);
	const header = Buffer.alloc(SECTOR, 0xff);
	header.fill(0, 0, 0x4c);
	Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(header);
	header.writeUInt16LE(0x3e, 0x18);
	header.writeUInt16LE(3, 0x1a);
	header.writeUInt16LE(0xfffe, 0x1c);
	header.writeUInt16LE(9, 0x1e);
	header.writeUInt16LE(6, 0x20);
	header.writeUInt32LE(1, 0x2c); // one FAT sector
	header.writeUInt32LE(1, 0x30); // directory at sector 1
	header.writeUInt32LE(4096, 0x38);
	header.writeUInt32LE(END, 0x3c); // no mini FAT
	header.writeUInt32LE(0, 0x40);
	header.writeUInt32LE(END, 0x44); // no DIFAT sectors
	header.writeUInt32LE(0, 0x48);
	header.writeUInt32LE(0, 0x4c); // DIFAT[0]: the FAT is sector 0
	return Buffer.concat([header, fat, dir, doc, table]);
}

/** A one-page text PDF (Helvetica, Flate-compressed content) showing `lines`. */
export function textPdf(lines) {
	const esc = (s) => s.replace(/[\\()]/g, (c) => `\\${c}`);
	const content = `BT /F1 12 Tf 72 720 Td ${lines.map((l, i) => `${i ? "0 -16 Td " : ""}(${esc(l)}) Tj`).join(" ")} ET`;
	const packed = zlib.deflateSync(Buffer.from(content, "latin1"));
	const objects = [
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
	];
	const parts = [Buffer.from("%PDF-1.7\n", "latin1")];
	const offsets = [];
	let length = parts[0].length;
	const push = (b) => {
		parts.push(b);
		length += b.length;
	};
	objects.forEach((o, i) => {
		offsets.push(length);
		push(Buffer.from(`${i + 1} 0 obj\n${o}\nendobj\n`, "latin1"));
	});
	offsets.push(length);
	push(Buffer.from(`5 0 obj\n<< /Length ${packed.length} /Filter /FlateDecode >>\nstream\n`, "latin1"));
	push(packed);
	push(Buffer.from("\nendstream\nendobj\n", "latin1"));
	const xref = `xref\n0 6\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, "0")} 00000 n \n`).join("")}`;
	push(Buffer.from(`${xref}trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${length}\n%%EOF\n`, "latin1"));
	return Buffer.concat(parts);
}
