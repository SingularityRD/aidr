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

/** A ZIP with deflated entries (what Word writes). */
function zip(files) {
	const locals = [];
	const centrals = [];
	let offset = 0;
	for (const [name, content] of Object.entries(files)) {
		const nameBytes = Buffer.from(name, "utf8");
		const data = Buffer.from(content, "utf8");
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
		out.set(name, (method === 8 ? zlib.inflateRawSync(raw) : raw).toString("utf8"));
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
