import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { deflateRaw, InflateLimitError, inflateBounded } from "../engine/office/deflate.js";
import {
	applyReplacements,
	decodeXmlText,
	extractText,
	type TextSpec,
	walkXml,
	XmlError,
} from "../engine/office/xml.js";
import {
	ArchiveError,
	crc32,
	createZip,
	DEFAULT_ZIP_LIMITS,
	isSafeEntryName,
	readEntry,
	readZip,
	rewriteZip,
} from "../engine/office/zip.js";
import { docx, para, run, sanitize } from "./helpers/documents.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

function u32(b: Uint8Array, o: number): number {
	return (
		((b[o] ?? 0) | ((b[o + 1] ?? 0) << 8) | ((b[o + 2] ?? 0) << 16)) + (b[o + 3] ?? 0) * 0x1000000
	);
}
function setU32(b: Uint8Array, o: number, v: number): void {
	b[o] = v & 0xff;
	b[o + 1] = (v >>> 8) & 0xff;
	b[o + 2] = (v >>> 16) & 0xff;
	b[o + 3] = (v >>> 24) & 0xff;
}
function eocdOffset(b: Uint8Array): number {
	for (let i = b.length - 22; i >= 0; i--) if (u32(b, i) === 0x06054b50) return i;
	throw new Error("no EOCD");
}
/** Offset of the central directory record for the `index`-th entry. */
function centralRecord(b: Uint8Array, index: number): number {
	let o = u32(b, eocdOffset(b) + 16);
	for (let i = 0; i < index; i++) {
		const n = (b[o + 28] ?? 0) | ((b[o + 29] ?? 0) << 8);
		const e = (b[o + 30] ?? 0) | ((b[o + 31] ?? 0) << 8);
		const c = (b[o + 32] ?? 0) | ((b[o + 33] ?? 0) << 8);
		o += 46 + n + e + c;
	}
	return o;
}

async function refusal(bytes: Uint8Array): Promise<string> {
	try {
		const archive = readZip(bytes);
		for (const e of archive.entries) await readEntry(archive, e);
		return "ok";
	} catch (error) {
		if (error instanceof ArchiveError) return error.code;
		throw error;
	}
}

describe("zip reader/writer", () => {
	it("computes the standard CRC-32 check value", () => {
		expect(crc32(enc("123456789"))).toBe(0xcbf43926);
	});

	it("round-trips entries (stored and deflated) with UTF-8 names", async () => {
		const big = "Türkçe karakterler: ğüşıöç İĞÜŞÖÇ ".repeat(200);
		const zip = await createZip([
			{ name: "a.txt", data: "x" },
			{ name: "klasör/büyük.xml", data: big },
			{ name: "empty", data: "" },
		]);
		const archive = readZip(zip);
		expect(archive.entries.map((e) => e.name)).toEqual(["a.txt", "klasör/büyük.xml", "empty"]);
		expect(archive.entries[1]?.method).toBe(8);
		expect(dec(await readEntry(archive, archive.entries[1] as never))).toBe(big);
		expect(dec(await readEntry(archive, archive.entries[2] as never))).toBe("");
	});

	it("rewrites replaced entries and copies untouched compressed data byte-for-byte", async () => {
		const zip = await createZip([
			{ name: "keep.xml", data: "<a>".repeat(500) },
			{ name: "change.xml", data: "<b/>" },
		]);
		const before = readZip(zip);
		const out = await rewriteZip(before, new Map([["change.xml", enc("<c/>")]]));
		const after = readZip(out);
		const keepIn = before.entries[0];
		const keepOut = after.entries[0];
		if (!keepIn || !keepOut) throw new Error("missing");
		expect(out.subarray(keepOut.dataOffset, keepOut.dataOffset + keepOut.compressedSize)).toEqual(
			zip.subarray(keepIn.dataOffset, keepIn.dataOffset + keepIn.compressedSize),
		);
		expect(dec(await readEntry(after, after.entries[1] as never))).toBe("<c/>");
	});

	it("drops data hidden outside the central directory (prepended bytes, archive comment)", async () => {
		const zip = await createZip([{ name: "a.xml", data: "<a/>" }]);
		const eocd = eocdOffset(zip);
		const commented = new Uint8Array(zip.length + 5);
		commented.set(zip);
		commented.set(enc("HIDDN"), zip.length);
		commented[eocd + 20] = 5; // comment length
		const out = await rewriteZip(readZip(commented), new Map([["a.xml", enc("<b/>")]]));
		expect(dec(out)).not.toContain("HIDDN");
	});

	it.each([
		["/etc/passwd", false],
		["../evil.xml", false],
		["word/../../evil.xml", false],
		["C:/x.xml", false],
		["word\\document.xml", false],
		["word//document.xml", false],
		["a\u0000b", false],
		["word/document.xml", true],
		["word/", true],
		["[Content_Types].xml", true],
	])("isSafeEntryName(%j) === %s", (name, safe) => {
		expect(isSafeEntryName(name)).toBe(safe);
	});

	it("refuses path traversal and duplicate names", async () => {
		expect(await refusal(await createZip([{ name: "../x.xml", data: "x" }]))).toBe("UNSAFE_PATH");
		expect(
			await refusal(
				await createZip([
					{ name: "word/document.xml", data: "a" },
					{ name: "WORD/document.xml", data: "b" },
				]),
			),
		).toBe("DUPLICATE_ENTRY");
	});

	it("refuses ZIP64 archives and multi-disk archives", async () => {
		const zip = await createZip([{ name: "a.xml", data: "<a/>" }]);
		const zip64 = zip.slice();
		zip64[eocdOffset(zip64) + 10] = 0xff;
		zip64[eocdOffset(zip64) + 11] = 0xff;
		expect(await refusal(zip64)).toBe("ZIP64_UNSUPPORTED");
		const sentinel = zip.slice();
		setU32(sentinel, centralRecord(sentinel, 0) + 24, 0xffffffff);
		expect(await refusal(sentinel)).toBe("ZIP64_UNSUPPORTED");
		const disk = zip.slice();
		disk[eocdOffset(disk) + 4] = 1;
		expect(await refusal(disk)).toBe("MULTI_DISK");
	});

	it("refuses encrypted entries", async () => {
		const zip = await createZip([{ name: "a.xml", data: "<a/>" }]);
		zip[centralRecord(zip, 0) + 8] |= 1;
		expect(await refusal(zip)).toBe("ENTRY_ENCRYPTED");
	});

	it("refuses too many entries", async () => {
		const files = Array.from({ length: DEFAULT_ZIP_LIMITS.maxEntries + 1 }, (_, i) => ({
			name: `f${i}`,
			data: "",
		}));
		expect(await refusal(await createZip(files))).toBe("TOO_MANY_ENTRIES");
	});

	it("refuses a high-ratio entry (zip bomb) without inflating it", async () => {
		const zeros = new Uint8Array(32 * 1024 * 1024);
		const zip = await createZip([{ name: "word/document.xml", data: zeros }]);
		expect(zip.length).toBeLessThan(100_000);
		const started = Date.now();
		expect(await refusal(zip)).toBe("RATIO_EXCEEDED");
		expect(Date.now() - started).toBeLessThan(1_000);
	}, 30_000);

	it("stops inflating as soon as an entry exceeds its (false) declared size", async () => {
		const zeros = new Uint8Array(16 * 1024 * 1024);
		const zip = await createZip([{ name: "word/document.xml", data: zeros }]);
		// Lie about the size so the ratio check passes; inflation must still stop at the claim.
		setU32(zip, centralRecord(zip, 0) + 24, 1000);
		const started = Date.now();
		expect(await refusal(zip)).toBe("MALFORMED");
		expect(Date.now() - started).toBeLessThan(2_000);
	}, 30_000);

	it("refuses overlapping entries and a corrupt CRC", async () => {
		const zip = await createZip([
			{ name: "a.xml", data: "<a/>" },
			{ name: "b.xml", data: "<b/>" },
		]);
		const overlap = zip.slice();
		setU32(overlap, centralRecord(overlap, 1) + 42, 0); // b.xml "starts" at a.xml
		expect(await refusal(overlap)).toBe("MALFORMED");
		const crc = zip.slice();
		setU32(crc, centralRecord(crc, 0) + 16, 0x12345678);
		expect(await refusal(crc)).toBe("CRC_MISMATCH");
	});

	it("distinguishes non-ZIP input from a damaged ZIP", async () => {
		expect(await refusal(enc("hello world, definitely not a zip file"))).toBe("NOT_A_ZIP");
		const zip = await createZip([{ name: "a.xml", data: "<a/>" }]);
		expect(await refusal(zip.subarray(0, zip.length - 10))).toBe("MALFORMED");
	});

	it("blocks a zip-bomb DOCX through sanitizeFile", async () => {
		const zip = await createZip([
			{ name: "[Content_Types].xml", data: "<Types/>" },
			{ name: "word/document.xml", data: new Uint8Array(8 * 1024 * 1024) },
		]);
		expect(await sanitize("bomb.docx", zip)).toEqual({
			action: "block",
			counts: {},
			reasons: ["ARCHIVE_RATIO_EXCEEDED"],
		});
	}, 30_000);

	it("blocks a DOCX whose inflated size exceeds the read budget", async () => {
		// 60 MiB of varied XML: ratio stays low, but the total exceeds maxEntryBytes (48 MiB).
		const chunk = enc(`${para(run("Rapor satırı: değer"))}`);
		const big = new Uint8Array(60 * 1024 * 1024);
		for (let o = 0; o < big.length; o += chunk.length)
			big.set(chunk.subarray(0, big.length - o), o);
		const zip = await createZip([
			{ name: "[Content_Types].xml", data: "<Types/>" },
			{ name: "word/document.xml", data: big },
		]);
		const reasons = (await sanitize("large.docx", zip)).reasons;
		expect(["ARCHIVE_LIMIT_EXCEEDED", "ARCHIVE_RATIO_EXCEEDED"]).toContain(reasons[0]);
	}, 60_000);
});

describe("bundle safety", () => {
	it("document engine sources contain no Unicode noncharacters (Chrome rejects such content scripts)", () => {
		// esbuild emits regex/string escapes as literal UTF-8; Chrome refuses to load a content
		// script holding U+FFFE/U+FFFF/U+FDD0..U+FDEF ("isn't UTF-8 encoded").
		const dirs = ["office", "pdf"].map((d) => join(HERE, "..", "engine", d));
		const files = [
			join(HERE, "..", "engine", "files.ts"),
			...dirs.flatMap((d) => readdirSync(d).map((f) => join(d, f))),
		];
		const escaped = /\\u(?:fff[ef]|fd[de][0-9a-f])|\\u\{(?:[0-9a-f]*fff[ef]|fd[de][0-9a-f])\}/i;
		for (const file of files) {
			const src = readFileSync(file, "utf8");
			const literal = [...src].some((ch) => {
				const c = ch.codePointAt(0) ?? 0;
				return (c >= 0xfdd0 && c <= 0xfdef) || (c & 0xfffe) === 0xfffe;
			});
			expect({ file, literal, escaped: escaped.test(src) }).toEqual({
				file,
				literal: false,
				escaped: false,
			});
		}
	});
});

describe("bounded inflate", () => {
	it("throws InflateLimitError past the budget and reports corrupt streams", async () => {
		const packed = await deflateRaw(new Uint8Array(1024 * 1024));
		await expect(inflateBounded(packed, "deflate-raw", 1000)).rejects.toBeInstanceOf(
			InflateLimitError,
		);
		const ok = await inflateBounded(packed, "deflate-raw", 2 * 1024 * 1024);
		expect(ok).toMatchObject({ complete: true });
		expect(ok.bytes.length).toBe(1024 * 1024);
		const corrupt = await inflateBounded(new Uint8Array([0xff, 0xff, 0xff]), "deflate-raw", 100);
		expect(corrupt.complete).toBe(false);
	});
});

describe("XML scanner and text model", () => {
	const WORD: TextSpec = {
		paragraphs: new Set(["w:p"]),
		leaves: new Set(["w:t"]),
		breaks: new Map([["w:tab", ["\t", "w:r"]]]),
		preserveSpace: new Set(["w:t"]),
	};

	it("joins runs of a paragraph, maps edits back and rewrites only touched runs", () => {
		const xml =
			'<w:p><w:r><w:t>Ad: </w:t></w:r><w:r><w:tab/><w:t>Ay</w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>şe</w:t></w:r><w:r><w:t xml:space="preserve"> Kaya son</w:t></w:r></w:p>';
		const [segment] = extractText(xml, WORD);
		expect(segment?.text).toBe("Ad: \tAyşe Kaya son");
		const start = segment?.text.indexOf("Ayşe Kaya") ?? -1;
		const out = applyReplacements(
			xml,
			segment?.apply([{ start, end: start + 9, text: "[PERSON_1]" }]) ?? [],
		);
		expect(out).toBe(
			'<w:p><w:r><w:t>Ad: </w:t></w:r><w:r><w:tab/><w:t>[PERSON_1]</w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t></w:t></w:r><w:r><w:t xml:space="preserve"> son</w:t></w:r></w:p>',
		);
	});

	it("ignores w:tab outside runs (tab stops) and keeps paragraphs apart", () => {
		const xml =
			'<w:body><w:p><w:pPr><w:tabs><w:tab w:val="left" w:pos="720"/></w:tabs></w:pPr><w:r><w:t>bir</w:t></w:r></w:p><w:p><w:r><w:t>iki</w:t></w:r></w:p></w:body>';
		expect(extractText(xml, WORD).map((s) => s.text)).toEqual(["bir", "iki"]);
	});

	it("decodes predefined and numeric entities and refuses unknown ones", () => {
		expect(decodeXmlText("&lt;a&gt; &amp; &quot;&apos; &#351;&#x11F;")).toBe("<a> & \"' şğ");
		expect(() => decodeXmlText("&nbsp;")).toThrow(XmlError);
		expect(() => decodeXmlText("&#xD800;")).toThrow(XmlError);
	});

	it.each([
		["<a><b></a></b>", "MISMATCHED_TAG"],
		["<a>", "UNCLOSED"],
		["<!DOCTYPE a><a/>", "DOCTYPE_REFUSED"],
		["<a/><b/>", "MULTIPLE_ROOTS"],
		['<a x="1" x="2"/>', "DUPLICATE_ATTRIBUTE"],
		["<a x=1/>", "BAD_ATTRIBUTE"],
		["text", "TEXT_OUTSIDE_ROOT"],
		[" <!-- only a comment --> ", "NO_ROOT"],
	])("rejects malformed XML %j (%s)", (xml, code) => {
		expect(() => walkXml(xml, {})).toThrow(new XmlError(code));
	});

	it("masks attribute values and CDATA text in generic mode", () => {
		const xml = '<r><x v="mail a@b.co">x</x><y><![CDATA[kod a@b.co]]></y></r>';
		const segments = extractText(xml, {
			paragraphs: new Set(),
			leaves: new Set(),
			allText: true,
			attributes: (tag) => (tag.name === "x" ? ["v"] : []),
		});
		expect(segments.map((s) => s.text)).toEqual(["mail a@b.co", "x", "kod a@b.co"]);
		const reps = segments.flatMap((s) => {
			const i = s.text.indexOf("a@b.co");
			return i < 0 ? [] : s.apply([{ start: i, end: i + 6, text: "[EMAIL_1]" }]);
		});
		expect(applyReplacements(xml, reps)).toBe(
			'<r><x v="mail [EMAIL_1]">x</x><y>kod [EMAIL_1]</y></r>',
		);
	});

	it("refuses to rewrite a leaf that holds child markup", () => {
		const xml = "<w:p><w:r><w:t>a@b.co<w:x/></w:t></w:r></w:p>";
		const [segment] = extractText(xml, WORD);
		expect(() => segment?.apply([{ start: 0, end: 6, text: "[EMAIL_1]" }])).toThrow(XmlError);
	});

	it("masks a document end to end with the real engine (sanity)", async () => {
		const d = await sanitize("a.docx", await docx(para(run("mail: a.b@c.com.tr"))));
		expect(d.action).toBe("mask");
	});
});
