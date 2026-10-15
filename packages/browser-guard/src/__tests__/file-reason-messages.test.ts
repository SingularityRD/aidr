/**
 * Blocked-upload messages: every reason code that can stop an upload has a plain EN and TR
 * sentence, and no rendered upload message shows an internal UPPER_SNAKE reason code.
 */
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { blockedMessage } from "../content/file-guard";
import { type Lang, STRINGS } from "../content/strings";
import { FILE_BLOCK_REASONS, FILE_PASS_REASONS, type SignalCode } from "../types";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const LANGS: readonly Lang[] = ["en", "tr"];
/** An internal code such as SENSITIVE_DATA_IN_PDF or IMAGE_OCR_UNCERTAIN. */
const UPPER_SNAKE = /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b/;
const SIGNALS: readonly SignalCode[] = [
	"INSTRUCTION_OVERRIDE",
	"PROMPT_EXTRACTION",
	"ROLE_DELIMITER",
	"ROLE_SPOOF",
	"ACTIVE_CONTENT",
	"SOURCE_CODE_HINT",
	"EXACT_DATA_MATCH",
];
const NAME = "rapor-2026.pdf";

function render(lang: Lang, reasons: readonly string[], counts = { EMAIL: 1 }): string {
	return blockedMessage(STRINGS[lang], { name: NAME, reasons, counts });
}

/** Every quoted file reason code in the engine sources (documents, PDF, images, text). */
function engineReasonCodes(): Set<string> {
	const dir = join(SRC, "engine");
	const files = readdirSync(dir, { recursive: true, encoding: "utf8" }).filter(
		(f) => f.endsWith(".ts") && !f.includes("__tests__"),
	);
	const literal =
		/"((?:SENSITIVE_DATA|DOCUMENT|PDF|LEGACY_OFFICE|IMAGE|BINARY_FILE|FILE|TEXT_FILE|SCAN|FORMULA|NATIVE_NER)(?:_[A-Z0-9]+)*)"/g;
	const codes = new Set<string>();
	for (const file of files)
		for (const m of readFileSync(join(dir, file), "utf8").matchAll(literal))
			codes.add(m[1] as string);
	return codes;
}

describe("uninspected picture messages", () => {
	it("a picture no helper app inspected: not uploaded, with how to install and enable it", () => {
		const en = render("en", ["IMAGE_NOT_INSPECTED"]);
		expect(en).toContain("was not uploaded because the picture could not be inspected");
		expect(en).toContain("Singularity AIDR desktop app");
		expect(en).toContain("install-companion");
		expect(en).toContain('"Use the AIDR Privacy helper app"');
		const tr = render("tr", ["IMAGE_NOT_INSPECTED"]);
		expect(tr).toContain("yüklenmedi çünkü görsel denetlenemedi");
		expect(tr).toContain("masaüstü uygulamasından");
		expect(tr).toContain('"AIDR Privacy yardımcı uygulamasını kullan"');
		// In block mode the engine adds BINARY_FILE_UNSCANNABLE first; the picture sentence still wins.
		expect(render("en", ["BINARY_FILE_UNSCANNABLE", "IMAGE_NOT_INSPECTED"])).toBe(en);
	});

	it("a picture the helper app could not read: no install advice", () => {
		for (const lang of LANGS) {
			const text = render(lang, ["IMAGE_NOT_INSPECTED", "IMAGE_OCR_UNCERTAIN"]);
			expect(text).toContain(`"${NAME}"`);
			expect(text).not.toContain("install-companion");
			expect(text).not.toMatch(UPPER_SNAKE);
		}
	});
});

describe("blocked upload messages", () => {
	it("has an EN and a TR sentence for every reason code (exhaustive over FILE_BLOCK_REASONS)", () => {
		for (const lang of LANGS) {
			expect(Object.keys(STRINGS[lang].fileReasons).sort()).toEqual([...FILE_BLOCK_REASONS].sort());
		}
		for (const code of FILE_BLOCK_REASONS) {
			const en = STRINGS.en.fileReasons[code](NAME, "1 email address");
			const tr = STRINGS.tr.fileReasons[code](NAME, "1 e-posta adresi");
			for (const text of [en, tr]) {
				expect(text, code).toContain(`"${NAME}"`);
				expect(text, code).not.toMatch(UPPER_SNAKE);
				expect(text.length, code).toBeGreaterThan(40);
			}
			expect(tr, code).not.toBe(en);
			expect(en, code).toMatch(/not uploaded/);
			expect(tr, code).toMatch(/yüklenmedi/);
		}
	});

	it("classifies every reason code the engine emits", () => {
		const known = new Set<string>([...FILE_BLOCK_REASONS, ...FILE_PASS_REASONS]);
		const unknown = [...engineReasonCodes()].filter((code) => !known.has(code));
		expect(unknown).toEqual([]);
	});

	it.each(LANGS)("never renders a reason code (%s)", (lang) => {
		const cases: string[][] = [
			...FILE_BLOCK_REASONS.map((code) => [code]),
			...FILE_BLOCK_REASONS.map((code) => ["BINARY_FILE_UNSCANNABLE", code, "IMAGE_OCR_UNCERTAIN"]),
			...SIGNALS.map((signal) => [`SIGNAL_${signal}`]),
			["SENSITIVE_DATA_IN_PDF", "SIGNAL_SOURCE_CODE_HINT"],
			["ARCHIVE_ZIP64_UNSUPPORTED"],
			["SIGNAL_SOMETHING_NEW"],
			["SOME_FUTURE_CODE"],
			[...FILE_PASS_REASONS],
			[],
		];
		for (const reasons of cases) {
			for (const counts of [{}, { EMAIL: 1, TC_KIMLIK: 2 }]) {
				const text = render(lang, reasons, counts);
				expect(text, reasons.join(",")).not.toMatch(UPPER_SNAKE);
				expect(text, reasons.join(",")).toContain(`"${NAME}"`);
			}
		}
	});

	it("names the data the way the rest of the extension does", () => {
		expect(render("en", ["SENSITIVE_DATA_IN_PDF"])).toBe(
			`"${NAME}" contains personal or confidential data (1 email address), so it was not uploaded. PDFs cannot be masked: copy the text you need and paste it into the message instead (pasted text is masked), or ask your IT team.`,
		);
		expect(render("tr", ["SENSITIVE_DATA_IN_PDF"])).toBe(
			`"${NAME}" kişisel veya gizli bilgi içeriyor (1 e-posta adresi), bu yüzden yüklenmedi. PDF dosyaları maskelenemez: gereken metni kopyalayıp mesaja yapıştırın (yapıştırılan metin maskelenir) ya da BT ekibinize başvurun.`,
		);
		expect(render("tr", ["SENSITIVE_DATA_IN_IMAGE"], {})).not.toContain("()");
	});

	it("explains the most specific reason present", () => {
		const en = STRINGS.en.fileReasons;
		const pdfImages = [
			"BINARY_FILE_UNSCANNABLE",
			"PDF_IMAGES_NOT_INSPECTED",
			"PDF_IMAGE_OCR_UNAVAILABLE",
		];
		expect(render("en", pdfImages, {})).toBe(en.PDF_IMAGE_OCR_UNAVAILABLE(NAME, ""));
		const legacy = ["BINARY_FILE_UNSCANNABLE", "LEGACY_OFFICE_FORMAT", "LEGACY_OFFICE_UNSUPPORTED"];
		expect(render("en", legacy, {})).toBe(en.LEGACY_OFFICE_UNSUPPORTED(NAME, ""));
		expect(render("en", ["SENSITIVE_DATA_IN_PDF", "SIGNAL_SOURCE_CODE_HINT"], {})).toBe(
			en.SENSITIVE_DATA_IN_PDF(NAME, ""),
		);
		expect(render("en", ["ARCHIVE_CRC_MISMATCH"], {})).toBe(en.DOCUMENT_MALFORMED(NAME, ""));
		expect(render("tr", ["SIGNAL_SOURCE_CODE_HINT"], {})).toMatch(
			/^"rapor-2026\.pdf" yüklenmedi\. \S/,
		);
		expect(render("en", ["SOME_FUTURE_CODE"])).toBe(
			STRINGS.en.fileBlockedGeneric(NAME, "1 email address"),
		);
	});
});
