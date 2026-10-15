// @vitest-environment jsdom
/**
 * Uploads that pass without a complete check are always announced (legacy Office, images,
 * pictures inside documents), images are OCR'd through the worker's native bridge
 * (NATIVE_IMAGE_SCAN) when the policy enables the host, and blocked images explain why.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseImageInspection } from "../content/guard";
import type { FileDecision, GuardMessage, ImageInspection } from "../types";
import { FakeDataTransfer, type Harness, makeFilesWritable, setupGuard } from "./content-helpers";

let h: Harness | undefined;
const scope = window as unknown as Record<string, unknown>;

beforeEach(() => {
	scope.DataTransfer = FakeDataTransfer;
});

afterEach(() => {
	h?.guard.stop();
	h = undefined;
	document.body.innerHTML = "";
	delete scope.DataTransfer;
});

function start(options: Parameters<typeof setupGuard>[0] = {}): Harness {
	h = setupGuard(options);
	return h;
}

function upload(name: string, bytes = new Uint8Array([1, 2, 3])): { pageSaw: () => number } {
	const input = document.getElementById("file") as HTMLInputElement;
	makeFilesWritable(input, [new File([bytes], name)]);
	let saw = 0;
	input.addEventListener("change", () => saw++);
	input.dispatchEvent(new Event("change", { bubbles: true }));
	return { pageSaw: () => saw };
}

const allow = (...reasons: string[]): FileDecision => ({ action: "allow", counts: {}, reasons });
const sensitive: ImageInspection = {
	result: "sensitive",
	counts: { EMAIL: 1 },
	reasons: ["IMAGE_SENSITIVE_TEXT"],
};

describe("content guard: uploads that are not fully checked", () => {
	it.each([
		["eski.doc", ["BINARY_FILE_UNSCANNED", "LEGACY_OFFICE_FORMAT"], "old .doc/.xls/.ppt format"],
		[
			"ekran.png",
			["BINARY_FILE_UNSCANNED", "IMAGE_NOT_INSPECTED"],
			"images need the AIDR Privacy helper app",
		],
		["rapor.docx", ["DOCUMENT_IMAGES_NOT_INSPECTED"], 'Pictures inside "rapor.docx"'],
		[
			"tarama.pdf",
			["BINARY_FILE_UNSCANNED", "PDF_IMAGES_NOT_INSPECTED", "PDF_IMAGE_OCR_UNAVAILABLE"],
			'Images in "tarama.pdf" were not checked',
		],
	])("warns for %s", async (name, reasons, text) => {
		const g = start({ sanitizeFile: async () => allow(...reasons) });
		const { pageSaw } = upload(name);
		await expect.poll(() => g.toastText()).toContain(text);
		expect(pageSaw()).toBe(1);
	});

	it("keeps the masked summary next to the pictures warning", async () => {
		const g = start({
			sanitizeFile: async (f) => ({
				action: "mask",
				masked: { name: f.name, type: "", bytes: new Uint8Array([9]) },
				counts: { EMAIL: 1 },
				reasons: ["SENSITIVE_DATA", "DOCUMENT_IMAGES_NOT_INSPECTED"],
			}),
		});
		upload("rapor.docx");
		await expect
			.poll(() => g.toastText())
			.toContain("1 file masked before upload: 1 email address.");
		expect(g.toastText()).toContain('Pictures inside "rapor.docx" were not checked');
	});

	it("explains a blocked image and a blocked legacy file", async () => {
		const g = start({
			sanitizeFile: async (f) =>
				f.name.endsWith(".png")
					? { action: "block", counts: { EMAIL: 1 }, reasons: ["SENSITIVE_DATA_IN_IMAGE"] }
					: {
							action: "block",
							counts: {},
							reasons: ["BINARY_FILE_UNSCANNABLE", "LEGACY_OFFICE_FORMAT"],
						},
		});
		const png = upload("ekran.png");
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("Pictures cannot be masked");
		expect(g.bubble()?.textContent).toContain("crop or black out that part");
		expect(png.pageSaw()).toBe(0);
		g.bubbleButton("close")?.click();
		upload("eski.xls");
		await expect
			.poll(() => g.bubble()?.textContent ?? "")
			.toContain("(old .doc/.xls/.ppt format) could not be fully checked");
		expect(g.bubble()?.textContent).toContain("Save it as .docx/.xlsx/.pptx");
	});
});

describe("content guard: image OCR through the native host", () => {
	/** A sanitizer that forwards the image to the guard's OCR and blocks on a sensitive result. */
	const ocrSanitizer: Parameters<typeof setupGuard>[0] = {
		sanitizeFile: async (file, deps) => {
			const inspection = (await deps.inspectImage?.(file.bytes)) ?? null;
			return inspection?.result === "sensitive"
				? { action: "block", counts: inspection.counts, reasons: ["SENSITIVE_DATA_IN_IMAGE"] }
				: allow(inspection ? `OCR_${inspection.result.toUpperCase()}` : "IMAGE_NOT_INSPECTED");
		},
	};
	const imageScans = (g: Harness) =>
		g.messages.filter(
			(m): m is Extract<GuardMessage, { type: "NATIVE_IMAGE_SCAN" }> =>
				m.type === "NATIVE_IMAGE_SCAN",
		);

	it("sends the image to the worker and blocks on sensitive text", async () => {
		const g = start({
			...ocrSanitizer,
			policy: { useNativeHost: true },
			respond: (m) =>
				m.type === "NATIVE_IMAGE_SCAN"
					? { ok: true, inspection: sensitive, status: "connected" }
					: undefined,
		});
		const { pageSaw } = upload("ekran.png", new Uint8Array([0x89, 0x50, 0x4e, 0x47]));
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("Pictures cannot be masked");
		expect(imageScans(g)).toEqual([{ type: "NATIVE_IMAGE_SCAN", data: "iVBORw==" }]);
		expect(pageSaw()).toBe(0);
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", counts: { EMAIL: 1 } });
	});

	it("does not contact the host when the policy does not enable it", async () => {
		const g = start({ ...ocrSanitizer, policy: { useNativeHost: false } });
		upload("ekran.png");
		await expect.poll(() => g.sanitizeFile.mock.calls.length).toBe(1);
		await expect.poll(() => g.records().length).toBe(1);
		expect(imageScans(g)).toEqual([]);
	});

	it("treats a malformed or late reply as no inspection", async () => {
		const late = start({
			...ocrSanitizer,
			policy: { useNativeHost: true },
			nativeImageTimeoutMs: 20,
			respond: (m) => (m.type === "NATIVE_IMAGE_SCAN" ? new Promise(() => undefined) : undefined),
		});
		upload("ekran.png");
		await expect.poll(() => late.toastText()).toBe("");
		await expect.poll(() => late.records().length).toBe(1);
		expect(late.records()[0]).toMatchObject({ action: "allowed" });
	});

	it("validates the worker's inspection", () => {
		expect(parseImageInspection({ ok: true, inspection: sensitive })).toEqual(sensitive);
		for (const bad of [
			undefined,
			{ ok: false, error: "BAD_MESSAGE" },
			{ ok: true, inspection: null },
			{ ok: true, inspection: { ...sensitive, result: "maybe" } },
			{ ok: true, inspection: { ...sensitive, counts: { NOT_A_TYPE: 1 } } },
			{ ok: true, inspection: { ...sensitive, counts: { EMAIL: -1 } } },
			{ ok: true, inspection: { ...sensitive, reasons: [1] } },
		]) {
			expect(parseImageInspection(bad)).toBeNull();
		}
	});
});
