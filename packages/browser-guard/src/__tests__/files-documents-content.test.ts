// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type SanitizeDeps, sanitizeFile } from "../engine/files.js";
import {
	EMAIL,
	FakeDataTransfer,
	fileList,
	type Harness,
	makeFilesWritable,
	setupGuard,
} from "./content-helpers";
import { docx, para, run, unzipText } from "./helpers/documents.js";

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

function readBytes(file: File): Promise<Uint8Array> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
		reader.onerror = () => reject(reader.error);
		reader.readAsArrayBuffer(file);
	});
}

const DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

describe("content guard: document uploads", () => {
	it("replaces an uploaded DOCX with a masked copy (real sanitiser)", async () => {
		const g = start({
			sanitizeFile: (file, deps) => sanitizeFile(file, deps as SanitizeDeps),
		});
		const input = document.getElementById("file") as HTMLInputElement;
		const bytes = await docx(para(run("İletişim: jane.doe@"), run("example.com", true)));
		makeFilesWritable(input, [new File([bytes], "rapor.docx", { type: DOCX_TYPE })]);
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		await expect.poll(() => g.records().at(-1)?.action, { timeout: 5_000 }).toBe("masked");
		const replaced = input.files?.[0];
		expect(replaced?.name).toBe("rapor.docx");
		expect(replaced?.type).toBe(DOCX_TYPE);
		const xml = (await unzipText(await readBytes(replaced as File))).get("word/document.xml") ?? "";
		expect(xml).toContain("İletişim: [EMAIL_1]");
		expect(xml).not.toContain(EMAIL);
		expect(xml).not.toContain("jane.doe@");
		expect(g.toastText()).toContain("1 file sanitized before upload: 1 EMAIL");
	});

	it("documentHandling=block rejects Office/PDF uploads in every mode, other files pass", async () => {
		const g = start({ policy: { documentHandling: "block", mode: "monitor" } });
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["x"], "plan.pdf", { type: "application/pdf" })]);
		const change = new Event("change", { bubbles: true, cancelable: true });
		input.dispatchEvent(change);
		expect(change.defaultPrevented).toBe(true);
		expect(g.bubble()?.textContent).toContain("does not allow Office or PDF documents");
		expect(g.sanitizeFile).not.toHaveBeenCalled();
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", channel: "file" });

		// Monitor mode: a plain file is held only until its content was sniffed, then the
		// original (never a sanitised copy) is handed back to the page and recorded.
		const text = document.getElementById("file") as HTMLInputElement;
		const notes = new File(["x"], "notes.txt", { type: "text/plain" });
		makeFilesWritable(text, [notes]);
		const replayed: Event[] = [];
		text.addEventListener("change", (event) => replayed.push(event));
		const other = new Event("change", { bubbles: true, cancelable: true });
		text.dispatchEvent(other);
		expect(other.defaultPrevented).toBe(true);
		await expect.poll(() => replayed.length).toBe(1); // the replay (the original was stopped)
		expect(text.files?.[0]).toBe(notes);
		expect(g.records().at(-1)).toMatchObject({ action: "allowed", channel: "file" });
		expect(g.sanitizeFile).toHaveBeenCalledTimes(1); // the monitor recording, not a rewrite
	});

	it("documentHandling=block in monitor mode also refuses a PDF renamed to .txt (content sniff)", async () => {
		const g = start({ policy: { documentHandling: "block", mode: "monitor" } });
		const input = document.getElementById("file") as HTMLInputElement;
		const pdf = new File(["%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF"], "notes.txt", {
			type: "text/plain",
		});
		makeFilesWritable(input, [pdf]);
		const replayed: Event[] = [];
		input.addEventListener("change", (event) => replayed.push(event));
		const change = new Event("change", { bubbles: true, cancelable: true });
		input.dispatchEvent(change);
		expect(change.defaultPrevented).toBe(true);
		await expect
			.poll(() => g.bubble()?.textContent ?? "")
			.toContain("does not allow Office or PDF documents");
		expect(g.bubble()?.textContent).toContain("DOCUMENT_BLOCKED_BY_POLICY");
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", channel: "file" });
		expect(replayed).toHaveLength(0); // never handed to the page
	});

	it("documentHandling=block on a disabled site refuses a renamed PDF dropped on the page", async () => {
		const g = start({ policy: { documentHandling: "block", disabledSites: ["chatgpt"] } });
		const zone = document.getElementById("drop-zone") as HTMLElement;
		const received: Event[] = [];
		zone.addEventListener("drop", (event) => received.push(event));
		const drop = new Event("drop", { bubbles: true, cancelable: true });
		const pdf = new File(["%PDF-1.4 renamed"], "readme.md", { type: "text/markdown" });
		Object.defineProperty(drop, "dataTransfer", { value: { files: fileList([pdf]), items: [] } });
		zone.dispatchEvent(drop);
		expect(drop.defaultPrevented).toBe(true);
		await expect.poll(() => g.records().at(-1)?.action).toBe("blocked");
		expect(g.bubble()?.textContent).toContain("does not allow Office or PDF documents");
		expect(received).toHaveLength(0);
	});

	it("documentHandling=block in auto mode blocks a renamed PDF through the real sanitiser", async () => {
		const g = start({
			policy: { documentHandling: "block" },
			sanitizeFile: (file, deps) => sanitizeFile(file, deps as SanitizeDeps),
		});
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["%PDF-1.7 renamed"], "notes.txt", { type: "text/plain" })]);
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		await expect.poll(() => g.records().at(-1)?.action).toBe("blocked");
		expect(g.bubble()?.textContent).toContain("DOCUMENT_BLOCKED_BY_POLICY");
	});

	it("tells the user to paste the text when a PDF is blocked for sensitive data", async () => {
		const g = start({
			sanitizeFile: async () => ({
				action: "block",
				counts: { EMAIL: 1 },
				reasons: ["SENSITIVE_DATA_IN_PDF"],
			}),
		});
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["%PDF-1.7"], "rapor.pdf", { type: "application/pdf" })]);
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("SENSITIVE_DATA_IN_PDF");
		expect(g.bubble()?.textContent).toContain("paste it instead");
	});

	it("tells the user to save as .docx when a legacy file is blocked for sensitive data", async () => {
		const g = start({
			sanitizeFile: async () => ({
				action: "block",
				counts: { EMAIL: 1 },
				reasons: ["SENSITIVE_DATA_IN_LEGACY_OFFICE"],
			}),
		});
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File([new Uint8Array([0xd0, 0xcf])], "sozlesme.doc")]);
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		await expect
			.poll(() => g.bubble()?.textContent ?? "")
			.toContain("SENSITIVE_DATA_IN_LEGACY_OFFICE");
		expect(g.bubble()?.textContent).toContain("cannot be masked");
		expect(g.bubble()?.textContent).toContain("Save the file as .docx/.xlsx/.pptx");
		expect(g.bubble()?.textContent).not.toContain("could not be fully checked");
	});
});
