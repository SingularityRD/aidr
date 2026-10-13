// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FileDecision } from "../types";
import {
	EMAIL,
	FakeDataTransfer,
	fakeEngine,
	fileList,
	type Harness,
	makeFilesWritable,
	readText,
	setupGuard,
} from "./content-helpers";

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

function pasteEvent(text: string, files: File[] = []): Event {
	const event = new Event("paste", { bubbles: true, cancelable: true });
	const data = new FakeDataTransfer();
	data.setData("text/plain", text);
	for (const file of files) data.items.add(file);
	Object.defineProperty(event, "clipboardData", { value: data });
	return event;
}

const encoder = new TextEncoder();
const maskedFile = (name: string, content: string): FileDecision => ({
	action: "mask",
	masked: { name, type: "text/plain", bytes: encoder.encode(content) },
	counts: { EMAIL: 1 },
	reasons: ["SENSITIVE_DATA"],
});

describe("content guard: paste", () => {
	it("on a disabled site records pastes with findings but lets the site insert them unchanged", async () => {
		const g = start({ policy: { disabledSites: ["chatgpt"], mode: "block" } });
		const event = pasteEvent(`mail ${EMAIL}`);
		g.editor.dispatchEvent(event);
		expect(event.defaultPrevented).toBe(false); // the site handles the paste itself
		await expect
			.poll(() => g.records())
			.toEqual([
				{
					type: "RECORD",
					site: "chatgpt",
					action: "allowed",
					channel: "paste",
					counts: { EMAIL: 1 },
				},
			]);
		expect(g.vault.size()).toBe(0);
	});

	it("masks pasted text and inserts the masked version at the caret", async () => {
		const g = start();
		g.editor.value = "Hi ";
		g.editor.setSelectionRange(3, 3);
		const event = pasteEvent(`contact ${EMAIL}`);
		g.editor.dispatchEvent(event);
		expect(event.defaultPrevented).toBe(true);
		await expect.poll(() => g.editor.value).toBe("Hi contact [EMAIL_1]");
		expect(g.toastText()).toContain("Pasted text masked: 1 email address.");
		expect(g.records()).toEqual([
			{ type: "RECORD", site: "chatgpt", action: "masked", channel: "paste", counts: { EMAIL: 1 } },
		]);
		expect(JSON.stringify(g.messages)).not.toContain(EMAIL);
	});

	it("inserts clean pasted text unchanged", async () => {
		const g = start();
		g.editor.dispatchEvent(pasteEvent("nothing to see"));
		await expect.poll(() => g.editor.value).toBe("nothing to see");
		expect(g.records()).toEqual([]);
	});

	it("block mode refuses to insert sensitive pasted text", async () => {
		const g = start({ policy: { mode: "block" } });
		g.editor.dispatchEvent(pasteEvent(`contact ${EMAIL}`));
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("was not inserted");
		expect(g.editor.value).toBe("");
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", channel: "paste" });
	});

	it("fails closed when the paste cannot be scanned", async () => {
		const g = start({ engine: fakeEngine({ fail: "throw" }) });
		const event = pasteEvent(`contact ${EMAIL}`);
		g.editor.dispatchEvent(event);
		expect(event.defaultPrevented).toBe(true);
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("could not check the pasted");
		expect(g.editor.value).toBe("");
	});

	it("leaves pastes alone when maskPaste is off, and in monitor mode", async () => {
		const g = start({ policy: { maskPaste: false } });
		const off = pasteEvent(`contact ${EMAIL}`);
		g.editor.dispatchEvent(off);
		expect(off.defaultPrevented).toBe(false);

		g.policy = { ...(g.policy ?? ({} as never)), maskPaste: true, mode: "monitor" };
		const monitored = pasteEvent(`contact ${EMAIL}`);
		g.editor.dispatchEvent(monitored);
		expect(monitored.defaultPrevented).toBe(false);
		await expect
			.poll(() => g.records())
			.toEqual([
				{
					type: "RECORD",
					site: "chatgpt",
					action: "allowed",
					channel: "paste",
					counts: { EMAIL: 1 },
				},
			]);
	});

	it("ignores pastes outside the editor", () => {
		const g = start();
		const outside = document.getElementById("drop-zone") as HTMLElement;
		const event = pasteEvent(`contact ${EMAIL}`);
		outside.dispatchEvent(event);
		expect(event.defaultPrevented).toBe(false);
		expect(g.engine.scan).not.toHaveBeenCalled();
	});

	it("never intercepts the editor module's own synthetic paste (masked rewrite)", async () => {
		const g = start();
		// A rich editor whose write path relies on the synthetic paste strategy.
		const rich = document.createElement("div");
		rich.setAttribute("contenteditable", "true");
		g.editor.replaceWith(rich);
		rich.id = "editor"; // the guard's findEditor now resolves to the rich editor
		const { editorAccess } = await import("../dom/editor");
		const access = editorAccess(rich);
		let pastes = 0;
		rich.addEventListener("paste", (event) => {
			pastes++;
			const text = (event as ClipboardEvent).clipboardData?.getData("text/plain") ?? "";
			event.preventDefault();
			rich.textContent = text;
		});
		await access.write("[EMAIL_1] hi");
		expect(pastes).toBeGreaterThan(0);
		expect(rich.textContent).toBe("[EMAIL_1] hi");
		expect(g.engine.scan).not.toHaveBeenCalled();
	});
});

describe("content guard: file uploads", () => {
	it("replaces a selected file with the sanitized copy through DataTransfer and re-dispatches change", async () => {
		const g = start({ sanitizeFile: async (f) => maskedFile(f.name, "mail [EMAIL_1]") });
		const input = document.getElementById("file") as HTMLInputElement;
		const original = new File([`mail ${EMAIL}`], "notes.txt", { type: "text/plain" });
		makeFilesWritable(input, [original]);
		const seen: string[] = [];
		input.addEventListener("change", () => {
			const file = input.files?.[0];
			if (file) void readText(file).then((text) => seen.push(text));
		});

		const change = new Event("change", { bubbles: true, cancelable: true });
		input.dispatchEvent(change);
		expect(seen).toEqual([]); // the page never saw the original selection

		await expect.poll(() => seen).toEqual(["mail [EMAIL_1]"]);
		expect(input.files?.[0]?.name).toBe("notes.txt");
		expect(input.files?.[0]).not.toBe(original);
		const call = g.sanitizeFile.mock.calls[0]?.[0] as { bytes: Uint8Array; name: string };
		expect(new TextDecoder().decode(call.bytes)).toBe(`mail ${EMAIL}`);
		expect(g.toastText()).toContain("1 file masked before upload: 1 email address.");
		expect(g.records()).toEqual([
			{ type: "RECORD", site: "chatgpt", action: "masked", channel: "file", counts: { EMAIL: 1 } },
		]);
	});

	it("blocks a file the sanitizer rejects: prevents, clears and shows a bubble", async () => {
		const g = start({
			sanitizeFile: async () => ({ action: "block", counts: {}, reasons: ["FORMULA_CELL"] }),
		});
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["=cmd()"], "sheet.csv", { type: "text/csv" })]);
		let pageSaw = 0;
		input.addEventListener("change", () => pageSaw++);
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		await expect
			.poll(() => g.bubble()?.textContent ?? "")
			.toContain('"sheet.csv" was not uploaded');
		expect(g.bubble()?.textContent).toContain("FORMULA_CELL");
		expect(pageSaw).toBe(0);
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", channel: "file" });
	});

	it("warns when a binary file could not be scanned", async () => {
		const g = start({
			sanitizeFile: async () => ({
				action: "allow",
				counts: {},
				reasons: ["BINARY_FILE_UNSCANNED"],
			}),
		});
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [
			new File([new Uint8Array([0, 1, 2])], "photo.png", { type: "image/png" }),
		]);
		let pageSaw = 0;
		input.addEventListener("change", () => pageSaw++);
		input.dispatchEvent(new Event("change", { bubbles: true }));
		await expect.poll(() => g.toastText()).toContain('"photo.png" could not be checked');
		expect(pageSaw).toBe(1);
	});

	it("blocks files over maxFileBytes without reading them", async () => {
		const g = start({ policy: { maxFileBytes: 4 } });
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["0123456789"], "big.txt")]);
		input.dispatchEvent(new Event("change", { bubbles: true }));
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("FILE_TOO_LARGE");
		expect(g.sanitizeFile).not.toHaveBeenCalled();
	});

	it("fails closed when the sanitizer throws", async () => {
		const g = start({
			sanitizeFile: async () => {
				throw new Error("parser crashed");
			},
		});
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["x"], "a.txt")]);
		let pageSaw = 0;
		input.addEventListener("change", () => pageSaw++);
		input.dispatchEvent(new Event("change", { bubbles: true }));
		await expect.poll(() => g.bubble()?.textContent ?? "").toContain("file could not be checked");
		expect(pageSaw).toBe(0);
	});

	it("masks dropped files and replays a synthetic drop with the sanitized copy", async () => {
		const g = start({ sanitizeFile: async (f) => maskedFile(f.name, "[EMAIL_1]") });
		const zone = document.getElementById("drop-zone") as HTMLElement;
		const received: string[] = [];
		zone.addEventListener("drop", (event) => {
			const file = (event as DragEvent).dataTransfer?.files[0];
			if (file) void readText(file).then((text) => received.push(text));
		});
		const drop = new Event("drop", { bubbles: true, cancelable: true });
		Object.defineProperty(drop, "dataTransfer", {
			value: { files: fileList([new File([EMAIL], "e.txt")]), items: [] },
		});
		zone.dispatchEvent(drop);
		expect(drop.defaultPrevented).toBe(true);
		await expect.poll(() => received).toEqual(["[EMAIL_1]"]);
		expect(g.records().at(-1)).toMatchObject({ action: "masked", channel: "file" });
	});

	it("fileHandling=block blocks uploads in every mode", async () => {
		const g = start({ policy: { fileHandling: "block", mode: "monitor" } });
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["x"], "a.txt")]);
		const change = new Event("change", { bubbles: true, cancelable: true });
		input.dispatchEvent(change);
		expect(g.bubble()?.textContent).toContain("does not allow file uploads");
		expect(g.sanitizeFile).not.toHaveBeenCalled();
	});

	it("on a disabled site counts file uploads without replacing them", async () => {
		const g = start({
			policy: { disabledSites: ["chatgpt"] },
			sanitizeFile: async () => maskedFile("a.txt", "[EMAIL_1]"),
		});
		const input = document.getElementById("file") as HTMLInputElement;
		const original = new File([`mail ${EMAIL}`], "a.txt");
		makeFilesWritable(input, [original]);
		const change = new Event("change", { bubbles: true, cancelable: true });
		input.dispatchEvent(change);
		expect(change.defaultPrevented).toBe(false);
		await expect
			.poll(() => g.records())
			.toEqual([
				{
					type: "RECORD",
					site: "chatgpt",
					action: "allowed",
					channel: "file",
					counts: { EMAIL: 1 },
				},
			]);
		expect(input.files?.[0]).toBe(original);
	});

	it("blocks uploads when the browser cannot replace files", async () => {
		delete scope.DataTransfer;
		const g = start();
		const input = document.getElementById("file") as HTMLInputElement;
		makeFilesWritable(input, [new File(["x"], "a.txt")]);
		input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		expect(g.bubble()?.textContent).toContain("cannot replace the file");
	});
});
