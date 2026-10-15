// @vitest-environment jsdom
/**
 * Detached and shadow-DOM `<input type=file>` (review regression): the guard's window
 * capture listeners never saw a detached input (createElement + click) and saw an
 * input in a shadow root only retargeted, without its non-composed `change`, so the
 * page received the original file unchecked. The page-world hook
 * (content/file-input-hook.ts) now routes those selections through sanitizeFile, and a
 * shadow-DOM selection without the hook is blocked.
 *
 * jsdom runs both "worlds" in one realm, so the test installs the hook and the guard
 * on the same window; the hook only talks to the guard over DOM events, as in a browser.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type FileInputHook, installFileInputHook } from "../content/file-input-hook";
import { RELAY_RESULT, RELAY_SCAN } from "../content/file-relay";
import type { FileDecision } from "../types";
import {
	EMAIL,
	FakeDataTransfer,
	fileList,
	type Harness,
	readText,
	setupGuard,
} from "./content-helpers";

(window as unknown as { DataTransfer: unknown }).DataTransfer = FakeDataTransfer;

const proto = HTMLInputElement.prototype;
const realFiles = Object.getOwnPropertyDescriptor(proto, "files") as PropertyDescriptor;
const realValue = Object.getOwnPropertyDescriptor(proto, "value") as PropertyDescriptor;
const realClick = proto.click;

/**
 * A browser-like native `files` accessor: jsdom's setter only takes its own FileList and
 * there is no picker, so the "user's selection" is written through this setter.
 */
function installNativeFiles(): void {
	const store = new WeakMap<HTMLInputElement, FileList>();
	Object.defineProperty(proto, "files", {
		configurable: true,
		enumerable: true,
		get(this: HTMLInputElement) {
			if (this.type !== "file") return null;
			let list = store.get(this);
			if (!list) {
				list = fileList([]);
				store.set(this, list);
			}
			return list;
		},
		set(this: HTMLInputElement, value: FileList) {
			store.set(this, value);
		},
	});
	Object.defineProperty(proto, "value", {
		...realValue,
		set(this: HTMLInputElement, value: string) {
			if (this.type === "file") {
				if (value === "") store.set(this, fileList([]));
				return;
			}
			realValue.set?.call(this, value);
		},
	});
}

let h: Harness | undefined;
let hook: FileInputHook | null = null;

beforeEach(() => {
	installNativeFiles();
});

afterEach(() => {
	hook?.uninstall();
	hook = null;
	h?.guard.stop();
	h = undefined;
	Object.defineProperty(proto, "files", realFiles);
	Object.defineProperty(proto, "value", realValue);
	proto.click = realClick;
	document.body.innerHTML = "";
});

const encoder = new TextEncoder();
const maskingSanitizer = async (file: { name: string }): Promise<FileDecision> => ({
	action: "mask",
	masked: { name: file.name, type: "text/plain", bytes: encoder.encode("mail [EMAIL_1]") },
	counts: { EMAIL: 1 },
	reasons: ["SENSITIVE_DATA"],
});

/** The user picks `files` in the native dialog: the browser sets them, then fires input + change. */
function choose(input: HTMLInputElement, files: File[]): void {
	(realFilesSetter() as (this: HTMLInputElement, v: FileList) => void).call(input, fileList(files));
	input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
	input.dispatchEvent(new Event("change", { bubbles: true }));
}
const realFilesSetter = () => Object.getOwnPropertyDescriptor(proto, "files")?.set;

const original = () => new File([`mail ${EMAIL}`], "n.txt", { type: "text/plain" });
const settle = () => new Promise((r) => setTimeout(r, 20));

/** A page that records every file its change handler can read. */
function pageInput(input: HTMLInputElement): File[] {
	const seen: File[] = [];
	input.addEventListener("change", () => {
		for (const f of input.files ?? []) seen.push(f);
	});
	return seen;
}

describe("page-world file-input hook", () => {
	it("routes a detached input (createElement + click) through sanitizeFile", async () => {
		hook = installFileInputHook(window);
		const g = (h = setupGuard({ sanitizeFile: maskingSanitizer }));
		const input = document.createElement("input");
		input.type = "file"; // never attached
		const seen = pageInput(input);
		input.click();
		const file = original();
		choose(input, [file]);
		await expect.poll(() => seen.length).toBe(1);
		expect(g.sanitizeFile).toHaveBeenCalledTimes(1);
		expect(seen).not.toContain(file);
		expect(await readText(seen[0] as File)).toBe("mail [EMAIL_1]");
		expect(g.records().at(-1)).toMatchObject({ action: "masked", channel: "file" });
	});

	it("routes an input inside an open shadow root opened directly by the user", async () => {
		hook = installFileInputHook(window);
		const g = (h = setupGuard({ sanitizeFile: maskingSanitizer }));
		const host = document.createElement("div");
		document.body.append(host);
		const input = document.createElement("input");
		input.type = "file";
		host.attachShadow({ mode: "open" }).append(input);
		const seen = pageInput(input);
		const file = original();
		choose(input, [file]); // no click(): only the files getter sees it
		await expect.poll(() => seen.length).toBe(1);
		expect(g.sanitizeFile).toHaveBeenCalledTimes(1);
		expect(seen).not.toContain(file);
		expect(await readText(seen[0] as File)).toBe("mail [EMAIL_1]");
	});

	it("routes an input inside a closed shadow root", async () => {
		hook = installFileInputHook(window);
		const g = (h = setupGuard({ sanitizeFile: maskingSanitizer }));
		const host = document.createElement("div");
		document.body.append(host);
		const input = document.createElement("input");
		input.type = "file";
		host.attachShadow({ mode: "closed" }).append(input);
		const seen = pageInput(input);
		input.showPicker?.();
		input.click();
		choose(input, [original()]);
		await expect.poll(() => seen.length).toBe(1);
		expect(g.sanitizeFile).toHaveBeenCalledTimes(1);
		expect(await readText(seen[0] as File)).toBe("mail [EMAIL_1]");
	});

	it("releases nothing when the guard blocks the file", async () => {
		hook = installFileInputHook(window);
		const g = (h = setupGuard({
			sanitizeFile: async () => ({ action: "block", counts: { EMAIL: 1 }, reasons: ["X"] }),
		}));
		const input = document.createElement("input");
		input.type = "file";
		const seen = pageInput(input);
		input.click();
		choose(input, [original()]);
		await expect.poll(() => g.records().length).toBe(1);
		await settle();
		expect(seen).toEqual([]);
		expect(input.files?.length).toBe(0);
		expect(g.bubble()?.textContent ?? "").toContain("n.txt");
	});

	it("keeps the selection cleared when no guard accepts the request (fail closed)", async () => {
		hook = installFileInputHook(window, { timeoutMs: 50 });
		const input = document.createElement("input");
		input.type = "file";
		const seen = pageInput(input);
		input.click();
		choose(input, [original()]);
		await new Promise((r) => setTimeout(r, 100));
		expect(seen).toEqual([]);
		expect(input.files?.length).toBe(0);
	});

	it("keeps the selection cleared when the guard never answers", async () => {
		hook = installFileInputHook(window, { timeoutMs: 50 });
		const swallow = (event: Event) => event.preventDefault(); // accepts, never answers
		window.addEventListener(RELAY_SCAN, swallow, true);
		try {
			const input = document.createElement("input");
			input.type = "file";
			const seen = pageInput(input);
			input.click();
			choose(input, [original()]);
			await new Promise((r) => setTimeout(r, 100));
			// A late or forged answer for an unknown request releases nothing.
			const data = new FakeDataTransfer();
			data.items.add(original());
			data.setData("application/x-aidr-request", "nope");
			data.setData("application/x-aidr-verdict", "ok");
			const late = new Event(RELAY_RESULT);
			Object.defineProperty(late, "dataTransfer", { value: data });
			document.dispatchEvent(late);
			expect(seen).toEqual([]);
			expect(input.files?.length).toBe(0);
		} finally {
			window.removeEventListener(RELAY_SCAN, swallow, true);
		}
	});

	it("leaves document inputs to the window listeners (no double scan)", async () => {
		hook = installFileInputHook(window);
		const g = (h = setupGuard({ sanitizeFile: maskingSanitizer }));
		const input = document.getElementById("file") as HTMLInputElement;
		const seen = pageInput(input);
		input.click();
		choose(input, [original()]);
		await expect.poll(() => seen.length).toBe(1);
		expect(g.sanitizeFile).toHaveBeenCalledTimes(1);
		expect(await readText(seen[0] as File)).toBe("mail [EMAIL_1]");
	});

	it("passes files through unchanged when file handling is allow", async () => {
		hook = installFileInputHook(window);
		const g = (h = setupGuard({ policy: { fileHandling: "allow" } }));
		const input = document.createElement("input");
		input.type = "file";
		const seen = pageInput(input);
		input.click();
		const file = original();
		choose(input, [file]);
		await expect.poll(() => seen.length).toBe(1);
		expect(seen[0]).toBe(file);
		expect(g.sanitizeFile).not.toHaveBeenCalled();
	});
});

describe("isolated guard without the page-world hook", () => {
	it("blocks a selection from an open shadow root it cannot guard", async () => {
		const g = (h = setupGuard({ sanitizeFile: maskingSanitizer }));
		const host = document.createElement("div");
		document.body.append(host);
		const input = document.createElement("input");
		input.type = "file";
		host.attachShadow({ mode: "open" }).append(input);
		const seen = pageInput(input);
		choose(input, [original()]);
		await settle();
		expect(seen).toEqual([]);
		expect(input.files?.length).toBe(0);
		expect(g.sanitizeFile).not.toHaveBeenCalled();
		expect(g.bubble()?.textContent ?? "").toContain("cannot be checked on this page");
		expect(g.records().at(-1)).toMatchObject({ action: "blocked", channel: "file" });
	});
});

describe("page-world footprint (BG-14)", () => {
	const ownKeys = (target: object) => [
		...Object.getOwnPropertyNames(target),
		...Object.getOwnPropertySymbols(target).map(String),
	];

	it("leaves no named global, symbol or flag on window", () => {
		const before = new Set(ownKeys(window));
		hook = installFileInputHook(window);
		expect(hook).not.toBeNull();
		expect(ownKeys(window).filter((k) => !before.has(k))).toEqual([]);
		expect(ownKeys(window).filter((k) => /aidr/i.test(k))).toEqual([]);
		expect("__aidrFileInputHook" in window).toBe(false);
	});

	it("still installs only once per window, and again after uninstall", () => {
		hook = installFileInputHook(window);
		expect(hook).not.toBeNull();
		expect(installFileInputHook(window)).toBeNull();
		hook?.uninstall();
		hook = installFileInputHook(window);
		expect(hook).not.toBeNull();
	});
});
