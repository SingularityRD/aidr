// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	editorAccess,
	findEditor,
	findEditorNear,
	findSendButton,
	insertAtSelection,
	isSyntheticEditorEvent,
} from "../dom/editor";
import { hasLayout, isVisible } from "../dom/visibility";
import type { SiteAdapter } from "../types";

function adapter(overrides: Partial<SiteAdapter> = {}): SiteAdapter {
	return {
		id: "other",
		label: "Test",
		hosts: [],
		editorSelectors: [],
		sendButtonSelectors: [],
		responseSelectors: [],
		userMessageSelectors: [],
		fileInputSelectors: [],
		...overrides,
	};
}

function mount(html: string): HTMLElement {
	document.body.innerHTML = html;
	return document.body;
}

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
	const element = document.getElementById(id);
	if (!element) throw new Error(`missing #${id}`);
	return element as T;
}

/** Simulates the browser's native execCommand editing over the current selection. */
function nativeExecCommand(command: string, _showUi?: boolean, value?: string): boolean {
	const selection = document.getSelection();
	if (!selection || selection.rangeCount === 0) return false;
	const range = selection.getRangeAt(0);
	range.deleteContents();
	if (command === "insertText" && value) {
		const fragment = document.createDocumentFragment();
		value.split("\n").forEach((line, index) => {
			if (index > 0) fragment.appendChild(document.createElement("br"));
			if (line) fragment.appendChild(document.createTextNode(line));
		});
		range.insertNode(fragment);
	}
	return true;
}

function stubExecCommand(impl: (command: string, showUi?: boolean, value?: string) => boolean) {
	const fn = vi.fn(impl);
	Object.defineProperty(document, "execCommand", { configurable: true, writable: true, value: fn });
	return fn;
}

function placeCaret(node: Node, offset: number, endOffset = offset): void {
	const range = document.createRange();
	range.setStart(node, offset);
	range.setEnd(node, endOffset);
	const selection = document.getSelection();
	selection?.removeAllRanges();
	selection?.addRange(range);
}

afterEach(() => {
	Reflect.deleteProperty(document, "execCommand");
	document.body.innerHTML = "";
	vi.restoreAllMocks();
});

describe("textarea editors", () => {
	it("writes through the native prototype setter so React-style trackers see a change", async () => {
		mount('<textarea id="t"></textarea>');
		const textarea = byId<HTMLTextAreaElement>("t");
		const proto = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
		if (!proto?.get || !proto.set) throw new Error("jsdom lacks textarea value accessor");
		const protoGet = proto.get;
		const protoSet = proto.set;
		// React installs an instance-level value property to track the last value it rendered.
		let tracked = "";
		let instanceSets = 0;
		Object.defineProperty(textarea, "value", {
			configurable: true,
			get() {
				return protoGet.call(this);
			},
			set(value: string) {
				instanceSets++;
				tracked = value;
				protoSet.call(this, value);
			},
		});
		const seen: Array<{ inputType: string; value: string; trackerStale: boolean }> = [];
		textarea.addEventListener("input", (event) => {
			expect(event.bubbles).toBe(true);
			expect(isSyntheticEditorEvent(event)).toBe(true);
			seen.push({
				inputType: (event as InputEvent).inputType,
				value: textarea.value,
				trackerStale: textarea.value !== tracked,
			});
		});
		const change = vi.fn();
		textarea.addEventListener("change", change);

		const editor = editorAccess(textarea);
		expect(editor.kind).toBe("textarea");
		await editor.write("hello\r\nworld");

		expect(instanceSets).toBe(0);
		expect(seen).toEqual([
			{ inputType: "insertReplacementText", value: "hello\nworld", trackerStale: true },
		]);
		expect(change).toHaveBeenCalledTimes(1);
		expect(editor.read()).toBe("hello\nworld");
		expect(textarea.selectionStart).toBe("hello\nworld".length);
	});

	it("strips line breaks for single-line inputs and rejects when a handler rewrites the value", async () => {
		mount('<input id="i" type="text" />');
		const input = byId<HTMLInputElement>("i");
		const editor = editorAccess(input);
		await editor.write("a\nb");
		expect(editor.read()).toBe("ab");

		input.addEventListener("input", () => {
			input.value = "reverted";
		});
		await expect(editor.write("masked")).rejects.toThrow("EDITOR_WRITE_MISMATCH");
	});
});

describe("contenteditable reading", () => {
	it("preserves paragraph and line breaks of a plain contenteditable", () => {
		mount(
			'<div id="e" contenteditable="true">line1<div>line2</div><div><br></div><div>line4</div></div>',
		);
		const editor = editorAccess(byId("e"));
		expect(editor.kind).toBe("contenteditable");
		expect(editor.read()).toBe("line1\nline2\n\nline4");
	});

	it("drops one trailing <br> per block, maps nbsp and trims only trailing zero-width chars", () => {
		mount('<div id="e" contenteditable="">a&nbsp;b<br>c<br><br></div>');
		expect(editorAccess(byId("e")).read()).toBe("a b\nc\n");
		mount('<div id="e" contenteditable="true">​keep​﻿</div>');
		expect(editorAccess(byId("e")).read()).toBe("​keep");
	});

	it("reads lists and ignores formatting whitespace between blocks", () => {
		mount(`<div id="e" contenteditable="true">
			<p>intro</p>
			<ul>
				<li>one</li>
				<li>two</li>
			</ul>
			<script>ignored()</script>
		</div>`);
		expect(editorAccess(byId("e")).read()).toBe("intro\none\ntwo");
	});
});

describe("ProseMirror editors", () => {
	const pm = `<div id="pm" class="ProseMirror" contenteditable="true" tabindex="0">
		<p>Hello</p>
		<p>a<br>b</p>
		<p><br class="ProseMirror-trailingBreak"></p>
		<p>end<br><br class="ProseMirror-trailingBreak"></p>
	</div>`;

	it("reads paragraphs, hard breaks and trailing breaks", () => {
		mount(pm);
		const editor = editorAccess(byId("pm"));
		expect(editor.kind).toBe("prosemirror");
		expect(editor.read()).toBe("Hello\na\nb\n\nend\n");
	});

	it("resolves nodes inside the editor to the editing host", () => {
		mount(pm);
		const paragraph = byId("pm").querySelector("p") as HTMLElement;
		const editor = editorAccess(paragraph);
		expect(editor.element.id).toBe("pm");
		expect(editor.kind).toBe("prosemirror");
	});

	it("writes via execCommand insertText over a select-all range", async () => {
		mount(pm);
		const exec = stubExecCommand(nativeExecCommand);
		const paste = vi.fn();
		byId("pm").addEventListener("paste", paste);
		const editor = editorAccess(byId("pm"));
		await editor.write("[PERSON_1] said\nhi");
		expect(exec).toHaveBeenCalledWith("insertText", false, "[PERSON_1] said\nhi");
		expect(paste).not.toHaveBeenCalled();
		expect(editor.read()).toBe("[PERSON_1] said\nhi");
	});

	it("falls back to a synthetic paste that the editor handles itself", async () => {
		mount(pm);
		stubExecCommand(() => false);
		const element = byId("pm");
		const pasted: string[] = [];
		element.addEventListener("paste", (event) => {
			const data = (event as ClipboardEvent).clipboardData;
			expect(isSyntheticEditorEvent(event)).toBe(true);
			const text = data?.getData("text/plain") ?? "";
			pasted.push(text);
			event.preventDefault();
			element.replaceChildren(
				...text.split("\n").map((line) => {
					const p = document.createElement("p");
					p.textContent = line;
					return p;
				}),
			);
		});
		await editorAccess(element).write("x\ny");
		expect(pasted).toEqual(["x\ny"]);
		expect(element.innerHTML).toBe("<p>x</p><p>y</p>");
	});

	it("uses a handled beforeinput before trying paste", async () => {
		mount(pm);
		const element = byId("pm");
		const paste = vi.fn();
		element.addEventListener("paste", paste);
		element.addEventListener("beforeinput", (event) => {
			const input = event as InputEvent;
			expect(input.inputType).toBe("insertReplacementText");
			event.preventDefault();
			element.textContent = input.dataTransfer?.getData("text/plain") ?? "";
		});
		await editorAccess(element).write("via beforeinput");
		expect(paste).not.toHaveBeenCalled();
		expect(element.textContent).toBe("via beforeinput");
	});
});

describe("Quill editors and the DOM fallback", () => {
	it("reads Quill paragraphs", () => {
		mount(
			'<div class="ql-container"><div id="q" class="ql-editor" contenteditable="true"><p>one</p><p><br></p><p>three</p></div></div>',
		);
		const editor = editorAccess(byId("q"));
		expect(editor.kind).toBe("quill");
		expect(editor.read()).toBe("one\n\nthree");
	});

	it("replaces the DOM with one <p> per line when execCommand is missing", async () => {
		mount('<div id="q" class="ql-editor" contenteditable="true"><p>secret</p></div>');
		const element = byId("q");
		const inputs: string[] = [];
		element.addEventListener("input", (event) => inputs.push((event as InputEvent).inputType));
		const editor = editorAccess(element);
		await editor.write("one\n\nthree");
		expect(element.innerHTML).toBe("<p>one</p><p><br></p><p>three</p>");
		expect(inputs).toEqual(["insertReplacementText"]);
		expect(editor.read()).toBe("one\n\nthree");
	});

	it("falls back when execCommand reports success but leaves the wrong text", async () => {
		mount('<div id="q" class="ql-editor" contenteditable="true"><p>secret</p></div>');
		const exec = stubExecCommand(() => true);
		const editor = editorAccess(byId("q"));
		await editor.write("masked");
		expect(exec).toHaveBeenCalledTimes(1);
		expect(editor.read()).toBe("masked");
	});

	it("falls back when execCommand returns false and can empty the editor", async () => {
		mount('<div id="q" class="ql-editor" contenteditable="true"><p>secret</p></div>');
		stubExecCommand(() => false);
		const editor = editorAccess(byId("q"));
		await editor.write("");
		expect(editor.read()).toBe("");
		expect(byId("q").innerHTML).toBe("<p><br></p>");
	});

	it("rejects when the editor refuses the rewrite", async () => {
		mount('<div id="q" class="ql-editor" contenteditable="true"><p>secret</p></div>');
		const element = byId("q");
		element.addEventListener("input", () => {
			element.innerHTML = "<p>secret</p>";
		});
		await expect(editorAccess(element).write("masked")).rejects.toThrow("EDITOR_WRITE_MISMATCH");
	});

	it("rejects writes to a detached editor", async () => {
		const orphan = document.createElement("textarea");
		await expect(editorAccess(orphan).write("x")).rejects.toThrow("EDITOR_DETACHED");
	});
});

describe("findEditor", () => {
	it("prefers the focused candidate among several", () => {
		mount('<textarea id="a"></textarea><textarea id="b"></textarea><textarea id="c"></textarea>');
		byId("b").focus();
		expect(findEditor(adapter(), document)?.element.id).toBe("b");
	});

	it("uses lastFocused when focus has left the editor", () => {
		mount(
			'<div id="pm" class="ProseMirror" contenteditable="true"><p id="inner">x</p></div><textarea id="t"></textarea>',
		);
		const found = findEditor(adapter(), document, byId("inner"));
		expect(found?.element.id).toBe("pm");
		expect(found?.kind).toBe("prosemirror");
	});

	it("ignores hidden, aria-hidden, inert, disabled, read-only and password fields", () => {
		mount(`
			<div style="display:none"><textarea id="hidden-parent"></textarea></div>
			<textarea id="hidden-attr" hidden></textarea>
			<div aria-hidden="true"><div id="aria" contenteditable="true"></div></div>
			<div inert><textarea id="inert"></textarea></div>
			<textarea id="invisible" style="visibility:hidden"></textarea>
			<textarea id="disabled" disabled></textarea>
			<textarea id="readonly" readonly></textarea>
			<textarea id="aria-disabled" aria-disabled="true"></textarea>
			<input id="pw" type="password" />
			<textarea id="ok"></textarea>
		`);
		byId("pw").focus();
		expect(findEditor(adapter(), document)?.element.id).toBe("ok");
		mount('<input type="password" /><div style="display:none"><textarea></textarea></div>');
		expect(findEditor(adapter(), document)).toBeNull();
	});

	it("prefers adapter matches, resolves wrappers and picks the last candidate in a composer", () => {
		mount(`
			<textarea id="search"></textarea>
			<div class="wrap" id="w1"><div id="e1" contenteditable="true"></div></div>
			<form><div class="wrap"><div id="e2" contenteditable="true"></div></div></form>
			<div class="wrap" id="w3"><div id="e3" contenteditable="true"></div></div>
		`);
		const site = adapter({ editorSelectors: [".nope[", ".wrap"] });
		expect(findEditor(site, document)?.element.id).toBe("e2");
		mount(
			'<textarea id="x"></textarea><div class="wrap"><div id="only" contenteditable></div></div>',
		);
		expect(findEditor(site, document)?.element.id).toBe("only");
	});

	it("honours an injected visibility check", () => {
		mount('<textarea id="a"></textarea><textarea id="b"></textarea>');
		const found = findEditor(adapter(), document, null, {
			isVisible: (element) => element.id === "b",
		});
		expect(found?.element.id).toBe("b");
	});
});

describe("findEditor in open shadow roots", () => {
	it("finds a shadow-DOM editor when the light DOM has none and follows focus into it", () => {
		mount('<x-chat id="host"></x-chat>');
		const root = byId("host").attachShadow({ mode: "open" });
		root.innerHTML = '<textarea id="a"></textarea><textarea id="b"></textarea>';
		(root.getElementById("b") as HTMLTextAreaElement).focus();
		expect(findEditor(adapter(), document)?.element.id).toBe("b");
	});
});

describe("findEditorNear", () => {
	it("resolves the composer of a button from its position, not from focus", () => {
		mount(`
			<input type="search" id="q">
			<form><textarea id="composer"></textarea><button id="send">Send</button></form>`);
		byId("q").focus();
		const match = findEditorNear(adapter(), byId("send"));
		expect(match?.editor?.element.id).toBe("composer");
		expect(match?.container).toBe(document.querySelector("form"));
	});

	it("prefers the editor holding text, and the nearest one when none does", () => {
		mount(`
			<div id="box"><div><textarea id="far"></textarea></div><textarea id="near"></textarea><button id="b">x</button></div>`);
		expect(findEditorNear(adapter(), byId("b"))?.editor?.element.id).toBe("near");
		byId<HTMLTextAreaElement>("far").value = "typed";
		expect(findEditorNear(adapter(), byId("b"))?.editor?.element.id).toBe("far");
	});

	it("reports ambiguity (editor null) when several editors in the container hold text", () => {
		mount(
			'<form id="f"><textarea id="a">one</textarea><textarea id="b">two</textarea><button id="s">s</button></form>',
		);
		const match = findEditorNear(adapter(), byId("s"));
		expect(match?.editor).toBeNull();
		expect(match?.container).toBe(byId("f"));
	});

	it("returns the editor an anchor is inside, also inside an open shadow root", () => {
		mount('<x-chat id="host"></x-chat>');
		const root = byId("host").attachShadow({ mode: "open" });
		root.innerHTML =
			'<div id="ce" contenteditable="true"><p id="p">hi</p></div><button id="go">Go</button>';
		const inner = root.getElementById("p") as HTMLElement;
		expect(findEditorNear(adapter(), inner)?.editor?.element.id).toBe("ce");
		const viaButton = findEditorNear(adapter(), root.getElementById("go") as HTMLElement);
		expect(viaButton?.editor?.element.id).toBe("ce");
		expect(viaButton?.container).toBe(root);
	});

	it("crosses from a light-DOM button into a shadow-DOM editor and returns null without editors", () => {
		mount('<div id="wrap"><x-editor id="host"></x-editor><button id="go">Go</button></div>');
		const root = byId("host").attachShadow({ mode: "open" });
		root.innerHTML = '<textarea id="t"></textarea>';
		expect(findEditorNear(adapter(), byId("go"))?.editor?.element.id).toBe("t");
		mount('<button id="lonely">Send</button>');
		expect(findEditorNear(adapter(), byId("lonely"))).toBeNull();
	});

	it("does not treat a read-only or disabled field as the anchor's editor", () => {
		mount('<textarea id="ro" readonly></textarea><textarea id="dis" disabled></textarea>');
		expect(findEditorNear(adapter(), byId("ro"))).toBeNull();
		expect(findEditorNear(adapter(), byId("dis"))).toBeNull();
	});
});

describe("visibility", () => {
	it("falls back to style checks when the document has no layout (jsdom)", () => {
		mount(
			'<textarea id="a"></textarea><div style="display:none"><textarea id="b"></textarea></div>',
		);
		expect(hasLayout(document)).toBe(false);
		expect(isVisible(byId("a"))).toBe(true);
		expect(isVisible(byId("b"))).toBe(false);
	});

	it("uses client rects when layout is available", () => {
		mount('<textarea id="a"></textarea><textarea id="b"></textarea>');
		vi.spyOn(document.documentElement, "getClientRects").mockReturnValue([
			{},
		] as unknown as DOMRectList);
		vi.spyOn(byId("a"), "getClientRects").mockReturnValue([{}] as unknown as DOMRectList);
		expect(hasLayout(document)).toBe(true);
		expect(isVisible(byId("a"))).toBe(true);
		expect(isVisible(byId("b"))).toBe(false);
	});
});

describe("findSendButton", () => {
	const layout = `
		<form id="other"><button id="far" class="send" type="submit">far</button></form>
		<form id="composer">
			<div><div><textarea id="t"></textarea></div></div>
			<button id="disabled" class="send" disabled>x</button>
			<button id="hidden" class="send" style="display:none">x</button>
			<div><div><div><button id="deep" class="send"><svg class="icon"></svg></button></div></div></div>
			<button id="near" class="send"><span class="icon"></span></button>
		</form>`;

	it("picks the nearest enabled visible button in the editor's composer", () => {
		mount(layout);
		const editor = editorAccess(byId("t"));
		expect(findSendButton(adapter({ sendButtonSelectors: [".send"] }), document, editor)?.id).toBe(
			"near",
		);
		// Selector matching an icon inside the button resolves to the button.
		expect(findSendButton(adapter({ sendButtonSelectors: [".icon"] }), document, editor)?.id).toBe(
			"near",
		);
	});

	it("uses generic selectors when the adapter matches nothing and handles no editor", () => {
		mount(layout);
		const site = adapter({ sendButtonSelectors: ["#missing"] });
		expect(findSendButton(site, document, null)?.id).toBe("far");
		mount('<textarea id="t"></textarea><button id="g" aria-label="Send message">go</button>');
		expect(findSendButton(site, document, editorAccess(byId("t")))?.id).toBe("g");
		mount('<textarea id="t"></textarea><button disabled aria-label="Send">go</button>');
		expect(findSendButton(site, document, editorAccess(byId("t")))).toBeNull();
	});
});

describe("insertAtSelection", () => {
	it("replaces the textarea selection and dispatches an input event", () => {
		mount('<textarea id="t">mail me at a@b.co please</textarea>');
		const textarea = byId<HTMLTextAreaElement>("t");
		textarea.setSelectionRange(11, 17);
		const inputs: string[] = [];
		textarea.addEventListener("input", (event) => inputs.push((event as InputEvent).inputType));
		insertAtSelection(editorAccess(textarea), "[EMAIL_1]");
		expect(textarea.value).toBe("mail me at [EMAIL_1] please");
		expect(textarea.selectionStart).toBe(20);
		expect(inputs).toEqual(["insertFromPaste"]);
	});

	it("inserts at the contenteditable caret with <br> line breaks when execCommand is missing", () => {
		mount('<div id="e" contenteditable="true"><p id="p">before after</p></div>');
		const text = byId("p").firstChild as Text;
		placeCaret(text, 7);
		const inputs: string[] = [];
		byId("e").addEventListener("input", (event) => inputs.push((event as InputEvent).inputType));
		const editor = editorAccess(byId("e"));
		insertAtSelection(editor, "[A]\n[B] ");
		expect(editor.read()).toBe("before [A]\n[B] after");
		expect(inputs).toEqual(["insertFromPaste"]);
	});

	it("uses execCommand insertText when available", () => {
		mount('<div id="e" class="ProseMirror" contenteditable="true"><p id="p">abc</p></div>');
		placeCaret(byId("p").firstChild as Text, 1, 2);
		const exec = stubExecCommand(nativeExecCommand);
		const editor = editorAccess(byId("e"));
		insertAtSelection(editor, "[X]");
		expect(exec).toHaveBeenCalledWith("insertText", false, "[X]");
		expect(editor.read()).toBe("a[X]c");
	});

	it("places the caret at the end when the selection is outside the editor", () => {
		mount('<p id="outside">x</p><div id="e" contenteditable="true">abc</div>');
		placeCaret(byId("outside").firstChild as Text, 0);
		const editor = editorAccess(byId("e"));
		insertAtSelection(editor, "!");
		expect(editor.read()).toBe("abc!");
	});
});
