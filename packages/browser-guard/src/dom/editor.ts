/**
 * Prompt-editor DOM access: locate the chat composer, read its plain text and
 * rewrite it so the page's framework (React, ProseMirror, Quill, Lexical...)
 * observes the change as if the user had typed it.
 *
 * Write strategy for rich editors, in order, each verified by reading back:
 *   1. `document.execCommand("insertText")` over a select-all range. Native
 *      editing keeps the framework's model and undo stack in sync.
 *   2. A synthetic `beforeinput` (insertReplacementText + DataTransfer) for
 *      editors that apply input through beforeinput handlers (Slate/Lexical).
 *   3. A synthetic `paste` carrying a text/plain DataTransfer (ProseMirror and
 *      Quill both implement their own paste handling).
 *   4. Direct DOM replacement, one <p> per line, plus an `input` event.
 * If the editor still does not hold the requested text, `write()` rejects with
 * `EDITOR_WRITE_MISMATCH` so the caller can fail closed instead of sending
 * content it did not verify.
 */

import type { EditorAccess, EditorKind, SiteAdapter } from "../types";
import { isDisabled, isVisible, type VisibilityCheck } from "./visibility";

export interface EditorLookupOptions {
	/** Override the visibility policy (defaults to `isVisible` from ./visibility). */
	readonly isVisible?: VisibilityCheck;
}

/** Fallback editor selectors used after the adapter's own selectors. */
export const GENERIC_EDITOR_SELECTORS: readonly string[] = [
	"textarea",
	'[contenteditable="true"]',
	'[contenteditable=""]',
	'[contenteditable="plaintext-only"]',
	'[role="textbox"]',
	'input[type="text"]',
	'input[type="search"]',
	"input:not([type])",
];

/** Fallback send-button selectors used when the adapter's selectors match nothing usable. */
export const GENERIC_SEND_SELECTORS: readonly string[] = [
	'button[type="submit"]',
	'button[aria-label*="send" i]',
	'button[data-testid*="send" i]',
	'[role="button"][aria-label*="send" i]',
	'button[aria-label*="gönder" i]',
];

const COMPOSER_SELECTOR =
	'form, [data-composer], [class*="composer" i], [data-testid*="composer" i], [id*="composer" i]';
const EDITABLE_DESCENDANT = 'textarea, [contenteditable]:not([contenteditable="false"])';
const TEXT_INPUT_TYPES = new Set(["", "text", "search"]);
const EDITABLE_VALUES = new Set(["", "true", "plaintext-only"]);
const BLOCK_TAGS = new Set([
	"ADDRESS",
	"ARTICLE",
	"ASIDE",
	"BLOCKQUOTE",
	"DD",
	"DETAILS",
	"DIV",
	"DL",
	"DT",
	"FIELDSET",
	"FIGCAPTION",
	"FIGURE",
	"FOOTER",
	"FORM",
	"H1",
	"H2",
	"H3",
	"H4",
	"H5",
	"H6",
	"HEADER",
	"HR",
	"LI",
	"MAIN",
	"NAV",
	"OL",
	"P",
	"PRE",
	"SECTION",
	"SUMMARY",
	"TABLE",
	"TBODY",
	"TFOOT",
	"THEAD",
	"TR",
	"UL",
]);
const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "TEMPLATE", "NOSCRIPT"]);
const TRAILING_ZERO_WIDTH = /[​‌‍⁠﻿]+$/u;
const LAYOUT_WHITESPACE = /^[ \t\n\r]*$/;

/* ------------------------------------------------------------------------ */
/* Synthetic event bookkeeping                                               */
/* ------------------------------------------------------------------------ */

const syntheticEvents = new WeakSet<Event>();

/**
 * True for events this module dispatched while writing (input, beforeinput,
 * paste, change). Guard listeners (e.g. paste masking) must ignore these so a
 * rewrite does not re-trigger interception.
 */
export function isSyntheticEditorEvent(event: Event): boolean {
	return syntheticEvents.has(event);
}

function dispatch(target: EventTarget, event: Event): Event {
	syntheticEvents.add(event);
	target.dispatchEvent(event);
	return event;
}

function windowOf(element: Element): Window & typeof globalThis {
	return (element.ownerDocument.defaultView ?? globalThis) as Window & typeof globalThis;
}

function inputEvent(
	element: Element,
	type: "input" | "beforeinput",
	inputType: string,
	data: string | null,
	dataTransfer: DataTransfer | null = null,
): Event {
	const view = windowOf(element);
	const init = {
		bubbles: true,
		cancelable: type === "beforeinput",
		composed: true,
		inputType,
		data,
		dataTransfer,
	};
	let event: Event;
	try {
		event = new view.InputEvent(type, init);
	} catch {
		event = new view.Event(type, { bubbles: true, cancelable: init.cancelable, composed: true });
	}
	// Environments whose InputEvent ignores `dataTransfer` in the init dict.
	if (dataTransfer && (event as InputEvent).dataTransfer == null) {
		Object.defineProperty(event, "dataTransfer", { value: dataTransfer });
	}
	return event;
}

/** A text/plain DataTransfer; a minimal read-only stand-in where the constructor is missing. */
function textDataTransfer(element: Element, text: string): DataTransfer {
	const view = windowOf(element);
	if (typeof view.DataTransfer === "function") {
		try {
			const transfer = new view.DataTransfer();
			transfer.setData("text/plain", text);
			return transfer;
		} catch {
			// Fall through to the stand-in.
		}
	}
	const data = new Map<string, string>([["text/plain", text]]);
	const standIn = {
		dropEffect: "none",
		effectAllowed: "all",
		files: [] as unknown as FileList,
		items: [] as unknown as DataTransferItemList,
		types: ["text/plain"],
		getData: (format: string) => data.get(format.toLowerCase()) ?? "",
		setData: (format: string, value: string) => {
			data.set(format.toLowerCase(), value);
		},
		clearData: () => data.clear(),
		setDragImage: () => undefined,
	};
	return standIn as unknown as DataTransfer;
}

function pasteEvent(element: Element, transfer: DataTransfer): Event {
	const view = windowOf(element);
	const init = { bubbles: true, cancelable: true, composed: true, clipboardData: transfer };
	if (typeof view.ClipboardEvent === "function") {
		try {
			const event = new view.ClipboardEvent("paste", init);
			if (event.clipboardData) return event;
		} catch {
			// A stand-in DataTransfer is rejected by real ClipboardEvent constructors.
		}
	}
	const event = new view.Event("paste", init);
	Object.defineProperty(event, "clipboardData", { value: transfer });
	return event;
}

const microtask = (): Promise<void> => Promise.resolve();

/* ------------------------------------------------------------------------ */
/* Element classification                                                    */
/* ------------------------------------------------------------------------ */

function isTextControl(element: Element): element is HTMLTextAreaElement | HTMLInputElement {
	return element.tagName === "TEXTAREA" || element.tagName === "INPUT";
}

function isTextInput(element: Element): element is HTMLInputElement {
	return (
		element.tagName === "INPUT" &&
		TEXT_INPUT_TYPES.has((element.getAttribute("type") ?? "").trim().toLowerCase())
	);
}

/** The outermost contenteditable host containing `element`, or null when not editable. */
function editingHost(element: Element): HTMLElement | null {
	let host: HTMLElement | null = null;
	for (let node: Element | null = element; node; node = node.parentElement) {
		const value = node.getAttribute("contenteditable");
		if (value === null) continue;
		const normalized = value.trim().toLowerCase();
		if (normalized === "false") break;
		if (EDITABLE_VALUES.has(normalized)) host = node as HTMLElement;
	}
	return host;
}

/** Map a selector match to the editable element it denotes (itself, its host or a descendant). */
function resolveEditable(element: Element): HTMLElement | null {
	if (element.tagName === "TEXTAREA") return element as HTMLTextAreaElement;
	if (element.tagName === "INPUT") return isTextInput(element) ? element : null;
	const host = editingHost(element);
	if (host) return host;
	const descendant = element.querySelector(EDITABLE_DESCENDANT);
	return descendant ? resolveEditable(descendant) : null;
}

function isUsableEditor(element: HTMLElement, visible: VisibilityCheck): boolean {
	if (isTextControl(element)) {
		if (element.tagName === "INPUT" && !isTextInput(element)) return false;
		if (element.readOnly) return false;
	}
	return !isDisabled(element) && visible(element);
}

function kindOf(element: HTMLElement): EditorKind {
	if (isTextControl(element)) return "textarea";
	if (element.classList.contains("ProseMirror")) return "prosemirror";
	if (element.classList.contains("ql-editor")) return "quill";
	return "contenteditable";
}

/* ------------------------------------------------------------------------ */
/* Plain-text serialisation of rich editors                                  */
/* ------------------------------------------------------------------------ */

interface InlineRun {
	text: string;
	endsWithBreak: boolean;
	hasBreak: boolean;
}

function isBlock(node: Node, cache: Map<Node, boolean>): boolean {
	if (node.nodeType !== 1) return false;
	const cached = cache.get(node);
	if (cached !== undefined) return cached;
	const element = node as Element;
	let block = BLOCK_TAGS.has(element.tagName);
	if (!block && !SKIP_TAGS.has(element.tagName)) {
		// An inline wrapper around block content (e.g. <span><p>..</p></span>) acts as a block.
		for (const child of element.childNodes) {
			if (isBlock(child, cache)) {
				block = true;
				break;
			}
		}
	}
	cache.set(node, block);
	return block;
}

function appendInline(node: Node, run: InlineRun, cache: Map<Node, boolean>): void {
	if (node.nodeType === 3 || node.nodeType === 4) {
		const value = node.nodeValue ?? "";
		if (value.length > 0) {
			run.text += value;
			run.endsWithBreak = false;
		}
		return;
	}
	if (node.nodeType !== 1) return;
	const element = node as Element;
	if (SKIP_TAGS.has(element.tagName)) return;
	if (element.tagName === "BR") {
		run.text += "\n";
		run.endsWithBreak = true;
		run.hasBreak = true;
		return;
	}
	for (const child of element.childNodes) appendInline(child, run, cache);
}

/**
 * Serialise a block container: consecutive inline content forms one segment,
 * every block child forms its own; segments are joined with "\n". A trailing
 * <br> at the end of a segment is not rendered by browsers (it only gives an
 * empty block its height, cf. ProseMirror-trailingBreak / Quill `<p><br></p>`),
 * so exactly one trailing break per segment is dropped. Whitespace-only inline
 * runs between blocks are treated as source formatting and ignored.
 */
function serializeBlock(container: Node, cache: Map<Node, boolean>): string {
	const children = [...container.childNodes];
	const hasBlockChild = children.some((child) => isBlock(child, cache));
	const segments: string[] = [];
	let run: InlineRun | null = null;
	const flush = (): void => {
		if (!run) return;
		const current: InlineRun = run;
		run = null;
		if (hasBlockChild && !current.hasBreak && LAYOUT_WHITESPACE.test(current.text)) return;
		segments.push(current.endsWithBreak ? current.text.slice(0, -1) : current.text);
	};
	for (const child of children) {
		if (isBlock(child, cache)) {
			flush();
			segments.push(serializeBlock(child, cache));
			continue;
		}
		run ??= { text: "", endsWithBreak: false, hasBreak: false };
		appendInline(child, run, cache);
	}
	flush();
	return segments.join("\n");
}

function readRich(element: HTMLElement): string {
	return normalizeRich(serializeBlock(element, new Map()));
}

function normalizeRich(text: string): string {
	return text.replace(/\r\n?/g, "\n").replace(/ /g, " ").replace(TRAILING_ZERO_WIDTH, "");
}

function normalizeControl(element: HTMLTextAreaElement | HTMLInputElement, text: string): string {
	const unified = text.replace(/\r\n?/g, "\n");
	// Single-line inputs strip line breaks from their value (HTML value sanitisation).
	return element.tagName === "INPUT" ? unified.replace(/\n/g, "") : unified;
}

/* ------------------------------------------------------------------------ */
/* Writing                                                                   */
/* ------------------------------------------------------------------------ */

function setNativeValue(element: HTMLTextAreaElement | HTMLInputElement, value: string): void {
	const view = windowOf(element);
	const proto =
		element.tagName === "TEXTAREA"
			? view.HTMLTextAreaElement.prototype
			: view.HTMLInputElement.prototype;
	// Bypass instance-level value trackers (React) so the framework sees a real change.
	const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
	if (!setter) throw new Error("EDITOR_UNSUPPORTED");
	setter.call(element, value);
}

async function writeTextControl(
	element: HTMLTextAreaElement | HTMLInputElement,
	text: string,
): Promise<void> {
	const target = normalizeControl(element, text);
	setNativeValue(element, target);
	try {
		element.setSelectionRange(target.length, target.length);
	} catch {
		// Some input types do not support selection; the value is what matters.
	}
	dispatch(element, inputEvent(element, "input", "insertReplacementText", target));
	dispatch(element, new (windowOf(element).Event)("change", { bubbles: true }));
	await microtask();
	if (element.value !== target) throw new Error("EDITOR_WRITE_MISMATCH");
}

function focusEditor(element: HTMLElement): void {
	const active = element.ownerDocument.activeElement;
	if (active && (active === element || element.contains(active))) return;
	try {
		element.focus({ preventScroll: true });
	} catch {
		element.focus();
	}
}

function selectAllContents(element: HTMLElement): Selection | null {
	const doc = element.ownerDocument;
	const selection = doc.getSelection();
	if (!selection) return null;
	const range = doc.createRange();
	range.selectNodeContents(element);
	selection.removeAllRanges();
	selection.addRange(range);
	return selection;
}

function selectionInside(element: HTMLElement): Selection | null {
	const selection = element.ownerDocument.getSelection();
	if (!selection || selection.rangeCount === 0) return null;
	const range = selection.getRangeAt(0);
	return element.contains(range.startContainer) && element.contains(range.endContainer)
		? selection
		: null;
}

function execInsertText(element: HTMLElement, text: string): boolean {
	const doc = element.ownerDocument;
	if (typeof doc.execCommand !== "function") return false;
	try {
		return text === ""
			? doc.execCommand("delete", false)
			: doc.execCommand("insertText", false, text);
	} catch {
		return false;
	}
}

function dispatchBeforeInput(element: HTMLElement, text: string): boolean {
	if (text === "") return false;
	const transfer = textDataTransfer(element, text);
	const event = inputEvent(element, "beforeinput", "insertReplacementText", text, transfer);
	return dispatch(element, event).defaultPrevented;
}

function dispatchPaste(element: HTMLElement, text: string): boolean {
	if (text === "") return false;
	return dispatch(element, pasteEvent(element, textDataTransfer(element, text))).defaultPrevented;
}

function placeCaretAtEnd(element: HTMLElement): void {
	const doc = element.ownerDocument;
	const selection = doc.getSelection();
	if (!selection) return;
	const range = doc.createRange();
	range.selectNodeContents(element);
	range.collapse(false);
	selection.removeAllRanges();
	selection.addRange(range);
}

function replaceDom(element: HTMLElement, text: string): void {
	const doc = element.ownerDocument;
	const paragraphs = text.split("\n").map((line) => {
		const paragraph = doc.createElement("p");
		if (line === "") paragraph.appendChild(doc.createElement("br"));
		else paragraph.textContent = line;
		return paragraph;
	});
	element.replaceChildren(...paragraphs);
	placeCaretAtEnd(element);
	dispatch(element, inputEvent(element, "input", "insertReplacementText", text));
}

async function writeRich(element: HTMLElement, text: string): Promise<void> {
	const target = normalizeRich(text);
	focusEditor(element);
	const strategies: ReadonlyArray<(el: HTMLElement, value: string) => boolean> = [
		execInsertText,
		dispatchBeforeInput,
		dispatchPaste,
	];
	for (const strategy of strategies) {
		selectAllContents(element);
		if (!strategy(element, target)) continue;
		await microtask();
		if (readRich(element) === target) return;
	}
	replaceDom(element, target);
	await microtask();
	if (readRich(element) !== target) throw new Error("EDITOR_WRITE_MISMATCH");
}

class DomEditorAccess implements EditorAccess {
	readonly element: HTMLElement;
	readonly kind: EditorKind;

	constructor(element: HTMLElement) {
		this.element = element;
		this.kind = kindOf(element);
	}

	read(): string {
		const element = this.element;
		if (isTextControl(element)) return element.value;
		return readRich(element);
	}

	async write(text: string): Promise<void> {
		const element = this.element;
		if (!element.isConnected) throw new Error("EDITOR_DETACHED");
		if (isTextControl(element)) return writeTextControl(element, text);
		return writeRich(element, text);
	}
}

/**
 * Wrap an element as an editor. Accepts the editor itself, any node inside a
 * contenteditable host (resolved to the outermost host), or a wrapper that
 * contains one editable descendant.
 */
export function editorAccess(element: HTMLElement): EditorAccess {
	return new DomEditorAccess(resolveEditable(element) ?? element);
}

/**
 * Insert `text` at the current caret / over the current selection (paste
 * masking). Textareas use `setRangeText`; rich editors try execCommand, then a
 * synthetic paste, then a direct DOM insertion. Dispatches `input` where the
 * browser would not do so itself.
 */
export function insertAtSelection(editor: EditorAccess, text: string): void {
	const element = editor.element;
	if (isTextControl(element)) {
		const value = normalizeControl(element, text);
		const start = element.selectionStart ?? element.value.length;
		const end = element.selectionEnd ?? start;
		element.setRangeText(value, start, end, "end");
		dispatch(element, inputEvent(element, "input", "insertFromPaste", value));
		return;
	}
	const value = text.replace(/\r\n?/g, "\n");
	// Focusing can move the caret (to the start in some engines); keep the user's selection.
	const saved = selectionInside(element)?.getRangeAt(0).cloneRange() ?? null;
	focusEditor(element);
	const current = element.ownerDocument.getSelection();
	if (saved && current) {
		current.removeAllRanges();
		current.addRange(saved);
	} else {
		placeCaretAtEnd(element);
	}
	if (value === "") return;
	if (execInsertText(element, value)) return;
	if (dispatchPaste(element, value)) return;
	const selection = selectionInside(element);
	if (!selection) throw new Error("EDITOR_NO_SELECTION");
	const doc = element.ownerDocument;
	const range = selection.getRangeAt(0);
	range.deleteContents();
	const fragment = doc.createDocumentFragment();
	value.split("\n").forEach((line, index) => {
		if (index > 0) fragment.appendChild(doc.createElement("br"));
		if (line !== "") fragment.appendChild(doc.createTextNode(line));
	});
	const last = fragment.lastChild;
	range.insertNode(fragment);
	if (last) {
		range.setStartAfter(last);
		range.collapse(true);
		selection.removeAllRanges();
		selection.addRange(range);
	}
	dispatch(element, inputEvent(element, "input", "insertFromPaste", value));
}

/* ------------------------------------------------------------------------ */
/* Discovery                                                                 */
/* ------------------------------------------------------------------------ */

function queryAll(root: ParentNode, selector: string): Element[] {
	try {
		return [...root.querySelectorAll(selector)];
	} catch {
		// Invalid selector in an adapter must not break discovery.
		return [];
	}
}

function collectEditors(
	root: Document,
	selectors: readonly string[],
	visible: VisibilityCheck,
	seen: Set<Element>,
): HTMLElement[] {
	const out: HTMLElement[] = [];
	for (const selector of selectors) {
		for (const match of queryAll(root, selector)) {
			const editable = resolveEditable(match);
			if (!editable || seen.has(editable)) continue;
			seen.add(editable);
			if (isUsableEditor(editable, visible)) out.push(editable);
		}
	}
	return out;
}

function candidateContaining(
	node: Element | null | undefined,
	candidates: readonly HTMLElement[],
): HTMLElement | null {
	if (!node || !node.isConnected) return null;
	return candidates.find((candidate) => candidate === node || candidate.contains(node)) ?? null;
}

function inComposer(element: Element): boolean {
	try {
		return element.closest(COMPOSER_SELECTOR) !== null;
	} catch {
		return element.closest("form") !== null;
	}
}

/**
 * Locate the prompt editor.
 *
 * Candidates: adapter selectors first, then generic fallbacks; each must be
 * visible (see ./visibility), enabled, writable and not a password field.
 * Preference: the focused element (or `lastFocused`) when it is, or is inside,
 * a candidate; otherwise among adapter matches (or generic matches when the
 * adapter matched nothing): the single candidate; else the last candidate
 * inside a form/composer; else the first candidate in selector order (adapter
 * selectors are ordered most specific first). Returns null when nothing usable
 * exists.
 */
export function findEditor(
	adapter: SiteAdapter,
	root: Document,
	lastFocused?: Element | null,
	options: EditorLookupOptions = {},
): EditorAccess | null {
	const visible = options.isVisible ?? isVisible;
	const seen = new Set<Element>();
	const specific = collectEditors(root, adapter.editorSelectors, visible, seen);
	const generic = collectEditors(root, GENERIC_EDITOR_SELECTORS, visible, seen);
	const all = [...specific, ...generic];
	if (all.length === 0) return null;

	const focused =
		candidateContaining(root.activeElement, all) ?? candidateContaining(lastFocused, all);
	if (focused) return editorAccess(focused);

	const pool = specific.length > 0 ? specific : generic;
	if (pool.length === 1) return editorAccess(pool[0] as HTMLElement);
	const composed = pool.filter(inComposer);
	const chosen = composed.length > 0 ? composed[composed.length - 1] : pool[0];
	return chosen ? editorAccess(chosen) : null;
}

function asButton(element: Element): HTMLElement | null {
	const button = element.closest('button, [role="button"], input[type="submit"]') ?? element;
	return button.nodeType === 1 ? (button as HTMLElement) : null;
}

function collectButtons(
	root: Document,
	selectors: readonly string[],
	visible: VisibilityCheck,
): HTMLElement[] {
	const out: HTMLElement[] = [];
	const seen = new Set<Element>();
	for (const selector of selectors) {
		for (const match of queryAll(root, selector)) {
			const button = asButton(match);
			if (!button || seen.has(button)) continue;
			seen.add(button);
			if (!isDisabled(button) && visible(button)) out.push(button);
		}
	}
	return out;
}

/** Number of parent/child edges between two nodes of the same tree (Infinity if disjoint). */
function treeDistance(a: Node, b: Node): number {
	const depthFromA = new Map<Node, number>();
	let depth = 0;
	for (let node: Node | null = a; node; node = node.parentNode) depthFromA.set(node, depth++);
	depth = 0;
	for (let node: Node | null = b; node; node = node.parentNode) {
		const up = depthFromA.get(node);
		if (up !== undefined) return up + depth;
		depth++;
	}
	return Number.POSITIVE_INFINITY;
}

/**
 * Find the enabled, visible send button for `editor`. Adapter selectors are
 * used first, generic send-button selectors only when they yield nothing.
 * With an editor, buttons in the editor's form/composer container win, then
 * the shortest DOM tree distance to the editor, then selector/document order.
 */
export function findSendButton(
	adapter: SiteAdapter,
	root: Document,
	editor: EditorAccess | null,
	options: EditorLookupOptions = {},
): HTMLElement | null {
	const visible = options.isVisible ?? isVisible;
	let buttons = collectButtons(root, adapter.sendButtonSelectors, visible);
	if (buttons.length === 0) buttons = collectButtons(root, GENERIC_SEND_SELECTORS, visible);
	if (buttons.length === 0) return null;
	if (!editor) return buttons[0] ?? null;

	const origin = editor.element;
	let container: Element | null = null;
	try {
		container = origin.closest(COMPOSER_SELECTOR);
	} catch {
		container = origin.closest("form");
	}
	let best: HTMLElement | null = null;
	let bestScore = Number.POSITIVE_INFINITY;
	for (const button of buttons) {
		const outside = container?.contains(button) ? 0 : 1;
		const score = outside * 1_000_000 + treeDistance(origin, button);
		if (score < bestScore) {
			best = button;
			bestScore = score;
		}
	}
	return best ?? buttons[0] ?? null;
}
