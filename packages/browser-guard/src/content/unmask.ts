/**
 * Local response unmasking.
 *
 * Watches assistant responses and the user's own sent messages for vault
 * placeholders such as `[EMAIL_1]` and shows the original value in their place.
 *
 * Design constraints (see packages/privacy/extension for the previous design):
 * - Only TEXT NODES are touched; markup is never parsed or assigned (no innerHTML).
 * - The original value is rendered inside a CLOSED shadow root on a
 *   `<span class="aidr-restored">` whose light DOM still holds the placeholder. The
 *   light DOM is slotted into a visually hidden, aria-hidden wrapper: without a slot
 *   Chromium's innerText skips the unrendered light text (the page would read ""),
 *   with it the page's own scripts (analytics, session replay, the chat app's copy and
 *   edit actions) keep reading the placeholder through textContent/innerText, while
 *   the user (and assistive technology) perceives only the restored value.
 * - Framework-owned text nodes are never removed. The node keeps the text before the
 *   first placeholder and our nodes are inserted after it; when the framework later
 *   rewrites that node (streaming), our nodes are dropped and the node is re-processed.
 * - Nothing inside the prompt editor or any editable region is ever unmasked.
 */
import { PLACEHOLDER_PREFIX, type PlaceholderVault, type SiteAdapter } from "../types.js";

export interface UnmaskerDeps {
	readonly document: Document;
	readonly window: Window;
	readonly adapter: SiteAdapter;
	readonly vault: PlaceholderVault;
	/** The current prompt editor element (never unmasked), or null. */
	editorElement(): Element | null;
	/** Tooltip for restored values. */
	title(): string;
	/** Batching scheduler; defaults to queueMicrotask. */
	schedule?(callback: () => void): void;
}

export interface Unmasker {
	start(): void;
	stop(): void;
	/** true renders originals; false swaps every restored value back to its placeholder. */
	setVisible(visible: boolean): void;
	readonly visible: boolean;
	/** Processes queued mutations synchronously (tests, and before a toggle). */
	flush(): void;
	/** Number of text nodes currently carrying restored values. */
	readonly restoredCount: number;
}

interface RestoredSpan {
	readonly placeholder: string;
	readonly original: string;
	readonly shown: Text;
}

interface Entry {
	/** Text this module left in the framework-owned node. */
	readonly head: string;
	/** Full text the node held before processing (restored on stop). */
	readonly source: string;
	readonly extras: readonly Node[];
}

const SKIP_SELECTOR =
	'script,style,noscript,textarea,input,select,[contenteditable]:not([contenteditable="false"]),.aidr-restored,[data-aidr-guard]';

const restoredSpans = new WeakMap<Element, RestoredSpan>();

let placeholderSource: string | undefined;

/** Global regex matching every vault placeholder shape, e.g. `[EMAIL_1]`, `[TAX_ID_12]`. */
export function placeholderRegex(): RegExp {
	if (placeholderSource === undefined) {
		const prefixes = [...new Set(Object.values(PLACEHOLDER_PREFIX))].sort(
			(a, b) => b.length - a.length,
		);
		placeholderSource = `\\[(?:${prefixes.join("|")})_\\d{1,6}\\]`;
	}
	return new RegExp(placeholderSource, "g");
}

/** What the user currently sees in a restored span (original or placeholder). */
export function readRestored(span: Element): string | undefined {
	return restoredSpans.get(span)?.shown.data;
}

/** Text as rendered to the user: restored spans contribute their shadow content. */
export function visibleText(node: Node): string {
	if (node.nodeType === 3) return (node as Text).data;
	if (node.nodeType === 1 && restoredSpans.has(node as Element)) {
		return readRestored(node as Element) ?? "";
	}
	let out = "";
	for (const child of node.childNodes) out += visibleText(child);
	return out;
}

const SPAN_STYLE =
	":host{border-bottom:1px dotted #3862E8;background:rgba(56,98,232,.10);border-radius:3px;padding:0 1px}" +
	".ph{position:absolute;width:1px;height:1px;margin:-1px;padding:0;border:0;overflow:hidden;clip-path:inset(50%);white-space:nowrap}";

export function createUnmasker(deps: UnmaskerDeps): Unmasker {
	const { document: doc, adapter, vault } = deps;
	const scope = [...adapter.responseSelectors, ...adapter.userMessageSelectors].join(",");
	const schedule = deps.schedule ?? ((cb: () => void) => queueMicrotask(cb));
	const entries = new Map<Text, Entry>();
	const ours = new WeakSet<Node>();
	const queue = new Set<Node>();
	let visible = false;
	let scheduled = false;
	let observer: MutationObserver | null = null;
	let editor: Element | null = null;

	const eligible = (text: Text): boolean => {
		if (ours.has(text) || !scope) return false;
		const parent = text.parentElement;
		if (!parent?.closest(scope)) return false;
		if (parent.closest(SKIP_SELECTOR)) return false;
		return !(editor && (editor === parent || editor.contains(parent)));
	};

	const makeSpan = (placeholder: string, original: string): HTMLSpanElement => {
		const span = doc.createElement("span");
		span.className = "aidr-restored";
		span.title = deps.title();
		span.dataset.aidrPlaceholder = placeholder;
		const light = doc.createTextNode(placeholder);
		span.append(light);
		const shadow = span.attachShadow({ mode: "closed" });
		const style = doc.createElement("style");
		style.textContent = SPAN_STYLE;
		// Keeps the light-DOM placeholder in the rendered tree (so page innerText reads
		// it) without showing it or exposing it to assistive technology.
		const hidden = doc.createElement("span");
		hidden.className = "ph";
		hidden.setAttribute("aria-hidden", "true");
		hidden.append(doc.createElement("slot"));
		const shown = doc.createTextNode(visible ? original : placeholder);
		shadow.append(style, hidden, shown);
		restoredSpans.set(span, { placeholder, original, shown });
		ours.add(span);
		ours.add(light);
		return span;
	};

	const processText = (text: Text): void => {
		if (entries.has(text) || !eligible(text)) return;
		const data = text.data;
		if (!data.includes("[")) return;
		const pieces: { before: string; placeholder: string; original: string }[] = [];
		let last = 0;
		for (const match of data.matchAll(placeholderRegex())) {
			const placeholder = match[0];
			const original = vault.unmask(placeholder);
			if (original === placeholder) continue; // unknown or never-restore type
			pieces.push({ before: data.slice(last, match.index), placeholder, original });
			last = match.index + placeholder.length;
		}
		const first = pieces[0];
		if (!first) return;
		const extras: Node[] = [];
		pieces.forEach((piece, index) => {
			if (index > 0 && piece.before) {
				const between = doc.createTextNode(piece.before);
				ours.add(between);
				extras.push(between);
			}
			extras.push(makeSpan(piece.placeholder, piece.original));
		});
		const tail = data.slice(last);
		if (tail) {
			const rest = doc.createTextNode(tail);
			ours.add(rest);
			extras.push(rest);
		}
		text.data = first.before;
		text.after(...extras);
		entries.set(text, { head: first.before, source: data, extras });
	};

	const revert = (text: Text, entry: Entry, restoreSource: boolean): void => {
		for (const node of entry.extras) (node as ChildNode).remove();
		entries.delete(text);
		if (restoreSource && text.data === entry.head) text.data = entry.source;
	};

	const collectTexts = (root: Node, out: Text[]): void => {
		if (root.nodeType === 3) {
			out.push(root as Text);
			return;
		}
		const walker = doc.createTreeWalker(root, 4 /* NodeFilter.SHOW_TEXT */);
		for (let n = walker.nextNode(); n; n = walker.nextNode()) out.push(n as Text);
	};

	const processNode = (node: Node, out: Text[]): void => {
		if (!node.isConnected || ours.has(node)) return;
		if (node.nodeType === 3) {
			out.push(node as Text);
			return;
		}
		if (node.nodeType !== 1 || !scope) return;
		const el = node as Element;
		if (el.closest(scope)) {
			collectTexts(el, out);
			return;
		}
		for (const container of el.querySelectorAll(scope)) collectTexts(container, out);
	};

	const flush = (): void => {
		scheduled = false;
		for (const [text, entry] of entries) {
			if (!text.isConnected) revert(text, entry, false);
		}
		if (!visible) {
			queue.clear();
			return;
		}
		editor = deps.editorElement();
		const texts: Text[] = [];
		for (const node of queue) processNode(node, texts);
		queue.clear();
		for (const text of texts) processText(text);
	};

	const enqueue = (node: Node): void => {
		queue.add(node);
		if (!scheduled) {
			scheduled = true;
			schedule(flush);
		}
	};

	const onMutations = (records: MutationRecord[]): void => {
		for (const record of records) {
			if (record.type === "characterData") {
				const text = record.target as Text;
				if (ours.has(text)) continue;
				const entry = entries.get(text);
				if (entry) {
					if (text.data === entry.head) continue; // our own write
					revert(text, entry, false); // the page rewrote the node (streaming)
				}
				enqueue(text);
				continue;
			}
			for (const removed of record.removedNodes) {
				const entry = removed.nodeType === 3 ? entries.get(removed as Text) : undefined;
				if (entry) revert(removed as Text, entry, false);
			}
			for (const added of record.addedNodes) {
				if (!ours.has(added)) enqueue(added);
			}
		}
	};

	const setShown = (show: boolean): void => {
		for (const entry of entries.values()) {
			for (const node of entry.extras) {
				const info = restoredSpans.get(node as Element);
				if (info) info.shown.data = show ? info.original : info.placeholder;
			}
		}
	};

	return {
		start() {
			if (observer) return;
			const MO = (deps.window as Window & typeof globalThis).MutationObserver;
			observer = new MO(onMutations);
			observer.observe(doc.documentElement ?? doc, {
				childList: true,
				subtree: true,
				characterData: true,
			});
			if (visible && doc.body) enqueue(doc.body);
		},
		stop() {
			observer?.disconnect();
			observer = null;
			queue.clear();
			for (const [text, entry] of [...entries]) revert(text, entry, true);
		},
		setVisible(next: boolean) {
			if (next === visible) return;
			visible = next;
			setShown(next);
			if (next && doc.body) enqueue(doc.body);
		},
		get visible() {
			return visible;
		},
		flush,
		get restoredCount() {
			return entries.size;
		},
	};
}
