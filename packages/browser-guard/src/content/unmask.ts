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
 * - The restored value must not be OBSERVABLE by the page (it is the AI site: exactly
 *   the party the value was masked from). A closed shadow root alone is not enough:
 *     * inherited `font-family` lets page `@font-face` rules with one remote `src` per
 *       `unicode-range` character fetch a font for every character that is rendered;
 *     * the element's width reveals the value's length (and, per font, its glyphs);
 *     * `window.find()` (and find-in-page based APIs) search shadow-tree TEXT, so a
 *       page can confirm guesses character by character.
 *   So the value is never a text node: it is CSS generated content
 *   (`::before { content: attr(data-v) }`) of an element inside the closed root, which
 *   find/selection/innerText do not see but the user and the accessibility tree do.
 *   The host and that element reset every inherited property (`all: initial`, only
 *   `font-size`, `line-height` and `color` - which do not depend on the value - are
 *   inherited back), use generic font families only (`system-ui, sans-serif`: page
 *   `@font-face` rules can shadow a named family such as Arial, never a generic
 *   keyword), and render in a fixed-width box with an ellipsis, so the layout is the
 *   same for every value. The styles come from a constructed stylesheet adopted by the
 *   closed root (not subject to the page's CSP), with a `<style>` fallback. Proven in
 *   Chromium by the `restore-side-channels` E2E scenario.
 * - Restoration is limited to values the user actually sent from this tab (oracle
 *   mitigation): the guard reports every send (`noteSent`) with the vault placeholders
 *   that left the page, and a placeholder is restored only in content inserted into the
 *   document AFTER the send that carried it (the element holding the text, or one of its
 *   ancestors, was inserted after the send). Pre-existing containers, placeholders a page
 *   script invents, and placeholders issued for pastes/files that were never sent stay
 *   as placeholders. The sent set is persisted with the tab's vault (chrome.storage.session
 *   via the worker), so after a reload exactly the placeholders sent from this tab
 *   become restorable again (`rehydrateSent`); nothing else does.
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
	/**
	 * Records a send that just left the page carrying `placeholders` (this tab's vault
	 * placeholders). Only these become restorable, and only in content inserted after
	 * this call. Call it BEFORE the send is dispatched to the page.
	 */
	noteSent(placeholders: Iterable<string>): void;
	/**
	 * Placeholders sent from this tab in an EARLIER life of the page (persisted with the
	 * vault, see ./boot.ts). Every node of this page life appeared after those sends, so
	 * they are restorable in any response/user-message content, including content that
	 * was already rendered; placeholders never sent from this tab still are not.
	 */
	rehydrateSent(placeholders: Iterable<string>): void;
	/** Every placeholder sent from this tab so far (for persistence with the vault). */
	sentPlaceholders(): string[];
}

interface RestoredSpan {
	readonly placeholder: string;
	readonly original: string;
	/** Element inside the closed root whose generated content shows the value. */
	readonly shown: Element;
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
	return restoredSpans.get(span)?.shown.getAttribute(VALUE_ATTRIBUTE) ?? undefined;
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

/** Send epoch of placeholders rehydrated from a previous life of the page (see rehydrateSent). */
const PREVIOUS_PAGE_LIFE = -1;

/** Attribute (inside the closed root) whose value the generated content renders. */
const VALUE_ATTRIBUTE = "data-v";
/** Width of every restored value box; longer values end in an ellipsis. */
export const RESTORED_BOX_WIDTH_EM = 14;

/**
 * Closed-root styles. `!important` in the shadow tree beats the page's `!important`
 * rules on the host (the inner context wins for important declarations).
 */
export const SPAN_STYLE =
	":host{all:initial!important;display:inline!important;font-size:inherit!important;" +
	"line-height:inherit!important;color:inherit!important}" +
	".ph{all:initial!important;position:absolute!important;width:1px!important;height:1px!important;" +
	"margin:-1px!important;overflow:hidden!important;clip-path:inset(50%)!important;" +
	"white-space:nowrap!important}" +
	".v{all:initial!important;display:inline-block!important;box-sizing:border-box!important;" +
	`width:${RESTORED_BOX_WIDTH_EM}em!important;max-width:100%!important;` +
	"overflow:hidden!important;white-space:pre!important;text-overflow:ellipsis!important;" +
	"vertical-align:bottom!important;direction:ltr!important;unicode-bidi:isolate!important;" +
	"text-align:start!important;font-family:system-ui,sans-serif!important;" +
	"font-size:inherit!important;line-height:inherit!important;color:inherit!important;" +
	"border-bottom:1px dotted #3862E8!important;background:rgba(56,98,232,.10)!important;" +
	"border-radius:3px!important;padding:0 2px!important}" +
	`.v::before{content:attr(${VALUE_ATTRIBUTE})!important}`;

const sharedSheets = new WeakMap<Document, CSSStyleSheet | null>();

/** One constructed stylesheet per document, or null where they are unsupported. */
function sharedSheet(doc: Document): CSSStyleSheet | null {
	if (sharedSheets.has(doc)) return sharedSheets.get(doc) ?? null;
	let sheet: CSSStyleSheet | null = null;
	try {
		const Ctor = (doc.defaultView as (Window & typeof globalThis) | null)?.CSSStyleSheet;
		if (Ctor) {
			sheet = new Ctor();
			sheet.replaceSync(SPAN_STYLE);
		}
	} catch {
		sheet = null;
	}
	sharedSheets.set(doc, sheet);
	return sheet;
}

function applyStyles(doc: Document, root: ShadowRoot): void {
	const sheet = sharedSheet(doc);
	if (sheet && "adoptedStyleSheets" in root) {
		try {
			root.adoptedStyleSheets = [sheet];
			return;
		} catch {
			// e.g. a cross-compartment sheet in a Firefox content script: fall back.
		}
	}
	const style = doc.createElement("style");
	style.textContent = SPAN_STYLE;
	root.append(style);
}

export function createUnmasker(deps: UnmaskerDeps): Unmasker {
	const { document: doc, adapter, vault } = deps;
	const scope = [...adapter.responseSelectors, ...adapter.userMessageSelectors].join(",");
	const schedule = deps.schedule ?? ((cb: () => void) => queueMicrotask(cb));
	const entries = new Map<Text, Entry>();
	const ours = new WeakSet<Node>();
	const queue = new Set<Node>();
	/** Send counter; elements are stamped with its value when inserted. */
	let epoch = 0;
	/** Placeholder -> epoch of the first send that carried it. */
	const sentAt = new Map<string, number>();
	/** Element -> epoch at its (latest) insertion; absent = present before observation. */
	const insertedAt = new WeakMap<Node, number>();
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
		applyStyles(doc, shadow);
		// Keeps the light-DOM placeholder in the rendered tree (so page innerText reads
		// it) without showing it or exposing it to assistive technology.
		const hidden = doc.createElement("span");
		hidden.className = "ph";
		hidden.setAttribute("aria-hidden", "true");
		hidden.append(doc.createElement("slot"));
		// The value is generated content of this element (never a text node): see the
		// module comment for the side channels this closes.
		const shown = doc.createElement("span");
		shown.className = "v";
		shown.setAttribute(VALUE_ATTRIBUTE, visible ? original : placeholder);
		shadow.append(hidden, shown);
		restoredSpans.set(span, { placeholder, original, shown });
		ours.add(span);
		ours.add(light);
		return span;
	};

	/** Latest insertion epoch of the text's element or any ancestor (-1: pre-existing). */
	const insertionEpoch = (text: Text): number => {
		let latest = -1;
		for (let n: Node | null = text.parentNode; n; n = n.parentNode) {
			const at = insertedAt.get(n);
			if (at !== undefined && at > latest) latest = at;
		}
		return latest;
	};

	/**
	 * Original for `placeholder` in `text`, or null. Restored only when the placeholder
	 * was sent and the text's content was inserted after that send; unknown and
	 * never-restore placeholders stay as they are.
	 */
	const restoredValue = (placeholder: string, text: Text): string | null => {
		const sent = sentAt.get(placeholder);
		if (sent === undefined || insertionEpoch(text) < sent) return null;
		const original = vault.unmask(placeholder);
		return original === placeholder ? null : original;
	};

	const processText = (text: Text): void => {
		if (entries.has(text) || !eligible(text)) return;
		const data = text.data;
		if (!data.includes("[")) return;
		const pieces: { before: string; placeholder: string; original: string }[] = [];
		let last = 0;
		for (const match of data.matchAll(placeholderRegex())) {
			const placeholder = match[0];
			const original = restoredValue(placeholder, text);
			if (original === null) continue;
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

	/** Stamps an inserted element with the current send epoch and queues it. */
	const noteAdded = (node: Node): void => {
		if (ours.has(node)) return;
		if (node.nodeType === 1) insertedAt.set(node, epoch);
		enqueue(node);
	};

	const onTextChanged = (text: Text): void => {
		if (ours.has(text)) return;
		const entry = entries.get(text);
		if (entry) {
			if (text.data === entry.head) return; // our own write
			revert(text, entry, false); // the page rewrote the node (streaming)
		}
		enqueue(text);
	};

	const onChildList = (record: MutationRecord): void => {
		for (const removed of record.removedNodes) {
			const entry = removed.nodeType === 3 ? entries.get(removed as Text) : undefined;
			if (entry) revert(removed as Text, entry, false);
		}
		for (const added of record.addedNodes) noteAdded(added);
	};

	const onMutations = (records: MutationRecord[]): void => {
		for (const record of records) {
			if (record.type === "characterData") onTextChanged(record.target as Text);
			else onChildList(record);
		}
	};

	const setShown = (show: boolean): void => {
		for (const entry of entries.values()) {
			for (const node of entry.extras) {
				const info = restoredSpans.get(node as Element);
				if (info) info.shown.setAttribute(VALUE_ATTRIBUTE, show ? info.original : info.placeholder);
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
		noteSent(placeholders: Iterable<string>) {
			// Stamp everything inserted so far with the pre-send epoch first.
			if (observer) onMutations(observer.takeRecords());
			epoch += 1;
			for (const placeholder of placeholders) {
				if (!sentAt.has(placeholder)) sentAt.set(placeholder, epoch);
			}
		},
		rehydrateSent(placeholders: Iterable<string>) {
			// -1: before this page life, i.e. before every node (even pre-existing ones).
			for (const placeholder of placeholders) sentAt.set(placeholder, PREVIOUS_PAGE_LIFE);
			if (visible && doc.body) enqueue(doc.body);
		},
		sentPlaceholders() {
			return [...sentAt.keys()];
		},
	};
}
