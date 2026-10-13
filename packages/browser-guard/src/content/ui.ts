/**
 * In-page guard UI: a toast and a decision bubble rendered in a CLOSED shadow root
 * fixed at the bottom-right of the viewport, so the host page can neither style nor
 * read it. Toasts use role=status (role=alert for errors), stay up for a time that grows
 * with their length (toastLifetime), pause while hovered or focused and have a close
 * button (Escape closes them too). Bubbles use role=alertdialog with focus moved to the
 * default action, a Tab focus loop, Escape to dismiss and focus restored on close.
 */
import type { Strings } from "./strings.js";

type Tone = "info" | "warn" | "error";

export interface BubbleAction {
	readonly id: string;
	readonly label: string;
	readonly primary?: boolean;
}

export interface BubbleOptions {
	readonly title: string;
	readonly lines: readonly string[];
	readonly actions: readonly BubbleAction[];
	readonly tone: Tone;
	/** Action id that receives focus; defaults to the primary action, then the first. */
	readonly initialFocus?: string;
	/** Optional https link rendered under the lines (opens in a new tab, no opener). */
	readonly link?: { readonly href: string; readonly label: string };
	/** Small print under the title (e.g. a notice version). */
	readonly caption?: string;
	/** Small print under the buttons (e.g. what a button's choice means). */
	readonly footnote?: string;
}

/** Result id when a bubble is dismissed with Escape or replaced by another bubble. */
export const DISMISSED = "dismiss";

export interface GuardUi {
	toast(message: string, tone?: Tone): void;
	/** An info toast shown once the current toast (if any) has gone, so it never cuts one short. */
	toastWhenIdle(message: string): void;
	/** Shows a bubble and resolves with the chosen action id, or DISMISSED. */
	bubble(options: BubbleOptions): Promise<string>;
	closeBubble(): void;
	/** True when the event originated inside the guard UI. */
	isOwnEvent(event: Event): boolean;
	readonly bubbleOpen: boolean;
	/** The closed shadow root. Exposed to the content script (isolated world) for tests only. */
	readonly root: ShadowRoot;
	readonly host: HTMLElement;
	destroy(): void;
}

export interface GuardUiDeps {
	readonly document: Document;
	readonly window: Window;
	strings(): Strings;
	/** Fixed toast lifetime in ms (tests); by default it follows the text length (toastLifetime). */
	readonly toastMs?: number;
}

/** Shortest, per-character and longest toast lifetime (ms). */
const TOAST_MIN_MS = 5_000;
const TOAST_MS_PER_CHAR = 60;
const TOAST_MAX_MS = 20_000;
/** Time a toast stays after the pointer or focus leaves it, at least. */
const TOAST_RESUME_MS = 2_000;

/** How long a toast with `message` stays: 60 ms per character, between 5 and 20 seconds. */
export function toastLifetime(message: string): number {
	return Math.min(TOAST_MAX_MS, Math.max(TOAST_MIN_MS, message.length * TOAST_MS_PER_CHAR));
}

const STYLE = `
:host { all: initial; position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
  display: flex; flex-direction: column; align-items: flex-end; gap: 8px; max-width: min(420px, calc(100vw - 32px));
  font: 13px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif;
  --bg: #ffffff; --fg: #111827; --muted: #4b5563; --border: #d1d5db; --accent: #3862E8; --accent-fg: #ffffff;
  --warn: #b45309; --error: #b91c1c; --btn: #f3f4f6; --shadow: 0 8px 28px rgba(15, 23, 42, .18); }
@media (prefers-color-scheme: dark) {
  :host { --bg: #111827; --fg: #f3f4f6; --muted: #9ca3af; --border: #374151; --btn: #1f2937;
    --warn: #fbbf24; --error: #f87171; --shadow: 0 8px 28px rgba(0, 0, 0, .5); }
}
.card { box-sizing: border-box; width: 100%; background: var(--bg); color: var(--fg); border: 1px solid var(--border);
  border-left: 4px solid var(--accent); border-radius: 10px; box-shadow: var(--shadow); padding: 10px 14px; }
.card[data-tone="warn"] { border-left-color: var(--warn); }
.card[data-tone="error"] { border-left-color: var(--error); }
.brand { font-weight: 700; color: var(--accent); margin-right: 6px; }
.toast { display: flex; align-items: flex-start; gap: 8px; }
.toast .msg { flex: 1; min-width: 0; overflow-wrap: anywhere; }
button.x { flex: none; padding: 0 6px; line-height: 1.4; border-color: transparent; background: transparent;
  color: var(--muted); font-size: 16px; }
button.x:hover { color: var(--fg); background: var(--btn); }
.footnote { margin: 8px 0 0; font-size: 12px; color: var(--muted); text-align: right; }
.title { font-weight: 600; margin: 0 0 4px; font-size: 14px; }
.line { margin: 4px 0; color: var(--muted); white-space: pre-wrap; overflow-wrap: anywhere; }
.body { max-height: min(50vh, 360px); overflow-y: auto; }
.caption { margin: 0 0 4px; font-size: 12px; color: var(--muted); }
a { color: var(--accent); }
a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; margin-top: 10px; }
button { font: inherit; cursor: pointer; border-radius: 7px; padding: 6px 12px; border: 1px solid var(--border);
  background: var(--btn); color: var(--fg); }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
[hidden] { display: none !important; }
@media (prefers-reduced-motion: no-preference) { .card { animation: in .14s ease-out; }
  @keyframes in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } } }
`;

/** Whether the pointer is over `element` (false where `:hover` is unsupported). */
function hovered(element: Element): boolean {
	try {
		return element.matches(":hover");
	} catch {
		return false;
	}
}

/** Index Tab (or Shift+Tab when `backwards`) moves focus to, wrapping at either end. */
function wrapFocusIndex(index: number, length: number, backwards: boolean): number {
	if (backwards) return index <= 0 ? length - 1 : index - 1;
	return index === length - 1 ? 0 : index + 1;
}

export function createGuardUi(deps: GuardUiDeps): GuardUi {
	const { document: doc, window: win } = deps;
	const host = doc.createElement("div");
	host.setAttribute("data-aidr-guard", "");
	const root = host.attachShadow({ mode: "closed" });
	const style = doc.createElement("style");
	style.textContent = STYLE;
	const toastEl = doc.createElement("div");
	toastEl.className = "card toast";
	toastEl.setAttribute("role", "status");
	toastEl.setAttribute("aria-live", "polite");
	toastEl.setAttribute("aria-atomic", "true");
	toastEl.hidden = true;
	const bubbleEl = doc.createElement("div");
	bubbleEl.className = "card";
	bubbleEl.setAttribute("role", "alertdialog");
	bubbleEl.hidden = true;
	root.append(style, bubbleEl, toastEl);

	let toastTimer: ReturnType<typeof setTimeout> | undefined;
	/** When the visible toast is due to close, and whether hover/focus holds it open. */
	let toastDue = 0;
	let toastHeld = false;
	/** Info message waiting for the visible toast to close (toastWhenIdle). */
	let queued: string | null = null;
	let pending: { resolve(id: string): void; restoreFocus: Element | null } | null = null;
	let bubbleSeq = 0;

	const mount = (): void => {
		if (host.isConnected) return;
		(doc.documentElement ?? doc.body)?.append(host);
	};

	/** The brand, kept in English casing whatever the page language ("Singularity AIDR"). */
	const brandSpan = (): HTMLSpanElement => {
		const b = doc.createElement("span");
		b.className = "brand";
		b.lang = "en";
		b.setAttribute("translate", "no");
		b.textContent = deps.strings().brand;
		return b;
	};

	const clearToastTimer = (): void => {
		if (toastTimer !== undefined) win.clearTimeout(toastTimer);
		toastTimer = undefined;
	};

	const hideToast = (): void => {
		clearToastTimer();
		toastHeld = false;
		toastEl.hidden = true;
		toastEl.replaceChildren();
		const next = queued;
		queued = null;
		if (next !== null) toast(next);
	};

	const scheduleToast = (ms: number): void => {
		clearToastTimer();
		toastDue = Date.now() + ms;
		toastTimer = win.setTimeout(hideToast, ms);
	};

	// Hover or keyboard focus keeps the toast up; leaving restarts the remaining time.
	const holdToast = (): void => {
		if (toastEl.hidden || toastHeld) return;
		toastHeld = true;
		clearToastTimer();
	};
	const releaseToast = (): void => {
		if (toastEl.hidden || !toastHeld) return;
		if (hovered(toastEl) || toastEl.contains(root.activeElement)) return;
		toastHeld = false;
		scheduleToast(Math.max(TOAST_RESUME_MS, toastDue - Date.now()));
	};
	toastEl.addEventListener("mouseenter", holdToast);
	toastEl.addEventListener("focusin", holdToast);
	toastEl.addEventListener("mouseleave", releaseToast);
	toastEl.addEventListener("focusout", () => win.setTimeout(releaseToast, 0));
	toastEl.addEventListener("keydown", (event) => {
		if ((event as KeyboardEvent).key === "Escape") {
			event.preventDefault();
			hideToast();
		}
		// Keys typed in the toast never reach the page's key handlers.
		event.stopPropagation();
	});

	function toast(message: string, tone: Tone = "info"): void {
		mount();
		const text = doc.createElement("span");
		text.className = "msg";
		text.append(brandSpan(), doc.createTextNode(message));
		const close = doc.createElement("button");
		close.type = "button";
		close.className = "x";
		close.textContent = "\u00d7";
		close.setAttribute("aria-label", deps.strings().close);
		close.title = deps.strings().close;
		close.addEventListener("click", (event) => {
			event.stopPropagation();
			hideToast();
		});
		toastHeld = false;
		toastEl.replaceChildren(text, close);
		toastEl.dataset.tone = tone;
		// Errors interrupt (role=alert); everything else waits its turn (role=status).
		const urgent = tone === "error";
		toastEl.setAttribute("role", urgent ? "alert" : "status");
		toastEl.setAttribute("aria-live", urgent ? "assertive" : "polite");
		toastEl.hidden = false;
		scheduleToast(deps.toastMs ?? toastLifetime(message));
	}

	const toastWhenIdle = (message: string): void => {
		if (toastEl.hidden) toast(message);
		else queued = message;
	};

	const finish = (id: string, restore: boolean): void => {
		const current = pending;
		pending = null;
		bubbleEl.hidden = true;
		bubbleEl.replaceChildren();
		if (!current) return;
		if (restore) {
			const target = current.restoreFocus as HTMLElement | null;
			if (target?.isConnected && typeof target.focus === "function") target.focus();
		}
		current.resolve(id);
	};

	const buttons = (): HTMLButtonElement[] => [...bubbleEl.querySelectorAll("button")];
	/** Tab order of the open bubble: its link (if any) and its buttons. */
	const focusables = (): HTMLElement[] => [
		...bubbleEl.querySelectorAll<HTMLElement>("a[href], button"),
	];

	bubbleEl.addEventListener("keydown", (event) => {
		const e = event as KeyboardEvent;
		if (e.key === "Escape") {
			e.preventDefault();
			e.stopPropagation();
			finish(DISMISSED, true);
			return;
		}
		if (e.key === "Tab") {
			const list = focusables();
			if (list.length === 0) return;
			const active = root.activeElement;
			const index = list.findIndex((b) => b === active);
			e.preventDefault();
			list[wrapFocusIndex(index, list.length, e.shiftKey)]?.focus();
		}
		// Keys typed in the bubble never reach the page's key handlers.
		e.stopPropagation();
	});

	/** A paragraph of small print (line, caption, footnote) with an optional id. */
	const paragraph = (className: string, text: string, id?: string): HTMLParagraphElement => {
		const p = doc.createElement("p");
		p.className = className;
		if (id) p.id = id;
		p.textContent = text;
		return p;
	};

	/** The bubble's lines and optional link. */
	const bubbleBody = (options: BubbleOptions, id: string): HTMLDivElement => {
		const body = doc.createElement("div");
		body.id = id;
		body.className = "body";
		for (const line of options.lines) body.append(paragraph("line", line));
		if (options.link) {
			const p = paragraph("line", "");
			const a = doc.createElement("a");
			a.href = options.link.href;
			a.target = "_blank";
			a.rel = "noopener noreferrer";
			a.textContent = options.link.label;
			a.addEventListener("click", (event) => event.stopPropagation());
			p.append(a);
			body.append(p);
		}
		return body;
	};

	const bubbleActions = (options: BubbleOptions): HTMLDivElement => {
		const actions = doc.createElement("div");
		actions.className = "actions";
		for (const action of options.actions) {
			const button = doc.createElement("button");
			button.type = "button";
			button.textContent = action.label;
			button.dataset.action = action.id;
			if (action.primary) button.className = "primary";
			button.addEventListener("click", (event) => {
				event.stopPropagation();
				finish(action.id, true);
			});
			actions.append(button);
		}
		return actions;
	};

	const bubble = (options: BubbleOptions): Promise<string> => {
		mount();
		const restoreFocus = pending ? pending.restoreFocus : doc.activeElement;
		if (pending) finish(DISMISSED, false);
		const seq = ++bubbleSeq;
		const titleId = `aidr-bubble-title-${seq}`;
		const bodyId = `aidr-bubble-body-${seq}`;
		const noteId = `aidr-bubble-note-${seq}`;
		const title = doc.createElement("p");
		title.className = "title";
		title.id = titleId;
		title.append(brandSpan(), doc.createTextNode(options.title));
		const caption = options.caption ? [paragraph("caption", options.caption)] : [];
		// Small print under the buttons, e.g. what "Send original" means.
		const footnote = options.footnote ? [paragraph("footnote", options.footnote, noteId)] : [];
		bubbleEl.replaceChildren(
			title,
			...caption,
			bubbleBody(options, bodyId),
			bubbleActions(options),
			...footnote,
		);
		bubbleEl.dataset.tone = options.tone;
		bubbleEl.setAttribute("aria-labelledby", titleId);
		bubbleEl.setAttribute("aria-describedby", footnote.length ? `${bodyId} ${noteId}` : bodyId);
		bubbleEl.hidden = false;
		return new Promise<string>((resolve) => {
			pending = { resolve, restoreFocus };
			const focusId =
				options.initialFocus ??
				options.actions.find((a) => a.primary)?.id ??
				options.actions[0]?.id;
			const target = buttons().find((b) => b.dataset.action === focusId);
			target?.focus();
		});
	};

	return {
		toast,
		toastWhenIdle,
		bubble,
		closeBubble: () => finish(DISMISSED, false),
		isOwnEvent: (event) => event.composedPath().includes(host),
		get bubbleOpen() {
			return pending !== null;
		},
		root,
		host,
		destroy: () => {
			queued = null;
			clearToastTimer();
			finish(DISMISSED, false);
			host.remove();
		},
	};
}
