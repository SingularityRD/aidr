/**
 * In-page guard UI: a toast and a decision bubble rendered in a CLOSED shadow root
 * fixed at the bottom-right of the viewport, so the host page can neither style nor
 * read it. Toasts use role=status; bubbles use role=alertdialog with focus moved to
 * the default action, a Tab focus loop, Escape to dismiss and focus restored on close.
 */
import type { Strings } from "./strings.js";

export type Tone = "info" | "warn" | "error";

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
}

/** Result id when a bubble is dismissed with Escape or replaced by another bubble. */
export const DISMISSED = "dismiss";

export interface GuardUi {
	toast(message: string, tone?: Tone): void;
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
	/** Toast lifetime in ms. */
	readonly toastMs?: number;
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
.brand { font-weight: 700; letter-spacing: .08em; color: var(--accent); margin-right: 6px; }
.title { font-weight: 600; margin: 0 0 4px; font-size: 14px; }
.line { margin: 4px 0; color: var(--muted); }
.actions { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; margin-top: 10px; }
button { font: inherit; cursor: pointer; border-radius: 7px; padding: 6px 12px; border: 1px solid var(--border);
  background: var(--btn); color: var(--fg); }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
[hidden] { display: none !important; }
@media (prefers-reduced-motion: no-preference) { .card { animation: in .14s ease-out; }
  @keyframes in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } } }
`;

export function createGuardUi(deps: GuardUiDeps): GuardUi {
	const { document: doc, window: win } = deps;
	const toastMs = deps.toastMs ?? 5000;
	const host = doc.createElement("div");
	host.setAttribute("data-aidr-guard", "");
	const root = host.attachShadow({ mode: "closed" });
	const style = doc.createElement("style");
	style.textContent = STYLE;
	const toastEl = doc.createElement("div");
	toastEl.className = "card";
	toastEl.setAttribute("role", "status");
	toastEl.setAttribute("aria-live", "polite");
	toastEl.hidden = true;
	const bubbleEl = doc.createElement("div");
	bubbleEl.className = "card";
	bubbleEl.setAttribute("role", "alertdialog");
	bubbleEl.hidden = true;
	root.append(style, bubbleEl, toastEl);

	let toastTimer: ReturnType<typeof setTimeout> | undefined;
	let pending: { resolve(id: string): void; restoreFocus: Element | null } | null = null;
	let bubbleSeq = 0;

	const mount = (): void => {
		if (host.isConnected) return;
		(doc.documentElement ?? doc.body)?.append(host);
	};

	const brandSpan = (): HTMLSpanElement => {
		const b = doc.createElement("span");
		b.className = "brand";
		b.textContent = deps.strings().brand;
		return b;
	};

	const toast = (message: string, tone: Tone = "info"): void => {
		mount();
		toastEl.replaceChildren(brandSpan(), doc.createTextNode(message));
		toastEl.dataset.tone = tone;
		toastEl.hidden = false;
		if (toastTimer !== undefined) win.clearTimeout(toastTimer);
		toastTimer = win.setTimeout(() => {
			toastEl.hidden = true;
			toastEl.replaceChildren();
		}, toastMs);
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

	bubbleEl.addEventListener("keydown", (event) => {
		const e = event as KeyboardEvent;
		if (e.key === "Escape") {
			e.preventDefault();
			e.stopPropagation();
			finish(DISMISSED, true);
			return;
		}
		if (e.key === "Tab") {
			const list = buttons();
			if (list.length === 0) return;
			const active = root.activeElement;
			const index = list.findIndex((b) => b === active);
			const next = e.shiftKey
				? index <= 0
					? list.length - 1
					: index - 1
				: index === list.length - 1
					? 0
					: index + 1;
			e.preventDefault();
			list[next]?.focus();
		}
		// Keys typed in the bubble never reach the page's key handlers.
		e.stopPropagation();
	});

	const bubble = (options: BubbleOptions): Promise<string> => {
		mount();
		const restoreFocus = pending ? pending.restoreFocus : doc.activeElement;
		if (pending) finish(DISMISSED, false);
		const seq = ++bubbleSeq;
		const titleId = `aidr-bubble-title-${seq}`;
		const bodyId = `aidr-bubble-body-${seq}`;
		const title = doc.createElement("p");
		title.className = "title";
		title.id = titleId;
		title.append(brandSpan(), doc.createTextNode(options.title));
		const body = doc.createElement("div");
		body.id = bodyId;
		for (const line of options.lines) {
			const p = doc.createElement("p");
			p.className = "line";
			p.textContent = line;
			body.append(p);
		}
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
		bubbleEl.replaceChildren(title, body, actions);
		bubbleEl.dataset.tone = options.tone;
		bubbleEl.setAttribute("aria-labelledby", titleId);
		bubbleEl.setAttribute("aria-describedby", bodyId);
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
		bubble,
		closeBubble: () => finish(DISMISSED, false),
		isOwnEvent: (event) => event.composedPath().includes(host),
		get bubbleOpen() {
			return pending !== null;
		},
		root,
		host,
		destroy: () => {
			if (toastTimer !== undefined) win.clearTimeout(toastTimer);
			finish(DISMISSED, false);
			host.remove();
		},
	};
}
