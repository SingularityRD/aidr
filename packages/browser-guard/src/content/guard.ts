/**
 * Content-script guard: intercepts prompt sends, pastes and file uploads on AI chat
 * sites, masks sensitive data through the placeholder vault before the page sees it,
 * and restores placeholders locally in responses.
 *
 * Everything is injected (`ContentGuardDeps`) so the guard is testable with fakes and
 * independent of the concrete engine/vault/adapter/editor implementations.
 *
 * Failure policy (CLAUDE.md): this is a connector entry point, so it fails CLOSED.
 * A missing policy, a scan error or an incomplete scan blocks the send (except in
 * `monitor` mode, which never blocks). Telemetry (`RECORD`) is best-effort and
 * carries counts only - never prompt text, originals or file content.
 */
import {
	type DetectionEngine,
	type EditorAccess,
	type EntityType,
	type Finding,
	type GuardMessage,
	type GuardPolicy,
	type PlaceholderVault,
	type PrivacyScanEvent,
	type ScanResult,
	type SignalCode,
	type SiteAdapter,
} from "../types.js";
import { type Counts, createFileGuard, type SanitizeFileFn } from "./file-guard.js";
import {
	formatCounts,
	type Lang,
	resolveLanguage,
	STRINGS,
	type Strings,
	totalCount,
} from "./strings.js";
import { type BubbleAction, createGuardUi, type GuardUi } from "./ui.js";
import { createUnmasker, placeholderRegex, type Unmasker } from "./unmask.js";

export interface ContentGuardDeps {
	readonly window: Window;
	readonly document: Document;
	readonly adapter: SiteAdapter;
	readonly engine: DetectionEngine;
	readonly vault: PlaceholderVault;
	/** Effective policy, or null while it has not been received (the guard then fails closed). */
	getPolicy(): GuardPolicy | null;
	findEditor(
		adapter: SiteAdapter,
		root: Document,
		lastFocused?: Element | null,
	): EditorAccess | null;
	findSendButton(
		adapter: SiteAdapter,
		root: Document,
		editor: EditorAccess | null,
	): HTMLElement | null;
	/** Inserts text at the caret; defaults to execCommand/setRangeText with an editor.write fallback. */
	insertAtSelection?(editor: EditorAccess, text: string): Promise<void> | void;
	/**
	 * True for events the editor module dispatched itself while rewriting the prompt
	 * (input/beforeinput/paste/change). They are never intercepted: a masked rewrite
	 * must not be re-scanned or re-masked as if the user had pasted it.
	 */
	isSyntheticEvent(event: Event): boolean;
	readonly sanitizeFile: SanitizeFileFn;
	coachingFor(code: SignalCode, lang: Lang): string;
	send(message: GuardMessage): Promise<unknown>;
	now?(): number;
	/** Batching scheduler for the unmask observer; defaults to queueMicrotask. */
	schedule?(callback: () => void): void;
	/** Debounce for the background pre-scan of the editor text (ms). */
	readonly prescanDelayMs?: number;
}

export interface ContentGuard {
	start(): void;
	stop(): void;
	/** Call after the policy returned by getPolicy() changed. */
	policyChanged(): void;
	/** User toggle (SET_RESTORE_VISIBLE); combined with policy.restoreResponses. */
	setRestoreVisible(visible: boolean): void;
	readonly ui: GuardUi;
	readonly unmasker: Unmasker;
}

type SendOrigin =
	| {
			readonly kind: "key";
			readonly target: HTMLElement;
			readonly ctrlKey: boolean;
			readonly metaKey: boolean;
	  }
	| { readonly kind: "click"; readonly button: HTMLElement }
	| { readonly kind: "submit"; readonly form: HTMLFormElement };

type Win = Window & typeof globalThis;

const CACHE_LIMIT = 8;
const CACHE_TTL_MS = 60_000;
const BUTTON_RETRY_MS = 50;
const BUTTON_RETRIES = 6;

/** Normalises editor text for equality checks (line endings, nbsp, outer whitespace). */
export function normalizeText(text: string): string {
	return text.replace(/\r\n?/g, "\n").replace(/ /g, " ").trim();
}

export function countFindings(findings: readonly Finding[]): Counts {
	const counts: Counts = {};
	for (const f of findings) counts[f.type] = (counts[f.type] ?? 0) + 1;
	return counts;
}

const asElement = (node: unknown): Element | null =>
	node && (node as Node).nodeType === 1 ? (node as Element) : null;

const contains = (outer: Element, inner: Element): boolean =>
	outer === inner || outer.contains(inner);

const isDisabled = (el: HTMLElement): boolean =>
	el.hasAttribute("disabled") || el.getAttribute("aria-disabled") === "true";

export function createContentGuard(deps: ContentGuardDeps): ContentGuard {
	const { document: doc, adapter, engine, vault } = deps;
	const win = deps.window as Win;
	const now = deps.now ?? (() => Date.now());
	const prescanDelay = deps.prescanDelayMs ?? 250;
	const sendSelector = adapter.sendButtonSelectors.join(",");
	const lang = (): Lang => resolveLanguage(deps.getPolicy()?.language, win.navigator?.language);
	const strings = (): Strings => STRINGS[lang()];

	const ui = createGuardUi({ document: doc, window: win, strings });
	const cache = new Map<string, { policy: GuardPolicy; result: ScanResult; at: number }>();
	let lastFocused: Element | null = null;
	/** Re-entrancy token: set only while our own replayed send is being dispatched. */
	let replayText: string | null = null;
	let busy = false;
	let restoreVisible = true;
	let prescanTimer: ReturnType<typeof setTimeout> | undefined;
	let started = false;

	const siteDisabled = (p: GuardPolicy): boolean => p.disabledSites.includes(adapter.id);
	const siteBlocked = (p: GuardPolicy): boolean => p.blockedSites.includes(adapter.id);

	const record = (
		action: PrivacyScanEvent["action"],
		channel: PrivacyScanEvent["channel"],
		counts: Readonly<Counts>,
	): void => {
		const safe: Partial<Record<EntityType, number>> = {};
		for (const [type, n] of Object.entries(counts) as [EntityType, number | undefined][]) {
			if (typeof n === "number" && n > 0) safe[type] = n;
		}
		try {
			void Promise.resolve(
				deps.send({ type: "RECORD", site: adapter.id, action, channel, counts: safe }),
			).catch(() => undefined);
		} catch {
			// Telemetry is best-effort; the decision itself has already been enforced.
		}
	};

	const stopEvent = (event: Event): void => {
		if (event.cancelable) event.preventDefault();
		event.stopImmediatePropagation();
	};

	const showBlocked = (lines: readonly string[], title = strings().blockedTitle): void => {
		void ui.bubble({
			title,
			lines,
			actions: [{ id: "close", label: strings().close, primary: true }],
			tone: "error",
		});
	};

	const remember = (text: string, policy: GuardPolicy, result: ScanResult): void => {
		cache.delete(text);
		cache.set(text, { policy, result, at: now() });
		while (cache.size > CACHE_LIMIT) {
			const oldest = cache.keys().next().value;
			if (oldest === undefined) break;
			cache.delete(oldest);
		}
	};

	const cached = (text: string, policy: GuardPolicy): ScanResult | undefined => {
		const entry = cache.get(text);
		if (!entry || entry.policy !== policy || now() - entry.at > CACHE_TTL_MS) return undefined;
		return entry.result;
	};

	/** Scans text; null when the scan failed or was incomplete (callers fail closed). */
	const scan = async (text: string, policy: GuardPolicy | null): Promise<ScanResult | null> => {
		try {
			const result = await engine.scan(text);
			if (!result || result.incomplete) return null;
			if (policy) remember(text, policy, result);
			return result;
		} catch {
			return null;
		}
	};

	/** Findings that are not already inside one of our own placeholders. */
	const relevantFindings = (text: string, result: ScanResult): Finding[] => {
		const spans: [number, number][] = [];
		for (const m of text.matchAll(placeholderRegex())) {
			if (vault.lookup(m[0]) !== undefined) spans.push([m.index, m.index + m[0].length]);
		}
		if (spans.length === 0) return [...result.findings];
		return result.findings.filter((f) => !spans.some(([a, b]) => f.start < b && f.end > a));
	};

	const activeSignals = (policy: GuardPolicy, result: ScanResult): SignalCode[] =>
		policy.detectSignals && policy.signalAction !== "off" ? [...result.signals] : [];

	const wait = (ms: number): Promise<void> =>
		new Promise((resolve) => {
			win.setTimeout(resolve, ms);
		});

	const editorFor = (hint: Element | null): EditorAccess | null => {
		try {
			return deps.findEditor(adapter, doc, hint ?? lastFocused);
		} catch {
			return null;
		}
	};

	// ---- replaying a send ---------------------------------------------------------

	const perform = (text: string, fn: () => void): void => {
		replayText = text;
		try {
			fn();
		} finally {
			replayText = null;
		}
	};

	const stillHolds = (editor: EditorAccess, text: string): boolean => {
		try {
			return normalizeText(editor.read()) === normalizeText(text);
		} catch {
			return false;
		}
	};

	/** Clicks the send button once the site has enabled it for the new text. */
	const clickSend = async (
		origin: SendOrigin,
		editor: EditorAccess,
		text: string,
	): Promise<boolean> => {
		for (let attempt = 0; attempt <= BUTTON_RETRIES; attempt++) {
			if (!stillHolds(editor, text)) return false;
			const button =
				origin.kind === "click" && origin.button.isConnected
					? origin.button
					: deps.findSendButton(adapter, doc, editor);
			if (button && !isDisabled(button)) {
				perform(text, () => button.click());
				return true;
			}
			await wait(BUTTON_RETRY_MS);
		}
		return false;
	};

	/** Re-sends exactly once; the capture listeners let it through only while `text` is in the editor. */
	const replay = async (origin: SendOrigin, editor: EditorAccess, text: string): Promise<void> => {
		if (!stillHolds(editor, text)) {
			ui.toast(strings().textChanged, "warn");
			return;
		}
		if (origin.kind === "submit") {
			const form = origin.form;
			perform(text, () => {
				if (typeof form.requestSubmit === "function") form.requestSubmit();
				else form.dispatchEvent(new win.Event("submit", { bubbles: true, cancelable: true }));
			});
			return;
		}
		if (origin.kind === "key") {
			const target = origin.target.isConnected ? origin.target : editor.element;
			let handled = false;
			perform(text, () => {
				const event = new win.KeyboardEvent("keydown", {
					key: "Enter",
					code: "Enter",
					keyCode: 13,
					which: 13,
					bubbles: true,
					cancelable: true,
					composed: true,
					ctrlKey: origin.ctrlKey,
					metaKey: origin.metaKey,
				});
				handled = !target.dispatchEvent(event);
			});
			// Sites that handle Enter call preventDefault; otherwise fall back to the button.
			if (handled) return;
		}
		if (!(await clickSend(origin, editor, text)) && stillHolds(editor, text)) {
			ui.toast(strings().pressSendAgain, "info");
		}
	};

	// ---- decisions ----------------------------------------------------------------

	const maskAndSend = async (
		origin: SendOrigin,
		editor: EditorAccess,
		text: string,
		findings: readonly Finding[],
	): Promise<void> => {
		const s = strings();
		busy = true;
		let masked: string;
		let counts: Counts;
		try {
			const result = vault.mask(text, findings);
			masked = result.masked;
			counts = { ...result.counts };
			await editor.write(masked);
		} catch {
			busy = false;
			showBlocked([s.rewriteFailed]);
			record("blocked", "prompt", countFindings(findings));
			return;
		}
		busy = false;
		if (!stillHolds(editor, masked)) {
			showBlocked([s.rewriteFailed]);
			record("blocked", "prompt", counts);
			return;
		}
		ui.toast(s.maskedToast(totalCount(counts), formatCounts(counts)), "info");
		record("masked", "prompt", counts);
		await replay(origin, editor, masked);
	};

	const decide = async (
		policy: GuardPolicy,
		origin: SendOrigin,
		editor: EditorAccess,
		text: string,
		result: ScanResult | null,
	): Promise<void> => {
		const s = strings();
		if (!result) {
			showBlocked([s.scanFailed]);
			record("blocked", "prompt", {});
			return;
		}
		if (!stillHolds(editor, text)) {
			ui.toast(s.textChanged, "warn");
			return;
		}
		const findings = relevantFindings(text, result);
		const counts = countFindings(findings);
		const signals = activeSignals(policy, result);
		if (findings.length === 0 && signals.length === 0) {
			record("allowed", "prompt", {});
			await replay(origin, editor, text);
			return;
		}
		const total = totalCount(counts);
		const summary = formatCounts(counts);
		const coaching = signals.map((code) => deps.coachingFor(code, lang()));
		if (signals.length > 0 && policy.signalAction === "block") {
			showBlocked([...(total > 0 ? [s.blockedBody(total, summary)] : []), ...coaching]);
			record("blocked", "prompt", counts);
			return;
		}
		if (findings.length > 0 && policy.mode === "block") {
			showBlocked([s.blockedBody(total, summary), s.blockedCoaching, ...coaching]);
			record("blocked", "prompt", counts);
			return;
		}
		if (policy.mode === "auto" && signals.length === 0) {
			await maskAndSend(origin, editor, text, findings);
			return;
		}
		// confirm mode, or a warn-level signal: ask the user.
		const actions: BubbleAction[] = [];
		const lines: string[] = [];
		if (findings.length > 0) {
			lines.push(s.confirmBody(total, summary));
			actions.push({ id: "send-masked", label: s.sendMasked, primary: true });
			actions.push({ id: "edit", label: s.edit });
			if (policy.allowSendAnyway) actions.push({ id: "send-original", label: s.sendOriginal });
		} else {
			actions.push({ id: "edit", label: s.edit, primary: true });
			actions.push({ id: "send-anyway", label: s.sendAnyway });
		}
		lines.push(...coaching);
		const choice = await ui.bubble({
			title: findings.length > 0 ? s.confirmTitle : s.warnTitle,
			lines,
			actions,
			tone: "warn",
		});
		if (choice === "send-masked") {
			await maskAndSend(origin, editor, text, findings);
			return;
		}
		if (choice === "send-original" || choice === "send-anyway") {
			if (!stillHolds(editor, text)) {
				ui.toast(s.textChanged, "warn");
				return;
			}
			record(findings.length > 0 ? "allowed" : "warned", "prompt", counts);
			await replay(origin, editor, text);
			return;
		}
		// Edit / Escape: nothing was sent.
		record("warned", "prompt", counts);
		try {
			editor.element.focus();
		} catch {
			// focus is cosmetic
		}
	};

	const monitorScan = async (
		text: string,
		channel: "prompt" | "paste",
		policy: GuardPolicy,
	): Promise<void> => {
		const result = await scan(text, policy);
		const counts = result ? countFindings(relevantFindings(text, result)) : {};
		if (channel === "paste" && totalCount(counts) === 0) return;
		record("allowed", channel, counts);
	};

	// ---- send interception ----------------------------------------------------------

	const onSendAttempt = (event: Event, origin: SendOrigin, editor: EditorAccess | null): void => {
		let text: string | null = null;
		try {
			text = editor ? editor.read() : null;
		} catch {
			text = null;
		}
		if (replayText !== null && text !== null && normalizeText(text) === normalizeText(replayText)) {
			return; // our own replay of an already-checked prompt
		}
		const policy = deps.getPolicy();
		const s = strings();
		if (!policy) {
			stopEvent(event);
			showBlocked([s.policyMissing]);
			record("blocked", "prompt", {});
			return;
		}
		if (siteDisabled(policy)) return;
		if (siteBlocked(policy)) {
			stopEvent(event);
			showBlocked([s.siteBlocked]);
			record("blocked", "prompt", {});
			return;
		}
		if (!editor || text === null) {
			if (policy.mode === "monitor") return;
			stopEvent(event);
			showBlocked([s.editorMissing]);
			record("blocked", "prompt", {});
			return;
		}
		if (normalizeText(text) === "") return;
		if (policy.mode === "monitor") {
			void monitorScan(text, "prompt", policy);
			return;
		}
		if (busy) {
			stopEvent(event);
			ui.toast(s.busy, "info");
			return;
		}
		if (ui.bubbleOpen) ui.closeBubble();
		const hit = cached(text, policy);
		if (
			hit &&
			relevantFindings(text, hit).length === 0 &&
			activeSignals(policy, hit).length === 0
		) {
			record("allowed", "prompt", {});
			return; // pre-scanned clean: the original, trusted event goes through untouched
		}
		stopEvent(event);
		busy = true;
		const scanned = text;
		void (async () => {
			let result: ScanResult | null;
			try {
				result = hit ?? (await scan(scanned, policy));
			} finally {
				busy = false;
			}
			await decide(policy, origin, editor, scanned, result);
		})().catch(() => {
			busy = false;
			showBlocked([strings().scanFailed]);
			record("blocked", "prompt", {});
		});
	};

	/** Events the guard must never intercept: our own UI and the editor module's rewrites. */
	const ignored = (event: Event): boolean => {
		if (ui.isOwnEvent(event)) return true;
		try {
			return deps.isSyntheticEvent(event);
		} catch {
			return false;
		}
	};

	const onKeyDown = (event: KeyboardEvent): void => {
		if (event.key !== "Enter" || event.shiftKey || event.altKey) return;
		if (event.isComposing || event.keyCode === 229) return;
		if (ignored(event)) return;
		const target = asElement(event.composedPath()[0] ?? event.target);
		if (!target) return;
		const editor = editorFor(target);
		if (!editor || !contains(editor.element, target)) return;
		onSendAttempt(
			event,
			{
				kind: "key",
				target: target as HTMLElement,
				ctrlKey: event.ctrlKey,
				metaKey: event.metaKey,
			},
			editor,
		);
	};

	const resolveSendButton = (
		target: Element,
	): { button: HTMLElement; editor: EditorAccess | null } | null => {
		const bySelector = sendSelector ? target.closest<HTMLElement>(sendSelector) : null;
		if (bySelector) return { button: bySelector, editor: editorFor(null) };
		const editor = editorFor(null);
		const found = deps.findSendButton(adapter, doc, editor);
		return found && contains(found, target) ? { button: found, editor } : null;
	};

	const onClick = (event: MouseEvent): void => {
		if (ignored(event)) return;
		const target = asElement(event.composedPath()[0] ?? event.target);
		if (!target) return;
		const hit = resolveSendButton(target);
		if (!hit) return;
		onSendAttempt(event, { kind: "click", button: hit.button }, hit.editor);
	};

	const onSubmit = (event: Event): void => {
		if (ignored(event)) return;
		const form = asElement(event.target);
		if (!form || form.tagName !== "FORM") return;
		const editor = editorFor(null);
		if (!editor || !form.contains(editor.element)) return;
		onSendAttempt(event, { kind: "submit", form: form as HTMLFormElement }, editor);
	};

	// ---- pre-scan while typing --------------------------------------------------------

	const schedulePrescan = (): void => {
		const policy = deps.getPolicy();
		if (!policy || policy.mode === "monitor" || siteDisabled(policy) || siteBlocked(policy)) return;
		if (prescanTimer !== undefined) win.clearTimeout(prescanTimer);
		prescanTimer = win.setTimeout(() => {
			prescanTimer = undefined;
			const current = deps.getPolicy();
			const editor = editorFor(null);
			if (!current || !editor) return;
			let text: string;
			try {
				text = editor.read();
			} catch {
				return;
			}
			if (normalizeText(text) === "" || cached(text, current)) return;
			void scan(text, current);
		}, prescanDelay);
	};

	const onInput = (event: Event): void => {
		const target = asElement(event.target);
		if (target?.tagName === "INPUT" && (target as HTMLInputElement).type === "file") {
			fileGuard.onInputEvent(event);
			return;
		}
		if (event.type !== "input" || !target || ignored(event)) return;
		const editor = editorFor(target);
		if (editor && contains(editor.element, target)) schedulePrescan();
	};

	// ---- paste ------------------------------------------------------------------------

	const insertText = async (editor: EditorAccess, text: string): Promise<void> => {
		if (deps.insertAtSelection) {
			await deps.insertAtSelection(editor, text);
			return;
		}
		const el = editor.element;
		el.focus();
		const exec = (doc as Document & { execCommand?: Document["execCommand"] }).execCommand;
		if (typeof exec === "function" && exec.call(doc, "insertText", false, text)) return;
		if (el.tagName === "TEXTAREA" || el.tagName === "INPUT") {
			const field = el as HTMLTextAreaElement;
			const start = field.selectionStart ?? field.value.length;
			const end = field.selectionEnd ?? start;
			field.setRangeText(text, start, end, "end");
			field.dispatchEvent(
				new win.InputEvent("input", { bubbles: true, inputType: "insertFromPaste", data: text }),
			);
			return;
		}
		await editor.write(editor.read() + text);
	};

	const maskText = async (text: string): Promise<{ text: string; counts: Counts } | null> => {
		const result = await scan(text, deps.getPolicy());
		if (!result) return null;
		const findings = relevantFindings(text, result);
		if (findings.length === 0) return { text, counts: {} };
		const masked = vault.mask(text, findings);
		return { text: masked.masked, counts: { ...masked.counts } };
	};

	const onPaste = (event: ClipboardEvent): void => {
		if (ignored(event) || fileGuard.replaying) return;
		if (fileGuard.onPasteFiles(event)) return;
		const target = asElement(event.composedPath()[0] ?? event.target);
		if (!target) return;
		const editor = editorFor(target);
		if (!editor || !contains(editor.element, target)) return;
		const text = event.clipboardData?.getData("text/plain") ?? "";
		if (!text) return;
		const policy = deps.getPolicy();
		const s = strings();
		if (!policy) {
			stopEvent(event);
			ui.toast(s.policyMissing, "error");
			return;
		}
		if (siteDisabled(policy)) return;
		if (siteBlocked(policy)) {
			stopEvent(event);
			showBlocked([s.siteBlocked]);
			record("blocked", "paste", {});
			return;
		}
		if (!policy.maskPaste) return;
		if (policy.mode === "monitor") {
			void monitorScan(text, "paste", policy);
			return;
		}
		stopEvent(event);
		void (async () => {
			const result = await scan(text, policy);
			if (!result) {
				showBlocked([s.pasteScanFailed]);
				record("blocked", "paste", {});
				return;
			}
			const findings = relevantFindings(text, result);
			if (findings.length === 0) {
				await insertText(editor, text);
				return;
			}
			const counts = countFindings(findings);
			if (policy.mode === "block") {
				showBlocked([s.pasteBlocked, s.blockedCoaching]);
				record("blocked", "paste", counts);
				return;
			}
			const masked = vault.mask(text, findings);
			await insertText(editor, masked.masked);
			ui.toast(s.pasteMaskedToast(totalCount(masked.counts), formatCounts(masked.counts)), "info");
			record("masked", "paste", masked.counts);
		})().catch(() => {
			showBlocked([strings().rewriteFailed]);
		});
	};

	// ---- files, unmasking, lifecycle ---------------------------------------------------

	const fileGuard = createFileGuard({
		window: win,
		adapter,
		engine,
		vault,
		ui,
		sanitizeFile: deps.sanitizeFile,
		getPolicy: deps.getPolicy,
		strings,
		record,
		maskText,
	});

	const unmasker = createUnmasker({
		document: doc,
		window: win,
		adapter,
		vault,
		editorElement: () => editorFor(null)?.element ?? null,
		title: () => strings().restoredTitle,
		schedule: deps.schedule,
	});

	const applyRestore = (): void => {
		const policy = deps.getPolicy();
		unmasker.setVisible(!!policy && policy.restoreResponses && restoreVisible);
	};

	const onFocusIn = (event: FocusEvent): void => {
		if (ui.isOwnEvent(event)) return;
		const target = asElement(event.composedPath()[0] ?? event.target);
		if (target) lastFocused = target;
	};

	const onDrop = (event: DragEvent): void => fileGuard.onDrop(event);

	const listeners: [string, (event: never) => void][] = [
		["keydown", onKeyDown],
		["click", onClick],
		["submit", onSubmit],
		["paste", onPaste],
		["drop", onDrop],
		["input", onInput],
		["change", onInput],
		["focusin", onFocusIn],
	];

	return {
		start() {
			if (started) return;
			started = true;
			for (const [type, fn] of listeners) win.addEventListener(type, fn as EventListener, true);
			unmasker.start();
			applyRestore();
		},
		stop() {
			if (!started) return;
			started = false;
			for (const [type, fn] of listeners) win.removeEventListener(type, fn as EventListener, true);
			if (prescanTimer !== undefined) win.clearTimeout(prescanTimer);
			unmasker.stop();
			ui.destroy();
			cache.clear();
		},
		policyChanged() {
			cache.clear();
			applyRestore();
		},
		setRestoreVisible(visible: boolean) {
			restoreVisible = visible;
			applyRestore();
		},
		ui,
		unmasker,
	};
}
