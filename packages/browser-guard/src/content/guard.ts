/**
 * Content-script guard: intercepts prompt sends, pastes and file uploads on AI chat
 * sites, masks sensitive data through the placeholder vault before the page sees it,
 * and restores placeholders locally in responses.
 *
 * Everything is injected (`ContentGuardDeps`) so the guard is testable with fakes and
 * independent of the concrete engine/vault/adapter/editor implementations.
 *
 * Every send that is let through is reported to the unmasker (`noteSent`) with the vault
 * placeholders it carries (plus those of masked files attached since the previous send):
 * only those are ever restored in the page, and only in content that appears after
 * the send (see ./unmask.ts).
 *
 * With `policy.useNativeHost`, every prompt/paste scan also asks the worker for native
 * NER (NATIVE_SCAN, bounded to NATIVE_MAX_CHARS and NATIVE_REPLY_TIMEOUT_MS) in parallel
 * with the rule engine and merges its PERSON/ADDRESS/LOCATION findings before masking.
 * When the host gives no usable answer the scan proceeds rules-only and the user is told
 * so (never a silent "NER checked" claim) - unless the managed policy sets
 * `requireNativeNer` (with a NER type enabled): then any outcome other than "used" (host
 * missing, crash, timeout, rules-only coverage, malformed reply, text over NATIVE_MAX_CHARS)
 * blocks the send, paste or upload with that reason, and the RECORD says `native:
 * "unavailable"` (monitor mode records it that way instead of blocking). Uploaded text is
 * then checked through the same NER (`nativeFileGate`).
 * Uploaded images (and pictures inside documents) are OCR'd through the same host
 * (NATIVE_IMAGE_SCAN, NATIVE_IMAGE_REPLY_TIMEOUT_MS); without a usable answer they are
 * reported as not inspected, never as clean.
 *
 * Sites in `policy.disabledSites` get monitor semantics: nothing is masked or blocked by
 * the guard, but prompts/pastes/files are still scanned and counted (RECORD "allowed").
 * Organisation blocks (`blockedSites`, `fileHandling: "block"`) still apply there.
 *
 * Failure policy (CLAUDE.md): this is a connector entry point, so it fails CLOSED.
 * A missing policy, a scan error or an incomplete scan blocks the send (except in
 * `monitor` mode, which never blocks). Telemetry (`RECORD`) is best-effort and
 * carries counts only - never prompt text, originals or file content.
 */

import { toBase64 } from "../../../privacy/src/browser/transport.js";
import { type Counts, countFindings } from "../engine/counts.js";
import { MAX_OCR_IMAGE_BYTES } from "../engine/office/images.js";
import {
	type DetectionEngine,
	type EditorAccess,
	ENTITY_TYPES,
	type EntityType,
	type Finding,
	type GuardMessage,
	type GuardPolicy,
	type ImageInspection,
	type NativeNerUse,
	type PlaceholderVault,
	type PrivacyScanEvent,
	type ScanResult,
	type SignalCode,
	type SiteAdapter,
} from "../types.js";
import {
	createFileGuard,
	NATIVE_UNAVAILABLE,
	type NativeFileGate,
	type SanitizeFileFn,
} from "./file-guard.js";
import { RELAY_SCAN } from "./file-relay.js";
import {
	formatCounts,
	type Lang,
	resolveLanguage,
	STRINGS,
	type Strings,
	totalCount,
} from "./strings.js";
import { type BubbleAction, type BubbleOptions, createGuardUi, type GuardUi } from "./ui.js";
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
	/** Called after a send left the page (the set of sent placeholders may have grown). */
	onSent?(): void;
	/** Upper bound for waiting on NATIVE_SCAN (ms); defaults to NATIVE_REPLY_TIMEOUT_MS. */
	readonly nativeTimeoutMs?: number;
	/** Upper bound for waiting on NATIVE_IMAGE_SCAN (ms); defaults to NATIVE_IMAGE_REPLY_TIMEOUT_MS. */
	readonly nativeImageTimeoutMs?: number;
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

/** Entity types the native host's NER contributes on top of the rule layer. */
const NATIVE_NER_TYPES: readonly EntityType[] = Object.freeze(["PERSON", "ADDRESS", "LOCATION"]);
/**
 * How long a scan waits for NATIVE_SCAN: the worker's bridge gives up after 2 s
 * (background/native.ts NATIVE_TIMEOUT_MS); the rest is messaging slack.
 */
export const NATIVE_REPLY_TIMEOUT_MS = 2_500;
/** How long an image OCR waits: the worker's bridge gives up after 60 s, plus messaging slack. */
const NATIVE_IMAGE_REPLY_TIMEOUT_MS = 65_000;
const INSPECTION_RESULTS: readonly ImageInspection["result"][] = [
	"clean",
	"sensitive",
	"incomplete",
];

/** A NATIVE_IMAGE_SCAN reply's inspection, validated; null for anything else. */
export function parseImageInspection(reply: unknown): ImageInspection | null {
	const r = reply as { ok?: unknown; inspection?: unknown } | null | undefined;
	if (r?.ok !== true || typeof r.inspection !== "object" || r.inspection === null) return null;
	const { result, counts, reasons } = r.inspection as Record<string, unknown>;
	if (!INSPECTION_RESULTS.includes(result as ImageInspection["result"])) return null;
	if (!Array.isArray(reasons) || !reasons.every((x) => typeof x === "string")) return null;
	if (typeof counts !== "object" || counts === null) return null;
	const safe: Partial<Record<EntityType, number>> = {};
	for (const [type, n] of Object.entries(counts)) {
		if (!ENTITY_TYPES.includes(type as EntityType) || !Number.isSafeInteger(n) || (n as number) < 0)
			return null;
		safe[type as EntityType] = n as number;
	}
	return { result: result as ImageInspection["result"], counts: safe, reasons: [...reasons] };
}

/** Longest text sent to the native host (the rule engine's own input limit). */
export const NATIVE_MAX_CHARS = 200_000;

/**
 * Whether native NER took part in a scan: "used" (its findings are merged), "unavailable"
 * (enabled by policy but no usable answer: rules only, and the user is told so) or "off".
 */
export type NativeUse = "used" | "unavailable" | "off";

/**
 * policy.requireNativeNer with at least one NER type enabled: native NER must take part in
 * every text check (anything short of "used" blocks).
 */
export function nativeNerRequired(policy: GuardPolicy | null): boolean {
	return (
		policy?.requireNativeNer === true &&
		NATIVE_NER_TYPES.some((t) => policy.enabledEntities.includes(t))
	);
}

/** A file scan the required native NER did not check: incomplete, so the upload fails closed. */
const NOT_NER_CHECKED: ScanResult = Object.freeze({
	findings: [],
	signals: [],
	counts: {},
	incomplete: true,
	elapsedMs: 0,
});

/** The native outcome a RECORD carries (`undefined` when native NER was off). */
const recordedNative = (use: NativeUse | undefined): NativeNerUse | undefined =>
	use === "used" || use === "unavailable" ? use : undefined;

/** A rule scan with the native host's findings merged in. */
export interface GuardScan extends ScanResult {
	readonly native: NativeUse;
}

function isNativeFinding(raw: unknown, text: string, types: readonly EntityType[]): boolean {
	if (!raw || typeof raw !== "object") return false;
	const f = raw as Partial<Finding>;
	return (
		types.includes(f.type as EntityType) &&
		Number.isSafeInteger(f.start) &&
		Number.isSafeInteger(f.end) &&
		(f.start as number) >= 0 &&
		(f.start as number) < (f.end as number) &&
		(f.end as number) <= text.length
	);
}

/**
 * Adds the native host's findings to a rule scan. A native span already covered by a
 * finding is dropped (no double count); overlapping spans are kept, and the vault
 * merges them into one masked span so no detected character stays in clear text.
 */
export function mergeNativeFindings(
	result: ScanResult,
	native: readonly Finding[],
	use: NativeUse,
): GuardScan {
	const findings = [...result.findings];
	for (const f of native) {
		if (findings.some((g) => g.start <= f.start && g.end >= f.end)) continue;
		const score = Number.isFinite(f.score) ? f.score : 0;
		findings.push({ type: f.type, start: f.start, end: f.end, score, source: "native-ner" });
	}
	findings.sort((a, b) => a.start - b.start || b.end - a.end);
	return { ...result, findings, counts: countFindings(findings), native: use };
}

/** The parts of `finding` outside the (start-sorted) `holes`. */
function remainders(
	finding: Finding,
	holes: readonly (readonly [number, number])[],
): [number, number][] {
	let cursor = finding.start;
	const pieces: [number, number][] = [];
	for (const [a, b] of holes) {
		if (b <= cursor || a >= finding.end) continue;
		if (a > cursor) pieces.push([cursor, a]);
		cursor = Math.max(cursor, b);
	}
	if (cursor < finding.end) pieces.push([cursor, finding.end]);
	return pieces;
}

/** At least one letter or digit: a remainder without one carries no data worth masking. */
const MEANINGFUL = /[\p{L}\p{N}]/u;

/**
 * Cuts `placeholders` (sorted or not, [start, end) offsets of our own vault
 * placeholders in `text`) out of every finding. A finding wholly inside a placeholder
 * is dropped (it is already masked); a finding that spans one - e.g. a labelled field
 * such as `Name: [EMAIL_1] John Smith` - keeps every remaining sub-span, trimmed of
 * whitespace, so the sensitive text around the placeholder is still masked. Remainders
 * without a letter or digit (punctuation, separators) are dropped.
 */
export function subtractPlaceholders(
	text: string,
	findings: readonly Finding[],
	placeholders: readonly (readonly [number, number])[],
): Finding[] {
	if (placeholders.length === 0) return [...findings];
	const holes = [...placeholders].sort((a, b) => a[0] - b[0]);
	const out: Finding[] = [];
	for (const finding of findings) {
		const pieces = remainders(finding, holes);
		const untouched = pieces.length === 1 && pieces[0]?.[0] === finding.start;
		if (untouched && pieces[0]?.[1] === finding.end) {
			out.push(finding);
			continue;
		}
		for (const [start, end] of pieces) {
			const slice = text.slice(start, end);
			const lead = slice.length - slice.trimStart().length;
			const trimmed = slice.trim();
			if (MEANINGFUL.test(trimmed)) {
				out.push({ ...finding, start: start + lead, end: start + lead + trimmed.length });
			}
		}
	}
	return out;
}

/** Normalises editor text for equality checks (line endings, nbsp, outer whitespace). */
export function normalizeText(text: string): string {
	return text.replace(/\r\n?/g, "\n").replace(/ /g, " ").trim();
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
	// Read at use: a custom site's adapter is resolved once its policy arrives (boot.ts).
	const sendSelector = (): string => adapter.sendButtonSelectors.join(",");
	const lang = (): Lang => resolveLanguage(deps.getPolicy()?.language, win.navigator?.language);
	const strings = (): Strings => STRINGS[lang()];

	const nativeTimeout = deps.nativeTimeoutMs ?? NATIVE_REPLY_TIMEOUT_MS;
	const nativeImageTimeout = deps.nativeImageTimeoutMs ?? NATIVE_IMAGE_REPLY_TIMEOUT_MS;

	const ui = createGuardUi({ document: doc, window: win, strings });
	const cache = new Map<string, { policy: GuardPolicy; result: GuardScan; at: number }>();
	/** Set once the user was told that native NER is unavailable; cleared when it works again. */
	let nativeNoticeShown = false;
	let lastFocused: Element | null = null;
	/** Re-entrancy token: set only while our own replayed send is being dispatched. */
	let replayText: string | null = null;
	let busy = false;
	let restoreVisible = true;
	let prescanTimer: ReturnType<typeof setTimeout> | undefined;
	let started = false;
	/** Placeholders of masked files attached since the last send (they leave with it). */
	const pendingAttachments = new Set<string>();

	const siteBlocked = (p: GuardPolicy): boolean => p.blockedSites.includes(adapter.id);
	/**
	 * Monitor semantics: nothing is masked or held back, usage is only counted. A site in
	 * `disabledSites` is monitored whatever the mode (organisation site blocks still apply).
	 */
	const monitoring = (p: GuardPolicy): boolean =>
		p.mode === "monitor" || p.disabledSites.includes(adapter.id);

	const record = (
		action: PrivacyScanEvent["action"],
		channel: PrivacyScanEvent["channel"],
		counts: Readonly<Counts>,
		native?: NativeUse,
	): void => {
		const safe: Partial<Record<EntityType, number>> = {};
		for (const [type, n] of Object.entries(counts) as [EntityType, number | undefined][]) {
			if (typeof n === "number" && n > 0) safe[type] = n;
		}
		const use = recordedNative(native);
		try {
			void Promise.resolve(
				deps.send({
					type: "RECORD",
					site: adapter.id,
					action,
					channel,
					counts: safe,
					...(use ? { native: use } : {}),
				}),
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

	const remember = (text: string, policy: GuardPolicy, result: GuardScan): void => {
		cache.delete(text);
		cache.set(text, { policy, result, at: now() });
		while (cache.size > CACHE_LIMIT) {
			const oldest = cache.keys().next().value;
			if (oldest === undefined) break;
			cache.delete(oldest);
		}
	};

	const cached = (text: string, policy: GuardPolicy): GuardScan | undefined => {
		const entry = cache.get(text);
		if (!entry || entry.policy !== policy || now() - entry.at > CACHE_TTL_MS) return undefined;
		return entry.result;
	};

	/** [start, end) offsets of this vault's placeholders in `text`. */
	const ownPlaceholderSpans = (text: string): [number, number][] => {
		const spans: [number, number][] = [];
		for (const m of text.matchAll(placeholderRegex())) {
			if (vault.lookup(m[0]) !== undefined) spans.push([m.index, m.index + m[0].length]);
		}
		return spans;
	};

	/** `text` with this vault's placeholders replaced by spaces of the same length. */
	const blankOwnPlaceholders = (text: string): string => {
		const spans = ownPlaceholderSpans(text);
		if (spans.length === 0) return text;
		let out = "";
		let cursor = 0;
		for (const [a, b] of spans) {
			out += text.slice(cursor, a) + " ".repeat(b - a);
			cursor = b;
		}
		return out + text.slice(cursor);
	};

	/** The worker's reply to `message`, or undefined when none arrives within `ms`. */
	const sendWithin = async (message: GuardMessage, ms: number): Promise<unknown> => {
		let timer: ReturnType<typeof setTimeout> | undefined;
		try {
			return await Promise.race([
				Promise.resolve(deps.send(message)),
				new Promise<undefined>((resolve) => {
					timer = win.setTimeout(() => resolve(undefined), ms);
				}),
			]);
		} finally {
			if (timer !== undefined) win.clearTimeout(timer);
		}
	};

	/**
	 * Native NER for `text` through the worker's bridge (NATIVE_SCAN), bounded in size and
	 * time. Never rejects: any failure is "unavailable" and the scan continues rules-only
	 * (or is refused by the caller under policy.requireNativeNer).
	 */
	const nativeScan = async (
		text: string,
		policy: GuardPolicy | null,
	): Promise<{ findings: readonly Finding[]; use: NativeUse }> => {
		const types = NATIVE_NER_TYPES.filter((t) => policy?.enabledEntities.includes(t));
		const enabled = policy?.useNativeHost === true || policy?.requireNativeNer === true;
		if (!enabled || types.length === 0) return { findings: [], use: "off" };
		const unavailable = { findings: [], use: "unavailable" as const };
		if (text.length > NATIVE_MAX_CHARS) return unavailable;
		try {
			const reply = await sendWithin({ type: "NATIVE_SCAN", text }, nativeTimeout);
			const found = (reply as { ok?: unknown; findings?: unknown } | undefined)?.findings;
			if ((reply as { ok?: unknown } | undefined)?.ok !== true || !Array.isArray(found))
				return unavailable;
			return { findings: found.filter((f) => isNativeFinding(f, text, types)), use: "used" };
		} catch {
			return unavailable;
		}
	};

	/**
	 * Scans text with the rule engine and, when the policy enables it, native NER in
	 * parallel. Null when the rule scan failed or was incomplete (callers fail closed);
	 * an unavailable native host only degrades the result to rules-only (`native`).
	 */
	const scan = async (text: string, policy: GuardPolicy | null): Promise<GuardScan | null> => {
		try {
			// Our own placeholders are blanked (same length, so offsets hold): a labelled
			// field such as `password: [EMAIL_1] hunter2` must be judged on the value that
			// follows the placeholder, not on the placeholder itself.
			const input = blankOwnPlaceholders(text);
			const [result, native] = await Promise.all([engine.scan(input), nativeScan(input, policy)]);
			if (!result || result.incomplete) return null;
			const merged = mergeNativeFindings(result, native.findings, native.use);
			if (native.use === "used") nativeNoticeShown = false;
			// A required NER check that did not happen is not reused: the send asks again.
			if (policy && !nativeMissing(policy, merged)) remember(text, policy, merged);
			return merged;
		} catch {
			return null;
		}
	};

	/** policy.requireNativeNer and this scan was not NER-checked: it must not pass as clean. */
	function nativeMissing(policy: GuardPolicy, result: GuardScan): boolean {
		return nativeNerRequired(policy) && result.native !== "used";
	}

	/** The "rules only" note for messages about a scan native NER should have been part of. */
	const nativeLines = (result: GuardScan | null): string[] =>
		result?.native === "unavailable" ? [strings().nativeUnavailable] : [];

	/** Tells the user once (until NER works again) that a clean prompt was checked rules-only. */
	const noticeNativeOnce = (result: GuardScan): void => {
		if (result.native !== "unavailable" || nativeNoticeShown) return;
		nativeNoticeShown = true;
		ui.toast(strings().nativeUnavailable, "warn");
	};

	/**
	 * The findings with our own placeholders cut out (see subtractPlaceholders): a
	 * placeholder is never re-masked, but sensitive text around it still is.
	 */
	const relevantFindings = (text: string, result: ScanResult): Finding[] =>
		subtractPlaceholders(text, result.findings, ownPlaceholderSpans(text));

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
		noteSent(text);
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
		scanned: GuardScan,
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
		ui.toast(
			[s.maskedToast(totalCount(counts), formatCounts(counts)), ...nativeLines(scanned)].join(" "),
			"info",
		);
		record("masked", "prompt", counts, scanned.native);
		await replay(origin, editor, masked);
	};

	const decide = async (
		policy: GuardPolicy,
		origin: SendOrigin,
		editor: EditorAccess,
		text: string,
		result: GuardScan | null,
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
		if (nativeMissing(policy, result)) {
			showBlocked([s.nativeRequired]);
			record("blocked", "prompt", counts, result.native);
			return;
		}
		const signals = activeSignals(policy, result);
		if (findings.length === 0 && signals.length === 0) {
			record("allowed", "prompt", {}, result.native);
			noticeNativeOnce(result);
			await replay(origin, editor, text);
			return;
		}
		const coaching = [
			...signals.map((code) => deps.coachingFor(code, lang())),
			...nativeLines(result),
		];
		const blocked = blockedLines(policy, findings.length > 0, signals.length > 0, counts, coaching);
		if (blocked) {
			showBlocked(blocked);
			record("blocked", "prompt", counts, result.native);
			return;
		}
		if (policy.mode === "auto" && signals.length === 0) {
			await maskAndSend(origin, editor, text, findings, result);
			return;
		}
		// confirm mode, or a warn-level signal: ask the user.
		await askUser(policy, origin, editor, text, findings, result, counts, coaching);
	};

	/** The block bubble's lines when the policy refuses this send outright, otherwise null. */
	const blockedLines = (
		policy: GuardPolicy,
		hasFindings: boolean,
		hasSignals: boolean,
		counts: Readonly<Counts>,
		coaching: readonly string[],
	): string[] | null => {
		const s = strings();
		const total = totalCount(counts);
		const summary = formatCounts(counts);
		if (hasSignals && policy.signalAction === "block") {
			return [...(total > 0 ? [s.blockedBody(total, summary)] : []), ...coaching];
		}
		if (hasFindings && policy.mode === "block") {
			return [s.blockedBody(total, summary), s.blockedCoaching, ...coaching];
		}
		return null;
	};

	/**
	 * Confirm bubble: send masked / edit (/ send original) when there are findings,
	 * edit / send anyway for a warn-level signal alone.
	 */
	const confirmBubble = (
		policy: GuardPolicy,
		hasFindings: boolean,
		counts: Readonly<Counts>,
		coaching: readonly string[],
	): BubbleOptions => {
		const s = strings();
		if (!hasFindings) {
			return {
				title: s.warnTitle,
				lines: [...coaching],
				actions: [
					{ id: "edit", label: s.edit, primary: true },
					{ id: "send-anyway", label: s.sendAnyway },
				],
				tone: "warn",
			};
		}
		const actions: BubbleAction[] = [
			{ id: "send-masked", label: s.sendMasked, primary: true },
			{ id: "edit", label: s.edit },
		];
		if (policy.allowSendAnyway) actions.push({ id: "send-original", label: s.sendOriginal });
		return {
			title: s.confirmTitle,
			lines: [s.confirmBody(totalCount(counts), formatCounts(counts)), ...coaching],
			actions,
			tone: "warn",
		};
	};

	const askUser = async (
		policy: GuardPolicy,
		origin: SendOrigin,
		editor: EditorAccess,
		text: string,
		findings: readonly Finding[],
		scanned: GuardScan,
		counts: Counts,
		coaching: readonly string[],
	): Promise<void> => {
		const s = strings();
		const choice = await ui.bubble(confirmBubble(policy, findings.length > 0, counts, coaching));
		if (choice === "send-masked") {
			await maskAndSend(origin, editor, text, findings, scanned);
			return;
		}
		if (choice === "send-original" || choice === "send-anyway") {
			if (!stillHolds(editor, text)) {
				ui.toast(s.textChanged, "warn");
				return;
			}
			record(findings.length > 0 ? "allowed" : "warned", "prompt", counts, scanned.native);
			await replay(origin, editor, text);
			return;
		}
		// Edit / Escape: nothing was sent.
		record("warned", "prompt", counts, scanned.native);
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
		// Monitor never blocks, but a required NER check that did not happen is recorded as such.
		const missing = !!result && nativeMissing(policy, result);
		if (channel === "paste" && totalCount(counts) === 0 && !missing) return;
		record("allowed", channel, counts, result?.native);
	};

	// ---- send interception ----------------------------------------------------------

	const readEditor = (editor: EditorAccess | null): string | null => {
		try {
			return editor ? editor.read() : null;
		} catch {
			return null;
		}
	};

	/** True while `text` is the prompt our own replay is re-sending. */
	const isReplay = (text: string | null): boolean =>
		replayText !== null && text !== null && normalizeText(text) === normalizeText(replayText);

	/** Stops the send and tells the user why (fail closed). */
	const refuseSend = (event: Event, line: string): void => {
		stopEvent(event);
		showBlocked([line]);
		record("blocked", "prompt", {});
	};

	const isClean = (text: string, policy: GuardPolicy, result: GuardScan): boolean =>
		!nativeMissing(policy, result) &&
		relevantFindings(text, result).length === 0 &&
		activeSignals(policy, result).length === 0;

	/** Holds the send while the prompt is scanned (or reuses a pre-scan), then decides. */
	const scanAndDecide = (
		policy: GuardPolicy,
		origin: SendOrigin,
		editor: EditorAccess,
		text: string,
		hit: GuardScan | undefined,
	): void => {
		busy = true;
		void (async () => {
			let result: GuardScan | null;
			try {
				result = hit ?? (await scan(text, policy));
			} finally {
				busy = false;
			}
			await decide(policy, origin, editor, text, result);
		})().catch(() => {
			busy = false;
			showBlocked([strings().scanFailed]);
			record("blocked", "prompt", {});
		});
	};

	/**
	 * The policy a send is checked against, or null when the send was already refused
	 * (no policy, blocked site).
	 */
	const sendPolicy = (event: Event): GuardPolicy | null => {
		const policy = deps.getPolicy();
		if (!policy) {
			refuseSend(event, strings().policyMissing);
			return null;
		}
		if (siteBlocked(policy)) {
			refuseSend(event, strings().siteBlocked);
			return null;
		}
		return policy;
	};

	const onSendAttempt = (event: Event, origin: SendOrigin, editor: EditorAccess | null): void => {
		const text = readEditor(editor);
		if (isReplay(text)) return; // our own replay of an already-checked prompt
		const policy = sendPolicy(event);
		if (!policy) return;
		if (!editor || text === null) {
			if (!monitoring(policy)) refuseSend(event, strings().editorMissing);
			return;
		}
		if (normalizeText(text) === "") return;
		if (monitoring(policy)) {
			noteSent(text);
			void monitorScan(text, "prompt", policy);
			return;
		}
		guardSend(event, policy, origin, editor, text);
	};

	/** Enforcing modes: let a pre-scanned clean prompt through, otherwise hold it and scan. */
	const guardSend = (
		event: Event,
		policy: GuardPolicy,
		origin: SendOrigin,
		editor: EditorAccess,
		text: string,
	): void => {
		if (busy) {
			stopEvent(event);
			ui.toast(strings().busy, "info");
			return;
		}
		if (ui.bubbleOpen) ui.closeBubble();
		const hit = cached(text, policy);
		if (hit && isClean(text, policy, hit)) {
			record("allowed", "prompt", {}, hit.native);
			noticeNativeOnce(hit);
			noteSent(text);
			return; // pre-scanned clean: the original, trusted event goes through untouched
		}
		stopEvent(event);
		scanAndDecide(policy, origin, editor, text, hit);
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

	/** The event's innermost target and the editor containing it; null outside the editor. */
	const editorTargetOf = (event: Event): { target: Element; editor: EditorAccess } | null => {
		const target = asElement(event.composedPath()[0] ?? event.target);
		if (!target) return null;
		const editor = editorFor(target);
		return editor && contains(editor.element, target) ? { target, editor } : null;
	};

	const onKeyDown = (event: KeyboardEvent): void => {
		if (event.key !== "Enter" || event.shiftKey || event.altKey) return;
		if (event.isComposing || event.keyCode === 229) return;
		if (ignored(event)) return;
		const hit = editorTargetOf(event);
		if (!hit) return;
		const { target, editor } = hit;
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
		const selector = sendSelector();
		let bySelector: HTMLElement | null = null;
		try {
			bySelector = selector ? target.closest<HTMLElement>(selector) : null;
		} catch {
			bySelector = null;
		}
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
		if (!policy || monitoring(policy) || siteBlocked(policy)) return;
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
		// composedPath()[0]: a file input in an open shadow root is retargeted to its host.
		const inner = asElement(event.composedPath()[0] ?? event.target);
		if (inner?.tagName === "INPUT" && (inner as HTMLInputElement).type === "file") {
			fileGuard.onInputEvent(event);
			return;
		}
		const target = asElement(event.target);
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

	const maskText = async (
		text: string,
	): Promise<{ text: string; counts: Counts } | typeof NATIVE_UNAVAILABLE | null> => {
		const policy = deps.getPolicy();
		const result = await scan(text, policy);
		if (!result) return null;
		if (policy && nativeMissing(policy, result)) return NATIVE_UNAVAILABLE;
		const findings = relevantFindings(text, result);
		if (findings.length === 0) return { text, counts: {} };
		const masked = vault.mask(text, findings);
		return { text: masked.masked, counts: { ...masked.counts } };
	};

	/** Scans pasted text, then inserts it as is, masked, or not at all (block mode). */
	const pasteScanned = async (
		editor: EditorAccess,
		text: string,
		policy: GuardPolicy,
	): Promise<void> => {
		const s = strings();
		const result = await scan(text, policy);
		if (!result) {
			showBlocked([s.pasteScanFailed]);
			record("blocked", "paste", {});
			return;
		}
		const findings = relevantFindings(text, result);
		if (nativeMissing(policy, result)) {
			showBlocked([s.nativeRequired]);
			record("blocked", "paste", countFindings(findings), result.native);
			return;
		}
		if (findings.length === 0) {
			noticeNativeOnce(result);
			await insertText(editor, text);
			return;
		}
		if (policy.mode === "block") {
			showBlocked([s.pasteBlocked, s.blockedCoaching, ...nativeLines(result)]);
			record("blocked", "paste", countFindings(findings), result.native);
			return;
		}
		const masked = vault.mask(text, findings);
		await insertText(editor, masked.masked);
		ui.toast(
			[
				s.pasteMaskedToast(totalCount(masked.counts), formatCounts(masked.counts)),
				...nativeLines(result),
			].join(" "),
			"info",
		);
		record("masked", "paste", masked.counts, result.native);
	};

	/**
	 * The policy a text paste is checked under, or null when the paste is not checked:
	 * refused (no policy, blocked site) or left to the page (maskPaste off).
	 */
	const pastePolicy = (event: Event): GuardPolicy | null => {
		const policy = deps.getPolicy();
		if (!policy) {
			stopEvent(event);
			ui.toast(strings().policyMissing, "error");
			return null;
		}
		if (siteBlocked(policy)) {
			stopEvent(event);
			showBlocked([strings().siteBlocked]);
			record("blocked", "paste", {});
			return null;
		}
		return policy.maskPaste ? policy : null;
	};

	const onPaste = (event: ClipboardEvent): void => {
		if (ignored(event) || fileGuard.replaying) return;
		if (fileGuard.onPasteFiles(event)) return;
		const editor = editorTargetOf(event)?.editor;
		if (!editor) return;
		const text = event.clipboardData?.getData("text/plain") ?? "";
		if (!text) return;
		const policy = pastePolicy(event);
		if (!policy) return;
		if (monitoring(policy)) {
			void monitorScan(text, "paste", policy);
			return;
		}
		stopEvent(event);
		pasteScanned(editor, text, policy).catch(() => {
			showBlocked([strings().rewriteFailed]);
		});
	};

	// ---- files, unmasking, lifecycle ---------------------------------------------------

	// Masked files go out when they are attached; their placeholders become restorable
	// with the next send (the one the files are attached to).
	const fileVault: PlaceholderVault = {
		mask(text, findings) {
			const result = vault.mask(text, findings);
			for (const placeholder of result.placeholders) pendingAttachments.add(placeholder);
			return result;
		},
		unmask: (text) => vault.unmask(text),
		lookup: (placeholder) => vault.lookup(placeholder),
		size: () => vault.size(),
		clear: () => vault.clear(),
		exportSession: () => vault.exportSession(),
	};

	/** OCR of an uploaded image through the worker's native bridge; null: not inspected. */
	const inspectImage = async (bytes: Uint8Array): Promise<ImageInspection | null> => {
		const policy = deps.getPolicy();
		const enabled = policy?.useNativeHost === true || policy?.requireNativeNer === true;
		if (!enabled || bytes.length > MAX_OCR_IMAGE_BYTES) return null;
		try {
			const message: GuardMessage = { type: "NATIVE_IMAGE_SCAN", data: toBase64(bytes) };
			return parseImageInspection(await sendWithin(message, nativeImageTimeout));
		} catch {
			return null;
		}
	};

	/**
	 * policy.requireNativeNer for one upload: the rule engine with native NER merged into every
	 * text scan, and OCR, both remembering whether the host ever failed to answer. A scan the
	 * host did not NER-check reports `incomplete` (the file scan then fails closed); text over
	 * NATIVE_MAX_CHARS does too, without marking the host failed, so the file sanitiser's
	 * smaller retry windows can still be NER-checked. After the host failed once, later scans
	 * of the same upload are refused at once instead of waiting for the timeout again.
	 */
	const nativeFileGate = (policy: GuardPolicy): NativeFileGate | null => {
		if (!nativeNerRequired(policy)) return null;
		let failed = false;
		const gate: NativeFileGate = {
			get failed() {
				return failed;
			},
			engine: {
				async scan(text: string): Promise<ScanResult> {
					if (failed) return NOT_NER_CHECKED;
					const [result, native] = await Promise.all([engine.scan(text), nativeScan(text, policy)]);
					if (native.use === "used") return mergeNativeFindings(result, native.findings, "used");
					if (text.length <= NATIVE_MAX_CHARS) failed = true;
					return { ...result, incomplete: true };
				},
			},
			async inspectImage(bytes: Uint8Array): Promise<ImageInspection | null> {
				const inspection = await inspectImage(bytes);
				if (inspection === null || inspection.result === "incomplete") failed = true;
				return inspection;
			},
		};
		return gate;
	};

	const fileGuard = createFileGuard({
		window: win,
		adapter,
		engine,
		vault: fileVault,
		ui,
		sanitizeFile: deps.sanitizeFile,
		getPolicy: deps.getPolicy,
		strings,
		record,
		maskText,
		inspectImage,
		nativeGate: nativeFileGate,
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

	/** Reports a send leaving the page: the vault placeholders it carries become restorable. */
	function noteSent(text: string | null): void {
		const sent = new Set(pendingAttachments);
		pendingAttachments.clear();
		for (const match of (text ?? "").matchAll(placeholderRegex())) {
			if (vault.lookup(match[0]) !== undefined) sent.add(match[0]);
		}
		unmasker.noteSent(sent);
		try {
			deps.onSent?.();
		} catch {
			// Persistence is best-effort; the send itself is unaffected.
		}
	}

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
		// Detached and shadow-DOM file inputs, routed by the page-world hook (./file-relay.ts).
		[RELAY_SCAN, (event: Event) => fileGuard.onRelayScan(event)],
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
