/**
 * File upload interception for the content script: `<input type=file>` selections,
 * drag-and-drop and pasted files.
 *
 * Every file is read locally and passed to `sanitizeFile` before the page sees it.
 * Masked files replace the originals through a DataTransfer, and the original
 * event is replayed once so the site's own upload handler receives only sanitized
 * content. Anything that cannot be checked or replaced is blocked (fail closed).
 *
 * Window capture listeners only see inputs rooted in the document. Detached inputs
 * (`createElement` + `click()`) and inputs in shadow roots are handled by the page-world
 * hook (./file-input-hook.ts), which hands their selections to `onRelayScan`; a
 * shadow-DOM selection seen here while that hook is missing is blocked.
 */

import { type Counts, mergeCounts } from "../engine/counts.js";
import { isDocumentFile } from "../engine/files.js";
import type {
	DetectionEngine,
	FileDecision,
	GuardPolicy,
	ImageInspection,
	PlaceholderVault,
	PrivacyScanEvent,
	SiteAdapter,
} from "../types.js";
import {
	isDocumentRooted,
	RELAY_ID_FORMAT,
	RELAY_PING,
	RELAY_RESULT,
	RELAY_VERDICT_FORMAT,
	relayData,
	relayEvent,
} from "./file-relay.js";
import { formatCounts, type Strings } from "./strings.js";
import type { GuardUi } from "./ui.js";

type InspectImageFn = (bytes: Uint8Array) => Promise<ImageInspection | null>;

export type SanitizeFileFn = (
	file: { name: string; type: string; bytes: Uint8Array },
	deps: {
		engine: DetectionEngine;
		vault: PlaceholderVault;
		policy: GuardPolicy;
		inspectImage?: InspectImageFn;
	},
) => Promise<FileDecision>;

export interface FileGuardDeps {
	readonly window: Window;
	readonly adapter: SiteAdapter;
	readonly engine: DetectionEngine;
	readonly vault: PlaceholderVault;
	readonly ui: GuardUi;
	readonly sanitizeFile: SanitizeFileFn;
	getPolicy(): GuardPolicy | null;
	strings(): Strings;
	record(
		action: PrivacyScanEvent["action"],
		channel: PrivacyScanEvent["channel"],
		counts: Counts,
	): void;
	/** Masks clipboard text that accompanies pasted files; null means it could not be checked. */
	maskText(text: string): Promise<{ text: string; counts: Counts } | null>;
	/** OCR through the native host (policy.useNativeHost); absent or null: not inspected. */
	inspectImage?: InspectImageFn;
}

export interface FileGuard {
	/** Capture listener for `input` and `change`. */
	onInputEvent(event: Event): void;
	/** Capture listener for RELAY_SCAN requests from the page-world file-input hook. */
	onRelayScan(event: Event): void;
	/** Capture listener for `drop`. */
	onDrop(event: DragEvent): void;
	/** Handles a paste that carries files. Returns true when it took over the event. */
	onPasteFiles(event: ClipboardEvent): boolean;
	/** True while this module is replaying a sanitized event. */
	readonly replaying: boolean;
}

type Win = Window & typeof globalThis;

/** An upload that may proceed; `sanitizeAll` builds it up file by file. */
interface OkOutcome {
	readonly kind: "ok";
	readonly files: File[];
	masked: number;
	/** Warnings for files that pass without a complete check (binary, legacy, images...). */
	readonly warnings: string[];
	readonly counts: Counts;
}

type Outcome =
	| OkOutcome
	| {
			readonly kind: "blocked";
			readonly name: string;
			readonly reasons: readonly string[];
			readonly counts: Counts;
	  }
	| { readonly kind: "error" };

/** Bubble text for a blocked upload: reason codes, counts, and a hint for what to do instead. */
function blockedMessage(
	s: Strings,
	outcome: { readonly name: string; readonly reasons: readonly string[]; readonly counts: Counts },
): string {
	const summary = formatCounts(outcome.counts);
	const reasons = [...outcome.reasons, ...(summary ? [summary] : [])].join(", ");
	const has = (code: string) => outcome.reasons.includes(code);
	const hints = [
		...(has("SENSITIVE_DATA_IN_PDF") ? [s.pdfPasteHint] : []),
		...(has("SENSITIVE_DATA_IN_IMAGE") ? [s.imageBlockedHint] : []),
		...(has("LEGACY_OFFICE_FORMAT") ? [s.legacyOfficeHint] : []),
		...(has("SENSITIVE_DATA_IN_LEGACY_OFFICE") ? [s.legacyOfficeSensitiveHint] : []),
	];
	return [s.fileBlockedBody(outcome.name, reasons), ...hints].join(" ");
}

/** Why an allowed/masked file was not fully checked, as a user message (null: fully checked). */
function passWarning(s: Strings, name: string, reasons: readonly string[]): string | null {
	if (reasons.includes("LEGACY_OFFICE_FORMAT")) return s.legacyOfficeToast(name);
	if (reasons.includes("IMAGE_NOT_INSPECTED")) return s.imageUnscannedToast(name);
	if (reasons.includes("PDF_IMAGES_NOT_INSPECTED")) return s.pdfImagesUnscannedToast(name);
	if (reasons.some((r) => r.startsWith("BINARY_FILE"))) return s.fileUnscannedToast(name);
	if (reasons.includes("DOCUMENT_IMAGES_NOT_INSPECTED")) return s.documentImagesToast(name);
	return null;
}

async function readFileBytes(file: Blob, win: Window): Promise<Uint8Array> {
	if (typeof file.arrayBuffer === "function") return new Uint8Array(await file.arrayBuffer());
	const Reader = (win as Win).FileReader;
	return new Promise((resolve, reject) => {
		const reader = new Reader();
		reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
		reader.onerror = () => reject(reader.error ?? new Error("FILE_READ_FAILED"));
		reader.readAsArrayBuffer(file);
	});
}

const isFileInput = (node: EventTarget | null): node is HTMLInputElement =>
	!!node &&
	(node as Element).nodeType === 1 &&
	(node as Element).tagName === "INPUT" &&
	(node as HTMLInputElement).type === "file";

/** The event's innermost target when it is a file input (an input in an open shadow root is retargeted to its host). */
function fileInputOf(event: Event): HTMLInputElement | null {
	const inner = event.composedPath()[0] ?? event.target;
	return isFileInput(inner) ? inner : null;
}

function transferFiles(data: DataTransfer | null | undefined): File[] {
	if (!data) return [];
	if (data.files && data.files.length > 0) return [...data.files];
	const out: File[] = [];
	for (const item of data.items ?? []) {
		if (item.kind === "file") {
			const file = item.getAsFile();
			if (file) out.push(file);
		}
	}
	return out;
}

function makeTransferEvent(
	win: Win,
	type: "drop" | "paste",
	data: DataTransfer,
	source: Event,
): Event {
	const init = { bubbles: true, cancelable: true, composed: true };
	if (type === "drop") {
		const mouse = source as DragEvent;
		const dragInit = {
			...init,
			clientX: mouse.clientX ?? 0,
			clientY: mouse.clientY ?? 0,
			screenX: mouse.screenX ?? 0,
			screenY: mouse.screenY ?? 0,
			dataTransfer: data,
		};
		if (typeof win.DragEvent === "function") {
			const event = new win.DragEvent("drop", dragInit);
			if (event.dataTransfer === data) return event;
		}
		const event = new win.Event("drop", init);
		Object.defineProperty(event, "dataTransfer", { value: data });
		return event;
	}
	if (typeof win.ClipboardEvent === "function") {
		const event = new win.ClipboardEvent("paste", { ...init, clipboardData: data });
		if (event.clipboardData === data) return event;
	}
	const event = new win.Event("paste", init);
	Object.defineProperty(event, "clipboardData", { value: data });
	return event;
}

export function createFileGuard(deps: FileGuardDeps): FileGuard {
	const win = deps.window as Win;
	const inFlight = new WeakSet<HTMLInputElement>();
	let replaying = false;

	const siteBlocked = (policy: GuardPolicy): boolean =>
		policy.blockedSites.includes(deps.adapter.id);
	const siteDisabled = (policy: GuardPolicy): boolean =>
		policy.disabledSites.includes(deps.adapter.id);

	const stop = (event: Event): void => {
		if (event.cancelable) event.preventDefault();
		event.stopImmediatePropagation();
	};

	const showBlocked = (message: string): void => {
		const s = deps.strings();
		void deps.ui.bubble({
			title: s.fileBlockedTitle,
			lines: [message],
			actions: [{ id: "close", label: s.close, primary: true }],
			tone: "error",
		});
	};

	/** Sanitises one file into `batch`; returns an outcome only when the whole upload must stop. */
	const sanitizeInto = async (
		batch: OkOutcome,
		file: File,
		policy: GuardPolicy,
	): Promise<Outcome | null> => {
		const { counts } = batch;
		if (file.size > policy.maxFileBytes) {
			return { kind: "blocked", name: file.name, reasons: ["FILE_TOO_LARGE"], counts };
		}
		const bytes = await readFileBytes(file, win);
		const decision = await deps.sanitizeFile(
			{ name: file.name, type: file.type, bytes },
			{
				engine: deps.engine,
				vault: deps.vault,
				policy,
				...(deps.inspectImage ? { inspectImage: deps.inspectImage } : {}),
			},
		);
		mergeCounts(counts, decision.counts);
		if (decision.action === "block") {
			return { kind: "blocked", name: file.name, reasons: decision.reasons, counts };
		}
		const warning = passWarning(deps.strings(), file.name, decision.reasons);
		if (warning) batch.warnings.push(warning);
		if (decision.action === "mask") {
			if (!decision.masked) return { kind: "error" };
			const { name, type, bytes: cleaned } = decision.masked;
			batch.files.push(
				new win.File([new Uint8Array(cleaned)], name, { type, lastModified: Date.now() }),
			);
			batch.masked++;
			return null;
		}
		batch.files.push(file);
		return null;
	};

	const sanitizeAll = async (files: readonly File[], policy: GuardPolicy): Promise<Outcome> => {
		const batch: OkOutcome = { kind: "ok", files: [], masked: 0, warnings: [], counts: {} };
		try {
			for (const file of files) {
				const stopped = await sanitizeInto(batch, file, policy);
				if (stopped) return stopped;
			}
		} catch {
			return { kind: "error" };
		}
		return batch;
	};

	/** Reports a finished outcome; returns the replacement files when the upload may proceed. */
	const settle = (outcome: Outcome): File[] | null => {
		const s = deps.strings();
		if (outcome.kind === "error") {
			showBlocked(s.fileScanFailed);
			deps.record("blocked", "file", {});
			return null;
		}
		if (outcome.kind === "blocked") {
			showBlocked(blockedMessage(s, outcome));
			deps.record("blocked", "file", outcome.counts);
			return null;
		}
		const masked =
			outcome.masked > 0 ? [s.fileMaskedToast(outcome.masked, formatCounts(outcome.counts))] : [];
		// Anything that passed without a complete check is a warning, never a silent pass.
		if (outcome.warnings.length > 0)
			deps.ui.toast([...masked, ...outcome.warnings].join(" "), "warn");
		else if (masked.length > 0) deps.ui.toast(masked[0] as string, "info");
		deps.record(outcome.masked > 0 ? "masked" : "allowed", "file", outcome.counts);
		return outcome.files;
	};

	const monitor = (files: readonly File[], policy: GuardPolicy): void => {
		void sanitizeAll(files, policy).then((outcome) => {
			deps.record("allowed", "file", outcome.kind === "error" ? {} : outcome.counts);
		});
	};

	const buildTransfer = (files: readonly File[]): DataTransfer => {
		const data = new win.DataTransfer();
		for (const file of files) data.items.add(file);
		return data;
	};

	const replay = (fn: () => void): void => {
		replaying = true;
		try {
			fn();
		} finally {
			replaying = false;
		}
	};

	const refuse = (message: string): "blocked" => {
		showBlocked(message);
		deps.record("blocked", "file", {});
		return "blocked";
	};

	/** Why an organisation rule blocks these uploads here (in every mode), or null. */
	const blockedBy = (policy: GuardPolicy, files: readonly File[]): string | null => {
		if (siteBlocked(policy)) return deps.strings().siteBlocked;
		if (policy.fileHandling === "block") return deps.strings().fileBlockedByPolicy;
		if (
			policy.fileHandling === "scan" &&
			policy.documentHandling === "block" &&
			files.some(isDocumentFile)
		)
			return deps.strings().documentBlockedByPolicy;
		return null;
	};

	/**
	 * Uploads left to the page: file handling "allow", or monitor mode / a site the user
	 * disabled (recorded only).
	 */
	const passesThrough = (event: Event, files: readonly File[], policy: GuardPolicy): boolean => {
		if (policy.fileHandling === "allow") return true;
		if (policy.mode !== "monitor" && !siteDisabled(policy)) return false;
		// input and change both fire for one selection: record it once.
		if (event.type !== "input") monitor(files, policy);
		return true;
	};

	/** Common gate. Returns the policy when the event must be taken over, or null to let it pass. */
	const gate = (event: Event, files: readonly File[]): GuardPolicy | "blocked" | null => {
		const policy = deps.getPolicy();
		if (!policy) {
			stop(event);
			return refuse(deps.strings().policyMissing);
		}
		// Site blocks and file blocks are organisation rules: enforced in every mode, and
		// on sites the user disabled (which are monitored, see ./guard.ts).
		const blockMessage = blockedBy(policy, files);
		if (blockMessage === null && passesThrough(event, files, policy)) return null;
		stop(event);
		if (blockMessage !== null) return refuse(blockMessage);
		if (typeof win.DataTransfer !== "function") {
			return refuse(deps.strings().fileReplaceUnsupported);
		}
		return policy;
	};

	const clearInput = (input: HTMLInputElement): void => {
		try {
			input.value = "";
		} catch {
			// Some engines reject programmatic value writes on file inputs; files are replaced below.
		}
	};

	/** True when the page-world hook (./file-input-hook.ts) answers the ping. */
	const pageHookInstalled = (): boolean => {
		try {
			return !win.document.dispatchEvent(new win.Event(RELAY_PING, { cancelable: true }));
		} catch {
			return false;
		}
	};

	/**
	 * A shadow-DOM input's `input` event: its `change` never reaches this listener, so the
	 * page-world hook handles it. Without the hook the selection cannot be guarded: block it.
	 */
	const onShadowInput = (event: Event, input: HTMLInputElement): void => {
		if (pageHookInstalled()) return;
		stop(event);
		clearInput(input);
		refuse(deps.strings().fileInputUnguarded);
	};

	const onInputEvent = (event: Event): void => {
		const input = replaying ? null : fileInputOf(event);
		if (!input) return;
		if (!isDocumentRooted(input)) {
			onShadowInput(event, input);
			return;
		}
		if (inFlight.has(input)) {
			event.stopImmediatePropagation();
			return;
		}
		const files = [...(input.files ?? [])];
		if (files.length === 0) return;
		const verdict = gate(event, files);
		if (verdict === "blocked") clearInput(input);
		else if (verdict !== null) replaceInputFiles(input, files, verdict);
	};

	/** Sanitises a document input's selection and replays it with the sanitised files. */
	const replaceInputFiles = (
		input: HTMLInputElement,
		files: readonly File[],
		policy: GuardPolicy,
	): void => {
		inFlight.add(input);
		clearInput(input);
		void sanitizeAll(files, policy).then((outcome) => {
			try {
				const replacement = settle(outcome);
				if (!replacement) return;
				const data = buildTransfer(replacement);
				input.files = data.files;
				replay(() => {
					input.dispatchEvent(new win.Event("input", { bubbles: true, composed: true }));
					input.dispatchEvent(new win.Event("change", { bubbles: true }));
				});
			} finally {
				inFlight.delete(input);
			}
		});
	};

	/**
	 * Sanitises the files and masks any text pasted with them. A failed text scan fails
	 * the whole transfer; `text` is the (masked) text to put back, "" when there is none.
	 */
	const sanitizeTransfer = async (
		files: readonly File[],
		policy: GuardPolicy,
		text: string,
	): Promise<{ outcome: Outcome; text: string }> => {
		const outcome = await sanitizeAll(files, policy);
		if (outcome.kind !== "ok" || !text) return { outcome, text: "" };
		const maskedText = await deps.maskText(text);
		if (!maskedText) return { outcome: { kind: "error" }, text: "" };
		const counts = mergeCounts({ ...outcome.counts }, maskedText.counts);
		return { outcome: { ...outcome, counts }, text: maskedText.text };
	};

	const takeOverTransfer = (
		event: Event,
		type: "drop" | "paste",
		files: readonly File[],
		text: string,
	): boolean => {
		const verdict = gate(event, files);
		if (verdict === null) return false;
		if (verdict === "blocked") return true;
		const target = (event.composedPath()[0] ?? event.target) as Node | null;
		void (async () => {
			const sanitized = await sanitizeTransfer(files, verdict, text);
			const replacement = settle(sanitized.outcome);
			if (!replacement) return;
			const data = buildTransfer(replacement);
			if (sanitized.text) data.setData("text/plain", sanitized.text);
			const dispatchTarget = target?.isConnected
				? target
				: (deps.window.document.body as Node | null);
			if (!dispatchTarget) return;
			replay(() => {
				dispatchTarget.dispatchEvent(makeTransferEvent(win, type, data, event));
			});
		})();
		return true;
	};

	/** Answers a page-world hook request with the files the page may see (or a block). */
	const answerRelay = (id: string, files: readonly File[] | null): void => {
		try {
			const data = new win.DataTransfer();
			for (const file of files ?? []) data.items.add(file);
			data.setData(RELAY_ID_FORMAT, id);
			data.setData(RELAY_VERDICT_FORMAT, files ? "ok" : "blocked");
			win.document.dispatchEvent(relayEvent(win, RELAY_RESULT, data, false));
		} catch {
			// No answer: the hook times out and keeps the selection cleared (fail closed).
		}
	};

	/**
	 * A selection from a detached or shadow-DOM file input, handed over by the page-world
	 * hook (./file-relay.ts). Same rules as a document input: organisation blocks, pass-
	 * through for "allow"/monitor, otherwise sanitised; anything else is refused.
	 */
	const onRelayScan = (event: Event): void => {
		const data = relayData(event);
		const id = data?.getData(RELAY_ID_FORMAT);
		if (!data || !id) return;
		if (event.cancelable) event.preventDefault(); // accepted: the hook waits for RESULT
		event.stopImmediatePropagation();
		const files = transferFiles(data);
		if (files.length === 0) {
			answerRelay(id, []);
			return;
		}
		const policy = deps.getPolicy();
		if (!policy) {
			refuse(deps.strings().policyMissing);
			answerRelay(id, null);
			return;
		}
		const blockMessage = blockedBy(policy, files);
		if (blockMessage !== null) {
			refuse(blockMessage);
			answerRelay(id, null);
			return;
		}
		if (passesThrough(event, files, policy)) {
			answerRelay(id, files);
			return;
		}
		void sanitizeAll(files, policy).then((outcome) => {
			answerRelay(id, settle(outcome));
		});
	};

	return {
		onInputEvent,
		onRelayScan,
		onDrop(event) {
			if (replaying || deps.ui.isOwnEvent(event)) return;
			const files = transferFiles(event.dataTransfer);
			if (files.length === 0) return;
			takeOverTransfer(event, "drop", files, "");
		},
		onPasteFiles(event) {
			if (replaying) return false;
			const files = transferFiles(event.clipboardData);
			if (files.length === 0) return false;
			const text = event.clipboardData?.getData("text/plain") ?? "";
			return takeOverTransfer(event, "paste", files, text);
		},
		get replaying() {
			return replaying;
		},
	};
}
