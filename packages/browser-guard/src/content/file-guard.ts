/**
 * File upload interception for the content script: `<input type=file>` selections,
 * drag-and-drop and pasted files.
 *
 * Every file is read locally and passed to `sanitizeFile` before the page sees it.
 * Masked files replace the originals through a DataTransfer, and the original
 * event is replayed once so the site's own upload handler receives only sanitized
 * content. Anything that cannot be checked or replaced is blocked (fail closed).
 */
import type {
	DetectionEngine,
	EntityType,
	FileDecision,
	GuardPolicy,
	PlaceholderVault,
	PrivacyScanEvent,
	SiteAdapter,
} from "../types.js";
import { formatCounts, type Strings } from "./strings.js";
import type { GuardUi } from "./ui.js";

export type Counts = Partial<Record<EntityType, number>>;

export type SanitizeFileFn = (
	file: { name: string; type: string; bytes: Uint8Array },
	deps: { engine: DetectionEngine; vault: PlaceholderVault; policy: GuardPolicy },
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
}

export interface FileGuard {
	/** Capture listener for `input` and `change`. */
	onInputEvent(event: Event): void;
	/** Capture listener for `drop`. */
	onDrop(event: DragEvent): void;
	/** Handles a paste that carries files. Returns true when it took over the event. */
	onPasteFiles(event: ClipboardEvent): boolean;
	/** True while this module is replaying a sanitized event. */
	readonly replaying: boolean;
}

type Win = Window & typeof globalThis;

type Outcome =
	| {
			readonly kind: "ok";
			readonly files: File[];
			readonly masked: number;
			readonly unscanned: string[];
			readonly counts: Counts;
	  }
	| {
			readonly kind: "blocked";
			readonly name: string;
			readonly reasons: readonly string[];
			readonly counts: Counts;
	  }
	| { readonly kind: "error" };

export function mergeCounts(into: Counts, add: Readonly<Counts>): Counts {
	for (const [type, n] of Object.entries(add) as [EntityType, number | undefined][]) {
		if (n) into[type] = (into[type] ?? 0) + n;
	}
	return into;
}

export async function readFileBytes(file: Blob, win: Window): Promise<Uint8Array> {
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

	const sanitizeAll = async (files: readonly File[], policy: GuardPolicy): Promise<Outcome> => {
		const Ctor = win.File;
		const counts: Counts = {};
		const out: File[] = [];
		const unscanned: string[] = [];
		let masked = 0;
		try {
			for (const file of files) {
				if (file.size > policy.maxFileBytes) {
					return { kind: "blocked", name: file.name, reasons: ["FILE_TOO_LARGE"], counts };
				}
				const bytes = await readFileBytes(file, win);
				const decision = await deps.sanitizeFile(
					{ name: file.name, type: file.type, bytes },
					{ engine: deps.engine, vault: deps.vault, policy },
				);
				mergeCounts(counts, decision.counts);
				if (decision.action === "block") {
					return { kind: "blocked", name: file.name, reasons: decision.reasons, counts };
				}
				if (decision.action === "mask") {
					if (!decision.masked) return { kind: "error" };
					const { name, type, bytes: cleaned } = decision.masked;
					out.push(new Ctor([new Uint8Array(cleaned)], name, { type, lastModified: Date.now() }));
					masked++;
					continue;
				}
				if (decision.reasons.some((r) => r.startsWith("BINARY_FILE"))) unscanned.push(file.name);
				out.push(file);
			}
		} catch {
			return { kind: "error" };
		}
		return { kind: "ok", files: out, masked, unscanned, counts };
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
			const summary = formatCounts(outcome.counts);
			const reasons = [...outcome.reasons, ...(summary ? [summary] : [])].join(", ");
			showBlocked(s.fileBlockedBody(outcome.name, reasons));
			deps.record("blocked", "file", outcome.counts);
			return null;
		}
		if (outcome.masked > 0) {
			deps.ui.toast(s.fileMaskedToast(outcome.masked, formatCounts(outcome.counts)), "info");
		} else if (outcome.unscanned.length > 0) {
			deps.ui.toast(s.fileUnscannedToast(outcome.unscanned.join(", ")), "warn");
		}
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

	/** Common gate. Returns the policy when the event must be taken over, or null to let it pass. */
	const gate = (event: Event, files: readonly File[]): GuardPolicy | "blocked" | null => {
		const policy = deps.getPolicy();
		if (!policy) {
			stop(event);
			showBlocked(deps.strings().policyMissing);
			deps.record("blocked", "file", {});
			return "blocked";
		}
		if (siteDisabled(policy)) return null;
		// Site blocks and file blocks are organisation rules: enforced in every mode.
		const blocked = siteBlocked(policy) || policy.fileHandling === "block";
		if (!blocked) {
			if (policy.fileHandling === "allow") return null;
			if (policy.mode === "monitor") {
				// input and change both fire for one selection: record it once.
				if (event.type !== "input") monitor(files, policy);
				return null;
			}
		}
		stop(event);
		if (blocked) {
			showBlocked(
				siteBlocked(policy) ? deps.strings().siteBlocked : deps.strings().fileBlockedByPolicy,
			);
			deps.record("blocked", "file", {});
			return "blocked";
		}
		if (typeof win.DataTransfer !== "function") {
			showBlocked(deps.strings().fileReplaceUnsupported);
			deps.record("blocked", "file", {});
			return "blocked";
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

	const onInputEvent = (event: Event): void => {
		if (replaying) return;
		const input = event.target;
		if (!isFileInput(input)) return;
		if (inFlight.has(input)) {
			event.stopImmediatePropagation();
			return;
		}
		const files = input.files ? [...input.files] : [];
		if (files.length === 0) return;
		const verdict = gate(event, files);
		if (verdict === null) return;
		if (verdict === "blocked") {
			clearInput(input);
			return;
		}
		inFlight.add(input);
		clearInput(input);
		void sanitizeAll(files, verdict).then((outcome) => {
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
			const outcome = await sanitizeAll(files, verdict);
			let maskedText: { text: string; counts: Counts } | null = { text: "", counts: {} };
			if (outcome.kind === "ok" && text) maskedText = await deps.maskText(text);
			if (outcome.kind === "ok" && !maskedText) {
				settle({ kind: "error" });
				return;
			}
			const merged: Outcome =
				outcome.kind === "ok" && maskedText
					? { ...outcome, counts: mergeCounts({ ...outcome.counts }, maskedText.counts) }
					: outcome;
			const replacement = settle(merged);
			if (!replacement) return;
			const data = buildTransfer(replacement);
			if (maskedText?.text) data.setData("text/plain", maskedText.text);
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

	return {
		onInputEvent,
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
