/**
 * Shared fakes for the content-script tests (jsdom). Not a test file itself.
 *
 * The engine is a deterministic fake (e-mail regex + configurable signals); the
 * vault and the editor access are the real implementations so interception, the
 * masked rewrite and the synthetic-event bookkeeping are exercised end to end.
 */
import { vi } from "vitest";
import { type ContentGuard, createContentGuard } from "../content/guard";
import { editorAccess, insertAtSelection, isSyntheticEditorEvent } from "../dom/editor";
import { createVault } from "../engine/vault";
import type {
	DetectionEngine,
	FileDecision,
	Finding,
	GuardMessage,
	GuardPolicy,
	PlaceholderVault,
	ScanResult,
	SignalCode,
	SiteAdapter,
} from "../types";

export const EMAIL = "jane.doe@example.com";

export const ADAPTER: SiteAdapter = {
	id: "chatgpt",
	label: "ChatGPT",
	hosts: ["chatgpt.com"],
	editorSelectors: ["#editor"],
	sendButtonSelectors: ["#send"],
	responseSelectors: ['[data-role="assistant"]'],
	userMessageSelectors: ['[data-role="user"]'],
	fileInputSelectors: ['input[type="file"]'],
};

export const BASE_POLICY: GuardPolicy = {
	version: 1,
	mode: "auto",
	enabledEntities: ["EMAIL"],
	neverRestore: ["SECRET"],
	literals: [],
	exactData: [],
	detectSignals: true,
	signalAction: "warn",
	blockedSites: [],
	disabledSites: [],
	allowUserPause: true,
	allowSendAnyway: false,
	maskPaste: true,
	fileHandling: "scan",
	maxFileBytes: 1_000_000,
	restoreResponses: true,
	useNativeHost: false,
	telemetry: null,
	language: "en",
	managedKeys: [],
	policyId: "test-policy",
};

/** Scans for e-mail addresses; `signals` are reported when the text contains "ignore previous". */
export function fakeEngine(
	options: { signals?: SignalCode[]; fail?: "throw" | "incomplete" } = {},
): DetectionEngine & { scan: ReturnType<typeof vi.fn> } {
	const scan = vi.fn(async (text: string): Promise<ScanResult> => {
		if (options.fail === "throw") throw new Error("ENGINE_DOWN");
		const findings: Finding[] = [];
		for (const m of text.matchAll(/[\w.+-]+@[\w-]+\.[\w.]+/g)) {
			findings.push({
				type: "EMAIL",
				start: m.index,
				end: m.index + m[0].length,
				score: 0.99,
				source: "rule",
			});
		}
		const signals = /ignore previous/i.test(text) ? (options.signals ?? []) : [];
		return {
			findings,
			signals,
			counts: findings.length > 0 ? { EMAIL: findings.length } : {},
			incomplete: options.fail === "incomplete",
			elapsedMs: 1,
		};
	});
	return { scan };
}

export interface Harness {
	readonly guard: ContentGuard;
	readonly engine: ReturnType<typeof fakeEngine>;
	readonly vault: PlaceholderVault;
	readonly editor: HTMLTextAreaElement;
	readonly button: HTMLButtonElement;
	readonly form: HTMLFormElement;
	/** Prompts the "site" actually sent (Enter handler, send button or form submit). */
	readonly sent: string[];
	/** Every message passed to deps.send. */
	readonly messages: GuardMessage[];
	readonly sanitizeFile: ReturnType<typeof vi.fn>;
	policy: GuardPolicy | null;
	records(): Extract<GuardMessage, { type: "RECORD" }>[];
	toastText(): string;
	bubble(): HTMLElement | null;
	bubbleButton(id: string): HTMLButtonElement | null;
	enter(init?: KeyboardEventInit): KeyboardEvent;
}

export interface HarnessOptions {
	readonly policy?: Partial<GuardPolicy> | null;
	readonly engine?: ReturnType<typeof fakeEngine>;
	readonly sanitizeFile?: (file: {
		name: string;
		type: string;
		bytes: Uint8Array;
	}) => Promise<FileDecision>;
	readonly prescanDelayMs?: number;
	readonly navigatorLanguage?: string;
}

export function setupGuard(options: HarnessOptions = {}): Harness {
	document.body.innerHTML = `
		<form id="composer">
			<textarea id="editor"></textarea>
			<button id="send" type="button">Send</button>
		</form>
		<input id="file" type="file" />
		<div id="drop-zone"></div>
		<div data-role="assistant" id="answer"></div>`;
	const editor = document.getElementById("editor") as HTMLTextAreaElement;
	const button = document.getElementById("send") as HTMLButtonElement;
	const form = document.getElementById("composer") as HTMLFormElement;
	const sent: string[] = [];
	const messages: GuardMessage[] = [];

	// The "site": Enter sends (and prevents the newline), the button sends, submit sends.
	editor.addEventListener("keydown", (event) => {
		if (event.key === "Enter" && !event.shiftKey) {
			event.preventDefault();
			sent.push(editor.value);
		}
	});
	button.addEventListener("click", () => sent.push(editor.value));
	form.addEventListener("submit", (event) => {
		event.preventDefault();
		sent.push(editor.value);
	});

	const engine = options.engine ?? fakeEngine();
	const vault = createVault({ neverRestore: ["SECRET"] });
	const sanitizeFile = vi.fn(
		options.sanitizeFile ??
			(async () => ({ action: "allow", counts: {}, reasons: [] }) as FileDecision),
	);
	const harness = {
		policy: options.policy === null ? null : { ...BASE_POLICY, ...options.policy },
	} as Harness;

	if (options.navigatorLanguage) {
		Object.defineProperty(window.navigator, "language", {
			value: options.navigatorLanguage,
			configurable: true,
		});
	}

	const guard = createContentGuard({
		window,
		document,
		adapter: ADAPTER,
		engine,
		vault,
		getPolicy: () => harness.policy,
		findEditor: (_adapter, root) => {
			const el = root.getElementById("editor");
			return el ? editorAccess(el) : null;
		},
		findSendButton: (_adapter, root) => root.getElementById("send"),
		insertAtSelection,
		isSyntheticEvent: isSyntheticEditorEvent,
		sanitizeFile: (file) => sanitizeFile(file),
		coachingFor: (code, lang) => `coach:${code}:${lang}`,
		send: async (message) => {
			messages.push(message);
			return undefined;
		},
		schedule: (callback) => queueMicrotask(callback),
		prescanDelayMs: options.prescanDelayMs ?? 60_000,
	});
	guard.start();

	const root = guard.ui.root;
	Object.assign(harness, {
		guard,
		engine,
		vault,
		editor,
		button,
		form,
		sent,
		messages,
		sanitizeFile,
		records: () =>
			messages.filter((m): m is Extract<GuardMessage, { type: "RECORD" }> => m.type === "RECORD"),
		toastText: () => {
			const toast = root.querySelector<HTMLElement>('[role="status"]');
			return toast && !toast.hidden ? (toast.textContent ?? "") : "";
		},
		bubble: () => {
			const el = root.querySelector<HTMLElement>('[role="alertdialog"]');
			return el && !el.hidden ? el : null;
		},
		bubbleButton: (id: string) =>
			root.querySelector<HTMLButtonElement>(`[role="alertdialog"] button[data-action="${id}"]`),
		enter: (init: KeyboardEventInit = {}) => {
			const event = new KeyboardEvent("keydown", {
				key: "Enter",
				bubbles: true,
				cancelable: true,
				...init,
			});
			editor.dispatchEvent(event);
			return event;
		},
	});
	return harness;
}

/** Minimal DataTransfer polyfill (jsdom has none) exposing a FileList-like `files`. */
export class FakeDataTransfer {
	readonly #files: File[] = [];
	readonly #data = new Map<string, string>();
	readonly items = {
		add: (file: File) => {
			this.#files.push(file);
		},
		[Symbol.iterator]: function* (this: FakeDataTransfer) {
			// no string items
		},
	};
	get files(): FileList {
		return fileList(this.#files);
	}
	setData(format: string, value: string): void {
		this.#data.set(format, value);
	}
	getData(format: string): string {
		return this.#data.get(format) ?? "";
	}
}

export function fileList(files: readonly File[]): FileList {
	const list: Record<number, File> & { length: number; item(i: number): File | null } = {
		length: files.length,
		item: (i: number) => files[i] ?? null,
	};
	files.forEach((file, i) => {
		list[i] = file;
	});
	(list as unknown as Iterable<File>)[Symbol.iterator] = () => files[Symbol.iterator]();
	return list as unknown as FileList;
}

/**
 * jsdom's HTMLInputElement.files setter only accepts its own FileList; browsers accept
 * DataTransfer.files. Give one input a plain property so the replacement can be observed.
 */
export function makeFilesWritable(input: HTMLInputElement, initial: readonly File[]): void {
	let current = fileList(initial);
	Object.defineProperty(input, "files", {
		configurable: true,
		get: () => current,
		set: (value: FileList) => {
			current = value;
		},
	});
}

export async function readText(file: File): Promise<string> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(String(reader.result));
		reader.onerror = () => reject(reader.error);
		reader.readAsText(file);
	});
}
