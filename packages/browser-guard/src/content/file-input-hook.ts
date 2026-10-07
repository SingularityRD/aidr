/**
 * Page-world (MAIN) hook for `<input type=file>` elements the isolated content script
 * cannot intercept: inputs that were never attached (`createElement("input")` +
 * `click()`, a common upload pattern) and inputs inside shadow roots (their `change`
 * event is not composed, and a closed root hides the input from window listeners). The
 * window-level capture listeners in ./guard.ts keep handling ordinary document inputs.
 *
 * For such an input the hook makes sure the page never sees an unchecked selection:
 *   - `HTMLInputElement.prototype.click` / `showPicker` register capture listeners on the
 *     input, which stop its `input`/`change` events while the selection is unchecked;
 *   - the `files` getter returns an empty FileList for an unchecked selection (also
 *     covering inputs whose picker the user opened directly, and page listeners
 *     registered before ours);
 * and hands the files to the isolated guard (./file-relay.ts). The guard sanitises them
 * like any other upload; the hook then puts the files the guard returned into the
 * input and replays `input` + `change`. Fail closed: when the guard does not accept
 * the request or does not answer in time, or blocks the files, the selection is
 * cleared and nothing is released.
 *
 * Out of scope (README "Limitations"): forms submitted natively (or `new FormData(form)`)
 * read a shadow/detached input's files without the getter, and a page can undo this
 * hook, as it runs in the page's own JavaScript world.
 */
import {
	isDocumentRooted,
	RELAY_ID_FORMAT,
	RELAY_PING,
	RELAY_RESULT,
	RELAY_SCAN,
	RELAY_VERDICT_FORMAT,
	relayData,
	relayEvent,
} from "./file-relay.js";

type Win = Window & typeof globalThis;

/** How long a selection waits for the guard (sanitising can OCR several images). */
export const RELAY_TIMEOUT_MS = 10 * 60_000;

const HOOK_FLAG = "__aidrFileInputHook";

export interface FileInputHook {
	/** Removes the hook (tests). */
	uninstall(): void;
}

export function installFileInputHook(
	win: Window,
	options: { timeoutMs?: number } = {},
): FileInputHook | null {
	const w = win as Win & Record<string, unknown>;
	if (w[HOOK_FLAG]) return null;
	const proto = w.HTMLInputElement?.prototype;
	const filesDesc = proto && Object.getOwnPropertyDescriptor(proto, "files");
	const valueDesc = proto && Object.getOwnPropertyDescriptor(proto, "value");
	if (!proto || !filesDesc?.get || !filesDesc.set || !valueDesc?.set) return null;
	w[HOOK_FLAG] = true;

	const timeoutMs = options.timeoutMs ?? RELAY_TIMEOUT_MS;
	const nativeFiles = filesDesc.get;
	const setFiles = filesDesc.set;
	const setValue = valueDesc.set;
	const nativeClick = proto.click;
	const nativeShowPicker = (proto as { showPicker?: () => void }).showPicker;
	const doc = win.document;

	/** The FileList the guard released for an input (identity of the native list). */
	const approved = new WeakMap<HTMLInputElement, FileList>();
	const pending = new WeakSet<HTMLInputElement>();
	const watched = new WeakSet<HTMLInputElement>();
	const waiting = new Map<string, (data: DataTransfer | null) => void>();
	let replaying = false;
	let counter = 0;

	const isFileInput = (el: unknown): el is HTMLInputElement =>
		el instanceof w.HTMLInputElement && el.type === "file";
	const needsHook = (input: HTMLInputElement): boolean => !isDocumentRooted(input);
	const emptyFiles = (): FileList => new w.DataTransfer().files;
	const unchecked = (input: HTMLInputElement, list: FileList | null): list is FileList =>
		!!list && list.length > 0 && approved.get(input) !== list;

	const clear = (input: HTMLInputElement): void => {
		try {
			setValue.call(input, "");
		} catch {
			setFiles.call(input, emptyFiles());
		}
	};

	const release = (input: HTMLInputElement, data: DataTransfer): void => {
		setFiles.call(input, data.files);
		approved.set(input, nativeFiles.call(input) as FileList);
		replaying = true;
		try {
			input.dispatchEvent(new w.Event("input", { bubbles: true, composed: true }));
			input.dispatchEvent(new w.Event("change", { bubbles: true }));
		} finally {
			replaying = false;
		}
	};

	/** Hands an unchecked selection to the guard; nothing is released until it answers. */
	const route = (input: HTMLInputElement, list: FileList): void => {
		if (pending.has(input)) return;
		const files = [...list];
		clear(input);
		pending.add(input);
		const id = `${Date.now().toString(36)}-${(counter++).toString(36)}`;
		const done = (data: DataTransfer | null): void => {
			if (!waiting.delete(id)) return;
			w.clearTimeout(timer);
			// Released in a later task, so the rest of the user's selection events (the
			// `change` after `input`) are still held back as pending and the page sees the
			// selection exactly once, from the replay.
			w.setTimeout(() => {
				pending.delete(input);
				if (data && data.getData(RELAY_VERDICT_FORMAT) === "ok") release(input, data);
			}, 0);
		};
		waiting.set(id, done);
		const timer = w.setTimeout(() => done(null), timeoutMs);
		let accepted = false;
		try {
			const data = new w.DataTransfer();
			for (const file of files) data.items.add(file);
			data.setData(RELAY_ID_FORMAT, id);
			accepted = !doc.dispatchEvent(relayEvent(win, RELAY_SCAN, data, true));
		} catch {
			accepted = false;
		}
		if (!accepted) done(null); // no guard listening: the selection stays cleared
	};

	const onInputEvent = (event: Event): void => {
		if (replaying) return;
		const input = event.currentTarget as HTMLInputElement;
		const list = nativeFiles.call(input) as FileList | null;
		if (!pending.has(input) && !unchecked(input, list)) return;
		event.stopImmediatePropagation();
		if (list && unchecked(input, list)) route(input, list);
	};

	const watch = (input: HTMLInputElement): void => {
		if (watched.has(input)) return;
		watched.add(input);
		input.addEventListener("input", onInputEvent, true);
		input.addEventListener("change", onInputEvent, true);
	};

	const onResult = (event: Event): void => {
		const data = relayData(event);
		const id = data?.getData(RELAY_ID_FORMAT);
		const resolve = id ? waiting.get(id) : undefined;
		if (resolve) resolve(data);
	};
	const onPing = (event: Event): void => {
		if (event.cancelable) event.preventDefault();
	};

	const filesGetter = function (this: HTMLInputElement): FileList | null {
		const list = nativeFiles.call(this) as FileList | null;
		if (!isFileInput(this) || !needsHook(this)) return list;
		if (pending.has(this)) return emptyFiles();
		if (!unchecked(this, list)) return list;
		route(this, list);
		return emptyFiles();
	};
	const wrap = (native: (() => void) | undefined) =>
		native &&
		function (this: HTMLInputElement): void {
			if (isFileInput(this) && needsHook(this)) watch(this);
			native.call(this);
		};

	Object.defineProperty(proto, "files", { ...filesDesc, get: filesGetter });
	const click = wrap(nativeClick);
	if (click) proto.click = click;
	const showPicker = wrap(nativeShowPicker);
	if (showPicker) (proto as { showPicker?: () => void }).showPicker = showPicker;
	w.addEventListener(RELAY_RESULT, onResult, true);
	w.addEventListener(RELAY_PING, onPing, true);

	return {
		uninstall() {
			Object.defineProperty(proto, "files", filesDesc);
			proto.click = nativeClick;
			if (nativeShowPicker) (proto as { showPicker?: () => void }).showPicker = nativeShowPicker;
			w.removeEventListener(RELAY_RESULT, onResult, true);
			w.removeEventListener(RELAY_PING, onPing, true);
			for (const resolve of [...waiting.values()]) resolve(null);
			delete w[HOOK_FLAG];
		},
	};
}
