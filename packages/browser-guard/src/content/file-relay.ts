/**
 * Event protocol between the page-world file-input hook (./file-input-hook.ts, injected
 * as a MAIN-world content script) and the isolated content script (./file-guard.ts).
 *
 * The two worlds share the DOM but not JavaScript objects, so everything travels on DOM
 * events dispatched on `document` whose payload is a DataTransfer (a platform object both
 * worlds can read): its files, plus string items for the request id and the verdict.
 *
 *   PING   isolated -> page   cancelable; the hook calls preventDefault() ("installed")
 *   SCAN   page -> isolated   cancelable; carries the selected files and a request id;
 *                             the guard calls preventDefault() to accept it
 *   RESULT isolated -> page   carries the request id, the verdict and (when "ok") the
 *                             files the page may see (sanitised copies or the originals)
 *
 * These events are visible to (and can be forged by) page scripts. That is acceptable:
 * the hook protects against upload code the window listeners cannot see (detached or
 * shadow-DOM inputs), not against a page that deliberately undoes it; a page can remove a
 * MAIN-world hook anyway. See the README "Limitations".
 */

export const RELAY_PING = "aidr-file-hook-ping";
export const RELAY_SCAN = "aidr-file-scan";
export const RELAY_RESULT = "aidr-file-result";

/** DataTransfer string items used by the protocol. */
export const RELAY_ID_FORMAT = "application/x-aidr-request";
export const RELAY_VERDICT_FORMAT = "application/x-aidr-verdict";

type Win = Window & typeof globalThis;

/** An event of `type` carrying `data` as its `dataTransfer` (a DragEvent where possible). */
export function relayEvent(
	win: Window,
	type: string,
	data: DataTransfer,
	cancelable: boolean,
): Event {
	const w = win as Win;
	if (typeof w.DragEvent === "function") {
		try {
			const event = new w.DragEvent(type, { cancelable, dataTransfer: data });
			if (event.dataTransfer === data) return event;
		} catch {
			// fall through
		}
	}
	// Same-world fallback (engines whose DragEvent ignores dataTransfer, and tests).
	const event = new w.Event(type, { cancelable });
	Object.defineProperty(event, "dataTransfer", { value: data });
	return event;
}

export function relayData(event: Event): DataTransfer | null {
	return (event as DragEvent).dataTransfer ?? null;
}

/** True when an input's events reach window-level listeners with the input as target. */
export function isDocumentRooted(input: Node): boolean {
	return input.isConnected && input.getRootNode() === input.ownerDocument;
}
