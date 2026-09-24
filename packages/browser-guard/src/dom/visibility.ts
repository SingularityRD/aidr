/**
 * Visibility / usability checks for editor and send-button discovery.
 *
 * Real browsers answer "is this rendered?" through layout: an element that is
 * `display: none` (itself or via an ancestor) or detached has no client rects.
 * DOM implementations without a layout engine (jsdom, some prerender/snapshot
 * contexts) return no rects for *every* element, so treating "no rects" as
 * hidden there would hide everything. `hasLayout()` detects that case: the root
 * `<html>` element of a rendered document always has a client rect. Without
 * layout we fall back to style-only checks (`hidden`, `display: none` on the
 * element or an ancestor, `visibility: hidden`). Callers that need a different
 * policy can inject their own `VisibilityCheck`.
 */

export type VisibilityCheck = (element: Element) => boolean;

/** True when the document is laid out (the root element produces a client rect). */
export function hasLayout(doc: Document): boolean {
	const root = doc.documentElement;
	if (!root || typeof root.getClientRects !== "function") return false;
	return root.getClientRects().length > 0;
}

function hiddenByAttribute(element: Element): boolean {
	for (let node: Element | null = element; node; node = node.parentElement) {
		if (node.getAttribute("aria-hidden") === "true") return true;
		if (node.hasAttribute("inert")) return true;
	}
	return false;
}

function hiddenByStyle(element: Element, view: Window | null): boolean {
	if (!view || typeof view.getComputedStyle !== "function") return false;
	const own = view.getComputedStyle(element);
	if (own.visibility === "hidden" || own.visibility === "collapse") return true;
	for (let node: Element | null = element; node; node = node.parentElement) {
		if ((node as HTMLElement).hidden === true) return true;
		if (view.getComputedStyle(node).display === "none") return true;
	}
	return false;
}

/**
 * Default visibility check. Rejects detached, `aria-hidden="true"` and `inert`
 * subtrees, `visibility: hidden`; then uses layout (client rects / offsetParent)
 * when available, otherwise the style-only fallback described above.
 */
export const isVisible: VisibilityCheck = (element) => {
	if (!element.isConnected) return false;
	if (hiddenByAttribute(element)) return false;
	const doc = element.ownerDocument;
	const view = doc.defaultView;
	if (hasLayout(doc)) {
		if (view && typeof view.getComputedStyle === "function") {
			const style = view.getComputedStyle(element);
			if (style.visibility === "hidden" || style.visibility === "collapse") return false;
		}
		if (element.getClientRects().length > 0) return true;
		return (element as HTMLElement).offsetParent != null;
	}
	return !hiddenByStyle(element, view);
};

/** True for form controls / widgets that are disabled natively or via ARIA. */
export function isDisabled(element: Element): boolean {
	if ("disabled" in element && (element as HTMLButtonElement).disabled === true) return true;
	if (element.getAttribute("aria-disabled") === "true") return true;
	// A disabled <fieldset> disables every control inside it (except its first legend).
	const fieldset = element.closest("fieldset");
	if (!fieldset || fieldset === element || !fieldset.disabled) return false;
	return !fieldset.querySelector(":scope > legend")?.contains(element);
}
