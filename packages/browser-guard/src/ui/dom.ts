/**
 * Minimal DOM builder for the UI renderers. Text is always set through
 * textContent (never innerHTML), so values such as custom terms cannot inject
 * markup.
 */

export type Child = Node | string | null | undefined | false;

export interface Attrs {
	readonly [name: string]: string | number | boolean | null | undefined;
}

function setAttribute(element: HTMLElement, name: string, value: string | number | true): void {
	if (name === "className") element.className = String(value);
	else if (name === "checked" && element instanceof HTMLInputElement) element.checked = true;
	else if (name === "value" && "value" in element) {
		(element as HTMLInputElement).value = String(value);
		element.setAttribute("value", String(value));
	} else element.setAttribute(name, value === true ? "" : String(value));
}

export function h<K extends keyof HTMLElementTagNameMap>(
	doc: Document,
	tag: K,
	attrs: Attrs = {},
	children: readonly Child[] = [],
): HTMLElementTagNameMap[K] {
	const element = doc.createElement(tag);
	for (const [name, value] of Object.entries(attrs)) {
		if (value !== null && value !== undefined && value !== false)
			setAttribute(element, name, value);
	}
	append(element, children);
	return element;
}

export function append(parent: Node, children: readonly Child[]): void {
	const doc = parent.ownerDocument ?? (parent as Document);
	for (const child of children) {
		if (child === null || child === undefined || child === false) continue;
		parent.appendChild(typeof child === "string" ? doc.createTextNode(child) : child);
	}
}

const SVG_NS = "http://www.w3.org/2000/svg";

/** Small inline icons (24x24 stroke paths). Decorative: hidden from assistive tech. */
const ICON_PATHS = {
	lock: ["M6 11h12v9H6z", "M8.5 11V8a3.5 3.5 0 0 1 7 0v3"],
	shield: ["M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z", "M9 12l2 2 4-4"],
	shieldOff: ["M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z", "M9 9l6 6", "M15 9l-6 6"],
	pause: ["M9 6v12", "M15 6v12"],
	play: ["M8 5l11 7-11 7z"],
	info: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M12 11v5", "M12 8h.01"],
	eye: ["M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z", "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"],
	trash: ["M4 7h16", "M10 11v6", "M14 11v6", "M6 7l1 13h10l1-13", "M9 7V4h6v3"],
	settings: [
		"M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
		"M19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.5 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7 7 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.5-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z",
	],
	alert: ["M12 3l10 18H2z", "M12 10v4", "M12 17h.01"],
	block: ["M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z", "M5.6 5.6l12.8 12.8"],
} as const;

export type IconName = keyof typeof ICON_PATHS;

export function icon(doc: Document, name: IconName, className = "icon"): SVGSVGElement {
	const svg = doc.createElementNS(SVG_NS, "svg");
	svg.setAttribute("viewBox", "0 0 24 24");
	svg.setAttribute("class", className);
	svg.setAttribute("aria-hidden", "true");
	svg.setAttribute("focusable", "false");
	for (const d of ICON_PATHS[name]) {
		const path = doc.createElementNS(SVG_NS, "path");
		path.setAttribute("d", d);
		svg.appendChild(path);
	}
	return svg;
}
