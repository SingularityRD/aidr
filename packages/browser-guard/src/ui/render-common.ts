/** Rendering pieces shared by the popup and the options page. */
import { type Attrs, type Child, h, icon } from "./dom.js";
import type { Translate } from "./i18n.js";

/** Visible "Managed" badge with the full explanation as tooltip and accessible name. */
export function managedBadge(doc: Document, t: Translate, id?: string): HTMLElement {
	const text = t("managed_by_org");
	return h(doc, "span", { className: "managed-badge", title: text, id, role: "note" }, [
		icon(doc, "lock", "icon icon--sm"),
		h(doc, "span", { className: "managed-badge__label" }, [t("managed_short")]),
		h(doc, "span", { className: "sr-only" }, [`: ${text}`]),
	]);
}

export interface SwitchOptions {
	readonly id: string;
	readonly label: string;
	readonly checked: boolean;
	readonly disabled?: boolean;
	readonly description?: string;
	readonly action: string;
	readonly data?: Attrs;
	readonly trailing?: Child;
}

/** Native checkbox styled as a switch (role="switch" keeps checkbox semantics). */
export function switchRow(doc: Document, options: SwitchOptions): HTMLElement {
	const descriptionId = options.description ? `${options.id}-desc` : undefined;
	const input = h(doc, "input", {
		type: "checkbox",
		role: "switch",
		className: "switch__input",
		id: options.id,
		checked: options.checked,
		disabled: options.disabled,
		"aria-describedby": descriptionId,
		"data-action": options.action,
		...options.data,
	});
	return h(doc, "div", { className: `switch-row${options.disabled ? " is-disabled" : ""}` }, [
		h(doc, "div", { className: "switch-row__text" }, [
			h(doc, "label", { className: "switch-row__label", for: options.id }, [options.label]),
			options.description
				? h(doc, "p", { className: "switch-row__desc", id: descriptionId }, [options.description])
				: null,
		]),
		options.trailing ?? null,
		h(doc, "span", { className: "switch" }, [
			input,
			h(doc, "span", { className: "switch__track", "aria-hidden": "true" }),
		]),
	]);
}

export interface Notice {
	readonly kind: "ok" | "error";
	readonly text: string;
}

/**
 * Updates the page's persistent live region (a `role="status"` element that is
 * part of the static markup, so screen readers announce changes to it).
 */
export function renderNotice(region: HTMLElement, notice: Notice | null): void {
	const doc = region.ownerDocument;
	region.className = `notice${notice ? ` notice--${notice.kind}` : ""}`;
	region.replaceChildren();
	if (!notice) return;
	region.append(
		icon(doc, notice.kind === "error" ? "alert" : "info", "icon icon--sm"),
		h(doc, "span", {}, [notice.text]),
	);
}
