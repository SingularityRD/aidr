import type { SiteAdapter, SiteId } from "../types";

/**
 * Localisation-neutral fallbacks appended to every site adapter (after the
 * site-specific selectors) and used on their own by the generic adapter.
 * Site DOMs change without notice; these keep interception working on a
 * redesigned page until the specific selectors are updated.
 */
const GENERIC_SELECTORS = {
	editor: ["textarea", '[contenteditable="true"]', '[role="textbox"]'],
	send: ['button[type="submit"]', 'button[aria-label*="send" i]'],
	response: ['[data-message-author-role="assistant"]', "article", ".markdown", ".prose"],
	userMessage: ['[data-message-author-role="user"]'],
	fileInput: ['input[type="file"]'],
} as const;

export interface SiteSelectors {
	readonly id: Exclude<SiteId, "other">;
	readonly label: string;
	readonly hosts: readonly string[];
	readonly editor: readonly string[];
	readonly send: readonly string[];
	readonly response: readonly string[];
	readonly userMessage: readonly string[];
	readonly fileInput: readonly string[];
}

function merge(specific: readonly string[], fallback: readonly string[]): readonly string[] {
	return Object.freeze([...new Set([...specific, ...fallback])]);
}

/** Builds a frozen adapter: site selectors first, then the generic fallbacks (deduplicated). */
export function defineAdapter(site: SiteSelectors): SiteAdapter {
	return Object.freeze({
		id: site.id,
		label: site.label,
		hosts: Object.freeze([...site.hosts]),
		editorSelectors: merge(site.editor, GENERIC_SELECTORS.editor),
		sendButtonSelectors: merge(site.send, GENERIC_SELECTORS.send),
		responseSelectors: merge(site.response, GENERIC_SELECTORS.response),
		userMessageSelectors: merge(site.userMessage, GENERIC_SELECTORS.userMessage),
		fileInputSelectors: merge(site.fileInput, GENERIC_SELECTORS.fileInput),
	});
}

/** Adapter for any page that is not one of the supported AI chat products. */
export const GENERIC_ADAPTER: SiteAdapter = Object.freeze({
	id: "other",
	label: "Other site",
	hosts: Object.freeze([]),
	editorSelectors: Object.freeze([...GENERIC_SELECTORS.editor]),
	sendButtonSelectors: Object.freeze([...GENERIC_SELECTORS.send]),
	responseSelectors: Object.freeze([...GENERIC_SELECTORS.response]),
	userMessageSelectors: Object.freeze([...GENERIC_SELECTORS.userMessage]),
	fileInputSelectors: Object.freeze([...GENERIC_SELECTORS.fileInput]),
});
