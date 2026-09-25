/**
 * Adapters for company-internal AI portals configured by the administrator (managed key
 * `customSites`, validated by src/background/policy.ts). Their selectors come first, then
 * the same localisation-neutral fallbacks every built-in adapter carries.
 *
 * Selectors are data from policy: one that the page's selector engine rejects would make
 * `closest()` / `querySelectorAll()` throw inside the guard, so every selector is checked
 * against a real parser when a DOM is available and dropped when it does not parse.
 */
import type { CustomSiteConfig, SiteAdapter } from "../types";
import { defineAdapter } from "./generic";

export const CUSTOM_SITE_LIMITS = Object.freeze({
	maxSites: 20,
	maxHostsPerSite: 10,
	maxSelectorsPerList: 20,
	maxSelectorChars: 256,
	maxLabelChars: 64,
});

/** Rule/markup syntax and control characters: never part of a selector from policy. */
export const SELECTOR_FORBIDDEN = /[{};<\u0000-\u001f\u007f]/;

/** True when `selector` is a non-empty CSS selector the current DOM (if any) accepts. */
export function isUsableSelector(selector: unknown): selector is string {
	if (typeof selector !== "string") return false;
	const trimmed = selector.trim();
	if (trimmed.length === 0 || selector.length > CUSTOM_SITE_LIMITS.maxSelectorChars) return false;
	// Rule/markup syntax and control characters never belong in a selector list from policy.
	if (SELECTOR_FORBIDDEN.test(selector)) return false;
	const doc = (globalThis as { document?: Document }).document;
	if (!doc?.createDocumentFragment) return true;
	try {
		doc.createDocumentFragment().querySelector(selector);
		return true;
	} catch {
		return false;
	}
}

const usable = (list: readonly string[]): string[] => list.filter(isUsableSelector);

/** Frozen adapter (id "custom") for one configured internal portal. */
export function customAdapter(site: CustomSiteConfig): SiteAdapter {
	return defineAdapter({
		id: "custom",
		label: site.label,
		hosts: site.hosts,
		editor: usable(site.editorSelectors),
		send: usable(site.sendButtonSelectors),
		response: usable(site.responseSelectors),
		userMessage: [],
		fileInput: [],
	});
}

/** The configured site that lists `hostname` exactly, or null. */
export function customSiteForHost(
	hostname: string,
	customSites: readonly CustomSiteConfig[] | undefined,
): CustomSiteConfig | null {
	if (!Array.isArray(customSites)) return null;
	const host = hostname.toLowerCase();
	return (
		customSites.find((site) => Array.isArray(site?.hosts) && site.hosts.includes(host)) ?? null
	);
}
