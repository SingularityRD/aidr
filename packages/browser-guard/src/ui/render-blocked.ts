/** Blocked-site page (static/blocked.html): names the blocked site in the heading. */
import type { Translate } from "./i18n.js";
import { SUPPORTED_SITES } from "./model.js";

/**
 * Reads the blocked site from the redirect URL. A declarativeNetRequest redirect
 * may append `?site=<SiteId>`; only known ids are used, so nothing from the URL
 * is ever echoed into the page.
 */
export function blockedSiteFromUrl(href: string): string | null {
	try {
		const site = new URL(href).searchParams.get("site");
		return SUPPORTED_SITES.find((entry) => entry.id === site)?.label ?? null;
	} catch {
		return null;
	}
}

/** Fills the dynamic heading of blocked.html. Static text is handled by applyI18n. */
export function renderBlocked(doc: Document, t: Translate, siteLabel: string | null): void {
	const title = doc.getElementById("blocked-title");
	if (title)
		title.textContent = siteLabel ? t("blocked_title_site", siteLabel) : t("blocked_title");
	doc.title = t("blocked_page_title");
}
