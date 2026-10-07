/** Blocked-site page (static/blocked.html): names the blocked site in the heading. */
import { serviceById } from "../sites/catalog.js";
import type { Translate } from "./i18n.js";
import { SUPPORTED_SITES } from "./model.js";

/**
 * Reads the blocked site from the page URL. The background opens the page with
 * `?site=<SiteId>` (built-in blocked sites, src/background/dnr.ts) or
 * `?service=<catalog id>` (Shadow AI, src/background/shadow-ai.ts); only known ids are
 * used, so nothing from the URL is ever echoed into the page.
 */
export function blockedSiteFromUrl(href: string): string | null {
	try {
		const params = new URL(href).searchParams;
		const site = params.get("site");
		const builtIn = SUPPORTED_SITES.find((entry) => entry.id === site)?.label;
		if (builtIn) return builtIn;
		return serviceById(params.get("service"))?.name ?? null;
	} catch {
		return null;
	}
}

/** Whether the page was opened for a Shadow AI block (an unsanctioned AI service). */
export function blockedByShadowAi(href: string): boolean {
	try {
		return serviceById(new URL(href).searchParams.get("service")) !== null;
	} catch {
		return false;
	}
}

/** Fills the dynamic heading of blocked.html. Static text is handled by applyI18n. */
export function renderBlocked(
	doc: Document,
	t: Translate,
	siteLabel: string | null,
	shadowAi = false,
): void {
	const title = doc.getElementById("blocked-title");
	if (title)
		title.textContent = siteLabel ? t("blocked_title_site", siteLabel) : t("blocked_title");
	if (shadowAi) {
		const detail = doc.getElementById("blocked-detail");
		if (detail) detail.textContent = t("blocked_detail_shadow_ai");
	}
	doc.title = t("blocked_page_title");
}
