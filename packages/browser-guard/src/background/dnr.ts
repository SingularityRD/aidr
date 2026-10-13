/**
 * declarativeNetRequest dynamic rules for AI chat products listed in
 * `policy.blockedSites`: top-level navigations and framed embeds are blocked, so
 * no request reaches the site.
 *
 * The explanation page (`/blocked.html?site=<id>`) is shown by the background
 * worker itself: when a tab's URL becomes a blocked site (the request was refused
 * by the rule above), `redirectBlockedTab` navigates that tab to the page with
 * `tabs.update`. That is an extension-initiated navigation, so blocked.html needs no
 * web_accessible_resources entry and web pages cannot probe for it (extension
 * fingerprinting). A DNR `redirect` would need the page to be web accessible, and
 * Chrome refuses DNR redirects to `use_dynamic_url` resources, so it is not used.
 * The installed rules are the source of truth for the redirect: the page is shown
 * exactly when the network rule is in force.
 *
 * The host list is kept here on purpose (the background must not depend on the
 * content-side site adapters). It mirrors the adapters' exact HTTPS hosts;
 * `requestDomains` also covers their subdomains, which is the safe direction for
 * a block rule. A host the site shares with another product (`SITE_PATHS`: Microsoft 365
 * Copilot Chat on `m365.cloud.microsoft`) is blocked only on the site's path, with one more
 * rule using a `regexFilter`, so the rest of that host keeps working.
 */
import { type AiServicePath, pathInScope, scopeRegexFilter } from "../sites/catalog.js";
import type { SiteId } from "../types.js";
import type { ChromeApi, DnrRule, TabInfo } from "./storage.js";

/** Built-in sites ("custom" portals have policy-defined hosts, "other" has none). */
type SupportedSite = Exclude<SiteId, "other" | "custom">;

export const SITE_HOSTS: Readonly<Record<SupportedSite, readonly string[]>> = Object.freeze({
	chatgpt: Object.freeze(["chatgpt.com", "chat.openai.com"]),
	gemini: Object.freeze(["gemini.google.com"]),
	claude: Object.freeze(["claude.ai"]),
	copilot: Object.freeze(["copilot.microsoft.com", "copilot.cloud.microsoft"]),
	perplexity: Object.freeze(["www.perplexity.ai", "perplexity.ai"]),
	deepseek: Object.freeze(["chat.deepseek.com"]),
	mistral: Object.freeze(["chat.mistral.ai"]),
	grok: Object.freeze(["grok.com"]),
});

/** Paths of shared hosts that belong to a site (the content script runs on the whole host). */
export const SITE_PATHS: Readonly<Partial<Record<SupportedSite, readonly AiServicePath[]>>> =
	Object.freeze({
		copilot: Object.freeze([Object.freeze({ host: "m365.cloud.microsoft", path: "/chat" })]),
	});

const SUPPORTED_SITES = Object.keys(SITE_HOSTS) as SupportedSite[];

/** Page a blocked top-level navigation lands on. */
const BLOCKED_PAGE_PATH = "/blocked.html";

/** Dynamic rule ids owned by this module: two per supported site (navigation + frame block). */
const DNR_RULE_ID_BASE = 7300;
const navigationRuleId = (i: number) => DNR_RULE_ID_BASE + i * 2 + 1;
const frameRuleId = (i: number) => DNR_RULE_ID_BASE + i * 2 + 2;
/** One more rule per site with `SITE_PATHS` (7381..; below the Shadow AI range 7401..). */
const pathRuleId = (i: number) => DNR_RULE_ID_BASE + 80 + i + 1;
const sitePaths = (site: SupportedSite): readonly AiServicePath[] => SITE_PATHS[site] ?? [];
export const DNR_RULE_IDS: readonly number[] = Object.freeze(
	SUPPORTED_SITES.flatMap((site, i) => [
		navigationRuleId(i),
		frameRuleId(i),
		...(sitePaths(site).length ? [pathRuleId(i)] : []),
	]),
);

/** Exact hosts the content script runs on: the site hosts plus its shared hosts. */
const HOST_TO_SITE: ReadonlyMap<string, SupportedSite> = new Map(
	SUPPORTED_SITES.flatMap((site) =>
		[...SITE_HOSTS[site], ...sitePaths(site).map((p) => p.host)].map(
			(host) => [host, site] as const,
		),
	),
);

/**
 * Site for a page/frame URL: exact https host of a supported site (no port, no
 * credentials), otherwise null. Used to decide which tabs may talk to the worker.
 */
export function siteForUrl(url: unknown): SupportedSite | null {
	if (typeof url !== "string" || url.length > 8192) return null;
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return null;
	}
	if (parsed.protocol !== "https:" || parsed.port || parsed.username || parsed.password)
		return null;
	return HOST_TO_SITE.get(parsed.hostname) ?? null;
}

/** Rules for the given sites ("other" and "custom" yield no rule). */
export function buildBlockRules(blockedSites: readonly SiteId[]): DnrRule[] {
	const rules: DnrRule[] = [];
	SUPPORTED_SITES.forEach((site, i) => {
		if (!blockedSites.includes(site)) return;
		rules.push(
			{
				id: navigationRuleId(i),
				priority: 1,
				action: { type: "block" },
				condition: { requestDomains: [...SITE_HOSTS[site]], resourceTypes: ["main_frame"] },
			},
			{
				id: frameRuleId(i),
				priority: 1,
				action: { type: "block" },
				condition: { requestDomains: [...SITE_HOSTS[site]], resourceTypes: ["sub_frame"] },
			},
		);
		const paths = sitePaths(site);
		if (paths.length) {
			rules.push({
				id: pathRuleId(i),
				priority: 1,
				action: { type: "block" },
				condition: {
					regexFilter: scopeRegexFilter([], paths),
					resourceTypes: ["main_frame", "sub_frame"],
				},
			});
		}
	});
	return rules;
}

/** Replaces this module's dynamic rules with the ones for `blockedSites`. */
export async function applyBlockedSites(
	chrome: Pick<ChromeApi, "declarativeNetRequest">,
	blockedSites: readonly SiteId[],
): Promise<boolean> {
	try {
		await chrome.declarativeNetRequest.updateDynamicRules({
			removeRuleIds: [...DNR_RULE_IDS],
			addRules: buildBlockRules(blockedSites),
		});
		return true;
	} catch {
		return false;
	}
}

/**
 * Supported site whose host (or a subdomain of it, like the DNR `requestDomains`
 * condition) serves `url` over http(s), otherwise null.
 */
export function siteForNavigation(url: unknown): SupportedSite | null {
	if (typeof url !== "string" || url.length > 8192) return null;
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return null;
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
	const host = parsed.hostname.toLowerCase();
	for (const site of SUPPORTED_SITES) {
		if (SITE_HOSTS[site].some((h) => host === h || host.endsWith(`.${h}`))) return site;
		if (sitePaths(site).some((p) => host === p.host && pathInScope(parsed.pathname, p.path)))
			return site;
	}
	return null;
}

/** True when `rules` hold this module's top-level navigation block for `site`. */
export function navigationBlocked(rules: readonly DnrRule[], site: SupportedSite): boolean {
	const id = navigationRuleId(SUPPORTED_SITES.indexOf(site));
	return rules.some(
		(r) =>
			r.id === id && r.action.type === "block" && r.condition.resourceTypes.includes("main_frame"),
	);
}

/**
 * tabs.onUpdated handler body: when a tab's URL is a site whose navigation rule is
 * installed, navigate the tab to the blocked page. Returns the site it redirected for.
 * Only URLs the extension may see (its site host permissions) are ever reported by
 * the browser, so this never reads other browsing.
 */
export async function redirectBlockedTab(
	chrome: Pick<ChromeApi, "declarativeNetRequest" | "runtime" | "tabs">,
	tabId: number,
	url: string | undefined,
): Promise<SupportedSite | null> {
	const site = siteForNavigation(url);
	if (!site || !chrome.declarativeNetRequest.getDynamicRules || !chrome.tabs.update) return null;
	const rules = await chrome.declarativeNetRequest.getDynamicRules();
	if (!navigationBlocked(rules, site)) return null;
	await chrome.tabs.update(tabId, {
		url: chrome.runtime.getURL(`${BLOCKED_PAGE_PATH}?site=${site}`),
	});
	return site;
}

/** URL a tabs.onUpdated event reports for a navigation, if any. */
export function updatedTabUrl(
	changeInfo: { readonly url?: string; readonly status?: string },
	tab: TabInfo | undefined,
): string | undefined {
	if (typeof changeInfo.url === "string") return changeInfo.url;
	return changeInfo.status === "loading" ? tab?.url : undefined;
}
