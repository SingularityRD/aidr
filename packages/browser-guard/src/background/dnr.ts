/**
 * declarativeNetRequest dynamic rules for AI chat products listed in
 * `policy.blockedSites`: a top-level navigation is redirected to the extension's
 * `/blocked.html?site=<id>` explanation page (which the manifest must list under
 * web_accessible_resources for the redirect to load), and framed embeds are blocked.
 *
 * The host list is kept here on purpose (the background must not depend on the
 * content-side site adapters). It mirrors the adapters' exact HTTPS hosts;
 * `requestDomains` also covers their subdomains, which is the safe direction for
 * a block rule.
 */
import type { SiteId } from "../types.js";
import type { ChromeApi, DnrRule } from "./storage.js";

type SupportedSite = Exclude<SiteId, "other">;

export const SITE_HOSTS: Readonly<Record<SupportedSite, readonly string[]>> = Object.freeze({
	chatgpt: Object.freeze(["chatgpt.com", "chat.openai.com"]),
	gemini: Object.freeze(["gemini.google.com"]),
	claude: Object.freeze(["claude.ai"]),
	copilot: Object.freeze(["copilot.microsoft.com"]),
	perplexity: Object.freeze(["www.perplexity.ai", "perplexity.ai"]),
	deepseek: Object.freeze(["chat.deepseek.com"]),
	mistral: Object.freeze(["chat.mistral.ai"]),
	grok: Object.freeze(["grok.com"]),
});

const SUPPORTED_SITES = Object.keys(SITE_HOSTS) as SupportedSite[];

/** Page a blocked top-level navigation lands on. */
export const BLOCKED_PAGE_PATH = "/blocked.html";

/** Dynamic rule ids owned by this module: two per supported site (redirect + frame block). */
export const DNR_RULE_ID_BASE = 7300;
const redirectRuleId = (i: number) => DNR_RULE_ID_BASE + i * 2 + 1;
const frameRuleId = (i: number) => DNR_RULE_ID_BASE + i * 2 + 2;
export const DNR_RULE_IDS: readonly number[] = Object.freeze(
	SUPPORTED_SITES.flatMap((_, i) => [redirectRuleId(i), frameRuleId(i)]),
);

const HOST_TO_SITE: ReadonlyMap<string, SupportedSite> = new Map(
	SUPPORTED_SITES.flatMap((site) => SITE_HOSTS[site].map((host) => [host, site] as const)),
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

/** Rules for the given sites ("other" has no hosts and yields no rule). */
export function buildBlockRules(blockedSites: readonly SiteId[]): DnrRule[] {
	const rules: DnrRule[] = [];
	SUPPORTED_SITES.forEach((site, i) => {
		if (!blockedSites.includes(site)) return;
		rules.push(
			{
				id: redirectRuleId(i),
				priority: 1,
				action: {
					type: "redirect",
					redirect: { extensionPath: `${BLOCKED_PAGE_PATH}?site=${site}` },
				},
				condition: { requestDomains: [...SITE_HOSTS[site]], resourceTypes: ["main_frame"] },
			},
			{
				id: frameRuleId(i),
				priority: 1,
				action: { type: "block" },
				condition: { requestDomains: [...SITE_HOSTS[site]], resourceTypes: ["sub_frame"] },
			},
		);
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
