import type { CustomSiteConfig, SiteAdapter, SiteId } from "../types";
import { chatgpt } from "./chatgpt";
import { claude } from "./claude";
import { copilot } from "./copilot";
import { customAdapter, customSiteForHost } from "./custom";
import { deepseek } from "./deepseek";
import { FRAME_GUARD_HOSTS } from "./frames";
import { gemini } from "./gemini";
import { GENERIC_ADAPTER } from "./generic";
import { grok } from "./grok";
import { mistral } from "./mistral";
import { perplexity } from "./perplexity";

export { GENERIC_ADAPTER } from "./generic";

/** Supported AI chat products (the generic "other" adapter is not listed). */
export const ADAPTERS: readonly SiteAdapter[] = Object.freeze([
	chatgpt,
	gemini,
	claude,
	copilot,
	perplexity,
	deepseek,
	mistral,
	grok,
]);

/**
 * Every SiteId, supported sites first, then "custom" (administrator-configured internal
 * portals) and "other" last (for policy/UI lists).
 */
export const SITE_IDS: readonly SiteId[] = Object.freeze([
	...ADAPTERS.map((a) => a.id),
	"custom",
	GENERIC_ADAPTER.id,
]);

/** Content-script / host-permission match patterns: exact HTTPS hosts only. */
export const MATCH_PATTERNS: readonly string[] = Object.freeze(
	ADAPTERS.flatMap((a) => a.hosts.map((h) => `https://${h}/*`)),
);

/**
 * The subset of {@link MATCH_PATTERNS} whose content scripts run in every frame
 * (`all_frames: true`): the Microsoft 365 Copilot hosts, whose Copilot pane is embedded in
 * the Office web apps as a cross-origin iframe (./frames.ts). Every other site is top-frame
 * only.
 */
export const FRAME_MATCH_PATTERNS: readonly string[] = Object.freeze(
	FRAME_GUARD_HOSTS.map((h) => `https://${h}/*`),
);

const BY_HOST: ReadonlyMap<string, SiteAdapter> = new Map(
	ADAPTERS.flatMap((a) => a.hosts.map((h) => [h, a] as const)),
);

const MAX_URL_LENGTH = 8192;

/**
 * Resolves the adapter for a page URL. Only an exact https host from an
 * adapter's `hosts` list matches: no suffix matching, no explicit port, no
 * credentials, no other scheme. A built-in site always wins; otherwise an exact host
 * of an administrator-configured custom site (policy `customSites`) yields that site's
 * adapter (id "custom"). Anything else gets the generic adapter.
 */
export function adapterForUrl(
	url: string,
	customSites: readonly CustomSiteConfig[] = [],
): SiteAdapter {
	if (typeof url !== "string" || url.length > MAX_URL_LENGTH) return GENERIC_ADAPTER;
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return GENERIC_ADAPTER;
	}
	if (parsed.protocol !== "https:" || parsed.port || parsed.username || parsed.password) {
		return GENERIC_ADAPTER;
	}
	const builtIn = BY_HOST.get(parsed.hostname);
	if (builtIn) return builtIn;
	const custom = customSiteForHost(parsed.hostname, customSites);
	return custom ? customAdapter(custom) : GENERIC_ADAPTER;
}

/** Adapter for a SiteId; "other" (or an unknown id) yields the generic adapter. */
export function adapterById(id: SiteId): SiteAdapter {
	return ADAPTERS.find((a) => a.id === id) ?? GENERIC_ADAPTER;
}
