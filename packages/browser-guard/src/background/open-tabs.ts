/**
 * Protection for AI tabs that were already open when the extension started running.
 *
 * Manifest content scripts are injected only into pages loaded after the extension is
 * installed, updated or re-enabled. A ChatGPT or Claude tab that stays open for days would
 * otherwise send unmasked prompts until it is reloaded, while the popup claimed it was
 * protected. Two parts fix that:
 *
 * - `ContentTabs` remembers, per tab, the page origin whose content script fetched its
 *   policy (GET_POLICY at boot). It lives in storage.session, which the browser clears
 *   when the extension is updated, reloaded or re-enabled, so a script orphaned by an update
 *   never counts as live. The popup shows "Not protected - reload" for a protected site
 *   whose tab has no live script.
 * - `injectOpenTabs` runs once per extension start (install, update, enable, browser
 *   start-up; the session flag marks it done) and after a custom-site host grant. It injects
 *   content.js and the page-world hook content-main.js with chrome.scripting.executeScript
 *   into every open tab of a protected site that has no live script. The tab's URL is only
 *   visible (and injection only allowed) on hosts the extension has access to: the built-in
 *   sites and granted custom-site hosts. A discarded tab is skipped; it reloads, and gets the
 *   manifest scripts, when the user returns to it.
 */
import type { ChromeApi, GuardStorage, TabInfo } from "./storage.js";
import { STORAGE_KEYS } from "./storage.js";

const CONTENT_SCRIPT_FILE = "content.js";
const MAIN_WORLD_SCRIPT_FILE = "content-main.js";

const isTabId = (raw: unknown): raw is number => Number.isSafeInteger(raw) && (raw as number) >= 0;

function originOf(url: unknown): string | null {
	if (typeof url !== "string") return null;
	try {
		const parsed = new URL(url);
		return parsed.protocol === "https:" ? parsed.origin : null;
	} catch {
		return null;
	}
}

/** Tab id -> origin of the page whose content script fetched the policy (storage.session). */
export class ContentTabs {
	private chain: Promise<unknown> = Promise.resolve();

	constructor(private readonly storage: GuardStorage) {}

	/** Records a live content script for `tabId` on `origin`. */
	mark(tabId: number, origin: string): Promise<void> {
		return this.update((tabs) => {
			if (tabs[String(tabId)] === origin) return false;
			tabs[String(tabId)] = origin;
			return true;
		});
	}

	remove(tabId: number): Promise<void> {
		return this.update((tabs) => {
			if (!(String(tabId) in tabs)) return false;
			delete tabs[String(tabId)];
			return true;
		});
	}

	/**
	 * Whether `tabId` runs a live content script for the page at `url` (same origin). With
	 * no URL (the browser did not report it), any live script recorded for the tab counts.
	 */
	async isLive(tabId: number, url: string | undefined): Promise<boolean> {
		const origin = (await this.read())[String(tabId)];
		if (origin === undefined) return false;
		return url === undefined || originOf(url) === origin;
	}

	private async read(): Promise<Record<string, string>> {
		const raw = await this.storage.getSession(STORAGE_KEYS.contentTabs);
		const out: Record<string, string> = {};
		if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
		for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
			if (isTabId(Number(key)) && typeof value === "string") out[key] = value;
		}
		return out;
	}

	private update(change: (tabs: Record<string, string>) => boolean): Promise<void> {
		const task = async () => {
			const tabs = await this.read();
			if (change(tabs)) await this.storage.setSession(STORAGE_KEYS.contentTabs, tabs);
		};
		const next = this.chain.then(task, task);
		this.chain = next.catch(() => {});
		return next;
	}
}

export interface InjectOpenTabsDeps {
	readonly chrome: Pick<ChromeApi, "scripting" | "tabs">;
	readonly contentTabs: ContentTabs;
	/** Whether the content script runs on `url` (built-in or configured custom site). */
	readonly protectedUrl: (url: string | undefined) => boolean;
	readonly log?: (message: string) => void;
}

/**
 * Injects the content scripts into every open, loaded tab of a protected site that has no
 * live script. Returns the tab ids injected. Never rejects.
 */
export async function injectOpenTabs(deps: InjectOpenTabsDeps): Promise<number[]> {
	const { chrome, contentTabs, protectedUrl } = deps;
	const execute = chrome.scripting?.executeScript?.bind(chrome.scripting);
	if (!execute) return [];
	let tabs: TabInfo[] = [];
	try {
		tabs = await chrome.tabs.query({});
	} catch {
		deps.log?.("tabs: query failed; open tabs not injected");
		return [];
	}
	const injected: number[] = [];
	for (const tab of tabs) {
		const tabId = tab.id;
		if (!isTabId(tabId) || tab.discarded || !protectedUrl(tab.url)) continue;
		if (await contentTabs.isLive(tabId, tab.url)) continue;
		try {
			await execute({ target: { tabId }, files: [CONTENT_SCRIPT_FILE] });
			await execute({ target: { tabId }, files: [MAIN_WORLD_SCRIPT_FILE], world: "MAIN" });
			injected.push(tabId);
		} catch {
			// Closed, navigating, an error page, or no host access: the popup reports it.
			deps.log?.("tabs: could not inject into an open tab; it is protected after a reload");
		}
	}
	return injected;
}

/** Runs `injectOpenTabs` once per extension start (storage.session flag). */
export async function injectOpenTabsOnce(
	storage: GuardStorage,
	deps: InjectOpenTabsDeps,
): Promise<number[]> {
	if ((await storage.getSession(STORAGE_KEYS.openTabsInjected)) === true) return [];
	await storage.setSession(STORAGE_KEYS.openTabsInjected, true);
	return injectOpenTabs(deps);
}
