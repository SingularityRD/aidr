/**
 * Content-script registration for administrator-configured internal AI portals
 * (managed key `customSites`).
 *
 * The manifest's static content scripts cover the built-in sites only. For a custom
 * site the browser must first grant host access to its origins (optional host
 * permissions, requested from the options page: browsers only prompt from a user
 * gesture, and a managed policy cannot grant it silently). The worker then registers the
 * same content.js (plus the page-world file-input hook content-main.js, see
 * ../content/file-input-hook.ts) for exactly the granted hosts with chrome.scripting
 * (`scripting` permission), and re-syncs whenever the policy or a grant changes. A host
 * without access gets no script: nothing is injected where the user did not allow it.
 */
import type { CustomSiteAccess, CustomSiteConfig } from "../types.js";
import type { ChromeApi, RegisteredContentScript } from "./storage.js";

export const CUSTOM_SCRIPT_ID = "aidr-custom-sites";
/** The page-world (MAIN) companion script, registered and removed together with content.js. */
export const CUSTOM_MAIN_SCRIPT_ID = "aidr-custom-sites-main";
const CONTENT_SCRIPT_FILE = "content.js";
const MAIN_WORLD_SCRIPT_FILE = "content-main.js";
const SCRIPT_IDS = [CUSTOM_SCRIPT_ID, CUSTOM_MAIN_SCRIPT_ID];

const originForHost = (host: string): string => `https://${host}/*`;

function customSiteOrigins(site: CustomSiteConfig): string[] {
	return site.hosts.map(originForHost);
}

/**
 * Configured site serving a page/frame URL: exact https host from the policy, no port,
 * no credentials; otherwise null.
 */
export function customSiteForUrl(
	url: unknown,
	customSites: readonly CustomSiteConfig[],
): CustomSiteConfig | null {
	if (typeof url !== "string" || url.length > 8192 || customSites.length === 0) return null;
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return null;
	}
	if (parsed.protocol !== "https:" || parsed.port || parsed.username || parsed.password)
		return null;
	return customSites.find((site) => site.hosts.includes(parsed.hostname)) ?? null;
}

/** Whether host access to `origin` is granted; false when it cannot be determined. */
export async function originGranted(
	chrome: Pick<ChromeApi, "permissions">,
	origin: string,
): Promise<boolean> {
	try {
		return (await chrome.permissions?.contains?.({ origins: [origin] })) === true;
	} catch {
		return false;
	}
}

const sameList = (a: readonly string[], b: readonly string[]) =>
	a.length === b.length && a.every((v, i) => v === b[i]);

export class CustomSiteScripts {
	private chain: Promise<unknown> = Promise.resolve();
	private registered: readonly string[] = [];

	constructor(
		private readonly chrome: Pick<ChromeApi, "permissions" | "scripting">,
		private readonly log: (message: string) => void = () => {},
	) {}

	/**
	 * Registers content.js for every granted custom-site host and nothing else. Returns
	 * the per-site status. Never rejects.
	 */
	sync(customSites: readonly CustomSiteConfig[]): Promise<CustomSiteAccess[]> {
		return this.serial(async () => {
			const granted = await this.grantedOrigins(customSites);
			const matches = [...granted].sort();
			await this.register(matches);
			return this.statusFor(customSites, granted);
		});
	}

	/** Per-site status without changing registrations. */
	status(customSites: readonly CustomSiteConfig[]): Promise<CustomSiteAccess[]> {
		return this.serial(async () =>
			this.statusFor(customSites, await this.grantedOrigins(customSites)),
		);
	}

	private statusFor(
		customSites: readonly CustomSiteConfig[],
		granted: ReadonlySet<string>,
	): CustomSiteAccess[] {
		return customSites.map((site) => {
			const origins = customSiteOrigins(site);
			return {
				id: site.id,
				label: site.label,
				hosts: [...site.hosts],
				origins,
				granted: origins.every((o) => granted.has(o)),
				active: origins.some((o) => this.registered.includes(o)),
			};
		});
	}

	private async grantedOrigins(customSites: readonly CustomSiteConfig[]): Promise<Set<string>> {
		const origins = [...new Set(customSites.flatMap(customSiteOrigins))];
		const results = await Promise.all(origins.map((o) => originGranted(this.chrome, o)));
		return new Set(origins.filter((_, i) => results[i]));
	}

	private async register(matches: string[]): Promise<void> {
		const scripting = this.chrome.scripting;
		if (!scripting) {
			this.registered = [];
			if (matches.length > 0) this.log("custom sites: scripting API unavailable");
			return;
		}
		let existing: RegisteredContentScript[] = [];
		try {
			existing = await scripting.getRegisteredContentScripts({ ids: SCRIPT_IDS });
		} catch {
			existing = [];
		}
		const isolated = existing.find((s) => s.id === CUSTOM_SCRIPT_ID);
		const main = existing.find((s) => s.id === CUSTOM_MAIN_SCRIPT_ID);
		const current = [...(isolated?.matches ?? [])].sort();
		if (
			isolated &&
			main &&
			sameList(current, matches) &&
			sameList([...(main.matches ?? [])].sort(), matches)
		) {
			this.registered = current;
			return;
		}
		try {
			const stale = existing.map((s) => s.id);
			if (stale.length > 0) await scripting.unregisterContentScripts({ ids: stale });
			this.registered = [];
			if (matches.length === 0) return;
			const base = {
				runAt: "document_start",
				allFrames: false,
				persistAcrossSessions: true,
			} as const;
			// The page-world hook is registered with content.js: without it, detached and
			// shadow-DOM file inputs on the custom site would not be routed to the guard.
			const scripts: RegisteredContentScript[] = [
				{ ...base, matches: [...matches], id: CUSTOM_SCRIPT_ID, js: [CONTENT_SCRIPT_FILE] },
				{
					...base,
					matches: [...matches],
					id: CUSTOM_MAIN_SCRIPT_ID,
					js: [MAIN_WORLD_SCRIPT_FILE],
					world: "MAIN",
				},
			];
			try {
				await scripting.registerContentScripts(scripts);
			} catch {
				// Browsers without persistent registrations: the worker re-registers on start-up.
				await scripting.unregisterContentScripts({ ids: SCRIPT_IDS }).catch(() => undefined);
				await scripting.registerContentScripts(
					scripts.map(({ persistAcrossSessions: _persist, ...transient }) => transient),
				);
			}
			this.registered = matches;
		} catch {
			this.registered = [];
			this.log("custom sites: content script registration failed");
		}
	}

	private serial<T>(task: () => Promise<T>): Promise<T> {
		const next = this.chain.then(task, task);
		this.chain = next.catch(() => {});
		return next;
	}
}
