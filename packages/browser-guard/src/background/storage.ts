/**
 * Minimal, typed view of the WebExtension APIs the background worker uses, plus
 * fault-tolerant wrappers around chrome.storage.{managed,local,session}.
 *
 * The package deliberately has no @types/chrome dependency: the subset below is the
 * whole surface the worker touches, which also keeps the in-memory test fake honest.
 *
 * Storage layout:
 *   local   userSettings, installationId, telemetryQueue, telemetryState,
 *           aupAcknowledged (acceptable-use notice id -> highest acknowledged version),
 *           shadowAiUsage (per-day visit/block counts per catalog service id; no URLs),
 *           dashboardPolicy / dashboardPolicyHighWater (last signed dashboard document, re-verified
 *           on every load, and the highest accepted sequence; see ./dashboard-policy.ts)
 *   session guardStats, pausedUntil, `vault:<tabId>:<origin>` (per-tab placeholder vault,
 *           see ./vault-store.ts; TRUSTED_CONTEXTS only, so page scripts cannot read it)
 *   managed administrator policy keys (static/managed_schema.json)
 */
import type { UserSettings } from "../types.js";

interface ChromeEvent<F extends (...args: never[]) => unknown> {
	addListener(listener: F): void;
	removeListener(listener: F): void;
}

export interface StorageAreaApi {
	get(keys?: string | string[] | Record<string, unknown> | null): Promise<Record<string, unknown>>;
	set(items: Record<string, unknown>): Promise<void>;
	remove(keys: string | string[]): Promise<void>;
	setAccessLevel?(options: { accessLevel: string }): Promise<void>;
}

export interface StorageChange {
	oldValue?: unknown;
	newValue?: unknown;
}

export interface MessageSender {
	id?: string;
	url?: string;
	origin?: string;
	frameId?: number;
	documentId?: string;
	tab?: { id?: number; url?: string };
}

export interface TabInfo {
	id?: number;
	url?: string;
	active?: boolean;
}

type DnrRuleAction = { type: "block" } | { type: "redirect"; redirect: { extensionPath: string } };

export interface DnrRule {
	id: number;
	priority: number;
	action: DnrRuleAction;
	condition: { requestDomains: string[]; resourceTypes: string[] };
}

export type MessageListener = (
	message: unknown,
	sender: MessageSender,
	sendResponse: (response: unknown) => void,
) => boolean | undefined;

export interface ChromeApi {
	runtime: {
		readonly id: string;
		getManifest(): { version: string };
		getURL(path: string): string;
		onMessage: ChromeEvent<MessageListener>;
		onInstalled: ChromeEvent<(details: { reason: string }) => void>;
		onStartup: ChromeEvent<() => void>;
	};
	storage: {
		managed: StorageAreaApi;
		local: StorageAreaApi;
		session?: StorageAreaApi;
		onChanged: ChromeEvent<(changes: Record<string, StorageChange>, areaName: string) => void>;
	};
	tabs: {
		query(query: Record<string, unknown>): Promise<TabInfo[]>;
		sendMessage(tabId: number, message: unknown, options?: { frameId?: number }): Promise<unknown>;
		update?(tabId: number, properties: { url: string }): Promise<unknown>;
		onRemoved: ChromeEvent<(tabId: number) => void>;
		onUpdated?: ChromeEvent<
			(tabId: number, changeInfo: { url?: string; status?: string }, tab: TabInfo) => void
		>;
	};
	action: {
		setBadgeText(details: { text: string; tabId?: number }): Promise<void>;
		setBadgeBackgroundColor?(details: { color: string; tabId?: number }): Promise<void>;
	};
	alarms: {
		create(name: string, info: { periodInMinutes?: number; when?: number }): Promise<void> | void;
		clear(name: string): Promise<boolean> | undefined;
		get?(name: string): Promise<{ name: string } | undefined>;
		onAlarm: ChromeEvent<(alarm: { name: string }) => void>;
	};
	declarativeNetRequest: {
		updateDynamicRules(options: { addRules?: DnrRule[]; removeRuleIds?: number[] }): Promise<void>;
		getDynamicRules?(): Promise<DnrRule[]>;
	};
	/**
	 * Optional-permission grants: the options page requests `nativeMessaging` and host
	 * access (`origins`) for Shadow AI and administrator-configured custom sites.
	 */
	permissions?: {
		contains?(permissions: { permissions?: string[]; origins?: string[] }): Promise<boolean>;
		onAdded?: ChromeEvent<PermissionsListener>;
		onRemoved?: ChromeEvent<PermissionsListener>;
	};
	/** Dynamic content scripts for custom sites (`scripting` permission). */
	scripting?: {
		registerContentScripts(scripts: RegisteredContentScript[]): Promise<void>;
		unregisterContentScripts(filter?: { ids?: string[] }): Promise<void>;
		getRegisteredContentScripts(filter?: { ids?: string[] }): Promise<RegisteredContentScript[]>;
	};
}

export type PermissionsListener = (permissions: {
	permissions?: string[];
	origins?: string[];
}) => void;

export interface RegisteredContentScript {
	id: string;
	matches?: string[];
	js?: string[];
	css?: string[];
	runAt?: "document_start" | "document_end" | "document_idle";
	allFrames?: boolean;
	persistAcrossSessions?: boolean;
}

/** The global `chrome` namespace, when running inside an extension. */
export function getChrome(): ChromeApi | undefined {
	const candidate = (globalThis as { chrome?: Partial<ChromeApi> }).chrome;
	return candidate?.runtime?.id && candidate.storage ? (candidate as ChromeApi) : undefined;
}

export const STORAGE_KEYS = Object.freeze({
	userSettings: "userSettings",
	installationId: "installationId",
	telemetryQueue: "telemetryQueue",
	telemetryState: "telemetryState",
	stats: "guardStats",
	pausedUntil: "pausedUntil",
	aupAcknowledged: "aupAcknowledged",
	shadowAiUsage: "shadowAiUsage",
});

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type ManagedRead =
	| { readonly status: "ok"; readonly value: Record<string, unknown> }
	| { readonly status: "absent" }
	| { readonly status: "error" };

/**
 * Firefox rejects storage.managed.get() when no managed manifest is installed;
 * that is "no administrator policy", not a failure.
 */
const MANAGED_ABSENT = /managed storage manifest not found|not supported|not available/i;

export class GuardStorage {
	/** Fallback when storage.session is unavailable (older Firefox): memory only. */
	private readonly memorySession = new Map<string, unknown>();

	constructor(
		private readonly chrome: ChromeApi,
		private readonly log: (message: string) => void = () => {},
	) {}

	async readManaged(): Promise<ManagedRead> {
		try {
			const value = await this.chrome.storage.managed.get(null);
			if (!value || typeof value !== "object" || Object.keys(value).length === 0)
				return { status: "absent" };
			return { status: "ok", value };
		} catch (error) {
			if (error instanceof Error && MANAGED_ABSENT.test(error.message)) return { status: "absent" };
			this.log("storage: managed policy unavailable");
			return { status: "error" };
		}
	}

	async readUserSettings(): Promise<unknown> {
		return this.getLocal(STORAGE_KEYS.userSettings);
	}

	async writeUserSettings(settings: Partial<UserSettings>): Promise<boolean> {
		return this.setLocal(STORAGE_KEYS.userSettings, settings);
	}

	/** Stable per-install UUID (telemetry `iid`), created on first use. */
	async installationId(): Promise<string> {
		const existing = await this.getLocal(STORAGE_KEYS.installationId);
		if (typeof existing === "string" && UUID_PATTERN.test(existing)) return existing;
		const id = crypto.randomUUID();
		await this.setLocal(STORAGE_KEYS.installationId, id);
		return id;
	}

	async getLocal(key: string): Promise<unknown> {
		try {
			const items = await this.chrome.storage.local.get(key);
			return items?.[key];
		} catch {
			this.log(`storage: local read failed for "${key}"`);
			return undefined;
		}
	}

	async setLocal(key: string, value: unknown): Promise<boolean> {
		try {
			await this.chrome.storage.local.set({ [key]: value });
			return true;
		} catch {
			this.log(`storage: local write failed for "${key}"`);
			return false;
		}
	}

	async removeLocal(key: string): Promise<void> {
		try {
			await this.chrome.storage.local.remove(key);
		} catch {
			this.log(`storage: local remove failed for "${key}"`);
		}
	}

	async getSession(key: string): Promise<unknown> {
		const area = this.chrome.storage.session;
		if (area) {
			try {
				const items = await area.get(key);
				return items?.[key];
			} catch {
				this.log(`storage: session read failed for "${key}"`);
			}
		}
		return this.memorySession.get(key);
	}

	async setSession(key: string, value: unknown): Promise<void> {
		this.memorySession.set(key, value);
		const area = this.chrome.storage.session;
		if (!area) return;
		try {
			await area.set({ [key]: value });
		} catch {
			this.log(`storage: session write failed for "${key}"`);
		}
	}

	/** Session keys starting with `prefix` (memory fallback included). */
	async sessionKeys(prefix: string): Promise<string[]> {
		const keys = new Set([...this.memorySession.keys()].filter((k) => k.startsWith(prefix)));
		const area = this.chrome.storage.session;
		if (area) {
			try {
				for (const key of Object.keys((await area.get(null)) ?? {}))
					if (key.startsWith(prefix)) keys.add(key);
			} catch {
				this.log("storage: session listing failed");
			}
		}
		return [...keys];
	}

	async removeSession(keys: readonly string[]): Promise<void> {
		if (keys.length === 0) return;
		for (const key of keys) this.memorySession.delete(key);
		try {
			await this.chrome.storage.session?.remove([...keys]);
		} catch {
			this.log("storage: session remove failed");
		}
	}

	/** Restricts session storage to extension pages + worker (not content scripts). */
	async restrictSessionAccess(): Promise<void> {
		try {
			await this.chrome.storage.session?.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
		} catch {
			this.log("storage: session access level unavailable");
		}
	}
}
