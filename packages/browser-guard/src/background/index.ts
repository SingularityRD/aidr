/**
 * Browser Guard background service worker.
 *
 * Owns the effective policy (managed over user over default), per-tab statistics,
 * privacy telemetry, the site-blocking network rules and the optional native host
 * bridge, and answers GuardMessage requests from content scripts and extension pages.
 *
 * Trust model: only this extension's own contexts may talk to the worker
 * (sender.id === runtime.id). Extension pages (popup/options) may change settings;
 * content scripts are accepted only from the exact HTTPS hosts of supported sites and
 * are limited to their own tab. Content scripts never receive the telemetry API key.
 */
import type {
	GuardError,
	GuardPolicy,
	GuardResponse,
	GuardStats,
	NativeBridge,
	PrivacyScanEvent,
	SiteId,
	UserSettings,
} from "../types.js";
import { applyBlockedSites, redirectBlockedTab, siteForUrl, updatedTabUrl } from "./dnr.js";
import { createNativeBridge } from "./native.js";
import { DEFAULT_POLICY, evaluatePolicy, validateUserSettings } from "./policy.js";
import { badgeText, StatsStore } from "./stats.js";
import {
	type ChromeApi,
	GuardStorage,
	getChrome,
	type MessageSender,
	STORAGE_KEYS,
	type StorageChange,
} from "./storage.js";
import {
	type NavigatorLike,
	TELEMETRY_ALARM,
	TELEMETRY_LIMITS,
	TelemetryClient,
} from "./telemetry.js";

export const PAUSE_ALARM = "aidr-pause-end";
export const PAUSE_MAX_MINUTES = 60;
/** Upper bound for text proxied to the native host in one NATIVE_SCAN. */
export const NATIVE_SCAN_MAX_CHARS = 1_000_000;

const ACTIONS: readonly PrivacyScanEvent["action"][] = ["masked", "blocked", "warned", "allowed"];
const CHANNELS: readonly PrivacyScanEvent["channel"][] = ["prompt", "paste", "file"];

export interface BackgroundOptions {
	readonly chrome: ChromeApi;
	readonly fetch?: typeof fetch;
	readonly now?: () => number;
	readonly random?: () => number;
	readonly navigator?: NavigatorLike;
	readonly createNativeBridge?: (enabled: boolean) => NativeBridge;
	readonly log?: (message: string) => void;
}

export interface BackgroundController {
	/** Resolves once the first policy load finished (never rejects). */
	readonly ready: Promise<void>;
	readonly telemetry: TelemetryClient;
	readonly stats: StatsStore;
	handleMessage(message: unknown, sender: MessageSender): Promise<GuardResponse>;
	reload(broadcast: boolean): Promise<GuardPolicy>;
	policy(): GuardPolicy;
	warnings(): readonly string[];
}

type Sender =
	| { readonly kind: "extension"; readonly tabId: number | undefined }
	| { readonly kind: "content"; readonly tabId: number; readonly site: SiteId };

const fail = (error: string, keys?: readonly string[]): GuardError =>
	keys ? { ok: false, error, keys } : { ok: false, error };

function isRecord(raw: unknown): raw is Record<string, unknown> {
	return raw !== null && typeof raw === "object" && !Array.isArray(raw);
}

const isTabId = (raw: unknown): raw is number => Number.isSafeInteger(raw) && (raw as number) >= 0;

export function startBackground(options: BackgroundOptions): BackgroundController {
	const { chrome } = options;
	const now = options.now ?? Date.now;
	const log = options.log ?? ((m: string) => console.warn(`[aidr-browser-guard] ${m}`));
	const bridgeFactory = options.createNativeBridge ?? createNativeBridge;
	const storage = new GuardStorage(chrome, log);
	const stats = new StatsStore(storage);
	const telemetry = new TelemetryClient({
		storage,
		fetch: options.fetch ?? ((...args) => globalThis.fetch(...args)),
		now,
		random: options.random ?? Math.random,
		navigator: options.navigator ?? (globalThis.navigator as NavigatorLike | undefined),
		aidrVersion: chrome.runtime.getManifest().version,
		log,
	});

	let current: GuardPolicy = DEFAULT_POLICY;
	let currentWarnings: readonly string[] = [];
	let bridge: NativeBridge | null = null;
	let bridgeEnabled: boolean | null = null;
	let reloadChain: Promise<unknown> = Promise.resolve();
	const extensionBase = chrome.runtime.getURL("");

	function classifySender(sender: MessageSender | undefined): Sender | null {
		if (!sender || sender.id !== chrome.runtime.id) return null;
		if (typeof sender.url === "string" && sender.url.startsWith(extensionBase)) {
			if (sender.origin !== undefined && `${sender.origin}/` !== extensionBase) return null;
			return { kind: "extension", tabId: isTabId(sender.tab?.id) ? sender.tab.id : undefined };
		}
		const tabId = sender.tab?.id;
		const site = siteForUrl(sender.url);
		if (!isTabId(tabId) || !site) return null;
		return { kind: "content", tabId, site };
	}

	async function pausedUntil(): Promise<number | null> {
		const raw = await storage.getSession(STORAGE_KEYS.pausedUntil);
		return typeof raw === "number" && Number.isFinite(raw) && raw > now() ? raw : null;
	}

	/** Policy as seen by one context: pause / per-site disable force monitor mode. */
	function effectivePolicy(
		site: SiteId | null,
		forContent: boolean,
		paused: number | null,
	): GuardPolicy {
		const monitor =
			(paused !== null && current.allowUserPause) ||
			(site !== null && current.disabledSites.includes(site));
		if (!monitor && !forContent) return current;
		return Object.freeze({
			...current,
			mode: monitor ? "monitor" : current.mode,
			telemetry: forContent ? null : current.telemetry,
		});
	}

	async function broadcastPolicy(): Promise<void> {
		const paused = await pausedUntil();
		let tabs: Awaited<ReturnType<ChromeApi["tabs"]["query"]>> = [];
		try {
			tabs = await chrome.tabs.query({});
		} catch {
			log("tabs: query failed; policy change not broadcast");
			return;
		}
		await Promise.all(
			tabs.map(async (tab) => {
				const site = siteForUrl(tab.url);
				if (!isTabId(tab.id) || !site) return;
				const policy = effectivePolicy(site, true, paused);
				await chrome.tabs.sendMessage(tab.id, { type: "POLICY_CHANGED", policy }).catch(() => {});
			}),
		);
	}

	async function loadPolicy(broadcast: boolean): Promise<GuardPolicy> {
		const managed = await storage.readManaged();
		// If managed policy state is unknown, user settings must not weaken the defaults.
		const user = managed.status === "error" ? undefined : await storage.readUserSettings();
		const evaluation = evaluatePolicy(managed.status === "ok" ? managed.value : undefined, user);
		current = evaluation.policy;
		currentWarnings =
			managed.status === "error"
				? [...evaluation.warnings, "managed: policy storage unavailable; user settings suspended"]
				: evaluation.warnings;
		for (const warning of currentWarnings) log(`policy: ${warning}`);

		if (bridgeEnabled !== current.useNativeHost) {
			bridgeEnabled = current.useNativeHost;
			try {
				bridge = bridgeFactory(current.useNativeHost);
			} catch {
				bridge = null;
				log("native: bridge unavailable");
			}
		}
		if (!(await applyBlockedSites(chrome, current.blockedSites)))
			log("dnr: failed to update blocked-site rules");
		await telemetry.configure(current.telemetry);
		if (broadcast) await broadcastPolicy();
		return current;
	}

	function reload(broadcast: boolean): Promise<GuardPolicy> {
		const next = reloadChain.then(
			() => loadPolicy(broadcast),
			() => loadPolicy(broadcast),
		);
		reloadChain = next.catch(() => {});
		return next;
	}

	async function setBadge(tabId: number, maskedItems: number): Promise<void> {
		try {
			await chrome.action.setBadgeText({ tabId, text: badgeText(maskedItems) });
			await chrome.action.setBadgeBackgroundColor?.({ tabId, color: "#1f6feb" });
		} catch {
			// The tab may have closed; the badge is cosmetic.
		}
	}

	async function ensureTelemetryAlarm(): Promise<void> {
		try {
			const existing = await chrome.alarms.get?.(TELEMETRY_ALARM);
			if (!existing)
				await chrome.alarms.create(TELEMETRY_ALARM, {
					periodInMinutes: TELEMETRY_LIMITS.flushPeriodMinutes,
				});
		} catch {
			log("alarms: telemetry flush alarm unavailable");
		}
	}

	async function getStats(tabId: number | undefined): Promise<GuardStats> {
		const [{ site, counters }, paused] = await Promise.all([stats.get(tabId), pausedUntil()]);
		return {
			site,
			protectedPrompts: counters.protectedPrompts,
			maskedItems: counters.maskedItems,
			blockedSends: counters.blockedSends,
			byType: counters.byType,
			pausedUntil: current.allowUserPause ? paused : null,
			nativeHost: current.useNativeHost && bridge ? bridge.status() : "disabled",
		};
	}

	async function setUserSettings(raw: unknown): Promise<GuardResponse> {
		if (!isRecord(raw)) return fail("BAD_MESSAGE");
		const keys = Object.keys(raw);
		const locked = keys.filter((k) => current.managedKeys.includes(k));
		if (locked.length) return fail("LOCKED_KEYS", locked);
		const validation = validateUserSettings(raw);
		const rejected = [...validation.unknownKeys, ...validation.invalidKeys];
		if (rejected.length) return fail("INVALID_SETTINGS", rejected);
		const existing = validateUserSettings(await storage.readUserSettings()).settings;
		const next: Partial<UserSettings> = { ...existing, ...validation.settings };
		if (!(await storage.writeUserSettings(next))) return fail("INTERNAL");
		await reload(true);
		return { ok: true, policy: effectivePolicy(null, false, await pausedUntil()) };
	}

	async function pause(minutes: unknown): Promise<GuardResponse> {
		if (!Number.isSafeInteger(minutes) || (minutes as number) < 0) return fail("BAD_MESSAGE");
		if ((minutes as number) > PAUSE_MAX_MINUTES) return fail("BAD_MESSAGE");
		if (minutes !== 0 && !current.allowUserPause) return fail("PAUSE_DISABLED");
		const until = minutes === 0 ? null : now() + (minutes as number) * 60_000;
		await storage.setSession(STORAGE_KEYS.pausedUntil, until);
		try {
			if (until === null) await chrome.alarms.clear(PAUSE_ALARM);
			else await chrome.alarms.create(PAUSE_ALARM, { when: until });
		} catch {
			log("alarms: pause alarm unavailable");
		}
		await broadcastPolicy();
		return { ok: true, pausedUntil: until };
	}

	async function nativeScan(text: unknown): Promise<GuardResponse> {
		if (typeof text !== "string" || text.length > NATIVE_SCAN_MAX_CHARS) return fail("BAD_MESSAGE");
		if (!current.useNativeHost || !bridge) return { ok: true, findings: null };
		try {
			return { ok: true, findings: await bridge.scanText(text) };
		} catch {
			return { ok: true, findings: null };
		}
	}

	async function setRestoreVisible(visible: unknown, who: Sender): Promise<GuardResponse> {
		if (typeof visible !== "boolean") return fail("BAD_MESSAGE");
		let tabId = who.tabId;
		if (tabId === undefined) {
			const [active] = await chrome.tabs
				.query({ active: true, lastFocusedWindow: true })
				.catch(() => []);
			if (!active || !isTabId(active.id) || !siteForUrl(active.url)) return fail("NOT_ALLOWED");
			tabId = active.id;
		}
		await chrome.tabs.sendMessage(tabId, { type: "SET_RESTORE_VISIBLE", visible }).catch(() => {});
		return { ok: true };
	}

	async function record(message: Record<string, unknown>, who: Sender): Promise<GuardResponse> {
		if (who.kind !== "content") return fail("NOT_ALLOWED");
		const { action, channel, counts } = message;
		if (!ACTIONS.includes(action as PrivacyScanEvent["action"])) return fail("BAD_MESSAGE");
		if (!CHANNELS.includes(channel as PrivacyScanEvent["channel"])) return fail("BAD_MESSAGE");
		// The site is derived from the sender, never taken from the message.
		const tab = await stats.record(
			who.tabId,
			who.site,
			action as PrivacyScanEvent["action"],
			counts,
		);
		await setBadge(who.tabId, tab.maskedItems);
		void telemetry
			.record({
				site: who.site,
				action: action as PrivacyScanEvent["action"],
				channel: channel as PrivacyScanEvent["channel"],
				counts,
				policyId: current.policyId,
			})
			.catch(() => log("telemetry: failed to queue event"));
		return { ok: true };
	}

	async function dispatch(message: unknown, sender: MessageSender): Promise<GuardResponse> {
		const who = classifySender(sender);
		if (!who) return fail("SENDER_DENIED");
		if (!isRecord(message) || typeof message.type !== "string") return fail("BAD_MESSAGE");
		await ready;
		const extensionOnly = () => who.kind !== "extension";
		switch (message.type) {
			case "GET_POLICY":
				return {
					ok: true,
					policy: effectivePolicy(
						who.kind === "content" ? who.site : null,
						who.kind === "content",
						await pausedUntil(),
					),
				};
			case "RECORD":
				return record(message, who);
			case "GET_STATS": {
				if (message.tabId !== undefined && !isTabId(message.tabId)) return fail("BAD_MESSAGE");
				const tabId = who.kind === "content" ? who.tabId : (message.tabId as number | undefined);
				return { ok: true, stats: await getStats(tabId) };
			}
			case "SET_USER_SETTINGS":
				return extensionOnly() ? fail("NOT_ALLOWED") : setUserSettings(message.settings);
			case "PAUSE":
				return extensionOnly() ? fail("NOT_ALLOWED") : pause(message.minutes);
			case "NATIVE_SCAN":
				return nativeScan(message.text);
			case "SET_RESTORE_VISIBLE":
				return setRestoreVisible(message.visible, who);
			default:
				return fail("BAD_MESSAGE");
		}
	}

	async function handleMessage(message: unknown, sender: MessageSender): Promise<GuardResponse> {
		try {
			return await dispatch(message, sender);
		} catch {
			return fail("INTERNAL");
		}
	}

	// Listeners are registered synchronously so a woken service worker receives the event.
	chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
		void handleMessage(message, sender).then(sendResponse);
		return true;
	});
	chrome.runtime.onInstalled.addListener(() => {
		void reload(false);
		void ensureTelemetryAlarm();
	});
	chrome.runtime.onStartup.addListener(() => {
		void reload(false);
		void ensureTelemetryAlarm();
	});
	chrome.storage.onChanged.addListener((changes: Record<string, StorageChange>, area: string) => {
		if (area === "managed" || (area === "local" && STORAGE_KEYS.userSettings in changes))
			void reload(true);
	});
	chrome.alarms.onAlarm.addListener((alarm) => {
		if (alarm.name === TELEMETRY_ALARM) void telemetry.flush();
		else if (alarm.name === PAUSE_ALARM) void broadcastPolicy();
	});
	chrome.tabs.onRemoved.addListener((tabId) => {
		void stats.removeTab(tabId);
	});
	chrome.tabs.onUpdated?.addListener((tabId, changeInfo, tab) => {
		const url = updatedTabUrl(changeInfo, tab);
		if (!isTabId(tabId) || url === undefined) return;
		void (async () => {
			await ready;
			await redirectBlockedTab(chrome, tabId, url);
		})().catch(() => log("dnr: could not show the blocked-site page"));
	});

	const ready: Promise<void> = (async () => {
		await storage.restrictSessionAccess();
		await reload(false).catch(() => log("policy: initial load failed; defaults in force"));
		await ensureTelemetryAlarm();
	})();

	return {
		ready,
		telemetry,
		stats,
		handleMessage,
		reload,
		policy: () => current,
		warnings: () => currentWarnings,
	};
}

const runtimeChrome = getChrome();
if (runtimeChrome) startBackground({ chrome: runtimeChrome });
