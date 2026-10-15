/**
 * Browser Guard background service worker.
 *
 * Owns the effective policy (managed over user over default), per-tab statistics,
 * privacy telemetry, the site-blocking network rules and the optional native host
 * bridge, and answers GuardMessage requests from content scripts and extension pages.
 *
 * Trust model: only this extension's own contexts may talk to the worker
 * (sender.id === runtime.id). Extension pages (popup/options) may change settings;
 * content scripts are accepted only from the exact HTTPS hosts of supported sites (and of
 * administrator-configured `customSites`, where ./custom-sites.ts registers the script
 * once the user granted host access) and are limited to their own tab. Content scripts
 * never receive the telemetry API key. Shadow AI discovery and blocking (./shadow-ai.ts)
 * sees tab URLs only on origins the user granted and keeps catalog ids and counts only.
 * The per-tab placeholder vault (VAULT_SAVE / VAULT_LOAD, ./vault-store.ts) is keyed by
 * the sender's tab id and page origin, so one tab or site can never read another's.
 *
 * Content scripts run in the top frame, except on the Microsoft 365 Copilot hosts
 * (../sites/frames.ts), where they also run in subframes so the Copilot pane the Office web
 * apps embed as a cross-origin iframe is guarded. A message from a subframe is accepted only
 * from those hosts; the site comes from the frame's own URL (`sender.url`), never from the
 * top-level page, so telemetry and stats are tagged `copilot`. A subframe guard keeps its own
 * vault record (`frame:` scope, so it never overwrites the top frame's) and is registered in
 * ./content-frames.ts so policy changes reach it although its tab's page is not a protected
 * site.
 *
 * Acceptable-use acknowledgements (AUP_STATUS / AUP_ACKNOWLEDGE) are kept per browser
 * profile in storage.local and reported once per notice version, counts only.
 */

import { fromBase64 } from "../../../privacy/src/browser/transport.js";
import { serviceForUrl } from "../sites/catalog.js";
import { isFrameGuardUrl } from "../sites/frames.js";
import type {
	AccountType,
	GuardError,
	GuardPolicy,
	GuardResponse,
	GuardResponses,
	GuardStats,
	NativeBridge,
	NativeNerUse,
	NativeScanOptions,
	PrivacyScanEvent,
	SiteAccessStatus,
	SiteId,
	UserSettings,
} from "../types.js";
import { ContentFrames } from "./content-frames.js";
import { CustomSiteScripts, customSiteForUrl, originGranted } from "./custom-sites.js";
import {
	DASHBOARD_POLICY_ALARM,
	DASHBOARD_POLICY_LIMITS,
	DashboardPolicyClient,
	withDashboardPolicy,
} from "./dashboard-policy.js";
import { applyBlockedSites, redirectBlockedTab, siteForUrl, updatedTabUrl } from "./dnr.js";
import { createNativeBridge, NATIVE_MAX_IMAGE_BYTES } from "./native.js";
import { ContentTabs, injectOpenTabs, injectOpenTabsOnce } from "./open-tabs.js";
import {
	DEFAULT_POLICY,
	evaluatePolicy,
	NOTICE_ID_PATTERN,
	validateUserSettings,
} from "./policy.js";
import {
	applyShadowRules,
	blockedServices,
	ShadowAiMonitor,
	ShadowAiUsageStore,
	shadowAiOrigins,
} from "./shadow-ai.js";
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
	isAccountType,
	type NavigatorLike,
	POLICY_ERRORS_MAX,
	TELEMETRY_ALARM,
	TELEMETRY_LIMITS,
	TelemetryClient,
} from "./telemetry.js";
import { VaultStore } from "./vault-store.js";

const PAUSE_ALARM = "aidr-pause-end";
/** Acknowledged notice ids kept in storage.local (older ids are dropped first). */
const AUP_ACK_MAX_IDS = 16;
const PAUSE_MAX_MINUTES = 60;
/** Upper bound for text proxied to the native host in one NATIVE_SCAN. */
const NATIVE_SCAN_MAX_CHARS = 1_000_000;

const ACTIONS: readonly PrivacyScanEvent["action"][] = ["masked", "blocked", "warned", "allowed"];
const CHANNELS: readonly PrivacyScanEvent["channel"][] = ["prompt", "paste", "file"];
const NATIVE_NER_USES: readonly NativeNerUse[] = ["used", "unavailable"];

/** RECORD fields: a known action and channel, optional native NER and account enums. */
function isRecordMessage(message: Record<string, unknown>): boolean {
	const { action, channel, native, account } = message;
	return (
		ACTIONS.includes(action as PrivacyScanEvent["action"]) &&
		CHANNELS.includes(channel as PrivacyScanEvent["channel"]) &&
		(native === undefined || NATIVE_NER_USES.includes(native as NativeNerUse)) &&
		(account === undefined || isAccountType(account))
	);
}
/** policy.requireNativeNer: only a host answer with NER coverage counts (see native.ts). */
const REQUIRE_NER: NativeScanOptions = Object.freeze({ requireNer: true });
/** After the native host could not supply exact-data keys, ask again no sooner than this. */
const EXACT_DATA_KEY_RETRY_MS = 30_000;

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
	readonly shadowUsage: ShadowAiUsageStore;
	handleMessage(message: unknown, sender: MessageSender): Promise<GuardResponse>;
	reload(broadcast: boolean): Promise<GuardPolicy>;
	policy(): GuardPolicy;
	warnings(): readonly string[];
	/** Tab ids the start-up injection reached (./open-tabs.ts); resolves after `ready`. */
	readonly openTabsInjected: Promise<readonly number[]>;
}

type Sender =
	| { readonly kind: "extension"; readonly tabId: number | undefined }
	| {
			readonly kind: "content";
			readonly tabId: number;
			readonly site: SiteId;
			/** Page origin from the sender URL (vault persistence is keyed by tab + origin). */
			readonly origin: string;
			readonly topFrame: boolean;
			/** Sender frame id (0 = top frame). */
			readonly frameId: number;
	  };

const fail = (error: string, keys?: readonly string[]): GuardError =>
	keys ? { ok: false, error, keys } : { ok: false, error };

function isRecord(raw: unknown): raw is Record<string, unknown> {
	return raw !== null && typeof raw === "object" && !Array.isArray(raw);
}

const isTabId = (raw: unknown): raw is number => Number.isSafeInteger(raw) && (raw as number) >= 0;

/** Content scripts run in the top frame, plus subframes of the frame-guarded hosts. */
const isTopFrame = (sender: MessageSender): boolean => (sender.frameId ?? 0) === 0;

export function startBackground(options: BackgroundOptions): BackgroundController {
	const { chrome } = options;
	const now = options.now ?? Date.now;
	const log = options.log ?? ((m: string) => console.warn(`[aidr-browser-guard] ${m}`));
	const bridgeFactory = options.createNativeBridge ?? createNativeBridge;
	const storage = new GuardStorage(chrome, log);
	const stats = new StatsStore(storage);
	const vaults = new VaultStore(storage, now);
	const shadowUsage = new ShadowAiUsageStore(storage, now);
	const shadowMonitor = new ShadowAiMonitor({ chrome, usage: shadowUsage, now });
	const customScripts = new CustomSiteScripts(chrome, log);
	const contentTabs = new ContentTabs(storage);
	const contentFrames = new ContentFrames(storage);
	const fetchImpl: typeof fetch = options.fetch ?? ((...args) => globalThis.fetch(...args));
	const dashboard = new DashboardPolicyClient({ storage, fetch: fetchImpl, now, log });
	const telemetry = new TelemetryClient({
		storage,
		fetch: fetchImpl,
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
	/**
	 * Exact-data keys the native host derived for the policy's datasets, by dataset id. Memory
	 * only: never persisted and never sent to extension pages, only to content scripts (BG-8).
	 */
	let exactDataKeys: ReadonlyMap<string, string> = new Map();
	let exactDataKeyRequest: Promise<void> | null = null;
	let exactDataKeyRetryAt = 0;
	let reloadChain: Promise<unknown> = Promise.resolve();
	let tabEvents: Promise<unknown> = Promise.resolve();
	const extensionBase = chrome.runtime.getURL("");

	/** An extension page (popup, options) of this extension, unless its origin disagrees. */
	function extensionSender(sender: MessageSender): Sender | null {
		if (sender.origin !== undefined && `${sender.origin}/` !== extensionBase) return null;
		return { kind: "extension", tabId: isTabId(sender.tab?.id) ? sender.tab.id : undefined };
	}

	/**
	 * Site whose content script may run on `url`: an exact built-in host, or an exact host
	 * of a custom site in the current policy (its script is only registered there).
	 */
	function contentSiteForUrl(url: unknown): SiteId | null {
		return siteForUrl(url) ?? (customSiteForUrl(url, current.customSites) ? "custom" : null);
	}

	function classifySender(sender: MessageSender | undefined): Sender | null {
		if (!sender || sender.id !== chrome.runtime.id) return null;
		if (typeof sender.url === "string" && sender.url.startsWith(extensionBase)) {
			return extensionSender(sender);
		}
		const tabId = sender.tab?.id;
		const site = contentSiteForUrl(sender.url);
		if (!isTabId(tabId) || !site) return null;
		const topFrame = isTopFrame(sender);
		// Subframe content scripts exist only on the frame-guarded hosts (the manifest's
		// all_frames entry); anything else claiming to be one is refused.
		if (!topFrame && !isFrameGuardUrl(sender.url)) return null;
		// siteForUrl accepted the URL, so it parses.
		const origin = new URL(sender.url as string).origin;
		return { kind: "content", tabId, site, origin, topFrame, frameId: sender.frameId ?? 0 };
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
			// Only the content script fingerprints prompts; a dataset whose key has not arrived
			// stays keyless there, so its scans are incomplete (fail closed).
			exactData: forContent ? exactDataWithKeys() : current.exactData,
		});
	}

	function exactDataWithKeys(): GuardPolicy["exactData"] {
		return current.exactData.map((set) => {
			const keyB64 = exactDataKeys.get(set.datasetId);
			return keyB64 ? Object.freeze({ ...set, keyB64 }) : set;
		});
	}

	/**
	 * Asks the native host for the keys of the policy's exact-data datasets that have none yet,
	 * then pushes the keyed policy to open tabs. One request at a time; after a miss, no new
	 * request for EXACT_DATA_KEY_RETRY_MS (content scripts ask again through GET_POLICY).
	 */
	function refreshExactDataKeys(): void {
		const missing = current.exactData
			.map((set) => set.datasetId)
			.filter((id) => !exactDataKeys.has(id));
		const target = bridge;
		if (!missing.length || !target?.exactDataKeys || exactDataKeyRequest) return;
		if (now() < exactDataKeyRetryAt) return;
		exactDataKeyRequest = (async () => {
			const keys = await target.exactDataKeys?.(missing).catch(() => null);
			if (target !== bridge) return;
			const got = Object.entries(keys ?? {}).filter(([id]) => missing.includes(id));
			if (got.length) {
				exactDataKeys = new Map([...exactDataKeys, ...got]);
				await broadcastPolicy();
			}
			if (got.length < missing.length) {
				exactDataKeyRetryAt = now() + EXACT_DATA_KEY_RETRY_MS;
				log(
					"exactData: the native host gave no key for some datasets; their scans stay incomplete",
				);
			}
		})().finally(() => {
			exactDataKeyRequest = null;
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
		const frames = await contentFrames.list().catch(() => []);
		const send = (tabId: number, frameId: number, site: SiteId) =>
			chrome.tabs
				.sendMessage(
					tabId,
					{ type: "POLICY_CHANGED", policy: effectivePolicy(site, true, paused) },
					{ frameId },
				)
				.catch(() => {});
		await Promise.all([
			// Top frames, each with the policy of its own site; a subframe guard (which may be
			// another site than its tab's page) gets the policy of its own site below.
			...tabs.map(async (tab) => {
				const site = contentSiteForUrl(tab.url);
				if (!isTabId(tab.id) || !site) return;
				await send(tab.id, 0, site);
			}),
			...frames.map((frame) => send(frame.tabId, frame.frameId, frame.site)),
		]);
	}

	/** (Re)creates the native bridge: on a policy change, or after the permission changed. */
	function resetBridge(): void {
		bridgeEnabled = current.useNativeHost;
		exactDataKeys = new Map();
		exactDataKeyRetryAt = 0;
		try {
			bridge = bridgeFactory(current.useNativeHost);
		} catch {
			bridge = null;
			log("native: bridge unavailable");
		}
	}

	/**
	 * Signed dashboard decisions, only with an administrator-pinned trust anchor; they can
	 * tighten the enterprise Shadow AI policy and switch on `requireNativeNer`, never relax
	 * either (./dashboard-policy.ts).
	 */
	async function applyDashboardDecisions(
		policy: GuardPolicy,
		warnings: string[],
	): Promise<GuardPolicy> {
		const trust = policy.dashboardPolicy ?? null;
		const decisions = trust ? await dashboard.stored(trust) : null;
		if (decisions?.expired)
			warnings.push("dashboard: Shadow AI decisions expired; blocks kept, sanctions dropped");
		const applied = withDashboardPolicy(policy, decisions);
		if (applied.requireNativeNer === true && policy.requireNativeNer !== true)
			warnings.push('dashboard: "requireNativeNer" on; "useNativeHost" forced on');
		return applied;
	}

	async function loadPolicy(broadcast: boolean): Promise<GuardPolicy> {
		const managed = await storage.readManaged();
		// If managed policy state is unknown, it is treated as a managed policy without valid
		// keys: user settings must not weaken the defaults, pause and send-original are off.
		const user = managed.status === "error" ? undefined : await storage.readUserSettings();
		const evaluation = evaluatePolicy(managed.status === "ok" ? managed.value : undefined, user, {
			managedUnavailable: managed.status === "error",
		});
		const warnings = [...evaluation.warnings];
		current = await applyDashboardDecisions(evaluation.policy, warnings);
		currentWarnings = warnings;
		for (const warning of currentWarnings) log(`policy: ${warning}`);

		if (bridgeEnabled !== current.useNativeHost) resetBridge();
		// Keys of datasets that left the policy are forgotten.
		const datasetIds = new Set(current.exactData.map((set) => set.datasetId));
		exactDataKeys = new Map([...exactDataKeys].filter(([id]) => datasetIds.has(id)));
		refreshExactDataKeys();
		if (!(await applyBlockedSites(chrome, current.blockedSites)))
			log("dnr: failed to update blocked-site rules");
		if (!(await applyShadowRules(chrome, current.shadowAi)))
			log("dnr: failed to update Shadow AI rules");
		enforceBlocksOnOpenTabs();
		await customScripts.sync(current.customSites);
		await telemetry.configure(current.telemetry);
		if (!current.telemetry) await shadowUsage.clearPending();
		if (broadcast) await broadcastPolicy();
		return current;
	}

	/**
	 * The block rules stop the next navigation only. A tab already open on a site or service
	 * the policy now blocks is sent to blocked.html at once (queued with the tabs.onUpdated
	 * events, so it is counted like a refused navigation). Tabs whose URL the browser does not
	 * report (Shadow AI hosts without a grant) are cut off by the Shadow AI API rules instead.
	 */
	function enforceBlocksOnOpenTabs(): void {
		const blockedIds = new Set(blockedServices(current.shadowAi).map((s) => s.id));
		const blockedSites = current.blockedSites;
		if (blockedIds.size === 0 && blockedSites.length === 0) return;
		const blocked = (url: string) => {
			const site = siteForUrl(url);
			const service = serviceForUrl(url);
			return (
				(site !== null && blockedSites.includes(site)) || (!!service && blockedIds.has(service.id))
			);
		};
		void chrome.tabs
			.query({})
			.then((tabs) => {
				for (const tab of tabs) {
					if (isTabId(tab.id) && typeof tab.url === "string" && blocked(tab.url))
						queueTabUrl(tab.id, tab.url);
				}
			})
			.catch(() => log("tabs: query failed; open tabs not checked against blocks"));
	}

	/** What ./open-tabs.ts needs to inject into open protected tabs without a live script. */
	function injectDeps() {
		return {
			chrome,
			contentTabs,
			protectedUrl: (url: string | undefined) => contentSiteForUrl(url) !== null,
			log,
		};
	}

	/** Aggregated Shadow AI counts become telemetry events just before each flush. */
	async function queueShadowTelemetry(): Promise<void> {
		if (!telemetry.enabled) return;
		const sanctioned = new Set(current.shadowAi.sanctioned);
		for (const delta of await shadowUsage.drainPending()) {
			for (const action of ["visited", "blocked"] as const) {
				const count = delta[action];
				if (count < 1) continue;
				await telemetry.recordShadow({
					serviceId: delta.serviceId,
					action,
					count,
					sanctioned: sanctioned.has(delta.serviceId),
					policyId: current.policyId,
				});
			}
		}
	}

	async function siteAccess(): Promise<SiteAccessStatus> {
		const policy = current.shadowAi;
		const origins = shadowAiOrigins(policy);
		const granted = await Promise.all(origins.map((o) => originGranted(chrome, o)));
		const [usage, customSites] = await Promise.all([
			shadowUsage.usage(),
			customScripts.status(current.customSites),
		]);
		return {
			shadowAi: {
				mode: policy.mode,
				blocked: blockedServices(policy).map((s) => s.id),
				origins,
				missingOrigins: origins.filter((_, i) => !granted[i]),
				usage,
			},
			customSites,
		};
	}

	let dashboardChain: Promise<unknown> = Promise.resolve();

	/**
	 * Fetches the signed dashboard document (one at a time) and reloads the effective
	 * policy when a new verified one was stored. Needs the managed trust anchor and a
	 * telemetry endpoint; without them the stored document (if any) stays as it is.
	 */
	function refreshDashboardPolicy(): Promise<void> {
		const task = async () => {
			const trust = current.dashboardPolicy ?? null;
			const endpoint = current.telemetry;
			if (!trust || !endpoint) return;
			if (await dashboard.refresh(trust, endpoint)) await reload(true);
		};
		const next = dashboardChain.then(task, task);
		dashboardChain = next.catch(() => log("dashboard policy: refresh failed"));
		return dashboardChain as Promise<void>;
	}

	async function ensureDashboardAlarm(): Promise<void> {
		try {
			const existing = await chrome.alarms.get?.(DASHBOARD_POLICY_ALARM);
			if (!existing)
				await chrome.alarms.create(DASHBOARD_POLICY_ALARM, {
					periodInMinutes: DASHBOARD_POLICY_LIMITS.refreshMinutes,
				});
		} catch {
			log("alarms: dashboard policy refresh alarm unavailable");
		}
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

	/** Whether `tabId` runs a live content script for the page it currently shows. */
	async function contentActive(tabId: number): Promise<boolean> {
		let url: string | undefined;
		try {
			url = (await chrome.tabs.get?.(tabId))?.url;
		} catch {
			return false;
		}
		return contentTabs.isLive(tabId, url);
	}

	async function getStats(tabId: number | undefined): Promise<GuardStats> {
		const [{ site, counters }, paused, active] = await Promise.all([
			stats.get(tabId),
			pausedUntil(),
			tabId === undefined ? undefined : contentActive(tabId),
		]);
		return {
			site,
			protectedPrompts: counters.protectedPrompts,
			maskedItems: counters.maskedItems,
			blockedSends: counters.blockedSends,
			byType: counters.byType,
			pausedUntil: current.allowUserPause ? paused : null,
			nativeHost: current.useNativeHost && bridge ? bridge.status() : "disabled",
			...(active === undefined ? {} : { contentActive: active }),
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
		if (!current.useNativeHost || !bridge) return { ok: true, findings: null, status: "disabled" };
		const used = bridge;
		let findings: GuardResponses["NATIVE_SCAN"]["findings"] = null;
		try {
			findings = current.requireNativeNer
				? await used.scanText(text, REQUIRE_NER)
				: await used.scanText(text);
		} catch {
			findings = null;
		}
		return { ok: true, findings, status: used.status() };
	}

	/** OCR of one uploaded image through the native host (counts-only verdict, see native.ts). */
	async function nativeImageScan(data: unknown): Promise<GuardResponse> {
		let bytes: Uint8Array;
		try {
			bytes = fromBase64(data, NATIVE_MAX_IMAGE_BYTES);
		} catch {
			return fail("BAD_MESSAGE");
		}
		try {
			if (!current.useNativeHost || !bridge?.scanImage)
				return { ok: true, inspection: null, status: "disabled" };
			const used = bridge;
			let inspection: GuardResponses["NATIVE_IMAGE_SCAN"]["inspection"] = null;
			try {
				const options = current.requireNativeNer ? [REQUIRE_NER] : [];
				inspection = (await used.scanImage?.(bytes, ...options)) ?? null;
			} catch {
				inspection = null;
			}
			return { ok: true, inspection, status: used.status() };
		} finally {
			bytes.fill(0);
		}
	}

	/**
	 * Vault record scope: the page origin for the top frame, `frame:<origin>` for a subframe
	 * guard, so a Copilot frame never overwrites (or reads) the top frame's record, even on
	 * the same origin.
	 */
	const vaultScope = (who: Extract<Sender, { kind: "content" }>): string =>
		who.topFrame ? who.origin : `frame:${who.origin}`;

	async function vaultSave(message: Record<string, unknown>, who: Sender): Promise<GuardResponse> {
		if (who.kind !== "content") return fail("NOT_ALLOWED");
		const result = await vaults.save(who.tabId, vaultScope(who), message.snapshot, message.sent);
		if (result === "invalid") return fail("BAD_MESSAGE");
		if (result === "too-large") return fail("TOO_LARGE");
		return { ok: true };
	}

	async function vaultLoad(who: Sender): Promise<GuardResponse> {
		if (who.kind !== "content") return fail("NOT_ALLOWED");
		const stored = await vaults.load(who.tabId, vaultScope(who));
		return { ok: true, snapshot: stored?.snapshot ?? null, sent: stored?.sent ?? [] };
	}

	async function setRestoreVisible(visible: unknown, who: Sender): Promise<GuardResponse> {
		if (typeof visible !== "boolean") return fail("BAD_MESSAGE");
		let tabId = who.tabId;
		if (tabId === undefined) {
			const [active] = await chrome.tabs
				.query({ active: true, lastFocusedWindow: true })
				.catch(() => []);
			if (
				!active ||
				!isTabId(active.id) ||
				!(contentSiteForUrl(active.url) || (await contentFrames.has(active.id)))
			)
				return fail("NOT_ALLOWED");
			tabId = active.id;
		}
		await chrome.tabs.sendMessage(tabId, { type: "SET_RESTORE_VISIBLE", visible }).catch(() => {});
		return { ok: true };
	}

	async function record(message: Record<string, unknown>, who: Sender): Promise<GuardResponse> {
		if (who.kind !== "content") return fail("NOT_ALLOWED");
		const { action, channel, counts, native, account } = message;
		if (!isRecordMessage(message)) return fail("BAD_MESSAGE");
		const marks = await telemetryMarks();
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
				...(native !== undefined ? { nativeNer: native as NativeNerUse } : {}),
				...(account !== undefined ? { accountType: account as AccountType } : {}),
				...marks,
			})
			.catch(() => log("telemetry: failed to queue event"));
		return { ok: true };
	}

	/** A send during a user pause, and invalid managed keys in force (counts only). */
	async function telemetryMarks(): Promise<{ paused?: true; policyErrors?: number }> {
		const paused = current.allowUserPause && (await pausedUntil()) !== null;
		const policyErrors = Math.min(current.policyErrors?.length ?? 0, POLICY_ERRORS_MAX);
		return {
			...(paused ? { paused: true as const } : {}),
			...(policyErrors > 0 ? { policyErrors } : {}),
		};
	}

	/** Notice id -> highest acknowledged version, from storage.local (malformed entries dropped). */
	async function acknowledgements(): Promise<Record<string, number>> {
		const raw = await storage.getLocal(STORAGE_KEYS.aupAcknowledged);
		const out: Record<string, number> = {};
		if (!isRecord(raw)) return out;
		for (const [id, version] of Object.entries(raw)) {
			if (NOTICE_ID_PATTERN.test(id) && Number.isSafeInteger(version) && (version as number) > 0)
				out[id] = version as number;
		}
		return out;
	}

	async function aupStatus(): Promise<GuardResponse> {
		const notice = current.acceptableUse ?? null;
		if (!notice) return { ok: true, notice: null, acknowledged: true };
		const acknowledged = ((await acknowledgements())[notice.id] ?? 0) >= notice.version;
		return { ok: true, notice, acknowledged };
	}

	let ackChain: Promise<unknown> = Promise.resolve();

	/** Records "I understand" for the notice in force; one telemetry event per new version. */
	function aupAcknowledge(message: Record<string, unknown>, who: Sender): Promise<GuardResponse> {
		// Subframe senders are already limited to the frame-guarded hosts (classifySender).
		if (who.kind !== "content") return Promise.resolve(fail("NOT_ALLOWED"));
		const notice = current.acceptableUse ?? null;
		if (!notice || message.noticeId !== notice.id || message.version !== notice.version)
			return Promise.resolve(fail("BAD_MESSAGE"));
		const task = async (): Promise<GuardResponse> => {
			const known = await acknowledgements();
			if ((known[notice.id] ?? 0) >= notice.version) return { ok: true };
			delete known[notice.id];
			const kept = Object.entries(known).slice(-(AUP_ACK_MAX_IDS - 1));
			const next = Object.fromEntries([...kept, [notice.id, notice.version]]);
			if (!(await storage.setLocal(STORAGE_KEYS.aupAcknowledged, next))) return fail("INTERNAL");
			void telemetry
				.recordAcknowledgement({
					site: who.site,
					noticeId: notice.id,
					noticeVersion: notice.version,
				})
				.catch(() => log("telemetry: failed to queue acknowledgement"));
			return { ok: true };
		};
		const result = ackChain.then(task, task);
		ackChain = result.catch(() => {});
		return result;
	}

	async function policyFor(who: Sender): Promise<GuardResponse> {
		const content = who.kind === "content";
		if (content) {
			// A content script fetches its policy when it boots: the tab is protected from now on.
			if (who.topFrame) await contentTabs.mark(who.tabId, who.origin);
			// A subframe guard (the Copilot pane of an Office web app) is registered for policy pushes.
			else await contentFrames.mark(who.tabId, who.frameId, who.site);
			refreshExactDataKeys();
		}
		return {
			ok: true,
			policy: effectivePolicy(content ? who.site : null, content, await pausedUntil()),
		};
	}

	/** Content scripts only ever see their own tab's stats; extension pages may name a tab. */
	async function statsFor(requested: unknown, who: Sender): Promise<GuardResponse> {
		if (requested !== undefined && !isTabId(requested)) return fail("BAD_MESSAGE");
		const tabId = who.kind === "content" ? who.tabId : (requested as number | undefined);
		return { ok: true, stats: await getStats(tabId) };
	}

	async function dispatch(message: unknown, sender: MessageSender): Promise<GuardResponse> {
		let who = classifySender(sender);
		if (!who && sender?.id === chrome.runtime.id) {
			// A custom-site content script is recognised from the loaded policy.
			await ready;
			who = classifySender(sender);
		}
		if (!who) return fail("SENDER_DENIED");
		if (!isRecord(message) || typeof message.type !== "string") return fail("BAD_MESSAGE");
		await ready;
		const extensionOnly = () => who.kind !== "extension";
		switch (message.type) {
			case "GET_POLICY":
				return policyFor(who);
			case "RECORD":
				return record(message, who);
			case "GET_STATS":
				return statsFor(message.tabId, who);
			case "SET_USER_SETTINGS":
				return extensionOnly() ? fail("NOT_ALLOWED") : setUserSettings(message.settings);
			case "PAUSE":
				return extensionOnly() ? fail("NOT_ALLOWED") : pause(message.minutes);
			case "NATIVE_SCAN":
				return nativeScan(message.text);
			case "NATIVE_IMAGE_SCAN":
				return nativeImageScan(message.data);
			case "SET_RESTORE_VISIBLE":
				return setRestoreVisible(message.visible, who);
			case "VAULT_SAVE":
				return vaultSave(message, who);
			case "VAULT_LOAD":
				return vaultLoad(who);
			case "AUP_STATUS":
				return aupStatus();
			case "AUP_ACKNOWLEDGE":
				return aupAcknowledge(message, who);
			case "GET_SITE_ACCESS":
				return extensionOnly() ? fail("NOT_ALLOWED") : { ok: true, access: await siteAccess() };
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
		if (area === "managed") void reload(true).then(() => refreshDashboardPolicy());
		else if (area === "local" && STORAGE_KEYS.userSettings in changes) void reload(true);
	});
	chrome.alarms.onAlarm.addListener((alarm) => {
		if (alarm.name === DASHBOARD_POLICY_ALARM) void ready.then(() => refreshDashboardPolicy());
		else if (alarm.name === TELEMETRY_ALARM) {
			void queueShadowTelemetry()
				.catch(() => log("telemetry: failed to queue Shadow AI counts"))
				.then(() => telemetry.flush());
			void vaults.sweep();
		} else if (alarm.name === PAUSE_ALARM) void broadcastPolicy();
	});
	chrome.tabs.onRemoved.addListener((tabId) => {
		void stats.removeTab(tabId);
		void contentTabs.remove(tabId);
		void contentFrames.remove(tabId);
		void vaults.removeTab(tabId);
		shadowMonitor.removeTab(tabId);
	});
	// A newly granted (or revoked) nativeMessaging permission takes effect at once instead
	// of after the bridge's back-off from the earlier "not permitted" probe. A host-access
	// change re-syncs the custom-site content scripts (DNR rules need no change: they act
	// as soon as the browser grants access to the host).
	const onPermissionsChanged = (change: { permissions?: string[]; origins?: string[] }) => {
		if (change?.permissions?.includes("nativeMessaging")) {
			void ready.then(() => {
				if (current.useNativeHost) resetBridge();
			});
		}
		if (change?.origins?.length) {
			// A new grant also protects the custom-site tabs that are already open.
			void ready
				.then(() => customScripts.sync(current.customSites))
				.then(() => injectOpenTabs(injectDeps()))
				.catch(() => log("custom sites: re-sync failed"));
		}
	};
	chrome.permissions?.onAdded?.addListener(onPermissionsChanged);
	chrome.permissions?.onRemoved?.addListener(onPermissionsChanged);
	/** Handled one at a time, in arrival order, so a visit is never counted twice. */
	function queueTabUrl(tabId: number, url: string): void {
		const task = async () => {
			await ready;
			const site = await redirectBlockedTab(chrome, tabId, url);
			await shadowMonitor.observe(tabId, url, {
				policy: current.shadowAi,
				blockedBySite: site !== null,
				report: telemetry.enabled,
			});
		};
		tabEvents = tabEvents.then(task).catch(() => log("dnr: could not show the blocked-site page"));
	}
	chrome.tabs.onUpdated?.addListener((tabId, changeInfo, tab) => {
		const url = updatedTabUrl(changeInfo, tab);
		if (isTabId(tabId) && url !== undefined) queueTabUrl(tabId, url);
	});

	const ready: Promise<void> = (async () => {
		await storage.restrictSessionAccess();
		await reload(false).catch(() => log("policy: initial load failed; defaults in force"));
		await ensureTelemetryAlarm();
		await ensureDashboardAlarm();
		await vaults.sweep();
	})();
	// Not awaited by `ready`: the stored dashboard document is already applied, and a slow
	// control plane must not delay message handling.
	void ready.then(() => refreshDashboardPolicy());
	// Install, update, enable and browser start-up all start a fresh worker with an empty
	// storage.session: protect the AI tabs that were already open (./open-tabs.ts).
	const openTabsInjected: Promise<readonly number[]> = ready
		.then(() => injectOpenTabsOnce(storage, injectDeps()))
		.catch(() => {
			log("tabs: open-tab injection failed");
			return [];
		});

	return {
		ready,
		telemetry,
		stats,
		shadowUsage,
		handleMessage,
		reload,
		policy: () => current,
		warnings: () => currentWarnings,
		openTabsInjected,
	};
}

const runtimeChrome = getChrome();
if (runtimeChrome) startBackground({ chrome: runtimeChrome });
