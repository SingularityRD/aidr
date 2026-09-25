/**
 * Shadow AI discovery and control (managed key `shadowAi`, catalog in src/sites/catalog.ts).
 *
 * Enforcement: one declarativeNetRequest dynamic rule per blocked service refuses its
 * top-level navigations and framed embeds; the worker then shows blocked.html in the tab
 * (`?service=<id>`), exactly like the built-in blocked-site flow in ./dnr.ts.
 *
 * Visibility: tabs.onUpdated reports a tab's URL only for hosts the extension has host
 * access to, so counting (and, under `declarativeNetRequestWithHostAccess`, blocking) a
 * catalogued service needs access to its origin. That access is requested from the
 * options page (optional host permissions, one grant for the catalog origins) instead of
 * the `tabs` or `webNavigation` permissions, which would expose every URL the user visits.
 * Only the catalog id of a matched host is ever kept: never the URL, path or title.
 *
 * Counts: a "visit" is a tab entering a service (in-app navigation inside the same
 * service is not counted again); a "blocked" count is a refused navigation. Per-day
 * counts are kept in chrome.storage.local for 30 days (options page) and, when telemetry
 * is configured, aggregated into `shadow_ai_usage` events at every telemetry flush.
 */
import {
	AI_SERVICES,
	type AiService,
	serviceById,
	serviceForUrl,
	serviceOrigins,
} from "../sites/catalog.js";
import type { ShadowAiDailyUsage, ShadowAiPolicy } from "../types.js";
import type { ChromeApi, DnrRule, GuardStorage } from "./storage.js";
import { STORAGE_KEYS } from "./storage.js";

/** Dynamic rule ids owned by this module: one per catalog service (7401..). */
const SHADOW_RULE_ID_BASE = 7400;
const ruleIdFor = (index: number) => SHADOW_RULE_ID_BASE + index + 1;
export const SHADOW_DNR_RULE_IDS: readonly number[] = Object.freeze(
	AI_SERVICES.map((_, i) => ruleIdFor(i)),
);
const RULE_ID_BY_SERVICE: ReadonlyMap<string, number> = new Map(
	AI_SERVICES.map((s, i) => [s.id, ruleIdFor(i)]),
);

const BLOCKED_PAGE_PATH = "/blocked.html";
/** A second report of the same refused navigation within this window is not counted. */
const BLOCKED_DEDUPE_MS = 5_000;
export const SHADOW_USAGE_LIMITS = Object.freeze({ retentionDays: 30, countMax: 100_000 });

/**
 * Services the policy blocks: every id in `blocked` (in any mode) plus, in
 * `block-unsanctioned` mode, every catalogued service that is not sanctioned.
 */
export function blockedServices(policy: ShadowAiPolicy): AiService[] {
	const blocked = new Set(policy.blocked);
	const sanctioned = new Set(policy.sanctioned);
	return AI_SERVICES.filter(
		(s) => blocked.has(s.id) || (policy.mode === "block-unsanctioned" && !sanctioned.has(s.id)),
	);
}

/** Whether visits are counted (the administrator turned discovery on). */
export const shadowAiObserved = (policy: ShadowAiPolicy): boolean => policy.mode !== "off";

/**
 * Host-permission origins the policy needs: every catalog origin when discovery is on
 * (visibility), otherwise only those of explicitly blocked services (enforcement).
 */
export function shadowAiOrigins(policy: ShadowAiPolicy): string[] {
	return serviceOrigins(shadowAiObserved(policy) ? AI_SERVICES : blockedServices(policy));
}

export function buildShadowRules(policy: ShadowAiPolicy): DnrRule[] {
	return blockedServices(policy).map((s) => ({
		id: RULE_ID_BY_SERVICE.get(s.id) as number,
		priority: 1,
		action: { type: "block" },
		condition: { requestDomains: [...s.hosts], resourceTypes: ["main_frame", "sub_frame"] },
	}));
}

/** Replaces this module's dynamic rules with the ones for `policy`. */
export async function applyShadowRules(
	chrome: Pick<ChromeApi, "declarativeNetRequest">,
	policy: ShadowAiPolicy,
): Promise<boolean> {
	try {
		await chrome.declarativeNetRequest.updateDynamicRules({
			removeRuleIds: [...SHADOW_DNR_RULE_IDS],
			addRules: buildShadowRules(policy),
		});
		return true;
	} catch {
		return false;
	}
}

/** True when `rules` hold this module's navigation block for `service`. */
export function shadowRuleInstalled(rules: readonly DnrRule[], service: AiService): boolean {
	const id = RULE_ID_BY_SERVICE.get(service.id);
	return rules.some(
		(r) =>
			r.id === id && r.action.type === "block" && r.condition.resourceTypes.includes("main_frame"),
	);
}

type Counts = [visited: number, blocked: number];

interface UsageSnapshot {
	/** UTC day (YYYY-MM-DD) -> service id -> [visited, blocked]. */
	days: Record<string, Record<string, Counts>>;
	/** Not yet turned into telemetry events: service id -> [visited, blocked]. */
	pending: Record<string, Counts>;
}

const DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const utcDay = (ms: number): string => new Date(ms).toISOString().slice(0, 10);

function readCounts(raw: unknown): Counts | null {
	if (!Array.isArray(raw) || raw.length !== 2) return null;
	const [v, b] = raw;
	const ok = (n: unknown) =>
		Number.isSafeInteger(n) && (n as number) >= 0 && (n as number) <= Number.MAX_SAFE_INTEGER;
	return ok(v) && ok(b) ? [v as number, b as number] : null;
}

function readServiceCounts(raw: unknown): Record<string, Counts> {
	const out: Record<string, Counts> = {};
	if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
	for (const [id, value] of Object.entries(raw as Record<string, unknown>)) {
		const counts = readCounts(value);
		if (counts && serviceById(id)) out[id] = counts;
	}
	return out;
}

function readSnapshot(raw: unknown): UsageSnapshot {
	const r = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
	const days: UsageSnapshot["days"] = {};
	if (r.days && typeof r.days === "object" && !Array.isArray(r.days)) {
		for (const [day, value] of Object.entries(r.days as Record<string, unknown>)) {
			if (DAY_PATTERN.test(day)) days[day] = readServiceCounts(value);
		}
	}
	return { days, pending: readServiceCounts(r.pending) };
}

export interface ShadowAiDelta {
	readonly serviceId: string;
	readonly visited: number;
	readonly blocked: number;
}

/** Per-day counts in chrome.storage.local (counts and catalog ids only). */
export class ShadowAiUsageStore {
	private chain: Promise<unknown> = Promise.resolve();

	constructor(
		private readonly storage: GuardStorage,
		private readonly now: () => number,
	) {}

	/** Adds one visit or block; `pending` also queues it for the next telemetry flush. */
	record(serviceId: string, action: "visited" | "blocked", pending: boolean): Promise<void> {
		if (!serviceById(serviceId)) return Promise.resolve();
		return this.serial(async () => {
			const snapshot = await this.load();
			const day = utcDay(this.now());
			const slot = action === "visited" ? 0 : 1;
			const today = snapshot.days[day] ?? {};
			const counts: Counts = today[serviceId] ?? [0, 0];
			counts[slot] = Math.min(counts[slot] + 1, Number.MAX_SAFE_INTEGER);
			today[serviceId] = counts;
			snapshot.days[day] = today;
			if (pending) {
				const queued: Counts = snapshot.pending[serviceId] ?? [0, 0];
				queued[slot] = Math.min(queued[slot] + 1, SHADOW_USAGE_LIMITS.countMax);
				snapshot.pending[serviceId] = queued;
			}
			this.prune(snapshot);
			await this.storage.setLocal(STORAGE_KEYS.shadowAiUsage, snapshot);
		});
	}

	/** Local counts for the last 30 UTC days, newest day first, busiest service first. */
	usage(): Promise<ShadowAiDailyUsage[]> {
		return this.serial(async () => {
			const snapshot = await this.load();
			this.prune(snapshot);
			const out: ShadowAiDailyUsage[] = [];
			for (const day of Object.keys(snapshot.days).sort().reverse()) {
				const rows = Object.entries(snapshot.days[day] ?? {})
					.map(([serviceId, [visited, blocked]]) => ({ day, serviceId, visited, blocked }))
					.sort((a, b) => b.visited + b.blocked - (a.visited + a.blocked));
				out.push(...rows);
			}
			return out;
		});
	}

	/** Returns and clears the counts not yet sent as telemetry. */
	drainPending(): Promise<ShadowAiDelta[]> {
		return this.serial(async () => {
			const snapshot = await this.load();
			const deltas = Object.entries(snapshot.pending)
				.map(([serviceId, [visited, blocked]]) => ({ serviceId, visited, blocked }))
				.filter((d) => d.visited > 0 || d.blocked > 0);
			if (deltas.length === 0) return [];
			snapshot.pending = {};
			await this.storage.setLocal(STORAGE_KEYS.shadowAiUsage, snapshot);
			return deltas;
		});
	}

	/** Drops counts queued for telemetry (telemetry switched off or re-targeted). */
	clearPending(): Promise<void> {
		return this.serial(async () => {
			const snapshot = await this.load();
			if (Object.keys(snapshot.pending).length === 0) return;
			snapshot.pending = {};
			await this.storage.setLocal(STORAGE_KEYS.shadowAiUsage, snapshot);
		});
	}

	private prune(snapshot: UsageSnapshot): void {
		const oldest = utcDay(this.now() - (SHADOW_USAGE_LIMITS.retentionDays - 1) * 86_400_000);
		for (const day of Object.keys(snapshot.days)) if (day < oldest) delete snapshot.days[day];
	}

	private async load(): Promise<UsageSnapshot> {
		return readSnapshot(await this.storage.getLocal(STORAGE_KEYS.shadowAiUsage));
	}

	private serial<T>(task: () => Promise<T>): Promise<T> {
		const next = this.chain.then(task, task);
		this.chain = next.catch(() => {});
		return next;
	}
}

interface TabState {
	readonly serviceId: string;
	readonly action: "visited" | "blocked";
	readonly at: number;
}

export interface ShadowAiMonitorDeps {
	readonly chrome: Pick<ChromeApi, "declarativeNetRequest" | "runtime" | "tabs">;
	readonly usage: ShadowAiUsageStore;
	readonly now: () => number;
}

export interface ObserveOptions {
	readonly policy: ShadowAiPolicy;
	/** The built-in blocked-site flow already refused this navigation (./dnr.ts). */
	readonly blockedBySite: boolean;
	/** Queue the count for telemetry (telemetry is configured). */
	readonly report: boolean;
}

/**
 * Turns tabs.onUpdated URLs into Shadow AI counts and blocked-page redirects. Tab state
 * lives in memory only (a worker restart may count one visit again).
 */
export class ShadowAiMonitor {
	private readonly tabs = new Map<number, TabState>();

	constructor(private readonly deps: ShadowAiMonitorDeps) {}

	/**
	 * Handles one reported tab URL. Returns what was counted for the tab (null when the
	 * URL is not a catalogued service, or nothing new happened).
	 */
	async observe(
		tabId: number,
		url: string | undefined,
		options: ObserveOptions,
	): Promise<TabState | null> {
		const service = serviceForUrl(url);
		const inactive =
			!shadowAiObserved(options.policy) &&
			options.policy.blocked.length === 0 &&
			!options.blockedBySite;
		if (!service || inactive) {
			this.tabs.delete(tabId);
			return null;
		}
		const blocked = options.blockedBySite || (await this.redirectIfBlocked(tabId, service));
		const action = blocked ? "blocked" : "visited";
		const previous = this.tabs.get(tabId);
		const now = this.deps.now();
		if (previous?.serviceId === service.id && previous.action === action) {
			if (action === "visited" || now - previous.at < BLOCKED_DEDUPE_MS) return null;
		}
		const state: TabState = { serviceId: service.id, action, at: now };
		this.tabs.set(tabId, state);
		if (shadowAiObserved(options.policy))
			await this.deps.usage.record(service.id, action, options.report);
		return state;
	}

	removeTab(tabId: number): void {
		this.tabs.delete(tabId);
	}

	/** Shows blocked.html when this module's rule for `service` is installed. */
	private async redirectIfBlocked(tabId: number, service: AiService): Promise<boolean> {
		const { chrome } = this.deps;
		if (!chrome.declarativeNetRequest.getDynamicRules || !chrome.tabs.update) return false;
		const rules = await chrome.declarativeNetRequest.getDynamicRules();
		if (!shadowRuleInstalled(rules, service)) return false;
		await chrome.tabs.update(tabId, {
			url: chrome.runtime.getURL(`${BLOCKED_PAGE_PATH}?service=${service.id}`),
		});
		return true;
	}
}
