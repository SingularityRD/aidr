/**
 * Per-tab and global protection counters, persisted in chrome.storage.session so they
 * survive service-worker restarts but never touch disk. Counts only.
 */
import { ENTITY_TYPES, type EntityType, type PrivacyScanEvent, type SiteId } from "../types.js";
import { SITE_ID_LIST } from "./policy.js";
import { type GuardStorage, STORAGE_KEYS } from "./storage.js";
import { sanitizeCounts } from "./telemetry.js";

export interface StatsCounters {
	readonly protectedPrompts: number;
	readonly maskedItems: number;
	readonly blockedSends: number;
	readonly byType: Readonly<Partial<Record<EntityType, number>>>;
}

interface TabCounters extends StatsCounters {
	readonly site: SiteId;
}

interface StatsSnapshot {
	global: StatsCounters;
	tabs: Record<string, TabCounters>;
}

const COUNTER_MAX = Number.MAX_SAFE_INTEGER;
const MAX_TABS = 512;

const EMPTY_COUNTERS: StatsCounters = Object.freeze({
	protectedPrompts: 0,
	maskedItems: 0,
	blockedSends: 0,
	byType: Object.freeze({}),
});

function count(n: unknown): number {
	return Number.isSafeInteger(n) && (n as number) > 0 ? (n as number) : 0;
}

function readCounters(raw: unknown): StatsCounters {
	if (!raw || typeof raw !== "object") return EMPTY_COUNTERS;
	const r = raw as Record<string, unknown>;
	const byType: Partial<Record<EntityType, number>> = {};
	if (r.byType && typeof r.byType === "object") {
		for (const type of ENTITY_TYPES) {
			const n = count((r.byType as Record<string, unknown>)[type]);
			if (n) byType[type] = n;
		}
	}
	return {
		protectedPrompts: count(r.protectedPrompts),
		maskedItems: count(r.maskedItems),
		blockedSends: count(r.blockedSends),
		byType,
	};
}

function readSnapshot(raw: unknown): StatsSnapshot {
	const r = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
	const tabs: Record<string, TabCounters> = {};
	if (r.tabs && typeof r.tabs === "object") {
		for (const [key, value] of Object.entries(r.tabs as Record<string, unknown>)) {
			if (!/^\d{1,10}$/.test(key) || !value || typeof value !== "object") continue;
			const site = (value as Record<string, unknown>).site;
			if (!SITE_ID_LIST.includes(site as SiteId)) continue;
			tabs[key] = { ...readCounters(value), site: site as SiteId };
		}
	}
	return { global: readCounters(r.global), tabs };
}

const add = (a: number, b: number) => Math.min(COUNTER_MAX, a + b);

function apply(
	base: StatsCounters,
	action: PrivacyScanEvent["action"],
	counts: Partial<Record<EntityType, number>>,
): StatsCounters {
	let items = 0;
	const byType: Partial<Record<EntityType, number>> = { ...base.byType };
	for (const [type, n] of Object.entries(counts) as [EntityType, number][]) {
		items += n;
		byType[type] = add(byType[type] ?? 0, n);
	}
	const intervened = action === "masked" || action === "blocked";
	return {
		protectedPrompts: add(base.protectedPrompts, intervened ? 1 : 0),
		maskedItems: add(base.maskedItems, action === "masked" ? items : 0),
		blockedSends: add(base.blockedSends, action === "blocked" ? 1 : 0),
		byType,
	};
}

export class StatsStore {
	private chain: Promise<unknown> = Promise.resolve();

	constructor(private readonly storage: GuardStorage) {}

	/**
	 * Applies one RECORD. `protectedPrompts` counts sends the guard masked or blocked,
	 * `maskedItems` the entities replaced by placeholders, `byType` every detection.
	 * Returns the tab's counters after the update (global counters when no tab).
	 */
	record(
		tabId: number | undefined,
		site: SiteId,
		action: PrivacyScanEvent["action"],
		rawCounts: unknown,
	): Promise<StatsCounters> {
		const counts = sanitizeCounts(rawCounts);
		return this.serial(async () => {
			const snapshot = await this.load();
			snapshot.global = apply(snapshot.global, action, counts);
			let result = snapshot.global;
			if (tabId !== undefined) {
				const key = String(tabId);
				const previous = snapshot.tabs[key];
				const base = previous && previous.site === site ? previous : EMPTY_COUNTERS;
				delete snapshot.tabs[key];
				const next = { ...apply(base, action, counts), site };
				snapshot.tabs[key] = next;
				const keys = Object.keys(snapshot.tabs);
				for (const stale of keys.slice(0, Math.max(0, keys.length - MAX_TABS)))
					delete snapshot.tabs[stale];
				result = next;
			}
			await this.storage.setSession(STORAGE_KEYS.stats, snapshot);
			return result;
		});
	}

	/** Counters for one tab (site null when the tab has no record) or the global totals. */
	get(tabId?: number): Promise<{ site: SiteId | null; counters: StatsCounters }> {
		return this.serial(async () => {
			const snapshot = await this.load();
			if (tabId === undefined) return { site: null, counters: snapshot.global };
			const tab = snapshot.tabs[String(tabId)];
			return tab ? { site: tab.site, counters: tab } : { site: null, counters: EMPTY_COUNTERS };
		});
	}

	removeTab(tabId: number): Promise<void> {
		return this.serial(async () => {
			const snapshot = await this.load();
			if (!(String(tabId) in snapshot.tabs)) return;
			delete snapshot.tabs[String(tabId)];
			await this.storage.setSession(STORAGE_KEYS.stats, snapshot);
		});
	}

	private async load(): Promise<StatsSnapshot> {
		return readSnapshot(await this.storage.getSession(STORAGE_KEYS.stats));
	}

	private serial<T>(task: () => Promise<T>): Promise<T> {
		const next = this.chain.then(task, task);
		this.chain = next.catch(() => {});
		return next;
	}
}

/** Badge label for a masked-item count ("" hides the badge). */
export function badgeText(maskedItems: number): string {
	if (maskedItems <= 0) return "";
	return maskedItems > 999 ? "999+" : String(maskedItems);
}
