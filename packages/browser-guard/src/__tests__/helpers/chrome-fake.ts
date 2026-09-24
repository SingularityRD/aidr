/**
 * In-memory fake of the WebExtension APIs used by the Browser Guard background worker
 * (see src/background/storage.ts ChromeApi). Deterministic and synchronous-ish: every
 * async API resolves on the microtask queue; onChanged/onMessage listeners fire like
 * the real browser does.
 */
import type {
	ChromeApi,
	DnrRule,
	MessageListener,
	MessageSender,
	StorageAreaApi,
	StorageChange,
	TabInfo,
} from "../../background/storage.js";

export const EXTENSION_ID = "abcdefghijklmnopabcdefghijklmnop";
export const EXTENSION_BASE = `chrome-extension://${EXTENSION_ID}/`;

// biome-ignore lint/suspicious/noExplicitAny: listener lists hold heterogeneous callbacks
class FakeEvent<F extends (...args: any[]) => unknown> {
	readonly listeners: F[] = [];
	addListener(listener: F): void {
		this.listeners.push(listener);
	}
	removeListener(listener: F): void {
		const i = this.listeners.indexOf(listener);
		if (i >= 0) this.listeners.splice(i, 1);
	}
	hasListener(listener: F): boolean {
		return this.listeners.includes(listener);
	}
	dispatch(...args: Parameters<F>): unknown[] {
		return this.listeners.map((l) => l(...args));
	}
}

const clone = <T>(value: T): T => (value === undefined ? value : structuredClone(value));

export class FakeStorageArea implements StorageAreaApi {
	readonly data = new Map<string, unknown>();
	/** When set, every call rejects with this error. */
	failWith: Error | null = null;
	accessLevel: string | null = null;

	constructor(
		readonly areaName: string,
		private readonly onChanged: FakeEvent<
			(changes: Record<string, StorageChange>, area: string) => void
		>,
	) {}

	async get(
		keys?: string | string[] | Record<string, unknown> | null,
	): Promise<Record<string, unknown>> {
		if (this.failWith) throw this.failWith;
		const out: Record<string, unknown> = {};
		if (keys === undefined || keys === null) {
			for (const [k, v] of this.data) out[k] = clone(v);
		} else if (typeof keys === "string" || Array.isArray(keys)) {
			for (const k of typeof keys === "string" ? [keys] : keys)
				if (this.data.has(k)) out[k] = clone(this.data.get(k));
		} else {
			for (const [k, def] of Object.entries(keys))
				out[k] = this.data.has(k) ? clone(this.data.get(k)) : def;
		}
		return out;
	}

	async set(items: Record<string, unknown>): Promise<void> {
		if (this.failWith) throw this.failWith;
		const changes: Record<string, StorageChange> = {};
		for (const [k, v] of Object.entries(items)) {
			changes[k] = { oldValue: clone(this.data.get(k)), newValue: clone(v) };
			this.data.set(k, clone(v));
		}
		this.onChanged.dispatch(changes, this.areaName);
	}

	async remove(keys: string | string[]): Promise<void> {
		if (this.failWith) throw this.failWith;
		const changes: Record<string, StorageChange> = {};
		for (const k of typeof keys === "string" ? [keys] : keys) {
			if (!this.data.has(k)) continue;
			changes[k] = { oldValue: clone(this.data.get(k)) };
			this.data.delete(k);
		}
		if (Object.keys(changes).length) this.onChanged.dispatch(changes, this.areaName);
	}

	async setAccessLevel(options: { accessLevel: string }): Promise<void> {
		this.accessLevel = options.accessLevel;
	}

	/** Administrator/browser-side write (fires onChanged like a policy push). */
	async adminSet(items: Record<string, unknown>): Promise<void> {
		const saved = this.failWith;
		this.failWith = null;
		await this.set(items);
		this.failWith = saved;
	}

	async adminReplace(items: Record<string, unknown>): Promise<void> {
		const changes: Record<string, StorageChange> = {};
		for (const k of this.data.keys()) changes[k] = { oldValue: this.data.get(k) };
		this.data.clear();
		for (const [k, v] of Object.entries(items)) {
			changes[k] = { ...changes[k], newValue: v };
			this.data.set(k, clone(v));
		}
		this.onChanged.dispatch(changes, this.areaName);
	}
}

export interface SentTabMessage {
	readonly tabId: number;
	readonly message: unknown;
}

export interface ChromeFake {
	readonly chrome: ChromeApi;
	readonly managed: FakeStorageArea;
	readonly local: FakeStorageArea;
	readonly session: FakeStorageArea;
	readonly tabs: TabInfo[];
	readonly tabMessages: SentTabMessage[];
	readonly badges: Map<number | "global", string>;
	readonly alarms: Map<string, { periodInMinutes?: number; when?: number }>;
	readonly dnrRules: Map<number, DnrRule>;
	readonly events: {
		readonly onMessage: FakeEvent<MessageListener>;
		readonly onInstalled: FakeEvent<(details: { reason: string }) => void>;
		readonly onStartup: FakeEvent<() => void>;
		readonly onChanged: FakeEvent<(changes: Record<string, StorageChange>, area: string) => void>;
		readonly onAlarm: FakeEvent<(alarm: { name: string }) => void>;
		readonly onRemoved: FakeEvent<(tabId: number) => void>;
	};
	/** Delivers a runtime message as the browser would and resolves with the response. */
	sendRuntimeMessage(message: unknown, sender: MessageSender): Promise<unknown>;
	fireAlarm(name: string): void;
	/** Sender objects for the popup (extension page) and a content script in a tab. */
	extensionSender(page?: string): MessageSender;
	contentSender(tabId: number, url: string): MessageSender;
}

export function createChromeFake(options: { version?: string } = {}): ChromeFake {
	const onChanged = new FakeEvent<(changes: Record<string, StorageChange>, area: string) => void>();
	const events = {
		onMessage: new FakeEvent<MessageListener>(),
		onInstalled: new FakeEvent<(details: { reason: string }) => void>(),
		onStartup: new FakeEvent<() => void>(),
		onChanged,
		onAlarm: new FakeEvent<(alarm: { name: string }) => void>(),
		onRemoved: new FakeEvent<(tabId: number) => void>(),
	};
	const managed = new FakeStorageArea("managed", onChanged);
	const local = new FakeStorageArea("local", onChanged);
	const session = new FakeStorageArea("session", onChanged);
	const tabs: TabInfo[] = [];
	const tabMessages: SentTabMessage[] = [];
	const badges = new Map<number | "global", string>();
	const alarms = new Map<string, { periodInMinutes?: number; when?: number }>();
	const dnrRules = new Map<number, DnrRule>();

	const chrome: ChromeApi = {
		runtime: {
			id: EXTENSION_ID,
			getManifest: () => ({ version: options.version ?? "1.0.0" }),
			getURL: (path: string) => `${EXTENSION_BASE}${path.replace(/^\//, "")}`,
			onMessage: events.onMessage,
			onInstalled: events.onInstalled,
			onStartup: events.onStartup,
		},
		storage: { managed, local, session, onChanged },
		tabs: {
			async query(query: Record<string, unknown>) {
				return tabs
					.filter((t) => (query.active === true ? t.active === true : true))
					.map((t) => ({ ...t }));
			},
			async sendMessage(tabId: number, message: unknown) {
				if (!tabs.some((t) => t.id === tabId))
					throw new Error("Could not establish connection. Receiving end does not exist.");
				tabMessages.push({ tabId, message: clone(message) });
				return undefined;
			},
			onRemoved: events.onRemoved,
		},
		action: {
			async setBadgeText(details) {
				badges.set(details.tabId ?? "global", details.text);
			},
			async setBadgeBackgroundColor() {},
		},
		alarms: {
			async create(name, info) {
				alarms.set(name, { ...info });
			},
			async clear(name) {
				return alarms.delete(name);
			},
			async get(name) {
				return alarms.has(name) ? { name, ...alarms.get(name) } : undefined;
			},
			onAlarm: events.onAlarm,
		},
		declarativeNetRequest: {
			async updateDynamicRules({ addRules = [], removeRuleIds = [] }) {
				for (const id of removeRuleIds) dnrRules.delete(id);
				for (const rule of addRules) {
					if (dnrRules.has(rule.id)) throw new Error(`Rule with id ${rule.id} already exists`);
					dnrRules.set(rule.id, clone(rule));
				}
			},
			async getDynamicRules() {
				return [...dnrRules.values()].map(clone);
			},
		},
	};

	return {
		chrome,
		managed,
		local,
		session,
		tabs,
		tabMessages,
		badges,
		alarms,
		dnrRules,
		events,
		sendRuntimeMessage(message, sender) {
			return new Promise((resolve) => {
				let responded = false;
				const respond = (response: unknown) => {
					if (!responded) {
						responded = true;
						resolve(response);
					}
				};
				const results = events.onMessage.dispatch(clone(message), sender, respond);
				if (!results.includes(true)) respond(undefined);
			});
		},
		fireAlarm(name) {
			events.onAlarm.dispatch({ name });
		},
		extensionSender(page = "popup.html") {
			return {
				id: EXTENSION_ID,
				url: `${EXTENSION_BASE}${page}`,
				origin: EXTENSION_BASE.slice(0, -1),
			};
		},
		contentSender(tabId, url) {
			return { id: EXTENSION_ID, url, frameId: 0, tab: { id: tabId, url } };
		},
	};
}
