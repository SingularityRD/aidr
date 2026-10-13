/**
 * Subframe content scripts (the Microsoft 365 Copilot pane inside the Office web apps,
 * ../sites/frames.ts) that fetched their policy, by tab and frame id.
 *
 * Policy changes are pushed to tabs whose top-level URL is a protected site. A Copilot pane
 * frame lives in a tab whose top-level page (Word, Excel, Outlook on the web) is not one, and
 * the extension cannot see that page's URL (no host permission, no `tabs`/`webNavigation`).
 * So a subframe guard registers itself when it boots (GET_POLICY), and the worker pushes
 * every policy change to the registered frames (`tabs.sendMessage` with their `frameId`),
 * each with the effective policy of its own site.
 *
 * Kept in storage.session (cleared on extension update/reload, like ./open-tabs.ts
 * `ContentTabs`) so a service-worker restart does not orphan the frames. Bounded: at most
 * MAX_FRAMES_PER_TAB frames per tab and MAX_TABS tabs (oldest dropped). A frame that went
 * away only makes a later push fail silently; the record is dropped with its tab.
 */
import type { SiteId } from "../types.js";
import type { GuardStorage } from "./storage.js";
import { STORAGE_KEYS } from "./storage.js";

const MAX_FRAMES_PER_TAB = 8;
const MAX_TABS = 256;

const isId = (raw: unknown): raw is number => Number.isSafeInteger(raw) && (raw as number) >= 0;

export interface ContentFrame {
	readonly tabId: number;
	readonly frameId: number;
	readonly site: SiteId;
}

type FrameTable = Record<string, Record<string, SiteId>>;

export class ContentFrames {
	private chain: Promise<unknown> = Promise.resolve();

	constructor(private readonly storage: GuardStorage) {}

	/** Records a live subframe content script (frameId > 0) for `site`. */
	mark(tabId: number, frameId: number, site: SiteId): Promise<void> {
		if (!isId(tabId) || !isId(frameId) || frameId === 0) return Promise.resolve();
		return this.update((table) => {
			const tab = String(tabId);
			const frames = { ...(table[tab] ?? {}) };
			if (frames[String(frameId)] === site) return false;
			delete frames[String(frameId)];
			frames[String(frameId)] = site;
			const keys = Object.keys(frames);
			for (const old of keys.slice(0, Math.max(0, keys.length - MAX_FRAMES_PER_TAB)))
				delete frames[old];
			delete table[tab];
			table[tab] = frames;
			const tabs = Object.keys(table);
			for (const old of tabs.slice(0, Math.max(0, tabs.length - MAX_TABS))) delete table[old];
			return true;
		});
	}

	remove(tabId: number): Promise<void> {
		return this.update((table) => {
			if (!(String(tabId) in table)) return false;
			delete table[String(tabId)];
			return true;
		});
	}

	async list(): Promise<ContentFrame[]> {
		const table = await this.read();
		return Object.entries(table).flatMap(([tab, frames]) =>
			Object.entries(frames).map(([frame, site]) => ({
				tabId: Number(tab),
				frameId: Number(frame),
				site,
			})),
		);
	}

	/** Whether `tabId` has a registered subframe guard. */
	async has(tabId: number): Promise<boolean> {
		return String(tabId) in (await this.read());
	}

	private async read(): Promise<FrameTable> {
		const raw = await this.storage.getSession(STORAGE_KEYS.contentFrames);
		const out: FrameTable = {};
		if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
		for (const [tab, frames] of Object.entries(raw as Record<string, unknown>)) {
			if (!isId(Number(tab)) || !frames || typeof frames !== "object") continue;
			const kept: Record<string, SiteId> = {};
			for (const [frame, site] of Object.entries(frames as Record<string, unknown>)) {
				if (isId(Number(frame)) && Number(frame) > 0 && typeof site === "string")
					kept[frame] = site as SiteId;
			}
			if (Object.keys(kept).length) out[tab] = kept;
		}
		return out;
	}

	private update(change: (table: FrameTable) => boolean): Promise<void> {
		const task = async () => {
			const table = await this.read();
			if (change(table)) await this.storage.setSession(STORAGE_KEYS.contentFrames, table);
		};
		const next = this.chain.then(task, task);
		this.chain = next.catch(() => {});
		return next;
	}
}
