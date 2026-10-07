/**
 * Per-tab persistence of the content script's placeholder vault, so answers that
 * arrive (or are re-rendered) after a page reload can still be restored locally.
 *
 * Storage: chrome.storage.session only (memory-backed, cleared when the browser
 * closes), under `vault:<tabId>:<origin>`. The worker restricts session storage to
 * TRUSTED_CONTEXTS at start-up, so neither page scripts nor content scripts can read
 * it directly; content scripts reach it only through VAULT_SAVE / VAULT_LOAD, and the
 * worker derives the tab id and origin from the message sender, never from the
 * message. Nothing here is written to storage.local or sent over the network.
 *
 * Lifetime: a record is removed when its tab closes (tabs.onRemoved), when it has not
 * been saved for VAULT_TTL_MS (checked on load and by a periodic sweep), and replaced
 * wholesale on every save. Records are validated with the vault's own strict snapshot
 * parser before they are stored and again when they are read back.
 */
import { createVault, DEFAULT_VAULT_TTL_MS, MAX_VAULT_ENTRIES } from "../engine/vault.js";
import type { VaultSnapshot } from "../types.js";
import type { GuardStorage } from "./storage.js";

const VAULT_KEY_PREFIX = "vault:";
/** A record not saved for this long is forgotten (same as the vault's own idle TTL). */
const VAULT_TTL_MS = DEFAULT_VAULT_TTL_MS;
/** Upper bound on one serialised record (storage.session has a ~10 MB quota in total). */
const VAULT_MAX_CHARS = 1_048_576;

export interface StoredVault {
	readonly snapshot: VaultSnapshot;
	/** Placeholders already sent from this tab (the unmasker only restores these). */
	readonly sent: readonly string[];
}

interface VaultRecord extends StoredVault {
	readonly savedAt: number;
}

export type VaultSaveResult = "ok" | "invalid" | "too-large";

function vaultStorageKey(tabId: number, origin: string): string {
	return `${VAULT_KEY_PREFIX}${tabId}:${origin}`;
}

/** Validates and canonicalises a snapshot + sent list; null when malformed. */
function normalise(snapshot: unknown, sent: unknown, now: () => number): StoredVault | null {
	if (!Array.isArray(sent) || sent.length > MAX_VAULT_ENTRIES) return null;
	if (!sent.every((p) => typeof p === "string")) return null;
	let canonical: VaultSnapshot;
	try {
		// The vault's parser rejects malformed input; exporting drops expired entries.
		canonical = createVault({
			neverRestore: [],
			snapshot: snapshot as VaultSnapshot,
			now,
		}).exportSession();
	} catch {
		return null;
	}
	const known = new Set(canonical.entries.map((e) => e.placeholder));
	return { snapshot: canonical, sent: [...new Set(sent as string[])].filter((p) => known.has(p)) };
}

export class VaultStore {
	constructor(
		private readonly storage: GuardStorage,
		private readonly now: () => number,
	) {}

	async save(
		tabId: number,
		origin: string,
		snapshot: unknown,
		sent: unknown,
	): Promise<VaultSaveResult> {
		const key = vaultStorageKey(tabId, origin);
		const stored = normalise(snapshot, sent, this.now);
		if (!stored) return "invalid";
		if (stored.snapshot.entries.length === 0) {
			await this.storage.removeSession([key]);
			return "ok";
		}
		const record: VaultRecord = { savedAt: this.now(), ...stored };
		if (JSON.stringify(record).length > VAULT_MAX_CHARS) {
			// Never leave an older, now inconsistent mapping behind.
			await this.storage.removeSession([key]);
			return "too-large";
		}
		await this.storage.setSession(key, record);
		return "ok";
	}

	async load(tabId: number, origin: string): Promise<StoredVault | null> {
		const key = vaultStorageKey(tabId, origin);
		const record = await this.storage.getSession(key);
		const live = this.liveRecord(record);
		if (!live) {
			if (record !== undefined) await this.storage.removeSession([key]);
			return null;
		}
		return live;
	}

	async removeTab(tabId: number): Promise<void> {
		await this.storage.removeSession(
			await this.storage.sessionKeys(`${VAULT_KEY_PREFIX}${tabId}:`),
		);
	}

	/** Removes expired and malformed records of every tab. */
	async sweep(): Promise<void> {
		const stale: string[] = [];
		for (const key of await this.storage.sessionKeys(VAULT_KEY_PREFIX)) {
			if (!this.liveRecord(await this.storage.getSession(key))) stale.push(key);
		}
		await this.storage.removeSession(stale);
	}

	private liveRecord(raw: unknown): StoredVault | null {
		if (!raw || typeof raw !== "object") return null;
		const { savedAt, snapshot, sent } = raw as Partial<VaultRecord>;
		if (typeof savedAt !== "number" || !Number.isFinite(savedAt)) return null;
		if (this.now() - savedAt > VAULT_TTL_MS) return null;
		const stored = normalise(snapshot, sent, this.now);
		return stored && stored.snapshot.entries.length > 0 ? stored : null;
	}
}
