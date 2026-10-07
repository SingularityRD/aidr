/**
 * JSON file-based verdict cache for Singularity AIDR.
 *
 * ## Authentication
 *
 * The cache lives in the user's state directory, and a cached verdict decides a
 * later call without re-inspection. An unauthenticated file would let anything
 * that can write there (including a prompt-injected agent) plant an entry that
 * changes a verdict. Every persisted entry therefore carries an HMAC-SHA256
 * under a random per-installation key kept next to the cache with owner-only
 * permissions (`<cache path>.key`). On load, an entry whose MAC is missing or
 * does not verify is treated as absent, exactly like an expired one; a missing
 * or unsafe key makes every persisted entry absent.
 *
 * Residual risk: code running as the same OS user can read the key file and
 * mint valid entries. The key raises the bar from "edit a JSON file" to "read a
 * private key file and compute an HMAC"; the self-defense rules that deny agent
 * access to the AIDR state directory are the other half of that boundary.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { lstat, open, readFile, unlink } from "node:fs/promises";
import { canonicalJson } from "./canonical-json.js";
import { resolvePath } from "./config.js";
import { decryptFile, deriveKey, encryptedFileContent } from "./encryption.js";
import { atomicWriteJson, atomicWriteText, getFileContent } from "./file-utils.js";
import { preparePrivateLocalFile } from "./private-local-file.js";
import type { CacheConfig, CachedEntry, CachedVerdict, CacheStore, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { normalizeUrl } from "./url-utils.js";

const ONE_HOUR = 3600;
const TWENTY_FOUR_HOURS = 86400;
const FAR_FUTURE = "9999-12-31T23:59:59+00:00";
const CACHE_KEY_BYTES = 32;
const MAC_DOMAIN = "aidr-verdict-cache-v1";

type CacheSection = keyof CacheStore;
const SECTIONS: readonly CacheSection[] = ["urls", "commands", "packages"];

function isCachedEntry(value: unknown): value is CacheStore["packages"][string] {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const entry = value as Record<string, unknown>;
	return (
		(entry.verdict === "allow" || entry.verdict === "deny" || entry.verdict === "ask") &&
		(entry.severity === "info" || entry.severity === "warning" || entry.severity === "critical") &&
		Array.isArray(entry.reasons) &&
		entry.reasons.every((reason) => typeof reason === "string") &&
		typeof entry.source === "string" &&
		typeof entry.expiresAt === "string"
	);
}

/** The path of the per-installation key that authenticates a cache file. */
export function cacheKeyPath(cachePath: string): string {
	return `${resolvePath(cachePath)}.key`;
}

/** MAC of one entry, bound to its section and key so entries cannot be moved. */
export function cacheEntryMac(
	key: Buffer,
	section: CacheSection,
	entryKey: string,
	entry: CachedEntry,
): string {
	const { mac: _mac, ...unsigned } = entry;
	// JSON round-trip drops `undefined` fields exactly as the file would.
	const canonical = canonicalJson(JSON.parse(JSON.stringify(unsigned)));
	return createHmac("sha256", key)
		.update(`${MAC_DOMAIN}\0${section}\0${entryKey}\0${canonical}`, "utf8")
		.digest("hex");
}

function macMatches(key: Buffer, section: CacheSection, entryKey: string, entry: CachedEntry) {
	if (typeof entry.mac !== "string" || !/^[0-9a-f]{64}$/.test(entry.mac)) return false;
	let expected: string;
	try {
		expected = cacheEntryMac(key, section, entryKey, entry);
	} catch {
		return false;
	}
	return timingSafeEqual(Buffer.from(entry.mac, "hex"), Buffer.from(expected, "hex"));
}

/** Attach a MAC to every entry of `store` (used when persisting it). */
export function signCacheStore(store: CacheStore, key: Buffer): CacheStore {
	const signed: CacheStore = { urls: {}, commands: {}, packages: {} };
	for (const section of SECTIONS) {
		for (const [entryKey, entry] of Object.entries(store[section] ?? {})) {
			signed[section][entryKey] = {
				...entry,
				mac: cacheEntryMac(key, section, entryKey, entry),
			};
		}
	}
	return signed;
}

/**
 * The well-formed entries of a persisted store whose MAC verifies. An entry
 * that does not authenticate (or any entry, when there is no key) is absent,
 * never trusted.
 */
function authenticatedStore(
	data: unknown,
	macKey: Buffer | null,
): { store: CacheStore; rejected: number } {
	const store: CacheStore = { urls: {}, commands: {}, packages: {} };
	let rejected = 0;
	for (const section of SECTIONS) {
		const entries = (data as Partial<CacheStore> | null)?.[section];
		if (!entries || typeof entries !== "object" || Array.isArray(entries)) continue;
		for (const [entryKey, entry] of Object.entries(entries)) {
			if (!isCachedEntry(entry)) continue;
			if (macKey && macMatches(macKey, section, entryKey, entry)) store[section][entryKey] = entry;
			else rejected += 1;
		}
	}
	return { store, rejected };
}

function parseKey(raw: string): Buffer | null {
	const text = raw.trim();
	const bytes = Buffer.from(text, "base64");
	return bytes.length === CACHE_KEY_BYTES && bytes.toString("base64") === text ? bytes : null;
}

/**
 * Read the cache key. Null when it is absent, malformed, not a regular file, or
 * (POSIX) readable by anyone but its owner: a key others could read cannot
 * authenticate anything.
 */
export async function readCacheKey(cachePath: string): Promise<Buffer | null> {
	const path = cacheKeyPath(cachePath);
	try {
		const info = await lstat(path);
		if (!info.isFile() || info.isSymbolicLink()) return null;
		if (process.platform !== "win32") {
			if ((info.mode & 0o077) !== 0) return null;
			if (typeof process.getuid === "function" && info.uid !== process.getuid()) return null;
		}
		return parseKey(await readFile(path, "utf8"));
	} catch {
		return null;
	}
}

/**
 * Return the cache key, creating it (owner-only permissions; on Windows a
 * protected owner/SYSTEM/Administrators ACL) when there is none yet. Null when
 * no trustworthy key can be produced, in which case nothing is persisted.
 */
export async function loadOrCreateCacheKey(cachePath: string): Promise<Buffer | null> {
	const existing = await readCacheKey(cachePath);
	if (existing) return existing;
	const path = cacheKeyPath(cachePath);
	const fresh = randomBytes(CACHE_KEY_BYTES);
	try {
		const handle = await open(path, "wx", 0o600);
		try {
			await handle.writeFile(fresh.toString("base64"), "utf8");
			await handle.sync();
		} finally {
			await handle.close();
		}
	} catch (error) {
		// Another process created it first; use theirs if it is trustworthy.
		if ((error as NodeJS.ErrnoException).code === "EEXIST") return readCacheKey(cachePath);
		return null;
	}
	try {
		preparePrivateLocalFile(path);
	} catch {
		await unlink(path).catch(() => undefined);
		return null;
	}
	return readCacheKey(cachePath);
}

export class VerdictCache {
	private store: CacheStore = { urls: {}, commands: {}, packages: {} };
	private readonly path: string;
	private readonly config: CacheConfig;
	private readonly logger: Logger;
	private readonly version: string | undefined;
	private readonly encryptionKey: Buffer | null;

	constructor(
		config: CacheConfig,
		logger: Logger = nullLogger,
		version?: string,
		installationId?: string,
	) {
		this.config = config;
		this.logger = logger;
		this.path = resolvePath(config.path);
		this.version = version;
		if (config.enabled && config.encryption?.enabled && !installationId) {
			throw new Error(
				"Encrypted cache requires an installation identifier; plaintext caching is refused.",
			);
		}
		this.encryptionKey =
			installationId && config.encryption?.enabled ? deriveKey(installationId) : null;
	}

	async load(): Promise<void> {
		if (!this.config.enabled) return;

		let data: CacheStore;
		try {
			const raw = this.encryptionKey
				? await decryptFile(this.path, this.encryptionKey)
				: await getFileContent(this.path);
			data = JSON.parse(raw) as CacheStore;
		} catch {
			this.store = { urls: {}, commands: {}, packages: {} };
			return;
		}
		const macKey = await readCacheKey(this.path);
		const { store, rejected } = authenticatedStore(data, macKey);
		if (rejected > 0) {
			this.logger.warn("Ignoring unauthenticated verdict cache entries", {
				path: this.path,
				rejected,
				keyAvailable: macKey !== null,
			});
		}
		this.store = store;
	}

	getUrl(url: string): CachedVerdict | null {
		if (!this.config.enabled) return null;
		const key = normalizeUrl(url);
		const entry = this.store.urls[key];
		if (!entry || this.isUrlStale(entry)) return null;

		return {
			verdict: entry.verdict,
			severity: entry.severity,
			reasons: entry.reasons,
			source: entry.source,
		};
	}

	putUrl(
		url: string,
		verdict: CachedVerdict,
		isMalicious: boolean,
		cacheValidUntil?: number,
	): void {
		if (!this.config.enabled) return;

		const key = normalizeUrl(url);
		const now = new Date();
		if (
			verdict.verdict === "allow" &&
			(!Number.isFinite(cacheValidUntil) || cacheValidUntil! <= now.getTime())
		)
			return;
		const ttl = isMalicious ? this.config.ttl_malicious_seconds : this.config.ttl_clean_seconds;
		const ttlExpiresAt = now.getTime() + ttl * 1000;
		const expiresAt = new Date(
			cacheValidUntil === undefined ? ttlExpiresAt : Math.min(ttlExpiresAt, cacheValidUntil),
		);
		if (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= now.getTime()) return;

		this.store.urls[key] = {
			...verdict,
			checkedAt: now.toISOString(),
			expiresAt: expiresAt.toISOString(),
			...(Number.isFinite(cacheValidUntil)
				? { sourceFreshUntil: new Date(cacheValidUntil!).toISOString() }
				: {}),
			aidrVersion: this.version,
		};
	}

	getCommand(commandHash: string): CachedVerdict | null {
		if (!this.config.enabled) return null;
		const entry = this.store.commands[commandHash];
		if (!entry || this.isStale(entry)) return null;

		return {
			verdict: entry.verdict,
			severity: entry.severity,
			reasons: entry.reasons,
			source: entry.source,
		};
	}

	putCommand(commandHash: string, verdict: CachedVerdict): void {
		if (!this.config.enabled) return;

		const now = new Date();
		this.store.commands[commandHash] = {
			...verdict,
			checkedAt: now.toISOString(),
			expiresAt: FAR_FUTURE,
			aidrVersion: this.version,
		};
	}

	getPackage(key: string): CachedVerdict | null {
		if (!this.config.enabled) return null;
		const entry = this.store.packages[key];
		if (!isCachedEntry(entry)) return null;
		if (!entry || this.isStale(entry)) return null;

		return {
			verdict: entry.verdict,
			severity: entry.severity,
			reasons: entry.reasons,
			source: entry.source,
		};
	}

	putPackage(key: string, verdict: CachedVerdict, packageAgeDays: number | null): void {
		if (!this.config.enabled) return;

		const ttlSeconds = this.computePackageTtl(verdict.verdict, packageAgeDays);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

		this.store.packages[key] = {
			...verdict,
			checkedAt: now.toISOString(),
			expiresAt: expiresAt.toISOString(),
			aidrVersion: this.version,
		};
	}

	private isStale(entry: { expiresAt: string; aidrVersion?: string }): boolean {
		const expiresAt = new Date(entry.expiresAt).getTime();
		if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return true;
		// Sharp cutover: anything not stamped with the current AIDR version is stale.
		if (this.version && this.version !== "dev" && entry.aidrVersion !== this.version) return true;
		return false;
	}

	private isUrlStale(entry: CacheStore["urls"][string]): boolean {
		if (this.isStale(entry)) return true;
		if (entry.verdict !== "allow") return false;
		const sourceFreshUntil = new Date(entry.sourceFreshUntil ?? "").getTime();
		return !Number.isFinite(sourceFreshUntil) || sourceFreshUntil <= Date.now();
	}

	private computePackageTtl(verdict: string, packageAgeDays: number | null): number {
		const isFresh = packageAgeDays !== null && packageAgeDays < 7;

		switch (verdict) {
			case "deny":
				return TWENTY_FOUR_HOURS;
			case "allow":
				return isFresh ? ONE_HOUR : TWENTY_FOUR_HOURS;
			default:
				return ONE_HOUR;
		}
	}

	async save(): Promise<void> {
		if (!this.config.enabled) return;

		try {
			this.pruneStaleEntries();
			const isEmpty = SECTIONS.every((section) => Object.keys(this.store[section]).length === 0);
			// An empty store needs no key; anything else is only worth persisting
			// if it can be authenticated when it is read back.
			const macKey = isEmpty ? null : await loadOrCreateCacheKey(this.path);
			if (!isEmpty && !macKey) {
				this.logger.warn("Verdict cache key is unavailable; cache entries were not persisted", {
					path: this.path,
				});
				return;
			}
			const persisted = macKey ? signCacheStore(this.store, macKey) : this.store;
			if (this.encryptionKey) {
				await atomicWriteText(
					this.path,
					encryptedFileContent(Buffer.from(JSON.stringify(persisted), "utf8"), this.encryptionKey),
				);
			} else {
				await atomicWriteJson(this.path, persisted);
			}
		} catch (e) {
			this.logger.warn(`Failed to save cache to ${this.path}`, { error: String(e) });
		}
	}

	private pruneStaleEntries(): void {
		for (const [key, entry] of Object.entries(this.store.urls)) {
			if (this.isUrlStale(entry)) delete this.store.urls[key];
		}
		for (const [key, entry] of Object.entries(this.store.commands)) {
			if (this.isStale(entry)) delete this.store.commands[key];
		}
		for (const [key, entry] of Object.entries(this.store.packages)) {
			if (this.isStale(entry)) delete this.store.packages[key];
		}
	}
}
