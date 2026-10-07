/**
 * JSON file-based verdict cache for Singularity AIDR.
 * Replaces the Python SQLite implementation.
 *
 * ## Authentication
 *
 * The cache file sits in the user's home directory, where the policed agent can
 * write. A cached verdict short-circuits a reputation lookup, so an
 * unauthenticated file let anything that could write it plant an `allow` for a
 * URL or package and flip the verdict. Every persisted entry therefore carries
 * an HMAC-SHA256 over its content, its kind and its key, under a random
 * per-installation key stored next to the cache (`cache.key`, owner-only).
 * Entries without a valid MAC are dropped on load; when the key cannot be
 * established safely the cache is simply not used (a cache miss is always safe:
 * the leg runs or is reported unavailable).
 *
 * A cached entry is reputation evidence only. It never replaces local rule
 * matching: the evaluator applies cached URL verdicts only to make an `allow`
 * stricter, so no cache entry can downgrade a rule-match deny.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Stats } from "node:fs";
import { link, lstat, mkdir, open, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { resolvePath } from "./config.js";
import { decryptFile, deriveKey, encryptedFileContent } from "./encryption.js";
import { atomicWriteJson, atomicWriteText, getFileContent } from "./file-utils.js";
import type { CacheConfig, CachedEntry, CachedVerdict, CacheStore, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { normalizeUrl } from "./url-utils.js";

const ONE_HOUR = 3600;
const TWENTY_FOUR_HOURS = 86400;
const FAR_FUTURE = "9999-12-31T23:59:59+00:00";

/** File name of the per-installation cache authentication key, next to the cache. */
export const CACHE_KEY_FILE = "cache.key";
const CACHE_KEY_BYTES = 32;

type CacheKind = keyof CacheStore;
const CACHE_KINDS: readonly CacheKind[] = ["urls", "commands", "packages"];

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

function errorCode(error: unknown): string | undefined {
	return typeof error === "object" && error !== null && "code" in error
		? String((error as { code: unknown }).code)
		: undefined;
}

/** The exact bytes an entry's MAC covers. Binding kind and key stops an entry being moved. */
function macPayload(kind: CacheKind, key: string, entry: CachedEntry): string {
	return JSON.stringify([
		"aidr-verdict-cache-v1",
		kind,
		key,
		entry.verdict,
		entry.severity,
		entry.reasons,
		entry.source,
		entry.checkedAt ?? null,
		entry.expiresAt,
		entry.sourceFreshUntil ?? null,
		entry.aidrVersion ?? null,
	]);
}

/** HMAC-SHA256 (hex) of a cache entry under the installation's cache key. */
export function cacheEntryMac(
	cacheKey: Buffer,
	kind: CacheKind,
	key: string,
	entry: CachedEntry,
): string {
	return createHmac("sha256", cacheKey)
		.update(macPayload(kind, key, entry), "utf8")
		.digest("hex");
}

function macMatches(cacheKey: Buffer, kind: CacheKind, key: string, entry: CachedEntry): boolean {
	if (typeof entry.mac !== "string" || !/^[0-9a-f]{64}$/.test(entry.mac)) return false;
	return timingSafeEqual(
		Buffer.from(cacheEntryMac(cacheKey, kind, key, entry), "hex"),
		Buffer.from(entry.mac, "hex"),
	);
}

function assertPrivateKeyFile(info: Stats): void {
	if (info.isSymbolicLink() || !info.isFile()) {
		throw new Error("Cache key is not a regular file.");
	}
	// On Windows the file inherits the user-profile ACL; POSIX mode bits are
	// not meaningful there.
	if (process.platform === "win32") return;
	if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
		throw new Error("Cache key is owned by another user.");
	}
	if ((info.mode & 0o077) !== 0) {
		throw new Error("Cache key is readable or writable by other users.");
	}
}

async function readKeyFile(path: string): Promise<Buffer> {
	const handle = await open(path, "r");
	try {
		const info = await handle.stat();
		if (info.size !== CACHE_KEY_BYTES) throw new Error("Cache key has an unexpected size.");
		const buffer = Buffer.alloc(CACHE_KEY_BYTES);
		const { bytesRead } = await handle.read(buffer, 0, CACHE_KEY_BYTES, 0);
		if (bytesRead !== CACHE_KEY_BYTES) throw new Error("Cache key could not be read.");
		return buffer;
	} finally {
		await handle.close();
	}
}

/**
 * The per-installation cache key in `directory`, created once (owner-only) on
 * first use. Throws when an existing key is unsafe; the caller then does not
 * use the cache at all.
 */
export async function loadOrCreateCacheKey(directory: string): Promise<Buffer> {
	const path = join(directory, CACHE_KEY_FILE);
	for (let attempt = 0; attempt < 3; attempt++) {
		try {
			assertPrivateKeyFile(await lstat(path));
			return await readKeyFile(path);
		} catch (error) {
			if (errorCode(error) !== "ENOENT") throw error;
		}
		await mkdir(directory, { recursive: true, mode: 0o700 });
		// Publish a complete key with link(): it either appears whole or fails
		// with EEXIST because a concurrent hook process published one first.
		const tmp = join(directory, `${CACHE_KEY_FILE}.${randomBytes(6).toString("hex")}.tmp`);
		try {
			const handle = await open(tmp, "wx", 0o600);
			try {
				await handle.writeFile(randomBytes(CACHE_KEY_BYTES));
			} finally {
				await handle.close();
			}
			await link(tmp, path);
		} catch (error) {
			if (errorCode(error) !== "EEXIST") throw error;
		} finally {
			await unlink(tmp).catch(() => undefined);
		}
	}
	throw new Error("Cache key could not be established.");
}

export class VerdictCache {
	private store: CacheStore = { urls: {}, commands: {}, packages: {} };
	private readonly path: string;
	private readonly config: CacheConfig;
	private readonly logger: Logger;
	private readonly version: string | undefined;
	private readonly encryptionKey: Buffer | null;
	private macKey: Buffer | null = null;
	/** Set when the authentication key is unusable: the cache is then bypassed. */
	private unavailable = false;

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

	private get active(): boolean {
		return this.config.enabled && !this.unavailable;
	}

	/** Load (or create) the authentication key; on failure the cache is bypassed. */
	private async ensureMacKey(): Promise<Buffer | null> {
		if (this.macKey) return this.macKey;
		if (this.unavailable) return null;
		try {
			this.macKey = await loadOrCreateCacheKey(dirname(this.path));
			return this.macKey;
		} catch (error) {
			this.unavailable = true;
			this.store = { urls: {}, commands: {}, packages: {} };
			this.logger.warn("Verdict cache disabled: its authentication key is unavailable", {
				error: String(error),
			});
			return null;
		}
	}

	async load(): Promise<void> {
		if (!this.config.enabled) return;
		const macKey = await this.ensureMacKey();
		if (!macKey) return;

		let data: Partial<Record<CacheKind, unknown>>;
		try {
			const raw = this.encryptionKey
				? await decryptFile(this.path, this.encryptionKey)
				: await getFileContent(this.path);
			data = JSON.parse(raw) as Partial<Record<CacheKind, unknown>>;
		} catch {
			this.store = { urls: {}, commands: {}, packages: {} };
			return;
		}

		let rejected = 0;
		const verified = (kind: CacheKind): Record<string, CachedEntry> => {
			const value = data?.[kind];
			if (!value || typeof value !== "object" || Array.isArray(value)) return {};
			const entries: Record<string, CachedEntry> = {};
			for (const [key, entry] of Object.entries(value)) {
				if (!isCachedEntry(entry)) continue;
				if (!macMatches(macKey, kind, key, entry)) {
					rejected += 1;
					continue;
				}
				const { mac: _mac, ...rest } = entry;
				entries[key] = rest;
			}
			return entries;
		};
		this.store = {
			urls: verified("urls"),
			commands: verified("commands"),
			packages: verified("packages"),
		};
		if (rejected > 0) {
			this.logger.warn("Ignored unauthenticated verdict cache entries", { count: rejected });
		}
	}

	getUrl(url: string): CachedVerdict | null {
		if (!this.active) return null;
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
		if (!this.active) return;

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
		if (!this.active) return null;
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
		if (!this.active) return;

		const now = new Date();
		this.store.commands[commandHash] = {
			...verdict,
			checkedAt: now.toISOString(),
			expiresAt: FAR_FUTURE,
			aidrVersion: this.version,
		};
	}

	getPackage(key: string): CachedVerdict | null {
		if (!this.active) return null;
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
		if (!this.active) return;

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

	/** The store as persisted: every entry carries its MAC. */
	private signedStore(macKey: Buffer): CacheStore {
		const signed: CacheStore = { urls: {}, commands: {}, packages: {} };
		for (const kind of CACHE_KINDS) {
			for (const [key, entry] of Object.entries(this.store[kind])) {
				const { mac: _mac, ...rest } = entry;
				signed[kind][key] = { ...rest, mac: cacheEntryMac(macKey, kind, key, rest) };
			}
		}
		return signed;
	}

	async save(): Promise<void> {
		if (!this.active) return;

		try {
			const macKey = await this.ensureMacKey();
			if (!macKey) return;
			this.pruneStaleEntries();
			const store = this.signedStore(macKey);
			if (this.encryptionKey) {
				await atomicWriteText(
					this.path,
					encryptedFileContent(Buffer.from(JSON.stringify(store), "utf8"), this.encryptionKey),
				);
			} else {
				await atomicWriteJson(this.path, store);
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
