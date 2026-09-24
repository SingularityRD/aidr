/**
 * JSON file-based verdict cache for Singularity AIDR.
 * Replaces the Python SQLite implementation.
 */

import { resolvePath } from "./config.js";
import { decryptFile, deriveKey, encryptFile } from "./encryption.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { CacheConfig, CachedVerdict, CacheStore, Logger } from "./types.js";
import { nullLogger } from "./types.js";
import { normalizeUrl } from "./url-utils.js";

const ONE_HOUR = 3600;
const TWENTY_FOUR_HOURS = 86400;
const FAR_FUTURE = "9999-12-31T23:59:59+00:00";

function isCachedPackageEntry(value: unknown): value is CacheStore["packages"][string] {
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
		this.encryptionKey =
			installationId && config.encryption?.enabled ? deriveKey(installationId) : null;
	}

	async load(): Promise<void> {
		if (!this.config.enabled) return;

		try {
			const raw = this.encryptionKey
				? await decryptFile(this.path, this.encryptionKey)
				: await getFileContent(this.path);
			const data = JSON.parse(raw) as CacheStore;
			this.store = {
				urls: data.urls ?? {},
				commands: data.commands ?? {},
				packages: data.packages ?? {},
			};
		} catch {
			this.store = { urls: {}, commands: {}, packages: {} };
		}
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

	putUrl(url: string, verdict: CachedVerdict, isMalicious: boolean, cacheValidUntil?: number): void {
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
		if (!isCachedPackageEntry(entry)) return null;
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
			await atomicWriteJson(this.path, this.store);
			if (this.encryptionKey) {
				await encryptFile(this.path, this.encryptionKey);
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
