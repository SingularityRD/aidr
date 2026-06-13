/**
 * Real-time threat rule synchronization from CDN.
 * Implements polling, delta updates, and emergency push for critical rules.
 */

import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

export interface RuleSyncConfig {
	cdnUrl: string;
	pollIntervalMinutes: number;
	emergencyPollIntervalSeconds: number;
	localCachePath: string;
	maxCacheAgeHours: number;
}

interface RemoteRule {
	id: string;
	version: string;
	pattern: string;
	category: string;
	severity: "low" | "medium" | "high" | "critical";
	action: "block" | "require_approval" | "log";
	createdAt: string;
	updatedAt: string;
	hash: string; // For integrity verification
}

interface SyncStats {
	updated: number;
	added: number;
	removed: number;
	unchanged: number;
}

interface CachedRules {
	version: string;
	lastSync: string;
	rules: RemoteRule[];
}

export class RealTimeRuleSync {
	private lastSync: Date | null = null;
	private emergencyRules: string[] = [];
	private timer: NodeJS.Timeout | null = null;
	private currentRules = new Map<string, RemoteRule>();
	private readonly localCachePath: string;
	private isEmergencyMode = false;
	private readonly logger: Logger;

	constructor(
		private config: RuleSyncConfig,
		logger: Logger = nullLogger,
	) {
		this.localCachePath = resolvePath(config.localCachePath);
		this.logger = logger;
	}

	/**
	 * Start the real-time sync process.
	 * Performs initial sync and starts polling loop.
	 */
	async start(): Promise<void> {
		// Load cached rules if available
		await this.loadCachedRules();

		// Initial sync
		await this.sync();

		// Start polling loop
		this.startPolling();

		this.logger.info("Real-time rule sync started", {
			pollInterval: this.config.pollIntervalMinutes,
			cachePath: this.localCachePath,
		});
	}

	/**
	 * Stop the polling loop.
	 */
	stop(): void {
		if (this.timer) {
			clearInterval(this.timer);
			this.timer = null;
		}
		this.isEmergencyMode = false;
		this.logger.info("Real-time rule sync stopped");
	}

	/**
	 * Perform a sync operation.
	 * Fetches rules from CDN, compares with local cache, and applies updates.
	 */
	async sync(): Promise<SyncStats> {
		try {
			const stats = await this.performSync();
			this.lastSync = new Date();

			this.logger.info("Rule sync completed", {
				updated: stats.updated,
				added: stats.added,
				removed: stats.removed,
				unchanged: stats.unchanged,
			});
			return stats;
		} catch (error) {
			this.logger.error("Rule sync failed", {
				error: error instanceof Error ? error.message : String(error),
			});

			// Return empty stats on failure
			return {
				updated: 0,
				added: 0,
				removed: 0,
				unchanged: this.currentRules.size,
			};
		}
	}

	/**
	 * Emergency push for critical rules.
	 * Immediately downloads specified rules and temporarily increases poll frequency.
	 */
	async emergencyPush(ruleIds: string[]): Promise<void> {
		this.emergencyRules = ruleIds;
		this.isEmergencyMode = true;

		this.logger.warn("Emergency push triggered", { ruleIds });

		// Immediate sync for emergency rules
		await this.performEmergencySync();

		// Restart polling with emergency interval
		this.startPolling(true);
	}

	/**
	 * Get all current rules.
	 */
	async getCurrentRules(): Promise<RemoteRule[]> {
		return Array.from(this.currentRules.values());
	}

	/**
	 * Get last sync time.
	 */
	getLastSync(): Date | null {
		return this.lastSync;
	}

	/**
	 * Check if in emergency mode.
	 */
	isInEmergencyMode(): boolean {
		return this.isEmergencyMode;
	}

	/**
	 * Start or restart the polling loop.
	 */
	private startPolling(emergency = false): void {
		// Clear existing timer
		if (this.timer) {
			clearInterval(this.timer);
		}

		const interval = emergency
			? this.config.emergencyPollIntervalSeconds * 1000
			: this.config.pollIntervalMinutes * 60 * 1000;

		this.timer = setInterval(() => {
			this.sync().catch((error) => {
				this.logger.error("Scheduled sync failed", {
					error: error instanceof Error ? error.message : String(error),
				});
			});
		}, interval);
	}

	/**
	 * Load cached rules from disk.
	 */
	private async loadCachedRules(): Promise<void> {
		try {
			const content = await getFileContent(this.localCachePath);
			const cached: CachedRules = JSON.parse(content);

			// Check cache age
			const cacheAge = (Date.now() - new Date(cached.lastSync).getTime()) / (1000 * 60 * 60); // hours

			if (cacheAge > this.config.maxCacheAgeHours) {
				this.logger.warn("Cached rules expired, will fetch fresh", {
					age: cacheAge,
					maxAge: this.config.maxCacheAgeHours,
				});
				return;
			}

			// Load cached rules into memory
			for (const rule of cached.rules) {
				this.currentRules.set(rule.id, rule);
			}

			this.lastSync = new Date(cached.lastSync);

			this.logger.info("Loaded cached rules", {
				count: this.currentRules.size,
				version: cached.version,
			});
		} catch {
			// No cache file or invalid, will fetch fresh
			this.logger.info("No valid cache found, starting fresh");
		}
	}

	/**
	 * Perform the actual sync operation.
	 */
	private async performSync(): Promise<SyncStats> {
		// Fetch delta updates since last sync
		const delta = await this.downloadDelta(this.lastSync);

		const stats: SyncStats = {
			updated: 0,
			added: 0,
			removed: 0,
			unchanged: 0,
		};

		// Apply delta updates
		for (const rule of delta) {
			const existing = this.currentRules.get(rule.id);

			if (!existing) {
				// New rule
				this.currentRules.set(rule.id, rule);
				stats.added++;
			} else if (existing.hash !== rule.hash) {
				// Updated rule
				this.currentRules.set(rule.id, rule);
				stats.updated++;
			} else {
				stats.unchanged++;
			}
		}

		// Check for removed rules (rules in cache but not in manifest)
		const remoteIds = new Set(delta.map((r) => r.id));
		for (const [id, _rule] of this.currentRules) {
			if (!remoteIds.has(id)) {
				this.currentRules.delete(id);
				stats.removed++;
			}
		}

		// Save to cache
		await this.saveCache();

		return stats;
	}

	/**
	 * Perform emergency sync for critical rules.
	 */
	private async performEmergencySync(): Promise<void> {
		try {
			for (const ruleId of this.emergencyRules) {
				const rule = await this.downloadRule(ruleId);
				if (rule) {
					this.currentRules.set(rule.id, rule);
					this.logger.info("Emergency rule downloaded", { ruleId });
				}
			}

			await this.saveCache();
		} catch (error) {
			this.logger.error("Emergency sync failed", {
				error: error instanceof Error ? error.message : String(error),
			});
		}
	}

	/**
	 * Download delta updates since the given date.
	 */
	private async downloadDelta(since: Date | null): Promise<RemoteRule[]> {
		const sinceParam = since ? `?since=${since.toISOString()}` : "";
		const url = `${this.config.cdnUrl}/delta${sinceParam}`;

		const response = await fetch(url, {
			headers: {
				Accept: "application/json",
			},
		});

		if (!response.ok) {
			throw new Error(`Failed to fetch delta: ${response.status} ${response.statusText}`);
		}

		return (await response.json()) as RemoteRule[];
	}

	/**
	 * Download a single rule by ID from CDN.
	 * Returns the rule if found, null if 404, or throws on other errors.
	 */
	async downloadRule(ruleId: string): Promise<RemoteRule | null> {
		const url = `${this.config.cdnUrl}/${encodeURIComponent(ruleId)}`;

		try {
			const response = await fetch(url, {
				headers: {
					Accept: "application/json",
				},
			});

			if (response.status === 404) {
				this.logger.warn("Rule not found on CDN", { ruleId });
				return null;
			}

			if (!response.ok) {
				throw new Error(
					`Failed to fetch rule ${ruleId}: ${response.status} ${response.statusText}`,
				);
			}

			const rule = (await response.json()) as RemoteRule;
			this.logger.info("Rule downloaded successfully", { ruleId });
			return rule;
		} catch (error) {
			this.logger.error("Failed to download rule", {
				ruleId,
				error: error instanceof Error ? error.message : String(error),
			});
			throw error;
		}
	}

	/**
	 * Save current rules to local cache.
	 */
	private async saveCache(): Promise<void> {
		const cache: CachedRules = {
			version: this.getManifestVersion(),
			lastSync: new Date().toISOString(),
			rules: Array.from(this.currentRules.values()),
		};

		await atomicWriteJson(this.localCachePath, cache);
	}

	/**
	 * Generate a manifest version based on current rules.
	 */
	private getManifestVersion(): string {
		// Simple hash of rule IDs and versions
		const ruleHashes = Array.from(this.currentRules.values())
			.map((r) => `${r.id}:${r.version}`)
			.sort()
			.join(";");

		// Return a hash-like version string
		return Buffer.from(ruleHashes).toString("base64").slice(0, 16);
	}
}
