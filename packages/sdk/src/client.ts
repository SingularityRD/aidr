import {
	type Config as CoreConfig,
	DecisionEngine,
	HeuristicsEngine,
	type Logger,
	loadThreats,
	loadTrustedDomains,
	nullLogger,
	UrlCheckClient,
	type Verdict,
	VerdictCache,
} from "@singularityrd/aidr-core";
import type {
	CheckRequest,
	CheckResult,
	DecisionEvent,
	ErrorEvent,
	EventListener,
	SDKConfig,
	SDKEvent,
} from "./config.js";
import { CheckResultSchema } from "./config.js";

export type { Logger };

/**
 * AIDRClient - Main SDK client for security checks
 */
export class AIDRClient {
	private config: SDKConfig;
	private cache?: VerdictCache;
	private engine: DecisionEngine;
	private urlClient: UrlCheckClient;
	private heuristics: HeuristicsEngine;
	private logger: Logger;
	private listeners: Map<string, Set<EventListener>> = new Map();
	private retryDelays = [1000, 2000, 4000];

	constructor(config: SDKConfig) {
		this.config = config;
		this.logger = config.logger ?? nullLogger;

		// Initialize cache if enabled
		if (config.cache) {
			this.cache = new VerdictCache({
				ttlMs: config.cacheTtl,
				maxSize: 1000,
			});
		}

		// Initialize core components
		const coreConfig: CoreConfig = {
			sensitivity: 0.85, // balanced
			logging: { level: "info" },
		};

		this.engine = new DecisionEngine(coreConfig);
		this.urlClient = new UrlCheckClient({
			timeoutMs: config.timeout,
		});
		this.heuristics = new HeuristicsEngine(loadThreats(), loadTrustedDomains());
	}

	/**
	 * Perform a security check on an action
	 */
	async check(request: CheckRequest): Promise<CheckResult> {
		const startTime = Date.now();
		let attempts = 0;
		let lastError: Error | undefined;

		while (attempts <= this.config.retries) {
			try {
				const result = await this._performCheck(request);
				this._emitDecisionEvent(request, result);
				return result;
			} catch (error) {
				lastError = error instanceof Error ? error : new Error(String(error));
				attempts++;

				if (attempts <= this.config.retries) {
					const delay = this.retryDelays[attempts - 1] ?? 4000;
					this.logger.warn(
						{ attempt: attempts, delay, error: lastError.message },
						"Retrying security check",
					);
					await this._sleep(delay);
				}
			}
		}

		// All retries exhausted - fail open with ask decision
		const fallbackResult: CheckResult = {
			allowed: false,
			decision: "ask",
			confidence: 0.5,
			reason: `Check failed after ${attempts} attempts: ${lastError?.message}`,
		};

		this._emitErrorEvent(lastError!, request);
		return fallbackResult;
	}

	/**
	 * Internal check implementation
	 */
	private async _performCheck(request: CheckRequest): Promise<CheckResult> {
		// Check cache first
		const cacheKey = this._getCacheKey(request);
		if (this.cache) {
			const cached = this.cache.get(cacheKey);
			if (cached) {
				this.logger.debug({ cacheKey }, "Cache hit");
				return this._verdictToResult(cached);
			}
		}

		// Run heuristics
		const matches = this.heuristics.check(request.resource, request.action);

		// Run URL check if it's a fetch action
		let urlResult: { safe: boolean; categories?: string[] } | undefined;
		if (request.action === "fetch") {
			try {
				urlResult = await this.urlClient.check(request.resource);
			} catch (e) {
				this.logger.warn({ error: e, url: request.resource }, "URL check failed");
			}
		}

		// Get verdict from decision engine
		const verdict = this.engine.decide({
			request,
			heuristicMatches: matches,
			urlResult,
		});

		// Cache the result
		if (this.cache) {
			this.cache.set(cacheKey, verdict);
		}

		return this._verdictToResult(verdict);
	}

	/**
	 * Convert core Verdict to SDK CheckResult
	 */
	private _verdictToResult(verdict: Verdict): CheckResult {
		const result: CheckResult = {
			allowed: verdict.decision === "allow",
			decision: verdict.decision,
			confidence: verdict.confidence ?? 0.85,
			reason: verdict.reason,
			threatId: verdict.threatId,
			metadata: verdict.metadata,
		};

		return CheckResultSchema.parse(result);
	}

	/**
	 * Generate cache key for a request
	 */
	private _getCacheKey(request: CheckRequest): string {
		return `${request.action}:${request.resource}`;
	}

	/**
	 * Sleep helper for retries
	 */
	private _sleep(ms: number): Promise<void> {
		return new Promise((resolve) => setTimeout(resolve, ms));
	}

	/**
	 * Add event listener
	 */
	on<T extends SDKEvent>(eventType: T["type"], listener: EventListener<T>): () => void {
		if (!this.listeners.has(eventType)) {
			this.listeners.set(eventType, new Set());
		}
		this.listeners.get(eventType)!.add(listener as EventListener);

		// Return unsubscribe function
		return () => {
			this.listeners.get(eventType)?.delete(listener as EventListener);
		};
	}

	/**
	 * Emit decision event
	 */
	private _emitDecisionEvent(request: CheckRequest, result: CheckResult): void {
		const event: DecisionEvent = {
			type: "decision",
			timestamp: Date.now(),
			request,
			result,
		};

		this.listeners.get("decision")?.forEach((listener) => {
			try {
				listener(event);
			} catch (e) {
				this.logger.error({ error: e }, "Error in decision event listener");
			}
		});
	}

	/**
	 * Emit error event
	 */
	private _emitErrorEvent(error: Error, context: unknown): void {
		const event: ErrorEvent = {
			type: "error",
			timestamp: Date.now(),
			error,
			context,
		};

		this.listeners.get("error")?.forEach((listener) => {
			try {
				listener(event);
			} catch (e) {
				this.logger.error({ error: e }, "Error in error event listener");
			}
		});
	}

	/**
	 * Clear the cache
	 */
	clearCache(): void {
		this.cache?.clear();
		this.logger.info("Cache cleared");
	}

	/**
	 * Get cache stats
	 */
	getCacheStats(): { size: number; hitRate: number } | undefined {
		if (!this.cache) return undefined;
		return {
			size: this.cache.size,
			hitRate: this.cache.hitRate,
		};
	}

	/**
	 * Update configuration
	 */
	updateConfig(updates: Partial<SDKConfig>): void {
		this.config = { ...this.config, ...updates };
		this.logger.info({ updates: Object.keys(updates) }, "Configuration updated");
	}

	/**
	 * Dispose of resources
	 */
	dispose(): void {
		this.clearCache();
		this.listeners.clear();
		this.logger.info("Client disposed");
	}
}
