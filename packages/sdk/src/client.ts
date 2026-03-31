import {
	DecisionEngine,
	HeuristicsEngine,
	type Logger,
	loadThreats,
	loadTrustedDomains,
	nullLogger,
	type Threat,
	type TrustedDomain,
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
	private heuristics?: HeuristicsEngine;
	private logger: Logger;
	private listeners: Map<string, Set<EventListener>> = new Map();
	private retryDelays = [1000, 2000, 4000];
	private threats: Threat[] = [];
	private trustedDomains: TrustedDomain[] = [];
	private initialized = false;

	constructor(config: SDKConfig) {
		this.config = config;
		this.logger = config.logger ?? nullLogger;

		// Initialize cache if enabled
		if (config.cache) {
			this.cache = new VerdictCache({
				enabled: true,
				ttl_malicious_seconds: Math.floor((config.cacheTtl ?? 300000) / 1000),
				ttl_clean_seconds: Math.floor((config.cacheTtl ?? 300000) / 1000),
				path: "~/.singularity-aidr/cache.json",
			});
		}

		// Initialize core components
		this.engine = new DecisionEngine("balanced");
		this.urlClient = new UrlCheckClient({
			enabled: true,
			timeout_seconds: (config.timeout ?? 5000) / 1000,
		});
	}

	/**
	 * Initialize the client by loading threats and trusted domains
	 */
	async init(): Promise<void> {
		if (this.initialized) return;

		// Load threats and trusted domains
		this.threats = await loadThreats("threats");
		this.trustedDomains = await loadTrustedDomains("allowlists");
		this.heuristics = new HeuristicsEngine(this.threats, this.trustedDomains);

		this.initialized = true;
		this.logger.info("AIDR client initialized");
	}

	/**
	 * Perform a security check on an action
	 */
	async check(request: CheckRequest): Promise<CheckResult> {
		// Ensure initialized
		if (!this.initialized) {
			await this.init();
		}

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
						`Retrying security check (attempt ${attempts}, delay: ${delay}ms): ${lastError.message}`,
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
			const cached = this.cache.getUrl(cacheKey);
			if (cached) {
				this.logger.debug(`Cache hit for ${cacheKey}`);
				return this._cachedVerdictToResult(cached);
			}
		}

		// Extract artifacts from the request
		const artifacts = this._extractArtifacts(request);

		// Run heuristics (heuristics is guaranteed to be initialized here)
		const matches = this.heuristics!.match(artifacts);

		// Run URL check if it's a fetch action
		const urlCheckResults: Array<{
			url: string;
			isMalicious: boolean;
			findings: Array<{ severityName: string; typeName: string }>;
			flags: string[];
		}> = [];
		if (request.action === "fetch") {
			try {
				const results = await this.urlClient.checkUrls([request.resource]);
				urlCheckResults.push(...results);
			} catch (e) {
				this.logger.warn(
					`URL check failed for ${request.resource}: ${e instanceof Error ? e.message : String(e)}`,
				);
			}
		}

		// Get verdict from decision engine
		const verdict = await this.engine.decide({
			heuristicMatches: matches,
			urlCheckResults,
		});

		// Cache the result
		if (this.cache) {
			const isMalicious = verdict.decision === "deny";
			const verdictStr = isMalicious ? "deny" : verdict.decision === "allow" ? "clean" : "ask";
			this.cache.putUrl(
				cacheKey,
				{
					verdict: verdictStr as "allow" | "deny" | "ask",
					severity: verdict.severity,
					reasons: verdict.reasons,
					source: verdict.source,
				},
				isMalicious,
			);
		}

		return this._verdictToResult(verdict);
	}

	/**
	 * Extract artifacts from the request
	 */
	private _extractArtifacts(
		request: CheckRequest,
	): Array<{ type: "url" | "command" | "file_path" | "content"; value: string; context?: string }> {
		const artifacts: Array<{
			type: "url" | "command" | "file_path" | "content";
			value: string;
			context?: string;
		}> = [];

		// Add the resource as an artifact based on action type
		switch (request.action) {
			case "fetch":
				artifacts.push({ type: "url", value: request.resource });
				break;
			case "read":
			case "write":
				artifacts.push({ type: "file_path", value: request.resource });
				break;
			case "execute":
				artifacts.push({ type: "command", value: request.resource });
				break;
			default:
				artifacts.push({ type: "content", value: request.resource });
		}

		return artifacts;
	}

	/**
	 * Convert core Verdict to SDK CheckResult
	 */
	private _verdictToResult(verdict: Verdict): CheckResult {
		const result: CheckResult = {
			allowed: verdict.decision === "allow",
			decision: verdict.decision,
			confidence: verdict.confidence ?? 0.85,
			reason: verdict.reasons?.join("; ") ?? undefined,
			threatId: verdict.matchedThreatId ?? undefined,
		};

		return CheckResultSchema.parse(result);
	}

	/**
	 * Convert cached verdict to CheckResult
	 */
	private _cachedVerdictToResult(cached: {
		verdict: "allow" | "deny" | "ask";
		severity: "info" | "warning" | "critical";
		reasons: string[];
		source: string;
	}): CheckResult {
		const decision =
			cached.verdict === "allow" ? "allow" : cached.verdict === "deny" ? "deny" : "ask";

		const result: CheckResult = {
			allowed: decision === "allow",
			decision,
			confidence: 0.85,
			reason: cached.reasons?.join("; ") ?? undefined,
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
				this.logger.error(
					`Error in decision event listener: ${e instanceof Error ? e.message : String(e)}`,
				);
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
				this.logger.error(
					`Error in error event listener: ${e instanceof Error ? e.message : String(e)}`,
				);
			}
		});
	}

	/**
	 * Clear the cache
	 */
	clearCache(): void {
		// Since VerdictCache doesn't have a clear method, we'll create a new instance
		if (this.cache && this.config.cache) {
			this.cache = new VerdictCache({
				enabled: true,
				ttl_malicious_seconds: Math.floor((this.config.cacheTtl ?? 300000) / 1000),
				ttl_clean_seconds: Math.floor((this.config.cacheTtl ?? 300000) / 1000),
				path: "~/.singularity-aidr/cache.json",
			});
		}
		this.logger.info("Cache cleared");
	}

	/**
	 * Get cache stats
	 */
	getCacheStats(): { size: number; hitRate: number } | undefined {
		if (!this.cache) return undefined;
		// VerdictCache doesn't expose these properties directly, return default values
		return {
			size: 0,
			hitRate: 0,
		};
	}

	/**
	 * Update configuration
	 */
	updateConfig(updates: Partial<SDKConfig>): void {
		this.config = { ...this.config, ...updates };
		this.logger.info(`Configuration updated: ${Object.keys(updates).join(", ")}`);
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
