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
import { AIDRInitError, type DataDirResolution, resolveDataDirs } from "./bundled-dirs.js";
import type {
	CheckRequest,
	CheckResult,
	DecisionEvent,
	ErrorEvent,
	EventListener,
	SDKConfig,
	SDKEvent,
} from "./config.js";
import { CheckResultSchema, SDKConfigSchema } from "./config.js";
import { INDETERMINATE_METADATA_KEY } from "./enforcement.js";

export type { Logger };

/** Render a candidate-path list for error messages. */
function formatSearched(paths: string[]): string {
	return paths.length > 0
		? paths.map((path, index) => `  ${index + 1}. ${path}`).join("\n")
		: "  (none)";
}

/**
 * AIDRClient - Main SDK client for security checks
 */
export class AIDRClient {
	private config: SDKConfig;
	private cache?: VerdictCache;
	private cacheEntryCount = 0;
	private engine: DecisionEngine;
	private urlClient: UrlCheckClient;
	private heuristics?: HeuristicsEngine;
	private logger: Logger;
	private listeners: Map<string, Set<EventListener>> = new Map();
	private retryDelays = [1000, 2000, 4000];
	private threats: Threat[] = [];
	private trustedDomains: TrustedDomain[] = [];
	private dataDirs?: DataDirResolution;
	private initialized = false;

	constructor(config: SDKConfig) {
		// Validate and default the configuration up front.
		//
		// Without this the SDK trusted its caller's object shape: a JavaScript
		// caller (or a JSON config file) that omitted `retries` left it
		// `undefined`, and `while (attempts <= undefined)` is false, so the retry
		// loop never ran once and the first failure went straight to the
		// fail-closed fallback. `SDKConfigSchema.parse` supplies the schema
		// defaults (retries: 2, timeout: 5000, cache: true, cacheTtl: 300000,
		// environment: "production") and rejects out-of-range values.
		this.config = SDKConfigSchema.parse(config);
		this.logger = this.config.logger ?? nullLogger;

		// Initialize cache if enabled
		if (this.config.cache) {
			this.cache = new VerdictCache({
				enabled: true,
				ttl_malicious_seconds: Math.floor(this.config.cacheTtl / 1000),
				ttl_clean_seconds: Math.floor(this.config.cacheTtl / 1000),
				path: "~/.singularity-aidr/cache.json",
			});
		}

		// Initialize core components
		this.engine = new DecisionEngine("balanced");
		this.urlClient = this.createUrlClient();
	}

	private createUrlClient(): UrlCheckClient {
		return new UrlCheckClient({
			enabled: this.config.urlReputationEnabled,
			timeout_seconds: this.config.timeout / 1000,
			include_query_parameters: this.config.includeUrlQueryParameters,
		});
	}

	/**
	 * Initialize the client by loading the bundled threat rules and trusted
	 * domains.
	 *
	 * The rules are resolved relative to this module — never relative to
	 * `process.cwd()` — so the same code works from the monorepo source tree, from
	 * an installed tarball (`resources/` next to `dist/`), and with an explicit
	 * `AIDR_THREATS_DIR` / `AIDR_ALLOWLISTS_DIR` override. See
	 * `bundled-dirs.ts` for the full resolution order.
	 *
	 * Failure here is fatal and explicit, by design. A missing or empty rule set
	 * is an initialisation error, never a working client: with fail-closed
	 * enforcement in place, a client that loaded zero rules would answer `ask`
	 * forever and detect nothing, which is exactly the silent degradation this
	 * package must not have.
	 *
	 * @throws {AIDRDataDirError} when no threat/allowlist directory can be found;
	 *   the error names every path that was searched.
	 * @throws {AIDRInitError} when the directories exist but cannot be loaded, or
	 *   when zero threat rules load.
	 */
	async init(): Promise<void> {
		if (this.initialized) return;

		// Throws AIDRDataDirError (naming every candidate path) when the packaged
		// rule data is not present.
		const dataDirs = resolveDataDirs();
		const searchedThreats = dataDirs.searchedPaths.threats;
		const searchedAllowlists = dataDirs.searchedPaths.allowlists;

		let threats: Threat[];
		try {
			threats = await loadThreats(dataDirs.threatsDir, this.logger);
		} catch (error) {
			throw new AIDRInitError(
				`Singularity AIDR cannot initialise: failed to load threat rules from ${dataDirs.threatsDir} ` +
					`(${error instanceof Error ? error.message : String(error)}).\n` +
					`Searched for "threats" (in order):\n${formatSearched(searchedThreats)}`,
				{ searchedPaths: searchedThreats, cause: error },
			);
		}

		if (threats.length === 0) {
			throw new AIDRInitError(
				`Singularity AIDR cannot initialise: ${dataDirs.threatsDir} contains no loadable threat rules, ` +
					"so every check would be evaluated against an empty rule set and nothing could ever be detected. " +
					"This is an installation failure, not a clean result.\n" +
					`Searched for "threats" (in order):\n${formatSearched(searchedThreats)}`,
				{ searchedPaths: searchedThreats },
			);
		}

		let trustedDomains: TrustedDomain[];
		try {
			trustedDomains = await loadTrustedDomains(dataDirs.allowlistsDir, this.logger);
		} catch (error) {
			throw new AIDRInitError(
				`Singularity AIDR cannot initialise: failed to load trusted domains from ${dataDirs.allowlistsDir} ` +
					`(${error instanceof Error ? error.message : String(error)}).\n` +
					`Searched for "allowlists" (in order):\n${formatSearched(searchedAllowlists)}`,
				{ searchedPaths: searchedAllowlists, cause: error },
			);
		}

		if (trustedDomains.length === 0) {
			// Not fatal: an empty allowlist only costs extra false positives
			// (nothing is suppressed), it can never turn an unclean action into a
			// clean one.
			this.logger.warn(
				`No trusted domains loaded from ${dataDirs.allowlistsDir}; trusted-domain suppression is inactive`,
			);
		}

		this.threats = threats;
		this.trustedDomains = trustedDomains;
		this.heuristics = new HeuristicsEngine(this.threats, this.trustedDomains);
		this.dataDirs = dataDirs;
		this.initialized = true;
		this.logger.info(
			`AIDR client initialized: ${threats.length} threat rules from ${dataDirs.threatsDir} ` +
				`[${dataDirs.sources.threats}], ${trustedDomains.length} trusted domains from ${dataDirs.allowlistsDir} ` +
				`[${dataDirs.sources.allowlists}]`,
		);
	}

	/**
	 * Rule-data directories this client loaded, and which candidate produced each
	 * one. `undefined` until `init()` has succeeded. Exposed so host applications
	 * and health checks can report where detection data came from.
	 */
	getDataDirs(): DataDirResolution | undefined {
		return this.dataDirs;
	}

	/**
	 * Perform a security check on an action
	 */
	async check(request: CheckRequest): Promise<CheckResult> {
		// Ensure initialized
		if (!this.initialized) {
			await this.init();
		}

		// `this.config` is always the output of `SDKConfigSchema.parse` (constructor
		// and updateConfig both parse), so `retries` is a validated number here —
		// the schema default of 2 applies when the caller omitted it. The previous
		// code compared against a possibly-`undefined` value, and
		// `0 <= undefined` is false, so the loop body never executed once.
		const maxRetries = this.config.retries;

		let attempts = 0;
		let lastError: Error | undefined;

		while (attempts <= maxRetries) {
			try {
				const result = await this._performCheck(request);
				this._emitDecisionEvent(request, result);
				return result;
			} catch (error) {
				lastError = error instanceof Error ? error : new Error(String(error));
				attempts++;

				if (attempts <= maxRetries) {
					const delay = this.retryDelays[attempts - 1] ?? 4000;
					this.logger.warn(
						`Retrying security check (attempt ${attempts}, delay: ${delay}ms): ${lastError.message}`,
					);
					await this._sleep(delay);
				}
			}
		}

		// All retries exhausted. This is a FAIL-CLOSED result, not an approval:
		// `allowed: false` means "do not execute", and the `indeterminate` marker
		// tells every SDK enforcer (see enforcement.ts) that this came from a
		// broken security check rather than from a real `ask` verdict. An
		// indeterminate result is never routed to an approval callback unless the
		// caller explicitly opts in, so "the check is broken" can never be
		// converted into "run the wrapped function".
		const fallbackResult: CheckResult = {
			allowed: false,
			decision: "ask",
			confidence: 0.5,
			reason: `Check failed after ${attempts} attempts: ${lastError?.message}`,
			metadata: { [INDETERMINATE_METADATA_KEY]: true, attempts },
		};

		this._emitErrorEvent(lastError ?? new Error("Security check failed"), request);
		return fallbackResult;
	}

	/**
	 * Internal check implementation
	 */
	private async _performCheck(request: CheckRequest): Promise<CheckResult> {
		// Check cache first
		const cacheKey = this._getCacheKey(request);
		/** Set when the reputation leg could not run, so the result is never clean. */
		let urlLegUnavailableReason: string | undefined;
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
		const matches = this.heuristics?.match(artifacts);

		// Run URL check if it's a fetch action
		const urlCheckResults: Array<{
			url: string;
			isMalicious: boolean;
			findings: Array<{ severityName: string; typeName: string }>;
			flags: string[];
			cacheValidUntil?: number;
		}> = [];
		if (request.action === "fetch") {
			if (!this.config.urlReputationEnabled) {
				urlLegUnavailableReason = "disabled to avoid sending URLs to an external reputation provider";
			} else {
				try {
					const results = await this.urlClient.checkUrls([request.resource]);
					urlCheckResults.push(...results);
				} catch (e) {
					// A failed reputation lookup is an unavailable leg, not a clean URL.
					urlLegUnavailableReason = e instanceof Error ? e.message : String(e);
					this.logger.warn(`URL reputation lookup unavailable: ${urlLegUnavailableReason}`);
				}
			}
		}

		// Get verdict from decision engine
		const verdict = await this.engine.decide({
			heuristicMatches: matches ?? [],
			urlCheckResults,
		});

		// An unverified URL must never come back as `allow`. The same indeterminate
		// marker the retry-exhaustion path uses keeps every SDK enforcer from
		// routing this to an approval callback, so "the reputation leg is broken"
		// cannot be turned into "run the call".
		if (urlLegUnavailableReason && verdict.decision === "allow") {
			const indeterminate: CheckResult = {
				allowed: false,
				decision: "ask",
				confidence: 0.5,
				reason: `URL reputation lookup was unavailable (${urlLegUnavailableReason}), so ${request.resource} was NOT verified and requires review.`,
				metadata: { [INDETERMINATE_METADATA_KEY]: true, leg: "url_reputation" },
			};
			this._emitErrorEvent(
				new Error(`URL reputation unavailable: ${urlLegUnavailableReason}`),
				request,
			);
			return indeterminate;
		}

		// An incomplete reputation result must not be cached as clean (or as if
		// all enabled checks had completed).
		if (this.cache && !urlLegUnavailableReason) {
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
				urlCheckResults.find((result) => result.url === request.resource)?.cacheValidUntil,
			);
			this.cacheEntryCount++;
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

		return request.artifacts ? [...artifacts, ...request.artifacts] : artifacts;
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
		return [
			request.action,
			request.resource,
			JSON.stringify(request.artifacts ?? []),
			String(this.config.urlReputationEnabled),
			String(this.config.includeUrlQueryParameters),
		].join(":");
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
		this.listeners.get(eventType)?.add(listener as EventListener);

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
				ttl_malicious_seconds: Math.floor(this.config.cacheTtl / 1000),
				ttl_clean_seconds: Math.floor(this.config.cacheTtl / 1000),
				path: "~/.singularity-aidr/cache.json",
			});
			this.cacheEntryCount = 0;
		}
		this.logger.info("Cache cleared");
	}

	/**
	 * Get cache stats
	 */
	getCacheStats(): { size: number; hitRate: number } | undefined {
		if (!this.cache) return undefined;
		return {
			size: this.cacheEntryCount,
			hitRate: 0,
		};
	}

	/**
	 * Update configuration.
	 *
	 * The merged result is re-validated, so an invalid or missing `retries` /
	 * `timeout` cannot be introduced after construction either — the retry loop
	 * always reads a value the schema produced and defaulted.
	 *
	 * @throws {ZodError} when the merged configuration is invalid.
	 */
	updateConfig(updates: Partial<SDKConfig>): void {
		this.config = SDKConfigSchema.parse({ ...this.config, ...updates });
		this.urlClient = this.createUrlClient();
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
