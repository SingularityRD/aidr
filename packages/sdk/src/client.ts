import { createHash } from "node:crypto";
import {
	type Artifact,
	type Config,
	checkRunaway,
	DecisionEngine,
	extractFromBash,
	extractFromUnknownTool,
	extractUrls,
	getEffectiveManagedApiKey,
	HeuristicsEngine,
	INPUT_NOT_FULLY_INSPECTED,
	inspectionLimitsHit,
	inspectResponseBarrier,
	isInvalidConfig,
	type Logger,
	loadConfig,
	loadManagedState,
	loadThreatsWithReport,
	loadTrustedDomains,
	managedStatePath,
	nullLogger,
	REPUTATION_NOT_CHECKED_CATEGORY,
	type ResponseBarrierInspection,
	reputationNotCheckedVerdict,
	type Threat,
	type ThreatLoadError,
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
	SDKConfigInput,
	SDKEvent,
} from "./config.js";
import { CheckRequestSchema, CheckResultSchema, SDKConfigSchema } from "./config.js";
import { INDETERMINATE_METADATA_KEY } from "./enforcement.js";
import { MAX_INSPECTED_HEADER_CHARS, partitionHeaders } from "./http-headers.js";
import {
	AIDRPrivacyTextError,
	loadPrivacyTextGateway,
	type PrivacyGatewayOptions,
	type PrivacyTextGateway,
	type PrivacyTextSendOptions,
	type SDKPrivateOptions,
	snapshotPrivacyGateway,
} from "./privacy-text.js";

export type { Logger };

/**
 * Largest request body (`CheckRequest.context.body`, serialized) the SDK
 * inspects. A larger body is never judged on a prefix: the check returns `deny`
 * because the body could not be fully inspected.
 */
export const MAX_CONTEXT_BODY_CHARS = 1024 * 1024;

/**
 * Action for an HTTP request checked by the Express/Next.js helpers. The
 * resource is the request route (path + query), inspected as content with any
 * embedded URLs extracted; it is never treated as a local file path.
 */
export const HTTP_REQUEST_ACTION = "http_request";

type UrlCheckResult = Awaited<ReturnType<UrlCheckClient["checkUrls"]>>[number];

/** Most URLs one `fetch` check sends to the reputation provider. */
const MAX_REPUTATION_URLS = 16;

function earliest(values: ReadonlyArray<number | undefined>): number | undefined {
	const defined = values.filter((value): value is number => typeof value === "number");
	return defined.length > 0 ? Math.min(...defined) : undefined;
}

function withReasons(result: CheckResult, reasons: readonly string[]): CheckResult {
	const extra = reasons.filter((reason) => !result.reason?.includes(reason));
	if (extra.length === 0) return result;
	return { ...result, reason: [result.reason, ...extra].filter(Boolean).join("; ") };
}

/**
 * Surface core's `reputation_not_checked` label on the SDK result so callers can
 * tell "no reputation service looked at these URLs" from a clean reputation result.
 */
function labelNotChecked(
	result: CheckResult,
	verdict: Verdict,
	urlsNotChecked: readonly string[],
): CheckResult {
	if (urlsNotChecked.length === 0 || verdict.category !== REPUTATION_NOT_CHECKED_CATEGORY) {
		return result;
	}
	return {
		...result,
		metadata: {
			...result.metadata,
			category: REPUTATION_NOT_CHECKED_CATEGORY,
			leg: "url_reputation",
			uncheckedUrls: verdict.artifacts,
		},
	};
}

/** Same marker the core generic extractor emits for an input it could not fully walk. */
function notFullyInspected(): Artifact {
	return {
		type: "content",
		value: `${INPUT_NOT_FULLY_INSPECTED}:total_size`,
		context: `aidr:${INPUT_NOT_FULLY_INSPECTED}`,
	};
}

function serializeBody(body: unknown): string | undefined {
	try {
		return typeof body === "string" ? body : JSON.stringify(body);
	} catch {
		return undefined;
	}
}

/** Render a candidate-path list for error messages. */
function formatSearched(paths: string[]): string {
	return paths.length > 0
		? paths.map((path, index) => `  ${index + 1}. ${path}`).join("\n")
		: "  (none)";
}

/** Metadata key set on every result produced while bundled rules are incomplete. */
export const DEGRADED_METADATA_KEY = "degraded";
const RULES_INCOMPLETE_REASON = "rules incomplete — protection degraded";

/** Distinct rule file basenames named by load errors. */
function ruleFiles(errors: readonly ThreatLoadError[]): string[] {
	return [...new Set(errors.map((error) => error.file.split(/[\\/]/).pop() ?? error.file))];
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
	/** Bundled rule files/rules that did not load or verify; non-empty means degraded. */
	private ruleErrors: ThreatLoadError[] = [];
	private trustedDomains: TrustedDomain[] = [];
	private dataDirs?: DataDirResolution;
	private initialized = false;
	#privacyGatewayOptions?: PrivacyGatewayOptions;
	#privacyGateway?: Promise<PrivacyTextGateway>;

	constructor(config: SDKConfigInput, privateOptions?: SDKPrivateOptions) {
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
		this.#privacyGatewayOptions = snapshotPrivacyGateway(privateOptions);
		this.logger = this.config.logger ?? nullLogger;

		// Initialize cache if enabled
		this.cache = this.createCache();

		// Initialize core components
		this.engine = new DecisionEngine("balanced");
		this.urlClient = this.createUrlClient();
	}

	private createUrlClient(config = this.config, logger = this.logger): UrlCheckClient {
		return new UrlCheckClient(
			{
				enabled: config.urlReputationEnabled,
				endpoint: config.baseUrl ? `${config.baseUrl.replace(/\/+$/, "")}/url-check` : undefined,
				timeout_seconds: config.timeout / 1000,
				include_query_parameters: config.includeUrlQueryParameters,
			},
			logger,
			config.apiKey,
		);
	}

	private createCache(): VerdictCache | undefined {
		return this.config.cache
			? new VerdictCache({
					enabled: true,
					ttl_malicious_seconds: Math.floor(this.config.cacheTtl / 1000),
					ttl_clean_seconds: Math.floor(this.config.cacheTtl / 1000),
					path: "~/.singularity-aidr/cache.json",
				})
			: undefined;
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
		let ruleErrors: ThreatLoadError[];
		try {
			// The reporting loader: a corrupt, emptied or unverified rule file is absent from
			// `threats`, so it must be known here rather than look like "nothing matched".
			const report = await loadThreatsWithReport(dataDirs.threatsDir, this.logger, {
				manifest: {},
			});
			threats = report.threats;
			ruleErrors = report.errors;
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

		if (ruleErrors.length > 0) {
			this.logger.warn(
				`AIDR client: ${RULES_INCOMPLETE_REASON} (${ruleFiles(ruleErrors).join(", ")}); every result is marked degraded`,
			);
		}
		this.threats = threats;
		this.ruleErrors = ruleErrors;
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
	 * Bundled rule files (or rules) that did not load or verify at `init()`. Non-empty means
	 * every check is degraded: results carry `metadata.degraded` and are never a clean `allow`.
	 */
	getRuleLoadErrors(): readonly ThreatLoadError[] {
		return this.ruleErrors;
	}

	/** True when the bundled rules are incomplete ("rules incomplete — protection degraded"). */
	isDegraded(): boolean {
		return this.ruleErrors.length > 0;
	}

	/**
	 * With incomplete rules a result cannot be clean: `allow` becomes `ask` (a human decides, the
	 * same downgrade the evaluator applies) and every result carries the degraded flag.
	 */
	private _applyRuleDegradation(result: CheckResult): CheckResult {
		if (this.ruleErrors.length === 0) return result;
		const files = ruleFiles(this.ruleErrors);
		const metadata = {
			...result.metadata,
			[DEGRADED_METADATA_KEY]: true,
			rulesIncomplete: files,
		};
		const detail = `${RULES_INCOMPLETE_REASON}: bundled threat rules did not load or verify (${files.join(", ")}), so this action was NOT fully inspected.`;
		if (result.decision !== "allow") {
			return {
				...result,
				reason: result.reason ? `${result.reason} ${detail}` : detail,
				metadata,
			};
		}
		return {
			allowed: false,
			decision: "ask",
			confidence: 1,
			reason: `${detail} This is not a clean result.`,
			metadata,
		};
	}

	/**
	 * Perform a security check on an action
	 */
	async check(request: CheckRequest): Promise<CheckResult> {
		request = CheckRequestSchema.parse(request);
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
				this._emitDecisionEvent(
					result.metadata?.privacyRoute === "unsupported"
						? { action: "privacy-route", resource: "[withheld]" }
						: request,
					result.metadata?.privacyRoute === "unsupported"
						? { ...result, reason: "Required privacy routing blocked a caller-owned operation." }
						: result,
				);
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

	/** Recheck installed controls after approval/hooks, immediately before caller-owned execution. */
	async assertCallerOperationAllowed(): Promise<void> {
		try {
			const installed = await loadConfig();
			if (isInvalidConfig(installed) || installed.privacy?.required) {
				throw new AIDRPrivacyTextError("PRIVACY_CALLER_ROUTE_UNSUPPORTED");
			}
			if (await this._responseControlResult(installed))
				throw new AIDRPrivacyTextError("AIDR_INSTALLED_CONTROL_BLOCKED");
		} catch (error) {
			if (error instanceof AIDRPrivacyTextError) throw error;
			throw new AIDRPrivacyTextError("PRIVACY_POLICY_UNAVAILABLE");
		}
	}

	/** One bounded final model send through the installed privacy service; never retries dispatch. */
	async sendText(text: string, options: PrivacyTextSendOptions = {}): Promise<string> {
		try {
			if (typeof text !== "string" || !text.length || Buffer.byteLength(text) > 500_000) {
				throw new AIDRPrivacyTextError("PRIVACY_TEXT_INVALID");
			}
			if (
				Object.keys(options).some((key) => !["requestId", "reviewCaseId", "signal"].includes(key))
			) {
				throw new AIDRPrivacyTextError("PRIVACY_TEXT_OPTIONS_INVALID");
			}
			const sendOptions = {
				requestId: options.requestId,
				reviewCaseId: options.reviewCaseId,
				signal: options.signal,
			};
			sendOptions.signal?.throwIfAborted();
			const gatewayOptions = this.#privacyGatewayOptions;
			if (!gatewayOptions) throw new AIDRPrivacyTextError("PRIVACY_GATEWAY_REQUIRED");
			if (!this.initialized) await this.init();
			const installed = await loadConfig();
			if (isInvalidConfig(installed)) throw new AIDRPrivacyTextError("PRIVACY_POLICY_UNAVAILABLE");
			const barrier = await this._responseControlResult(installed);
			if (barrier) throw new AIDRPrivacyTextError("PRIVACY_SEND_BLOCKED");
			const verdict = await this.engine.decide({
				heuristicMatches: this.heuristics?.match([{ type: "content", value: text }]) ?? [],
				urlCheckResults: [],
			});
			// Incomplete rules: this text was not fully inspected, so it is not sent.
			if (verdict.decision !== "allow" || this.ruleErrors.length > 0) {
				throw new AIDRPrivacyTextError("PRIVACY_SEND_BLOCKED");
			}
			this.#privacyGateway ??= loadPrivacyTextGateway({
				...gatewayOptions,
				credentials: async () => {
					const credentials = await gatewayOptions.credentials();
					const beforeDispatch = await loadConfig();
					if (
						isInvalidConfig(beforeDispatch) ||
						(await this._responseControlResult(beforeDispatch))
					) {
						throw new AIDRPrivacyTextError("PRIVACY_SEND_BLOCKED");
					}
					return credentials;
				},
			});
			const gateway = await this.#privacyGateway;
			const current = await loadConfig();
			if (isInvalidConfig(current) || (await this._responseControlResult(current))) {
				throw new AIDRPrivacyTextError("PRIVACY_SEND_BLOCKED");
			}
			sendOptions.signal?.throwIfAborted();
			const receipt = await gateway.send(text, sendOptions).catch(() => {
				// Credential/transport exceptions are outside this SDK's error authority.
				throw new AIDRPrivacyTextError("PRIVACY_SEND_OUTCOME_UNAVAILABLE");
			});
			if (
				receipt.decision !== "sent" ||
				typeof receipt.outputText !== "string" ||
				Buffer.byteLength(receipt.outputText) > 2 * 1024 * 1024
			) {
				throw new AIDRPrivacyTextError("PRIVACY_MODEL_OUTPUT_UNAVAILABLE");
			}
			const delivered = await loadConfig();
			if (isInvalidConfig(delivered) || (await this._responseControlResult(delivered))) {
				throw new AIDRPrivacyTextError("PRIVACY_MODEL_OUTPUT_UNAVAILABLE");
			}
			return receipt.outputText;
		} catch (error) {
			if (error instanceof AIDRPrivacyTextError) throw error;
			throw new AIDRPrivacyTextError("PRIVACY_SEND_OUTCOME_UNAVAILABLE");
		}
	}

	/**
	 * Internal check implementation; every path (cache hits included) goes through the
	 * incomplete-rules downgrade.
	 */
	private async _performCheck(request: CheckRequest): Promise<CheckResult> {
		return this._applyRuleDegradation(await this._performRuleCheck(request));
	}

	private async _performRuleCheck(request: CheckRequest): Promise<CheckResult> {
		let installed: Config;
		try {
			installed = await loadConfig();
		} catch {
			return this._unsupportedPrivacyResult();
		}
		const barrier = await this._responseControlResult(installed);
		if (barrier)
			return isInvalidConfig(installed) || installed.privacy?.required
				? { ...barrier, metadata: { ...barrier.metadata, privacyRoute: "unsupported" } }
				: barrier;
		const privacy = await this._privacyRouteResult(request, installed);
		if (privacy) return privacy;
		// Extract artifacts from the request (resource, typed artifacts, body)
		const artifacts = this._extractArtifacts(request);
		const limits = inspectionLimitsHit(artifacts);
		if (limits.length > 0) {
			// Judging only the inspected part could pass an unsafe call: deny.
			return {
				allowed: false,
				decision: "deny",
				confidence: 1,
				reason: `Input could not be fully inspected (${limits.join(", ")}); it was blocked rather than judged on a part.`,
				metadata: { [INPUT_NOT_FULLY_INSPECTED]: limits },
			};
		}

		// Check cache first
		const cacheKey = this._getCacheKey(request, artifacts);
		if (this.cache) {
			const cached = this.cache.getUrl(cacheKey);
			if (cached) {
				this.logger.debug(`Cache hit for ${cacheKey}`);
				return this._applySessionLayers(request, installed, this._cachedVerdictToResult(cached));
			}
		}

		// Run heuristics (heuristics is guaranteed to be initialized here)
		const matches = this.heuristics?.match(artifacts);

		const {
			urlCheckResults,
			unavailableReason: urlLegUnavailableReason,
			notChecked: urlsNotChecked = [],
		} = await this._reputationLeg(request, artifacts, installed);

		// Get verdict from decision engine. URLs no reputation service looked at
		// (leg not enabled, `unchecked_action: allow`) label a clean local allow
		// `reputation_not_checked`, exactly as the core evaluator does.
		const decided = await this.engine.decide({
			heuristicMatches: matches ?? [],
			urlCheckResults,
		});
		const verdict =
			urlsNotChecked.length > 0
				? reputationNotCheckedVerdict(decided, urlsNotChecked, [], true)
				: decided;
		// Installed mandatory routing can change while a provider lookup is pending.
		let current: Config;
		try {
			current = await loadConfig();
		} catch {
			return this._unsupportedPrivacyResult();
		}
		const currentPrivacy = await this._privacyRouteResult(request, current);
		if (currentPrivacy) return currentPrivacy;
		const currentBarrier = await this._responseControlResult(current);
		if (currentBarrier) return currentBarrier;

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
		// all enabled checks had completed); neither may a verdict from incomplete rules,
		// since the cache file is shared with clients that loaded the full rule set.
		// A not-checked allow is not cached either: the cache entry would lose its
		// `reputation_not_checked` label and come back looking like a clean allow.
		if (
			this.cache &&
			!urlLegUnavailableReason &&
			urlsNotChecked.length === 0 &&
			this.ruleErrors.length === 0
		) {
			const isMalicious = verdict.decision === "deny";
			this.cache.putUrl(
				cacheKey,
				{
					verdict: verdict.decision,
					severity: verdict.severity,
					reasons: verdict.reasons,
					source: verdict.source,
				},
				isMalicious,
				request.action === "fetch"
					? earliest(urlCheckResults.map((result) => result.cacheValidUntil))
					: Date.now() + this.config.cacheTtl,
			);
			this.cacheEntryCount++;
		}

		return this._applySessionLayers(
			request,
			current,
			labelNotChecked(this._verdictToResult(verdict), verdict, urlsNotChecked),
		);
	}

	/**
	 * Session layers for a request that carries a `sessionId`: the runaway
	 * guard (loop, rate and budget checks) records the call in that session and
	 * turns an `allow` into an `ask` when a threshold is crossed. Applied after
	 * the cache so a cached verdict is still counted. A guard that could not
	 * run makes an `allow` indeterminate (never clean). A `deny` is not recorded:
	 * that call will not run.
	 */
	private async _applySessionLayers(
		request: CheckRequest,
		config: Config,
		result: CheckResult,
	): Promise<CheckResult> {
		if (!request.sessionId || result.decision === "deny") return result;
		const outcome = await checkRunaway(
			{
				sessionId: request.sessionId,
				toolName: request.action,
				toolInput: { resource: request.resource, artifacts: request.artifacts ?? [] },
			},
			config,
			{ agentRuntime: "sdk", logger: this.logger },
		);
		if (outcome.status === "disabled") return result;
		if (outcome.status === "unavailable") {
			if (result.decision !== "allow") return withReasons(result, [outcome.reason]);
			return {
				allowed: false,
				decision: "ask",
				confidence: 0.5,
				reason: outcome.reason,
				metadata: { [INDETERMINATE_METADATA_KEY]: true, leg: "runaway_guard" },
			};
		}
		if (outcome.signals.length === 0) return result;
		const reasons = outcome.signals.map(
			(signal) => `Runaway guard paused this session for human review: ${signal.reason}`,
		);
		if (result.decision !== "allow") return withReasons(result, reasons);
		return {
			allowed: false,
			decision: "ask",
			confidence: 1,
			reason: reasons.join("; "),
			threatId: outcome.signals[0]?.id,
			metadata: { session: "runaway_guard" },
		};
	}

	/**
	 * URL reputation for a `fetch` action: the resource and every URL found in
	 * the structured input / body are verified, not only the resource. Returns
	 * `unavailableReason` when an enabled leg could not run, so the result is never
	 * clean. While the leg is not enabled the URLs are returned as `notChecked`
	 * (decided by local rules, labelled `reputation_not_checked`) unless
	 * `urlReputationUncheckedAction` or the installed `url_check.unchecked_action`
	 * is `ask`, which keeps the strict hold-for-review behaviour.
	 */
	private async _reputationLeg(
		request: CheckRequest,
		artifacts: readonly Artifact[],
		installed: Config,
	): Promise<{
		urlCheckResults: UrlCheckResult[];
		unavailableReason?: string;
		notChecked?: string[];
	}> {
		if (request.action !== "fetch") return { urlCheckResults: [] };
		const urls = [
			...new Set([
				request.resource,
				...artifacts.filter((artifact) => artifact.type === "url").map((a) => a.value),
			]),
		];
		if (!this.config.urlReputationEnabled) {
			const strict =
				this.config.urlReputationUncheckedAction === "ask" ||
				installed.url_check?.unchecked_action === "ask";
			return strict
				? {
						urlCheckResults: [],
						unavailableReason: "disabled to avoid sending URLs to an external reputation provider",
					}
				: { urlCheckResults: [], notChecked: urls };
		}
		if (urls.length > MAX_REPUTATION_URLS) {
			return {
				urlCheckResults: [],
				unavailableReason: `${urls.length} URLs exceed the ${MAX_REPUTATION_URLS}-URL verification limit`,
			};
		}
		try {
			return { urlCheckResults: await this.urlClient.checkUrls(urls) };
		} catch (e) {
			// A failed reputation lookup is an unavailable leg, not a clean URL.
			const unavailableReason = e instanceof Error ? e.message : String(e);
			this.logger.warn(`URL reputation lookup unavailable: ${unavailableReason}`);
			return { urlCheckResults: [], unavailableReason };
		}
	}

	private async _privacyRouteResult(
		request: CheckRequest,
		installed: Config,
	): Promise<CheckResult | undefined> {
		if (!isInvalidConfig(installed) && !installed.privacy?.required) return undefined;
		try {
			const local = await this.engine.decide({
				heuristicMatches: this.heuristics?.match(this._extractArtifacts(request)) ?? [],
				urlCheckResults: [],
			});
			if (local.decision === "deny")
				return { ...this._verdictToResult(local), metadata: { privacyRoute: "unsupported" } };
		} catch {
			/* Broken detection cannot authorize an unsupported route. */
		}
		return this._unsupportedPrivacyResult();
	}

	private _unsupportedPrivacyResult(): CheckResult {
		return {
			allowed: false,
			decision: "deny",
			confidence: 1,
			reason:
				"Required privacy routing does not support caller-owned SDK operations; use the owned privacy text sender.",
			metadata: { privacyRoute: "unsupported" },
		};
	}

	private async _responseControlResult(installedConfig?: Config): Promise<CheckResult | undefined> {
		const barrier = await this._inspectInstalledResponseBarrier(installedConfig);
		if (barrier.status !== "paused" && barrier.status !== "unavailable") return undefined;
		return {
			allowed: false,
			decision: "deny",
			confidence: 1,
			reason:
				barrier.status === "paused"
					? "Installed AIDR response controls paused this agent."
					: "Installed AIDR response controls could not be verified; execution remains blocked.",
			metadata: { responseControl: barrier.status },
		};
	}

	/** Caller-owned remote API keys cannot authorize or bypass installed endpoint controls. */
	private async _inspectInstalledResponseBarrier(
		installedConfig?: Config,
	): Promise<ResponseBarrierInspection> {
		try {
			const config = installedConfig ?? (await loadConfig());
			const options = {
				required: config.control_plane.response_worker_required,
				managedState: {},
				apiKey: "",
				publicKeysPem: config.licensing.public_keys_pem,
			};
			// Avoid reading a credential vault when no response worker is installed.
			const installed = await inspectResponseBarrier({ ...options, required: false });
			if (installed.status === "unconfigured") {
				return options.required ? { status: "unavailable" } : installed;
			}
			const state = await loadManagedState(managedStatePath(), {
				authToken: config.auth.api_key,
				publicKeysPem: config.licensing.public_keys_pem,
			});
			return await inspectResponseBarrier({
				...options,
				managedState: state,
				apiKey: getEffectiveManagedApiKey(config.auth.api_key, state),
			});
		} catch {
			return { status: "unavailable" };
		}
	}

	/**
	 * Extract artifacts from the request
	 */
	private _extractArtifacts(request: CheckRequest): Artifact[] {
		const artifacts: Artifact[] = [];

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
			case HTTP_REQUEST_ACTION:
				// A route is server-side input, not a local file path.
				artifacts.push({ type: "content", value: request.resource, context: "http_route" });
				for (const url of extractUrls(request.resource)) {
					artifacts.push({ type: "url", value: url, context: "http_route:embedded_url" });
				}
				break;
			default:
				artifacts.push({ type: "content", value: request.resource });
		}

		if (request.artifacts) artifacts.push(...request.artifacts);
		artifacts.push(...this._contextBodyArtifacts(request));
		artifacts.push(...this._contextHeaderArtifacts(request));
		return artifacts;
	}

	/**
	 * Artifacts from `request.context.headers` (HTTP request headers). Every
	 * non-credential header value is walked by the generic extractor, so a
	 * command, URL or injection payload smuggled in a header is inspected like
	 * one in the body. Credential headers (`Authorization`, `Cookie`, any name
	 * containing token/secret/session/…) are skipped here as well as by the
	 * middleware: their values are opaque secrets, not content. A header set
	 * larger than {@link MAX_INSPECTED_HEADER_CHARS} is reported as not fully
	 * inspected (the check then denies).
	 */
	private _contextHeaderArtifacts(request: CheckRequest): Artifact[] {
		const raw = request.context?.headers;
		if (raw === undefined || raw === null || typeof raw !== "object" || Array.isArray(raw)) {
			return [];
		}
		const { inspected } = partitionHeaders(raw as Record<string, string>);
		if (Object.keys(inspected).length === 0) return [];
		const size = Object.entries(inspected).reduce(
			(total, [name, value]) => total + name.length + value.length,
			0,
		);
		if (size > MAX_INSPECTED_HEADER_CHARS) return [notFullyInspected()];
		// Header names say nothing about the value's kind (`x-cmd`, `x-query`), so
		// besides the generic walk each value is also parsed as a shell command:
		// a backend that forwards a header to a shell is exactly the case to catch.
		const artifacts = extractFromUnknownTool("http_headers", inspected);
		for (const value of Object.values(inspected)) artifacts.push(...extractFromBash(value));
		return artifacts;
	}

	/**
	 * Artifacts from `request.context.body` (an HTTP request body, or any
	 * structured payload a caller attaches). The body is walked by the same
	 * generic extractor the native connectors use for unknown tools, so URLs,
	 * commands, file paths and free text in it are all inspected. A body larger
	 * than {@link MAX_CONTEXT_BODY_CHARS}, or one that cannot be serialized, is
	 * reported as not fully inspected (the check then denies).
	 */
	private _contextBodyArtifacts(request: CheckRequest): Artifact[] {
		const body = request.context?.body;
		if (body === undefined || body === null || body === "") return [];
		const serialized = serializeBody(body);
		if (serialized === undefined || serialized.length > MAX_CONTEXT_BODY_CHARS) {
			return [notFullyInspected()];
		}
		let snapshot: unknown;
		try {
			snapshot = JSON.parse(serialized);
		} catch {
			snapshot = serialized;
		}
		const input =
			typeof snapshot === "object" && snapshot !== null && !Array.isArray(snapshot)
				? (snapshot as Record<string, unknown>)
				: { body: snapshot };
		return extractFromUnknownTool("http_body", input);
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
	private _getCacheKey(request: CheckRequest, artifacts: readonly Artifact[]): string {
		// VerdictCache normalizes URL keys (including fragments and case). Hash the
		// complete request (including artifacts extracted from the body) so
		// distinct commands, paths or bodies can never share a verdict.
		return createHash("sha256")
			.update(
				JSON.stringify([
					request.action,
					request.resource,
					artifacts,
					this.config.baseUrl ?? "",
					this.config.apiKey ?? "",
					this.config.urlReputationEnabled,
					this.config.includeUrlQueryParameters,
				]),
			)
			.digest("hex");
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
		this.cache = this.createCache();
		this.cacheEntryCount = 0;
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
		const config = SDKConfigSchema.parse({ ...this.config, ...updates });
		const logger = config.logger ?? nullLogger;
		const urlClient = this.createUrlClient(config, logger);
		this.config = config;
		this.logger = logger;
		this.urlClient = urlClient;
		this.clearCache();
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
