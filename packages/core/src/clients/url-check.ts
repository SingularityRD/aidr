/**
 * HTTP client for URL reputation checking.
 * Uses native fetch — no external HTTP dependencies.
 *
 * The default endpoint is expected to be operated by SingularityRD (or your
 * organization, if you override `url_check.endpoint`). Treat it as best-effort:
 * endpoint failures are reported as an unavailable detection leg. A configured
 * signed feed is verified for trust and freshness before its results are used.
 */

import { DetectionLegUnavailableError, describeHttpFailure } from "../detection-leg.js";
import {
	loadReputationFeed,
	type ReputationFeedLoadOptions,
	type ReputationFeedRecord,
} from "../reputation-feed.js";
import type { Logger, UrlCheckConfig, UrlCheckFinding, UrlCheckResult } from "../types.js";
import { nullLogger } from "../types.js";
import { VERSION } from "../version.js";

const DEFAULT_TIMEOUT = 5.0;
const MAX_URLS_PER_REQUEST = 50;
const SERVICE_NAME = "aidr";

function getProviderTld(): string {
	return "com";
}

const REQUEST_HEADERS = [
	{ name: "Accept", value: "application/json" },
	{ name: "Content-Type", value: "application/json" },
	{ name: "User-Agent", value: SERVICE_NAME },
];

function matchSignedUrl(
	url: string,
	exact: ReadonlyMap<string, ReputationFeedRecord>,
	domains: ReadonlyMap<string, ReputationFeedRecord>,
): ReputationFeedRecord | undefined {
	const exactMatch = exact.get(url);
	if (exactMatch) return exactMatch;
	try {
		const parsed = new URL(url);
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
		const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
		const labels = hostname.split(".");
		for (let i = 0; i < labels.length; i++) {
			const match = domains.get(labels.slice(i).join("."));
			if (match) return match;
		}
	} catch {
		return undefined;
	}
	return undefined;
}

function getProviderName(): string {
	return "singularityrd";
}

function getSubdomain(): string {
	return "svc";
}

function buildDomain(): string {
	return [getSubdomain(), getProviderName(), getProviderTld()].join(".");
}

export function resolveEndpoint(path: string): string {
	const normalizedPath = path.startsWith("/") ? path : `/${path}`;
	return `https://${SERVICE_NAME}-proxy.${buildDomain()}${normalizedPath}`;
}

export class UrlCheckClient {
	private readonly endpoint: string;
	private readonly timeoutMs: number;
	private readonly apiKey?: string;
	private readonly logger: Logger;
	private readonly reputationFeed?: ReputationFeedLoadOptions;

	constructor(
		config?: Partial<UrlCheckConfig> & { reputationFeed?: ReputationFeedLoadOptions },
		logger: Logger = nullLogger,
		apiKey?: string,
	) {
		this.endpoint = config?.endpoint ?? resolveEndpoint("/url-check");
		this.timeoutMs = (config?.timeout_seconds ?? DEFAULT_TIMEOUT) * 1000;
		this.apiKey = apiKey;
		this.logger = logger;
		this.reputationFeed = config?.reputationFeed;
	}

	async checkUrls(urls: string[]): Promise<UrlCheckResult[]> {
		if (urls.length === 0) return [];
		const signedResults = new Map<string, UrlCheckResult>();
		if (this.reputationFeed) {
			const feed = await loadReputationFeed(this.reputationFeed);
			if (feed.availability !== "available") {
				throw new DetectionLegUnavailableError(
					"url_reputation",
					`signed feed ${feed.feedId} is ${feed.availability}: ${feed.detail}`,
					undefined,
					[],
					urls.length,
				);
			}
			const exact = new Map<string, ReputationFeedRecord>();
			const domains = new Map<string, ReputationFeedRecord>();
			for (const record of feed.records) {
				if (record.verdict !== "deny") continue;
				if (record.kind === "url") exact.set(record.indicator, record);
				if (record.kind === "domain") domains.set(record.indicator.toLowerCase().replace(/\.$/, ""), record);
			}
			for (const url of urls) {
				const match = matchSignedUrl(url, exact, domains);
				if (match) {
					signedResults.set(url, {
						url,
						isMalicious: true,
						findings: [{ severityName: match.severity ?? "high", typeName: `signed-feed:${feed.feedId}:${match.id}` }],
						flags: ["signed_reputation_feed"],
					});
				}
			}
		}
		const uncheckedUrls = urls.filter((url) => !signedResults.has(url));
		if (uncheckedUrls.length === 0) return [...signedResults.values()];

		const batches: string[][] = [];
		for (let i = 0; i < uncheckedUrls.length; i += MAX_URLS_PER_REQUEST) {
			batches.push(uncheckedUrls.slice(i, i + MAX_URLS_PER_REQUEST));
		}

		// allSettled, not all: see checkHashes. Partial coverage must keep its
		// detections AND report the gap.
		const settled = await Promise.allSettled(batches.map((batch) => this.checkBatch(batch)));

		const results: UrlCheckResult[] = [...signedResults.values()];
		const failures: DetectionLegUnavailableError[] = [];
		let uncheckedCount = 0;
		settled.forEach((outcome, index) => {
			if (outcome.status === "fulfilled") {
				results.push(...outcome.value);
				return;
			}
			const reason = outcome.reason;
			failures.push(
				reason instanceof DetectionLegUnavailableError
					? reason
					: new DetectionLegUnavailableError("url_reputation", String(reason)),
			);
			uncheckedCount += batches[index]?.length ?? 0;
		});

		if (failures.length > 0) {
			throw new DetectionLegUnavailableError(
				"url_reputation",
				failures.length === 1
					? (failures[0]?.reason ?? "check failed")
					: `${failures.length} of ${batches.length} batches failed: ${failures[0]?.reason ?? "check failed"}`,
				failures[0]?.status,
				results,
				uncheckedCount,
			);
		}

		return results;
	}

	private async checkBatch(urls: string[]): Promise<UrlCheckResult[]> {
		const queries = urls.map((url) => ({ key: { "url-like": url } }));
		const payload = {
			queries,
			"client-info": {
				"product-name": SERVICE_NAME,
				"product-version": VERSION,
			},
		};

		try {
			const headers: Record<string, string> = Object.fromEntries(
				REQUEST_HEADERS.map((h) => [h.name, h.value]),
			);
			const apiKey = this.apiKey?.trim();
			if (apiKey) {
				headers.Authorization = `Bearer ${apiKey}`;
			}
			const response = await fetch(this.endpoint, {
				method: "POST",
				headers,
				body: JSON.stringify(payload),
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (!response.ok) {
				// Return [] here and an unauthenticated endpoint becomes
				// indistinguishable from a clean verdict - see detection-leg.ts.
				this.logger.warn(`URL check HTTP error: ${response.status}`);
				throw new DetectionLegUnavailableError(
					"url_reputation",
					describeHttpFailure(response.status),
					response.status,
				);
			}

			const data = (await response.json()) as Record<string, unknown>;
			const answers = (data.answers ?? []) as Record<string, unknown>[];

			const results: UrlCheckResult[] = [];
			for (const answer of answers) {
				const result = this.parseAnswer(answer);
				if (result !== null) {
					results.push(result);
				}
			}
			return results;
		} catch (e) {
			// An unavailable leg must stay distinguishable from a clean one, so the
			// typed error is re-thrown rather than converted into an empty result.
			if (e instanceof DetectionLegUnavailableError) throw e;
			this.logger.warn("URL check request failed", { error: String(e) });
			throw new DetectionLegUnavailableError("url_reputation", String(e));
		}
	}

	private parseAnswer(answer: Record<string, unknown>): UrlCheckResult | null {
		try {
			const url = (answer.key ?? "") as string;
			const result = (answer.result ?? {}) as Record<string, unknown>;
			const success = (result.success ?? {}) as Record<string, unknown>;
			const classification = (success.classification ?? {}) as Record<string, unknown>;
			const classResult = (classification.result ?? {}) as Record<string, unknown>;
			const flags = (success.flags ?? []) as string[];
			const malicious = classResult.malicious as Record<string, unknown> | undefined;

			const findings: UrlCheckFinding[] = malicious
				? ((malicious.findings ?? []) as Record<string, unknown>[]).map((f) => ({
						severityName: (f["severity-name"] ?? "unknown") as string,
						typeName: (f["type-name"] ?? "unknown") as string,
					}))
				: [];

			return {
				url,
				isMalicious: Boolean(malicious),
				findings,
				flags,
			};
		} catch (e) {
			this.logger.warn("Failed to parse answer", { error: String(e) });
			return null;
		}
	}
}
