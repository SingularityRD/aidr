/**
 * HTTP client for URL reputation checking.
 * Uses native fetch — no external HTTP dependencies.
 *
 * The default endpoint is expected to be operated by SingularityRD (or your
 * organization, if you override `url_check.endpoint`). Treat it as best-effort:
 * endpoint failures are reported as an unavailable detection leg. A configured
 * signed feed is verified for trust and freshness before its results are used.
 * An answer that the feed has no row for is unavailable too - never clean.
 */

import { DetectionLegUnavailableError, describeHttpFailure } from "../detection-leg.js";
import {
	loadReputationFeed,
	type ReputationFeedLoadOptions,
	type ReputationFeedRecord,
} from "../reputation-feed.js";
import type { Logger, UrlCheckConfig, UrlCheckFinding, UrlCheckResult } from "../types.js";
import { clampLegTimeoutSeconds, nullLogger } from "../types.js";
import { VERSION } from "../version.js";

const MAX_URLS_PER_REQUEST = 50;
const MAX_CONCURRENT_BATCHES = 4;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const SERVICE_NAME = "aidr";

/**
 * The endpoint's marker for "the reputation store holds no row for this URL".
 * Kept in sync with `supabase/functions/url-check/index.ts`. An answer that
 * carries it, or an `unknown` classification, means the URL was NOT checked -
 * which is not the same value as a checked-and-clean URL.
 */
const NO_COVERAGE = "no_data";

type ParsedAnswer =
	| { kind: "covered"; result: UrlCheckResult }
	| { kind: "uncovered"; url: string }
	| null;

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canSendToReputation(url: string, includeQueryParameters: boolean): boolean {
	try {
		const parsed = new URL(url);
		return (
			(parsed.protocol === "http:" || parsed.protocol === "https:") &&
			!parsed.username &&
			!parsed.password &&
			!parsed.hash &&
			(includeQueryParameters || !parsed.search)
		);
	} catch {
		return false;
	}
}

function validatedEndpoint(value: string, allowInsecureLoopback = false): string {
	const endpoint = new URL(value);
	const loopback =
		endpoint.hostname === "localhost" ||
		endpoint.hostname === "127.0.0.1" ||
		endpoint.hostname === "[::1]" ||
		endpoint.hostname === "::1";
	if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
		throw new Error("URL-check endpoint must not contain credentials, query, or fragment");
	}
	if (
		endpoint.protocol !== "https:" &&
		!(endpoint.protocol === "http:" && loopback && allowInsecureLoopback)
	) {
		throw new Error(
			"URL-check endpoint must use HTTPS (loopback HTTP requires allow_insecure_loopback)",
		);
	}
	return endpoint.href;
}

async function readBoundedJson(response: Response): Promise<unknown> {
	const length = response.headers?.get?.("content-length");
	if (length && /^\d+$/.test(length) && Number(length) > MAX_RESPONSE_BYTES) {
		throw new Error("response_too_large");
	}
	const reader = response.body?.getReader?.();
	// Unit-test stubs expose json() without a web stream. Real fetch responses use
	// the bounded streaming path below.
	if (!reader) return response.json();
	const chunks: Uint8Array[] = [];
	let bytes = 0;
	try {
		for (;;) {
			const item = await reader.read();
			if (item.done) break;
			bytes += item.value.byteLength;
			if (bytes > MAX_RESPONSE_BYTES) throw new Error("response_too_large");
			chunks.push(item.value);
		}
	} catch (error) {
		await reader.cancel(error).catch(() => undefined);
		throw error;
	}
	return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
}

function isUrlCheckResult(value: unknown): value is UrlCheckResult {
	if (!value || typeof value !== "object") return false;
	const candidate = value as Partial<UrlCheckResult>;
	return (
		typeof candidate.url === "string" &&
		typeof candidate.isMalicious === "boolean" &&
		Array.isArray(candidate.findings) &&
		Array.isArray(candidate.flags)
	);
}

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
	private readonly includeQueryParameters: boolean;

	constructor(
		config?: Partial<UrlCheckConfig> & {
			reputationFeed?: ReputationFeedLoadOptions;
			allow_insecure_loopback?: boolean;
		},
		logger: Logger = nullLogger,
		apiKey?: string,
	) {
		this.endpoint = validatedEndpoint(
			config?.endpoint ?? resolveEndpoint("/url-check"),
			config?.allow_insecure_loopback,
		);
		// Clamped here as well as in the config schema: a caller that builds the
		// client directly must not be able to exceed a host hook's deadline.
		this.timeoutMs = clampLegTimeoutSeconds(config?.timeout_seconds) * 1000;
		this.apiKey = apiKey;
		this.logger = logger;
		this.reputationFeed = config?.reputationFeed;
		this.includeQueryParameters = config?.include_query_parameters ?? false;
	}

	async checkUrls(urls: string[]): Promise<UrlCheckResult[]> {
		if (urls.length === 0) return [];
		const uniqueUrls = [...new Set(urls)];
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
				if (record.kind === "domain")
					domains.set(record.indicator.toLowerCase().replace(/\.$/, ""), record);
			}
			for (const url of uniqueUrls) {
				const match = matchSignedUrl(url, exact, domains);
				if (match) {
					signedResults.set(url, {
						url,
						isMalicious: true,
						findings: [
							{
								severityName: match.severity ?? "high",
								typeName: `signed-feed:${feed.feedId}:${match.id}`,
							},
						],
						flags: ["signed_reputation_feed"],
					});
				}
			}
		}
		const uncheckedUrls = uniqueUrls.filter((url) => !signedResults.has(url));
		const withheldUrls = uncheckedUrls.filter(
			(url) => !canSendToReputation(url, this.includeQueryParameters),
		);
		const requestableUrls = uncheckedUrls.filter((url) => !withheldUrls.includes(url));
		if (requestableUrls.length === 0 && withheldUrls.length === 0) {
			return urls.map((url) => signedResults.get(url)!);
		}

		const batches: string[][] = [];
		for (let i = 0; i < requestableUrls.length; i += MAX_URLS_PER_REQUEST) {
			batches.push(requestableUrls.slice(i, i + MAX_URLS_PER_REQUEST));
		}

		// Keep partial-failure semantics without opening one connection per batch.
		// Storing by index preserves input order even when batches finish out of order.
		const settled = new Array<PromiseSettledResult<UrlCheckResult[]>>(batches.length);
		let nextBatch = 0;
		const workers = Array.from(
			{ length: Math.min(MAX_CONCURRENT_BATCHES, batches.length) },
			async () => {
				while (nextBatch < batches.length) {
					const index = nextBatch++;
					const batch = batches[index];
					if (!batch) continue;
					try {
						settled[index] = { status: "fulfilled", value: await this.checkBatch(batch) };
					} catch (reason) {
						settled[index] = { status: "rejected", reason };
					}
				}
			},
		);
		await Promise.all(workers);

		const resultsByUrl = new Map(signedResults);
		const failures: DetectionLegUnavailableError[] = [];
		settled.forEach((outcome) => {
			if (outcome.status === "fulfilled") {
				for (const result of outcome.value) resultsByUrl.set(result.url, result);
				return;
			}
			const reason = outcome.reason;
			const failure =
				reason instanceof DetectionLegUnavailableError
					? reason
					: new DetectionLegUnavailableError("url_reputation", String(reason));
			failures.push(failure);
			// A batch can cover some of its URLs and not others (a feed with no
			// row for one of them). The classifications it did produce are
			// evidence, so they survive alongside the gap.
			for (const result of failure.partialResults.filter(isUrlCheckResult)) {
				resultsByUrl.set(result.url, result);
			}
		});
		const results = urls.flatMap((url) => {
			const result = resultsByUrl.get(url);
			return result ? [result] : [];
		});
		const uncheckedCount = urls.length - results.length;

		if (failures.length > 0 || withheldUrls.length > 0) {
			const reasons = [
				...(withheldUrls.length > 0
					? [
							`${withheldUrls.length} URL(s) withheld because query parameters, fragments, credentials, or an unsupported URL were not sent`,
						]
					: []),
				...(failures.length > 0
					? [
							failures.length === 1
								? (failures[0]?.reason ?? "check failed")
								: `${failures.length} of ${batches.length} batches failed: ${failures[0]?.reason ?? "check failed"}`,
						]
					: []),
			];
			throw new DetectionLegUnavailableError(
				"url_reputation",
				reasons.join("; "),
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
				redirect: "error",
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

			const data = await readBoundedJson(response);
			if (!isRecord(data) || !Array.isArray(data.answers)) {
				throw new DetectionLegUnavailableError(
					"url_reputation",
					"malformed reputation response",
					undefined,
					[],
					urls.length,
				);
			}
			const answers = data.answers;

			const results: UrlCheckResult[] = [];
			const requested = new Set(urls);
			const seen = new Set<string>();
			const uncovered = new Set<string>();
			let malformed = false;
			for (const answer of answers) {
				const parsed = isRecord(answer) ? this.parseAnswer(answer) : null;
				if (
					parsed === null ||
					!requested.has(parsed.kind === "covered" ? parsed.result.url : parsed.url) ||
					seen.has(parsed.kind === "covered" ? parsed.result.url : parsed.url)
				) {
					malformed = true;
					continue;
				}
				const url = parsed.kind === "covered" ? parsed.result.url : parsed.url;
				seen.add(url);
				if (parsed.kind === "uncovered") {
					uncovered.add(parsed.url);
					continue;
				}
				results.push(parsed.result);
			}
			const missing = [...requested].filter((url) => !seen.has(url));
			if (malformed || uncovered.size > 0 || missing.length > 0) {
				// The endpoint answered, but its reputation store holds no row for
				// these URLs. Reporting them as clean is exactly the false-clean
				// this client exists to prevent, so the gap is raised as an
				// unavailable leg while any real classification in the same batch
				// is kept as a partial result.
				const uncheckedCount = malformed
					? Math.max(0, requested.size - results.length)
					: uncovered.size + missing.length;
				throw new DetectionLegUnavailableError(
					"url_reputation",
					malformed
						? "malformed reputation response"
						: `no reputation feed coverage for ${uncheckedCount} of ${urls.length} requested URLs`,
					undefined,
					results,
					uncheckedCount,
				);
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

	private parseAnswer(answer: Record<string, unknown>): ParsedAnswer {
		try {
			const url = answer.key;
			const result = answer.result;
			const success = isRecord(result) ? result.success : undefined;
			const classification = isRecord(success) ? success.classification : undefined;
			const classResult = isRecord(classification) ? classification.result : undefined;
			const flags = isRecord(success) ? (success.flags ?? []) : undefined;
			if (
				typeof url !== "string" ||
				!isRecord(success) ||
				!isRecord(classification) ||
				!isRecord(classResult) ||
				!Array.isArray(flags) ||
				!flags.every((flag) => typeof flag === "string")
			) {
				return null;
			}
			const maliciousValue = classResult.malicious;
			if (maliciousValue !== undefined && !isRecord(maliciousValue)) return null;
			const malicious = maliciousValue as Record<string, unknown> | undefined;

			// An empty classification is clean only when the endpoint affirmatively
			// says this URL was covered. Missing coverage cannot distinguish a clean
			// verdict from an older endpoint's no-row response.
			const uncovered =
				classResult.unknown !== undefined ||
				answer.coverage === NO_COVERAGE ||
				success.coverage === NO_COVERAGE;
			const covered = answer.coverage === "covered" || success.coverage === "covered";
			if ((uncovered || !covered) && !malicious) {
				return { kind: "uncovered", url };
			}

			const rawFindings = malicious?.findings ?? [];
			if (!Array.isArray(rawFindings) || rawFindings.some((finding) => !isRecord(finding))) {
				return null;
			}
			const findings: UrlCheckFinding[] = rawFindings.map((finding) => {
				const severityName = finding["severity-name"] ?? "unknown";
				const typeName = finding["type-name"] ?? "unknown";
				if (typeof severityName !== "string" || typeof typeName !== "string") {
					throw new Error("invalid finding");
				}
				return { severityName, typeName };
			});
			const cacheValidUntil =
				typeof answer.cache_valid_until === "string"
					? Date.parse(answer.cache_valid_until)
					: Number.NaN;
			if (
				!malicious &&
				flags.length === 0 &&
				(!Number.isFinite(cacheValidUntil) || cacheValidUntil <= Date.now())
			) {
				return { kind: "uncovered", url };
			}

			return {
				kind: "covered",
				result: {
					url,
					isMalicious: Boolean(malicious),
					findings,
					flags,
					...(Number.isFinite(cacheValidUntil) ? { cacheValidUntil } : {}),
				},
			};
		} catch (e) {
			this.logger.warn("Failed to parse answer", { error: String(e) });
			return null;
		}
	}
}
