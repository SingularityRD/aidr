/**
 * HTTP client for file reputation API.
 * Queries file hash reputation — returns severity and detection names.
 * Single remote checks return null on endpoint errors; batch checks report an
 * unavailable detection leg. A configured signed feed fails closed if invalid.
 */

import { DetectionLegUnavailableError, describeHttpFailure } from "../detection-leg.js";
import { loadReputationFeed, type ReputationFeedLoadOptions } from "../reputation-feed.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { VERSION } from "../version.js";

const DEFAULT_TIMEOUT = 5.0;
const SERVICE_NAME = "aidr";
const MAX_HASHES_PER_REQUEST = 50;

function getProviderTld(): string {
	return "com";
}

const REQUEST_HEADERS = [
	{ name: "Accept", value: "application/json" },
	{ name: "Content-Type", value: "application/json" },
	{ name: "User-Agent", value: SERVICE_NAME },
];

export interface FileCheckResult {
	severity: string;
	detectionNames: string[];
}

export interface FileCheckBatchResult extends FileCheckResult {
	sha256: string;
}

function getProviderName(): string {
	return "singularityrd";
}

export class FileCheckClient {
	private readonly endpoint: string;
	private readonly timeoutMs: number;
	private readonly apiKey?: string;
	private readonly logger: Logger;
	private readonly reputationFeed?: ReputationFeedLoadOptions;

	constructor(
		config?: {
			endpoint?: string;
			timeout_seconds?: number;
			reputationFeed?: ReputationFeedLoadOptions;
		},
		logger: Logger = nullLogger,
		apiKey?: string,
	) {
		this.endpoint = config?.endpoint ?? this.resolveEndpoint();
		this.timeoutMs = (config?.timeout_seconds ?? DEFAULT_TIMEOUT) * 1000;
		this.apiKey = apiKey;
		this.logger = logger;
		this.reputationFeed = config?.reputationFeed;
	}

	private async signedMatches(hashes: string[]): Promise<Map<string, FileCheckBatchResult>> {
		const matches = new Map<string, FileCheckBatchResult>();
		if (!this.reputationFeed) return matches;
		const feed = await loadReputationFeed(this.reputationFeed);
		if (feed.availability !== "available") {
			throw new DetectionLegUnavailableError(
				"file_reputation",
				`signed feed ${feed.feedId} is ${feed.availability}: ${feed.detail}`,
				undefined,
				[],
				hashes.length,
			);
		}
		const denyByHash = new Map<string, string>();
		for (const record of feed.records) {
			if (
				(record.kind === "file_sha256" || record.kind === "package_sha256") &&
				record.verdict === "deny"
			) {
				denyByHash.set(record.indicator.toLowerCase(), record.id);
			}
		}
		for (const hash of hashes) {
			const recordId = denyByHash.get(hash.toLowerCase());
			if (recordId) {
				matches.set(hash, {
					sha256: hash,
					severity: "SEVERITY_MALWARE",
					detectionNames: [`signed-feed:${feed.feedId}:${recordId}`],
				});
			}
		}
		return matches;
	}

	private buildPath(): string {
		return "/file-check";
	}

	async checkHash(hash: string): Promise<FileCheckResult | null> {
		try {
			const signed = (await this.signedMatches([hash])).get(hash);
			if (signed) return { severity: signed.severity, detectionNames: signed.detectionNames };
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
				body: JSON.stringify({
					requests: [{ key: { sha256: hash } }],
					client_info: {
						product: {
							version_app: VERSION,
						},
					},
				}),
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (!response.ok) {
				this.logger.warn(`FileCheck HTTP error: ${response.status}`);
				return null;
			}

			const data = (await response.json()) as Record<string, unknown>;
			return this.parseResponse(data, hash);
		} catch (e) {
			if (e instanceof DetectionLegUnavailableError) throw e;
			this.logger.warn("FileCheck request failed", { error: String(e) });
			return null;
		}
	}

	private getSubdomain(): string {
		return "svc";
	}

	private resolveEndpoint(): string {
		return `https://${SERVICE_NAME}-proxy.${this.buildDomain()}${this.buildPath()}`;
	}

	private parseResponse(data: Record<string, unknown>, hash: string): FileCheckResult | null {
		try {
			if (!data || !Array.isArray(data.responses) || data.responses.length !== 1) return null;
			const first: unknown = data.responses[0];
			if (!first || typeof first !== "object" || Array.isArray(first)) return null;
			const entry = first as Record<string, unknown>;
			if (entry.key !== undefined) {
				if (!entry.key || typeof entry.key !== "object" || Array.isArray(entry.key)) return null;
				if ((entry.key as Record<string, unknown>).sha256 !== hash) return null;
			}
			// An omitted or invented severity is not a completed benign verdict.
			if (entry.severity !== "SEVERITY_UNKNOWN" && entry.severity !== "SEVERITY_MALWARE") {
				return null;
			}
			const severity = entry.severity;

			// malware_name is a repeated string field directly on FileResponse
			if (entry.malware_name !== undefined && !Array.isArray(entry.malware_name)) return null;
			const malwareNames = (entry.malware_name ?? []) as string[];
			if (!malwareNames.every((name) => typeof name === "string")) return null;
			const detectionNames = malwareNames.filter((n) => typeof n === "string" && n.length > 0);
			if (severity === "SEVERITY_UNKNOWN" && detectionNames.length > 0) return null;

			return { severity, detectionNames };
		} catch (e) {
			this.logger.warn("Failed to parse FileCheck response", { error: String(e) });
			return null;
		}
	}

	async checkHashes(hashes: string[]): Promise<FileCheckBatchResult[]> {
		if (hashes.length === 0) return [];
		const signed = await this.signedMatches(hashes);
		const uncheckedHashes = hashes.filter((hash) => !signed.has(hash));
		if (uncheckedHashes.length === 0) return [...signed.values()];

		const batches: string[][] = [];
		for (let i = 0; i < uncheckedHashes.length; i += MAX_HASHES_PER_REQUEST) {
			batches.push(uncheckedHashes.slice(i, i + MAX_HASHES_PER_REQUEST));
		}

		// allSettled, not all: a failure in one batch must not discard the
		// detections the other batches found, and it must not be silent either.
		// Whatever succeeded is kept, and the gap is reported.
		const settled = await Promise.allSettled(batches.map((batch) => this.checkHashBatch(batch)));

		const results: FileCheckBatchResult[] = [...signed.values()];
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
					: new DetectionLegUnavailableError("file_reputation", String(reason)),
			);
			uncheckedCount += batches[index]?.length ?? 0;
		});

		if (failures.length > 0) {
			// Carry the real detections out with the error so the caller can report
			// both "here is what we found" and "here is what we could not check".
			throw new DetectionLegUnavailableError(
				"file_reputation",
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

	private async checkHashBatch(hashes: string[]): Promise<FileCheckBatchResult[]> {
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
				body: JSON.stringify({
					requests: hashes.map((h) => ({ key: { sha256: h } })),
					client_info: {
						product_name: SERVICE_NAME,
						product_version: VERSION,
					},
				}),
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (!response.ok) {
				// Return [] here and an unauthenticated endpoint becomes
				// indistinguishable from a clean verdict - see detection-leg.ts.
				this.logger.warn(`FileCheck batch HTTP error: ${response.status}`);
				throw new DetectionLegUnavailableError(
					"file_reputation",
					describeHttpFailure(response.status),
					response.status,
				);
			}

			const data = (await response.json()) as Record<string, unknown>;
			return this.parseBatchResponse(data);
		} catch (e) {
			// An unavailable leg must stay distinguishable from a clean one, so the
			// typed error is re-thrown rather than converted into an empty result.
			if (e instanceof DetectionLegUnavailableError) throw e;
			this.logger.warn("FileCheck batch request failed", { error: String(e) });
			throw new DetectionLegUnavailableError("file_reputation", String(e));
		}
	}

	private parseBatchResponse(data: Record<string, unknown>): FileCheckBatchResult[] {
		const results: FileCheckBatchResult[] = [];
		try {
			const responses = (data.responses ?? []) as Record<string, unknown>[];
			for (const entry of responses) {
				const key = entry.key as Record<string, unknown> | undefined;
				const sha256 = (key?.sha256 ?? "") as string;
				if (!sha256) continue;

				const severity = (entry.severity ?? "SEVERITY_UNKNOWN") as string;
				const malwareNames = (entry.malware_name ?? []) as string[];
				const detectionNames = malwareNames.filter((n) => typeof n === "string" && n.length > 0);

				results.push({ sha256, severity, detectionNames });
			}
		} catch (e) {
			this.logger.warn("Failed to parse FileCheck batch response", { error: String(e) });
		}
		return results;
	}

	private buildDomain(): string {
		return [this.getSubdomain(), getProviderName(), getProviderTld()].join(".");
	}
}
