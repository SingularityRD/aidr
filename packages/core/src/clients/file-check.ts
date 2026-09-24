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
const MAX_CONCURRENT_BATCHES = 4;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const SHA256_PATTERN = /^[a-f0-9]{64}$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeSha256(value: unknown): string | null {
	return typeof value === "string" && SHA256_PATTERN.test(value) ? value.toLowerCase() : null;
}

function validatedEndpoint(value: string, allowInsecureLoopback = false): string {
	const endpoint = new URL(value);
	const loopback =
		endpoint.hostname === "localhost" ||
		endpoint.hostname === "127.0.0.1" ||
		endpoint.hostname === "[::1]" ||
		endpoint.hostname === "::1";
	if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
		throw new Error("file-check endpoint must not contain credentials, query, or fragment");
	}
	if (
		endpoint.protocol !== "https:" &&
		!(endpoint.protocol === "http:" && loopback && allowInsecureLoopback)
	) {
		throw new Error(
			"file-check endpoint must use HTTPS (loopback HTTP requires allow_insecure_loopback)",
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

function isFileCheckBatchResult(value: unknown): value is FileCheckBatchResult {
	return (
		isRecord(value) &&
		typeof value.sha256 === "string" &&
		typeof value.severity === "string" &&
		Array.isArray(value.detectionNames) &&
		value.detectionNames.every((name) => typeof name === "string")
	);
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
			allow_insecure_loopback?: boolean;
		},
		logger: Logger = nullLogger,
		apiKey?: string,
	) {
		this.endpoint = validatedEndpoint(
			config?.endpoint ?? this.resolveEndpoint(),
			config?.allow_insecure_loopback,
		);
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
				redirect: "error",
			});

			if (!response.ok) {
				this.logger.warn(`FileCheck HTTP error: ${response.status}`);
				return null;
			}

			const data = await readBoundedJson(response);
			return isRecord(data) ? this.parseResponse(data, hash) : null;
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
			const requestedHash = normalizeSha256(hash);
			if (
				!requestedHash ||
				!isRecord(entry.key) ||
				normalizeSha256(entry.key.sha256) !== requestedHash
			)
				return null;
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
		const uniqueBySha256 = new Map<string, string>();
		for (const hash of hashes) {
			const normalized = normalizeSha256(hash);
			if (!normalized) {
				throw new DetectionLegUnavailableError(
					"file_reputation",
					"invalid SHA-256 digest",
					undefined,
					[],
					hashes.length,
				);
			}
			if (!uniqueBySha256.has(normalized)) uniqueBySha256.set(normalized, hash);
		}
		const uniqueHashes = [...uniqueBySha256.values()];
		const signed = await this.signedMatches(uniqueHashes);
		const uncheckedHashes = uniqueHashes.filter((hash) => !signed.has(hash));

		const batches: string[][] = [];
		for (let i = 0; i < uncheckedHashes.length; i += MAX_HASHES_PER_REQUEST) {
			batches.push(uncheckedHashes.slice(i, i + MAX_HASHES_PER_REQUEST));
		}

		// Keep partial-failure semantics without opening one connection per batch.
		// Storing by index preserves input order even when batches finish out of order.
		const settled = new Array<PromiseSettledResult<FileCheckBatchResult[]>>(batches.length);
		let nextBatch = 0;
		const workers = Array.from(
			{ length: Math.min(MAX_CONCURRENT_BATCHES, batches.length) },
			async () => {
				while (nextBatch < batches.length) {
					const index = nextBatch++;
					const batch = batches[index];
					if (!batch) continue;
					try {
						settled[index] = { status: "fulfilled", value: await this.checkHashBatch(batch) };
					} catch (reason) {
						settled[index] = { status: "rejected", reason };
					}
				}
			},
		);
		await Promise.all(workers);

		const resultsBySha256 = new Map<string, FileCheckBatchResult>();
		for (const result of signed.values()) {
			const normalized = normalizeSha256(result.sha256);
			if (normalized) resultsBySha256.set(normalized, result);
		}
		const failures: DetectionLegUnavailableError[] = [];
		settled.forEach((outcome) => {
			if (outcome.status === "fulfilled") {
				for (const result of outcome.value) {
					const normalized = normalizeSha256(result.sha256);
					if (normalized) resultsBySha256.set(normalized, result);
				}
				return;
			}
			const reason = outcome.reason;
			const failure =
				reason instanceof DetectionLegUnavailableError
					? reason
					: new DetectionLegUnavailableError("file_reputation", String(reason));
			failures.push(failure);
			for (const result of failure.partialResults.filter(isFileCheckBatchResult)) {
				const normalized = normalizeSha256(result.sha256);
				if (normalized && uniqueBySha256.has(normalized)) {
					resultsBySha256.set(normalized, result);
				}
			}
		});
		const results = hashes.flatMap((hash) => {
			const result = resultsBySha256.get(normalizeSha256(hash) as string);
			return result ? [{ ...result, sha256: hash }] : [];
		});
		const uncheckedCount = hashes.length - results.length;

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
				redirect: "error",
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

			const data = await readBoundedJson(response);
			return this.parseBatchResponse(data, hashes);
		} catch (e) {
			// An unavailable leg must stay distinguishable from a clean one, so the
			// typed error is re-thrown rather than converted into an empty result.
			if (e instanceof DetectionLegUnavailableError) throw e;
			this.logger.warn("FileCheck batch request failed", { error: String(e) });
			throw new DetectionLegUnavailableError("file_reputation", String(e));
		}
	}

	private parseBatchResponse(data: unknown, hashes: string[]): FileCheckBatchResult[] {
		const results: FileCheckBatchResult[] = [];
		const requested = new Map<string, string>();
		const seen = new Set<string>();
		let malformed = false;
		for (const hash of hashes) {
			const normalized = normalizeSha256(hash);
			if (!normalized || requested.has(normalized)) {
				malformed = true;
				continue;
			}
			requested.set(normalized, hash);
		}
		malformed ||= !isRecord(data) || !Array.isArray(data.responses);
		const responses = !malformed && isRecord(data) ? data.responses : [];
		for (const value of responses as unknown[]) {
			if (!isRecord(value) || !isRecord(value.key)) {
				malformed = true;
				continue;
			}
			const sha256 = normalizeSha256(value.key.sha256);
			const severity = value.severity;
			const malwareNames = value.malware_name ?? [];
			if (
				!sha256 ||
				!requested.has(sha256) ||
				seen.has(sha256) ||
				(severity !== "SEVERITY_UNKNOWN" && severity !== "SEVERITY_MALWARE") ||
				!Array.isArray(malwareNames) ||
				!malwareNames.every((name) => typeof name === "string") ||
				(severity === "SEVERITY_UNKNOWN" && malwareNames.length > 0)
			) {
				malformed = true;
				continue;
			}
			seen.add(sha256);
			results.push({
				sha256: requested.get(sha256) ?? sha256,
				severity,
				detectionNames: malwareNames.filter((name) => name.length > 0),
			});
		}
		const missing = [...requested.keys()].filter((hash) => !seen.has(hash));
		if (malformed || missing.length > 0) {
			throw new DetectionLegUnavailableError(
				"file_reputation",
				malformed ? "malformed file reputation response" : "incomplete file reputation response",
				undefined,
				results,
				malformed ? Math.max(0, hashes.length - results.length) : missing.length,
			);
		}
		return results;
	}

	private buildDomain(): string {
		return [this.getSubdomain(), getProviderName(), getProviderTld()].join(".");
	}
}
