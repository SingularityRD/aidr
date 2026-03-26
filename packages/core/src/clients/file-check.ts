/**
 * HTTP client for file reputation API.
 * Queries file hash reputation — returns severity and detection names.
 * Fails open (returns null) on any error — file-check is supplementary.
 */

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

	constructor(
		config?: { endpoint?: string; timeout_seconds?: number },
		logger: Logger = nullLogger,
		apiKey?: string,
	) {
		this.endpoint = config?.endpoint ?? this.resolveEndpoint();
		this.timeoutMs = (config?.timeout_seconds ?? DEFAULT_TIMEOUT) * 1000;
		this.apiKey = apiKey;
		this.logger = logger;
	}

	private buildPath(): string {
		return "/file-check";
	}

	async checkHash(hash: string): Promise<FileCheckResult | null> {
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
			return this.parseResponse(data);
		} catch (e) {
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

	private parseResponse(data: Record<string, unknown>): FileCheckResult | null {
		try {
			const responses = (data.responses ?? []) as Record<string, unknown>[];
			if (responses.length === 0) return null;

			const first = responses[0] as Record<string, unknown>;
			const severity = (first.severity ?? "SEVERITY_UNKNOWN") as string;

			// malware_name is a repeated string field directly on FileResponse
			const malwareNames = (first.malware_name ?? []) as string[];
			const detectionNames = malwareNames.filter((n) => typeof n === "string" && n.length > 0);

			return { severity, detectionNames };
		} catch (e) {
			this.logger.warn("Failed to parse FileCheck response", { error: String(e) });
			return null;
		}
	}

	async checkHashes(hashes: string[]): Promise<FileCheckBatchResult[]> {
		if (hashes.length === 0) return [];

		const batches: string[][] = [];
		for (let i = 0; i < hashes.length; i += MAX_HASHES_PER_REQUEST) {
			batches.push(hashes.slice(i, i + MAX_HASHES_PER_REQUEST));
		}

		const batchResults = await Promise.all(batches.map((batch) => this.checkHashBatch(batch)));
		return batchResults.flat();
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
				this.logger.warn(`FileCheck batch HTTP error: ${response.status}`);
				return [];
			}

			const data = (await response.json()) as Record<string, unknown>;
			return this.parseBatchResponse(data);
		} catch (e) {
			this.logger.warn("FileCheck batch request failed", { error: String(e) });
			return [];
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
