import { resolvePath } from "../config.js";
import { atomicWriteJson, getFileContent } from "../file-utils.js";
import type { Logger, NvdConfig } from "../types.js";
import { nullLogger } from "../types.js";

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const MAX_RESULTS_PER_PAGE = 2000;
const DEFAULT_TIMEOUT = 30;
const DEFAULT_CACHE_TTL_HOURS = 6;

const AI_AGENT_KEYWORDS = [
	"AI",
	"artificial intelligence",
	"machine learning",
	"LLM",
	"large language model",
	"agent",
	"chatbot",
	"OpenClaw",
	"Claude",
	"Claude Code",
	"Cursor",
	"code assistant",
	"AI agent",
	"autonomous agent",
	"MCP",
	"Model Context Protocol",
];

export interface CveEntry {
	id: string;
	severity: "critical" | "high" | "medium" | "low";
	cvssScore: number;
	description: string;
	published: string;
	modified: string;
	affectedProducts: string[];
	references: string[];
	cweIds: string[];
	exploitabilityContext?: ExploitabilityContext;
}

export interface ExploitabilityContext {
	score: "trivial" | "easy" | "medium" | "hard" | "unknown";
	rationale: string;
	publicExploitAvailable: boolean;
	weaponized: boolean;
	attackRequirements: string[];
	epssScore?: number;
}

export interface CveMatch {
	cve: CveEntry;
	confidence: number;
	matchedKeywords: string[];
	recommendation: string;
}

interface NvdCve {
	id: string;
	published: string;
	lastModified: string;
	descriptions?: Array<{ value: string }>;
	metrics?: {
		cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
		cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string } }>;
	};
	configurations?: Array<{ nodes?: unknown[] }>;
	references?: Array<{ url: string }>;
	weaknesses?: Array<{ description?: Array<{ value: string }> }>;
}

export class NvdClient {
	private readonly apiKey: string | undefined;
	private readonly timeoutMs: number;
	private readonly cachePath: string;
	private readonly cacheTtlMs: number;
	private readonly logger: Logger;

	constructor(config: Partial<NvdConfig> = {}, logger: Logger = nullLogger) {
		this.apiKey = config.api_key;
		this.timeoutMs = (config.timeout_seconds ?? DEFAULT_TIMEOUT) * 1000;
		this.cachePath = resolvePath(config.cache_path ?? "~/.singularity-aidr/nvd-cache.json");
		this.cacheTtlMs = (config.cache_ttl_hours ?? DEFAULT_CACHE_TTL_HOURS) * 60 * 60 * 1000;
		this.logger = logger;
	}

	async fetchRecentCves(daysBack = 7): Promise<CveEntry[]> {
		const params = this.buildSearchParams(daysBack);

		try {
			const response = await fetch(`${NVD_API_BASE}?${params}`, {
				headers: { Accept: "application/json", "User-Agent": "Singularity-AIDR-NVD-Client" },
				signal: AbortSignal.timeout(this.timeoutMs),
			});

			if (!response.ok) {
				throw new Error(`NVD API error: ${response.status}`);
			}

			const data = (await response.json()) as { vulnerabilities?: Array<{ cve: NvdCve }> };
			const cves = this.parseEntries(data.vulnerabilities || []);

			this.logger.info(`Fetched ${cves.length} CVEs from NVD`);
			await this.saveToCache(cves);

			return cves;
		} catch (error) {
			this.logger.error("Failed to fetch CVEs", { error: String(error) });
			return this.loadFromCache();
		}
	}

	async searchAiAgentCves(): Promise<CveEntry[]> {
		const allCves = await this.fetchRecentCves(30);
		return allCves.filter((cve) => this.isAiAgentRelated(cve));
	}

	matchToolCallAgainstCves(
		toolName: string,
		toolInput: Record<string, unknown>,
		cves: CveEntry[],
	): CveMatch[] {
		const toolText = JSON.stringify({ toolName, toolInput }).toLowerCase();
		const matches = cves
			.map((cve) => this.calculateMatch(cve, toolText))
			.filter((m) => m.confidence > 0.5);
		return matches.sort((a, b) => b.confidence - a.confidence);
	}

	private buildSearchParams(daysBack: number): URLSearchParams {
		const startDate = new Date();
		startDate.setDate(startDate.getDate() - daysBack);

		const params = new URLSearchParams({
			pubStartDate: startDate.toISOString(),
			pubEndDate: new Date().toISOString(),
			resultsPerPage: String(MAX_RESULTS_PER_PAGE),
		});

		if (this.apiKey) {
			params.set("apiKey", this.apiKey);
		}

		return params;
	}

	private parseEntries(vulnerabilities: Array<{ cve: NvdCve }>): CveEntry[] {
		return vulnerabilities.map((v) => {
			const cve = v.cve;
			const metrics = cve.metrics?.cvssMetricV31?.[0] ?? cve.metrics?.cvssMetricV30?.[0];

			return {
				id: cve.id,
				severity: this.normalizeSeverity(metrics?.cvssData?.baseSeverity),
				cvssScore: metrics?.cvssData?.baseScore ?? 5.0,
				description: cve.descriptions?.[0]?.value ?? "",
				published: cve.published,
				modified: cve.lastModified,
				affectedProducts: this.extractProducts(cve.configurations ?? []),
				references: (cve.references ?? []).map((r) => r.url),
				cweIds: this.extractCweIds(cve.weaknesses ?? []),
			};
		});
	}

	private extractCweIds(weaknesses: Array<{ description?: Array<{ value: string }> }>): string[] {
		const ids: string[] = [];
		for (const w of weaknesses) {
			const value = w.description?.[0]?.value;
			if (value) ids.push(value);
		}
		return ids;
	}

	private isAiAgentRelated(cve: CveEntry): boolean {
		const text = `${cve.description} ${cve.affectedProducts.join(" ")}`.toLowerCase();
		return AI_AGENT_KEYWORDS.some((keyword) => text.includes(keyword.toLowerCase()));
	}

	private calculateMatch(cve: CveEntry, toolText: string): CveMatch {
		const matchedKeywords: string[] = [];
		let confidence = 0;

		for (const keyword of AI_AGENT_KEYWORDS) {
			const lowerKeyword = keyword.toLowerCase();
			if (cve.description.toLowerCase().includes(lowerKeyword) && toolText.includes(lowerKeyword)) {
				matchedKeywords.push(keyword);
				confidence += 0.2;
			}
		}

		for (const product of cve.affectedProducts) {
			if (toolText.includes(product.toLowerCase())) {
				confidence += 0.3;
			}
		}

		return {
			cve,
			confidence: Math.min(confidence, 1.0),
			matchedKeywords,
			recommendation: this.buildRecommendation(cve),
		};
	}

	private normalizeSeverity(severity: string | undefined): CveEntry["severity"] {
		const upper = (severity ?? "MEDIUM").toUpperCase();
		if (upper === "CRITICAL") return "critical";
		if (upper === "HIGH") return "high";
		if (upper === "LOW") return "low";
		return "medium";
	}

	private extractProducts(configs: Array<{ nodes?: unknown[] }>): string[] {
		const products = new Set<string>();

		for (const config of configs) {
			const nodes = config.nodes ?? [];
			for (const node of nodes) {
				const matches = (node as { cpeMatch?: Array<{ criteria?: string }> })?.cpeMatch ?? [];
				for (const match of matches) {
					const criteria = match.criteria;
					if (criteria) {
						const parts = criteria.split(":");
						if (parts.length >= 4 && parts[3]) {
							products.add(parts[3]);
						}
					}
				}
			}
		}

		return [...products];
	}

	private buildRecommendation(cve: CveEntry): string {
		const parts: string[] = [];

		if (cve.severity === "critical") parts.push("URGENT: Immediate remediation required");
		else if (cve.severity === "high") parts.push("HIGH: Remediate within 24 hours");

		if (cve.affectedProducts.length > 0) {
			parts.push(`Affected: ${cve.affectedProducts.slice(0, 3).join(", ")}`);
		}

		return parts.join(" | ") || "Review and assess impact";
	}

	private async saveToCache(cves: CveEntry[]): Promise<void> {
		try {
			await atomicWriteJson(this.cachePath, {
				timestamp: new Date().toISOString(),
				cves,
			});
		} catch (error) {
			this.logger.warn("Failed to cache NVD results", { error: String(error) });
		}
	}

	private async loadFromCache(): Promise<CveEntry[]> {
		try {
			const content = await getFileContent(this.cachePath);
			const cache = JSON.parse(content) as { timestamp: string; cves: CveEntry[] };

			const age = Date.now() - new Date(cache.timestamp).getTime();
			if (age > this.cacheTtlMs) {
				this.logger.warn("NVD cache expired");
				return [];
			}

			this.logger.info(`Loaded ${cache.cves.length} CVEs from cache`);
			return cache.cves;
		} catch {
			return [];
		}
	}
}
