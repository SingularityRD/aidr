import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

/**
 * Sensitivity level assigned to classified content.
 * - public: Safe for public disclosure
 * - internal: Safe within the organization
 * - confidential: Sensitive, limited distribution
 * - restricted: Highly sensitive, strict need-to-know
 */
export type SensitivityLevel = "public" | "internal" | "confidential" | "restricted";

/**
 * Category of content identified by the classifier.
 */
export type ContentCategory =
	| "source_code"
	| "configuration"
	| "credentials"
	| "intellectual_property"
	| "database"
	| "binary"
	| "documentation"
	| "unknown";

/**
 * Result of classifying a single file path and its content.
 */
export interface ContentClassification {
	/** The file path that was classified */
	filePath: string;
	/** The detected content category */
	category: ContentCategory;
	/** The assigned sensitivity level */
	sensitivity: SensitivityLevel;
	/** Confidence score between 0 and 1 */
	confidence: number;
	/** Human-readable reasons that triggered this classification */
	indicators: string[];
}

/**
 * Configuration options for the ContentClassifier.
 */
export interface ContentClassifierConfig {
	/**
	 * Enable content scanning in addition to extension matching.
	 * @default true
	 */
	enableContentScanning: boolean;
	/**
	 * Minimum confidence threshold (0–1) for returning a result.
	 * @default 0.5
	 */
	confidenceThreshold: number;
	/**
	 * Custom extension overrides per category.
	 * These are merged with the built-in extension maps.
	 */
	customExtensions?: Partial<Record<ContentCategory, string[]>>;
}

/** @internal Default configuration used when no config is provided. */
const DEFAULT_CONFIG: ContentClassifierConfig = {
	enableContentScanning: true,
	confidenceThreshold: 0.5,
};

/** @internal Mapping from file extension to content category. */
const EXTENSION_MAP: ReadonlyMap<string, ContentCategory> = new Map([
	// Source Code
	[".js", "source_code"],
	[".ts", "source_code"],
	[".py", "source_code"],
	[".java", "source_code"],
	[".go", "source_code"],
	[".rs", "source_code"],
	[".c", "source_code"],
	[".cpp", "source_code"],
	[".h", "source_code"],
	[".hpp", "source_code"],
	[".cs", "source_code"],
	[".rb", "source_code"],
	[".php", "source_code"],
	[".swift", "source_code"],
	[".kt", "source_code"],
	[".scala", "source_code"],
	[".wasm", "source_code"],
	// Configuration
	[".env", "configuration"],
	[".json", "configuration"],
	[".yaml", "configuration"],
	[".yml", "configuration"],
	[".toml", "configuration"],
	[".ini", "configuration"],
	[".cfg", "configuration"],
	[".conf", "configuration"],
	[".config", "configuration"],
	// Database
	[".db", "database"],
	[".sqlite", "database"],
	[".sqlite3", "database"],
	[".sql", "database"],
	[".dbf", "database"],
	[".mdb", "database"],
	// Binary
	[".exe", "binary"],
	[".dll", "binary"],
	[".so", "binary"],
	[".dylib", "binary"],
	[".bin", "binary"],
	[".obj", "binary"],
	[".o", "binary"],
	[".class", "binary"],
	[".pyc", "binary"],
	// Documentation
	[".md", "documentation"],
	[".txt", "documentation"],
	[".doc", "documentation"],
	[".docx", "documentation"],
	[".pdf", "documentation"],
	[".rst", "documentation"],
	[".wiki", "documentation"],
]);

/** @internal Sensitivity mapping per category (overridden by content analysis). */
const CATEGORY_SENSITIVITY: ReadonlyMap<ContentCategory, SensitivityLevel> = new Map([
	["source_code", "internal"],
	["configuration", "confidential"],
	["credentials", "restricted"],
	["intellectual_property", "confidential"],
	["database", "confidential"],
	["binary", "internal"],
	["documentation", "public"],
	["unknown", "public"],
]);

/** @internal Content patterns that indicate credential files. */
const CREDENTIAL_PATTERNS: readonly { regex: RegExp; label: string; weight: number }[] = [
	{ regex: /password\s*[=:]\s*\S+/i, label: "contains password assignment", weight: 0.9 },
	{
		regex: /(?:api[_-]?key|apikey)\s*[=:]\s*\S+/i,
		label: "contains API key assignment",
		weight: 0.9,
	},
	{
		regex: /(?:secret|token)\s*[=:]\s*\S+/i,
		label: "contains secret/token assignment",
		weight: 0.85,
	},
	{
		regex: /BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY/,
		label: "contains private key block",
		weight: 1.0,
	},
	{
		regex: /(?:aws_access_key_id|aws_secret_access_key)\s*=/,
		label: "contains AWS credential",
		weight: 1.0,
	},
	{
		regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
		label: "contains GitHub token",
		weight: 1.0,
	},
	{
		regex: /(?:https?:\/\/)?[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+/,
		label: "contains URL-embedded credentials",
		weight: 0.8,
	},
	{
		regex: /(?:sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]+/,
		label: "contains Stripe key",
		weight: 0.95,
	},
	{ regex: /(?:xox[abposr]-)[A-Za-z0-9-]+/, label: "contains Slack token", weight: 0.95 },
	{ regex: /(?:-----BEGIN\s+CERTIFICATE-----)/, label: "contains certificate block", weight: 0.7 },
];

/** @internal Content patterns that indicate intellectual property. */
const IP_PATTERNS: readonly { regex: RegExp; label: string; weight: number }[] = [
	{
		regex: /copyright\s+(?:©\s*)?(?:\d{4}\s+)?(?:by\s+)?[\w\s,.]+/i,
		label: "contains copyright notice",
		weight: 0.7,
	},
	{ regex: /all\s+rights\s+reserved/i, label: "contains all rights reserved", weight: 0.6 },
	{
		regex: /proprietary\s+(?:and\s+)?confidential/i,
		label: "contains proprietary notice",
		weight: 0.8,
	},
	{
		regex: /confidential\s+(?:and\s+)?proprietary/i,
		label: "contains confidential notice",
		weight: 0.8,
	},
	{ regex: /trade\s*(?:-|\s)?secret/i, label: "contains trade secret notice", weight: 0.85 },
	{ regex: /patent(?:ed| pending)/i, label: "contains patent notice", weight: 0.6 },
	{
		regex: /pat\.?\s*(?:pending|no\.?\s*[\d,]+)/i,
		label: "contains patent reference",
		weight: 0.5,
	},
	{ regex: /license\s+terms/i, label: "contains license terms reference", weight: 0.4 },
	{
		regex: /\d{4}\s+[\w\s]+\.\s+All\s+rights\s+reserved\./,
		label: "contains formal copyright line",
		weight: 0.75,
	},
];

/**
 * Normalizes a file extension to lowercase with a leading dot.
 * Returns an empty string if the input has no extension.
 */
function normalizeExtension(filePath: string): string {
	const dotIndex = filePath.lastIndexOf(".");
	if (dotIndex < 0) return "";
	return filePath.slice(dotIndex).toLowerCase();
}

/**
 * Determines whether the given file path likely refers to a binary file
 * by checking for non-printable characters.
 */
function hasBinaryContent(content: string): boolean {
	const sample = content.slice(0, 4096);
	for (let i = 0; i < sample.length; i++) {
		const code = sample.charCodeAt(i);
		// Unicode text is printable; only binary control characters indicate binary data.
		const isWhitespace = code === 0x09 || code === 0x0a || code === 0x0d;
		if ((code < 0x20 || code === 0x7f) && !isWhitespace) return true;
	}
	return false;
}

/**
 * Classifies files by their extension and optionally by their content.
 *
 * Detects source code, configuration files, credentials,
 * intellectual property, database files, binaries, and documentation.
 */
export class ContentClassifier {
	private readonly config: ContentClassifierConfig;
	private readonly logger: Logger;
	private readonly extensionMap: Map<string, ContentCategory>;

	/**
	 * Creates a new ContentClassifier.
	 *
	 * @param config - Optional configuration overrides.
	 * @param logger - Optional logger instance.
	 */
	constructor(config: Partial<ContentClassifierConfig> = {}, logger: Logger = nullLogger) {
		this.config = { ...DEFAULT_CONFIG, ...config };
		this.logger = logger;

		// Build extension map with optional custom overrides
		this.extensionMap = new Map(EXTENSION_MAP);
		if (this.config.customExtensions) {
			for (const [category, extensions] of Object.entries(this.config.customExtensions)) {
				if (extensions) {
					for (const ext of extensions) {
						this.extensionMap.set(ext.toLowerCase(), category as ContentCategory);
					}
				}
			}
		}
	}

	/**
	 * Classifies a file given its path and optional content.
	 *
	 * Uses file extension as the primary signal, then deepens the
	 * classification with content analysis when available.
	 *
	 * @param filePath - Absolute or relative path to the file.
	 * @param content - Optional file content for deeper analysis.
	 * @returns A {@link ContentClassification} result.
	 */
	classify(filePath: string, content?: string): ContentClassification {
		if (!filePath) {
			return {
				filePath: "",
				category: "unknown",
				sensitivity: "public",
				confidence: 0,
				indicators: ["empty file path provided"],
			};
		}

		const indicators: string[] = [];
		const ext = normalizeExtension(filePath);

		// 1. Extension-based classification
		let category: ContentCategory = "unknown";
		let extConfidence = 0.6;

		if (ext) {
			const mappedCategory = this.extensionMap.get(ext);
			if (mappedCategory) {
				category = mappedCategory;
				extConfidence = 0.8;
				indicators.push(`file extension .${ext.slice(1)} maps to ${mappedCategory}`);
			}
		}

		// 2. Content-based refinement
		let contentConfidence = 0;
		if (content !== undefined && this.config.enableContentScanning) {
			if (content.length === 0) {
				indicators.push("file content is empty");
			} else {
				const contentResult = this.analyzeContent(content, ext);
				if (contentResult) {
					category = contentResult.category;
					contentConfidence = contentResult.confidence;
					indicators.push(...contentResult.indicators);
				}
			}
		}

		// 3. Binary content check (overrides extension-based for mislabeled files)
		if (content !== undefined && this.config.enableContentScanning && category !== "binary") {
			const binaryCheck = this.checkBinaryContent(filePath, ext, content);
			if (binaryCheck) {
				category = binaryCheck.category;
				contentConfidence = binaryCheck.confidence;
				indicators.push(...binaryCheck.indicators);
			}
		}

		// Compute final confidence
		const confidence =
			content !== undefined && this.config.enableContentScanning
				? Math.max(extConfidence, contentConfidence)
				: extConfidence;

		// Determine sensitivity level
		const sensitivity = this.determineSensitivity(category, content);

		// Apply confidence threshold
		if (confidence < this.config.confidenceThreshold) {
			this.logger.debug(`Classification below threshold for ${filePath}`, {
				confidence,
				threshold: this.config.confidenceThreshold,
			});
			return {
				filePath,
				category: "unknown",
				sensitivity: "public",
				confidence,
				indicators: [
					`confidence ${confidence.toFixed(2)} below threshold ${this.config.confidenceThreshold}`,
				],
			};
		}

		return {
			filePath,
			category,
			sensitivity,
			confidence,
			indicators,
		};
	}

	/**
	 * Classifies multiple files in a single call.
	 *
	 * @param entries - Array of { filePath, content? } objects.
	 * @returns Array of {@link ContentClassification} results.
	 */
	classifyBatch(entries: { filePath: string; content?: string }[]): ContentClassification[] {
		return entries.map((entry) => this.classify(entry.filePath, entry.content));
	}

	/**
	 * Analyzes file content to refine the category.
	 * Returns null if content analysis doesn't change the classification.
	 */
	private analyzeContent(
		content: string,
		ext: string,
	): { category: ContentCategory; confidence: number; indicators: string[] } | null {
		// Check credentials patterns first (highest priority)
		const credScore = this.matchPatterns(content, CREDENTIAL_PATTERNS);
		if (credScore.score >= 0.5) {
			return {
				category: "credentials",
				confidence: credScore.score,
				indicators: credScore.labels,
			};
		}

		// Check intellectual property patterns
		const ipScore = this.matchPatterns(content, IP_PATTERNS);
		if (ipScore.score >= 0.5) {
			return {
				category: "intellectual_property",
				confidence: ipScore.score,
				indicators: ipScore.labels,
			};
		}

		// Refine source code vs configuration vs documentation based on content
		if (ext && this.extensionMap.has(ext)) {
			const extCategory = this.extensionMap.get(ext);
			if (extCategory === "documentation" || extCategory === "configuration") {
				return null; // Extension is sufficient
			}
		}

		return null;
	}

	/**
	 * Checks if content is binary for files that might be mislabeled.
	 */
	private checkBinaryContent(
		filePath: string,
		ext: string,
		content: string,
	): { category: ContentCategory; confidence: number; indicators: string[] } | null {
		// Skip files that are expected to be binary by extension
		if (this.extensionMap.get(ext) === "binary") return null;

		if (content.length > 0 && hasBinaryContent(content)) {
			return {
				category: "binary",
				confidence: 0.9,
				indicators: ["content contains null bytes or non-ASCII characters"],
			};
		}

		return null;
	}

	/**
	 * Scores content against a set of regex patterns and collects labels.
	 */
	private matchPatterns(
		content: string,
		patterns: readonly { regex: RegExp; label: string; weight: number }[],
	): { score: number; labels: string[] } {
		let maxScore = 0;
		const labels: string[] = [];

		for (const pattern of patterns) {
			if (pattern.regex.test(content)) {
				if (pattern.weight > maxScore) {
					maxScore = pattern.weight;
				}
				labels.push(pattern.label);
			}
		}

		return { score: maxScore, labels };
	}

	/**
	 * Determines the sensitivity level for a classified item.
	 * Sensitivity may be upgraded based on content analysis.
	 */
	private determineSensitivity(category: ContentCategory, content?: string): SensitivityLevel {
		const baseSensitivity = CATEGORY_SENSITIVITY.get(category) ?? "public";

		if (!content) return baseSensitivity;

		// Upgrade sensitivity if credentials or IP content is detected
		if (!this.config.enableContentScanning) return baseSensitivity;

		const credScore = this.matchPatterns(content, CREDENTIAL_PATTERNS);
		if (credScore.score >= 0.7) {
			return "restricted";
		}

		const ipScore = this.matchPatterns(content, IP_PATTERNS);
		if (ipScore.score >= 0.7) {
			return "confidential";
		}

		return baseSensitivity;
	}
}
