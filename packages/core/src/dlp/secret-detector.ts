/**
 * Secret Detection Module
 *
 * Detects exposed secrets, tokens, and credentials in text content
 * using regex patterns with named capture groups and entropy-based
 * false positive reduction.
 *
 * Supported secret types:
 * - AWS Access Keys (AKIA...)
 * - AWS Secret Keys (40-char base64)
 * - GitHub Tokens (ghp_/gho_/ghs_/ghr_)
 * - GitLab Tokens (glpat-)
 * - Slack Tokens (xoxb-/xoxp-/xoxa-)
 * - npm Tokens (npm_)
 * - Private Keys (RSA/DSA/EC)
 * - Generic API Keys
 * - Environment Variable Secrets
 */

import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

// ── Types ────────────────────────────────────────────────────────────

/**
 * Supported secret types for detection.
 */
export type SecretType =
	| "aws_access_key"
	| "aws_secret_key"
	| "github_token"
	| "gitlab_token"
	| "slack_token"
	| "npm_token"
	| "private_key"
	| "generic_api_key"
	| "env_secret";

/**
 * Severity level for a detected secret.
 */
export type SecretSeverity = "low" | "medium" | "high" | "critical";

/**
 * Metadata for a single detected secret match.
 */
export interface SecretMatch {
	/** The type of secret detected */
	type: SecretType;
	/** The matched secret value (from named group where applicable) */
	value: string;
	/** Surrounding context text (up to 50 chars before and after the match) */
	context: string;
	/** Character index in the source content */
	index: number;
	/** Shannon entropy of the matched value */
	entropy: number;
	/** Risk score from 0–100 */
	riskScore: number;
	/** Confidence level from 0.0–1.0 */
	confidence: number;
}

/**
 * Configuration options for the SecretDetector.
 */
export interface SecretDetectorConfig {
	/**
	 * Minimum Shannon entropy threshold.
	 * Matches below this threshold are discarded for non-specific patterns.
	 * @default 3.5
	 */
	entropyThreshold?: number;
	/**
	 * Minimum secret length to consider.
	 * @default 8
	 */
	minLength?: number;
	/** Logger instance (defaults to nullLogger) */
	logger?: Logger;
}

// ── Constants ────────────────────────────────────────────────────────

/** Number of characters to capture on each side of a match for context. */
const CONTEXT_WINDOW = 50;

/** Default entropy threshold used when not specified in config. */
const DEFAULT_ENTROPY_THRESHOLD = 3.5;

/** Default minimum secret length used when not specified in config. */
const DEFAULT_MIN_LENGTH = 8;

// ── Pattern definitions ──────────────────────────────────────────────

interface SecretPattern {
	/** Compiled regex with named groups where applicable */
	pattern: RegExp;
	/** Secret type identifier */
	type: SecretType;
	/** Severity level for this secret pattern */
	severity: SecretSeverity;
	/** Human-readable pattern name */
	name: string;
	/**
	 * Optional value validator.
	 * Called after extraction to perform additional validation on the
	 * candidate secret value before accepting the match.
	 * Return `true` to accept, `false` to discard.
	 */
	validate?: (value: string) => boolean;
}

/**
 * Secret detection patterns.
 *
 * Each pattern uses named capture groups for clarity:
 * - `value` – the extracted secret value
 * - `key`   – the variable/key name (for generic patterns)
 * - `keyType` – the key algorithm (for private keys)
 */
const SECRET_PATTERNS: readonly SecretPattern[] = Object.freeze([
	{
		type: "aws_access_key",
		pattern: /\b(?<value>AKIA[0-9A-Z]{16})\b/g,
		severity: "critical",
		name: "AWS Access Key ID",
	},
	{
		type: "aws_secret_key",
		pattern:
			/(?:(?:aws\s*(?:_|)\s*(?:secret|access|key)\s*[:=]\s*['"]?)?)(?<value>[0-9a-zA-Z\/+=]{40})\b/gi,
		severity: "critical",
		name: "AWS Secret Access Key",
		// Require at least one base64 special char to avoid matching
		// arbitrary 40-char alphanumeric strings (e.g. substrings of tokens).
		validate: (value: string): boolean => /[\/+=]/.test(value),
	},
	{
		type: "github_token",
		pattern: /\b(?<value>gh[psor]_[0-9a-zA-Z]{36,})\b/g,
		severity: "critical",
		name: "GitHub Token",
	},
	{
		type: "gitlab_token",
		pattern: /\b(?<value>glpat-[0-9a-zA-Z_-]{20,})\b/g,
		severity: "critical",
		name: "GitLab Token",
	},
	{
		type: "slack_token",
		pattern: /\b(?<value>xox[baprs]-[0-9a-zA-Z]{10,})\b/g,
		severity: "critical",
		name: "Slack Token",
	},
	{
		type: "npm_token",
		pattern: /\b(?<value>npm_[0-9a-zA-Z]{36,})\b/g,
		severity: "critical",
		name: "npm Token",
	},
	{
		type: "private_key",
		pattern: /(?<value>-----BEGIN\s+(?<keyType>RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----)/g,
		severity: "critical",
		name: "Private Key",
	},
	{
		type: "generic_api_key",
		pattern:
			/(?:(?<key>api[_-]?(?:key|secret)|apikey)\s*[:=]\s*['"]?(?<value>[a-zA-Z0-9_\-.]{16,64})['"]?)/gi,
		severity: "high",
		name: "Generic API Key",
	},
	{
		type: "env_secret",
		pattern:
			/\b(?:(?<key>SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\s*=\s*['"]?(?<value>[a-zA-Z0-9_!@#$%^&*()]{12,})['"]?)\b/gi,
		severity: "high",
		name: "Environment Variable Secret",
	},
]);

/**
 * Secret types whose regex patterns are specific enough to
 * skip entropy-based filtering.  These patterns have distinctive
 * prefixes (e.g. `AKIA`, `ghp_`, `glpat-`, `xoxb-`) that make
 * false positives extremely unlikely.
 */
const SPECIFIC_TYPES: ReadonlySet<SecretType> = new Set([
	"aws_access_key",
	"github_token",
	"gitlab_token",
	"slack_token",
	"npm_token",
	"private_key",
]);

// ── SecretDetector class ─────────────────────────────────────────────

/**
 * Detects exposed secrets, tokens, and credentials in text content.
 *
 * Uses a combination of regex pattern matching with named capture
 * groups and Shannon entropy calculation to balance detection rate
 * with false positive reduction.
 *
 * @example
 * ```ts
 * const detector = new SecretDetector({ entropyThreshold: 4.0 });
 * const matches = detector.detect("aws key = AKIAIOSFODNN7EXAMPLE");
 * console.log(matches[0].value); // "AKIAIOSFODNN7EXAMPLE"
 * ```
 */
export class SecretDetector {
	private readonly entropyThreshold: number;
	private readonly minLength: number;
	private readonly logger: Logger;

	/**
	 * @param config - Optional configuration overrides
	 */
	constructor(config: SecretDetectorConfig = {}) {
		this.entropyThreshold = config.entropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;
		this.minLength = config.minLength ?? DEFAULT_MIN_LENGTH;
		this.logger = config.logger ?? nullLogger;
	}

	// ── Public API ──────────────────────────────────────────────────

	/**
	 * Scan `content` for exposed secrets.
	 *
	 * Iterates all registered secret patterns, collects matches with
	 * metadata (entropy, confidence, risk score), and returns them
	 * sorted by position in the source content.
	 *
	 * @param content - The text content to scan
	 * @returns Array of detected {@link SecretMatch} instances
	 */
	detect(content: string): SecretMatch[] {
		const matches = [...this.scan(content)];

		// Sort matches by position in source content
		matches.sort((a, b) => a.index - b.index);

		// Deduplicate overlapping matches (same index and value)
		const deduplicated = this.deduplicateMatches(matches);

		this.logger.debug(`SecretDetector: found ${deduplicated.length} unique match(es)`);
		return deduplicated;
	}

	/**
	 * Lazily yield matches pattern by pattern, in pattern order and neither
	 * sorted nor deduplicated. A caller that only needs to know whether a secret
	 * exists can stop after the first match without running the remaining
	 * patterns. `types` restricts the scan to those secret types.
	 */
	*scan(content: string, types?: ReadonlySet<SecretType>): Generator<SecretMatch> {
		for (const secretPattern of SECRET_PATTERNS) {
			if (types && !types.has(secretPattern.type)) continue;
			yield* this.matchPattern(content, secretPattern);
		}
	}

	/**
	 * Remove duplicate matches that share the same index and value.
	 * Different pattern types can match the same content (e.g. both
	 * `generic_api_key` and `env_secret` matching "SECRET=...").
	 * The first match (highest precedence in the patterns array) wins.
	 */
	private deduplicateMatches(matches: SecretMatch[]): SecretMatch[] {
		const seen = new Set<string>();
		const result: SecretMatch[] = [];

		for (const match of matches) {
			const key = `${match.index}:${match.value}`;
			if (!seen.has(key)) {
				seen.add(key);
				result.push(match);
			}
		}

		return result;
	}

	// ── Private helpers ─────────────────────────────────────────────

	/**
	 * Run a single pattern against content and produce SecretMatch entries.
	 */
	private *matchPattern(content: string, secretPattern: SecretPattern): Generator<SecretMatch> {
		// Clone regex to reset lastIndex
		const regex = new RegExp(secretPattern.pattern.source, secretPattern.pattern.flags);
		let match: RegExpExecArray | null;

		while ((match = regex.exec(content)) !== null) {
			const value = this.extractValue(match);

			if (value.length < this.minLength) {
				continue;
			}

			// Run optional value validator (e.g. for base64 special char check)
			if (secretPattern.validate && !secretPattern.validate(value)) {
				continue;
			}

			const entropy = this.calculateShannonEntropy(value);

			// Discard low-entropy matches for non-specific patterns
			if (!SPECIFIC_TYPES.has(secretPattern.type) && entropy < this.entropyThreshold) {
				continue;
			}

			const confidence = this.calculateConfidence(secretPattern.type, entropy, value);
			const context = this.extractContext(content, match.index, value.length);
			const riskScore = this.calculateRiskScore(secretPattern.severity, entropy, confidence);

			yield {
				type: secretPattern.type,
				value,
				context,
				index: match.index,
				entropy,
				riskScore,
				confidence,
			};
		}
	}

	/**
	 * Extract the secret value from a regex match, respecting named groups.
	 *
	 * Priority order:
	 * 1. Named group `value` (used by patterns with surrounding key-name context)
	 * 2. First capture group (fallback)
	 * 3. Full match (bare patterns with no capture groups)
	 */
	private extractValue(match: RegExpExecArray): string {
		if (match.groups?.value !== undefined) {
			return match.groups.value;
		}
		if (match[1] !== undefined) {
			return match[1];
		}
		return match[0];
	}

	/**
	 * Build a context string around a match position.
	 *
	 * Captures up to {@link CONTEXT_WINDOW} characters before and after
	 * the matched value, with `...` ellipsis markers at truncation points.
	 */
	private extractContext(content: string, index: number, valueLength: number): string {
		const start = Math.max(0, index - CONTEXT_WINDOW);
		const end = Math.min(content.length, index + valueLength + CONTEXT_WINDOW);
		const before = content.slice(start, index);
		const after = content.slice(index + valueLength, end);

		let context = "";
		if (start > 0) {
			context += "...";
		}
		context += before;
		context += after;
		if (end < content.length) {
			context += "...";
		}

		return context;
	}

	/**
	 * Calculate the Shannon entropy of a string.
	 *
	 * Higher entropy indicates a more random-looking string, which is
	 * characteristic of generated secrets versus natural language.
	 *
	 * @param str - The string to analyse
	 * @returns Entropy value in bits per symbol
	 */
	private calculateShannonEntropy(str: string): number {
		const charCounts = new Map<string, number>();

		for (const char of str) {
			charCounts.set(char, (charCounts.get(char) || 0) + 1);
		}

		let entropy = 0;
		const len = str.length;

		for (const count of charCounts.values()) {
			const probability = count / len;
			entropy -= probability * Math.log2(probability);
		}

		return Math.round(entropy * 100) / 100;
	}

	/**
	 * Calculate confidence level (0.0–1.0) for a match.
	 *
	 * - Specific/tagged patterns (AWS key, GitHub token, etc.) get
	 *   a fixed high confidence because their prefixes are distinctive.
	 * - Generic patterns (env vars, generic API keys) derive confidence
	 *   from entropy ratio and value length.
	 */
	private calculateConfidence(type: SecretType, entropy: number, value: string): number {
		if (SPECIFIC_TYPES.has(type)) {
			return 0.95;
		}

		// For generic patterns, use entropy as a confidence signal.
		// Max realistic Shannon entropy for printable ASCII is ~6.5 bits/symbol.
		const entropyRatio = Math.min(1, entropy / 6);
		const lengthRatio = Math.min(1, value.length / 32);

		return Number((0.5 + entropyRatio * 0.3 + lengthRatio * 0.2).toFixed(2));
	}

	/**
	 * Calculate risk score (0–100) for a match.
	 *
	 * Combines the base severity rating with entropy bonus and
	 * confidence multiplier to produce a single actionable score.
	 */
	private calculateRiskScore(
		severity: SecretSeverity,
		entropy: number,
		confidence: number,
	): number {
		const severityBase: Record<SecretSeverity, number> = {
			low: 20,
			medium: 40,
			high: 60,
			critical: 80,
		};

		const base = severityBase[severity];
		const entropyBonus = Math.min(20, Math.round(entropy * 3));
		const confidenceMultiplier = 0.5 + confidence * 0.5;

		return Math.min(100, Math.round((base + entropyBonus) * confidenceMultiplier));
	}
}
