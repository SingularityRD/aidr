/**
 * PII Detector — DLP module for detecting personally identifiable information.
 *
 * Provides class-based detection with configurable patterns, confidence scoring
 * via Shannon entropy, and Zod-schema-validated configuration.
 *
 * @module dlp/pii-detector
 */

import { z } from "zod";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

// ── Zod Schemas ─────────────────────────────────────────────────────────

/** Supported PII type identifiers. */
export const PiiTypeSchema = z.enum([
	"ssn",
	"credit_card",
	"email",
	"phone",
	"ip_address",
	"aws_key",
	"api_key",
]);

/** Severity levels for detected PII. */
export const PiiSeveritySchema = z.enum(["low", "medium", "high", "critical"]);

/** Schema for a single PII match result. */
export const PiiMatchSchema = z.object({
	type: PiiTypeSchema,
	value: z.string(),
	start: z.number().int().nonnegative(),
	end: z.number().int().nonnegative(),
	confidence: z.number().min(0).max(1),
	severity: PiiSeveritySchema,
});

/** Schema for PII detector configuration (all fields optional with defaults). */
export const PiiDetectorConfigSchema = z.object({
	enableSsn: z.boolean().optional().default(true),
	enableCreditCard: z.boolean().optional().default(true),
	enableEmail: z.boolean().optional().default(true),
	enablePhone: z.boolean().optional().default(true),
	enableIpAddress: z.boolean().optional().default(true),
	enableAwsKey: z.boolean().optional().default(true),
	enableApiKey: z.boolean().optional().default(true),
	minConfidence: z.number().min(0).max(1).optional().default(0.5),
	entropyThreshold: z.number().min(0).max(8).optional().default(4.5),
});

// ── Inferred Types ──────────────────────────────────────────────────────

/** Supported PII type discriminator. */
export type PiiType = z.infer<typeof PiiTypeSchema>;

/**
 * A single PII match found in input text.
 *
 * @property type - Categorised PII type (ssn, credit_card, …).
 * @property value - The matched raw string.
 * @property start - Character offset where the match begins.
 * @property end - Character offset where the match ends (exclusive).
 * @property confidence - Score between 0 and 1 indicating how likely this is genuine PII.
 * @property severity - Semantic severity of the exposed data.
 */
export interface PiiMatch {
	readonly type: PiiType;
	readonly value: string;
	readonly start: number;
	readonly end: number;
	readonly confidence: number;
	readonly severity: "low" | "medium" | "high" | "critical";
}

/**
 * Configuration options for the PII detector.
 * All flags default to `true` — opt *out* of types you do not need.
 */
export type PiiDetectorConfig = z.infer<typeof PiiDetectorConfigSchema>;

/**
 * Public interface for PII detection.
 * Implementations must be safe to call concurrently.
 */
export interface PiiDetector {
	/**
	 * Scan `input` and return all PII matches that exceed `minConfidence`.
	 * Results are sorted by start position.
	 */
	detect(input: string): PiiMatch[];

	/**
	 * Convenience check — returns `true` when **at least one** PII match is found.
	 * Internally obeys the same thresholds as `detect()`.
	 */
	containsPii(input: string): boolean;
}

// ── Internal Pattern Definitions ────────────────────────────────────────

/** Internal descriptor for a single detection pattern. */
interface PatternDef {
	readonly type: PiiType;
	readonly regex: RegExp;
	readonly severity: "low" | "medium" | "high" | "critical";
	readonly confidenceBase: number;
	/** Optional post-match validation (e.g. Luhn check). */
	readonly validate?: (value: string) => boolean;
}

const PATTERNS: readonly PatternDef[] = Object.freeze([
	// ── SSN ──────────────────────────────────────────────────────────────
	{
		type: "ssn",
		// Reject known-invalid prefixes: 000, 666, 900–999 in group one;
		// reject 00 in group two and 0000 in the serial.
		regex: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
		severity: "critical",
		confidenceBase: 0.85,
	},

	// ── Credit / Debit Card ─────────────────────────────────────────────
	{
		type: "credit_card",
		// Matches 13–19 digits optionally separated by spaces, dashes, or dots.
		// Post-match Luhn validation separates genuine card numbers from noise.
		regex: /\b(?:\d[ -.]*?){13,19}\b/g,
		severity: "critical",
		confidenceBase: 0.8,
		validate: luhnCheck,
	},

	// ── Email ────────────────────────────────────────────────────────────
	{
		type: "email",
		// RFC 5322 simplified — covers the vast majority of real-world addresses.
		regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
		severity: "high",
		confidenceBase: 0.9,
	},

	// ── Phone Number (US / International) ────────────────────────────────
	{
		type: "phone",
		// Supports: +1 (555) 123-4567, 555-123-4567, +44 20 7946 0958, etc.
		// Validate callback ensures total digit count is 7–15 (E.164 range).
		regex:
			/\b(?:\+?\d{1,3}[-\s.]?)?\(?\d{2,4}\)?[-\s.]?\d{2,4}[-\s.]?\d{3,5}(?:\s?(?:x|ext\.?)\d{1,5})?\b/g,
		severity: "high",
		confidenceBase: 0.75,
		validate: (value: string): boolean => {
			const digits = value.replace(/\D/g, "");
			return digits.length >= 7 && digits.length <= 15;
		},
	},

	// ── IP Address (IPv4 + IPv6) ────────────────────────────────────────
	{
		type: "ip_address",
		// IPv4 + IPv6 (all common compressed forms).
		// Patterns starting with `:` use (?<!\w) instead of \b because
		// \b does not separate two non-word characters (e.g. space → colon).
		regex:
			/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}(?::|\b)|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|(?:[0-9a-fA-F]{1,4}:){1}(?::[0-9a-fA-F]{1,4}){1,6}\b|(?<!\w):(?::[0-9a-fA-F]{1,4}){1,7}\b|(?<!\w)::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
		severity: "medium",
		confidenceBase: 0.8,
	},

	// ── AWS Access Key ──────────────────────────────────────────────────
	{
		type: "aws_key",
		// AKIA + 16 uppercase alphanumeric characters.
		regex: /\bAKIA[0-9A-Z]{16}\b/g,
		severity: "critical",
		confidenceBase: 0.95,
	},

	// ── Generic API Key ─────────────────────────────────────────────────
	{
		type: "api_key",
		// Catches common prefixes: sk-, pk-, test-, prod-, etc.
		// Requires a minimum length of 20 characters after the prefix.
		regex: /\b(?:sk|pk|test|prod|live|sandbox)[-_]?[a-zA-Z0-9_-]{20,}\b/gi,
		severity: "critical",
		confidenceBase: 0.7,
	},
]);

// ── Luhn Check (Credit Card Validation) ─────────────────────────────────

/**
 * Validates a numeric string using the Luhn algorithm (ISO/IEC 7812).
 * Strips non-digit characters before checking.
 *
 * @param value - Raw credit-card candidate string.
 * @returns `true` when the check digit passes.
 */
export function luhnCheck(value: string): boolean {
	const digits = value.replace(/\D/g, "");
	if (digits.length < 13 || digits.length > 19) return false;

	let sum = 0;
	let alternate = false;

	for (let i = digits.length - 1; i >= 0; i--) {
		let n = Number.parseInt(digits.charAt(i), 10);
		if (Number.isNaN(n)) return false;
		if (alternate) {
			n *= 2;
			if (n > 9) n -= 9;
		}
		sum += n;
		alternate = !alternate;
	}

	return sum % 10 === 0;
}

// ── Shannon Entropy ─────────────────────────────────────────────────────

/**
 * Calculates the Shannon entropy of a string.
 * Higher values indicate greater randomness, which correlates with
 * generated secrets/tokens vs. natural-language text.
 *
 * @param str - Input string (should be non-empty).
 * @returns Entropy in bits (0 to log₂(n) where n = unique chars).
 */
export function shannonEntropy(str: string): number {
	if (str.length === 0) return 0;

	const counts = new Map<string, number>();
	for (const ch of str) {
		counts.set(ch, (counts.get(ch) ?? 0) + 1);
	}

	let entropy = 0;
	const len = str.length;
	for (const count of counts.values()) {
		const p = count / len;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

// ── Confidence Heuristic ────────────────────────────────────────────────

/**
 * Derives a confidence score from a matched value and the pattern definition.
 *
 * Factors:
 * 1. Base confidence from the pattern.
 * 2. Entropy bonus: values with entropy > `entropyThreshold` gain up to +0.15.
 * 3. Validation bonus: if the pattern has a `validate` callback that passes,
 *    confidence is capped at 1.0; if it fails, confidence is halved.
 *
 * @param value - The raw matched string.
 * @param def - The pattern definition that matched.
 * @param entropyThreshold - Shannon entropy threshold for bonus.
 * @returns Final confidence in [0, 1].
 */
export function calculateConfidence(
	value: string,
	def: PatternDef,
	entropyThreshold: number,
): number {
	let confidence = def.confidenceBase;

	// Entropy bonus — high-entropy values are more likely genuine secrets
	const entropy = shannonEntropy(value);
	if (entropy > entropyThreshold) {
		const bonus = Math.min(0.15, (entropy - entropyThreshold) * 0.04);
		confidence += bonus;
	}

	// Post-match validation (e.g. Luhn)
	if (def.validate) {
		if (def.validate(value)) {
			confidence = Math.max(confidence, 0.9);
		} else {
			confidence *= 0.5;
		}
	}

	return Math.min(1, Math.max(0, confidence));
}

// ── Main Detector Class ────────────────────────────────────────────────

/**
 * PII detector that scans text for personally identifiable information.
 *
 * Supports seven PII categories:
 *  - SSN, credit-card numbers, email, phone, IP addresses, AWS keys, generic API keys.
 *
 * Each detection is scored with a confidence value based on pattern specificity,
 * Shannon entropy, and optional post-match validation (e.g. Luhn for credit cards).
 *
 * @example
 * ```ts
 * const detector = new PiiDetectorImpl({ enableSsn: true, enableEmail: false });
 * const results = detector.detect("My email is user@example.com");
 * // → [{ type: "email", value: "user@example.com", confidence: 0.9, … }]
 * ```
 */
export class PiiDetectorImpl implements PiiDetector {
	private readonly config: PiiDetectorConfig;
	private readonly logger: Logger;
	private readonly enabledPatterns: readonly PatternDef[];

	/**
	 * @param config - Partial configuration (unspecified fields use defaults).
	 * @param logger - Optional logger for diagnostics.
	 */
	constructor(config: Partial<PiiDetectorConfig> = {}, logger: Logger = nullLogger) {
		this.config = PiiDetectorConfigSchema.parse(config);
		this.logger = logger;
		this.enabledPatterns = this.buildEnabledPatterns();
	}

	/** Filter PATTERNS down to those the user has enabled. */
	private buildEnabledPatterns(): PatternDef[] {
		const flagMap: Record<PiiType, keyof PiiDetectorConfig> = {
			ssn: "enableSsn",
			credit_card: "enableCreditCard",
			email: "enableEmail",
			phone: "enablePhone",
			ip_address: "enableIpAddress",
			aws_key: "enableAwsKey",
			api_key: "enableApiKey",
		};

		return PATTERNS.filter((p) => {
			const flag = flagMap[p.type];
			return this.config[flag] === true;
		});
	}

	/**
	 * Scan `input` for PII.
	 *
	 * The result array is sorted by start position. Each match includes the
	 * raw value, span offsets, confidence score, and severity.
	 *
	 * @param input - Text to scan. Must be a non-empty string.
	 * @returns Ordered list of PII matches exceeding `minConfidence`.
	 */
	detect(input: string): PiiMatch[] {
		if (typeof input !== "string") {
			this.logger.warn("PiiDetector.detect received non-string input", {
				type: typeof input,
			});
			return [];
		}

		const matches: PiiMatch[] = [];
		const { minConfidence, entropyThreshold } = this.config;

		for (const def of this.enabledPatterns) {
			let match: RegExpExecArray | null;

			// Reset lastIndex for global regexes
			def.regex.lastIndex = 0;

			while ((match = def.regex.exec(input)) !== null) {
				const value = match[0];
				const start = match.index;
				const end = start + value.length;

				const confidence = calculateConfidence(value, def, entropyThreshold);

				if (confidence < minConfidence) continue;

				// Deduplicate by exact position span
				const isDuplicate = matches.some(
					(m) => m.start === start && m.end === end && m.type === def.type,
				);
				if (isDuplicate) continue;

				matches.push({
					type: def.type,
					value,
					start,
					end,
					confidence,
					severity: def.severity,
				});
			}
		}

		matches.sort((a, b) => a.start - b.start);
		return matches;
	}

	/**
	 * Returns `true` when the input contains at least one PII match above the
	 * configured confidence threshold.
	 *
	 * @param input - Text to check.
	 */
	containsPii(input: string): boolean {
		return this.detect(input).length > 0;
	}
}
