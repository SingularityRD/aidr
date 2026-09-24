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
import type { DlpDetector } from "./policy.js";
import { scanPrivacyDetectors } from "./privacy-detectors.js";

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
	// AIDR Privacy TR/EN detectors (vendored rule layer, see ./privacy-detectors.ts).
	"tc_kimlik",
	"iban",
	"address",
	"person",
	"date_of_birth",
	"passport",
	"national_id",
	"tax_id",
	"bank_account",
	"secret",
	"private_key",
]);

/** Severity levels for detected PII. */
const PiiSeveritySchema = z.enum(["low", "medium", "high", "critical"]);

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
	/** Turkish national ID: 11-digit checksum, or any value after an explicit TC/TCKN label. */
	enableTcKimlik: z.boolean().optional().default(true),
	/** IBAN with ISO 13616 mod-97 across the full SWIFT registry, or after an IBAN label. */
	enableIban: z.boolean().optional().default(true),
	/**
	 * Credential tokens (sk-proj, sk-ant-api, github_pat_, glpat-, JWT, Bearer, URL userinfo)
	 * and `password=`/`şifre=` values. Opt-in: the key=value half is contextual and fires on
	 * source code; the token formats overlap the default-on `api_key`/`aws_key` patterns.
	 */
	enableSecret: z.boolean().optional().default(false),
	/** Complete PEM private-key blocks. */
	enablePrivateKey: z.boolean().optional().default(true),
	/**
	 * Contextual types are opt-in: they fire on labels such as `Adres:` or `name:`,
	 * which also appear in source code and schemas.
	 */
	enableAddress: z.boolean().optional().default(false),
	/** Person names only next to an explicit label or phrase (`Ad Soyad:`, `my name is`). */
	enablePerson: z.boolean().optional().default(false),
	/** Labelled TR/EN fields: date of birth, passport, national ID, tax ID, bank account. */
	enableLabelledFields: z.boolean().optional().default(false),
	minConfidence: z.number().min(0).max(1).optional().default(0.5),
	entropyThreshold: z.number().min(0).max(8).optional().default(4.5),
});

// ── Inferred Types ──────────────────────────────────────────────────────

/** Supported PII type discriminator. */
type PiiType = z.infer<typeof PiiTypeSchema>;

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
interface PiiDetector {
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

type PiiSeverity = "low" | "medium" | "high" | "critical";

/** How each privacy detector surfaces as a core PII type, and the flag that enables it. */
interface PrivacyTypeDef {
	readonly detector: DlpDetector;
	readonly type: PiiType;
	readonly severity: PiiSeverity;
	readonly flag: keyof PiiDetectorConfig;
}

const PRIVACY_TYPES: readonly PrivacyTypeDef[] = Object.freeze([
	{ detector: "tc_kimlik", type: "tc_kimlik", severity: "critical", flag: "enableTcKimlik" },
	{ detector: "iban", type: "iban", severity: "high", flag: "enableIban" },
	// TR mobile/landline, international and labelled phone numbers.
	{ detector: "phone", type: "phone", severity: "high", flag: "enablePhone" },
	{ detector: "secret", type: "secret", severity: "critical", flag: "enableSecret" },
	{ detector: "private_key", type: "private_key", severity: "critical", flag: "enablePrivateKey" },
	{ detector: "address", type: "address", severity: "medium", flag: "enableAddress" },
	{ detector: "person", type: "person", severity: "medium", flag: "enablePerson" },
	{
		detector: "date_of_birth",
		type: "date_of_birth",
		severity: "medium",
		flag: "enableLabelledFields",
	},
	{ detector: "passport", type: "passport", severity: "high", flag: "enableLabelledFields" },
	{ detector: "national_id", type: "national_id", severity: "high", flag: "enableLabelledFields" },
	{ detector: "tax_id", type: "tax_id", severity: "high", flag: "enableLabelledFields" },
	{
		detector: "bank_account",
		type: "bank_account",
		severity: "high",
		flag: "enableLabelledFields",
	},
]);

const SEVERITY_RANK: Record<PiiSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** A privacy match that overlaps an existing match of an equivalent type is a duplicate. */
const EQUIVALENT_TYPES: Partial<Record<PiiType, readonly PiiType[]>> = {
	secret: ["secret", "api_key", "aws_key"],
};

/**
 * Spans of one type sorted by start, with the running maximum end, so "does
 * any span overlap [start, end)" is a binary search instead of a full scan.
 */
interface SpanIndex {
	readonly starts: number[];
	readonly maxEnds: number[];
}

function indexSpansByType(matches: readonly PiiMatch[]): Map<PiiType, SpanIndex> {
	const byType = new Map<PiiType, PiiMatch[]>();
	for (const match of matches) {
		const list = byType.get(match.type);
		if (list) list.push(match);
		else byType.set(match.type, [match]);
	}
	const index = new Map<PiiType, SpanIndex>();
	for (const [type, list] of byType) {
		list.sort((a, b) => a.start - b.start);
		const starts: number[] = [];
		const maxEnds: number[] = [];
		let maxEnd = Number.NEGATIVE_INFINITY;
		for (const match of list) {
			maxEnd = Math.max(maxEnd, match.end);
			starts.push(match.start);
			maxEnds.push(maxEnd);
		}
		index.set(type, { starts, maxEnds });
	}
	return index;
}

/** true when a span that starts before `end` reaches past `start`. */
function spanIndexOverlaps(index: SpanIndex, start: number, end: number): boolean {
	let low = 0;
	let high = index.starts.length;
	while (low < high) {
		const mid = (low + high) >>> 1;
		if ((index.starts[mid] ?? 0) < end) low = mid + 1;
		else high = mid;
	}
	return low > 0 && (index.maxEnds[low - 1] ?? 0) > start;
}

function overlapsEquivalent(index: ReadonlyMap<PiiType, SpanIndex>, candidate: PiiMatch): boolean {
	const equivalent = EQUIVALENT_TYPES[candidate.type] ?? [candidate.type];
	return equivalent.some((type) => {
		const spans = index.get(type);
		return spans !== undefined && spanIndexOverlaps(spans, candidate.start, candidate.end);
	});
}

/** Result of {@link PiiDetectorImpl.detectWithCoverage}. */
export interface PiiDetection {
	readonly matches: PiiMatch[];
	/** true when the privacy rules could not inspect all input; matches are a lower bound. */
	readonly incomplete: boolean;
	/** Static reason codes (never input text). */
	readonly reasons: readonly string[];
}

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
		// RFC 5321 length limits (64-char local part, 253-char domain, 63-char
		// label) keep every attempt bounded: with unbounded runs a long `a.a.a…`
		// or `%41%41…` text is rescanned from every word boundary (quadratic).
		regex: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b/g,
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
 * Supports the core categories (SSN, credit-card numbers, email, phone, IP
 * addresses, AWS keys, generic API keys) plus the AIDR Privacy TR/EN detectors:
 * TC Kimlik, IBAN (mod-97, all registry countries), TR phones, PEM private keys
 * and — opt-in — credential tokens, addresses, contextual person names and
 * labelled identity fields.
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
	private readonly enabledPrivacyTypes: readonly PrivacyTypeDef[];

	/**
	 * @param config - Partial configuration (unspecified fields use defaults).
	 * @param logger - Optional logger for diagnostics.
	 */
	constructor(config: Partial<PiiDetectorConfig> = {}, logger: Logger = nullLogger) {
		this.config = PiiDetectorConfigSchema.parse(config);
		this.logger = logger;
		this.enabledPatterns = this.buildEnabledPatterns();
		this.enabledPrivacyTypes = PRIVACY_TYPES.filter((def) => this.config[def.flag] === true);
	}

	/** Filter PATTERNS down to those the user has enabled. */
	private buildEnabledPatterns(): PatternDef[] {
		// Privacy-rule types are enabled separately (PRIVACY_TYPES).
		const flagMap: Partial<Record<PiiType, keyof PiiDetectorConfig>> = {
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
			return flag !== undefined && this.config[flag] === true;
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
		const detection = this.detectWithCoverage(input);
		if (detection.incomplete) {
			this.logger.warn("PiiDetector privacy rules could not inspect all input", {
				reasons: detection.reasons,
			});
		}
		return detection.matches;
	}

	/**
	 * Like {@link detect}, but also reports whether the vendored AIDR Privacy rules
	 * inspected the whole input. An incomplete result is a lower bound, not a clean one.
	 */
	detectWithCoverage(input: string): PiiDetection {
		if (typeof input !== "string") {
			this.logger.warn("PiiDetector.detect received non-string input", {
				type: typeof input,
			});
			return { matches: [], incomplete: false, reasons: [] };
		}

		const matches: PiiMatch[] = [];
		const seen = new Set<string>();
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

				// Deduplicate by exact position span (a set: a linear scan per match is quadratic)
				const key = `${def.type}:${start}:${end}`;
				if (seen.has(key)) continue;
				seen.add(key);

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

		const privacy = this.detectPrivacyTypes(input, matches);
		// Same start: the more severe (more specific) type first, e.g. a checksum-valid
		// TC Kimlik ahead of the generic phone pattern matching the same digits.
		matches.sort(
			(a, b) => a.start - b.start || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
		);
		return { matches, incomplete: privacy.incomplete, reasons: privacy.reasons };
	}

	/** Append vendored privacy-rule matches that the core patterns did not already report. */
	private detectPrivacyTypes(
		input: string,
		matches: PiiMatch[],
	): { incomplete: boolean; reasons: readonly string[] } {
		if (this.enabledPrivacyTypes.length === 0) return { incomplete: false, reasons: [] };
		const byDetector = new Map(this.enabledPrivacyTypes.map((def) => [def.detector, def]));
		const scan = scanPrivacyDetectors(input, [...byDetector.keys()]);
		const existing = indexSpansByType(matches);
		for (const found of scan.matches) {
			const def = byDetector.get(found.detector);
			if (!def || found.score < this.config.minConfidence) continue;
			const match: PiiMatch = {
				type: def.type,
				value: input.slice(found.start, found.end),
				start: found.start,
				end: found.end,
				confidence: found.score,
				severity: def.severity,
			};
			if (overlapsEquivalent(existing, match)) continue;
			matches.push(match);
		}
		return { incomplete: scan.incomplete, reasons: scan.reasons };
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
