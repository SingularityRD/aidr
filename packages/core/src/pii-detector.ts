/**
 * PII Detection and Handling
 * Detects and handles personally identifiable information
 */

import { luhnCheck } from "./dlp/pii-detector.js";

const PII_PATTERNS = {
	email: {
		// RFC 5321 length limits (64-char local part, 253-char domain, 63-char
		// label) keep every attempt bounded: with unbounded runs a long `a.a.a…`
		// or `%41%41…` text is rescanned from every word boundary (quadratic).
		pattern: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b/g,
		type: "email",
		severity: "high",
	},
	phone: {
		pattern: /\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
		type: "phone",
		severity: "high",
	},
	ssn: {
		pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
		type: "ssn",
		severity: "critical",
	},
	creditCard: {
		pattern: /\b(?:\d[ -]*?){13,16}\b/g,
		type: "credit_card",
		severity: "critical",
		// Any 13–16 digit run (UUID fragments, ids, timestamps) matches the
		// pattern; only Luhn-valid numbers are reported as card numbers.
		validate: luhnCheck,
	},
	ipAddress: {
		pattern:
			/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
		type: "ip_address",
		severity: "medium",
	},
	apiKey: {
		pattern: /\b(?:api[\s_-]?key|apikey|token)["\s]*[:=]["\s]*[a-zA-Z0-9_-]{16,}\b/gi,
		type: "api_key",
		severity: "critical",
	},
	awsAccessKey: {
		pattern: /\bAKIA[0-9A-Z]{16}\b/g,
		type: "aws_access_key",
		severity: "critical",
	},
	privateKey: {
		pattern: /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
		type: "private_key",
		severity: "critical",
	},
	jwt: {
		// Starts only where a run of token characters starts. A `\b` start also
		// fired after `-`, so `eyJ-eyJ-…` rescanned the rest of the run from every
		// `eyJ` (quadratic).
		pattern: /(?<![A-Za-z0-9_-])eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
		type: "jwt_token",
		severity: "critical",
	},
	githubToken: {
		pattern: /\b(?:ghp|gho|github_pat)_[a-zA-Z0-9]{36,}\b/g,
		type: "github_token",
		severity: "critical",
	},
	slackWebhook: {
		pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[a-zA-Z0-9]+\b/g,
		type: "slack_webhook",
		severity: "critical",
	},
	googleApiKey: {
		pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
		type: "google_api_key",
		severity: "critical",
	},
	huggingFaceToken: {
		pattern: /\bhf_[a-zA-Z0-9]{32,}\b/g,
		type: "huggingface_token",
		severity: "critical",
	},
	anthropicKey: {
		pattern: /\b(?:sk-ant-)[a-zA-Z0-9_-]{20,}\b/g,
		type: "api_key",
		severity: "critical",
	},
	bearerToken: {
		pattern: /\b(?:Bearer|bearer)\s+[A-Za-z0-9_.-]{20,}\b/g,
		type: "bearer_token",
		severity: "critical",
	},
	secretAssignment: {
		pattern: /\b(?:SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*['"]?[a-zA-Z0-9_!@#$%^&*()]{12,}['"]?\b/g,
		type: "secret_assignment",
		severity: "critical",
	},
};

export interface PIIFinding {
	type: string;
	value: string;
	index: number;
	severity: "low" | "medium" | "high" | "critical";
}

export interface PIIReport {
	findings: PIIFinding[];
	hasCritical: boolean;
	hasHigh: boolean;
	redacted: string;
}

/**
 * Lazily yield findings pattern by pattern (unsorted). `types` restricts the
 * scan to those finding types, so a caller that only needs credentials does not
 * run the email, phone and card patterns at all. Patterns with a validator
 * (card numbers: Luhn) yield only validated matches.
 */
export function* matchPII(text: string, types?: ReadonlySet<string>): Generator<PIIFinding> {
	for (const config of Object.values(PII_PATTERNS)) {
		if (types && !types.has(config.type)) continue;
		for (const match of text.matchAll(config.pattern)) {
			if (match.index === undefined) continue;
			if ("validate" in config && !config.validate(match[0])) continue;
			yield {
				type: config.type,
				value: match[0],
				index: match.index,
				severity: config.severity as PIIFinding["severity"],
			};
		}
	}
}

export function detectPII(text: string): PIIReport {
	const findings = [...matchPII(text)];
	findings.sort((a, b) => a.index - b.index);
	return {
		findings,
		hasCritical: findings.some((f) => f.severity === "critical"),
		hasHigh: findings.some((f) => f.severity === "high" || f.severity === "critical"),
		redacted: redactPII(text, findings),
	};
}

const SEVERITY_RANK: Record<PIIFinding["severity"], number> = {
	low: 0,
	medium: 1,
	high: 2,
	critical: 3,
};

/**
 * Replace every finding with a `[REDACTED_<TYPE>]` token.
 *
 * Overlapping or nested findings (a phone number inside a card number, an API
 * key inside a secret assignment) are merged into one span covering their
 * union, so no suffix of a longer match survives and no token is spliced into
 * the middle of another. The merged span is labelled with its most severe
 * finding (then the longest, then the earliest).
 */
export function redactPII(text: string, findings: PIIFinding[]): string {
	const spans: Array<{ start: number; end: number; label: PIIFinding }> = [];
	const ordered = findings
		.map((finding) => ({
			finding,
			start: Math.max(0, Math.min(text.length, finding.index)),
			end: Math.max(0, Math.min(text.length, finding.index + finding.value.length)),
		}))
		.filter((candidate) => candidate.end > candidate.start)
		.sort((left, right) => left.start - right.start || right.end - left.end);
	for (const candidate of ordered) {
		const current = spans[spans.length - 1];
		if (!current || candidate.start >= current.end) {
			spans.push({ start: candidate.start, end: candidate.end, label: candidate.finding });
			continue;
		}
		current.end = Math.max(current.end, candidate.end);
		const rank = SEVERITY_RANK[candidate.finding.severity] ?? 0;
		const currentRank = SEVERITY_RANK[current.label.severity] ?? 0;
		if (
			rank > currentRank ||
			(rank === currentRank && candidate.finding.value.length > current.label.value.length)
		) {
			current.label = candidate.finding;
		}
	}
	let result = "";
	let cursor = 0;
	for (const span of spans) {
		result += `${text.slice(cursor, span.start)}${redactionToken(span.label.type)}`;
		cursor = span.end;
	}
	return result + text.slice(cursor);
}

function redactionToken(type: string): string {
	const label = type.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
	return `[REDACTED_${label || "PII"}]`;
}

/**
 * Mask a sensitive value for display. The result is a fixed placeholder that
 * reveals none of the value's characters and not its length.
 */
export function maskPII(_value: string, type: string): string {
	const label = type.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
	return label ? `[MASKED_${label}]` : "[MASKED]";
}

export function validateNoPII(text: string, context: string): void {
	const report = detectPII(text);
	if (report.hasCritical) {
		throw new Error(`Critical PII detected in ${context}`);
	}
}
