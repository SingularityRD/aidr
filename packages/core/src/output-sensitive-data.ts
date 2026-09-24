/**
 * High-precision secret and sensitive-data detection for tool/model output.
 *
 * Every finding here quarantines a whole tool result, so each rule must match
 * a value that is a credential (or a payment card / labelled SSN) with very
 * few false positives on ordinary developer output: `git log` author emails,
 * epoch timestamps, order ids, content hashes, UUIDs, semver strings and
 * prices never match. Contact data (email, phone, IP address) is deliberately
 * not a quarantine reason for tool output; it is governed by tenant DLP policy
 * instead.
 */
import { shannonEntropy } from "./dlp/pii-detector.js";
import { detectPreciseCommonPii } from "./pii-precision.js";

export interface OutputSensitiveMatch {
	/** Stable type name; `OUT-PII-<TYPE>` is derived from it. */
	type: string;
	/** Raw matched value. Never place it in a finding, log or excerpt. */
	value: string;
	index: number;
	severity: "high" | "critical";
}

interface SecretRule {
	type: string;
	pattern: RegExp;
	severity: "high" | "critical";
	/** Capture group holding the credential; the whole match when omitted. */
	group?: number;
	validate?: (value: string, match: RegExpExecArray, text: string) => boolean;
}

const PLACEHOLDER =
	/example|placeholder|changeme|change_me|dummy|sample|redacted|your[_-]|<[^>]*>|x{4,}|\*{3,}|\.{3,}|\$\{|\{\{/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A free-form value reads as a generated credential: long enough, mixes
 * letters and digits, is not a placeholder or UUID, and is not low-entropy.
 */
export function isCredentialLike(value: string, minLength = 12): boolean {
	return (
		value.length >= minLength &&
		value.length <= 512 &&
		/[A-Za-z]/.test(value) &&
		/\d/.test(value) &&
		!PLACEHOLDER.test(value) &&
		!UUID.test(value) &&
		shannonEntropy(value) >= 3
	);
}

function decodeBase64UrlJson(segment: string): unknown {
	const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
	const json = Buffer.from(normalized, "base64").toString("utf8");
	return JSON.parse(json);
}

/** A JWT's header must decode to a JSON object naming its algorithm. */
function isJwt(value: string): boolean {
	const [header, payload] = value.split(".");
	if (!header || !payload) return false;
	try {
		const decodedHeader = decodeBase64UrlJson(header);
		const decodedPayload = decodeBase64UrlJson(payload);
		return (
			typeof decodedHeader === "object" &&
			decodedHeader !== null &&
			typeof (decodedHeader as Record<string, unknown>).alg === "string" &&
			typeof decodedPayload === "object" &&
			decodedPayload !== null
		);
	} catch {
		return false;
	}
}

/** A PEM header alone (e.g. in a parser's source) is not key material. */
function hasPemBody(_value: string, match: RegExpExecArray, text: string): boolean {
	const after = text.slice(match.index + match[0].length, match.index + match[0].length + 400);
	return /[A-Za-z0-9+/=]{48,}/.test(after.replace(/[\s"'\\,]|\\n/g, ""));
}

/** Pagination, CSRF and similar "tokens" are identifiers, not credentials. */
const NON_SECRET_KEY =
	/(?:page|next|prev|continuation|sync|cursor|csrf|xsrf|state|request|idempotency|verification|max|num|total)[_-]?tokens?$/i;

/**
 * `API_KEY=value` in dotenv / shell style: an upper-case key immediately
 * followed by `=` and an unquoted literal. Such a value is the secret itself,
 * even when it is letters only, whereas `apiKey = someVariable` in source code
 * is an identifier. References (`$VAR`, `${VAR}`) and dotted expressions such
 * as `process.env.API_KEY` never qualify.
 */
function isDotenvLiteral(key: string, value: string, matched: string): boolean {
	return (
		/^[A-Z0-9_]+$/.test(key) &&
		matched === `${key}=${value}` &&
		value.length >= 16 &&
		/^[A-Za-z0-9_+/=-]+$/.test(value) &&
		!PLACEHOLDER.test(value) &&
		shannonEntropy(value) >= 3
	);
}

const SECRET_RULES: readonly SecretRule[] = [
	{ type: "aws_access_key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "critical" },
	{
		type: "aws_secret_key",
		pattern:
			/\baws[_-]?secret[_-]?(?:access[_-]?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
		group: 1,
		severity: "critical",
	},
	{
		type: "private_key",
		pattern: /-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----/g,
		severity: "critical",
		validate: hasPemBody,
	},
	{
		type: "github_token",
		pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g,
		severity: "critical",
	},
	{ type: "gitlab_token", pattern: /\bglpat-[A-Za-z0-9_-]{20,}/g, severity: "critical" },
	// Anthropic keys keep the historical `api_key` type (rule OUT-PII-API_KEY).
	{ type: "api_key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, severity: "critical" },
	{
		// OpenAI project, service-account, admin and legacy user keys.
		type: "api_key",
		pattern: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g,
		severity: "critical",
		validate: (value) => isCredentialLike(value.replace(/^sk-/, ""), 32),
	},
	{ type: "api_key", pattern: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g, severity: "critical" },
	{ type: "slack_token", pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, severity: "critical" },
	{
		type: "slack_webhook",
		pattern:
			/https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]{16,}/g,
		severity: "critical",
	},
	{ type: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "critical" },
	{ type: "huggingface_token", pattern: /\bhf_[A-Za-z0-9]{32,}\b/g, severity: "critical" },
	{ type: "npm_token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "critical" },
	{
		type: "jwt_token",
		pattern: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g,
		severity: "critical",
		validate: isJwt,
	},
	{
		type: "bearer_token",
		pattern: /\bBearer\s+([A-Za-z0-9._~+/-]{20,}=*)/gi,
		group: 1,
		severity: "critical",
		validate: (value) => isCredentialLike(value, 20),
	},
	{
		// `password = "..."`, `"api_key": "..."`, `CLIENT_SECRET=...` with a
		// generated-looking value.
		type: "secret_assignment",
		pattern:
			/(?<![A-Za-z0-9])((?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|password|passwd|secret|token))["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.!@#$%^&*~]{12,512})/gi,
		group: 2,
		severity: "high",
		validate: (value, match) =>
			!NON_SECRET_KEY.test(match[1] ?? "") &&
			(isCredentialLike(value) || isDotenvLiteral(match[1] ?? "", value, match[0])),
	},
];

function secretMatches(text: string): OutputSensitiveMatch[] {
	const matches: OutputSensitiveMatch[] = [];
	for (const rule of SECRET_RULES) {
		const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
		let match = pattern.exec(text);
		while (match !== null) {
			const value = rule.group === undefined ? match[0] : match[rule.group];
			if (value && (!rule.validate || rule.validate(value, match, text))) {
				matches.push({
					type: rule.type,
					value,
					index: match.index + (rule.group === undefined ? 0 : match[0].indexOf(value)),
					severity: rule.severity,
				});
			}
			match = pattern.exec(text);
		}
	}
	return matches;
}

/**
 * Credentials, Luhn-valid payment cards from a known network, and SSNs that
 * are explicitly labelled, ordered by position. Overlapping findings of the
 * same span (a JWT also read as a bearer token) are reported once.
 */
export function detectOutputSensitiveData(text: string): OutputSensitiveMatch[] {
	const found = secretMatches(text);
	for (const match of detectPreciseCommonPii(text, {
		types: ["credit_card", "ssn"],
		requireSsnContext: true,
	})) {
		found.push({ type: match.type, value: match.value, index: match.start, severity: "critical" });
	}
	found.sort((left, right) => left.index - right.index || right.value.length - left.value.length);
	const accepted: OutputSensitiveMatch[] = [];
	let coveredUntil = -1;
	for (const match of found) {
		if (match.index + match.value.length <= coveredUntil) continue;
		accepted.push(match);
		coveredUntil = Math.max(coveredUntil, match.index + match.value.length);
	}
	return accepted;
}
