/**
 * PII Detection and Handling
 * Detects and handles personally identifiable information
 */

const PII_PATTERNS = {
	email: {
		pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
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
		pattern: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g,
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

export function detectPII(text: string): PIIReport {
	const findings: PIIFinding[] = [];
	for (const [_name, config] of Object.entries(PII_PATTERNS)) {
		const matches = text.matchAll(config.pattern);
		for (const match of matches) {
			if (match.index !== undefined) {
				findings.push({
					type: config.type,
					value: match[0],
					index: match.index,
					severity: config.severity as PIIFinding["severity"],
				});
			}
		}
	}
	findings.sort((a, b) => a.index - b.index);
	return {
		findings,
		hasCritical: findings.some((f) => f.severity === "critical"),
		hasHigh: findings.some((f) => f.severity === "high" || f.severity === "critical"),
		redacted: redactPII(text, findings),
	};
}

export function redactPII(text: string, findings: PIIFinding[]): string {
	let result = text;
	for (const finding of [...findings].reverse()) {
		const before = result.slice(0, finding.index);
		const after = result.slice(finding.index + finding.value.length);
		result = `${before}[REDACTED_${finding.type.toUpperCase()}]${after}`;
	}
	return result;
}

export function maskPII(value: string, _type: string): string {
	if (value.length <= 8) return "*".repeat(value.length);
	const visible = 2;
	return value.slice(0, visible) + "*".repeat(value.length - visible * 2) + value.slice(-visible);
}

export function validateNoPII(text: string, context: string): void {
	const report = detectPII(text);
	if (report.hasCritical) {
		throw new Error(`Critical PII detected in ${context}`);
	}
}
