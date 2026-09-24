/**
 * Prompt protection: inspection of the user's own prompt before the agent
 * forwards it to the model.
 *
 * Built-in secret and PII detection is governed by the local
 * `prompt_protection` config (`off | warn | block` per category; secrets
 * default to `block`, PII to `warn`). An operator-provisioned tenant DLP policy
 * is applied on top of that and cannot be switched off locally: a prompt cannot
 * be rewritten by the host, so any tenant action other than `allow` (and an
 * uninspectable prompt) blocks.
 *
 * Results never contain a matched value — only category names and counts — so
 * the caller can show, log and audit them without re-disclosing the secret.
 */

import { PiiDetectorImpl } from "./dlp/pii-detector.js";
import type { DlpPolicy } from "./dlp/policy.js";
import { scanDlpInput } from "./dlp/scanner.js";
import { SecretDetector } from "./dlp/secret-detector.js";
import { detectPII } from "./pii-detector.js";
import type { PromptProtectionConfig } from "./types.js";

export type PromptProtectionDecision = "allow" | "warn" | "block";
export type PromptFindingCategory = "secret" | "pii" | "tenant_dlp";

export interface PromptFindingSummary {
	category: PromptFindingCategory;
	/** Human-readable kind, e.g. "GitHub token". Never the matched value. */
	kind: string;
	count: number;
}

export interface PromptProtectionResult {
	decision: PromptProtectionDecision;
	/** Findings the configured policy acted on (`off` categories are omitted). */
	findings: PromptFindingSummary[];
	/** Notice for the user. Present for `warn` and `block`; names kinds only. */
	userMessage?: string;
	/** Notice for the model. Present only for `warn`. */
	modelContext?: string;
}

export interface PromptTenantDlp {
	tenantId: string;
	policy: DlpPolicy;
}

export const DEFAULT_PROMPT_PROTECTION: Readonly<PromptProtectionConfig> = Object.freeze({
	secrets: "block",
	pii: "warn",
});

const SECRET_KIND_LABELS: Readonly<Record<string, string>> = {
	aws_access_key: "AWS access key",
	aws_secret_key: "AWS secret key",
	github_token: "GitHub token",
	gitlab_token: "GitLab token",
	slack_token: "Slack token",
	slack_webhook: "Slack webhook URL",
	npm_token: "npm token",
	private_key: "private key",
	generic_api_key: "API key",
	api_key: "API key",
	env_secret: "password or secret assignment",
	secret_assignment: "password or secret assignment",
	jwt_token: "JSON Web Token",
	google_api_key: "Google API key",
	huggingface_token: "Hugging Face token",
	bearer_token: "bearer token",
};

const PII_KIND_LABELS: Readonly<Record<string, string>> = {
	email: "email address",
	phone: "phone number",
	ssn: "social security number",
	credit_card: "payment card number",
};

/** Credential kinds from the general-purpose detector; its PII kinds are not used here. */
const LEGACY_SECRET_KINDS: ReadonlySet<string> = new Set([
	"api_key",
	"aws_access_key",
	"jwt_token",
	"github_token",
	"slack_webhook",
	"google_api_key",
	"huggingface_token",
	"bearer_token",
	"secret_assignment",
]);

/**
 * Any PEM/PGP private key header: `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`,
 * `RSA|EC|DSA|OPENSSH PRIVATE KEY`, `PGP PRIVATE KEY BLOCK`.
 */
const PRIVATE_KEY_HEADER = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;

const SECRET_DETECTOR = new SecretDetector();
const PII_DETECTOR = new PiiDetectorImpl({
	enableIpAddress: false,
	enableAwsKey: false,
	enableApiKey: false,
});

function shannonEntropy(value: string): number {
	const counts = new Map<string, number>();
	for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
	let entropy = 0;
	for (const count of counts.values()) {
		const probability = count / value.length;
		entropy -= probability * Math.log2(probability);
	}
	return entropy;
}

/** A standalone 40-character base64 run: the shape of an AWS secret access key. */
const AWS_SECRET_CANDIDATE = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g;
const AWS_SECRET_KEYWORD = /aws|secret/i;

/**
 * The AWS secret shape also matches long file paths and similar text. Keep only
 * generated-looking values (mixed case plus digits, few separators, no leading
 * slash) that either follow an `aws`/`secret` keyword or have high entropy.
 */
function plausibleAwsSecret(prompt: string, index: number, value: string): boolean {
	const generatedShape =
		/[A-Z]/.test(value) &&
		/[a-z]/.test(value) &&
		/\d/.test(value) &&
		(value.match(/\//g)?.length ?? 0) <= 3 &&
		!value.startsWith("/");
	if (!generatedShape) return false;
	return (
		AWS_SECRET_KEYWORD.test(prompt.slice(Math.max(0, index - 32), index)) ||
		shannonEntropy(value) >= 4.2
	);
}

/**
 * Formatted-only PII: a bare 9- or 10-digit run is far more often an ID,
 * timestamp or port than a phone number or SSN, so those need separators.
 */
function plausiblePii(type: string, value: string): boolean {
	if (type === "phone") return /[-\s.()+]/.test(value) && !/^\d+$/.test(value);
	if (type === "ssn") return /\d{3}[-\s]\d{2}[-\s]\d{4}/.test(value);
	return type in PII_KIND_LABELS;
}

function countKinds(
	kinds: string[],
	labels: Readonly<Record<string, string>>,
): Map<string, number> {
	const counts = new Map<string, number>();
	for (const kind of kinds) {
		const label = labels[kind] ?? kind;
		counts.set(label, (counts.get(label) ?? 0) + 1);
	}
	return counts;
}

/** Secret kinds found in `prompt`; overlapping matches of different detectors count once. */
function detectSecretKinds(prompt: string): string[] {
	const spans: Array<{ start: number; end: number }> = [];
	const kinds: string[] = [];
	const add = (kind: string, start: number, length: number): void => {
		const end = start + length;
		if (spans.some((span) => start < span.end && span.start < end)) return;
		spans.push({ start, end });
		kinds.push(kind);
	};
	for (const match of prompt.matchAll(PRIVATE_KEY_HEADER)) {
		add("private_key", match.index, match[0].length);
	}
	for (const match of prompt.matchAll(AWS_SECRET_CANDIDATE)) {
		if (plausibleAwsSecret(prompt, match.index, match[0])) {
			add("aws_secret_key", match.index, match[0].length);
		}
	}
	for (const match of SECRET_DETECTOR.detect(prompt)) {
		// Its AWS-secret pattern has no left boundary and matches paths; handled above.
		if (match.type === "aws_secret_key") continue;
		add(match.type, prompt.indexOf(match.value, match.index), match.value.length);
	}
	for (const finding of detectPII(prompt).findings) {
		if (LEGACY_SECRET_KINDS.has(finding.type)) {
			add(finding.type, finding.index, finding.value.length);
		}
	}
	return kinds;
}

/** A phone-shaped fragment of a longer digit run (e.g. an invalid card number). */
function isInsideLongerNumber(prompt: string, start: number, end: number): boolean {
	return (
		/\d[-\s.]?$/.test(prompt.slice(Math.max(0, start - 2), start)) ||
		/^[-\s.]?\d/.test(prompt.slice(end, end + 2))
	);
}

/** Phone numbers are matched last: their pattern also fits inside card numbers. */
const PII_PRECEDENCE: Readonly<Record<string, number>> = {
	credit_card: 0,
	ssn: 1,
	email: 2,
	phone: 3,
};

function detectPiiKinds(prompt: string): string[] {
	const kept: Array<{ type: string; start: number; end: number }> = [];
	const candidates = PII_DETECTOR.detect(prompt)
		.filter((match) => plausiblePii(match.type, match.value))
		.sort((left, right) => (PII_PRECEDENCE[left.type] ?? 9) - (PII_PRECEDENCE[right.type] ?? 9));
	for (const match of candidates) {
		if (kept.some((span) => match.start < span.end && span.start < match.end)) continue;
		if (match.type === "phone" && isInsideLongerNumber(prompt, match.start, match.end)) continue;
		kept.push({ type: match.type, start: match.start, end: match.end });
	}
	return kept.sort((left, right) => left.start - right.start).map((match) => match.type);
}

function summaries(
	category: PromptFindingCategory,
	counts: Map<string, number>,
): PromptFindingSummary[] {
	return [...counts].map(([kind, count]) => ({ category, kind, count }));
}

function kindList(findings: PromptFindingSummary[]): string {
	return [...new Set(findings.map((finding) => finding.kind))].join(", ");
}

/** Tenant DLP over the prompt. Returns the reason it blocks, or null to allow. */
function tenantDlpBlock(prompt: string, tenant: PromptTenantDlp): PromptFindingSummary | null {
	const scan = scanDlpInput(tenant.policy, {
		tenantId: tenant.tenantId,
		// Same shape as tool input, so policies written for JSON inspection apply.
		content: JSON.stringify({ prompt }),
		contentType: "application/json",
	});
	if (scan.status === "unavailable") {
		return { category: "tenant_dlp", kind: "content DLP could not inspect", count: 1 };
	}
	if (scan.action === "allow") return null;
	const labels = [...new Set(scan.findings.map((finding) => finding.labelName))];
	return {
		category: "tenant_dlp",
		kind: `organization DLP policy (${labels.join(", ") || "restricted content"})`,
		count: scan.findings.length,
	};
}

/**
 * Inspect one prompt. Throws only on programming or policy errors; the caller
 * owns the failure policy (see the Claude Code `UserPromptSubmit` hook).
 */
export function scanPrompt(
	prompt: string,
	config: PromptProtectionConfig = DEFAULT_PROMPT_PROTECTION,
	tenantDlp?: PromptTenantDlp,
): PromptProtectionResult {
	const blocking: PromptFindingSummary[] = [];
	const warning: PromptFindingSummary[] = [];
	const route = (mode: PromptProtectionConfig["secrets"], found: PromptFindingSummary[]): void => {
		if (mode === "block") blocking.push(...found);
		else if (mode === "warn") warning.push(...found);
	};

	if (config.secrets !== "off") {
		route(
			config.secrets,
			summaries("secret", countKinds(detectSecretKinds(prompt), SECRET_KIND_LABELS)),
		);
	}
	if (config.pii !== "off") {
		route(config.pii, summaries("pii", countKinds(detectPiiKinds(prompt), PII_KIND_LABELS)));
	}
	if (tenantDlp) {
		const tenantFinding = tenantDlpBlock(prompt, tenantDlp);
		if (tenantFinding) blocking.push(tenantFinding);
	}

	if (blocking.length > 0) {
		const findings = [...blocking, ...warning];
		return {
			decision: "block",
			findings,
			userMessage: `🛡️ Singularity AIDR blocked this prompt before it reached the model: it appears to contain sensitive data (${kindList(blocking)}). Remove the sensitive value and resubmit. If it was a live credential that has been shared anywhere else, rotate it.`,
		};
	}
	if (warning.length > 0) {
		const kinds = kindList(warning);
		return {
			decision: "warn",
			findings: warning,
			userMessage: `🛡️ Singularity AIDR: this prompt appears to contain sensitive data (${kinds}). It was sent to the model.`,
			modelContext: `Singularity AIDR prompt protection notice: the user's prompt appears to contain sensitive data (${kinds}). Do not repeat it, and do not copy it into files, commands, commit messages, web requests or other tools unless the user explicitly asks for that.`,
		};
	}
	return { decision: "allow", findings: [] };
}
