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
 *
 * Cost: a prompt can be megabytes of adversarial text, and the host kills a
 * slow hook and then sends the prompt. Every detector pass is linear in the
 * prompt, overlap resolution is a sort plus a sweep, a scan stops as soon as
 * its decision is `block`, and an optional deadline is checked between passes.
 */

import { PiiDetectorImpl } from "./dlp/pii-detector.js";
import type { DlpPolicy } from "./dlp/policy.js";
import { scanDlpInput } from "./dlp/scanner.js";
import { SecretDetector, type SecretType } from "./dlp/secret-detector.js";
import { matchPII } from "./pii-detector.js";
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
	/**
	 * true when scanning stopped at the first blocking finding: the decision is
	 * final, but counts are lower bounds and later categories were not scanned.
	 */
	partial?: true;
}

export interface PromptScanOptions {
	/**
	 * Wall-clock deadline (`Date.now()` milliseconds). Checked between detector
	 * passes; once it has passed the scan throws {@link PromptScanDeadlineError}
	 * instead of returning a result it did not finish.
	 */
	deadlineAt?: number;
}

/** The scan ran out of time; the prompt was not fully inspected. */
export class PromptScanDeadlineError extends Error {
	constructor() {
		super("prompt scan exceeded its deadline");
		this.name = "PromptScanDeadlineError";
	}
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

/**
 * SecretDetector types used here. Its AWS-secret pattern has no left boundary
 * and matches paths, so AWS secrets come from AWS_SECRET_CANDIDATE instead.
 */
const SECRET_DETECTOR_TYPES: ReadonlySet<SecretType> = new Set<SecretType>([
	"aws_access_key",
	"github_token",
	"gitlab_token",
	"slack_token",
	"npm_token",
	"private_key",
	"generic_api_key",
	"env_secret",
]);

interface Finding {
	kind: string;
	start: number;
	end: number;
}

/** Throws {@link PromptScanDeadlineError} once the scan deadline has passed. */
type Checkpoint = () => void;

/** Candidates collected between two deadline checks inside one pass. */
const CHECKPOINT_INTERVAL = 4096;

function deadlineCheckpoint(deadlineAt: number | undefined): Checkpoint {
	if (deadlineAt === undefined) return () => {};
	return () => {
		if (Date.now() > deadlineAt) throw new PromptScanDeadlineError();
	};
}

function mergeByStart(left: readonly Finding[], right: readonly Finding[]): Finding[] {
	const merged: Finding[] = [];
	let i = 0;
	let j = 0;
	while (i < left.length || j < right.length) {
		const a = left[i];
		const b = right[j];
		if (a !== undefined && (b === undefined || a.start <= b.start)) {
			merged.push(a);
			i++;
		} else if (b !== undefined) {
			merged.push(b);
			j++;
		}
	}
	return merged;
}

/**
 * Non-overlapping findings, sorted by start. A pass keeps each candidate that
 * overlaps neither a finding kept by an earlier pass nor an earlier-starting
 * candidate kept from the same pass: earlier passes win, then earlier starts.
 * A pass costs one sort plus one sweep; comparing every candidate with every
 * kept finding was quadratic (88k emails took ~30 s).
 */
class DisjointFindings {
	private kept: Finding[] = [];

	get all(): readonly Finding[] {
		return this.kept;
	}

	/** Adds one pass and returns the candidates it kept, in start order. */
	addPass(candidates: Finding[]): Finding[] {
		candidates.sort((left, right) => left.start - right.start);
		const accepted: Finding[] = [];
		let cursor = 0;
		for (const candidate of candidates) {
			// Kept findings are disjoint and sorted, so their ends are sorted too.
			while ((this.kept[cursor]?.end ?? Number.POSITIVE_INFINITY) <= candidate.start) cursor++;
			const next = this.kept[cursor];
			if (next !== undefined && next.start < candidate.end) continue;
			const previous = accepted[accepted.length - 1];
			if (previous !== undefined && previous.end > candidate.start) continue;
			accepted.push(candidate);
		}
		this.kept = mergeByStart(this.kept, accepted);
		return accepted;
	}
}

/** Collects a pass's candidates, checking the deadline as it goes. */
function collect(pass: Iterable<Finding>, checkpoint: Checkpoint): Finding[] {
	const candidates: Finding[] = [];
	for (const finding of pass) {
		candidates.push(finding);
		if (candidates.length % CHECKPOINT_INTERVAL === 0) checkpoint();
	}
	return candidates;
}

/** Secret candidate passes in precedence order. Each is lazy, so a scan can stop at its first hit. */
function secretPasses(prompt: string): Array<() => Generator<Finding>> {
	return [
		function* privateKeyHeaders() {
			for (const match of prompt.matchAll(PRIVATE_KEY_HEADER)) {
				yield { kind: "private_key", start: match.index, end: match.index + match[0].length };
			}
		},
		function* awsSecrets() {
			for (const match of prompt.matchAll(AWS_SECRET_CANDIDATE)) {
				if (plausibleAwsSecret(prompt, match.index, match[0])) {
					yield { kind: "aws_secret_key", start: match.index, end: match.index + match[0].length };
				}
			}
		},
		function* secretDetector() {
			for (const match of SECRET_DETECTOR.scan(prompt, SECRET_DETECTOR_TYPES)) {
				const start = prompt.indexOf(match.value, match.index);
				yield { kind: match.type, start, end: start + match.value.length };
			}
		},
		function* legacyCredentials() {
			for (const finding of matchPII(prompt, LEGACY_SECRET_KINDS)) {
				yield {
					kind: finding.type,
					start: finding.index,
					end: finding.index + finding.value.length,
				};
			}
		},
	];
}

/**
 * Secret kinds found in `prompt`; overlapping matches of different detectors
 * count once. With `stopAtFirst` the scan returns at the first confirmed
 * secret without running the remaining passes.
 */
function detectSecretKinds(prompt: string, stopAtFirst: boolean, checkpoint: Checkpoint): string[] {
	const kept = new DisjointFindings();
	const kinds: string[] = [];
	for (const pass of secretPasses(prompt)) {
		checkpoint();
		if (stopAtFirst) {
			const first = pass().next();
			if (!first.done) return [first.value.kind];
			continue;
		}
		for (const finding of kept.addPass(collect(pass(), checkpoint))) kinds.push(finding.kind);
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

/** PII kinds found in `prompt`, in position order; one pass per precedence level. */
function detectPiiKinds(prompt: string, checkpoint: Checkpoint): string[] {
	const passes = new Map<number, Finding[]>();
	const matches = PII_DETECTOR.detect(prompt);
	checkpoint();
	for (const match of matches) {
		if (!plausiblePii(match.type, match.value)) continue;
		if (match.type === "phone" && isInsideLongerNumber(prompt, match.start, match.end)) continue;
		const precedence = PII_PRECEDENCE[match.type] ?? 9;
		const pass = passes.get(precedence) ?? [];
		if (pass.length === 0) passes.set(precedence, pass);
		pass.push({ kind: match.type, start: match.start, end: match.end });
	}
	const kept = new DisjointFindings();
	for (const precedence of [...passes.keys()].sort((left, right) => left - right)) {
		kept.addPass(passes.get(precedence) ?? []);
	}
	return kept.all.map((finding) => finding.kind);
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

function blockResult(
	blocking: PromptFindingSummary[],
	warning: PromptFindingSummary[],
	partial: boolean,
): PromptProtectionResult {
	return {
		decision: "block",
		findings: [...blocking, ...warning],
		userMessage: `🛡️ Singularity AIDR blocked this prompt before it reached the model: it appears to contain sensitive data (${kindList(blocking)}). Remove the sensitive value and resubmit. If it was a live credential that has been shared anywhere else, rotate it.`,
		...(partial ? { partial: true as const } : {}),
	};
}

/**
 * Inspect one prompt. Throws {@link PromptScanDeadlineError} when
 * `options.deadlineAt` passes mid-scan, and otherwise only on programming or
 * policy errors; the caller owns the failure policy (see the Claude Code
 * `UserPromptSubmit` hook).
 *
 * A `block` is final, so the scan stops at the first blocking finding: with
 * secrets in `block` mode the first confirmed secret ends it, and later
 * categories are skipped (`partial: true`).
 */
export function scanPrompt(
	prompt: string,
	config: PromptProtectionConfig = DEFAULT_PROMPT_PROTECTION,
	tenantDlp?: PromptTenantDlp,
	options: PromptScanOptions = {},
): PromptProtectionResult {
	const checkpoint = deadlineCheckpoint(options.deadlineAt);
	const blocking: PromptFindingSummary[] = [];
	const warning: PromptFindingSummary[] = [];
	const route = (mode: PromptProtectionConfig["secrets"], found: PromptFindingSummary[]): void => {
		if (mode === "block") blocking.push(...found);
		else if (mode === "warn") warning.push(...found);
	};

	checkpoint();
	if (config.secrets !== "off") {
		const kinds = detectSecretKinds(prompt, config.secrets === "block", checkpoint);
		route(config.secrets, summaries("secret", countKinds(kinds, SECRET_KIND_LABELS)));
		// Stopped at the first secret: the count is a lower bound.
		if (blocking.length > 0) return blockResult(blocking, warning, true);
	}
	if (config.pii !== "off") {
		checkpoint();
		route(
			config.pii,
			summaries("pii", countKinds(detectPiiKinds(prompt, checkpoint), PII_KIND_LABELS)),
		);
	}
	if (tenantDlp) {
		if (blocking.length > 0) return blockResult(blocking, warning, true);
		checkpoint();
		const tenantFinding = tenantDlpBlock(prompt, tenantDlp);
		if (tenantFinding) blocking.push(tenantFinding);
	}

	if (blocking.length > 0) return blockResult(blocking, warning, false);
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
