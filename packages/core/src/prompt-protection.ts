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
 * Personal data is matched by the core patterns (email, phone, card, SSN) plus
 * the vendored AIDR Privacy rules for Turkish ID numbers (TC Kimlik), IBANs and
 * TR/international phone numbers. The privacy rules report when they could not
 * inspect part of the prompt; that is surfaced as `incomplete`, never as a clean
 * result: a `block` PII policy blocks the prompt and `warn` sends it with a
 * visible notice. Two avoidable causes are handled up front: the rules' 1 MiB
 * input limit (the prompt is scanned in overlapping windows) and an unterminated
 * quoted label value such as `name: "…` (the window is scanned again with that
 * quote neutralized).
 *
 * Cost: a prompt can be megabytes of adversarial text, and the host kills a
 * slow hook and then sends the prompt. Every detector pass is linear in the
 * prompt, overlap resolution is a sort plus a sweep, a scan stops as soon as
 * its decision is `block`, and an optional deadline is checked between passes.
 */

import { PiiDetectorImpl } from "./dlp/pii-detector.js";
import type { DlpDetector, DlpPolicy } from "./dlp/policy.js";
import { type PrivacyDetectorScan, scanPrivacyDetectors } from "./dlp/privacy-detectors.js";
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
	/**
	 * Present when a detector could not inspect the whole prompt, so its findings
	 * are lower bounds. The decision already accounts for it: a `block` policy for
	 * the category blocks, `warn` sends the prompt with a notice.
	 */
	incomplete?: PromptIncompleteInspection;
}

export interface PromptIncompleteInspection {
	/** Only the personal-data check can be incomplete; the secret passes always cover the prompt. */
	category: "pii";
	/** Static reason codes from the privacy rules (e.g. `INVALID_ENCODING`); never input text. */
	reasons: string[];
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
	tc_kimlik: "Turkish ID number (TC Kimlik)",
	iban: "IBAN",
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
/** Core PII patterns only; the privacy rules run separately, in windows (see scanPrivacyWindows). */
const PII_DETECTOR = new PiiDetectorImpl({
	enableIpAddress: false,
	enableAwsKey: false,
	enableApiKey: false,
	enablePrivacyRules: false,
});

/** AIDR Privacy detectors added to the core patterns; their names double as PII kinds. */
const PROMPT_PRIVACY_DETECTORS: readonly DlpDetector[] = ["tc_kimlik", "iban", "phone"];

/**
 * Privacy-rule window size: well below the rules' 1 MiB input and normalization
 * limits (NFKC can expand text), and small enough that the deadline is checked
 * every few tens of milliseconds.
 */
const PRIVACY_WINDOW_CHARS = 64 * 1024;

/**
 * Overlap between consecutive windows. Every TC Kimlik, IBAN and phone pattern
 * is far shorter than half of it, so a match lies wholly inside the window that
 * owns its start (see privacyWindows). A labelled value (`tc: …`) can run longer
 * and be cut at a window end, but is still counted once, by that window.
 */
const PRIVACY_WINDOW_OVERLAP = 4 * 1024;

/**
 * Incomplete-scan reasons that cannot hide a TC Kimlik, IBAN or phone number: an
 * unterminated quoted credential (`password: "…`) and a PEM block without its END
 * line. The rules detect both after every rule this scan enables, so a failure
 * there stops none of them; the secret passes cover credentials and key headers.
 */
const REASONS_OUTSIDE_PROMPT_PII: ReadonlySet<string> = new Set([
	"INCOMPLETE_SECRET",
	"INCOMPLETE_PRIVATE_KEY",
]);

/** A quoted label value with no closing quote (`name: "…` to the end of the window). */
const UNTERMINATED_FIELD = "INCOMPLETE_FIELD";

/** Quotes (and blanks) right after a label separator: where a quoted label value opens. */
const LABEL_VALUE_OPENING = /([:=#][ \t]*)(["'][ \t"']*)/g;

const ANY_NUMBER = /\p{N}/u;
const NOTHING_FOUND: PrivacyDetectorScan = Object.freeze({
	matches: [],
	incomplete: false,
	reasons: [],
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

/** Where a credential sits in a text. Deliberately carries no matched value. */
export interface SecretLocation {
	/** Detector kind, e.g. `github_token`. */
	kind: string;
	/** Human-readable kind, e.g. "GitHub token". */
	label: string;
	start: number;
	end: number;
}

/**
 * Every credential in `text`, located with the same detector passes (and the
 * same overlap resolution) the prompt check uses, so other surfaces such as the
 * secure-code guardrail share one definition of "a secret" instead of keeping
 * a second list of patterns.
 */
export function locateSecrets(text: string): SecretLocation[] {
	const kept = new DisjointFindings();
	const noDeadline: Checkpoint = () => {};
	for (const pass of secretPasses(text)) kept.addPass(collect(pass(), noDeadline));
	return kept.all.map((finding) => ({
		kind: finding.kind,
		label: SECRET_KIND_LABELS[finding.kind] ?? finding.kind,
		start: finding.start,
		end: finding.end,
	}));
}

/** A phone-shaped fragment of a longer digit run (e.g. an invalid card number). */
function isInsideLongerNumber(prompt: string, start: number, end: number): boolean {
	return (
		/\d[-\s.]?$/.test(prompt.slice(Math.max(0, start - 2), start)) ||
		/^[-\s.]?\d/.test(prompt.slice(end, end + 2))
	);
}

/**
 * Checksum-validated identifiers first (an IBAN's digits can pass Luhn), phone
 * numbers last: their pattern also fits inside card and ID numbers.
 */
const PII_PRECEDENCE: Readonly<Record<string, number>> = {
	iban: 0,
	credit_card: 1,
	tc_kimlik: 2,
	ssn: 2,
	email: 3,
	phone: 4,
};

/** true when `index` falls between the two halves of a surrogate pair. */
function splitsSurrogatePair(text: string, index: number): boolean {
	const before = text.charCodeAt(index - 1);
	const after = text.charCodeAt(index);
	return before >= 0xd800 && before <= 0xdbff && after >= 0xdc00 && after <= 0xdfff;
}

/**
 * One window through the privacy rules. When a quoted label value has no closing
 * quote (`name: "…`, or a window boundary inside a quoted value) the rules stop at
 * that field; the window is then scanned again with every quote that opens a label
 * value blanked out, same length, so the value is delimited like an unquoted one.
 */
function scanPrivacyWindow(text: string): PrivacyDetectorScan {
	// Every TC Kimlik, IBAN and phone number has digits, and so does every encoding
	// the rules decode (`%3X`, `&#NN;`, `\u003X`); NFKC digit sources are all \p{N}.
	if (!ANY_NUMBER.test(text)) return NOTHING_FOUND;
	const scan = scanPrivacyDetectors(text, PROMPT_PRIVACY_DETECTORS);
	if (!scan.reasons.includes(UNTERMINATED_FIELD)) return scan;
	const unquoted = text.replace(
		LABEL_VALUE_OPENING,
		(_match, separator: string, opening: string) => separator + opening.replace(/["']/g, " "),
	);
	return scanPrivacyDetectors(unquoted, PROMPT_PRIVACY_DETECTORS);
}

interface PrivacyWindowScan {
	findings: Finding[];
	/** Reasons some text was not inspected for these detectors; empty when complete. */
	incompleteReasons: string[];
}

interface PrivacyWindow {
	start: number;
	end: number;
	/** Match starts this window reports: [ownedFrom, ownedTo). */
	ownedFrom: number;
	ownedTo: number;
}

/**
 * Overlapping windows covering `prompt`, never splitting a surrogate pair. Window
 * `i` owns the match starts from the middle of its leading overlap to the middle
 * of its trailing one, so every match is reported exactly once and by a window
 * that holds it whole with context on both sides.
 */
function* privacyWindows(prompt: string): Generator<PrivacyWindow> {
	let start = 0;
	let ownedFrom = 0;
	for (;;) {
		let end = Math.min(start + PRIVACY_WINDOW_CHARS, prompt.length);
		if (splitsSurrogatePair(prompt, end)) end--;
		if (end === prompt.length) {
			yield { start, end, ownedFrom, ownedTo: end };
			return;
		}
		const ownedTo = end - PRIVACY_WINDOW_OVERLAP / 2;
		yield { start, end, ownedFrom, ownedTo };
		ownedFrom = ownedTo;
		start = end - PRIVACY_WINDOW_OVERLAP;
		if (splitsSurrogatePair(prompt, start)) start--;
	}
}

/**
 * The privacy rules over the whole prompt, in overlapping windows (the rules alone
 * give up on anything over 1 MiB). The deadline is checked before each window.
 */
function scanPrivacyWindows(prompt: string, checkpoint: Checkpoint): PrivacyWindowScan {
	const findings: Finding[] = [];
	const reasons = new Set<string>();
	for (const { start, end, ownedFrom, ownedTo } of privacyWindows(prompt)) {
		checkpoint();
		const scan = scanPrivacyWindow(prompt.slice(start, end));
		for (const reason of scan.reasons) {
			if (!REASONS_OUTSIDE_PROMPT_PII.has(reason)) reasons.add(reason);
		}
		for (const match of scan.matches) {
			const at = start + match.start;
			if (at >= ownedFrom && at < ownedTo) {
				findings.push({ kind: match.detector, start: at, end: start + match.end });
			}
		}
	}
	return { findings, incompleteReasons: [...reasons].sort() };
}

interface PiiScan {
	/** PII kinds found, in position order. */
	kinds: string[];
	/** Present when part of the prompt was not inspected; `kinds` is then a lower bound. */
	incomplete?: PromptIncompleteInspection;
}

/** PII in `prompt`: core patterns plus windowed privacy rules, one pass per precedence level. */
function detectPii(prompt: string, checkpoint: Checkpoint): PiiScan {
	const passes = new Map<number, Finding[]>();
	const add = (kind: string, start: number, end: number): void => {
		if (!plausiblePii(kind, prompt.slice(start, end))) return;
		if (kind === "phone" && isInsideLongerNumber(prompt, start, end)) return;
		const precedence = PII_PRECEDENCE[kind] ?? 9;
		const pass = passes.get(precedence) ?? [];
		if (pass.length === 0) passes.set(precedence, pass);
		pass.push({ kind, start, end });
	};
	const matches = PII_DETECTOR.detect(prompt);
	checkpoint();
	for (const match of matches) add(match.type, match.start, match.end);
	const privacy = scanPrivacyWindows(prompt, checkpoint);
	for (const finding of privacy.findings) add(finding.kind, finding.start, finding.end);
	const kept = new DisjointFindings();
	for (const precedence of [...passes.keys()].sort((left, right) => left - right)) {
		kept.addPass(passes.get(precedence) ?? []);
	}
	const reasons = privacy.incompleteReasons;
	return {
		kinds: kept.all.map((finding) => finding.kind),
		...(reasons.length > 0 ? { incomplete: { category: "pii", reasons } } : {}),
	};
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

const PII_INCOMPLETE_NOTICE =
	"could not fully inspect it for personal data (such as ID numbers, IBANs or phone numbers)";

function blockResult(
	blocking: PromptFindingSummary[],
	warning: PromptFindingSummary[],
	partial: boolean,
	incomplete?: PromptIncompleteInspection,
): PromptProtectionResult {
	const userMessage =
		blocking.length > 0
			? `🛡️ Singularity AIDR blocked this prompt before it reached the model: it appears to contain sensitive data (${kindList(blocking)}). Remove the sensitive value and resubmit. If it was a live credential that has been shared anywhere else, rotate it.${
					incomplete ? ` Singularity AIDR also ${PII_INCOMPLETE_NOTICE}.` : ""
				}`
			: `🛡️ Singularity AIDR blocked this prompt before it reached the model: it ${PII_INCOMPLETE_NOTICE}, and your prompt protection policy blocks personal data. Shorten or split the prompt, remove unusual encoded text, and resubmit.`;
	return {
		decision: "block",
		findings: [...blocking, ...warning],
		userMessage,
		...(partial ? { partial: true as const } : {}),
		...(incomplete ? { incomplete } : {}),
	};
}

function warnResult(
	warning: PromptFindingSummary[],
	incomplete?: PromptIncompleteInspection,
): PromptProtectionResult {
	const found =
		warning.length > 0 ? `appears to contain sensitive data (${kindList(warning)})` : "";
	if (!incomplete) {
		return {
			decision: "warn",
			findings: warning,
			userMessage: `🛡️ Singularity AIDR: this prompt ${found}. It was sent to the model.`,
			modelContext: `Singularity AIDR prompt protection notice: the user's prompt ${found}. Do not repeat it, and do not copy it into files, commands, commit messages, web requests or other tools unless the user explicitly asks for that.`,
		};
	}
	const foundSentence = found ? `this prompt ${found}, and ` : "";
	return {
		decision: "warn",
		findings: warning,
		userMessage: `🛡️ Singularity AIDR: ${foundSentence}the personal-data check (ID numbers, IBANs, phone numbers and similar) could not inspect the whole prompt, so it may contain personal data that was not detected. It was sent to the model.`,
		modelContext: `Singularity AIDR prompt protection notice: ${
			found ? `the user's prompt ${found}. The` : "the"
		} personal-data check could not fully inspect the user's prompt, so it may contain personal data (for example ID numbers, IBANs, phone numbers, email or postal addresses) that was not detected. Do not repeat personal data from the prompt, and do not copy it into files, commands, commit messages, web requests or other tools unless the user explicitly asks for that.`,
		incomplete,
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
 *
 * A personal-data scan that could not inspect the whole prompt sets
 * `incomplete`: with PII in `block` mode the prompt is blocked, in `warn` mode
 * it is sent with a user notice and model context saying the check was partial.
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
	let incomplete: PromptIncompleteInspection | undefined;
	if (config.pii !== "off") {
		checkpoint();
		const pii = detectPii(prompt, checkpoint);
		route(config.pii, summaries("pii", countKinds(pii.kinds, PII_KIND_LABELS)));
		incomplete = pii.incomplete;
	}
	// An incomplete PII scan is never a clean one: it blocks under a `block`
	// policy and is sent with a notice under `warn`.
	const localBlock = blocking.length > 0 || (incomplete !== undefined && config.pii === "block");
	if (tenantDlp && !localBlock) {
		checkpoint();
		const tenantFinding = tenantDlpBlock(prompt, tenantDlp);
		if (tenantFinding) blocking.push(tenantFinding);
	}

	if (localBlock || blocking.length > 0) {
		// A local block skips the tenant policy: later categories were not scanned.
		return blockResult(blocking, warning, localBlock && tenantDlp !== undefined, incomplete);
	}
	if (warning.length > 0 || incomplete) return warnResult(warning, incomplete);
	return { decision: "allow", findings: [] };
}
