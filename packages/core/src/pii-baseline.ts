/**
 * Built-in common-PII baseline for tenant DLP.
 *
 * When a tenant DLP policy is active, tool input is also checked for common
 * PII (SSN, payment card, email, phone, and the checksum-validated TC Kimlik
 * and IBAN from the AIDR Privacy rules) even if the tenant wrote no rule for
 * it. Each PII type is addressable by a reserved rule id, `pii-<type>`, so the
 * tenant policy stays the authority over the baseline:
 *
 * - A policy rule with that id overrides the baseline for its type. A disabled
 *   rule, or one whose `directions` exclude the scanned direction, turns the
 *   baseline for that type off; otherwise the rule's `action` applies
 *   (`ask` asks, `block` denies). `redact` masks the value with a typed
 *   placeholder (`maskCommonPiiInToolInput`) when the connector executes a
 *   rewritten input and every surviving finding is `redact`; anywhere else a
 *   `redact` finding denies, because passing the original would disclose it.
 * - An active exception for that rule id (scope `rule`, `content` or `match`,
 *   using the same fingerprints as tenant rules) suppresses the finding.
 * - With no such rule the baseline blocks.
 *
 * Matches pass the precision checks in `pii-precision.ts` first, so an epoch
 * timestamp or an order id is never reported as a phone number or SSN.
 */

import { maskPiiInToolInput, type PiiMaskResult, type PiiMaskSpan } from "./dlp/pii-masking.js";
import {
	type DlpDirection,
	type DlpException,
	type DlpPolicy,
	type DlpRule,
	isDlpExceptionActive,
} from "./dlp/policy.js";
import { scanPrivacyDetectors } from "./dlp/privacy-detectors.js";
import { createDlpContentFingerprint, createDlpMatchFingerprint } from "./dlp/scanner.js";
import { detectPreciseCommonPii } from "./pii-precision.js";

export const COMMON_PII_TYPES = [
	"ssn",
	"credit_card",
	"email",
	"phone",
	"tc_kimlik",
	"iban",
] as const;
export type CommonPiiType = (typeof COMMON_PII_TYPES)[number];

/** Reserved DLP rule id that governs one built-in PII type. */
export function commonPiiRuleId(type: CommonPiiType): string {
	return `pii-${type}`;
}

export interface CommonPiiBaselineFinding {
	decision: "deny" | "ask";
	type: CommonPiiType;
	ruleId: string;
	/** The governing tenant rule action; `block` when the baseline default applied. */
	action: "block" | "ask" | "redact";
}

export interface CommonPiiBaselineResult {
	/** Strongest surviving finding, or null when every match is allowed by policy. */
	finding: CommonPiiBaselineFinding | null;
	/** True when there is a finding and every surviving finding's rule action is `redact`. */
	redactOnly: boolean;
	appliedExceptionIds: string[];
}

/** Browser Guard placeholder prefixes, e.g. `[TCKN_1]`. */
export const COMMON_PII_PLACEHOLDER_LABEL: Readonly<Record<CommonPiiType, string>> = {
	ssn: "SSN",
	credit_card: "CARD",
	email: "EMAIL",
	phone: "PHONE",
	tc_kimlik: "TCKN",
	iban: "IBAN",
};

function isCommonPiiType(type: string): type is CommonPiiType {
	return (COMMON_PII_TYPES as readonly string[]).includes(type);
}

/** A reserved rule that is disabled or excludes this direction turns its type off. */
function isBaselineTypeDisabled(rule: DlpRule | undefined, direction: DlpDirection): boolean {
	return (
		rule !== undefined &&
		(rule.enabled === false || !(rule.directions ?? ["input", "output"]).includes(direction))
	);
}

interface GovernedMatch {
	type: CommonPiiType;
	ruleId: string;
	rule: DlpRule | undefined;
}

/** The reserved rule governing `match`, or null when its type is not checked here. */
function governingRule(
	rules: ReadonlyMap<string, DlpRule>,
	match: { type: string },
	direction: DlpDirection,
): GovernedMatch | null {
	if (!isCommonPiiType(match.type)) return null;
	const ruleId = commonPiiRuleId(match.type);
	const rule = rules.get(ruleId);
	return isBaselineTypeDisabled(rule, direction) ? null : { type: match.type, ruleId, rule };
}

/** Same scopes and fingerprints as `scanDlpContent` uses for tenant rules. */
function findException(
	exceptions: readonly DlpException[],
	tenantId: string,
	ruleId: string,
	value: string,
	contentFingerprint: () => string,
): DlpException | undefined {
	const candidates = exceptions.filter((exception) => exception.ruleId === ruleId);
	if (candidates.length === 0) return undefined;
	const matchFingerprint = createDlpMatchFingerprint(tenantId, ruleId, value);
	return candidates.find(
		(candidate) =>
			candidate.scope === "rule" ||
			(candidate.scope === "content" && candidate.fingerprint === contentFingerprint()) ||
			(candidate.scope === "match" && candidate.fingerprint === matchFingerprint),
	);
}

/**
 * `deny` outranks `ask`, and a `block` deny outranks a `redact` deny (which a
 * rewriting connector may resolve by masking); the earlier finding wins a tie.
 */
function stronger(
	current: CommonPiiBaselineFinding | null,
	candidate: CommonPiiBaselineFinding,
): CommonPiiBaselineFinding {
	return !current ||
		(current.decision === "ask" && candidate.decision === "deny") ||
		(candidate.decision === "deny" && current.action === "redact" && candidate.action === "block")
		? candidate
		: current;
}

interface CommonPiiMatch {
	type: string;
	value: string;
	start: number;
	end: number;
}

/** Precise common PII plus checksum-validated TC Kimlik / IBAN (mod-97). */
function commonPiiMatches(content: string): { matches: CommonPiiMatch[]; incomplete: boolean } {
	const matches: CommonPiiMatch[] = detectPreciseCommonPii(content).map((match) => ({
		type: match.type,
		value: match.value,
		start: match.start,
		end: match.end,
	}));
	const privacy = scanPrivacyDetectors(content, ["tc_kimlik", "iban"]);
	for (const match of privacy.matches) {
		matches.push({
			type: match.detector,
			value: content.slice(match.start, match.end),
			start: match.start,
			end: match.end,
		});
	}
	return { matches, incomplete: privacy.incomplete };
}

/** Normalized value so that repeats of one value share a placeholder. */
function placeholderKey(type: CommonPiiType, value: string): string {
	return type === "email" ? value.toLowerCase() : value.replace(/[^0-9A-Za-z]/g, "").toUpperCase();
}

/**
 * Evaluate the common-PII baseline against one tenant policy. The raw match is
 * used only to compute a tenant- and rule-bound fingerprint; it is never
 * returned.
 */
export function evaluateCommonPiiBaseline(
	policy: DlpPolicy,
	content: string,
	options: { direction?: DlpDirection; now?: Date } = {},
): CommonPiiBaselineResult {
	const direction = options.direction ?? "input";
	const now = options.now ?? new Date();
	const rules = new Map(policy.rules.map((rule) => [rule.id, rule]));
	const exceptions = (policy.exceptions ?? []).filter((exception) =>
		isDlpExceptionActive(exception, now),
	);
	let contentFingerprint: string | undefined;
	const lazyContentFingerprint = () => {
		contentFingerprint ??= createDlpContentFingerprint(policy.tenantId, content);
		return contentFingerprint;
	};
	const applied = new Set<string>();
	let strongest: CommonPiiBaselineFinding | null = null;
	let redactOnly = true;

	for (const match of commonPiiMatches(content).matches) {
		const governed = governingRule(rules, match, direction);
		if (!governed) continue;
		const { type, ruleId, rule } = governed;
		const exception = findException(
			exceptions,
			policy.tenantId,
			ruleId,
			match.value,
			lazyContentFingerprint,
		);
		if (exception) {
			applied.add(exception.id);
			continue;
		}
		const action = rule?.action ?? "block";
		if (action !== "redact") redactOnly = false;
		strongest = stronger(strongest, {
			decision: action === "ask" ? "ask" : "deny",
			type,
			ruleId,
			action,
		});
	}
	return {
		finding: strongest,
		redactOnly: strongest !== null && redactOnly,
		appliedExceptionIds: [...applied].sort(),
	};
}

/**
 * Mask the common PII that `policy` says to redact in a tool input (see
 * `dlp/pii-masking.ts` for which fields may be rewritten). Values whose type is
 * disabled for input or covered by a rule- or match-scoped exception are left
 * alone, as the baseline allows them. Returns null when the input cannot be
 * rewritten safely, a value is governed by a non-`redact` action, or detection
 * was incomplete. The caller must re-scan the result before using it.
 */
export function maskCommonPiiInToolInput(
	policy: DlpPolicy,
	input: Record<string, unknown>,
	options: { now?: Date } = {},
): PiiMaskResult | null {
	const now = options.now ?? new Date();
	const rules = new Map(policy.rules.map((rule) => [rule.id, rule]));
	const exceptions = (policy.exceptions ?? []).filter(
		(exception) => isDlpExceptionActive(exception, now) && exception.scope !== "content",
	);
	let blocked = false;
	const result = maskPiiInToolInput(input, (text) => {
		const { matches, incomplete } = commonPiiMatches(text);
		if (incomplete) return null;
		const spans: PiiMaskSpan[] = [];
		for (const match of matches) {
			const governed = governingRule(rules, match, "input");
			// Content-scoped exceptions fingerprint the whole call; masking changes
			// it, so they are not honoured here and the residual re-scan decides.
			if (
				!governed ||
				findException(exceptions, policy.tenantId, governed.ruleId, match.value, () => "")
			) {
				continue;
			}
			if (governed.rule?.action !== "redact") {
				blocked = true;
				continue;
			}
			spans.push({
				start: match.start,
				end: match.end,
				label: COMMON_PII_PLACEHOLDER_LABEL[governed.type],
				key: placeholderKey(governed.type, match.value),
			});
		}
		return spans;
	});
	return blocked ? null : result;
}
