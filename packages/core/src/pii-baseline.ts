/**
 * Built-in common-PII baseline for tenant DLP.
 *
 * When a tenant DLP policy is active, tool input is also checked for common
 * PII (SSN, payment card, email, phone) even if the tenant wrote no rule for
 * it. Each PII type is addressable by a reserved rule id, `pii-<type>`, so the
 * tenant policy stays the authority over the baseline:
 *
 * - A policy rule with that id overrides the baseline for its type. A disabled
 *   rule, or one whose `directions` exclude the scanned direction, turns the
 *   baseline for that type off; otherwise the rule's `action` applies
 *   (`ask` asks, `block` and `redact` deny — a verdict cannot rewrite input).
 * - An active exception for that rule id (scope `rule`, `content` or `match`,
 *   using the same fingerprints as tenant rules) suppresses the finding.
 * - With no such rule the baseline blocks.
 *
 * Matches pass the precision checks in `pii-precision.ts` first, so an epoch
 * timestamp or an order id is never reported as a phone number or SSN.
 */
import {
	type DlpDirection,
	type DlpException,
	type DlpPolicy,
	type DlpRule,
	isDlpExceptionActive,
} from "./dlp/policy.js";
import { createDlpContentFingerprint, createDlpMatchFingerprint } from "./dlp/scanner.js";
import { detectPreciseCommonPii } from "./pii-precision.js";

export const COMMON_PII_TYPES = ["ssn", "credit_card", "email", "phone"] as const;
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
	appliedExceptionIds: string[];
}

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

/** `deny` outranks `ask`; the earlier finding wins a tie. */
function stronger(
	current: CommonPiiBaselineFinding | null,
	candidate: CommonPiiBaselineFinding,
): CommonPiiBaselineFinding {
	return !current || (current.decision === "ask" && candidate.decision === "deny")
		? candidate
		: current;
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

	for (const match of detectPreciseCommonPii(content)) {
		if (!isCommonPiiType(match.type)) continue;
		const ruleId = commonPiiRuleId(match.type);
		const rule = rules.get(ruleId);
		if (isBaselineTypeDisabled(rule, direction)) continue;
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
		strongest = stronger(strongest, {
			decision: action === "ask" ? "ask" : "deny",
			type: match.type,
			ruleId,
			action,
		});
	}
	return { finding: strongest, appliedExceptionIds: [...applied].sort() };
}
