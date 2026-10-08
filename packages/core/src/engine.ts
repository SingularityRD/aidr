/**
 * Decision engine — combines signals into a final Verdict.
 */

import type {
	AmsiCheckResult,
	Decision,
	FrameworkRefs,
	HeuristicMatch,
	PackageCheckResult,
	PolicyMatch,
	RuleSeverity,
	SignalSources,
	UrlCheckResult,
	Verdict,
	VerdictSeverity,
} from "./types.js";

/** Default confidence threshold. */
export const CONFIDENCE_THRESHOLD = 0.85;

/** Sensitivity presets: maps preset name to confidence threshold. */
const SENSITIVITY_THRESHOLDS: Record<string, number> = {
	paranoid: 0.7,
	balanced: 0.85,
	relaxed: 0.95,
};

/** Severity mapping: 4-level threat def → 3-level user-facing verdict. */
const SEVERITY_MAP: Record<string, VerdictSeverity> = {
	critical: "critical",
	high: "warning",
	medium: "warning",
	low: "info",
};

/** Action mapping: threat def action → verdict decision. */
const ACTION_MAP: Record<string, Decision> = {
	block: "deny",
	require_approval: "ask",
	log: "allow",
};

/**
 * Signal categories that are advisory by design: code-quality findings on code
 * the agent writes (secure-code guardrails, insecure-coding skill hints). A
 * sub-threshold `log` signal in one of these is not escalated to `ask`, so a
 * routine edit does not need a human. Every other category, including any
 * category this list does not know, is security-relevant and still escalates:
 * an unrecognised category must never be rounded down to "clean".
 */
const ADVISORY_CATEGORY_PREFIXES = ["secure_code_"] as const;
const ADVISORY_CATEGORIES: ReadonlySet<string> = new Set([
	"skill_insecure_coding",
	"informational",
	"none",
]);

function isSecurityRelevantCategory(category: string): boolean {
	if (ADVISORY_CATEGORIES.has(category)) return false;
	return !ADVISORY_CATEGORY_PREFIXES.some((prefix) => category.startsWith(prefix));
}

/** Rule severity rank, used to report the most severe of equal-decision signals. */
const RULE_SEVERITY_RANK: Record<RuleSeverity, number> = {
	low: 0,
	medium: 1,
	high: 2,
	critical: 3,
};

function isRuleSeverity(value: unknown): value is RuleSeverity {
	return typeof value === "string" && Object.hasOwn(RULE_SEVERITY_RANK, value);
}

function severityRank(severity: RuleSeverity | undefined): number {
	return severity ? RULE_SEVERITY_RANK[severity] : -1;
}

/** Decision priority for merge precedence: deny > ask > allow. */
const DECISION_PRIORITY: Record<string, number> = {
	allow: 0,
	ask: 1,
	deny: 2,
};

interface Signal {
	decision: Decision;
	category: string;
	confidence: number;
	severity: VerdictSeverity;
	source: string;
	threatId: string | null;
	reason: string;
	artifact: string;
	frameworks?: FrameworkRefs;
	/** The 4-level severity of the rule or policy that produced the signal. */
	ruleSeverity?: RuleSeverity;
}

export class DecisionEngine {
	private readonly threshold: number;

	constructor(sensitivity = "balanced") {
		this.threshold = SENSITIVITY_THRESHOLDS[sensitivity] ?? CONFIDENCE_THRESHOLD;
	}

	async decide(sources: SignalSources): Promise<Verdict> {
		const signals = this.collectSignals(
			sources.heuristicMatches,
			sources.policyMatches,
			sources.urlCheckResults,
			sources.packageCheckResults,
			sources.amsiCheckResults,
		);

		if (signals.length === 0) {
			return this.allowVerdict();
		}

		// The confidence threshold is applied to each signal on its own, then
		// the per-signal decisions are merged (deny > ask > allow). Using the
		// maximum confidence across unrelated signals let one confident advisory
		// finding keep a weak deny at deny, or suppress the escalation of a weak
		// security signal.
		const decided = signals.map((signal) => ({
			signal,
			decision: this.effectiveDecision(signal),
		}));

		// Strongest decision first; among equal decisions the most severe rule
		// (stable otherwise), so the reported rule id and severity label describe
		// the same, most significant finding.
		decided.sort(
			(a, b) =>
				(DECISION_PRIORITY[b.decision] ?? 0) - (DECISION_PRIORITY[a.decision] ?? 0) ||
				severityRank(b.signal.ruleSeverity) - severityRank(a.signal.ruleSeverity),
		);
		const first = decided[0];
		if (!first) {
			return this.allowVerdict();
		}
		const top = first.signal;
		const decision = first.decision;

		const allArtifacts = [...new Map(signals.map((s) => [s.artifact, s.artifact])).values()];
		const allReasons = [...new Map(signals.map((s) => [s.reason, s.reason])).values()];
		// The reported confidence describes the signals that set the decision.
		const confidence = Math.max(
			...decided
				.filter((entry) => entry.decision === decision)
				.map((entry) => entry.signal.confidence),
		);

		return {
			decision,
			category: top.category,
			confidence,
			severity: top.severity,
			source: top.source,
			artifacts: allArtifacts,
			matchedThreatId: top.threatId,
			reasons: allReasons,
			...(top.ruleSeverity ? { ruleSeverity: top.ruleSeverity } : {}),
			...(top.frameworks ? { frameworks: top.frameworks } : {}),
		};
	}

	/**
	 * One signal's decision under the confidence threshold: a sub-threshold
	 * deny is held for review (`ask`); a sub-threshold `log` signal in a
	 * security-relevant category is escalated to `ask`. Advisory findings
	 * (secure-code hints on written code) are logged, not held for a human:
	 * holding routine edits for review trains users to approve blindly.
	 */
	private effectiveDecision(signal: Signal): Decision {
		if (signal.confidence >= this.threshold) return signal.decision;
		if (signal.decision === "deny") return "ask";
		if (signal.decision === "allow" && isSecurityRelevantCategory(signal.category)) return "ask";
		return signal.decision;
	}

	private collectSignals(
		heuristicMatches: HeuristicMatch[],
		policyMatches: PolicyMatch[] | undefined,
		urlCheckResults: UrlCheckResult[],
		packageCheckResults?: PackageCheckResult[],
		amsiCheckResults?: AmsiCheckResult[],
	): Signal[] {
		const signals: Signal[] = [];

		for (const match of heuristicMatches) {
			signals.push({
				decision: ACTION_MAP[match.threat.action] ?? "ask",
				category: match.threat.category,
				confidence: match.threat.confidence,
				severity: SEVERITY_MAP[match.threat.severity] ?? "warning",
				source: "heuristic",
				threatId: match.threat.id,
				reason: match.threat.title,
				artifact: match.artifact,
				...(isRuleSeverity(match.threat.severity) ? { ruleSeverity: match.threat.severity } : {}),
				...(match.threat.frameworks ? { frameworks: match.threat.frameworks } : {}),
			});
		}

		if (policyMatches) {
			for (const match of policyMatches) {
				signals.push({
					decision:
						match.action === "block"
							? "deny"
							: match.action === "require_approval"
								? "ask"
								: "allow",
					category: match.category,
					confidence: match.confidence,
					severity: SEVERITY_MAP[match.severity] ?? "warning",
					source: "policy",
					threatId: match.policyId,
					reason: match.title,
					artifact: match.artifact,
					...(isRuleSeverity(match.severity) ? { ruleSeverity: match.severity } : {}),
				});
			}
		}

		for (const result of urlCheckResults) {
			if (result.isMalicious) {
				const findingDetails = result.findings
					.map((f) => `${f.severityName}/${f.typeName}`)
					.join(", ");
				signals.push({
					decision: "deny",
					category: "network_egress",
					confidence: 1.0,
					severity: "critical",
					source: "url_check",
					threatId: null,
					reason: `Malicious URL (${findingDetails})`,
					artifact: result.url,
				});
			}

			for (const flag of result.flags) {
				signals.push({
					decision: "ask",
					category: "network_egress",
					confidence: 0.75,
					severity: "warning",
					source: "url_check",
					threatId: null,
					reason: `Suspicious URL: ${flag}`,
					artifact: result.url,
				});
			}
		}

		if (packageCheckResults) {
			for (const pkg of packageCheckResults) {
				if (pkg.verdict === "clean") continue;

				const signal = this.packageVerdictToSignal(pkg);
				if (signal) signals.push(signal);
			}
		}

		if (amsiCheckResults) {
			for (const result of amsiCheckResults) {
				if (result.isDetected) {
					signals.push({
						decision: "deny",
						category: "malware",
						confidence: 1.0,
						severity: "critical",
						source: "amsi",
						threatId: null,
						reason: `AMSI detected malware in ${result.contentName} (result=${result.amsiResult})`,
						artifact: result.contentName,
					});
				} else if (result.isBlockedByAdmin) {
					signals.push({
						decision: "deny",
						category: "malware",
						confidence: 0.9,
						severity: "critical",
						source: "amsi",
						threatId: null,
						reason: `AMSI: content blocked by admin policy in ${result.contentName} (result=${result.amsiResult})`,
						artifact: result.contentName,
					});
				}
			}
		}

		return signals;
	}

	private packageVerdictToSignal(pkg: PackageCheckResult): Signal | null {
		switch (pkg.verdict) {
			case "not_found":
				return {
					decision: "deny",
					category: "supply_chain",
					confidence: 0.95,
					severity: "critical",
					source: "package_check",
					threatId: null,
					reason: pkg.details,
					artifact: pkg.packageName,
				};
			case "malicious":
				return {
					decision: "deny",
					category: "supply_chain",
					confidence: 1.0,
					severity: "critical",
					source: "package_check",
					threatId: null,
					reason: pkg.details,
					artifact: pkg.packageName,
				};
			case "suspicious_age":
				return {
					decision: "ask",
					category: "supply_chain",
					confidence: 0.75,
					severity: "warning",
					source: "package_check",
					threatId: null,
					reason: pkg.details,
					artifact: pkg.packageName,
				};
			case "unknown":
				return {
					decision: "ask",
					category: "supply_chain",
					confidence: 0.6,
					severity: "warning",
					source: "package_check",
					threatId: null,
					reason: pkg.details,
					artifact: pkg.packageName,
				};
			default:
				return null;
		}
	}

	private allowVerdict(): Verdict {
		return {
			decision: "allow",
			category: "none",
			confidence: 1.0,
			severity: "info",
			source: "none",
			artifacts: [],
			matchedThreatId: null,
			reasons: [],
		};
	}
}
