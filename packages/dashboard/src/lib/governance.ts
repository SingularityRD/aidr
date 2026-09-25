/**
 * AI governance scorecard read model (docs/ai-governance-frameworks.md).
 *
 * The `governance_scorecard` RPC returns counts computed from the workspace's own
 * records. This module validates that answer strictly (a malformed or partial
 * answer is shown as unavailable, never as zeros), computes framework coverage
 * from the embedded control mapping (governance/frameworks/*.yaml) and the
 * tenant's deployment signals, and derives the "top risks" list from the same
 * numbers. Nothing here invents a value: every figure on the page traces back to
 * a field of the RPC answer.
 */

import {
	GOVERNANCE_MAPPING,
	type GovernanceControl,
	type GovernanceFramework,
} from "./governance-frameworks.generated";
import { supabase } from "./supabase";
import { errorCode } from "./workspace-settings";

export const GOVERNANCE_WINDOWS = [7, 30, 90] as const;
export type GovernanceWindow = (typeof GOVERNANCE_WINDOWS)[number];

export type GovernanceResult<T> = { ok: true; value: T } | { ok: false; error: string };

class Malformed extends Error {
	constructor(readonly path: string) {
		super(`Malformed governance scorecard at ${path}`);
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function rec(value: unknown, path: string): Record<string, unknown> {
	if (!isRecord(value)) throw new Malformed(path);
	return value;
}
function count(value: unknown, path: string): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
		throw new Malformed(path);
	return value;
}
function num(value: unknown, path: string, nullable = false): number | null {
	if (value === null && nullable) return null;
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Malformed(path);
	return value;
}
function bool(value: unknown, path: string): boolean {
	if (typeof value !== "boolean") throw new Malformed(path);
	return value;
}
function text(value: unknown, path: string, pattern: RegExp, nullable = false): string | null {
	if (value === null && nullable) return null;
	if (typeof value !== "string" || !pattern.test(value)) throw new Malformed(path);
	return value;
}
function instant(value: unknown, path: string, nullable = false): string | null {
	if (value === null && nullable) return null;
	if (typeof value !== "string" || value.length > 40 || !Number.isFinite(Date.parse(value))) {
		throw new Malformed(path);
	}
	return value;
}
function list<T>(
	value: unknown,
	path: string,
	parse: (item: Record<string, unknown>, at: string) => T,
): T[] {
	if (!Array.isArray(value)) throw new Malformed(path);
	return value.map((item, index) => parse(rec(item, `${path}[${index}]`), `${path}[${index}]`));
}

const SLUG = /^[a-z0-9_.-]{1,64}$/;
const SITE = /^[a-z0-9_-]{1,32}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const NOTICE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s<>"]{1,254}$/;
const CADENCE = /^(weekly|monthly)$/;
const RECIPIENTS = /^(owners|owners_admins)$/;
const DELIVERY_STATUS = /^(sent|partial|failed|no_transport|no_recipients)$/;

export const SIGNAL_KEYS = [
	"agents_reporting",
	"browser_guard_reporting",
	"dlp_policy_configured",
	"runtime_policy_configured",
	"human_approval_in_use",
	"acceptable_use_acknowledged",
	"mcp_inventory_reported",
	"posture_reported",
	"mfa_required",
	"retention_configured",
	"compliance_report_generated",
	"governance_digest_enabled",
] as const;
export type SignalKey = (typeof SIGNAL_KEYS)[number];

export interface PolicyAge {
	version: number | null;
	updatedAt: string;
	ageDays: number;
}

export interface Approver {
	userId: string;
	email: string | null;
	decisions: number;
	approved: number;
	denied: number;
	fastApprovals: number;
	medianSeconds: number | null;
	review: boolean;
}

export interface GovernanceSettings {
	digestEnabled: boolean;
	digestCadence: "weekly" | "monthly";
	digestRecipients: "owners" | "owners_admins";
	digestNextAt: string | null;
	digestLastAt: string | null;
	digestLastStatus: string | null;
	oversightFastSeconds: number;
	oversightMinDecisions: number;
	oversightFastShare: number;
}

export interface GovernanceScorecard {
	windowDays: GovernanceWindow;
	generatedAt: string;
	period: { from: string; to: string; days: number };
	usage: {
		agents: { enrolled: number; active: number };
		browserInstalls: { enrolled: number; active: number };
		byRuntime: Array<{ runtime: string; enrolled: number; active: number }>;
		aiSites: { distinct: number; bySite: Array<{ site: string; scans: number; blocked: number }> };
		mcpServers: { distinct: number; notApproved: number };
	};
	decisions: {
		allow: number;
		ask: number;
		deny: number;
		releasedByOperator: number;
		releasedByDashboard: number;
		releasedOther: number;
	};
	trend: Array<{
		day: string;
		allow: number;
		ask: number;
		deny: number;
		masked: number;
		blocked: number;
	}>;
	approvals: {
		requested: number;
		approved: number;
		denied: number;
		expiredWithoutDecision: number;
		pending: number;
		medianDecisionSeconds: number | null;
		p90DecisionSeconds: number | null;
	};
	oversight: {
		thresholds: { fastSeconds: number; minDecisions: number; fastShare: number };
		approvers: number;
		reviewPrompts: number;
		byApprover: Approver[];
	};
	incidents: {
		reported: number;
		open: number;
		statusUnknown: number;
		openBySeverity: {
			critical: number;
			high: number;
			warning: number;
			info: number;
			unknown: number;
		};
	};
	browserGuard: {
		scans: number;
		masked: number;
		warned: number;
		blocked: number;
		allowed: number;
		itemsMasked: number;
	};
	policies: {
		runtime: PolicyAge | null;
		dlp: PolicyAge | null;
		team: PolicyAge | null;
		runtimeRevisionsInPeriod: number;
		dlpRevisionsInPeriod: number;
	};
	identity: {
		requireMfa: boolean;
		ssoRequired: boolean;
		scimActiveTokens: number;
		ownersAdmins: number;
		ownersAdminsWithoutMfa: number;
		retentionPolicies: number;
		telemetryRetentionDays: number | null;
		legalHoldActive: boolean;
	};
	posture: { findings: number; critical: number; high: number; cveConfirmed: number };
	acceptableUse: Array<{
		noticeId: string;
		noticeVersion: number;
		installs: number;
		lastAcknowledgedAt: string;
	}>;
	signals: Record<SignalKey, boolean>;
	settings: GovernanceSettings;
	recentDeliveries: Array<{
		createdAt: string;
		trigger: "schedule" | "test";
		cadence: string;
		periodFrom: string;
		periodTo: string;
		status: string;
		recipients: number;
		delivered: number;
	}>;
}

function policyAge(value: unknown, path: string): PolicyAge | null {
	if (value === null || value === undefined) return null;
	const row = rec(value, path);
	return {
		version: row.version === undefined ? null : count(row.version, `${path}.version`),
		updatedAt: instant(row.updated_at, `${path}.updated_at`) as string,
		ageDays: count(row.age_days, `${path}.age_days`),
	};
}

/** Validate a `governance_scorecard` answer for the requested window. */
export function parseGovernanceScorecard(
	value: unknown,
	windowDays: GovernanceWindow,
): GovernanceScorecard {
	const root = rec(value, "$");
	if (root.window_days !== windowDays) throw new Malformed("window_days");
	const period = rec(root.period, "period");
	const usage = rec(root.usage, "usage");
	const agents = rec(usage.agents, "usage.agents");
	const browser = rec(usage.browser_installs, "usage.browser_installs");
	const sites = rec(usage.ai_sites, "usage.ai_sites");
	const mcp = rec(usage.mcp_servers, "usage.mcp_servers");
	const decisions = rec(root.decisions, "decisions");
	const approvals = rec(root.approvals, "approvals");
	const oversight = rec(root.oversight, "oversight");
	const thresholds = rec(oversight.thresholds, "oversight.thresholds");
	const incidents = rec(root.incidents, "incidents");
	const bySeverity = rec(incidents.open_by_severity, "incidents.open_by_severity");
	const guard = rec(root.browser_guard, "browser_guard");
	const policies = rec(root.policies, "policies");
	const identity = rec(root.identity, "identity");
	const posture = rec(root.posture, "posture");
	const aup = rec(root.acceptable_use, "acceptable_use");
	const signals = rec(root.signals, "signals");
	const settings = rec(root.settings, "settings");
	const trend = list(root.trend, "trend", (row, at) => ({
		day: text(row.day, `${at}.day`, DAY) as string,
		allow: count(row.allow, `${at}.allow`),
		ask: count(row.ask, `${at}.ask`),
		deny: count(row.deny, `${at}.deny`),
		masked: count(row.masked, `${at}.masked`),
		blocked: count(row.blocked, `${at}.blocked`),
	}));
	if (trend.length !== windowDays) throw new Malformed("trend");
	return {
		windowDays,
		generatedAt: instant(root.generated_at, "generated_at") as string,
		period: {
			from: instant(period.from, "period.from") as string,
			to: instant(period.to, "period.to") as string,
			days: count(period.days, "period.days"),
		},
		usage: {
			agents: {
				enrolled: count(agents.enrolled, "agents.enrolled"),
				active: count(agents.active, "agents.active"),
			},
			browserInstalls: {
				enrolled: count(browser.enrolled, "browser.enrolled"),
				active: count(browser.active, "browser.active"),
			},
			byRuntime: list(usage.by_runtime, "usage.by_runtime", (row, at) => ({
				runtime: text(row.runtime, `${at}.runtime`, SLUG) as string,
				enrolled: count(row.enrolled, `${at}.enrolled`),
				active: count(row.active, `${at}.active`),
			})),
			aiSites: {
				distinct: count(sites.distinct, "ai_sites.distinct"),
				bySite: list(sites.by_site, "ai_sites.by_site", (row, at) => ({
					site: text(row.site, `${at}.site`, SITE) as string,
					scans: count(row.scans, `${at}.scans`),
					blocked: count(row.blocked, `${at}.blocked`),
				})),
			},
			mcpServers: {
				distinct: count(mcp.distinct, "mcp.distinct"),
				notApproved: count(mcp.not_approved, "mcp.not_approved"),
			},
		},
		decisions: {
			allow: count(decisions.allow, "decisions.allow"),
			ask: count(decisions.ask, "decisions.ask"),
			deny: count(decisions.deny, "decisions.deny"),
			releasedByOperator: count(decisions.released_by_operator, "decisions.released_by_operator"),
			releasedByDashboard: count(
				decisions.released_by_dashboard,
				"decisions.released_by_dashboard",
			),
			releasedOther: count(decisions.released_other, "decisions.released_other"),
		},
		trend,
		approvals: {
			requested: count(approvals.requested, "approvals.requested"),
			approved: count(approvals.approved, "approvals.approved"),
			denied: count(approvals.denied, "approvals.denied"),
			expiredWithoutDecision: count(
				approvals.expired_without_decision,
				"approvals.expired_without_decision",
			),
			pending: count(approvals.pending, "approvals.pending"),
			medianDecisionSeconds: num(approvals.median_decision_seconds, "approvals.median", true),
			p90DecisionSeconds: num(approvals.p90_decision_seconds, "approvals.p90", true),
		},
		oversight: {
			thresholds: {
				fastSeconds: count(thresholds.fast_seconds, "thresholds.fast_seconds"),
				minDecisions: count(thresholds.min_decisions, "thresholds.min_decisions"),
				fastShare: num(thresholds.fast_share, "thresholds.fast_share") as number,
			},
			approvers: count(oversight.approvers, "oversight.approvers"),
			reviewPrompts: count(oversight.review_prompts, "oversight.review_prompts"),
			byApprover: list(oversight.by_approver, "oversight.by_approver", (row, at) => ({
				userId: text(row.user_id, `${at}.user_id`, UUID) as string,
				email: text(row.email, `${at}.email`, EMAIL, true),
				decisions: count(row.decisions, `${at}.decisions`),
				approved: count(row.approved, `${at}.approved`),
				denied: count(row.denied, `${at}.denied`),
				fastApprovals: count(row.fast_approvals, `${at}.fast_approvals`),
				medianSeconds: num(row.median_seconds, `${at}.median_seconds`, true),
				review: bool(row.review, `${at}.review`),
			})),
		},
		incidents: {
			reported: count(incidents.reported, "incidents.reported"),
			open: count(incidents.open, "incidents.open"),
			statusUnknown: count(incidents.status_unknown, "incidents.status_unknown"),
			openBySeverity: {
				critical: count(bySeverity.critical, "severity.critical"),
				high: count(bySeverity.high, "severity.high"),
				warning: count(bySeverity.warning, "severity.warning"),
				info: count(bySeverity.info, "severity.info"),
				unknown: count(bySeverity.unknown, "severity.unknown"),
			},
		},
		browserGuard: {
			scans: count(guard.scans, "browser_guard.scans"),
			masked: count(guard.masked, "browser_guard.masked"),
			warned: count(guard.warned, "browser_guard.warned"),
			blocked: count(guard.blocked, "browser_guard.blocked"),
			allowed: count(guard.allowed, "browser_guard.allowed"),
			itemsMasked: count(guard.items_masked, "browser_guard.items_masked"),
		},
		policies: {
			runtime: policyAge(policies.runtime, "policies.runtime"),
			dlp: policyAge(policies.dlp, "policies.dlp"),
			team: policyAge(policies.team, "policies.team"),
			runtimeRevisionsInPeriod: count(
				policies.runtime_revisions_in_period,
				"policies.runtime_revisions",
			),
			dlpRevisionsInPeriod: count(policies.dlp_revisions_in_period, "policies.dlp_revisions"),
		},
		identity: {
			requireMfa: bool(identity.require_mfa, "identity.require_mfa"),
			ssoRequired: bool(identity.sso_required, "identity.sso_required"),
			scimActiveTokens: count(identity.scim_active_tokens, "identity.scim_active_tokens"),
			ownersAdmins: count(identity.owners_admins, "identity.owners_admins"),
			ownersAdminsWithoutMfa: count(identity.owners_admins_without_mfa, "identity.without_mfa"),
			retentionPolicies: count(identity.retention_policies, "identity.retention_policies"),
			telemetryRetentionDays:
				identity.telemetry_retention_days === null
					? null
					: count(identity.telemetry_retention_days, "identity.telemetry_retention_days"),
			legalHoldActive: bool(identity.legal_hold_active, "identity.legal_hold_active"),
		},
		posture: {
			findings: count(posture.findings, "posture.findings"),
			critical: count(posture.critical, "posture.critical"),
			high: count(posture.high, "posture.high"),
			cveConfirmed: count(posture.cve_confirmed, "posture.cve_confirmed"),
		},
		acceptableUse: list(aup.versions, "acceptable_use.versions", (row, at) => ({
			noticeId: text(row.notice_id, `${at}.notice_id`, NOTICE) as string,
			noticeVersion: count(row.notice_version, `${at}.notice_version`),
			installs: count(row.installs, `${at}.installs`),
			lastAcknowledgedAt: instant(row.last_acknowledged_at, `${at}.last_acknowledged_at`) as string,
		})),
		signals: Object.fromEntries(
			SIGNAL_KEYS.map((key) => [key, bool(signals[key], `signals.${key}`)]),
		) as Record<SignalKey, boolean>,
		settings: parseSettings(settings),
		recentDeliveries: list(root.recent_deliveries, "recent_deliveries", (row, at) => ({
			createdAt: instant(row.created_at, `${at}.created_at`) as string,
			trigger: text(row.trigger, `${at}.trigger`, /^(schedule|test)$/) as "schedule" | "test",
			cadence: text(row.cadence, `${at}.cadence`, CADENCE) as string,
			periodFrom: instant(row.period_from, `${at}.period_from`) as string,
			periodTo: instant(row.period_to, `${at}.period_to`) as string,
			status: text(row.status, `${at}.status`, DELIVERY_STATUS) as string,
			recipients: count(row.recipients, `${at}.recipients`),
			delivered: count(row.delivered, `${at}.delivered`),
		})),
	};
}

export function parseSettings(settings: Record<string, unknown>): GovernanceSettings {
	return {
		digestEnabled: bool(settings.digest_enabled, "settings.digest_enabled"),
		digestCadence: text(settings.digest_cadence, "settings.digest_cadence", CADENCE) as
			| "weekly"
			| "monthly",
		digestRecipients: text(settings.digest_recipients, "settings.digest_recipients", RECIPIENTS) as
			| "owners"
			| "owners_admins",
		digestNextAt: instant(settings.digest_next_at, "settings.digest_next_at", true),
		digestLastAt: instant(settings.digest_last_at, "settings.digest_last_at", true),
		digestLastStatus: text(
			settings.digest_last_status,
			"settings.digest_last_status",
			DELIVERY_STATUS,
			true,
		),
		oversightFastSeconds: count(settings.oversight_fast_seconds, "settings.oversight_fast_seconds"),
		oversightMinDecisions: count(
			settings.oversight_min_decisions,
			"settings.oversight_min_decisions",
		),
		oversightFastShare: num(
			settings.oversight_fast_share,
			"settings.oversight_fast_share",
		) as number,
	};
}

// ── Framework coverage ─────────────────────────────────────────────────────

export type ControlStatus =
	| "in_place"
	| "partly_in_place"
	| "not_deployed"
	| "not_observable"
	| "customer";

export interface ControlAssessment {
	control: GovernanceControl;
	status: ControlStatus;
	/** Fraction of the mapped, observable capabilities the workspace has deployed. */
	deployed: number;
}

export interface FrameworkCoverage {
	framework: GovernanceFramework;
	controls: ControlAssessment[];
	/** Product-supported coverage in place: full = 1, partial = 0.5, times `deployed`. */
	inPlacePercent: number;
	/** The same weighting if every mapped capability were deployed. */
	availablePercent: number;
	counts: Record<ControlStatus, number>;
}

const CAPABILITY_SIGNAL = new Map(GOVERNANCE_MAPPING.capabilities.map((c) => [c.id, c.signal]));
const COVERAGE_WEIGHT = { full: 1, partial: 0.5, "customer-responsibility": 0 } as const;

function assess(
	control: GovernanceControl,
	signals: Record<SignalKey, boolean>,
): ControlAssessment {
	if (control.coverage === "customer-responsibility")
		return { control, status: "customer", deployed: 0 };
	const observable = control.capabilities
		.map((id) => CAPABILITY_SIGNAL.get(id))
		.filter((signal): signal is string => typeof signal === "string" && signal !== "local_only");
	if (observable.length === 0) return { control, status: "not_observable", deployed: 0 };
	const deployedCount = observable.filter(
		(signal) => signal === "always" || signals[signal as SignalKey] === true,
	).length;
	const deployed = deployedCount / observable.length;
	const status: ControlStatus =
		deployed === 1 ? "in_place" : deployed > 0 ? "partly_in_place" : "not_deployed";
	return { control, status, deployed };
}

export function frameworkCoverage(
	signals: Record<SignalKey, boolean>,
	frameworks: readonly GovernanceFramework[] = GOVERNANCE_MAPPING.frameworks,
): FrameworkCoverage[] {
	return frameworks.map((framework) => {
		const controls = framework.controls.map((control) => assess(control, signals));
		const counts: Record<ControlStatus, number> = {
			in_place: 0,
			partly_in_place: 0,
			not_deployed: 0,
			not_observable: 0,
			customer: 0,
		};
		let inPlace = 0;
		let available = 0;
		for (const item of controls) {
			counts[item.status] += 1;
			const weight = COVERAGE_WEIGHT[item.control.coverage];
			inPlace += weight * item.deployed;
			available += weight;
		}
		const total = Math.max(1, controls.length);
		return {
			framework,
			controls,
			counts,
			inPlacePercent: Math.round((100 * inPlace) / total),
			availablePercent: Math.round((100 * available) / total),
		};
	});
}

export function capabilityTitle(id: string): string {
	return GOVERNANCE_MAPPING.capabilities.find((c) => c.id === id)?.title ?? id;
}

export function evidenceDetail(id: string): string {
	return GOVERNANCE_MAPPING.evidence.find((e) => e.id === id)?.detail ?? id;
}

export const CONTROL_STATUS_LABEL: Readonly<Record<ControlStatus, string>> = {
	in_place: "In place",
	partly_in_place: "Partly in place",
	not_deployed: "Available, not deployed",
	not_observable: "Runs on endpoints (not visible here)",
	customer: "Customer responsibility",
};

// ── Top risks ─────────────────────────────────────────────────────────────

export type RiskSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface GovernanceRisk {
	id: string;
	severity: RiskSeverity;
	title: string;
	detail: string;
	href: string;
}

const SEVERITY_ORDER: Readonly<Record<RiskSeverity, number>> = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	info: 4,
};
/** EU AI Act Art. 26(6): logs kept at least six months (deployers of high-risk systems). */
export const SIX_MONTHS_DAYS = 183;
const STALE_POLICY_DAYS = 180;

const plural = (n: number, one: string, many = `${one}s`) =>
	`${n.toLocaleString()} ${n === 1 ? one : many}`;

/** Risks derived from the scorecard's own numbers; nothing is listed without data behind it. */
export function topRisks(card: GovernanceScorecard, limit = 6): GovernanceRisk[] {
	const risks: GovernanceRisk[] = [];
	const add = (risk: GovernanceRisk) => risks.push(risk);
	const open = card.incidents.openBySeverity;
	if (open.critical > 0)
		add({
			id: "incidents-critical",
			severity: "critical",
			title: `${plural(open.critical, "critical incident")} still open`,
			detail: `Reported in the last ${card.windowDays} days and not resolved.`,
			href: "/incidents",
		});
	if (open.high > 0)
		add({
			id: "incidents-high",
			severity: "high",
			title: `${plural(open.high, "high-severity incident")} still open`,
			detail: `Reported in the last ${card.windowDays} days and not resolved.`,
			href: "/incidents",
		});
	if (card.posture.critical > 0)
		add({
			id: "posture-critical",
			severity: "high",
			title: `${plural(card.posture.critical, "critical AI tool-chain finding")}`,
			detail: "Critical CVE, MCP server or skill findings uploaded in this window.",
			href: "/posture",
		});
	if (!card.identity.requireMfa && card.identity.ownersAdminsWithoutMfa > 0)
		add({
			id: "admins-without-mfa",
			severity: "high",
			title: `${plural(card.identity.ownersAdminsWithoutMfa, "owner or admin", "owners or admins")} without MFA`,
			detail:
				"The workspace does not require MFA, and these accounts can approve held agent actions.",
			href: "/settings",
		});
	if (card.oversight.reviewPrompts > 0)
		add({
			id: "oversight-review",
			severity: "medium",
			title: `${plural(card.oversight.reviewPrompts, "approver")} to review`,
			detail: `Approved at least ${Math.round(card.oversight.thresholds.fastShare * 100)}% of their decisions within ${card.oversight.thresholds.fastSeconds} s. A prompt to check for automatic approval, not a finding.`,
			href: "/approvals",
		});
	if (card.approvals.expiredWithoutDecision > 0)
		add({
			id: "approvals-expired",
			severity: "medium",
			title: `${plural(card.approvals.expiredWithoutDecision, "held action")} expired without a decision`,
			detail: "Nobody approved or denied these requests in time; the agent action stayed blocked.",
			href: "/approvals",
		});
	if (card.usage.mcpServers.notApproved > 0)
		add({
			id: "mcp-unapproved",
			severity: "medium",
			title: `${plural(card.usage.mcpServers.notApproved, "MCP server")} not approved`,
			detail: "Reported by inventory scans without an approved attestation.",
			href: "/posture",
		});
	if (card.policies.runtime === null)
		add({
			id: "runtime-policy-missing",
			severity: "medium",
			title: "No workspace runtime policy",
			detail:
				"Managed agents use their local defaults; there is no versioned workspace policy to review.",
			href: "/policies",
		});
	else if (card.policies.runtime.ageDays > STALE_POLICY_DAYS)
		add({
			id: "runtime-policy-stale",
			severity: "low",
			title: `Runtime policy unchanged for ${plural(card.policies.runtime.ageDays, "day")}`,
			detail: "Periodic review is expected by most AI governance frameworks.",
			href: "/policies",
		});
	const retention = card.identity.telemetryRetentionDays;
	if (retention === null)
		add({
			id: "retention-missing",
			severity: "low",
			title: "No telemetry retention policy",
			detail: "Decision logs have no configured retention period.",
			href: "/settings",
		});
	else if (retention < SIX_MONTHS_DAYS)
		add({
			id: "retention-short",
			severity: "low",
			title: `Decision logs kept ${plural(retention, "day")}`,
			detail:
				"Shorter than six months. Deployers of high-risk AI systems keep logs for at least six months (EU AI Act Art. 26(6)).",
			href: "/settings",
		});
	const latest = card.acceptableUse[0];
	if (latest && card.usage.browserInstalls.active > latest.installs)
		add({
			id: "aup-coverage",
			severity: "low",
			title: `Acceptable-use notice v${latest.noticeVersion} acknowledged on ${latest.installs.toLocaleString()} of ${card.usage.browserInstalls.active.toLocaleString()} active browsers`,
			detail:
				"Browsers that have not visited a protected AI site since the notice was published have not seen it yet.",
			href: "/privacy-guard",
		});
	if (!card.signals.agents_reporting && !card.signals.browser_guard_reporting)
		add({
			id: "nothing-reporting",
			severity: "info",
			title: "No agents or browsers reported in this window",
			detail: "Enroll coding agents or Browser Guard installs to populate the scorecard.",
			href: "/onboarding",
		});
	return risks
		.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
		.slice(0, limit);
}

// ── Reads and writes ───────────────────────────────────────────────────────

export async function readGovernanceScorecard(
	tenantId: string,
	windowDays: GovernanceWindow,
): Promise<GovernanceResult<GovernanceScorecard>> {
	try {
		const { data, error } = await supabase.rpc("governance_scorecard", {
			p_tenant_id: tenantId,
			p_days: windowDays,
		});
		if (error) return { ok: false, error: rpcError(error) };
		return { ok: true, value: parseGovernanceScorecard(data, windowDays) };
	} catch (cause) {
		return {
			ok: false,
			error: cause instanceof Malformed ? "governance_malformed" : "governance_unavailable",
		};
	}
}

export interface SettingsInput {
	digestEnabled: boolean;
	digestCadence: "weekly" | "monthly";
	digestRecipients: "owners" | "owners_admins";
	oversightFastSeconds: number;
	oversightMinDecisions: number;
	oversightFastShare: number;
}

/** Client-side bounds mirror set_governance_settings; the SQL re-validates. */
export function settingsProblem(input: SettingsInput): string | null {
	if (
		!Number.isSafeInteger(input.oversightFastSeconds) ||
		input.oversightFastSeconds < 1 ||
		input.oversightFastSeconds > 3600
	)
		return "Fast-approval time must be a whole number of seconds from 1 to 3600.";
	if (
		!Number.isSafeInteger(input.oversightMinDecisions) ||
		input.oversightMinDecisions < 1 ||
		input.oversightMinDecisions > 10000
	)
		return "Minimum decisions must be a whole number from 1 to 10000.";
	if (
		!Number.isFinite(input.oversightFastShare) ||
		input.oversightFastShare < 0.5 ||
		input.oversightFastShare > 1
	)
		return "Fast-approval share must be between 50% and 100%.";
	return null;
}

export async function saveGovernanceSettings(
	tenantId: string,
	input: SettingsInput,
): Promise<GovernanceResult<GovernanceSettings>> {
	const problem = settingsProblem(input);
	if (problem) return { ok: false, error: "invalid_governance_settings" };
	try {
		const { data, error } = await supabase.rpc("set_governance_settings", {
			p_tenant_id: tenantId,
			p_digest_enabled: input.digestEnabled,
			p_digest_cadence: input.digestCadence,
			p_digest_recipients: input.digestRecipients,
			p_oversight_fast_seconds: input.oversightFastSeconds,
			p_oversight_min_decisions: input.oversightMinDecisions,
			p_oversight_fast_share: Math.round(input.oversightFastShare * 1000) / 1000,
		});
		if (error) return { ok: false, error: rpcError(error) };
		return { ok: true, value: parseSettings(rec(data, "$")) };
	} catch (cause) {
		return {
			ok: false,
			error: cause instanceof Malformed ? "governance_malformed" : "governance_unavailable",
		};
	}
}

export interface TestSendResult {
	status: string;
	recipients: number;
	delivered: number;
}

export async function sendTestSummary(tenantId: string): Promise<GovernanceResult<TestSendResult>> {
	try {
		const { data, error } = await supabase.functions.invoke("governance-digest", {
			body: { action: "send_test", tenant_id: tenantId },
		});
		if (error)
			return { ok: false, error: (await errorCode(error)) ?? "governance_digest_unavailable" };
		const body = rec(data, "$");
		if (body.ok !== true) return { ok: false, error: "governance_digest_unavailable" };
		return {
			ok: true,
			value: {
				status: text(body.status, "status", DELIVERY_STATUS) as string,
				recipients: count(body.recipients, "recipients"),
				delivered: count(body.delivered, "delivered"),
			},
		};
	} catch {
		return { ok: false, error: "governance_digest_unavailable" };
	}
}

function rpcError(error: { code?: string; message?: string }): string {
	const message = String(error.message ?? "");
	if (error.code === "42501")
		return message.includes("identity_barrier")
			? "governance_identity_barrier"
			: "governance_forbidden";
	if (error.code === "22023")
		return message.includes("settings")
			? "invalid_governance_settings"
			: "invalid_governance_window";
	return "governance_unavailable";
}

const ERROR_TEXT: Readonly<Record<string, string>> = {
	governance_forbidden:
		"Only active owners and admins of this workspace can open the governance scorecard.",
	governance_identity_barrier:
		"Your session does not meet this workspace's sign-in policy (MFA or single sign-on). Sign in again.",
	governance_malformed:
		"The scorecard received was incomplete, so it is not shown. Refresh to try again.",
	invalid_governance_window: "Choose a 7, 30 or 90 day window.",
	invalid_governance_settings: "The settings are out of range. Check the values and try again.",
	mail_not_configured:
		"This deployment has no e-mail transport configured, so the summary was not sent. Ask your operator to configure mail delivery.",
	rate_limited: "Too many test summaries were requested. Wait a minute and try again.",
	governance_role_insufficient: "Only workspace owners and admins can send a test summary.",
	mfa_required:
		"This workspace requires a multi-factor session. Sign in again with your second factor.",
	sso_required:
		"This workspace requires single sign-on. Sign in with your organization's identity provider.",
};

export function governanceErrorText(code: string): string {
	return ERROR_TEXT[code] ?? "The governance data is unavailable right now. Try again later.";
}
