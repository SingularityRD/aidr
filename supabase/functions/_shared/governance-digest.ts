// Governance summary: parsing of the counts-only summary returned by
// public.governance_digest_summary / claim_due_governance_digests, and the
// e-mail built from it (docs/ai-governance-frameworks.md).
//
// Discipline: the e-mail is built only from the fields projected here. Every
// number is re-validated; a malformed summary refuses the send instead of
// mailing zeros. The message carries counts, enums and the workspace name
// only: no prompt text, no approver identities, no page addresses.

import { escapeHtml, isMailAddress, type MailMessage } from "./mailer.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NOTICE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export class GovernanceDigestError extends Error {
	constructor(readonly path: string) {
		super(`invalid governance summary at ${path}`);
		this.name = "GovernanceDigestError";
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown, path: string): Record<string, unknown> {
	if (!isRecord(value)) throw new GovernanceDigestError(path);
	return value;
}

function count(value: unknown, path: string): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
		throw new GovernanceDigestError(path);
	}
	return value;
}

function seconds(value: unknown, path: string): number | null {
	if (value === null || value === undefined) return null;
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new GovernanceDigestError(path);
	return value;
}

function instant(value: unknown, path: string): string {
	if (typeof value !== "string" || value.length > 40 || !Number.isFinite(Date.parse(value))) {
		throw new GovernanceDigestError(path);
	}
	return new Date(Date.parse(value)).toISOString();
}

function policyAge(value: unknown, path: string): { version: number | null; ageDays: number } | null {
	if (value === null || value === undefined) return null;
	const row = record(value, path);
	return {
		version: row.version === undefined ? null : count(row.version, `${path}.version`),
		ageDays: count(row.age_days, `${path}.age_days`),
	};
}

export interface GovernanceSummary {
	periodFrom: string;
	periodTo: string;
	agents: { enrolled: number; active: number };
	browserInstalls: { enrolled: number; active: number };
	aiSites: number;
	mcpServers: { distinct: number; notApproved: number };
	decisions: { allow: number; ask: number; deny: number; releasedByOperator: number; releasedByDashboard: number };
	approvals: {
		requested: number;
		approved: number;
		denied: number;
		expiredWithoutDecision: number;
		pending: number;
		medianDecisionSeconds: number | null;
	};
	oversight: { approvers: number; reviewPrompts: number };
	incidents: { reported: number; open: number; openCritical: number; openHigh: number };
	browserGuard: { scans: number; masked: number; warned: number; blocked: number; itemsMasked: number };
	acceptableUse: { noticeId: string; noticeVersion: number; installs: number } | null;
	policies: {
		runtime: { version: number | null; ageDays: number } | null;
		dlp: { version: number | null; ageDays: number } | null;
	};
}

/** Strict projection of the SQL summary; throws GovernanceDigestError. */
export function parseGovernanceSummary(value: unknown): GovernanceSummary {
	const root = record(value, "$");
	const period = record(root.period, "period");
	const usage = record(root.usage, "usage");
	const agents = record(usage.agents, "usage.agents");
	const browser = record(usage.browser_installs, "usage.browser_installs");
	const sites = record(usage.ai_sites, "usage.ai_sites");
	const mcp = record(usage.mcp_servers, "usage.mcp_servers");
	const decisions = record(root.decisions, "decisions");
	const approvals = record(root.approvals, "approvals");
	const oversight = record(root.oversight, "oversight");
	const incidents = record(root.incidents, "incidents");
	const openBySeverity = record(incidents.open_by_severity, "incidents.open_by_severity");
	const guard = record(root.browser_guard, "browser_guard");
	const aup = record(root.acceptable_use, "acceptable_use");
	const policies = record(root.policies, "policies");
	if (!Array.isArray(aup.versions)) throw new GovernanceDigestError("acceptable_use.versions");
	let latestNotice: GovernanceSummary["acceptableUse"] = null;
	if (aup.versions.length > 0) {
		const latest = record(aup.versions[0], "acceptable_use.versions[0]");
		if (typeof latest.notice_id !== "string" || !NOTICE_ID.test(latest.notice_id)) {
			throw new GovernanceDigestError("acceptable_use.versions[0].notice_id");
		}
		latestNotice = {
			noticeId: latest.notice_id,
			noticeVersion: count(latest.notice_version, "acceptable_use.versions[0].notice_version"),
			installs: count(latest.installs, "acceptable_use.versions[0].installs"),
		};
	}
	return {
		periodFrom: instant(period.from, "period.from"),
		periodTo: instant(period.to, "period.to"),
		agents: { enrolled: count(agents.enrolled, "usage.agents.enrolled"), active: count(agents.active, "usage.agents.active") },
		browserInstalls: {
			enrolled: count(browser.enrolled, "usage.browser_installs.enrolled"),
			active: count(browser.active, "usage.browser_installs.active"),
		},
		aiSites: count(sites.distinct, "usage.ai_sites.distinct"),
		mcpServers: {
			distinct: count(mcp.distinct, "usage.mcp_servers.distinct"),
			notApproved: count(mcp.not_approved, "usage.mcp_servers.not_approved"),
		},
		decisions: {
			allow: count(decisions.allow, "decisions.allow"),
			ask: count(decisions.ask, "decisions.ask"),
			deny: count(decisions.deny, "decisions.deny"),
			releasedByOperator: count(decisions.released_by_operator, "decisions.released_by_operator"),
			releasedByDashboard: count(decisions.released_by_dashboard, "decisions.released_by_dashboard"),
		},
		approvals: {
			requested: count(approvals.requested, "approvals.requested"),
			approved: count(approvals.approved, "approvals.approved"),
			denied: count(approvals.denied, "approvals.denied"),
			expiredWithoutDecision: count(approvals.expired_without_decision, "approvals.expired_without_decision"),
			pending: count(approvals.pending, "approvals.pending"),
			medianDecisionSeconds: seconds(approvals.median_decision_seconds, "approvals.median_decision_seconds"),
		},
		oversight: {
			approvers: count(oversight.approvers, "oversight.approvers"),
			reviewPrompts: count(oversight.review_prompts, "oversight.review_prompts"),
		},
		incidents: {
			reported: count(incidents.reported, "incidents.reported"),
			open: count(incidents.open, "incidents.open"),
			openCritical: count(openBySeverity.critical, "incidents.open_by_severity.critical"),
			openHigh: count(openBySeverity.high, "incidents.open_by_severity.high"),
		},
		browserGuard: {
			scans: count(guard.scans, "browser_guard.scans"),
			masked: count(guard.masked, "browser_guard.masked"),
			warned: count(guard.warned, "browser_guard.warned"),
			blocked: count(guard.blocked, "browser_guard.blocked"),
			itemsMasked: count(guard.items_masked, "browser_guard.items_masked"),
		},
		acceptableUse: latestNotice,
		policies: {
			runtime: policyAge(policies.runtime, "policies.runtime"),
			dlp: policyAge(policies.dlp, "policies.dlp"),
		},
	};
}

// ── Dispatcher claims ──────────────────────────────────────────────────────

interface GovernanceDigestClaim {
	tenantId: string;
	tenantName: string;
	claimId: string;
	cadence: "weekly" | "monthly";
	periodFrom: string;
	periodTo: string;
	recipients: string[];
}

export interface GovernanceDigestClaims {
	applied: boolean;
	due: number;
	claims: GovernanceDigestClaim[];
}

/**
 * Recipient addresses. The SQL already filters them with the same shape; an
 * address the mailer would refuse is skipped rather than failing the batch.
 */
function recipientList(value: unknown, path: string): string[] {
	if (!Array.isArray(value) || value.length > 50) throw new GovernanceDigestError(path);
	return [...new Set(value.filter((item): item is string => typeof item === "string" && isMailAddress(item)))];
}

function cadence(value: unknown, path: string): "weekly" | "monthly" {
	if (value !== "weekly" && value !== "monthly") throw new GovernanceDigestError(path);
	return value;
}

export function parseDigestClaims(value: unknown): GovernanceDigestClaims {
	const root = record(value, "$");
	if (typeof root.applied !== "boolean" || !Array.isArray(root.claims)) throw new GovernanceDigestError("$");
	return {
		applied: root.applied,
		due: count(root.due, "due"),
		claims: root.claims.map((item, index) => {
			const claim = record(item, `claims[${index}]`);
			for (const key of ["tenant_id", "claim_id"] as const) {
				if (typeof claim[key] !== "string" || !UUID.test(claim[key] as string)) {
					throw new GovernanceDigestError(`claims[${index}].${key}`);
				}
			}
			return {
				tenantId: String(claim.tenant_id).toLowerCase(),
				tenantName: typeof claim.tenant_name === "string" ? claim.tenant_name : "",
				claimId: String(claim.claim_id).toLowerCase(),
				cadence: cadence(claim.cadence, `claims[${index}].cadence`),
				periodFrom: instant(claim.period_from, `claims[${index}].period_from`),
				periodTo: instant(claim.period_to, `claims[${index}].period_to`),
				recipients: recipientList(claim.recipients, `claims[${index}].recipients`),
			};
		}),
	};
}

export interface GovernanceDigestTestContext {
	tenantName: string;
	cadence: "weekly" | "monthly";
	periodFrom: string;
	periodTo: string;
	recipients: string[];
}

export function parseDigestTestContext(value: unknown): GovernanceDigestTestContext {
	const root = record(value, "$");
	return {
		tenantName: typeof root.tenant_name === "string" ? root.tenant_name : "",
		cadence: cadence(root.cadence, "cadence"),
		periodFrom: instant(root.period_from, "period_from"),
		periodTo: instant(root.period_to, "period_to"),
		recipients: recipientList(root.recipients, "recipients"),
	};
}

/** Delivery status from recipient and delivered counts (mirrors the SQL check). */
export function deliveryStatus(recipients: number, delivered: number): "sent" | "partial" | "failed" | "no_recipients" {
	if (recipients === 0) return "no_recipients";
	if (delivered === recipients) return "sent";
	return delivered > 0 ? "partial" : "failed";
}

// ── E-mail ────────────────────────────────────────────────────────────────

/** Collapse whitespace and drop control characters from display text. */
function displayText(value: string, fallback: string, max = 120): string {
	const cleaned = value.replace(/\p{Cc}/gu, " ").replace(/\s+/g, " ").trim();
	if (cleaned === "") return fallback;
	return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

const day = (iso: string) => iso.slice(0, 10);
const n = (value: number) => value.toLocaleString("en-US");

function duration(value: number | null): string {
	if (value === null) return "no decisions";
	if (value < 90) return `${Math.round(value)} s`;
	if (value < 5400) return `${Math.round(value / 60)} min`;
	return `${(value / 3600).toFixed(1)} h`;
}

function policyLine(label: string, policy: { version: number | null; ageDays: number } | null): string {
	if (!policy) return `${label}: not configured`;
	const version = policy.version === null ? "" : ` v${policy.version}`;
	return `${label}${version}, last changed ${n(policy.ageDays)} day(s) ago`;
}

/** The summary's sections as plain lines (shared by the text and HTML bodies). */
function summarySections(summary: GovernanceSummary): Array<{ title: string; lines: string[] }> {
	const aup = summary.acceptableUse;
	return [
		{
			title: "AI usage",
			lines: [
				`Coding agents active: ${n(summary.agents.active)} of ${n(summary.agents.enrolled)} enrolled`,
				`Browser installs active: ${n(summary.browserInstalls.active)} of ${n(summary.browserInstalls.enrolled)} enrolled`,
				`AI sites in use: ${n(summary.aiSites)}`,
				`MCP servers reported: ${n(summary.mcpServers.distinct)} (${n(summary.mcpServers.notApproved)} not approved)`,
			],
		},
		{
			title: "Decisions on agent actions",
			lines: [
				`Allowed: ${n(summary.decisions.allow)} · held for approval: ${n(summary.decisions.ask)} · denied: ${n(summary.decisions.deny)}`,
				`Released after human approval: ${n(summary.decisions.releasedByDashboard)} in the dashboard, ${n(summary.decisions.releasedByOperator)} by a local operator`,
			],
		},
		{
			title: "Human oversight",
			lines: [
				`Approval requests: ${n(summary.approvals.requested)} (approved ${n(summary.approvals.approved)}, denied ${n(summary.approvals.denied)}, expired undecided ${n(summary.approvals.expiredWithoutDecision)}, pending now ${n(summary.approvals.pending)})`,
				`Median decision time: ${duration(summary.approvals.medianDecisionSeconds)}`,
				`Approvers to review (fast-approval pattern): ${n(summary.oversight.reviewPrompts)} of ${n(summary.oversight.approvers)}`,
			],
		},
		{
			title: "Incidents",
			lines: [
				`Reported: ${n(summary.incidents.reported)} · still open: ${n(summary.incidents.open)} (critical ${n(summary.incidents.openCritical)}, high ${n(summary.incidents.openHigh)})`,
			],
		},
		{
			title: "Browser Guard",
			lines: [
				`Sends scanned: ${n(summary.browserGuard.scans)} · masked: ${n(summary.browserGuard.masked)} (${n(summary.browserGuard.itemsMasked)} items) · warned: ${n(summary.browserGuard.warned)} · blocked: ${n(summary.browserGuard.blocked)}`,
				aup
					? `Acceptable-use notice ${aup.noticeId} v${aup.noticeVersion}: acknowledged on ${n(aup.installs)} browser install(s)`
					: "Acceptable-use notice: no acknowledgements reported",
			],
		},
		{
			title: "Policies",
			lines: [policyLine("Runtime policy", summary.policies.runtime), policyLine("DLP policy", summary.policies.dlp)],
		},
	];
}

export interface GovernanceDigestEmailInput {
	to: string;
	workspaceName: string;
	cadence: "weekly" | "monthly";
	summary: GovernanceSummary;
	/** Dashboard base URL; the message links to /governance when set. */
	dashboardUrl: string | null;
	idempotencyKey: string;
	test: boolean;
}

const FOOTER =
	"Counts only: this summary contains no prompt text, matched values, page addresses or approver identities. " +
	"It is generated from the records Singularity AIDR holds for your workspace and supports, but does not replace, your own governance review.";

export function governanceDigestEmail(input: GovernanceDigestEmailInput): MailMessage {
	const workspace = displayText(input.workspaceName, "your AIDR workspace");
	const period = `${day(input.summary.periodFrom)} to ${day(input.summary.periodTo)} (UTC)`;
	const label = input.cadence === "weekly" ? "Weekly" : "Monthly";
	const subject = `${input.test ? "[Test] " : ""}${label} AI governance summary: ${displayText(input.workspaceName, "AIDR workspace", 80)}`;
	const sections = summarySections(input.summary);
	const link = input.dashboardUrl ? `${input.dashboardUrl.replace(/\/+$/, "")}/governance` : null;
	const text = [
		`Singularity AIDR ${label.toLowerCase()} AI governance summary`,
		`Workspace: ${workspace}`,
		`Period: ${period}`,
		...(input.test ? ["This is a test message requested from the dashboard."] : []),
		"",
		...sections.flatMap((section) => [section.title, ...section.lines.map((line) => `- ${line}`), ""]),
		...(link ? [`Open the governance scorecard: ${link}`, ""] : []),
		FOOTER,
	].join("\n");
	const html = `<!doctype html>
<html lang="en">
<body style="margin:0;padding:24px;background:#f5f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1d2330">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:8px;border:1px solid #e3e6eb">
<tr><td style="padding:28px">
<h1 style="font-size:20px;margin:0 0 4px">${escapeHtml(label)} AI governance summary</h1>
<p style="margin:0 0 16px;color:#5b6475">${escapeHtml(workspace)} · ${escapeHtml(period)}</p>
${input.test ? `<p style="margin:0 0 16px;padding:8px 10px;background:#fff7e6;border-radius:6px;font-size:13px">This is a test message requested from the dashboard.</p>` : ""}
${sections
	.map(
		(section) =>
			`<h2 style="font-size:15px;margin:18px 0 6px">${escapeHtml(section.title)}</h2><ul style="margin:0;padding-left:20px;line-height:1.5">${section.lines
				.map((line) => `<li>${escapeHtml(line)}</li>`)
				.join("")}</ul>`,
	)
	.join("\n")}
${link ? `<p style="margin:24px 0 8px"><a href="${escapeHtml(link)}" style="display:inline-block;padding:10px 18px;background:#2d5bff;color:#ffffff;text-decoration:none;border-radius:6px">Open the governance scorecard</a></p>` : ""}
<p style="margin:16px 0 0;font-size:12px;color:#8a92a3">${escapeHtml(FOOTER)}</p>
</td></tr>
</table>
</body>
</html>`;
	return { to: input.to, subject, text, html, idempotencyKey: input.idempotencyKey };
}

/** Provider de-duplication key: no address, only a digest prefix of it. */
export async function digestIdempotencyKey(scope: string, recipient: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(recipient.toLowerCase()));
	const hex = [...new Uint8Array(digest)].slice(0, 8).map((byte) => byte.toString(16).padStart(2, "0")).join("");
	return `governance-digest/${scope}/${hex}`;
}

/** Constant-time comparison of two secrets through their SHA-256 digests. */
export async function secretsEqual(a: string, b: string): Promise<boolean> {
	const encoder = new TextEncoder();
	const [left, right] = await Promise.all([
		crypto.subtle.digest("SHA-256", encoder.encode(a)),
		crypto.subtle.digest("SHA-256", encoder.encode(b)),
	]);
	const x = new Uint8Array(left);
	const y = new Uint8Array(right);
	let difference = 0;
	for (let index = 0; index < x.length; index++) difference |= x[index] ^ y[index];
	return difference === 0 && a.length > 0 && b.length > 0;
}

/** Optional dashboard link base: https, or http on loopback for development. */
export function dashboardLinkBase(raw: string | undefined | null): string | null {
	if (!raw) return null;
	try {
		const url = new URL(raw.trim());
		const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
		if (url.username || url.password || url.search || url.hash) return null;
		if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) return null;
		return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
	} catch {
		return null;
	}
}
