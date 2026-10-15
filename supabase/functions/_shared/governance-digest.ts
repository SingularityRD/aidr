// Governance summary: parsing of the counts-only summary returned by
// public.governance_digest_summary / claim_due_governance_digests, and the
// e-mail built from it (docs/ai-governance-frameworks.md), in English or
// Turkish, optionally with the executive summary and the printable executive
// report attached (executive-report.ts).
//
// Discipline: the e-mail is built only from the fields projected here. Every
// number is re-validated; a malformed summary refuses the send instead of
// mailing zeros. The message carries counts, enums and the workspace name
// only: no prompt text, no approver identities, no page addresses.

import {
	displayText,
	executiveReportDocument,
	executiveSummary,
	type ReportLanguage,
	reportFileName,
	reportPeriod,
	reportSections,
	reportText,
	type TriageSummary,
	utf8Base64,
} from "./executive-report.ts";
import { escapeHtml, isMailAddress, type MailAttachment, type MailMessage } from "./mailer.ts";

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

export interface GovernanceDigestEmailInput {
	to: string;
	workspaceName: string;
	cadence: "weekly" | "monthly";
	summary: GovernanceSummary;
	/** Dashboard base URL; the message links to /governance when set. */
	dashboardUrl: string | null;
	idempotencyKey: string;
	test: boolean;
	/** English unless the workspace chose Turkish (tenant_governance_settings.digest_language). */
	language?: ReportLanguage;
	/** Incident triage counts; with them the message opens with the executive summary. */
	triage?: TriageSummary | null;
	/** Attach the printable executive report (self-contained HTML). */
	attachReport?: boolean;
	/** Generation time stamped on the attachment (ISO-8601). */
	generatedAt?: string;
}

const EMAIL_TEXT = {
	en: {
		weekly: "Weekly",
		monthly: "Monthly",
		subject: "{test}{label} AI governance summary: {workspace}",
		heading: "{label} AI governance summary",
		intro: "Singularity AIDR {label} AI governance summary",
		workspace: "Workspace: {workspace}",
		period: "Period: {period}",
		test: "This is a test message requested from the dashboard.",
		testTag: "[Test] ",
		link: "Open the governance scorecard",
		attached: "The printable executive report is attached ({file}); open it in a browser and print it to keep a PDF copy.",
		fallbackWorkspace: "your AIDR workspace",
		fallbackSubject: "AIDR workspace",
		footer:
			"Counts only: this summary contains no prompt text, matched values, page addresses or approver identities. " +
			"It is generated from the records Singularity AIDR holds for your workspace and supports, but does not replace, your own governance review.",
	},
	tr: {
		weekly: "Haftalık",
		monthly: "Aylık",
		subject: "{test}{label} yapay zekâ yönetişim özeti: {workspace}",
		heading: "{label} yapay zekâ yönetişim özeti",
		intro: "Singularity AIDR {label} yapay zekâ yönetişim özeti",
		workspace: "Çalışma alanı: {workspace}",
		period: "Dönem: {period}",
		test: "Bu, panelden istenen bir deneme iletisidir.",
		testTag: "[Deneme] ",
		link: "Yönetişim karnesini aç",
		attached: "Yazdırılabilir yönetici raporu ektedir ({file}); PDF kopyası için tarayıcıda açıp yazdırın.",
		fallbackWorkspace: "AIDR çalışma alanınız",
		fallbackSubject: "AIDR çalışma alanı",
		footer:
			"Yalnızca sayılar: bu özet istem metni, eşleşen değer, sayfa adresi ya da onaylayıcı kimliği içermez. " +
			"Singularity AIDR'nin çalışma alanınız için tuttuğu kayıtlardan üretilir; kendi yönetişim incelemenizi destekler, onun yerini tutmaz.",
	},
} as const;

function fill(template: string, params: Record<string, string>): string {
	return template.replace(/\{(\w+)\}/g, (match, name: string) => params[name] ?? match);
}

export function governanceDigestEmail(input: GovernanceDigestEmailInput): MailMessage {
	const language: ReportLanguage = input.language ?? "en";
	const strings = EMAIL_TEXT[language];
	const workspace = displayText(input.workspaceName, strings.fallbackWorkspace);
	const period = reportPeriod(language, input.summary.periodFrom, input.summary.periodTo);
	const label = input.cadence === "weekly" ? strings.weekly : strings.monthly;
	const subject = fill(strings.subject, {
		test: input.test ? strings.testTag : "",
		label,
		workspace: displayText(input.workspaceName, strings.fallbackSubject, 80),
	});
	const triage = input.triage ?? null;
	const executive = triage ? executiveSummary(input.summary, triage, language) : null;
	const sections = reportSections(input.summary, triage, language);
	const link = input.dashboardUrl ? `${input.dashboardUrl.replace(/\/+$/, "")}/governance` : null;
	const file = triage && input.attachReport ? reportFileName(language, input.summary.periodTo) : null;
	const statusLine = executive
		? reportText(language, executive.status === "attention" ? "head.attention" : "head.ok")
		: null;
	const text = [
		fill(strings.intro, { label: language === "en" ? label.toLowerCase() : label.toLocaleLowerCase("tr-TR") }),
		fill(strings.workspace, { workspace }),
		fill(strings.period, { period }),
		...(input.test ? [strings.test] : []),
		"",
		...(executive
			? [
					`${reportText(language, "head.title")}: ${statusLine}`,
					...executive.headlines.map((line) => `${line.level === "attention" ? "!" : "-"} ${line.text}`),
					"",
				]
			: []),
		...sections.flatMap((section) => [section.title, ...section.lines.map((line) => `- ${line}`), ""]),
		...(file ? [fill(strings.attached, { file }), ""] : []),
		...(link ? [`${strings.link}: ${link}`, ""] : []),
		strings.footer,
	].join("\n");
	const html = `<!doctype html>
<html lang="${language}">
<body style="margin:0;padding:24px;background:#f5f6f8;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1d2330">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:8px;border:1px solid #e3e6eb">
<tr><td style="padding:28px">
<h1 style="font-size:20px;margin:0 0 4px">${escapeHtml(fill(strings.heading, { label }))}</h1>
<p style="margin:0 0 16px;color:#5b6475">${escapeHtml(workspace)} · ${escapeHtml(period)}</p>
${input.test ? `<p style="margin:0 0 16px;padding:8px 10px;background:#fff7e6;border-radius:6px;font-size:13px">${escapeHtml(strings.test)}</p>` : ""}
${executive
	? `<h2 style="font-size:15px;margin:18px 0 6px">${escapeHtml(reportText(language, "head.title"))} · <span style="color:${executive.status === "attention" ? "#8a1c12" : "#155d2c"}">${escapeHtml(statusLine ?? "")}</span></h2><ul style="margin:0;padding-left:20px;line-height:1.5">${executive.headlines
			.map((line) => `<li${line.level === "attention" ? ' style="color:#8a1c12"' : ""}>${escapeHtml(line.text)}</li>`)
			.join("")}</ul>`
	: ""}
${sections
	.map(
		(section) =>
			`<h2 style="font-size:15px;margin:18px 0 6px">${escapeHtml(section.title)}</h2><ul style="margin:0;padding-left:20px;line-height:1.5">${section.lines
				.map((line) => `<li>${escapeHtml(line)}</li>`)
				.join("")}</ul>`,
	)
	.join("\n")}
${file ? `<p style="margin:18px 0 0;font-size:13px">${escapeHtml(fill(strings.attached, { file }))}</p>` : ""}
${link ? `<p style="margin:24px 0 8px"><a href="${escapeHtml(link)}" style="display:inline-block;padding:10px 18px;background:#2d5bff;color:#ffffff;text-decoration:none;border-radius:6px">${escapeHtml(strings.link)}</a></p>` : ""}
<p style="margin:16px 0 0;font-size:12px;color:#8a92a3">${escapeHtml(strings.footer)}</p>
</td></tr>
</table>
</body>
</html>`;
	const attachments: MailAttachment[] | undefined = file && triage
		? [{
				filename: file,
				contentType: "text/html",
				contentBase64: utf8Base64(executiveReportDocument({
					language,
					workspaceName: input.workspaceName,
					periodFrom: input.summary.periodFrom,
					periodTo: input.summary.periodTo,
					generatedAt: input.generatedAt ?? input.summary.periodTo,
					summary: input.summary,
					triage,
				})),
			}]
		: undefined;
	return { to: input.to, subject, text, html, idempotencyKey: input.idempotencyKey, ...(attachments ? { attachments } : {}) };
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
