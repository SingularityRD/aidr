// Executive report (E6): the localized (English / Turkish) sections of the
// scheduled governance summary, its executive headlines, the incident triage
// counts, the team rollup and the printable report document.
//
// The printable report is a self-contained HTML document (inline CSS, no
// scripts, no external resources). It is attached to the scheduled summary and
// offered as a download in the dashboard; the reader prints it to PDF. A
// server-side PDF is not generated: the standard PDF fonts cannot render
// Turkish letters (ğ, ş, ı, İ) and the Edge runtime ships no font to embed.
//
// Discipline (same as governance-digest.ts): everything is built from strictly
// re-validated counts, enums and the workspace name. No prompt text, matched
// values, page addresses, incident notes or approver identities.

import type { GovernanceSummary } from "./governance-digest.ts";
import { escapeHtml } from "./mailer.ts";

export type ReportLanguage = "en" | "tr";

export class ExecutiveReportError extends Error {
	constructor(readonly path: string) {
		super(`invalid executive report data at ${path}`);
		this.name = "ExecutiveReportError";
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown, path: string): Record<string, unknown> {
	if (!isRecord(value)) throw new ExecutiveReportError(path);
	return value;
}

function count(value: unknown, path: string): number {
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new ExecutiveReportError(path);
	return value;
}

// ── Incident triage counts (public.incident_triage_summary) ────────────────

export interface TriageSummary {
	total: number;
	open: number;
	acknowledged: number;
	resolved: number;
	falsePositive: number;
	snoozed: number;
	unassignedActive: number;
	activeCritical: number;
	activeHigh: number;
	medianCloseSeconds: number | null;
}

export function parseTriageSummary(value: unknown, path = "triage"): TriageSummary {
	const root = record(value, path);
	const median = root.median_close_seconds;
	if (median !== null && median !== undefined && (typeof median !== "number" || !Number.isFinite(median) || median < 0)) {
		throw new ExecutiveReportError(`${path}.median_close_seconds`);
	}
	return {
		total: count(root.total, `${path}.total`),
		open: count(root.open, `${path}.open`),
		acknowledged: count(root.acknowledged, `${path}.acknowledged`),
		resolved: count(root.resolved, `${path}.resolved`),
		falsePositive: count(root.false_positive, `${path}.false_positive`),
		snoozed: count(root.snoozed, `${path}.snoozed`),
		unassignedActive: count(root.unassigned_active, `${path}.unassigned_active`),
		activeCritical: count(root.active_critical, `${path}.active_critical`),
		activeHigh: count(root.active_high, `${path}.active_high`),
		medianCloseSeconds: typeof median === "number" ? median : null,
	};
}

export interface ReportContext {
	language: ReportLanguage;
	attachment: boolean;
	triage: TriageSummary;
}

/** public.governance_report_context: language, attachment flag and triage counts. */
export function parseReportContext(value: unknown): ReportContext {
	const root = record(value, "$");
	if (root.language !== "en" && root.language !== "tr") throw new ExecutiveReportError("language");
	if (typeof root.attachment !== "boolean") throw new ExecutiveReportError("attachment");
	return { language: root.language, attachment: root.attachment, triage: parseTriageSummary(root.triage) };
}

// ── Strings ────────────────────────────────────────────────────────────────

type Params = Record<string, string | number>;

const STRINGS = {
	en: {
		"usage.title": "AI usage",
		"usage.agents": "Coding agents active: {active} of {enrolled} enrolled",
		"usage.browser": "Browser installs active: {active} of {enrolled} enrolled",
		"usage.sites": "AI sites in use: {n}",
		"usage.mcp": "MCP servers reported: {n} ({notApproved} not approved)",
		"decisions.title": "Decisions on agent actions",
		"decisions.counts": "Allowed: {allow} · held for approval: {ask} · denied: {deny}",
		"decisions.released": "Released after human approval: {dashboard} in the dashboard, {operator} by a local operator",
		"oversight.title": "Human oversight",
		"oversight.requests":
			"Approval requests: {requested} (approved {approved}, denied {denied}, expired undecided {expired}, pending now {pending})",
		"oversight.median": "Median decision time: {duration}",
		"oversight.review": "Approvers to review (fast-approval pattern): {prompts} of {approvers}",
		"incidents.title": "Incidents",
		"incidents.reported":
			"Reported: {reported} · still open: {open} (critical {critical}, high {high})",
		"incidents.triage":
			"Triage of blocked and flagged actions in the period: {total} total · open {open} · acknowledged {acknowledged} · resolved {resolved} · false positive {falsePositive}",
		"incidents.triageActive":
			"Still to handle: {critical} critical, {high} high · without an owner: {unassigned} · snoozed: {snoozed} · median time to close: {duration}",
		"browser.title": "Browser Guard",
		"browser.counts":
			"Sends scanned: {scans} · masked: {masked} ({items} items) · warned: {warned} · blocked: {blocked}",
		"browser.aup": "Acceptable-use notice {notice} v{version}: acknowledged on {installs} browser install(s)",
		"browser.noAup": "Acceptable-use notice: no acknowledgements reported",
		"policies.title": "Policies",
		"policies.runtime": "Runtime policy",
		"policies.dlp": "DLP policy",
		"policies.none": "{label}: not configured",
		"policies.age": "{label}{version}, last changed {days} day(s) ago",
		"duration.none": "no decisions",
		"duration.noClosed": "none closed",
		"head.title": "Executive summary",
		"head.attention": "Needs attention",
		"head.ok": "No action needed",
		"head.critical": "{critical} critical and {high} high-severity incident(s) are still open or acknowledged.",
		"head.unassigned": "{n} open incident(s) have no owner.",
		"head.expired": "{n} approval request(s) expired without a decision.",
		"head.review": "{n} approver(s) show a fast-approval pattern worth reviewing.",
		"head.mcp": "{n} MCP server(s) in use are not approved.",
		"head.policyAge": "The runtime policy has not changed for {days} days.",
		"head.blocked": "{deny} risky agent action(s) were blocked and {ask} held for human approval.",
		"head.masked": "{masked} AI chat send(s) had personal data or secrets masked before leaving the browser.",
		"head.clear": "No open critical or high incidents, no unowned incidents and no undecided approvals.",
		"doc.title": "AI security executive report",
		"doc.workspace": "Workspace",
		"doc.period": "Period",
		"doc.generated": "Generated",
		"doc.keyFigures": "Key figures",
		"doc.figure.agents": "Coding agents active",
		"doc.figure.blocked": "Agent actions blocked",
		"doc.figure.held": "Held for approval",
		"doc.figure.masked": "AI sends masked",
		"doc.figure.incidents": "Incidents to handle",
		"doc.figure.pending": "Approvals pending",
		"doc.teams": "Team rollup",
		"doc.teamsLead": "Workspaces you administer, same period. Counts only.",
		"doc.team": "Workspace",
		"doc.restricted": "Not shown: the workspace's sign-in policy (MFA or SSO) is not met by this session.",
		"doc.print": "To keep a PDF copy, open this file in a browser and print it to PDF.",
		"period.utc": "{from} to {to} (UTC)",
		footer:
			"Counts only: this report contains no prompt text, matched values, page addresses, incident notes or approver identities. " +
			"It is generated from the records Singularity AIDR holds for your workspace and supports, but does not replace, your own governance review. " +
			"It is not a certification or an audit opinion.",
	},
	tr: {
		"usage.title": "Yapay zekâ kullanımı",
		"usage.agents": "Etkin kodlama ajanı: {enrolled} kayıtlı ajandan {active}",
		"usage.browser": "Etkin tarayıcı kurulumu: {enrolled} kayıtlı kurulumdan {active}",
		"usage.sites": "Kullanılan yapay zekâ sitesi: {n}",
		"usage.mcp": "Bildirilen MCP sunucusu: {n} ({notApproved} onaysız)",
		"decisions.title": "Ajan işlemleri için kararlar",
		"decisions.counts": "İzin verilen: {allow} · onaya bekletilen: {ask} · engellenen: {deny}",
		"decisions.released": "İnsan onayıyla serbest bırakılan: panelde {dashboard}, yerel operatörce {operator}",
		"oversight.title": "İnsan gözetimi",
		"oversight.requests":
			"Onay talebi: {requested} (onaylanan {approved}, reddedilen {denied}, karar verilmeden süresi dolan {expired}, şu an bekleyen {pending})",
		"oversight.median": "Ortanca karar süresi: {duration}",
		"oversight.review": "İncelenmesi önerilen onaylayıcı (hızlı onay örüntüsü): {approvers} kişiden {prompts}",
		"incidents.title": "Vakalar",
		"incidents.reported":
			"Bildirilen: {reported} · hâlâ açık: {open} (kritik {critical}, yüksek {high})",
		"incidents.triage":
			"Dönemdeki engellenen ve işaretlenen işlemlerin ele alınması: toplam {total} · açık {open} · üstlenilen {acknowledged} · çözülen {resolved} · yanlış pozitif {falsePositive}",
		"incidents.triageActive":
			"Ele alınması gereken: {critical} kritik, {high} yüksek · sorumlusu olmayan: {unassigned} · ertelenen: {snoozed} · ortanca kapanma süresi: {duration}",
		"browser.title": "Browser Guard",
		"browser.counts":
			"Taranan gönderim: {scans} · maskelenen: {masked} ({items} öğe) · uyarılan: {warned} · engellenen: {blocked}",
		"browser.aup": "Kabul edilebilir kullanım bildirimi {notice} s{version}: {installs} tarayıcı kurulumunda onaylandı",
		"browser.noAup": "Kabul edilebilir kullanım bildirimi: onay bildirilmedi",
		"policies.title": "Politikalar",
		"policies.runtime": "Çalışma zamanı politikası",
		"policies.dlp": "Veri sızıntısı önleme (DLP) politikası",
		"policies.none": "{label}: yapılandırılmamış",
		"policies.age": "{label}{version}, son değişiklik {days} gün önce",
		"duration.none": "karar yok",
		"duration.noClosed": "kapatılan yok",
		"head.title": "Yönetici özeti",
		"head.attention": "İlgilenilmesi gerekiyor",
		"head.ok": "İşlem gerekmiyor",
		"head.critical": "{critical} kritik ve {high} yüksek önem dereceli vaka hâlâ açık ya da üstlenilmiş durumda.",
		"head.unassigned": "{n} açık vakanın sorumlusu yok.",
		"head.expired": "{n} onay talebi karar verilmeden süresi doldu.",
		"head.review": "{n} onaylayıcıda incelenmesi önerilen hızlı onay örüntüsü var.",
		"head.mcp": "Kullanımdaki {n} MCP sunucusu onaylı değil.",
		"head.policyAge": "Çalışma zamanı politikası {days} gündür değişmedi.",
		"head.blocked": "{deny} riskli ajan işlemi engellendi, {ask} işlem insan onayına bekletildi.",
		"head.masked": "{masked} yapay zekâ sohbet gönderiminde kişisel veri ya da gizli bilgi tarayıcıdan çıkmadan maskelendi.",
		"head.clear": "Açık kritik ya da yüksek vaka, sorumlusuz vaka veya karar bekleyen süresi dolmuş onay yok.",
		"doc.title": "Yapay zekâ güvenliği yönetici raporu",
		"doc.workspace": "Çalışma alanı",
		"doc.period": "Dönem",
		"doc.generated": "Oluşturulma",
		"doc.keyFigures": "Temel göstergeler",
		"doc.figure.agents": "Etkin kodlama ajanı",
		"doc.figure.blocked": "Engellenen ajan işlemi",
		"doc.figure.held": "Onaya bekletilen",
		"doc.figure.masked": "Maskelenen gönderim",
		"doc.figure.incidents": "Ele alınacak vaka",
		"doc.figure.pending": "Bekleyen onay",
		"doc.teams": "Ekip bazında özet",
		"doc.teamsLead": "Yönettiğiniz çalışma alanları, aynı dönem. Yalnızca sayılar.",
		"doc.team": "Çalışma alanı",
		"doc.restricted": "Gösterilmiyor: bu oturum çalışma alanının oturum açma politikasını (MFA ya da SSO) karşılamıyor.",
		"doc.print": "PDF kopyası için bu dosyayı tarayıcıda açıp PDF olarak yazdırın.",
		"period.utc": "{from} – {to} (UTC)",
		footer:
			"Yalnızca sayılar: bu rapor istem metni, eşleşen değer, sayfa adresi, vaka notu ya da onaylayıcı kimliği içermez. " +
			"Singularity AIDR'nin çalışma alanınız için tuttuğu kayıtlardan üretilir; kendi yönetişim incelemenizi destekler, onun yerini tutmaz. " +
			"Bir sertifika ya da denetim görüşü değildir.",
	},
} as const satisfies Record<ReportLanguage, Record<string, string>>;

type StringKey = keyof (typeof STRINGS)["en"];

export function reportText(language: ReportLanguage, key: StringKey, params: Params = {}): string {
	return (STRINGS[language][key] as string).replace(/\{(\w+)\}/g, (match, name: string) =>
		Object.hasOwn(params, name) ? String(params[name]) : match,
	);
}

function formatCount(language: ReportLanguage, value: number): string {
	return value.toLocaleString(language === "tr" ? "tr-TR" : "en-US");
}

function duration(language: ReportLanguage, value: number | null, empty: StringKey): string {
	if (value === null) return reportText(language, empty);
	const unit = language === "tr" ? { s: "sn", min: "dk", h: "sa" } : { s: "s", min: "min", h: "h" };
	if (value < 90) return `${Math.round(value)} ${unit.s}`;
	if (value < 5400) return `${Math.round(value / 60)} ${unit.min}`;
	const hours = (value / 3600).toFixed(1);
	return `${language === "tr" ? hours.replace(".", ",") : hours} ${unit.h}`;
}

function policyLine(
	language: ReportLanguage,
	labelKey: "policies.runtime" | "policies.dlp",
	policy: { version: number | null; ageDays: number } | null,
): string {
	const label = reportText(language, labelKey);
	if (!policy) return reportText(language, "policies.none", { label });
	const version = policy.version === null ? "" : language === "tr" ? ` s${policy.version}` : ` v${policy.version}`;
	return reportText(language, "policies.age", { label, version, days: formatCount(language, policy.ageDays) });
}

export interface ReportSection {
	title: string;
	lines: string[];
}

/** The summary's sections as plain lines (e-mail text, e-mail HTML and the printable report). */
export function reportSections(
	summary: GovernanceSummary,
	triage: TriageSummary | null,
	language: ReportLanguage,
): ReportSection[] {
	const n = (value: number) => formatCount(language, value);
	const tx = (key: StringKey, params: Params = {}) => reportText(language, key, params);
	const aup = summary.acceptableUse;
	return [
		{
			title: tx("usage.title"),
			lines: [
				tx("usage.agents", { active: n(summary.agents.active), enrolled: n(summary.agents.enrolled) }),
				tx("usage.browser", { active: n(summary.browserInstalls.active), enrolled: n(summary.browserInstalls.enrolled) }),
				tx("usage.sites", { n: n(summary.aiSites) }),
				tx("usage.mcp", { n: n(summary.mcpServers.distinct), notApproved: n(summary.mcpServers.notApproved) }),
			],
		},
		{
			title: tx("decisions.title"),
			lines: [
				tx("decisions.counts", { allow: n(summary.decisions.allow), ask: n(summary.decisions.ask), deny: n(summary.decisions.deny) }),
				tx("decisions.released", {
					dashboard: n(summary.decisions.releasedByDashboard),
					operator: n(summary.decisions.releasedByOperator),
				}),
			],
		},
		{
			title: tx("oversight.title"),
			lines: [
				tx("oversight.requests", {
					requested: n(summary.approvals.requested),
					approved: n(summary.approvals.approved),
					denied: n(summary.approvals.denied),
					expired: n(summary.approvals.expiredWithoutDecision),
					pending: n(summary.approvals.pending),
				}),
				tx("oversight.median", { duration: duration(language, summary.approvals.medianDecisionSeconds, "duration.none") }),
				tx("oversight.review", { prompts: n(summary.oversight.reviewPrompts), approvers: n(summary.oversight.approvers) }),
			],
		},
		{
			title: tx("incidents.title"),
			lines: [
				tx("incidents.reported", {
					reported: n(summary.incidents.reported),
					open: n(summary.incidents.open),
					critical: n(summary.incidents.openCritical),
					high: n(summary.incidents.openHigh),
				}),
				...(triage
					? [
							tx("incidents.triage", {
								total: n(triage.total),
								open: n(triage.open),
								acknowledged: n(triage.acknowledged),
								resolved: n(triage.resolved),
								falsePositive: n(triage.falsePositive),
							}),
							tx("incidents.triageActive", {
								critical: n(triage.activeCritical),
								high: n(triage.activeHigh),
								unassigned: n(triage.unassignedActive),
								snoozed: n(triage.snoozed),
								duration: duration(language, triage.medianCloseSeconds, "duration.noClosed"),
							}),
						]
					: []),
			],
		},
		{
			title: tx("browser.title"),
			lines: [
				tx("browser.counts", {
					scans: n(summary.browserGuard.scans),
					masked: n(summary.browserGuard.masked),
					items: n(summary.browserGuard.itemsMasked),
					warned: n(summary.browserGuard.warned),
					blocked: n(summary.browserGuard.blocked),
				}),
				aup
					? tx("browser.aup", { notice: aup.noticeId, version: aup.noticeVersion, installs: n(aup.installs) })
					: tx("browser.noAup"),
			],
		},
		{
			title: tx("policies.title"),
			lines: [
				policyLine(language, "policies.runtime", summary.policies.runtime),
				policyLine(language, "policies.dlp", summary.policies.dlp),
			],
		},
	];
}

// ── Executive headlines ────────────────────────────────────────────────────

/** A runtime policy older than this is called out as stale. */
const STALE_POLICY_DAYS = 180;

interface Headline {
	level: "attention" | "info";
	text: string;
}

export interface ExecutiveSummary {
	status: "attention" | "ok";
	headlines: Headline[];
}

/** Attention items first, then context; never more than eight lines. */
export function executiveSummary(
	summary: GovernanceSummary,
	triage: TriageSummary,
	language: ReportLanguage,
): ExecutiveSummary {
	const n = (value: number) => formatCount(language, value);
	const tx = (key: StringKey, params: Params = {}) => reportText(language, key, params);
	const attention: string[] = [];
	if (triage.activeCritical + triage.activeHigh > 0) {
		attention.push(tx("head.critical", { critical: n(triage.activeCritical), high: n(triage.activeHigh) }));
	}
	if (triage.unassignedActive > 0) attention.push(tx("head.unassigned", { n: n(triage.unassignedActive) }));
	if (summary.approvals.expiredWithoutDecision > 0) {
		attention.push(tx("head.expired", { n: n(summary.approvals.expiredWithoutDecision) }));
	}
	if (summary.oversight.reviewPrompts > 0) attention.push(tx("head.review", { n: n(summary.oversight.reviewPrompts) }));
	if (summary.mcpServers.notApproved > 0) attention.push(tx("head.mcp", { n: n(summary.mcpServers.notApproved) }));
	if (summary.policies.runtime && summary.policies.runtime.ageDays > STALE_POLICY_DAYS) {
		attention.push(tx("head.policyAge", { days: n(summary.policies.runtime.ageDays) }));
	}
	const info: string[] = [];
	if (attention.length === 0) info.push(tx("head.clear"));
	info.push(tx("head.blocked", { deny: n(summary.decisions.deny), ask: n(summary.decisions.ask) }));
	if (summary.browserGuard.masked > 0) info.push(tx("head.masked", { masked: n(summary.browserGuard.masked) }));
	return {
		status: attention.length > 0 ? "attention" : "ok",
		headlines: [
			...attention.map((text) => ({ level: "attention" as const, text })),
			...info.map((text) => ({ level: "info" as const, text })),
		].slice(0, 8),
	};
}

// ── Team rollup ────────────────────────────────────────────────────────────

export interface TeamRollupFigures {
	agentsActive: number;
	agentsEnrolled: number;
	browserActive: number;
	allow: number;
	ask: number;
	deny: number;
	masked: number;
	blocked: number;
	incidentsActive: number;
	incidentsCritical: number;
	incidentsUnassigned: number;
	approvalsPending: number;
}

export interface TeamRollupRow {
	tenantId: string;
	name: string;
	role: "owner" | "admin";
	/** Null when the workspace's identity barrier refused this session. */
	figures: TeamRollupFigures | null;
}

export function teamRollupFigures(summary: GovernanceSummary, triage: TriageSummary): TeamRollupFigures {
	return {
		agentsActive: summary.agents.active,
		agentsEnrolled: summary.agents.enrolled,
		browserActive: summary.browserInstalls.active,
		allow: summary.decisions.allow,
		ask: summary.decisions.ask,
		deny: summary.decisions.deny,
		masked: summary.browserGuard.masked,
		blocked: summary.browserGuard.blocked,
		incidentsActive: triage.open + triage.acknowledged,
		incidentsCritical: triage.activeCritical,
		incidentsUnassigned: triage.unassignedActive,
		approvalsPending: summary.approvals.pending,
	};
}

// ── Printable report ───────────────────────────────────────────────────────

/** Collapse whitespace and drop control characters from display text. */
export function displayText(value: string, fallback: string, max = 120): string {
	const cleaned = value.replace(/\p{Cc}/gu, " ").replace(/\s+/g, " ").trim();
	if (cleaned === "") return fallback;
	return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

export function reportPeriod(language: ReportLanguage, from: string, to: string): string {
	return reportText(language, "period.utc", { from: from.slice(0, 10), to: to.slice(0, 10) });
}

export interface ExecutiveReportInput {
	language: ReportLanguage;
	workspaceName: string;
	periodFrom: string;
	periodTo: string;
	generatedAt: string;
	summary: GovernanceSummary;
	triage: TriageSummary;
	teams?: TeamRollupRow[];
}

const DOC_STYLE = `
*{box-sizing:border-box}
body{margin:0;padding:32px;font-family:-apple-system,"Segoe UI",Roboto,"Noto Sans","DejaVu Sans",Arial,sans-serif;color:#1d2330;background:#ffffff;line-height:1.45}
main{max-width:860px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:24px 0 8px;border-bottom:1px solid #e3e6eb;padding-bottom:4px}
.meta{color:#5b6475;margin:0 0 16px;font-size:13px}
.status{display:inline-block;padding:4px 10px;border-radius:12px;font-size:13px;font-weight:600}
.status-attention{background:#fdecea;color:#8a1c12}
.status-ok{background:#e7f6ec;color:#155d2c}
ul{margin:0;padding-left:20px}
li{margin:2px 0}
li.attention{color:#8a1c12}
.figures{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:8px 0}
.figure{border:1px solid #e3e6eb;border-radius:6px;padding:8px 10px}
.figure b{display:block;font-size:20px}
.figure span{font-size:12px;color:#5b6475}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{border:1px solid #e3e6eb;padding:4px 6px;text-align:right}
th:first-child,td:first-child{text-align:left}
.muted{color:#5b6475;font-size:12px}
footer{margin-top:28px;font-size:11px;color:#5b6475}
@media print{body{padding:0}.noprint{display:none}h2{break-after:avoid}table,.figures{break-inside:avoid}}
`;

function teamTable(language: ReportLanguage, teams: TeamRollupRow[]): string {
	const n = (value: number) => escapeHtml(formatCount(language, value));
	const head =
		language === "tr"
			? ["Çalışma alanı", "Etkin ajan", "İzin", "Onaya", "Engel", "Maskelenen", "Ele alınacak vaka", "Kritik", "Sorumlusuz", "Bekleyen onay"]
			: ["Workspace", "Agents active", "Allowed", "Held", "Denied", "Masked", "Incidents to handle", "Critical", "Unowned", "Approvals pending"];
	const rows = teams.map((team) => {
		const name = escapeHtml(displayText(team.name, "—", 80));
		if (!team.figures) {
			return `<tr><td>${name}</td><td colspan="${head.length - 1}" class="muted">${escapeHtml(reportText(language, "doc.restricted"))}</td></tr>`;
		}
		const f = team.figures;
		return `<tr><td>${name}</td><td>${n(f.agentsActive)} / ${n(f.agentsEnrolled)}</td><td>${n(f.allow)}</td><td>${n(f.ask)}</td><td>${n(f.deny)}</td><td>${n(f.masked)}</td><td>${n(f.incidentsActive)}</td><td>${n(f.incidentsCritical)}</td><td>${n(f.incidentsUnassigned)}</td><td>${n(f.approvalsPending)}</td></tr>`;
	});
	return `<table><thead><tr>${head.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`;
}

/** The printable executive report: one self-contained HTML document. */
export function executiveReportDocument(input: ExecutiveReportInput): string {
	const { language, summary, triage } = input;
	const tx = (key: StringKey, params: Params = {}) => reportText(language, key, params);
	const n = (value: number) => escapeHtml(formatCount(language, value));
	const executive = executiveSummary(summary, triage, language);
	const workspace = escapeHtml(displayText(input.workspaceName, "—"));
	const figures: Array<[StringKey, string]> = [
		["doc.figure.agents", `${n(summary.agents.active)} / ${n(summary.agents.enrolled)}`],
		["doc.figure.blocked", n(summary.decisions.deny)],
		["doc.figure.held", n(summary.decisions.ask)],
		["doc.figure.masked", n(summary.browserGuard.masked)],
		["doc.figure.incidents", n(triage.open + triage.acknowledged)],
		["doc.figure.pending", n(summary.approvals.pending)],
	];
	const sections = reportSections(summary, triage, language);
	const teams = input.teams && input.teams.length > 0
		? `<h2>${escapeHtml(tx("doc.teams"))}</h2><p class="muted">${escapeHtml(tx("doc.teamsLead"))}</p>${teamTable(language, input.teams)}`
		: "";
	return `<!doctype html>
<html lang="${language}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${escapeHtml(tx("doc.title"))} · ${workspace}</title>
<style>${DOC_STYLE}</style>
</head>
<body>
<main>
<h1>${escapeHtml(tx("doc.title"))}</h1>
<p class="meta">${escapeHtml(tx("doc.workspace"))}: ${workspace} · ${escapeHtml(tx("doc.period"))}: ${escapeHtml(reportPeriod(language, input.periodFrom, input.periodTo))} · ${escapeHtml(tx("doc.generated"))}: ${escapeHtml(input.generatedAt.slice(0, 16).replace("T", " "))} UTC</p>
<p class="muted noprint">${escapeHtml(tx("doc.print"))}</p>
<h2>${escapeHtml(tx("head.title"))}</h2>
<p><span class="status status-${executive.status}">${escapeHtml(tx(executive.status === "attention" ? "head.attention" : "head.ok"))}</span></p>
<ul>${executive.headlines.map((line) => `<li class="${line.level}">${escapeHtml(line.text)}</li>`).join("")}</ul>
<h2>${escapeHtml(tx("doc.keyFigures"))}</h2>
<div class="figures">${figures.map(([key, value]) => `<div class="figure"><b>${value}</b><span>${escapeHtml(tx(key))}</span></div>`).join("")}</div>
${sections.map((section) => `<h2>${escapeHtml(section.title)}</h2><ul>${section.lines.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul>`).join("\n")}
${teams}
<footer>${escapeHtml(tx("footer"))}</footer>
</main>
</body>
</html>
`;
}

/** UTF-8 bytes of a string as base64 (mail attachment content). */
export function utf8Base64(value: string): string {
	const bytes = new TextEncoder().encode(value);
	let binary = "";
	for (let index = 0; index < bytes.length; index += 0x8000) {
		binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
	}
	return btoa(binary);
}

export function reportFileName(language: ReportLanguage, periodTo: string): string {
	return `${language === "tr" ? "aidr-yonetici-raporu" : "aidr-executive-report"}-${periodTo.slice(0, 10)}.html`;
}
