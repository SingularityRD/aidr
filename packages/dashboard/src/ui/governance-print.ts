/**
 * Printable HTML edition of the AI governance scorecard, with the framework control
 * matrix. Self-contained (inline CSS, no scripts, no remote assets) with print CSS so
 * the browser's "Save as PDF" produces an A4 document; every value is HTML-escaped.
 * Approver identities are omitted: the export carries counts only.
 */

import {
	CONTROL_STATUS_LABEL,
	capabilityTitle,
	type FrameworkCoverage,
	type GovernanceScorecard,
	topRisks,
} from "../lib/governance";
import { GOVERNANCE_MAPPING } from "../lib/governance-frameworks.generated";

function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

const n = (value: number) => value.toLocaleString("en-US");
const COVERAGE_LABEL = {
	full: "Full",
	partial: "Partial",
	"customer-responsibility": "Customer",
} as const;

function table(headers: string[], rows: Array<Array<string | number>>): string {
	return `<table><thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead><tbody>${rows
		.map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(String(cell))}</td>`).join("")}</tr>`)
		.join("")}</tbody></table>`;
}

const STYLE = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font: 10.5pt/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #111; margin: 24px; }
header { border-bottom: 2px solid #0052cc; margin-bottom: 16px; padding-bottom: 8px; }
h1 { font-size: 18pt; margin: 0; color: #0a2a66; }
h2 { font-size: 13pt; margin: 20px 0 4px; color: #0a2a66; break-after: avoid; }
h3 { font-size: 11pt; margin: 12px 0 4px; break-after: avoid; }
.subtitle, .note { color: #444; margin: 2px 0 8px; }
.statement { border: 1px solid #c1d9f4; background: #f3f8fe; padding: 8px 10px; border-radius: 4px; }
table { border-collapse: collapse; width: 100%; margin: 4px 0 10px; font-size: 9pt; }
th, td { border: 1px solid #ccd3dd; padding: 3px 6px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: #eef2f7; }
tr { break-inside: avoid; }
@page { size: A4; margin: 14mm; }
@media print { body { margin: 0; } }
`;

export const GOVERNANCE_STATEMENT =
	"This scorecard is computed from the records Singularity AIDR holds for this workspace. It supports your AI governance, " +
	"KVKK/GDPR and EU AI Act obligations with evidence about the AI tools AIDR guards; it is not a certification, an audit " +
	"opinion or legal advice, and coverage figures describe product controls, not your organisation's compliance.";

export function renderGovernanceReport(
	card: GovernanceScorecard,
	coverage: FrameworkCoverage[],
	workspaceName: string,
): string {
	const risks = topRisks(card, 10);
	const meta = table(
		["Field", "Value"],
		[
			["Workspace", workspaceName],
			["Period", `${card.period.from} – ${card.period.to} (${card.period.days} days)`],
			["Generated", card.generatedAt],
			[
				"Control mapping",
				`${GOVERNANCE_MAPPING.source} (sha256 ${GOVERNANCE_MAPPING.source_sha256.slice(0, 16)}…)`,
			],
		],
	);
	const metrics = table(
		["Measure", "Value"],
		[
			[
				"Coding agents active / enrolled",
				`${n(card.usage.agents.active)} / ${n(card.usage.agents.enrolled)}`,
			],
			[
				"Browser installs active / enrolled",
				`${n(card.usage.browserInstalls.active)} / ${n(card.usage.browserInstalls.enrolled)}`,
			],
			["AI sites in use", n(card.usage.aiSites.distinct)],
			[
				"MCP servers reported (not approved)",
				`${n(card.usage.mcpServers.distinct)} (${n(card.usage.mcpServers.notApproved)})`,
			],
			[
				"Agent decisions allow / ask / deny",
				`${n(card.decisions.allow)} / ${n(card.decisions.ask)} / ${n(card.decisions.deny)}`,
			],
			[
				"Approval requests (approved / denied / expired undecided / pending)",
				`${n(card.approvals.requested)} (${n(card.approvals.approved)} / ${n(card.approvals.denied)} / ${n(card.approvals.expiredWithoutDecision)} / ${n(card.approvals.pending)})`,
			],
			[
				"Median decision time",
				card.approvals.medianDecisionSeconds === null
					? "no decisions"
					: `${card.approvals.medianDecisionSeconds} s`,
			],
			[
				"Approvers with a fast-approval review prompt",
				`${n(card.oversight.reviewPrompts)} of ${n(card.oversight.approvers)}`,
			],
			[
				"Releases after human approval (dashboard / local operator)",
				`${n(card.decisions.releasedByDashboard)} / ${n(card.decisions.releasedByOperator)}`,
			],
			[
				"Incidents reported / still open",
				`${n(card.incidents.reported)} / ${n(card.incidents.open)}`,
			],
			[
				"Browser Guard sends masked / warned / blocked",
				`${n(card.browserGuard.masked)} / ${n(card.browserGuard.warned)} / ${n(card.browserGuard.blocked)}`,
			],
			[
				"Critical / high AI tool-chain findings",
				`${n(card.posture.critical)} / ${n(card.posture.high)}`,
			],
			[
				"Runtime policy",
				card.policies.runtime
					? `v${card.policies.runtime.version ?? "-"}, ${n(card.policies.runtime.ageDays)} days old`
					: "not configured",
			],
			[
				"DLP policy",
				card.policies.dlp
					? `v${card.policies.dlp.version ?? "-"}, ${n(card.policies.dlp.ageDays)} days old`
					: "not configured",
			],
			[
				"Telemetry retention",
				card.identity.telemetryRetentionDays === null
					? "not configured"
					: `${n(card.identity.telemetryRetentionDays)} days`,
			],
		],
	);
	const aup = card.acceptableUse.length
		? table(
				["Notice", "Version", "Browser installs acknowledged", "Last acknowledged"],
				card.acceptableUse.map((row) => [
					row.noticeId,
					row.noticeVersion,
					row.installs,
					row.lastAcknowledgedAt,
				]),
			)
		: `<p class="note">No acknowledgements reported.</p>`;
	const summary = table(
		[
			"Framework",
			"Product-supported coverage in place",
			"If all mapped capabilities were deployed",
			"Controls",
			"Customer responsibility",
		],
		coverage.map((c) => [
			`${c.framework.name} (${c.framework.version})`,
			`${c.inPlacePercent}%`,
			`${c.availablePercent}%`,
			c.controls.length,
			c.counts.customer,
		]),
	);
	const matrices = coverage
		.map(
			(c) =>
				`<h3>${escapeHtml(c.framework.name)}</h3><p class="note">${escapeHtml(c.framework.scope)}</p>${table(
					["Control", "Title", "Coverage", "Status in this workspace", "Capabilities", "Note"],
					c.controls.map((a) => [
						a.control.id,
						a.control.title,
						COVERAGE_LABEL[a.control.coverage],
						CONTROL_STATUS_LABEL[a.status],
						a.control.capabilities.map(capabilityTitle).join("; ") || "-",
						a.control.note,
					]),
				)}`,
		)
		.join("");
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(`AI governance scorecard - ${workspaceName}`)}</title>
<style>${STYLE}</style>
</head>
<body>
<header>
<h1>AI governance scorecard</h1>
<p class="subtitle">Singularity AIDR</p>
${meta}
</header>
<p class="statement">${escapeHtml(GOVERNANCE_STATEMENT)}</p>
<h2>Top risks</h2>
${
	risks.length
		? table(
				["Severity", "Risk", "Detail"],
				risks.map((r) => [r.severity, r.title, r.detail]),
			)
		: `<p class="note">No risks derived from this period's data.</p>`
}
<h2>Framework coverage</h2>
${summary}
<h2>Key measures (counts only)</h2>
${metrics}
<h2>Acceptable-use acknowledgements</h2>
${aup}
<h2>Framework control matrix</h2>
${matrices}
<p class="note">Coverage: Full = the capability performs the activity for the AI tools it guards; Partial = it supports part of it; Customer = the organisation performs it and product data is input only. Approver identities are omitted from this export.</p>
</body>
</html>
`;
}
