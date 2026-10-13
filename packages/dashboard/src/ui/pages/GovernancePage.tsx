import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { useRichT, useT } from "../../i18n/I18nProvider";
import {
	type ControlStatus,
	capabilityTitle,
	evidenceDetail,
	type FrameworkCoverage,
	frameworkCoverage,
	GOVERNANCE_WINDOWS,
	type GovernanceScorecard,
	type GovernanceSettings,
	type GovernanceWindow,
	governanceErrorText,
	type RiskSeverity,
	readGovernanceScorecard,
	saveGovernanceSettings,
	sendTestSummary,
	settingsProblem,
	topRisks,
} from "../../lib/governance";
import { renderGovernanceReport } from "../governance-print";
import { siteLabel } from "../privacy-guard";

type Load =
	| { kind: "loading" }
	| { kind: "error"; code: string }
	| { kind: "ready"; card: GovernanceScorecard };

const SEVERITY_LABEL: Readonly<Record<RiskSeverity, DashboardMessageKey>> = {
	critical: "common.severity.critical",
	high: "common.severity.high",
	medium: "common.severity.medium",
	low: "common.severity.low",
	info: "common.severity.info",
};

const RISK_BADGE: Readonly<Record<RiskSeverity, string>> = {
	critical: "badge badge-deny",
	high: "badge badge-deny",
	medium: "badge badge-ask",
	low: "badge badge-info",
	info: "badge badge-info",
};

const n = (value: number) => value.toLocaleString();

function duration(seconds: number | null): string {
	if (seconds === null) return "—";
	if (seconds < 90) return `${Math.round(seconds)} s`;
	if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
	return `${(seconds / 3600).toFixed(1)} h`;
}

function saveFile(name: string, content: string, type: string) {
	const url = URL.createObjectURL(new Blob([content], { type }));
	const anchor = document.createElement("a");
	anchor.href = url;
	anchor.download = name;
	anchor.rel = "noopener";
	document.body.append(anchor);
	anchor.click();
	anchor.remove();
	setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function GovernancePage() {
	const t = useT();
	const { currentTeam, currentRole, isLoading, roleResolved } = useTeam();
	if (isLoading || (currentTeam && !roleResolved)) {
		return <div role="status">{t("gsc.resolving")}</div>;
	}
	if (!currentTeam) return <div role="alert">{t("gsc.selectTeam")}</div>;
	if (currentRole !== "owner" && currentRole !== "admin") {
		return (
			<section className="card">
				<h1>{t("gsc.title")}</h1>
				<div className="notice" role="alert">
					{t("gsc.ownersOnly")}
				</div>
			</section>
		);
	}
	return (
		<TenantGovernancePage
			key={currentTeam.id}
			tenantId={currentTeam.id}
			workspaceName={currentTeam.name ?? t("gsc.workspace")}
		/>
	);
}

function TenantGovernancePage({
	tenantId,
	workspaceName,
}: {
	tenantId: string;
	workspaceName: string;
}) {
	const t = useT();
	const [windowDays, setWindowDays] = useState<GovernanceWindow>(30);
	const [load, setLoad] = useState<Load>({ kind: "loading" });
	const [tick, setTick] = useState(0);

	useEffect(() => {
		let cancelled = false;
		// A refresh keeps the current figures on screen until the new ones arrive.
		setLoad((previous) =>
			previous.kind === "ready" && previous.card.windowDays === windowDays
				? previous
				: { kind: "loading" },
		);
		void readGovernanceScorecard(tenantId, windowDays).then((result) => {
			if (cancelled) return;
			setLoad(
				result.ok ? { kind: "ready", card: result.value } : { kind: "error", code: result.error },
			);
		});
		return () => {
			cancelled = true;
		};
		// tick re-runs the read on demand.
	}, [tenantId, windowDays, tick]);

	const card = load.kind === "ready" ? load.card : null;
	const coverage = useMemo(() => (card ? frameworkCoverage(card.signals) : []), [card]);

	const print = useCallback(() => {
		if (!card) return;
		const html = renderGovernanceReport(card, coverage, workspaceName);
		const view = window.open("", "_blank");
		if (!view) {
			saveFile(`aidr-governance-${card.period.to.slice(0, 10)}.html`, html, "text/html");
			return;
		}
		view.opener = null;
		view.document.open();
		view.document.write(html);
		view.document.close();
		view.focus();
		view.print();
	}, [card, coverage, workspaceName]);

	return (
		<div className="stack">
			<section className="card">
				<div
					className="row space-between"
					style={{ alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}
				>
					<div>
						<p className="eyebrow">{t("gsc.eyebrow")}</p>
						<h1>{t("gsc.title")}</h1>
						<p className="muted">{t("gsc.statement")}</p>
					</div>
					<div className="row" role="group" aria-label={t("gsc.window")}>
						{GOVERNANCE_WINDOWS.map((days) => (
							<button
								key={days}
								type="button"
								className={`button button-sm${days === windowDays ? "" : " button-secondary"}`}
								aria-pressed={days === windowDays}
								onClick={() => setWindowDays(days)}
							>
								{t("common.days", { count: days })}
							</button>
						))}
						<button
							type="button"
							className="button button-secondary button-sm"
							onClick={() => setTick((value) => value + 1)}
						>
							{t("common.refresh")}
						</button>
					</div>
				</div>
				{card ? (
					<div className="row" style={{ marginTop: 8, flexWrap: "wrap" }}>
						<button type="button" className="button button-secondary button-sm" onClick={print}>
							{t("gsc.print")}
						</button>
						<button
							type="button"
							className="button button-secondary button-sm"
							onClick={() =>
								saveFile(
									`aidr-governance-${card.period.to.slice(0, 10)}.html`,
									renderGovernanceReport(card, coverage, workspaceName),
									"text/html",
								)
							}
						>
							{t("gsc.download")}
						</button>
						<span className="muted small">
							{t("gsc.period", {
								from: card.period.from.slice(0, 10),
								to: card.period.to.slice(0, 10),
							})}
						</span>
					</div>
				) : null}
				{load.kind === "error" ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{governanceErrorText(load.code, t)}
					</div>
				) : null}
				{load.kind === "loading" ? <p role="status">{t("gsc.loading")}</p> : null}
			</section>

			{card ? (
				<>
					<RisksCard card={card} />
					<CoverageCard coverage={coverage} />
					<UsageCard card={card} />
					<TrendCard card={card} />
					<OversightCard card={card} />
					<IncidentsPostureCard card={card} />
					<BrowserGuardCard card={card} />
					<PolicyCard card={card} />
					<DigestCard
						tenantId={tenantId}
						card={card}
						onSaved={() => setTick((value) => value + 1)}
					/>
					<MatrixCard coverage={coverage} />
				</>
			) : null}
		</div>
	);
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
	return (
		<div className="card stat-card">
			<div className="stat-label">{label}</div>
			<div className="stat-value">{value}</div>
			{hint ? <div className="stat-hint">{hint}</div> : null}
		</div>
	);
}

function RisksCard({ card }: { card: GovernanceScorecard }) {
	const t = useT();
	const risks = topRisks(card, 6, t);
	return (
		<section className="card" aria-labelledby="governance-risks">
			<h2 id="governance-risks">{t("gsc.risks")}</h2>
			<p className="muted small">{t("gsc.risksLead")}</p>
			{risks.length === 0 ? (
				<p className="muted">{t("gsc.noRisks")}</p>
			) : (
				<ul className="stack" style={{ paddingLeft: 0, listStyle: "none" }}>
					{risks.map((risk) => (
						<li key={risk.id} data-testid={`risk-${risk.id}`}>
							<span className={RISK_BADGE[risk.severity]}>{t(SEVERITY_LABEL[risk.severity])}</span>{" "}
							<Link to={risk.href}>
								<b>{risk.title}</b>
							</Link>
							<div className="muted small">{risk.detail}</div>
						</li>
					))}
				</ul>
			)}
		</section>
	);
}

function CoverageCard({ coverage }: { coverage: FrameworkCoverage[] }) {
	const t = useT();
	const richT = useRichT();
	return (
		<section className="card" aria-labelledby="governance-coverage">
			<h2 id="governance-coverage">{t("gsc.coverage")}</h2>
			<p className="muted small">{richT("gsc.coverageLead", { and: <i>{t("gsc.and")}</i> })}</p>
			<div className="grid">
				{coverage.map((item) => (
					<div
						className="card stat-card"
						key={item.framework.id}
						data-testid={`coverage-${item.framework.id}`}
					>
						<div className="stat-label">{item.framework.name}</div>
						<div className="stat-value">{item.inPlacePercent}%</div>
						<div className="usage-bar" aria-hidden="true">
							<div className="usage-fill" style={{ width: `${item.inPlacePercent}%` }} />
						</div>
						<div className="stat-hint">
							{t("gsc.coverageHint", {
								available: item.availablePercent,
								inPlace: item.counts.in_place,
								partly: item.counts.partly_in_place,
								notDeployed: item.counts.not_deployed,
								customer: item.counts.customer,
							})}
						</div>
					</div>
				))}
			</div>
		</section>
	);
}

function UsageCard({ card }: { card: GovernanceScorecard }) {
	const t = useT();
	const richT = useRichT();
	const u = card.usage;
	const empty = u.agents.enrolled === 0 && u.browserInstalls.enrolled === 0;
	return (
		<section className="card" aria-labelledby="governance-usage">
			<h2 id="governance-usage">{t("gsc.usage")}</h2>
			{empty ? (
				<p className="muted">
					{richT("gsc.usageEmpty", {
						connect: <Link to="/onboarding">{t("gsc.connectAgents")}</Link>,
						enroll: <Link to="/privacy-guard">{t("gsc.enrollBrowsers")}</Link>,
					})}
				</p>
			) : null}
			<div className="grid">
				<Stat
					label={t("gsc.agentsActive")}
					value={n(u.agents.active)}
					hint={t("gsc.ofEnrolled", { count: n(u.agents.enrolled) })}
				/>
				<Stat
					label={t("gsc.browsersActive")}
					value={n(u.browserInstalls.active)}
					hint={t("gsc.ofEnrolled", { count: n(u.browserInstalls.enrolled) })}
				/>
				<Stat
					label={t("gsc.sitesInUse")}
					value={n(u.aiSites.distinct)}
					hint={
						u.aiSites.bySite.map((row) => siteLabel(row.site, t)).join(", ") ||
						t("gsc.noneReported")
					}
				/>
				<Stat
					label={t("gsc.mcpReported")}
					value={n(u.mcpServers.distinct)}
					hint={t("gsc.notApproved", { count: n(u.mcpServers.notApproved) })}
				/>
			</div>
		</section>
	);
}

function TrendCard({ card }: { card: GovernanceScorecard }) {
	const t = useT();
	const max = Math.max(1, ...card.trend.map((d) => d.allow + d.ask + d.deny));
	const d = card.decisions;
	return (
		<section className="card" aria-labelledby="governance-trend">
			<h2 id="governance-trend">{t("gsc.decisions")}</h2>
			<p className="muted small">
				{t("gsc.decisionsLead", {
					allow: n(d.allow),
					ask: n(d.ask),
					deny: n(d.deny),
					days: card.windowDays,
				})}
			</p>
			{d.allow + d.ask + d.deny === 0 ? (
				<p className="muted">{t("gsc.noDecisions")}</p>
			) : (
				<div
					className="privacy-series"
					role="img"
					aria-label={t("gsc.trendLabel", {
						allow: d.allow,
						ask: d.ask,
						deny: d.deny,
						days: card.windowDays,
					})}
				>
					{card.trend.map((day) => (
						<div
							key={day.day}
							className="privacy-series-day"
							title={t("gsc.dayTitle", {
								day: day.day,
								allow: day.allow,
								ask: day.ask,
								deny: day.deny,
							})}
						>
							<div
								className="privacy-series-stack"
								style={{ height: `${((day.allow + day.ask + day.deny) / max) * 100}%` }}
							>
								<span className="privacy-series-blocked" style={{ flexGrow: day.deny }} />
								<span className="privacy-series-warned" style={{ flexGrow: day.ask }} />
								<span className="privacy-series-allowed" style={{ flexGrow: day.allow }} />
							</div>
						</div>
					))}
				</div>
			)}
			<details style={{ marginTop: 10 }}>
				<summary className="small">{t("gsc.dailyTable")}</summary>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("gsc.col.day")}</th>
								<th>{t("gsc.col.allowed")}</th>
								<th>{t("gsc.col.ask")}</th>
								<th>{t("gsc.col.denied")}</th>
								<th>{t("gsc.col.masked")}</th>
								<th>{t("gsc.col.blocked")}</th>
							</tr>
						</thead>
						<tbody>
							{card.trend.map((day) => (
								<tr key={day.day}>
									<td className="mono">{day.day}</td>
									<td>{day.allow}</td>
									<td>{day.ask}</td>
									<td>{day.deny}</td>
									<td>{day.masked}</td>
									<td>{day.blocked}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</details>
		</section>
	);
}

function OversightCard({ card }: { card: GovernanceScorecard }) {
	const t = useT();
	const a = card.approvals;
	const o = card.oversight;
	const decided = a.approved + a.denied;
	return (
		<section className="card" aria-labelledby="governance-oversight">
			<h2 id="governance-oversight">{t("gsc.oversight")}</h2>
			<p className="muted small">{t("gsc.oversightLead")}</p>
			<div className="grid">
				<Stat
					label={t("gsc.approvalRequests")}
					value={n(a.requested)}
					hint={t("gsc.pendingNow", { count: n(a.pending) })}
				/>
				<Stat
					label={t("gsc.approveDeny")}
					value={`${n(a.approved)} / ${n(a.denied)}`}
					hint={
						decided
							? t("gsc.approvedShare", { percent: Math.round((100 * a.approved) / decided) })
							: t("gsc.noDecisionsShort")
					}
				/>
				<Stat
					label={t("gsc.medianTime")}
					value={duration(a.medianDecisionSeconds)}
					hint={t("gsc.p90", { time: duration(a.p90DecisionSeconds) })}
				/>
				<Stat
					label={t("gsc.expired")}
					value={n(a.expiredWithoutDecision)}
					hint={t("gsc.stayedBlocked")}
				/>
				<Stat
					label={t("gsc.released")}
					value={n(card.decisions.releasedByDashboard + card.decisions.releasedByOperator)}
					hint={t("gsc.releasedHint", {
						dashboard: n(card.decisions.releasedByDashboard),
						operator: n(card.decisions.releasedByOperator),
					})}
				/>
			</div>
			<h3>{t("gsc.approvers")}</h3>
			<p className="muted small">
				{t("gsc.approversLead", {
					min: o.thresholds.minDecisions,
					share: Math.round(o.thresholds.fastShare * 100),
					seconds: o.thresholds.fastSeconds,
				})}
			</p>
			{o.byApprover.length === 0 ? (
				<p className="muted">{t("gsc.noApprovals")}</p>
			) : (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("gsc.col.approver")}</th>
								<th>{t("gsc.col.decisions")}</th>
								<th>{t("gsc.col.approved")}</th>
								<th>{t("gsc.col.denied")}</th>
								<th>{t("gsc.col.fast")}</th>
								<th>{t("gsc.col.median")}</th>
								<th>{t("gsc.col.review")}</th>
							</tr>
						</thead>
						<tbody>
							{o.byApprover.map((row) => (
								<tr key={row.userId}>
									<td>{row.email ?? row.userId.slice(0, 8)}</td>
									<td>{row.decisions}</td>
									<td>{row.approved}</td>
									<td>{row.denied}</td>
									<td>{row.fastApprovals}</td>
									<td>{duration(row.medianSeconds)}</td>
									<td>
										{row.review ? (
											<span className="badge badge-ask" data-testid="review-prompt">
												{t("gsc.reviewPattern")}
											</span>
										) : (
											"—"
										)}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

function IncidentsPostureCard({ card }: { card: GovernanceScorecard }) {
	const t = useT();
	const i = card.incidents;
	return (
		<section className="card" aria-labelledby="governance-incidents">
			<h2 id="governance-incidents">{t("gsc.incidents")}</h2>
			<div className="grid">
				<Stat
					label={t("gsc.incidentsReported")}
					value={n(i.reported)}
					hint={t("gsc.stillOpen", { count: n(i.open) })}
				/>
				<Stat
					label={t("gsc.openCritical")}
					value={`${n(i.openBySeverity.critical)} / ${n(i.openBySeverity.high)}`}
					hint={i.statusUnknown ? t("gsc.noStatus", { count: n(i.statusUnknown) }) : undefined}
				/>
				<Stat
					label={t("gsc.findings")}
					value={n(card.posture.findings)}
					hint={t("gsc.findingsHint", {
						critical: n(card.posture.critical),
						high: n(card.posture.high),
						cve: n(card.posture.cveConfirmed),
					})}
				/>
			</div>
		</section>
	);
}

function BrowserGuardCard({ card }: { card: GovernanceScorecard }) {
	const t = useT();
	const richT = useRichT();
	const g = card.browserGuard;
	const active = card.usage.browserInstalls.active;
	return (
		<section className="card" aria-labelledby="governance-browser">
			<h2 id="governance-browser">{t("gsc.browser")}</h2>
			<div className="grid">
				<Stat label={t("gsc.scanned")} value={n(g.scans)} />
				<Stat
					label={t("gsc.masked")}
					value={n(g.masked)}
					hint={t("gsc.itemsReplaced", { count: n(g.itemsMasked) })}
				/>
				<Stat label={t("gsc.warnedBlocked")} value={`${n(g.warned)} / ${n(g.blocked)}`} />
			</div>
			<h3>{t("gsc.ack")}</h3>
			<p className="muted small">
				{richT("gsc.ackLead", {
					link: <Link to="/privacy-guard">{t("nav.browserGuard")}</Link>,
				})}
			</p>
			{card.acceptableUse.length === 0 ? (
				<p className="muted">{t("gsc.noAck")}</p>
			) : (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("gsc.col.notice")}</th>
								<th>{t("gsc.col.version")}</th>
								<th>{t("gsc.col.installsAck")}</th>
								<th>{t("gsc.col.ofActive")}</th>
								<th>{t("gsc.col.lastAck")}</th>
							</tr>
						</thead>
						<tbody>
							{card.acceptableUse.map((row) => (
								<tr key={`${row.noticeId}-${row.noticeVersion}`}>
									<td className="mono">{row.noticeId}</td>
									<td>v{row.noticeVersion}</td>
									<td>{n(row.installs)}</td>
									<td>
										{active ? `${Math.min(100, Math.round((100 * row.installs) / active))}%` : "—"}
									</td>
									<td className="mono">{new Date(row.lastAcknowledgedAt).toLocaleString()}</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

function PolicyCard({ card }: { card: GovernanceScorecard }) {
	const t = useT();
	const p = card.policies;
	const row = (label: string, value: GovernanceScorecard["policies"]["runtime"]) => (
		<tr key={label}>
			<td>{label}</td>
			<td>
				{value ? (value.version === null ? "—" : `v${value.version}`) : t("gsc.notConfigured")}
			</td>
			<td>{value ? t("gsc.daysAgo", { count: n(value.ageDays) }) : "—"}</td>
		</tr>
	);
	return (
		<section className="card" aria-labelledby="governance-policies">
			<h2 id="governance-policies">{t("gsc.policies")}</h2>
			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>{t("gsc.col.policy")}</th>
							<th>{t("gsc.col.version")}</th>
							<th>{t("gsc.col.lastChanged")}</th>
						</tr>
					</thead>
					<tbody>
						{row(t("gsc.runtimePolicy"), p.runtime)}
						{row(t("gsc.dlpPolicy"), p.dlp)}
						{row(t("gsc.teamPolicy"), p.team)}
					</tbody>
				</table>
			</div>
			<p className="muted small">
				{t("gsc.revisions", {
					runtime: n(p.runtimeRevisionsInPeriod),
					dlp: n(p.dlpRevisionsInPeriod),
					mfa: card.identity.requireMfa ? t("gsc.required") : t("gsc.notRequired"),
					sso: card.identity.ssoRequired ? t("gsc.required") : t("gsc.notRequired"),
					retention:
						card.identity.telemetryRetentionDays === null
							? t("gsc.noRetention")
							: t("common.days", { count: n(card.identity.telemetryRetentionDays) }),
				})}
			</p>
		</section>
	);
}

function DigestCard({
	tenantId,
	card,
	onSaved,
}: {
	tenantId: string;
	card: GovernanceScorecard;
	onSaved: () => void;
}) {
	const t = useT();
	const [form, setForm] = useState<GovernanceSettings>(card.settings);
	const [status, setStatus] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
	const [busy, setBusy] = useState(false);
	const sharePercent = Math.round(form.oversightFastShare * 100);
	const input = {
		digestEnabled: form.digestEnabled,
		digestCadence: form.digestCadence,
		digestRecipients: form.digestRecipients,
		oversightFastSeconds: form.oversightFastSeconds,
		oversightMinDecisions: form.oversightMinDecisions,
		oversightFastShare: form.oversightFastShare,
	};
	const problem = settingsProblem(input, t);

	async function save() {
		if (problem) {
			setStatus({ tone: "error", text: problem });
			return;
		}
		setBusy(true);
		const result = await saveGovernanceSettings(tenantId, input);
		setBusy(false);
		if (!result.ok) {
			setStatus({ tone: "error", text: governanceErrorText(result.error, t) });
			return;
		}
		setForm(result.value);
		setStatus({
			tone: "ok",
			text: result.value.digestEnabled
				? t("gsc.saved", {
						time: result.value.digestNextAt
							? new Date(result.value.digestNextAt).toUTCString()
							: t("gsc.scheduled"),
					})
				: t("gsc.savedOff"),
		});
		onSaved();
	}

	async function test() {
		setBusy(true);
		const result = await sendTestSummary(tenantId);
		setBusy(false);
		if (!result.ok) {
			setStatus({ tone: "error", text: governanceErrorText(result.error, t) });
			return;
		}
		setStatus({
			tone: result.value.status === "sent" ? "ok" : "error",
			text:
				result.value.status === "no_recipients"
					? t("gsc.noRecipients")
					: t("gsc.testDelivered", {
							delivered: result.value.delivered,
							recipients: result.value.recipients,
						}),
		});
		onSaved();
	}

	return (
		<section className="card" aria-labelledby="governance-digest">
			<h2 id="governance-digest">{t("gsc.digest")}</h2>
			<p className="muted small">{t("gsc.digestLead")}</p>
			<form
				noValidate
				className="stack"
				onSubmit={(event) => {
					event.preventDefault();
					void save();
				}}
			>
				<label className="row" style={{ alignItems: "center", gap: 8 }}>
					<input
						type="checkbox"
						checked={form.digestEnabled}
						onChange={(event) => setForm({ ...form, digestEnabled: event.target.checked })}
					/>
					{t("gsc.digestEnable")}
				</label>
				<div className="row" style={{ flexWrap: "wrap", gap: 12 }}>
					<label className="label" htmlFor="governance-digest-cadence">
						{t("gsc.frequency")}
					</label>
					<select
						id="governance-digest-cadence"
						className="input"
						value={form.digestCadence}
						onChange={(event) =>
							setForm({
								...form,
								digestCadence: event.target.value as GovernanceSettings["digestCadence"],
							})
						}
					>
						<option value="weekly">{t("gsc.weekly")}</option>
						<option value="monthly">{t("gsc.monthly")}</option>
					</select>
					<label className="label" htmlFor="governance-digest-recipients">
						{t("gsc.recipients")}
					</label>
					<select
						id="governance-digest-recipients"
						className="input"
						value={form.digestRecipients}
						onChange={(event) =>
							setForm({
								...form,
								digestRecipients: event.target.value as GovernanceSettings["digestRecipients"],
							})
						}
					>
						<option value="owners_admins">{t("gsc.ownersAdmins")}</option>
						<option value="owners">{t("gsc.ownersOnlyOption")}</option>
					</select>
				</div>
				<fieldset className="row" style={{ flexWrap: "wrap", gap: 12, border: 0, padding: 0 }}>
					<legend className="small">{t("gsc.thresholds")}</legend>
					<label className="label">
						{t("gsc.fastSeconds")}
						<input
							className="input"
							type="number"
							min={1}
							max={3600}
							value={form.oversightFastSeconds}
							onChange={(event) =>
								setForm({ ...form, oversightFastSeconds: Number(event.target.value) })
							}
						/>
					</label>
					<label className="label">
						{t("gsc.minDecisions")}
						<input
							className="input"
							type="number"
							min={1}
							max={10000}
							value={form.oversightMinDecisions}
							onChange={(event) =>
								setForm({ ...form, oversightMinDecisions: Number(event.target.value) })
							}
						/>
					</label>
					<label className="label">
						{t("gsc.fastShare")}
						<input
							className="input"
							type="number"
							min={50}
							max={100}
							value={sharePercent}
							onChange={(event) =>
								setForm({ ...form, oversightFastShare: Number(event.target.value) / 100 })
							}
						/>
					</label>
				</fieldset>
				<div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
					<button type="submit" className="button button-sm" disabled={busy}>
						{t("gsc.saveSettings")}
					</button>
					<button
						type="button"
						className="button button-secondary button-sm"
						disabled={busy}
						onClick={() => void test()}
					>
						{t("gsc.sendTest")}
					</button>
				</div>
				<div
					role="status"
					aria-live="polite"
					className={status?.tone === "error" ? "notice notice-danger" : "muted small"}
				>
					{status?.text ?? ""}
				</div>
			</form>
			<p className="muted small">
				{card.settings.digestLastAt
					? t("gsc.lastSummary", {
							time: new Date(card.settings.digestLastAt).toUTCString(),
							status: card.settings.digestLastStatus ?? t("common.unknown"),
						})
					: t("gsc.noSummary")}
			</p>
			{card.recentDeliveries.length ? (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("gsc.col.time")}</th>
								<th>{t("gsc.col.kind")}</th>
								<th>{t("gsc.col.period")}</th>
								<th>{t("common.status")}</th>
								<th>{t("gsc.col.delivered")}</th>
							</tr>
						</thead>
						<tbody>
							{card.recentDeliveries.map((row) => (
								<tr key={`${row.createdAt}-${row.trigger}`}>
									<td className="mono">{new Date(row.createdAt).toLocaleString()}</td>
									<td>
										{row.trigger === "test"
											? t("gsc.test")
											: row.cadence === "weekly"
												? t("gsc.weekly")
												: row.cadence === "monthly"
													? t("gsc.monthly")
													: row.cadence}
									</td>
									<td className="mono">
										{row.periodFrom.slice(0, 10)} – {row.periodTo.slice(0, 10)}
									</td>
									<td>{row.status.replaceAll("_", " ")}</td>
									<td>
										{row.delivered} / {row.recipients}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			) : null}
		</section>
	);
}

const COVERAGE_TEXT = {
	full: "gsc.cov.full",
	partial: "gsc.cov.partial",
	"customer-responsibility": "gsc.cov.customer",
} as const satisfies Record<string, DashboardMessageKey>;

const CONTROL_STATUS: Readonly<Record<ControlStatus, DashboardMessageKey>> = {
	in_place: "gsc.ctl.inPlace",
	partly_in_place: "gsc.ctl.partly",
	not_deployed: "gsc.ctl.notDeployed",
	not_observable: "gsc.ctl.notObservable",
	customer: "gsc.ctl.customer",
};

function MatrixCard({ coverage }: { coverage: FrameworkCoverage[] }) {
	const t = useT();
	return (
		<section className="card" aria-labelledby="governance-matrix">
			<h2 id="governance-matrix">{t("gsc.matrix")}</h2>
			<p className="muted small">{t("gsc.matrixLead")}</p>
			{coverage.map((item) => (
				<details key={item.framework.id}>
					<summary>
						{item.framework.name} <span className="muted small">({item.framework.version})</span>
					</summary>
					<p className="muted small">{item.framework.scope}</p>
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>{t("gsc.col.control")}</th>
									<th>{t("gsc.col.coverage")}</th>
									<th>{t("gsc.col.statusHere")}</th>
									<th>{t("gsc.col.capabilities")}</th>
								</tr>
							</thead>
							<tbody>
								{item.controls.map((a) => (
									<tr key={a.control.id}>
										<td>
											<b className="mono">{a.control.id}</b>
											<div className="small">{a.control.title}</div>
										</td>
										<td>{t(COVERAGE_TEXT[a.control.coverage])}</td>
										<td>{t(CONTROL_STATUS[a.status])}</td>
										<td className="small">
											{a.control.capabilities.map(capabilityTitle).join("; ") || "—"}
											<div className="muted">
												{t("gsc.evidence", {
													items: a.control.evidence.map(evidenceDetail).join(" ") || "—",
												})}
											</div>
											<div className="muted">{a.control.note}</div>
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				</details>
			))}
		</section>
	);
}
