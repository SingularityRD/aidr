import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import {
	CONTROL_STATUS_LABEL,
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
import { GOVERNANCE_STATEMENT, renderGovernanceReport } from "../governance-print";
import { siteLabel } from "../privacy-guard";

type Load =
	| { kind: "loading" }
	| { kind: "error"; message: string }
	| { kind: "ready"; card: GovernanceScorecard };

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
	const { currentTeam, currentRole, isLoading, roleResolved } = useTeam();
	if (isLoading || (currentTeam && !roleResolved)) {
		return <div role="status">Resolving the managed tenant…</div>;
	}
	if (!currentTeam) return <div role="alert">Select a team to view the governance scorecard.</div>;
	if (currentRole !== "owner" && currentRole !== "admin") {
		return (
			<section className="card">
				<h1>AI governance</h1>
				<div className="notice" role="alert">
					Only workspace owners and admins can view the governance scorecard.
				</div>
			</section>
		);
	}
	return (
		<TenantGovernancePage
			key={currentTeam.id}
			tenantId={currentTeam.id}
			workspaceName={currentTeam.name ?? "Workspace"}
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
				result.ok
					? { kind: "ready", card: result.value }
					: { kind: "error", message: governanceErrorText(result.error) },
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
						<p className="eyebrow">Governance</p>
						<h1>AI governance</h1>
						<p className="muted">{GOVERNANCE_STATEMENT}</p>
					</div>
					<div className="row" role="group" aria-label="Reporting window">
						{GOVERNANCE_WINDOWS.map((days) => (
							<button
								key={days}
								type="button"
								className={`button button-sm${days === windowDays ? "" : " button-secondary"}`}
								aria-pressed={days === windowDays}
								onClick={() => setWindowDays(days)}
							>
								{days} days
							</button>
						))}
						<button
							type="button"
							className="button button-secondary button-sm"
							onClick={() => setTick((value) => value + 1)}
						>
							Refresh
						</button>
					</div>
				</div>
				{card ? (
					<div className="row" style={{ marginTop: 8, flexWrap: "wrap" }}>
						<button type="button" className="button button-secondary button-sm" onClick={print}>
							Print / save as PDF
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
							Download printable HTML
						</button>
						<span className="muted small">
							Period {card.period.from.slice(0, 10)} to {card.period.to.slice(0, 10)} (UTC). Counts
							only.
						</span>
					</div>
				) : null}
				{load.kind === "error" ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{load.message}
					</div>
				) : null}
				{load.kind === "loading" ? <p role="status">Loading the governance scorecard…</p> : null}
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
	const risks = topRisks(card);
	return (
		<section className="card" aria-labelledby="governance-risks">
			<h2 id="governance-risks">Top risks</h2>
			<p className="muted small">
				Derived from this period's counts; each item links to where it is handled.
			</p>
			{risks.length === 0 ? (
				<p className="muted">No risks derived from this period's data.</p>
			) : (
				<ul className="stack" style={{ paddingLeft: 0, listStyle: "none" }}>
					{risks.map((risk) => (
						<li key={risk.id} data-testid={`risk-${risk.id}`}>
							<span className={RISK_BADGE[risk.severity]}>{risk.severity}</span>{" "}
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
	return (
		<section className="card" aria-labelledby="governance-coverage">
			<h2 id="governance-coverage">Framework coverage</h2>
			<p className="muted small">
				Share of the mapped controls that Singularity AIDR supports <i>and</i> that this workspace
				has deployed (full support counts 1, partial 0.5). It describes product controls, not your
				organisation's compliance; controls marked customer responsibility count as zero.
			</p>
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
							{item.availablePercent}% if every mapped capability were deployed ·{" "}
							{item.counts.in_place} in place, {item.counts.partly_in_place} partly,{" "}
							{item.counts.not_deployed} not deployed, {item.counts.customer} customer
						</div>
					</div>
				))}
			</div>
		</section>
	);
}

function UsageCard({ card }: { card: GovernanceScorecard }) {
	const u = card.usage;
	const empty = u.agents.enrolled === 0 && u.browserInstalls.enrolled === 0;
	return (
		<section className="card" aria-labelledby="governance-usage">
			<h2 id="governance-usage">AI usage</h2>
			{empty ? (
				<p className="muted">
					No coding agents or browser installs are enrolled yet.{" "}
					<Link to="/onboarding">Connect agents</Link> or{" "}
					<Link to="/privacy-guard">enroll browsers</Link> to populate this view.
				</p>
			) : null}
			<div className="grid">
				<Stat
					label="Coding agents active"
					value={n(u.agents.active)}
					hint={`of ${n(u.agents.enrolled)} enrolled`}
				/>
				<Stat
					label="Browser installs active"
					value={n(u.browserInstalls.active)}
					hint={`of ${n(u.browserInstalls.enrolled)} enrolled`}
				/>
				<Stat
					label="AI sites in use"
					value={n(u.aiSites.distinct)}
					hint={u.aiSites.bySite.map((row) => siteLabel(row.site)).join(", ") || "none reported"}
				/>
				<Stat
					label="MCP servers reported"
					value={n(u.mcpServers.distinct)}
					hint={`${n(u.mcpServers.notApproved)} not approved`}
				/>
			</div>
		</section>
	);
}

function TrendCard({ card }: { card: GovernanceScorecard }) {
	const max = Math.max(1, ...card.trend.map((d) => d.allow + d.ask + d.deny));
	const d = card.decisions;
	return (
		<section className="card" aria-labelledby="governance-trend">
			<h2 id="governance-trend">Agent decisions</h2>
			<p className="muted small">
				{n(d.allow)} allowed · {n(d.ask)} held for approval · {n(d.deny)} denied in{" "}
				{card.windowDays} days, per UTC day.
			</p>
			{d.allow + d.ask + d.deny === 0 ? (
				<p className="muted">No decisions were reported in this window.</p>
			) : (
				<div
					className="privacy-series"
					role="img"
					aria-label={`${d.allow} allowed, ${d.ask} held for approval, ${d.deny} denied over ${card.windowDays} days`}
				>
					{card.trend.map((day) => (
						<div
							key={day.day}
							className="privacy-series-day"
							title={`${day.day}: ${day.allow} allowed, ${day.ask} ask, ${day.deny} denied`}
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
				<summary className="small">Daily table</summary>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Day (UTC)</th>
								<th>Allowed</th>
								<th>Ask</th>
								<th>Denied</th>
								<th>Browser masked</th>
								<th>Browser blocked</th>
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
	const a = card.approvals;
	const o = card.oversight;
	const decided = a.approved + a.denied;
	return (
		<section className="card" aria-labelledby="governance-oversight">
			<h2 id="governance-oversight">Human oversight</h2>
			<p className="muted small">
				How held (ask) agent actions were decided by people outside the agent. Dashboard approvals
				are counted from their requests; local operator approvals only when a connector reported the
				release.
			</p>
			<div className="grid">
				<Stat
					label="Approval requests"
					value={n(a.requested)}
					hint={`${n(a.pending)} pending now`}
				/>
				<Stat
					label="Approve / deny"
					value={`${n(a.approved)} / ${n(a.denied)}`}
					hint={decided ? `${Math.round((100 * a.approved) / decided)}% approved` : "no decisions"}
				/>
				<Stat
					label="Median decision time"
					value={duration(a.medianDecisionSeconds)}
					hint={`90th percentile ${duration(a.p90DecisionSeconds)}`}
				/>
				<Stat
					label="Expired without decision"
					value={n(a.expiredWithoutDecision)}
					hint="the action stayed blocked"
				/>
				<Stat
					label="Released after approval"
					value={n(card.decisions.releasedByDashboard + card.decisions.releasedByOperator)}
					hint={`${n(card.decisions.releasedByDashboard)} dashboard · ${n(card.decisions.releasedByOperator)} local operator`}
				/>
			</div>
			<h3>Approvers</h3>
			<p className="muted small">
				A review prompt appears for an approver with at least {o.thresholds.minDecisions} decisions
				of which at least {Math.round(o.thresholds.fastShare * 100)}% were approvals made within{" "}
				{o.thresholds.fastSeconds} s of the request. It asks you to check for automatic approval
				(automation bias); it is not a finding about the person. Thresholds are set under Scheduled
				summary below.
			</p>
			{o.byApprover.length === 0 ? (
				<p className="muted">No approval decisions in this window.</p>
			) : (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Approver</th>
								<th>Decisions</th>
								<th>Approved</th>
								<th>Denied</th>
								<th>Fast approvals</th>
								<th>Median time</th>
								<th>Review</th>
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
												Review pattern
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
	const i = card.incidents;
	return (
		<section className="card" aria-labelledby="governance-incidents">
			<h2 id="governance-incidents">Incidents and AI tool-chain posture</h2>
			<div className="grid">
				<Stat label="Incidents reported" value={n(i.reported)} hint={`${n(i.open)} still open`} />
				<Stat
					label="Open critical / high"
					value={`${n(i.openBySeverity.critical)} / ${n(i.openBySeverity.high)}`}
					hint={i.statusUnknown ? `${n(i.statusUnknown)} without a reported status` : undefined}
				/>
				<Stat
					label="Posture findings"
					value={n(card.posture.findings)}
					hint={`${n(card.posture.critical)} critical · ${n(card.posture.high)} high · ${n(card.posture.cveConfirmed)} confirmed CVE`}
				/>
			</div>
		</section>
	);
}

function BrowserGuardCard({ card }: { card: GovernanceScorecard }) {
	const g = card.browserGuard;
	const active = card.usage.browserInstalls.active;
	return (
		<section className="card" aria-labelledby="governance-browser">
			<h2 id="governance-browser">Browser Guard and acceptable use</h2>
			<div className="grid">
				<Stat label="Sends scanned" value={n(g.scans)} />
				<Stat label="Masked" value={n(g.masked)} hint={`${n(g.itemsMasked)} items replaced`} />
				<Stat label="Warned / blocked" value={`${n(g.warned)} / ${n(g.blocked)}`} />
			</div>
			<h3>Acceptable-use acknowledgements</h3>
			<p className="muted small">
				Browser installs that pressed "I understand" on the acceptable-use notice, per notice
				version (counts only; publish the notice from{" "}
				<Link to="/privacy-guard">Browser Privacy</Link>).
			</p>
			{card.acceptableUse.length === 0 ? (
				<p className="muted">
					No acknowledgements reported. Publish a notice in the Browser Guard managed policy.
				</p>
			) : (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Notice</th>
								<th>Version</th>
								<th>Installs acknowledged</th>
								<th>Of active browsers</th>
								<th>Last acknowledged</th>
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
	const p = card.policies;
	const row = (label: string, value: GovernanceScorecard["policies"]["runtime"]) => (
		<tr key={label}>
			<td>{label}</td>
			<td>{value ? (value.version === null ? "—" : `v${value.version}`) : "not configured"}</td>
			<td>{value ? `${n(value.ageDays)} days ago` : "—"}</td>
		</tr>
	);
	return (
		<section className="card" aria-labelledby="governance-policies">
			<h2 id="governance-policies">Policy freshness</h2>
			<div className="table-wrap">
				<table className="table">
					<thead>
						<tr>
							<th>Policy</th>
							<th>Version</th>
							<th>Last changed</th>
						</tr>
					</thead>
					<tbody>
						{row("Runtime policy", p.runtime)}
						{row("DLP policy", p.dlp)}
						{row("Team policy", p.team)}
					</tbody>
				</table>
			</div>
			<p className="muted small">
				Revisions in this window: {n(p.runtimeRevisionsInPeriod)} runtime,{" "}
				{n(p.dlpRevisionsInPeriod)} DLP. MFA{" "}
				{card.identity.requireMfa ? "required" : "not required"}, single sign-on{" "}
				{card.identity.ssoRequired ? "required" : "not required"}, telemetry kept{" "}
				{card.identity.telemetryRetentionDays === null
					? "without a retention policy"
					: `${n(card.identity.telemetryRetentionDays)} days`}
				.
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
	const problem = settingsProblem(input);

	async function save() {
		if (problem) {
			setStatus({ tone: "error", text: problem });
			return;
		}
		setBusy(true);
		const result = await saveGovernanceSettings(tenantId, input);
		setBusy(false);
		if (!result.ok) {
			setStatus({ tone: "error", text: governanceErrorText(result.error) });
			return;
		}
		setForm(result.value);
		setStatus({
			tone: "ok",
			text: result.value.digestEnabled
				? `Saved. Next summary: ${result.value.digestNextAt ? new Date(result.value.digestNextAt).toUTCString() : "scheduled"}.`
				: "Saved. Scheduled summaries are off.",
		});
		onSaved();
	}

	async function test() {
		setBusy(true);
		const result = await sendTestSummary(tenantId);
		setBusy(false);
		if (!result.ok) {
			setStatus({ tone: "error", text: governanceErrorText(result.error) });
			return;
		}
		setStatus({
			tone: result.value.status === "sent" ? "ok" : "error",
			text:
				result.value.status === "no_recipients"
					? "No owner or admin has an e-mail address, so nothing was sent."
					: `Test summary delivered to ${result.value.delivered} of ${result.value.recipients} recipient(s).`,
		});
		onSaved();
	}

	return (
		<section className="card" aria-labelledby="governance-digest">
			<h2 id="governance-digest">Scheduled summary</h2>
			<p className="muted small">
				A counts-only e-mail to this workspace's owners (and admins) with the figures above. No
				prompt text, page addresses or approver identities are included. Delivery needs the
				deployment's mail transport and its hourly maintenance run.
			</p>
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
					Send a scheduled governance summary
				</label>
				<div className="row" style={{ flexWrap: "wrap", gap: 12 }}>
					<label className="label" htmlFor="governance-digest-cadence">
						Frequency
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
						<option value="weekly">Weekly (Monday 06:00 UTC)</option>
						<option value="monthly">Monthly (1st, 06:00 UTC)</option>
					</select>
					<label className="label" htmlFor="governance-digest-recipients">
						Recipients
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
						<option value="owners_admins">Owners and admins</option>
						<option value="owners">Owners only</option>
					</select>
				</div>
				<fieldset className="row" style={{ flexWrap: "wrap", gap: 12, border: 0, padding: 0 }}>
					<legend className="small">Human-oversight review thresholds</legend>
					<label className="label">
						Fast approval (seconds)
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
						Minimum decisions
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
						Fast-approval share (%)
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
						Save settings
					</button>
					<button
						type="button"
						className="button button-secondary button-sm"
						disabled={busy}
						onClick={() => void test()}
					>
						Send a test summary now
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
					? `Last scheduled summary ${new Date(card.settings.digestLastAt).toUTCString()} (${card.settings.digestLastStatus ?? "unknown"}).`
					: "No scheduled summary has been sent yet."}
			</p>
			{card.recentDeliveries.length ? (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Time</th>
								<th>Kind</th>
								<th>Period</th>
								<th>Status</th>
								<th>Delivered</th>
							</tr>
						</thead>
						<tbody>
							{card.recentDeliveries.map((row) => (
								<tr key={`${row.createdAt}-${row.trigger}`}>
									<td className="mono">{new Date(row.createdAt).toLocaleString()}</td>
									<td>{row.trigger === "test" ? "Test" : row.cadence}</td>
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
	full: "Full",
	partial: "Partial",
	"customer-responsibility": "Customer",
} as const;

function MatrixCard({ coverage }: { coverage: FrameworkCoverage[] }) {
	return (
		<section className="card" aria-labelledby="governance-matrix">
			<h2 id="governance-matrix">Framework control matrix</h2>
			<p className="muted small">
				How Singularity AIDR capabilities map to each framework, with the evidence source that shows
				it and the status in this workspace. Full: the capability performs the activity for the AI
				tools it guards. Partial: it supports part of it. Customer: your organisation performs it;
				product data is input only.
			</p>
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
									<th>Control</th>
									<th>Coverage</th>
									<th>Status here</th>
									<th>Capabilities and evidence</th>
								</tr>
							</thead>
							<tbody>
								{item.controls.map((a) => (
									<tr key={a.control.id}>
										<td>
											<b className="mono">{a.control.id}</b>
											<div className="small">{a.control.title}</div>
										</td>
										<td>{COVERAGE_TEXT[a.control.coverage]}</td>
										<td>{CONTROL_STATUS_LABEL[a.status]}</td>
										<td className="small">
											{a.control.capabilities.map(capabilityTitle).join("; ") || "—"}
											<div className="muted">
												Evidence: {a.control.evidence.map(evidenceDetail).join(" ") || "—"}
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
