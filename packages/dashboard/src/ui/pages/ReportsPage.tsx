import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { useDashboardLocale, useT } from "../../i18n/I18nProvider";
import { stepUpPath } from "../../lib/ai-governance";
import { sendTestSummary } from "../../lib/governance";
import {
	downloadExecutiveReport,
	type ExecutiveView,
	REPORT_WINDOWS,
	type ReportLanguage,
	type ReportWindow,
	readExecutiveSummary,
	readTeamRollup,
	reportErrorMessage,
	saveReportOptions,
	type TeamRollupRow,
} from "../../lib/reports";

type ReportOptions = { language: ReportLanguage; attachment: boolean };

type Load<T> = { kind: "loading" } | { kind: "error"; code: string } | { kind: "ready"; value: T };

function saveFile(name: string, content: string) {
	const url = URL.createObjectURL(new Blob([content], { type: "text/html;charset=utf-8" }));
	const anchor = document.createElement("a");
	anchor.href = url;
	anchor.download = name;
	anchor.rel = "noopener";
	document.body.append(anchor);
	anchor.click();
	anchor.remove();
	setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Executive summary, team rollup and scheduled report delivery (owners and admins). */
export function ReportsPage() {
	const t = useT();
	const { currentTeam, currentRole, isLoading, roleResolved } = useTeam();
	if (isLoading || (currentTeam && !roleResolved))
		return <div role="status">{t("gsc.resolving")}</div>;
	if (!currentTeam) return <div role="alert">{t("rpt.selectTeam")}</div>;
	if (currentRole !== "owner" && currentRole !== "admin") {
		return (
			<section className="card">
				<h1>{t("nav.reports")}</h1>
				<div className="notice" role="alert">
					{t("rpt.ownersOnly")}
				</div>
			</section>
		);
	}
	return <TenantReportsPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantReportsPage({ tenantId }: { tenantId: string }) {
	const t = useT();
	const locale = useDashboardLocale();
	const [days, setDays] = useState<ReportWindow>(30);
	const [language, setLanguage] = useState<ReportLanguage>(locale === "tr" ? "tr" : "en");
	const [summary, setSummary] = useState<Load<ExecutiveView>>({ kind: "loading" });
	const [teams, setTeams] = useState<Load<TeamRollupRow[]>>({ kind: "loading" });
	const [notice, setNotice] = useState<{
		tone: "ok" | "error";
		text: string;
		stepUp?: boolean;
	} | null>(null);
	const [busy, setBusy] = useState(false);
	const [options, setOptions] = useState<{ language: ReportLanguage; attachment: boolean } | null>(
		null,
	);
	const [includeTeams, setIncludeTeams] = useState(false);

	useEffect(() => {
		let cancelled = false;
		setSummary({ kind: "loading" });
		void readExecutiveSummary(tenantId, days, language).then((result) => {
			if (cancelled) return;
			setSummary(
				result.ok ? { kind: "ready", value: result.value } : { kind: "error", code: result.error },
			);
			if (result.ok) {
				setOptions(
					(previous) =>
						previous ?? {
							language: result.value.options.language,
							attachment: result.value.options.attachment,
						},
				);
			}
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId, days, language]);

	useEffect(() => {
		let cancelled = false;
		setTeams({ kind: "loading" });
		void readTeamRollup(tenantId, days).then((result) => {
			if (!cancelled)
				setTeams(
					result.ok
						? { kind: "ready", value: result.value }
						: { kind: "error", code: result.error },
				);
		});
		return () => {
			cancelled = true;
		};
	}, [tenantId, days]);

	const fail = (code: string) =>
		setNotice({
			tone: "error",
			text: reportErrorMessage(code, t),
			stepUp: code === "mfa_required",
		});

	async function download() {
		setBusy(true);
		const result = await downloadExecutiveReport(tenantId, days, language, includeTeams);
		setBusy(false);
		if (!result.ok) return fail(result.error);
		saveFile(result.value.filename, result.value.html);
		setNotice({ tone: "ok", text: t("rpt.downloaded", { file: result.value.filename }) });
	}

	async function saveOptions() {
		if (!options) return;
		setBusy(true);
		const result = await saveReportOptions(tenantId, options.language, options.attachment);
		setBusy(false);
		if (!result.ok) return fail(result.error);
		setOptions(result.value);
		setNotice({ tone: "ok", text: t("rpt.optionsSaved") });
	}

	async function sendTest() {
		setBusy(true);
		const result = await sendTestSummary(tenantId);
		setBusy(false);
		if (!result.ok) {
			setNotice({
				tone: "error",
				text:
					result.error === "mail_not_configured"
						? t("rpt.err.noMail")
						: reportErrorMessage(result.error, t),
				stepUp: result.error === "mfa_required",
			});
			return;
		}
		setNotice({
			tone: "ok",
			text: t("rpt.testSent", {
				delivered: result.value.delivered,
				recipients: result.value.recipients,
			}),
		});
	}

	return (
		<div className="stack">
			<section className="card">
				<h1>{t("nav.reports")}</h1>
				<p className="muted">{t("rpt.lead")}</p>
				<div className="row" style={{ alignItems: "center" }}>
					<label>
						{t("rpt.window")}{" "}
						<select value={days} onChange={(e) => setDays(Number(e.target.value) as ReportWindow)}>
							{REPORT_WINDOWS.map((value) => (
								<option key={value} value={value}>
									{t("rpt.lastDays", { count: value })}
								</option>
							))}
						</select>
					</label>
					<label>
						{t("rpt.language")}{" "}
						<select
							value={language}
							onChange={(e) => setLanguage(e.target.value as ReportLanguage)}
						>
							<option value="en">English</option>
							<option value="tr">Türkçe</option>
						</select>
					</label>
				</div>
				{notice ? (
					<div
						className={notice.tone === "ok" ? "notice" : "notice notice-error"}
						role={notice.tone === "ok" ? "status" : "alert"}
					>
						{notice.text}{" "}
						{notice.stepUp ? <Link to={stepUpPath(tenantId)}>{t("rpt.verifyNow")}</Link> : null}
					</div>
				) : null}
			</section>

			<ExecutiveCard summary={summary} />

			<TeamRollupCard teams={teams} />

			<section className="card" aria-labelledby="report-download">
				<h2 id="report-download">{t("rpt.download")}</h2>
				<p className="muted small">{t("rpt.downloadLead")}</p>
				<label>
					<input
						type="checkbox"
						checked={includeTeams}
						onChange={(e) => setIncludeTeams(e.target.checked)}
					/>{" "}
					{t("rpt.includeTeams")}
				</label>
				<div className="row">
					<button className="button" type="button" disabled={busy} onClick={() => void download()}>
						{t("rpt.downloadButton")}
					</button>
				</div>
			</section>

			<ScheduleCard
				summary={summary}
				options={options}
				setOptions={setOptions}
				busy={busy}
				onSave={() => void saveOptions()}
				onTest={() => void sendTest()}
			/>
		</div>
	);
}

function ExecutiveCard({ summary }: { summary: Load<ExecutiveView> }) {
	const t = useT();
	return (
		<section className="card" aria-labelledby="executive-summary">
			<h2 id="executive-summary">{t("rpt.executive")}</h2>
			{summary.kind === "loading" ? <div role="status">{t("rpt.loading")}</div> : null}
			{summary.kind === "error" ? (
				<div className="notice notice-error" role="alert">
					{reportErrorMessage(summary.code, t)}
				</div>
			) : null}
			{summary.kind === "ready" ? (
				<>
					<p>
						<span
							className={
								summary.value.status === "attention" ? "badge badge-deny" : "badge badge-allow"
							}
						>
							{summary.value.status === "attention" ? t("rpt.attention") : t("rpt.ok")}
						</span>{" "}
						<span className="muted small">
							{t("rpt.period", {
								from: summary.value.period.from.slice(0, 10),
								to: summary.value.period.to.slice(0, 10),
							})}
						</span>
					</p>
					<ul data-testid="executive-headlines">
						{summary.value.headlines.map((line) => (
							<li key={line.text} className={line.level === "attention" ? "text-error" : undefined}>
								{line.text}
							</li>
						))}
					</ul>
					<details>
						<summary>{t("rpt.details")}</summary>
						{summary.value.sections.map((section) => (
							<div key={section.title}>
								<h3 className="small">{section.title}</h3>
								<ul className="small">
									{section.lines.map((line) => (
										<li key={line}>{line}</li>
									))}
								</ul>
							</div>
						))}
					</details>
				</>
			) : null}
		</section>
	);
}

function TeamRollupCard({ teams }: { teams: Load<TeamRollupRow[]> }) {
	const t = useT();
	return (
		<section className="card" aria-labelledby="team-rollup">
			<h2 id="team-rollup">{t("rpt.teams")}</h2>
			<p className="muted small">{t("rpt.teamsLead")}</p>
			{teams.kind === "loading" ? <div role="status">{t("rpt.loading")}</div> : null}
			{teams.kind === "error" ? (
				<div className="notice notice-error" role="alert">
					{reportErrorMessage(teams.code, t)}
				</div>
			) : null}
			{teams.kind === "ready" ? (
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("rpt.col.team")}</th>
								<th>{t("rpt.col.agents")}</th>
								<th>{t("rpt.col.allow")}</th>
								<th>{t("rpt.col.ask")}</th>
								<th>{t("rpt.col.deny")}</th>
								<th>{t("rpt.col.masked")}</th>
								<th>{t("rpt.col.incidents")}</th>
								<th>{t("rpt.col.critical")}</th>
								<th>{t("rpt.col.unassigned")}</th>
								<th>{t("rpt.col.pending")}</th>
							</tr>
						</thead>
						<tbody>
							{teams.value.map((team) => (
								<tr key={team.tenantId}>
									<td>{team.name}</td>
									{team.figures ? (
										<>
											<td>
												{team.figures.agentsActive.toLocaleString()} /{" "}
												{team.figures.agentsEnrolled.toLocaleString()}
											</td>
											<td>{team.figures.allow.toLocaleString()}</td>
											<td>{team.figures.ask.toLocaleString()}</td>
											<td>{team.figures.deny.toLocaleString()}</td>
											<td>{team.figures.masked.toLocaleString()}</td>
											<td>{team.figures.incidentsActive.toLocaleString()}</td>
											<td>{team.figures.incidentsCritical.toLocaleString()}</td>
											<td>{team.figures.incidentsUnassigned.toLocaleString()}</td>
											<td>{team.figures.approvalsPending.toLocaleString()}</td>
										</>
									) : (
										<td colSpan={9} className="muted small">
											{t("rpt.restricted")}
										</td>
									)}
								</tr>
							))}
						</tbody>
					</table>
				</div>
			) : null}
		</section>
	);
}

function ScheduleCard(props: {
	summary: Load<ExecutiveView>;
	options: ReportOptions | null;
	setOptions: (options: ReportOptions) => void;
	busy: boolean;
	onSave: () => void;
	onTest: () => void;
}) {
	const t = useT();
	const { summary, options, setOptions, busy, onSave, onTest } = props;
	return (
		<section className="card" aria-labelledby="report-schedule">
			<h2 id="report-schedule">{t("rpt.schedule")}</h2>
			<p className="muted small">{t("rpt.scheduleLead")}</p>
			{summary.kind === "ready" ? (
				<p className="small">
					{summary.value.options.digestEnabled
						? t(
								summary.value.options.digestCadence === "monthly"
									? "rpt.scheduleMonthly"
									: "rpt.scheduleWeekly",
							)
						: t("rpt.scheduleOff")}{" "}
					<Link to="/governance">{t("rpt.scheduleLink")}</Link>
				</p>
			) : null}
			{options ? (
				<div className="stack">
					<label>
						{t("rpt.mailLanguage")}{" "}
						<select
							value={options.language}
							onChange={(e) =>
								setOptions({ ...options, language: e.target.value as ReportLanguage })
							}
						>
							<option value="en">English</option>
							<option value="tr">Türkçe</option>
						</select>
					</label>
					<label>
						<input
							type="checkbox"
							checked={options.attachment}
							onChange={(e) => setOptions({ ...options, attachment: e.target.checked })}
						/>{" "}
						{t("rpt.attach")}
					</label>
					<div className="row">
						<button className="button" type="button" disabled={busy} onClick={onSave}>
							{t("rpt.saveOptions")}
						</button>
						<button
							className="button button-secondary"
							type="button"
							disabled={busy}
							onClick={onTest}
						>
							{t("rpt.sendTest")}
						</button>
					</div>
				</div>
			) : null}
		</section>
	);
}
