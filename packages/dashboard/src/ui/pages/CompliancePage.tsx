import { useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { type Translate, useDashboardLocale, useRichT, useT } from "../../i18n/I18nProvider";
import {
	COMPLIANCE_SECTION_KEYS,
	type CompliancePeriod,
	type ComplianceReport,
	type ComplianceSectionKey,
	complianceErrorText,
	customPeriod,
	generateComplianceReport,
	type JsonObject,
	type JsonValue,
	presetPeriod,
} from "../../lib/compliance-report";
import { csvBundleZip, reportFileStem, sectionBlocks } from "../compliance-export";
import { PRINT_LABELS, type PrintLanguage, renderPrintableReport } from "../compliance-print";

const PRESETS = [
	{ value: "30", days: 30 },
	{ value: "90", days: 90 },
	{ value: "180", days: 180 },
	{ value: "365", days: 365 },
] as const;

type Status =
	| { kind: "idle" }
	| { kind: "loading" }
	| { kind: "error"; code: string }
	| { kind: "ready"; report: ComplianceReport };

function saveFile(name: string, content: BlobPart, type: string) {
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

function today(): string {
	return new Date().toISOString().slice(0, 10);
}

export function CompliancePage() {
	const t = useT();
	const { currentTeam, currentRole, isLoading, roleResolved } = useTeam();
	if (isLoading || (currentTeam && !roleResolved)) {
		return <div role="status">{t("gsc.resolving")}</div>;
	}
	if (!currentTeam) return <div role="alert">{t("cmp.selectTeam")}</div>;
	if (currentRole !== "owner" && currentRole !== "admin") {
		return (
			<section className="card">
				<h1>{t("cmp.title")}</h1>
				<div className="notice" role="alert">
					{t("cmp.ownersOnly")}
				</div>
			</section>
		);
	}
	return <TenantCompliancePage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantCompliancePage({ tenantId }: { tenantId: string }) {
	const t = useT();
	const richT = useRichT();
	const locale = useDashboardLocale();
	const [preset, setPreset] = useState<string>("90");
	const [fromDay, setFromDay] = useState("");
	const [toDay, setToDay] = useState(today());
	const [status, setStatus] = useState<Status>({ kind: "idle" });
	// The printable report defaults to the console language.
	const [language, setLanguage] = useState<PrintLanguage>(locale);

	async function generate() {
		let period: CompliancePeriod;
		if (preset === "custom") {
			const custom = customPeriod(fromDay, toDay);
			if (!custom.ok) {
				setStatus({ kind: "error", code: custom.error });
				return;
			}
			period = custom.value;
		} else {
			period = presetPeriod(Number(preset));
		}
		setStatus({ kind: "loading" });
		const result = await generateComplianceReport(tenantId, period);
		setStatus(
			result.ok ? { kind: "ready", report: result.value } : { kind: "error", code: result.error },
		);
	}

	const report = status.kind === "ready" ? status.report : null;

	return (
		<div className="stack">
			<section className="card">
				<p className="eyebrow">{t("cmp.eyebrow")}</p>
				<h1>{t("cmp.title")}</h1>
				<p className="muted">{t("cmp.lead")}</p>
				<form
					className="row"
					style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}
					onSubmit={(event) => {
						event.preventDefault();
						void generate();
					}}
				>
					<label className="label">
						{t("cmp.period")}
						<select
							className="input"
							value={preset}
							onChange={(event) => setPreset(event.target.value)}
						>
							{PRESETS.map((option) => (
								<option key={option.value} value={option.value}>
									{t("cmp.last", { count: option.days })}
								</option>
							))}
							<option value="custom">{t("cmp.custom")}</option>
						</select>
					</label>
					{preset === "custom" ? (
						<>
							<label className="label">
								{t("cmp.from")}
								<input
									className="input"
									type="date"
									value={fromDay}
									max={toDay || today()}
									onChange={(event) => setFromDay(event.target.value)}
									required
								/>
							</label>
							<label className="label">
								{t("cmp.to")}
								<input
									className="input"
									type="date"
									value={toDay}
									max={today()}
									onChange={(event) => setToDay(event.target.value)}
									required
								/>
							</label>
						</>
					) : null}
					<button className="button" type="submit" disabled={status.kind === "loading"}>
						{status.kind === "loading" ? t("cmp.generating") : t("cmp.generate")}
					</button>
				</form>
				<p className="muted small">{t("cmp.limits")}</p>
				{status.kind === "loading" ? <div role="status">{t("cmp.collecting")}</div> : null}
				{status.kind === "error" ? (
					<div className="notice notice-danger" role="alert">
						{complianceErrorText(status.code, t)}
					</div>
				) : null}
			</section>

			{report ? (
				<>
					<ReportHeader report={report} labels={PRINT_LABELS[locale]} />
					<section className="card" aria-labelledby="compliance-downloads">
						<h2 id="compliance-downloads">{t("cmp.download")}</h2>
						<p className="muted small">
							{richT("cmp.downloadLead", {
								command: <code>aidr compliance verify &lt;report.json&gt;</code>,
							})}
						</p>
						<div className="row" style={{ flexWrap: "wrap", gap: 8, alignItems: "flex-end" }}>
							<button
								type="button"
								className="button button-sm"
								onClick={() =>
									saveFile(
										`${reportFileStem(report)}.json`,
										`${JSON.stringify(report, null, 2)}\n`,
										"application/json",
									)
								}
							>
								{t("cmp.downloadJson")}
							</button>
							<button
								type="button"
								className="button button-secondary button-sm"
								onClick={() =>
									saveFile(
										`${reportFileStem(report)}-csv.zip`,
										csvBundleZip(report) as BlobPart,
										"application/zip",
									)
								}
							>
								{t("cmp.downloadCsv")}
							</button>
							<label className="label">
								{t("cmp.printLanguage")}
								<select
									className="input"
									value={language}
									onChange={(event) => setLanguage(event.target.value as PrintLanguage)}
								>
									<option value="en" lang="en">
										English
									</option>
									<option value="tr" lang="tr">
										Türkçe
									</option>
								</select>
							</label>
							<button
								type="button"
								className="button button-secondary button-sm"
								onClick={() => {
									const html = renderPrintableReport(report, language);
									const view = window.open("", "_blank");
									if (!view) {
										saveFile(`${reportFileStem(report)}-${language}.html`, html, "text/html");
										return;
									}
									view.opener = null;
									view.document.open();
									view.document.write(html);
									view.document.close();
									view.focus();
									view.print();
								}}
							>
								{t("gsc.print")}
							</button>
							<button
								type="button"
								className="button button-secondary button-sm"
								onClick={() =>
									saveFile(
										`${reportFileStem(report)}-${language}.html`,
										renderPrintableReport(report, language),
										"text/html",
									)
								}
							>
								{t("gsc.download")}
							</button>
						</div>
					</section>
					{COMPLIANCE_SECTION_KEYS.map((key) => (
						<SectionPreview
							key={key}
							sectionKey={key}
							section={report.sections[key]}
							language={locale}
						/>
					))}
					<section className="card" aria-labelledby="compliance-limitations">
						<h2 id="compliance-limitations">{t("cmp.limitations")}</h2>
						<ul>
							{report.limitations.map((text) => (
								<li key={text} className="small">
									{PRINT_LABELS[locale].limitations[text] ?? text}
								</li>
							))}
						</ul>
					</section>
				</>
			) : null}
		</div>
	);
}

function ReportHeader({
	report,
	labels,
}: {
	report: ComplianceReport;
	labels: (typeof PRINT_LABELS)[PrintLanguage];
}) {
	const t = useT();
	const locale = useDashboardLocale();
	const signature = report.integrity.signature;
	const profile = report.sections.tenant_profile;
	return (
		<section className="card" aria-label={t("cmp.summary")}>
			<div className="row space-between" style={{ alignItems: "flex-start" }}>
				<div>
					<h2>{String(profile.name ?? "")}</h2>
					<p className="muted small">
						{t("cmp.periodLine", {
							from: report.period.from.slice(0, 10),
							to: report.period.to.slice(0, 10),
							days: report.period.days,
							time: new Date(report.generated_at).toLocaleString(),
						})}
					</p>
				</div>
				<span className="badge">{signature ? t("cmp.signed") : t("cmp.hashOnly")}</span>
			</div>
			<dl className="kv">
				<dt>{t("cmp.reportId")}</dt>
				<dd className="mono">{report.report_id}</dd>
				<dt>SHA-256</dt>
				<dd className="mono" style={{ overflowWrap: "anywhere" }}>
					{report.integrity.sha256} <span className="muted small">{t("cmp.recomputed")}</span>
				</dd>
				<dt>{t("cmp.signature")}</dt>
				<dd>{signature ? t("cmp.signedWith", { key: signature.key_id }) : t("cmp.unsigned")}</dd>
			</dl>
			{/* The signed statement is English; the Turkish rendering is the print edition's translation. */}
			<p className="small">{locale === "en" ? report.statement : labels.statement}</p>
		</section>
	);
}

function num(value: JsonValue | undefined): string {
	return typeof value === "number" ? value.toLocaleString() : "—";
}

function get(section: JsonObject, path: string): JsonValue | undefined {
	let value: JsonValue | undefined = section;
	for (const part of path.split(".")) {
		if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
		value = value[part];
	}
	return value;
}

function highlights(
	key: ComplianceSectionKey,
	section: JsonObject,
	t: Translate,
): Array<[string, string]> {
	const yesNo = (value: JsonValue | undefined) =>
		value === true ? t("cmp.yes") : value === false ? t("cmp.no") : t("cmp.notConfigured");
	switch (key) {
		case "tenant_profile":
			return [
				[t("cmp.h.region"), String(get(section, "region") ?? t("cmp.notRecorded"))],
				[t("cmp.h.retention"), t("common.days", { count: num(get(section, "retention_days")) })],
				[t("cmp.h.status"), String(get(section, "status") ?? "—")],
			];
		case "protection_coverage":
			return [
				[t("cmp.h.enrolled"), num(get(section, "totals.enrolled"))],
				[t("cmp.h.active"), num(get(section, "totals.active_in_period"))],
				[t("cmp.h.browsersActive"), num(get(section, "totals.browser_installs_active_in_period"))],
			];
		case "data_protection_activity":
			return [
				[t("cmp.h.masked"), num(get(section, "browser_guard.totals.masked"))],
				[t("cmp.h.blocked"), num(get(section, "browser_guard.totals.blocked"))],
				[t("cmp.h.dlp"), num(get(section, "agent_decisions.data_protection.decisions"))],
			];
		case "policy_inventory": {
			const dlp = get(section, "dlp.current.version");
			const runtime = get(section, "runtime.current.version");
			return [
				[t("cmp.h.dlpPolicy"), typeof dlp === "number" ? `v${dlp}` : t("cmp.none")],
				[t("cmp.h.runtimePolicy"), typeof runtime === "number" ? `v${runtime}` : t("cmp.none")],
				[
					t("cmp.h.agentApproval"),
					yesNo(get(section, "approval_settings.agent_callable_approval")),
				],
			];
		}
		case "access_identity": {
			const admins = get(section, "admins");
			const list = Array.isArray(admins) ? admins : [];
			const withMfa = list.filter(
				(admin) =>
					admin !== null &&
					typeof admin === "object" &&
					!Array.isArray(admin) &&
					admin.mfa_verified === true,
			).length;
			return [
				[t("cmp.h.mfa"), yesNo(get(section, "identity_policy.require_mfa"))],
				[t("cmp.h.sso"), yesNo(get(section, "identity_policy.sso_required"))],
				[t("cmp.h.adminsMfa"), t("cmp.h.ofTotal", { count: withMfa, total: list.length })],
			];
		}
		case "incidents":
			return [
				[t("cmp.h.incidents"), num(get(section, "incidents.total"))],
				[t("cmp.h.pluginScans"), num(get(section, "plugin_scans_with_findings"))],
			];
		case "ai_security_posture":
			return [
				[t("cmp.h.cve"), num(get(section, "cve.findings"))],
				[t("cmp.h.criticalCve"), num(get(section, "cve.by_severity.critical") ?? 0)],
				[t("cmp.h.mcp"), num(get(section, "mcp.findings"))],
			];
		case "data_flows": {
			const flows = get(section, "flows");
			return [
				[t("cmp.h.flows"), num(Array.isArray(flows) ? flows.length : undefined)],
				[t("cmp.h.unknowns"), num(get(section, "open_unknowns"))],
				[t("cmp.h.matrix"), String(get(section, "matrix_status") ?? "—")],
			];
		}
		case "retention_deletion":
			return [
				[t("cmp.h.telemetry"), yesNo(get(section, "telemetry.within_policy"))],
				[t("cmp.h.legalHold"), yesNo(get(section, "legal_holds.active"))],
				[t("cmp.h.exports"), num(get(section, "audit_exports.expired_pending_cleanup"))],
			];
		case "control_mappings": {
			const frameworks = get(section, "frameworks");
			const list = Array.isArray(frameworks) ? frameworks : [];
			return list.flatMap((framework): Array<[string, string]> => {
				if (framework === null || typeof framework !== "object" || Array.isArray(framework))
					return [];
				const controls = Array.isArray(framework.controls) ? framework.controls : [];
				const covered = controls.filter(
					(control) =>
						control !== null &&
						typeof control === "object" &&
						!Array.isArray(control) &&
						control.coverage !== "customer-responsibility",
				).length;
				return [
					[
						String(framework.name ?? framework.id ?? "—"),
						t("cmp.h.mappedControls", { covered, total: controls.length }),
					],
				];
			});
		}
	}
}

function SectionPreview({
	sectionKey,
	section,
	language,
}: {
	sectionKey: ComplianceSectionKey;
	section: JsonObject;
	language: PrintLanguage;
}) {
	const t = useT();
	const meta = PRINT_LABELS[language].sections[sectionKey];
	const headingId = `compliance-${sectionKey}`;
	return (
		<section className="card" aria-labelledby={headingId}>
			<h2 id={headingId}>{meta.title}</h2>
			<p className="muted small">{meta.proves}</p>
			<dl className="kv">
				{highlights(sectionKey, section, t).map(([label, value]) => (
					<div key={label} style={{ display: "contents" }}>
						<dt>{label}</dt>
						<dd>{value}</dd>
					</div>
				))}
			</dl>
			<details>
				<summary>{t("cmp.allFields")}</summary>

				{sectionBlocks(section).map((block) => (
					<div key={block.path || "fields"} className="table-wrap">
						{block.path ? <h3 className="small">{block.path}</h3> : null}
						<table className="table">
							<thead>
								<tr>
									{block.headers.map((header) => (
										<th key={header}>{header}</th>
									))}
								</tr>
							</thead>
							<tbody>
								{block.rows.map((row, index) => (
									<tr key={index}>
										{row.map((cell, column) => (
											<td key={column} className={column === 0 ? "mono" : undefined}>
												{cell === null ? "—" : String(cell)}
											</td>
										))}
									</tr>
								))}
							</tbody>
						</table>
					</div>
				))}
			</details>
		</section>
	);
}
