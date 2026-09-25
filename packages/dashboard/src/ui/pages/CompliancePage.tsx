import { useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
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
	{ value: "30", label: "Last 30 days", days: 30 },
	{ value: "90", label: "Last 90 days", days: 90 },
	{ value: "180", label: "Last 180 days", days: 180 },
	{ value: "365", label: "Last 365 days", days: 365 },
] as const;

type Status =
	| { kind: "idle" }
	| { kind: "loading" }
	| { kind: "error"; message: string }
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
	const { currentTeam, currentRole, isLoading, roleResolved } = useTeam();
	if (isLoading || (currentTeam && !roleResolved)) {
		return <div role="status">Resolving the managed tenant…</div>;
	}
	if (!currentTeam) return <div role="alert">Select a team to generate a compliance report.</div>;
	if (currentRole !== "owner" && currentRole !== "admin") {
		return (
			<section className="card">
				<h1>Compliance evidence report</h1>
				<div className="notice" role="alert">
					Only workspace owners and admins can generate compliance reports.
				</div>
			</section>
		);
	}
	return <TenantCompliancePage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantCompliancePage({ tenantId }: { tenantId: string }) {
	const [preset, setPreset] = useState<string>("90");
	const [fromDay, setFromDay] = useState("");
	const [toDay, setToDay] = useState(today());
	const [status, setStatus] = useState<Status>({ kind: "idle" });
	const [language, setLanguage] = useState<PrintLanguage>("en");

	async function generate() {
		let period: CompliancePeriod;
		if (preset === "custom") {
			const custom = customPeriod(fromDay, toDay);
			if (!custom.ok) {
				setStatus({ kind: "error", message: complianceErrorText(custom.error) });
				return;
			}
			period = custom.value;
		} else {
			period = presetPeriod(Number(preset));
		}
		setStatus({ kind: "loading" });
		const result = await generateComplianceReport(tenantId, period);
		setStatus(
			result.ok
				? { kind: "ready", report: result.value }
				: { kind: "error", message: complianceErrorText(result.error) },
		);
	}

	const report = status.kind === "ready" ? status.report : null;

	return (
		<div className="stack">
			<section className="card">
				<p className="eyebrow">Security and data protection</p>
				<h1>Compliance evidence report</h1>
				<p className="muted">
					A signed, tenant-scoped evidence bundle for security and DPO teams, designed to support
					KVKK and GDPR accountability work: protection coverage, data-protection activity (counts
					only), policies in force, access and identity, incidents, AI security posture, data flows
					and retention evidence. It is not a certification and does not state that your
					organization is compliant.
				</p>
				<form
					className="row"
					style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 12 }}
					onSubmit={(event) => {
						event.preventDefault();
						void generate();
					}}
				>
					<label className="label">
						Period
						<select
							className="input"
							value={preset}
							onChange={(event) => setPreset(event.target.value)}
						>
							{PRESETS.map((option) => (
								<option key={option.value} value={option.value}>
									{option.label}
								</option>
							))}
							<option value="custom">Custom range</option>
						</select>
					</label>
					{preset === "custom" ? (
						<>
							<label className="label">
								From (UTC)
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
								To (UTC, inclusive)
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
						{status.kind === "loading" ? "Generating…" : "Generate report"}
					</button>
				</form>
				<p className="muted small">
					At most 366 days. Requires an owner or admin session with multi-factor authentication
					(AAL2). Every generated report is recorded in the workspace audit log.
				</p>
				{status.kind === "loading" ? (
					<div role="status">Collecting evidence and sealing the report…</div>
				) : null}
				{status.kind === "error" ? (
					<div className="notice notice-danger" role="alert">
						{status.message}
					</div>
				) : null}
			</section>

			{report ? (
				<>
					<ReportHeader report={report} />
					<section className="card" aria-labelledby="compliance-downloads">
						<h2 id="compliance-downloads">Download</h2>
						<p className="muted small">
							The JSON file is the authoritative artifact. Verify it offline with{" "}
							<code>aidr compliance verify &lt;report.json&gt;</code>. CSV and printable editions
							are derived from it in this browser.
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
								Download JSON
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
								Download CSV bundle (.zip)
							</button>
							<label className="label">
								Printable report language
								<select
									className="input"
									value={language}
									onChange={(event) => setLanguage(event.target.value as PrintLanguage)}
								>
									<option value="en">English</option>
									<option value="tr">Türkçe</option>
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
								Print / save as PDF
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
								Download printable HTML
							</button>
						</div>
					</section>
					{COMPLIANCE_SECTION_KEYS.map((key) => (
						<SectionPreview key={key} sectionKey={key} section={report.sections[key]} />
					))}
					<section className="card" aria-labelledby="compliance-limitations">
						<h2 id="compliance-limitations">What this report does not prove</h2>
						<ul>
							{report.limitations.map((text) => (
								<li key={text} className="small">
									{text}
								</li>
							))}
						</ul>
					</section>
				</>
			) : null}
		</div>
	);
}

function ReportHeader({ report }: { report: ComplianceReport }) {
	const signature = report.integrity.signature;
	const profile = report.sections.tenant_profile;
	return (
		<section className="card" aria-label="Report summary">
			<div className="row space-between" style={{ alignItems: "flex-start" }}>
				<div>
					<h2>{String(profile.name ?? "")}</h2>
					<p className="muted small">
						{report.period.from.slice(0, 10)} – {report.period.to.slice(0, 10)} ·{" "}
						{report.period.days} days · generated {new Date(report.generated_at).toLocaleString()}
					</p>
				</div>
				<span className="badge">{signature ? "Signed" : "Hash only"}</span>
			</div>
			<dl className="kv">
				<dt>Report ID</dt>
				<dd className="mono">{report.report_id}</dd>
				<dt>SHA-256</dt>
				<dd className="mono" style={{ overflowWrap: "anywhere" }}>
					{report.integrity.sha256}{" "}
					<span className="muted small">(recomputed in this browser)</span>
				</dd>
				<dt>Signature</dt>
				<dd>
					{signature
						? `Ed25519, key ${signature.key_id}`
						: "Not signed: this deployment has no compliance signing key configured."}
				</dd>
			</dl>
			<p className="small">{report.statement}</p>
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

function highlights(key: ComplianceSectionKey, section: JsonObject): Array<[string, string]> {
	const yesNo = (value: JsonValue | undefined) =>
		value === true ? "Yes" : value === false ? "No" : "Not configured";
	switch (key) {
		case "tenant_profile":
			return [
				["Region", String(get(section, "region") ?? "Not recorded")],
				["Retention", `${num(get(section, "retention_days"))} days`],
				["Status", String(get(section, "status") ?? "—")],
			];
		case "protection_coverage":
			return [
				["Enrolled agents", num(get(section, "totals.enrolled"))],
				["Active in period", num(get(section, "totals.active_in_period"))],
				["Browser installs active", num(get(section, "totals.browser_installs_active_in_period"))],
			];
		case "data_protection_activity":
			return [
				["Browser sends masked", num(get(section, "browser_guard.totals.masked"))],
				["Browser sends blocked", num(get(section, "browser_guard.totals.blocked"))],
				["Agent DLP decisions", num(get(section, "agent_decisions.data_protection.decisions"))],
			];
		case "policy_inventory": {
			const dlp = get(section, "dlp.current.version");
			const runtime = get(section, "runtime.current.version");
			return [
				["DLP policy", typeof dlp === "number" ? `v${dlp}` : "None"],
				["Runtime policy", typeof runtime === "number" ? `v${runtime}` : "None"],
				[
					"Agent-callable approval",
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
				["MFA required", yesNo(get(section, "identity_policy.require_mfa"))],
				["SSO required", yesNo(get(section, "identity_policy.sso_required"))],
				["Owners/admins with MFA", `${withMfa} of ${list.length}`],
			];
		}
		case "incidents":
			return [
				["Incidents", num(get(section, "incidents.total"))],
				["Plugin scans with findings", num(get(section, "plugin_scans_with_findings"))],
			];
		case "ai_security_posture":
			return [
				["CVE findings", num(get(section, "cve.findings"))],
				["Critical CVEs", num(get(section, "cve.by_severity.critical") ?? 0)],
				["MCP findings", num(get(section, "mcp.findings"))],
			];
		case "data_flows": {
			const flows = get(section, "flows");
			return [
				["Data flows", num(Array.isArray(flows) ? flows.length : undefined)],
				["Open unknowns", num(get(section, "open_unknowns"))],
				["Matrix status", String(get(section, "matrix_status") ?? "—")],
			];
		}
		case "retention_deletion":
			return [
				["Telemetry within retention", yesNo(get(section, "telemetry.within_policy"))],
				["Legal hold active", yesNo(get(section, "legal_holds.active"))],
				["Exports pending clean-up", num(get(section, "audit_exports.expired_pending_cleanup"))],
			];
	}
}

function SectionPreview({
	sectionKey,
	section,
}: {
	sectionKey: ComplianceSectionKey;
	section: JsonObject;
}) {
	const meta = PRINT_LABELS.en.sections[sectionKey];
	const headingId = `compliance-${sectionKey}`;
	return (
		<section className="card" aria-labelledby={headingId}>
			<h2 id={headingId}>{meta.title}</h2>
			<p className="muted small">{meta.proves}</p>
			<dl className="kv">
				{highlights(sectionKey, section).map(([label, value]) => (
					<div key={label} style={{ display: "contents" }}>
						<dt>{label}</dt>
						<dd>{value}</dd>
					</div>
				))}
			</dl>
			<details>
				<summary>All fields</summary>
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
