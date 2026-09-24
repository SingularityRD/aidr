import { useEffect, useMemo, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";

/** Findings older than this are outside the posture window (and the trend). */
export const POSTURE_WINDOW_DAYS = 90;
const TREND_DAYS = 30;
const MAX_ROWS = 5000;
const DAY_MS = 86_400_000;

export type PostureSeverity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export type PostureFindingRow = {
	id: number;
	source: "infra_scan" | "mcp_inventory" | "skill_scan";
	finding_kind: string;
	severity: PostureSeverity;
	cvss: number | string | null;
	vuln_id: string | null;
	component: string | null;
	component_version: string | null;
	applicability: string | null;
	target_digest: string | null;
	mcp_server_name: string | null;
	mcp_transport: string | null;
	risk_categories: string[] | null;
	attestation_status: string | null;
	subject_digest: string | null;
	plugin_key: string | null;
	rule_id: string | null;
	skill_risk_type: string | null;
	observed_at: string;
};

const COLUMNS =
	"id,source,finding_kind,severity,cvss,vuln_id,component,component_version,applicability,target_digest,mcp_server_name,mcp_transport,risk_categories,attestation_status,subject_digest,plugin_key,rule_id,skill_risk_type,observed_at";

const SEVERITY_ORDER: PostureSeverity[] = ["critical", "high", "medium", "low", "info", "unknown"];
const SEVERITY_RANK = new Map(SEVERITY_ORDER.map((severity, index) => [severity, index]));

/** AIG Skill-Scan (SkillTrustBench) taxonomy, mirrored from core. */
export const SKILL_RISK_TYPES: Record<string, string> = {
	T01: "Skill instruction hijacking",
	T02: "Agent memory poisoning",
	T03: "Remote payload retrieval and execution",
	T04: "Embedded malicious code",
	T05: "Unauthorized access and privilege escalation",
	T06: "System persistence",
	T07: "Tool hijacking and spoofing",
	T08: "Insecure dependencies",
	T09: "Insecure skill coding practices",
};

/** AIG MCP risk categories and the local configuration indicators. */
const MCP_CATEGORY_LABELS: Record<string, string> = {
	remote_mcp_url: "Remote endpoint",
	shell_wrapper_command: "Shell wrapper",
	broad_filesystem_access_arg: "Broad filesystem access",
	"mcp-01": "Token mismanagement & secret exposure",
	"mcp-02": "Privilege escalation via scope creep",
	"mcp-03": "Tool poisoning",
	"mcp-04": "Software supply chain",
	"mcp-05": "Command injection & execution",
	"mcp-06": "Prompt injection via context",
	"mcp-07": "Insufficient auth",
	"mcp-08": "Lack of audit & telemetry",
	"mcp-09": "Shadow MCP server",
	"mcp-10": "Context over-sharing",
	"mcp-11": "Name confusion",
	"mcp-12": "Rug pull",
	"mcp-13": "Tool shadowing",
	"mcp-14": "CORS misconfiguration",
};

function severityBadge(severity: PostureSeverity): string {
	if (severity === "critical") return "badge badge-critical";
	if (severity === "high") return "badge badge-high";
	if (severity === "medium") return "badge badge-medium";
	if (severity === "low") return "badge badge-low";
	if (severity === "info") return "badge badge-info";
	return "badge badge-neutral";
}

function cvssOf(row: PostureFindingRow): number | null {
	if (row.cvss === null || row.cvss === undefined) return null;
	const value = typeof row.cvss === "number" ? row.cvss : Number.parseFloat(row.cvss);
	return Number.isFinite(value) ? value : null;
}

function compareSeverity(a: PostureFindingRow, b: PostureFindingRow): number {
	return (SEVERITY_RANK.get(a.severity) ?? 9) - (SEVERITY_RANK.get(b.severity) ?? 9);
}

function bySeverityThenServer(a: PostureFindingRow, b: PostureFindingRow): number {
	return compareSeverity(a, b) || (a.mcp_server_name ?? "").localeCompare(b.mcp_server_name ?? "");
}

function bySeverityThenPlugin(a: PostureFindingRow, b: PostureFindingRow): number {
	return compareSeverity(a, b) || (a.plugin_key ?? "").localeCompare(b.plugin_key ?? "");
}

/**
 * The latest observation of each distinct finding. Every upload is a separate
 * observation (it feeds the trend); the tables show current exposure.
 */
/** Identity of a finding across uploads (per source). */
function findingKey(row: PostureFindingRow): string {
	if (row.source === "infra_scan") {
		return `infra|${row.target_digest ?? ""}|${row.vuln_id ?? ""}|${row.component ?? ""}|${row.finding_kind}`;
	}
	if (row.source === "mcp_inventory") {
		return `mcp|${row.subject_digest ?? row.mcp_server_name ?? row.id}`;
	}
	return `skill|${row.plugin_key ?? ""}|${row.rule_id ?? ""}|${row.subject_digest ?? row.id}`;
}

export function latestFindings(rows: PostureFindingRow[]): PostureFindingRow[] {
	const latest = new Map<string, PostureFindingRow>();
	for (const row of rows) {
		const key = findingKey(row);
		const existing = latest.get(key);
		if (!existing || Date.parse(row.observed_at) > Date.parse(existing.observed_at)) {
			latest.set(key, row);
		}
	}
	return [...latest.values()];
}

export type TrendDay = { day: string; critical: number; high: number; other: number };

/** Findings observed per UTC day over the trend window, oldest first. */
export function postureTrend(
	rows: PostureFindingRow[],
	nowMs: number,
	days = TREND_DAYS,
): TrendDay[] {
	const start = Math.floor(nowMs / DAY_MS) * DAY_MS - (days - 1) * DAY_MS;
	const buckets: TrendDay[] = Array.from({ length: days }, (_, index) => ({
		day: new Date(start + index * DAY_MS).toISOString().slice(0, 10),
		critical: 0,
		high: 0,
		other: 0,
	}));
	for (const row of rows) {
		const observed = Date.parse(row.observed_at);
		if (!Number.isFinite(observed) || observed < start) continue;
		const bucket = buckets[Math.floor((observed - start) / DAY_MS)];
		if (!bucket) continue;
		if (row.severity === "critical") bucket.critical += 1;
		else if (row.severity === "high") bucket.high += 1;
		else if (row.severity !== "info") bucket.other += 1;
	}
	return buckets;
}

type InfraGroup = {
	key: string;
	row: PostureFindingRow;
	targets: number;
	lastSeen: string;
};

function groupInfra(rows: PostureFindingRow[]): InfraGroup[] {
	const groups = new Map<
		string,
		{ row: PostureFindingRow; targets: Set<string>; lastSeen: string }
	>();
	for (const row of rows) {
		const key = `${row.vuln_id ?? row.finding_kind}|${row.component ?? ""}|${row.component_version ?? ""}`;
		const group = groups.get(key);
		if (!group) {
			groups.set(key, {
				row,
				targets: new Set([row.target_digest ?? `row-${row.id}`]),
				lastSeen: row.observed_at,
			});
			continue;
		}
		group.targets.add(row.target_digest ?? `row-${row.id}`);
		if (Date.parse(row.observed_at) > Date.parse(group.lastSeen)) group.lastSeen = row.observed_at;
	}
	return [...groups.entries()]
		.map(([key, group]) => ({
			key,
			row: group.row,
			targets: group.targets.size,
			lastSeen: group.lastSeen,
		}))
		.sort(
			(a, b) =>
				compareSeverity(a.row, b.row) ||
				(cvssOf(b.row) ?? -1) - (cvssOf(a.row) ?? -1) ||
				a.key.localeCompare(b.key),
		);
}

function countBySeverity(rows: PostureFindingRow[]): Record<PostureSeverity, number> {
	const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
	for (const row of rows) counts[row.severity] = (counts[row.severity] ?? 0) + 1;
	return counts;
}

/** Skill findings per T01-T09 risk type, ordered by type. */
function countSkillTypes(skills: PostureFindingRow[]): [string, number][] {
	const counts = new Map<string, number>();
	for (const row of skills) {
		if (row.skill_risk_type)
			counts.set(row.skill_risk_type, (counts.get(row.skill_risk_type) ?? 0) + 1);
	}
	return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
}

/** The tenant's findings in the posture window; `rows` is null when they could not be read. */
async function fetchPostureFindings(
	tenantId: string,
): Promise<{ rows: PostureFindingRow[] | null; error: string | null }> {
	const since = new Date(Date.now() - POSTURE_WINDOW_DAYS * DAY_MS).toISOString();
	try {
		const result = await supabase
			.from("posture_findings")
			.select(COLUMNS)
			.eq("tenant_id", tenantId)
			.gte("observed_at", since)
			.order("observed_at", { ascending: false })
			.limit(MAX_ROWS);
		if (result.error || !Array.isArray(result.data)) {
			return {
				rows: null,
				error: readErrorMessage(result.error, "Failed to load posture findings"),
			};
		}
		return { rows: result.data as unknown as PostureFindingRow[], error: null };
	} catch {
		return { rows: null, error: "Failed to load posture findings" };
	}
}

/** Bar colour for a trend day: its most severe finding. */
function trendColor(day: TrendDay): string {
	if (day.critical > 0) return "var(--sev-critical)";
	return day.high > 0 ? "var(--sev-high)" : "var(--sev-medium)";
}

function riskCategoriesText(row: PostureFindingRow): string {
	const categories = row.risk_categories ?? [];
	if (categories.length === 0) return "No configured risk indicator";
	return categories.map((category) => MCP_CATEGORY_LABELS[category] ?? category).join(", ");
}

function skillCategoryText(row: PostureFindingRow): string {
	if (!row.skill_risk_type) return "Command rule";
	return `${row.skill_risk_type} ${SKILL_RISK_TYPES[row.skill_risk_type] ?? ""}`;
}

function NoPostureData() {
	return (
		<section className="card" aria-label="No posture data">
			<h2>No posture findings reported yet</h2>
			<p className="muted">
				Nothing has been uploaded for this team. That means no scan has reported here — not that the
				environment is clean. Run a scan from an enrolled machine (the CLI uses that installation's
				enrolled API key):
			</p>
			<pre className="mono">
				{[
					"aidr scan --target http://10.0.0.5:11434 --upload   # AI infrastructure CVEs",
					"aidr discover --upload                              # MCP server inventory",
					"aidr scan --skill ~/.claude/skills/<name> --upload  # skill/plugin T01-T09",
				].join("\n")}
			</pre>
		</section>
	);
}

function SkillSection({
	skills,
	skillTypes,
}: {
	skills: PostureFindingRow[];
	skillTypes: [string, number][];
}) {
	return (
		<section className="card" aria-label="Skill and plugin findings">
			<h2>Skill and plugin findings</h2>
			{skillTypes.length > 0 ? (
				<div className="row" style={{ marginTop: 8 }}>
					{skillTypes.map(([type, count]) => (
						<span key={type} className="badge badge-neutral">
							{type} {SKILL_RISK_TYPES[type] ?? ""}: {count}
						</span>
					))}
				</div>
			) : null}
			<div className="table-wrap" style={{ marginTop: 12 }}>
				<table className="table">
					<thead>
						<tr>
							<th>Package</th>
							<th>Rule</th>
							<th>Category</th>
							<th>Severity</th>
							<th>Last seen</th>
						</tr>
					</thead>
					<tbody>
						{skills.map((row) => (
							<tr key={row.id}>
								<td className="mono">{row.plugin_key ?? "(name withheld)"}</td>
								<td className="mono">{row.rule_id ?? "—"}</td>
								<td>{skillCategoryText(row)}</td>
								<td>
									<span className={severityBadge(row.severity)}>{row.severity}</span>
								</td>
								<td className="mono">{new Date(row.observed_at).toLocaleString()}</td>
							</tr>
						))}
						{skills.length === 0 ? (
							<tr>
								<td colSpan={5} className="muted">
									No skill or plugin findings uploaded. Run{" "}
									<span className="mono">aidr scan --skill &lt;dir&gt; --upload</span>.
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</section>
	);
}

function TrendSection({ trend, trendMax }: { trend: TrendDay[]; trendMax: number }) {
	return (
		<section className="card" aria-label="Posture trend">
			<h2>Trend (last {TREND_DAYS} days)</h2>
			<p className="muted small">
				Findings reported per day (every upload is counted as an observation).
			</p>
			<div className="table-wrap" style={{ marginTop: 12 }}>
				<table className="table">
					<thead>
						<tr>
							<th>Day (UTC)</th>
							<th>Critical</th>
							<th>High</th>
							<th>Medium / low / unknown</th>
							<th aria-hidden="true" />
						</tr>
					</thead>
					<tbody>
						{trend
							.filter((day) => day.critical + day.high + day.other > 0)
							.reverse()
							.map((day) => (
								<tr key={day.day} data-testid="trend-day">
									<td className="mono">{day.day}</td>
									<td className="mono">{day.critical}</td>
									<td className="mono">{day.high}</td>
									<td className="mono">{day.other}</td>
									<td aria-hidden="true" style={{ width: "40%" }}>
										<div
											style={{
												height: 8,
												borderRadius: 4,
												background: trendColor(day),
												width: `${((day.critical + day.high + day.other) / trendMax) * 100}%`,
											}}
										/>
									</td>
								</tr>
							))}
						{trend.every((day) => day.critical + day.high + day.other === 0) ? (
							<tr>
								<td colSpan={5} className="muted">
									No non-informational findings reported in the last {TREND_DAYS} days.
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</section>
	);
}

export function PosturePage() {
	const { currentTeam, isLoading } = useTeam();
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	if (!currentTeam) return <div role="alert">Select a team to view AI security posture.</div>;
	return <TenantPosturePage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantPosturePage({ tenantId }: { tenantId: string }) {
	// null = not loaded / unavailable (fail closed); [] = a real, empty posture.
	const [rows, setRows] = useState<PostureFindingRow[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loaded, setLoaded] = useState(false);
	const [nowMs, setNowMs] = useState(() => Date.now());

	useEffect(() => {
		let cancelled = false;
		async function load() {
			const next = await fetchPostureFindings(tenantId);
			if (cancelled) return;
			setRows(next.rows);
			setError(next.error);
			setLoaded(true);
			setNowMs(Date.now());
		}
		void load();
		const timer = setInterval(load, 30_000);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [tenantId]);

	const current = useMemo(() => latestFindings(rows ?? []), [rows]);
	const infra = useMemo(() => current.filter((row) => row.source === "infra_scan"), [current]);
	const vulnerabilities = useMemo(
		() => groupInfra(infra.filter((row) => row.finding_kind !== "exposed_component")),
		[infra],
	);
	const exposedComponents = useMemo(
		() => groupInfra(infra.filter((row) => row.finding_kind === "exposed_component")),
		[infra],
	);
	const mcp = useMemo(
		() => current.filter((row) => row.source === "mcp_inventory").sort(bySeverityThenServer),
		[current],
	);
	const skills = useMemo(
		() => current.filter((row) => row.source === "skill_scan").sort(bySeverityThenPlugin),
		[current],
	);
	const trend = useMemo(() => postureTrend(rows ?? [], nowMs), [rows, nowMs]);
	const infraCounts = useMemo(
		() => countBySeverity(vulnerabilities.map((group) => group.row)),
		[vulnerabilities],
	);
	const skillTypes = useMemo(() => countSkillTypes(skills), [skills]);
	const trendMax = Math.max(1, ...trend.map((day) => day.critical + day.high + day.other));

	return (
		<div className="stack">
			<section className="card">
				<h1>AI security posture</h1>
				<p className="muted">
					Infrastructure exposure, MCP server inventory and skill/plugin package findings reported
					by <span className="mono">aidr scan --upload</span> and{" "}
					<span className="mono">aidr discover --upload</span> over the last {POSTURE_WINDOW_DAYS}{" "}
					days. Only identifiers, severities and digests are stored; target hosts, file paths and
					matched text never leave the scanning machine.
				</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}. Posture data is unavailable; this is not a clean result.
					</div>
				) : null}
				{!loaded && rows === null ? <div role="status">Loading posture findings…</div> : null}
			</section>

			{rows !== null && rows.length === 0 ? <NoPostureData /> : null}

			{rows !== null && rows.length > 0 ? (
				<>
					<section className="grid" aria-label="Posture counters">
						<div className="card stat-card">
							<div className="stat-label">Critical CVEs</div>
							<div className="stat-value">{infraCounts.critical}</div>
						</div>
						<div className="card stat-card">
							<div className="stat-label">High CVEs</div>
							<div className="stat-value">{infraCounts.high}</div>
						</div>
						<div className="card stat-card">
							<div className="stat-label">MCP servers</div>
							<div className="stat-value">{mcp.length}</div>
						</div>
						<div className="card stat-card">
							<div className="stat-label">Skill findings</div>
							<div className="stat-value">{skills.length}</div>
						</div>
					</section>

					<section className="card" aria-label="Infrastructure exposure">
						<h2>Infrastructure exposure</h2>
						<div className="row" style={{ marginTop: 8 }}>
							{SEVERITY_ORDER.filter((severity) => infraCounts[severity] > 0).map((severity) => (
								<span key={severity} className={severityBadge(severity)}>
									{infraCounts[severity]} {severity}
								</span>
							))}
							<span className="badge badge-neutral">
								{exposedComponents.length} identified component(s) without a matched CVE
							</span>
						</div>
						<div className="table-wrap" style={{ marginTop: 12 }}>
							<table className="table">
								<thead>
									<tr>
										<th>Vulnerability</th>
										<th>Component</th>
										<th>Severity</th>
										<th>CVSS</th>
										<th>Applicability</th>
										<th>Targets</th>
										<th>Last seen</th>
									</tr>
								</thead>
								<tbody>
									{vulnerabilities.map(({ key, row, targets, lastSeen }) => (
										<tr key={key}>
											<td className="mono">{row.vuln_id ?? "Advisory (no CVE id)"}</td>
											<td className="mono">
												{row.component ?? "unknown"}
												{row.component_version ? ` ${row.component_version}` : ""}
											</td>
											<td>
												<span className={severityBadge(row.severity)}>{row.severity}</span>
											</td>
											<td className="mono">{cvssOf(row)?.toFixed(1) ?? "—"}</td>
											<td>
												{row.applicability === "confirmed" ? "version confirmed" : "unconfirmed"}
											</td>
											<td className="mono">{targets}</td>
											<td className="mono">{new Date(lastSeen).toLocaleString()}</td>
										</tr>
									))}
									{vulnerabilities.length === 0 ? (
										<tr>
											<td colSpan={7} className="muted">
												No CVE matched in the uploaded infrastructure scans. This reflects only the
												compiled AI-Infra-Guard dataset for the targets that were scanned.
											</td>
										</tr>
									) : null}
								</tbody>
							</table>
						</div>
					</section>

					<section className="card" aria-label="MCP inventory risks">
						<h2>MCP inventory risks</h2>
						<div className="table-wrap" style={{ marginTop: 12 }}>
							<table className="table">
								<thead>
									<tr>
										<th>Server</th>
										<th>Transport</th>
										<th>Severity</th>
										<th>Risk categories</th>
										<th>Tool-manifest attestation</th>
										<th>Last seen</th>
									</tr>
								</thead>
								<tbody>
									{mcp.map((row) => (
										<tr key={row.id}>
											<td className="mono">{row.mcp_server_name ?? "(name withheld)"}</td>
											<td>{row.mcp_transport ?? "—"}</td>
											<td>
												<span className={severityBadge(row.severity)}>{row.severity}</span>
											</td>
											<td>{riskCategoriesText(row)}</td>
											<td>{row.attestation_status ?? "not reported"}</td>
											<td className="mono">{new Date(row.observed_at).toLocaleString()}</td>
										</tr>
									))}
									{mcp.length === 0 ? (
										<tr>
											<td colSpan={6} className="muted">
												No MCP inventory uploaded. Run{" "}
												<span className="mono">aidr discover --upload</span>.
											</td>
										</tr>
									) : null}
								</tbody>
							</table>
						</div>
					</section>

					<SkillSection skills={skills} skillTypes={skillTypes} />

					<TrendSection trend={trend} trendMax={trendMax} />
				</>
			) : null}
		</div>
	);
}
