import { useEffect, useMemo, useRef, useState } from "react";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useRichT, useT } from "../../i18n/I18nProvider";
import { aiBomFileName, buildTenantAiBom, type FleetAgentRow } from "../../lib/aibom";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import { RUNTIME_CATALOG } from "../../onboarding/runtime-catalog";
import { FrameworkCoverageSection } from "../framework-coverage";

/** Findings older than this are outside the posture window (and the trend). */
export const POSTURE_WINDOW_DAYS = 90;
const TREND_DAYS = 30;
const MAX_ROWS = 5000;
const DAY_MS = 86_400_000;

export type PostureSeverity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export type PostureFindingRow = {
	id: number;
	source: "infra_scan" | "mcp_inventory" | "skill_scan" | "agent_environment";
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
	/** Agent environment rows only. */
	agent_id?: string | null;
	agent_host?: string | null;
	check_id?: string | null;
	finding_count?: number | null;
	observed_at: string;
};

const COLUMNS =
	"id,source,finding_kind,severity,cvss,vuln_id,component,component_version,applicability,target_digest,mcp_server_name,mcp_transport,risk_categories,attestation_status,subject_digest,plugin_key,rule_id,skill_risk_type,agent_id,agent_host,check_id,finding_count,observed_at";

const SEVERITY_ORDER: PostureSeverity[] = ["critical", "high", "medium", "low", "info", "unknown"];
const SEVERITY_RANK = new Map(SEVERITY_ORDER.map((severity, index) => [severity, index]));

/** Skill and plugin scan taxonomy (T01-T09), mirrored from `threats/skill-scan.yaml`. */
export const SKILL_RISK_TYPES: Record<string, DashboardMessageKey> = {
	T01: "posture.skill.T01",
	T02: "posture.skill.T02",
	T03: "posture.skill.T03",
	T04: "posture.skill.T04",
	T05: "posture.skill.T05",
	T06: "posture.skill.T06",
	T07: "posture.skill.T07",
	T08: "posture.skill.T08",
	T09: "posture.skill.T09",
};

/** MCP risk categories (`mcp-01`..`mcp-14`) and the local configuration indicators. */
const MCP_CATEGORY_LABELS: Record<string, DashboardMessageKey> = {
	remote_mcp_url: "posture.mcp.remote",
	shell_wrapper_command: "posture.mcp.shell",
	broad_filesystem_access_arg: "posture.mcp.fs",
	"mcp-01": "posture.mcp.01",
	"mcp-02": "posture.mcp.02",
	"mcp-03": "posture.mcp.03",
	"mcp-04": "posture.mcp.04",
	"mcp-05": "posture.mcp.05",
	"mcp-06": "posture.mcp.06",
	"mcp-07": "posture.mcp.07",
	"mcp-08": "posture.mcp.08",
	"mcp-09": "posture.mcp.09",
	"mcp-10": "posture.mcp.10",
	"mcp-11": "posture.mcp.11",
	"mcp-12": "posture.mcp.12",
	"mcp-13": "posture.mcp.13",
	"mcp-14": "posture.mcp.14",
};

/** Agent environment checks (`aidr discover --agents --upload`), see docs/agent-environment-posture.md. */
export const AGENT_CHECK_LABELS: Record<string, DashboardMessageKey> = {
	permission_bypass_mode: "posture.check.bypass",
	broad_shell_allow_rule: "posture.check.broadShell",
	hooks_disabled: "posture.check.hooksDisabled",
	aidr_hook_missing: "posture.check.hookMissing",
	no_aidr_connector: "posture.check.noConnector",
	approval_policy_never: "posture.check.approvalNever",
	sandbox_full_access: "posture.check.sandbox",
	permission_allow_all: "posture.check.allowAll",
	running_as_root: "posture.check.root",
	docker_socket_writable: "posture.check.docker",
	cloud_credentials_in_env: "posture.check.cloudCreds",
	no_devcontainer: "posture.check.devcontainer",
	mcp_plaintext_secret: "posture.check.mcpSecret",
};

/** AI tool names (product names, shown as-is); the host environment is translated. */
const AGENT_HOST_LABELS: Record<string, string> = {
	"claude-code": "Claude Code",
	cursor: "Cursor",
	vscode: "VS Code",
	codex: "Codex",
	opencode: "OpenCode",
	openclaw: "OpenClaw",
	"gemini-cli": "Gemini CLI",
	aider: "Aider",
};

const SEVERITY_LABELS: Record<PostureSeverity, DashboardMessageKey> = {
	critical: "common.severity.critical",
	high: "common.severity.high",
	medium: "common.severity.medium",
	low: "common.severity.low",
	info: "common.severity.info",
	unknown: "common.unknown",
};

function hostLabel(host: string | null | undefined, t: Translate): string {
	if (host === "environment") return t("posture.host.environment");
	return AGENT_HOST_LABELS[host ?? ""] ?? host ?? t("posture.notReported");
}

function labelOf(
	labels: Record<string, DashboardMessageKey>,
	value: string | null | undefined,
	t: Translate,
	fallback: string,
): string {
	const key = labels[value ?? ""];
	return key ? t(key) : (value ?? fallback);
}

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
	if (row.source === "agent_environment") {
		return `agent|${row.agent_id ?? row.id}|${row.agent_host ?? ""}|${row.check_id ?? row.id}`;
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

export type AgentCheckGroup = {
	key: string;
	row: PostureFindingRow;
	installations: number;
	lastSeen: string;
};

/** Current agent findings per host and check, with how many installations report it. */
export function groupAgentFindings(rows: PostureFindingRow[]): AgentCheckGroup[] {
	const groups = new Map<
		string,
		{ row: PostureFindingRow; agents: Set<string>; lastSeen: string }
	>();
	for (const row of rows) {
		const key = `${row.agent_host ?? ""}|${row.check_id ?? `row-${row.id}`}`;
		const agent = row.agent_id ?? `row-${row.id}`;
		const group = groups.get(key);
		if (!group) {
			groups.set(key, { row, agents: new Set([agent]), lastSeen: row.observed_at });
			continue;
		}
		group.agents.add(agent);
		if (compareSeverity(row, group.row) < 0) group.row = row;
		if (Date.parse(row.observed_at) > Date.parse(group.lastSeen)) group.lastSeen = row.observed_at;
	}
	return [...groups.entries()]
		.map(([key, group]) => ({
			key,
			row: group.row,
			installations: group.agents.size,
			lastSeen: group.lastSeen,
		}))
		.sort(
			(a, b) =>
				compareSeverity(a.row, b.row) ||
				b.installations - a.installations ||
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
	t: Translate,
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
				error: readErrorMessage(result.error, t("posture.loadFailed")),
			};
		}
		return { rows: result.data as unknown as PostureFindingRow[], error: null };
	} catch {
		return { rows: null, error: t("posture.loadFailed") };
	}
}

/** Bar colour for a trend day: its most severe finding. */
function trendColor(day: TrendDay): string {
	if (day.critical > 0) return "var(--sev-critical)";
	return day.high > 0 ? "var(--sev-high)" : "var(--sev-medium)";
}

function riskCategoriesText(row: PostureFindingRow, t: Translate): string {
	const categories = row.risk_categories ?? [];
	if (categories.length === 0) return t("posture.noIndicator");
	return categories
		.map((category) => labelOf(MCP_CATEGORY_LABELS, category, t, category))
		.join(", ");
}

function skillTypeText(type: string, t: Translate): string {
	const key = SKILL_RISK_TYPES[type];
	return key ? t(key) : "";
}

function skillCategoryText(row: PostureFindingRow, t: Translate): string {
	if (!row.skill_risk_type) return t("posture.commandRule");
	return `${row.skill_risk_type} ${skillTypeText(row.skill_risk_type, t)}`;
}

const FLEET_PAGE_SIZE = 1000;
const FLEET_MAX_PAGES = 100;

function isFleetAgentRow(value: unknown): value is FleetAgentRow {
	if (typeof value !== "object" || value === null) return false;
	const row = value as Record<string, unknown>;
	return (
		(row.agent_runtime === null || typeof row.agent_runtime === "string") &&
		(row.agent_runtime_version === null || typeof row.agent_runtime_version === "string") &&
		typeof row.last_seen === "string"
	);
}

/**
 * Every fleet check-in of the tenant, paged until the exact count is reached
 * (the server may cap a page below the requested size). Null when a page cannot
 * be read or the fleet is larger than the browser export reads: an incomplete
 * BOM is never exported.
 */
async function fetchFleetAgents(tenantId: string): Promise<FleetAgentRow[] | null> {
	const agents: FleetAgentRow[] = [];
	for (let page = 0; page < FLEET_MAX_PAGES; page++) {
		const result = await supabase
			.from("agents")
			.select("id,agent_runtime,agent_runtime_version,last_seen", { count: "exact" })
			.eq("tenant_id", tenantId)
			.order("id", { ascending: true })
			.range(agents.length, agents.length + FLEET_PAGE_SIZE - 1);
		if (
			result.error ||
			typeof result.count !== "number" ||
			!Array.isArray(result.data) ||
			!result.data.every(isFleetAgentRow)
		)
			return null;
		for (const row of result.data as FleetAgentRow[])
			agents.push({
				agent_runtime: row.agent_runtime,
				agent_runtime_version: row.agent_runtime_version,
				last_seen: row.last_seen,
			});
		if (agents.length >= result.count) return agents;
		if (result.data.length === 0) return null;
	}
	return null;
}

/** Runtime ids (`agents.agent_runtime`) to product names, from the download catalog. */
function runtimeLabels(): Map<string, string> {
	const labels = new Map<string, string>();
	for (const entry of RUNTIME_CATALOG) {
		for (const runtime of entry.detection?.runtimes ?? []) {
			const existing = labels.get(runtime);
			// Browser Guard has one entry per browser family; name the runtime once.
			labels.set(runtime, existing ? (entry.label.split(" for ")[0] ?? entry.label) : entry.label);
		}
	}
	return labels;
}

type ReadyAiBom = { url: string; fileName: string; summary: string };

/**
 * "Export AI-BOM": a CycloneDX 1.6 document of the tenant's reported AI estate
 * (fleet runtimes, MCP servers, AI infrastructure components, skills/plugins and
 * their vulnerabilities), built in the browser from data already on this page.
 */
function AiBomExport({
	tenantId,
	tenantName,
	findings,
	truncated,
}: {
	tenantId: string;
	tenantName: string;
	findings: PostureFindingRow[] | null;
	truncated: boolean;
}) {
	const t = useT();
	const [exporting, setExporting] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [ready, setReady] = useState<ReadyAiBom | null>(null);
	const readyUrl = useRef<string | null>(null);

	useEffect(
		() => () => {
			if (readyUrl.current) URL.revokeObjectURL(readyUrl.current);
		},
		[],
	);

	async function exportAiBom() {
		if (findings === null) return;
		setExporting(true);
		setError(null);
		try {
			const agents = await fetchFleetAgents(tenantId);
			if (agents === null) {
				setError(t("posture.bom.fleetFailed"));
				return;
			}
			const generatedAt = new Date().toISOString();
			const bom = buildTenantAiBom({
				tenant: { id: tenantId, name: tenantName },
				agents,
				findings,
				runtimeLabels: runtimeLabels(),
				postureWindowDays: POSTURE_WINDOW_DAYS,
				postureTruncated: truncated,
				generatedAt,
				serialNumber: `urn:uuid:${crypto.randomUUID()}`,
			});
			const url = URL.createObjectURL(
				new Blob([`${JSON.stringify(bom, null, 2)}\n`], { type: "application/vnd.cyclonedx+json" }),
			);
			if (readyUrl.current) URL.revokeObjectURL(readyUrl.current);
			readyUrl.current = url;
			setReady({
				url,
				fileName: aiBomFileName(tenantName, generatedAt),
				summary: t("posture.bom.summary", {
					components: bom.components.length,
					services: bom.services.length,
					vulnerabilities: bom.vulnerabilities.length,
				}),
			});
		} catch {
			setError(t("posture.bom.failed"));
		} finally {
			setExporting(false);
		}
	}

	return (
		<div className="stack" aria-label={t("posture.bom.label")}>
			<div className="row">
				<button
					type="button"
					className="button button-secondary"
					disabled={exporting || findings === null}
					onClick={() => void exportAiBom()}
				>
					{exporting ? t("posture.bom.preparing") : t("posture.bom.export")}
				</button>
				<span className="muted small">{t("posture.bom.note")}</span>
			</div>
			{error ? (
				<div className="notice notice-danger" role="alert">
					{error}
				</div>
			) : null}
			{ready ? (
				<p role="status">
					{t("posture.bom.ready", { summary: ready.summary })}{" "}
					<a href={ready.url} download={ready.fileName}>
						{t("posture.bom.save", { file: ready.fileName })}
					</a>
					{truncated ? t("posture.bom.truncated", { count: MAX_ROWS }) : ""}
				</p>
			) : null}
		</div>
	);
}

function NoPostureData() {
	const t = useT();
	return (
		<section className="card" aria-label={t("posture.none.label")}>
			<h2>{t("posture.none.title")}</h2>
			<p className="muted">{t("posture.none.body")}</p>
			<pre className="mono">
				{[
					"aidr scan --target http://10.0.0.5:11434 --upload   # AI infrastructure CVEs",
					"aidr discover --upload                              # MCP server inventory",
					"aidr scan --skill ~/.claude/skills/<name> --upload  # skill/plugin T01-T09",
					"aidr discover --agents --upload                     # agent autonomy & environment",
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
	const t = useT();
	const richT = useRichT();
	return (
		<section className="card" aria-label={t("posture.skills")}>
			<h2>{t("posture.skills")}</h2>
			{skillTypes.length > 0 ? (
				<div className="row" style={{ marginTop: 8 }}>
					{skillTypes.map(([type, count]) => (
						<span key={type} className="badge badge-neutral">
							{type} {skillTypeText(type, t)}: {count}
						</span>
					))}
				</div>
			) : null}
			<div className="table-wrap" style={{ marginTop: 12 }}>
				<table className="table">
					<thead>
						<tr>
							<th>{t("posture.col.package")}</th>
							<th>{t("posture.col.rule")}</th>
							<th>{t("posture.col.category")}</th>
							<th>{t("posture.col.severity")}</th>
							<th>{t("posture.col.lastSeen")}</th>
						</tr>
					</thead>
					<tbody>
						{skills.map((row) => (
							<tr key={row.id}>
								<td className="mono">{row.plugin_key ?? t("posture.withheld")}</td>
								<td className="mono">{row.rule_id ?? "—"}</td>
								<td>{skillCategoryText(row, t)}</td>
								<td>
									<span className={severityBadge(row.severity)}>
										{t(SEVERITY_LABELS[row.severity])}
									</span>
								</td>
								<td className="mono">{new Date(row.observed_at).toLocaleString()}</td>
							</tr>
						))}
						{skills.length === 0 ? (
							<tr>
								<td colSpan={5} className="muted">
									{richT("posture.noSkills", {
										command: <span className="mono">aidr scan --skill &lt;dir&gt; --upload</span>,
									})}
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</section>
	);
}

function AgentEnvironmentSection({ groups }: { groups: AgentCheckGroup[] }) {
	const t = useT();
	const richT = useRichT();
	return (
		<section className="card" aria-label={t("posture.agentEnv")}>
			<h2>{t("posture.agentEnvTitle")}</h2>
			<p className="muted small">
				{richT("posture.agentEnvBody", {
					command: <span className="mono">aidr discover --agents</span>,
				})}
			</p>
			<div className="table-wrap" style={{ marginTop: 12 }}>
				<table className="table">
					<thead>
						<tr>
							<th>{t("posture.col.host")}</th>
							<th>{t("posture.col.check")}</th>
							<th>{t("posture.col.severity")}</th>
							<th>{t("posture.col.installations")}</th>
							<th>{t("posture.col.items")}</th>
							<th>{t("posture.col.lastSeen")}</th>
						</tr>
					</thead>
					<tbody>
						{groups.map(({ key, row, installations, lastSeen }) => (
							<tr key={key}>
								<td>{hostLabel(row.agent_host, t)}</td>
								<td>{labelOf(AGENT_CHECK_LABELS, row.check_id, t, t("posture.notReported"))}</td>
								<td>
									<span className={severityBadge(row.severity)}>
										{t(SEVERITY_LABELS[row.severity])}
									</span>
								</td>
								<td className="mono">{installations}</td>
								<td className="mono">{row.finding_count ?? "—"}</td>
								<td className="mono">{new Date(lastSeen).toLocaleString()}</td>
							</tr>
						))}
						{groups.length === 0 ? (
							<tr>
								<td colSpan={6} className="muted">
									{richT("posture.noAgentFindings", {
										command: <span className="mono">aidr discover --agents --upload</span>,
									})}
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
	const t = useT();
	return (
		<section className="card" aria-label={t("posture.trend")}>
			<h2>{t("posture.trendTitle", { days: TREND_DAYS })}</h2>
			<p className="muted small">{t("posture.trendNote")}</p>
			<div className="table-wrap" style={{ marginTop: 12 }}>
				<table className="table">
					<thead>
						<tr>
							<th>{t("posture.col.day")}</th>
							<th>{t("posture.col.critical")}</th>
							<th>{t("posture.col.high")}</th>
							<th>{t("posture.col.other")}</th>
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
									{t("posture.noTrend", { days: TREND_DAYS })}
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
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
	if (!currentTeam) return <div role="alert">{t("posture.noTeam")}</div>;
	return (
		<TenantPosturePage
			key={currentTeam.id}
			tenantId={currentTeam.id}
			tenantName={currentTeam.name}
		/>
	);
}

function TenantPosturePage({ tenantId, tenantName }: { tenantId: string; tenantName: string }) {
	const t = useT();
	const richT = useRichT();
	// null = not loaded / unavailable (fail closed); [] = a real, empty posture.
	const [rows, setRows] = useState<PostureFindingRow[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loaded, setLoaded] = useState(false);
	const [nowMs, setNowMs] = useState(() => Date.now());

	useEffect(() => {
		let cancelled = false;
		async function load() {
			const next = await fetchPostureFindings(tenantId, t);
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
	const agentGroups = useMemo(
		() => groupAgentFindings(current.filter((row) => row.source === "agent_environment")),
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
				<h1>{t("nav.posture")}</h1>
				<p className="muted">
					{richT("posture.intro", {
						scan: <span className="mono">aidr scan --upload</span>,
						discover: <span className="mono">aidr discover --upload</span>,
						days: POSTURE_WINDOW_DAYS,
					})}
				</p>
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{t("posture.unavailable", { error })}
					</div>
				) : null}
				{!loaded && rows === null ? <div role="status">{t("posture.loading")}</div> : null}
				<AiBomExport
					tenantId={tenantId}
					tenantName={tenantName}
					findings={rows === null ? null : current}
					truncated={(rows?.length ?? 0) >= MAX_ROWS}
				/>
			</section>

			{rows !== null && rows.length === 0 ? <NoPostureData /> : null}

			{rows !== null && rows.length > 0 ? (
				<>
					<section className="grid" aria-label={t("posture.counters")}>
						<div className="card stat-card">
							<div className="stat-label">{t("posture.criticalCves")}</div>
							<div className="stat-value">{infraCounts.critical}</div>
						</div>
						<div className="card stat-card">
							<div className="stat-label">{t("posture.highCves")}</div>
							<div className="stat-value">{infraCounts.high}</div>
						</div>
						<div className="card stat-card">
							<div className="stat-label">{t("posture.mcpServers")}</div>
							<div className="stat-value">{mcp.length}</div>
						</div>
						<div className="card stat-card">
							<div className="stat-label">{t("posture.skillFindings")}</div>
							<div className="stat-value">{skills.length}</div>
						</div>
						<div className="card stat-card">
							<div className="stat-label">{t("posture.agentRisk")}</div>
							<div className="stat-value">{agentGroups.length}</div>
						</div>
					</section>

					<section className="card" aria-label={t("posture.infra")}>
						<h2>{t("posture.infra")}</h2>
						<div className="row" style={{ marginTop: 8 }}>
							{SEVERITY_ORDER.filter((severity) => infraCounts[severity] > 0).map((severity) => (
								<span key={severity} className={severityBadge(severity)}>
									{`${infraCounts[severity]} ${t(SEVERITY_LABELS[severity])}`}
								</span>
							))}
							<span className="badge badge-neutral">
								{t("posture.components", { count: exposedComponents.length })}
							</span>
						</div>
						<div className="table-wrap" style={{ marginTop: 12 }}>
							<table className="table">
								<thead>
									<tr>
										<th>{t("posture.col.vuln")}</th>
										<th>{t("posture.col.component")}</th>
										<th>{t("posture.col.severity")}</th>
										<th>CVSS</th>
										<th>{t("posture.col.applicability")}</th>
										<th>{t("posture.col.targets")}</th>
										<th>{t("posture.col.lastSeen")}</th>
									</tr>
								</thead>
								<tbody>
									{vulnerabilities.map(({ key, row, targets, lastSeen }) => (
										<tr key={key}>
											<td className="mono">{row.vuln_id ?? t("posture.advisory")}</td>
											<td className="mono">
												{row.component ?? t("common.unknown")}
												{row.component_version ? ` ${row.component_version}` : ""}
											</td>
											<td>
												<span className={severityBadge(row.severity)}>
													{t(SEVERITY_LABELS[row.severity])}
												</span>
											</td>
											<td className="mono">{cvssOf(row)?.toFixed(1) ?? "—"}</td>
											<td>
												{row.applicability === "confirmed"
													? t("posture.confirmed")
													: t("posture.unconfirmed")}
											</td>
											<td className="mono">{targets}</td>
											<td className="mono">{new Date(lastSeen).toLocaleString()}</td>
										</tr>
									))}
									{vulnerabilities.length === 0 ? (
										<tr>
											<td colSpan={7} className="muted">
												{t("posture.noCve")}
											</td>
										</tr>
									) : null}
								</tbody>
							</table>
						</div>
					</section>

					<section className="card" aria-label={t("posture.mcp")}>
						<h2>{t("posture.mcp")}</h2>
						<div className="table-wrap" style={{ marginTop: 12 }}>
							<table className="table">
								<thead>
									<tr>
										<th>{t("posture.col.server")}</th>
										<th>{t("posture.col.transport")}</th>
										<th>{t("posture.col.severity")}</th>
										<th>{t("posture.col.risks")}</th>
										<th>{t("posture.col.attestation")}</th>
										<th>{t("posture.col.lastSeen")}</th>
									</tr>
								</thead>
								<tbody>
									{mcp.map((row) => (
										<tr key={row.id}>
											<td className="mono">{row.mcp_server_name ?? t("posture.withheld")}</td>
											<td>{row.mcp_transport ?? "—"}</td>
											<td>
												<span className={severityBadge(row.severity)}>
													{t(SEVERITY_LABELS[row.severity])}
												</span>
											</td>
											<td>{riskCategoriesText(row, t)}</td>
											<td>{row.attestation_status ?? t("posture.attestationNotReported")}</td>
											<td className="mono">{new Date(row.observed_at).toLocaleString()}</td>
										</tr>
									))}
									{mcp.length === 0 ? (
										<tr>
											<td colSpan={6} className="muted">
												{richT("posture.noMcp", {
													command: <span className="mono">aidr discover --upload</span>,
												})}
											</td>
										</tr>
									) : null}
								</tbody>
							</table>
						</div>
					</section>

					<SkillSection skills={skills} skillTypes={skillTypes} />

					<AgentEnvironmentSection groups={agentGroups} />

					<TrendSection trend={trend} trendMax={trendMax} />
				</>
			) : null}

			<FrameworkCoverageSection />
		</div>
	);
}
