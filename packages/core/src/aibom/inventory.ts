/**
 * AI inventory collection for the AI-BOM (`aidr aibom`).
 *
 * Every source is an existing discovery path, reused as is:
 * - agents and their AIDR protection state: supplied by the caller (the CLI's
 *   `aidr status` connector detection);
 * - MCP servers: `discoverMcpServers` (the `aidr discover` inventory), with the
 *   command line attached only in redacted form;
 * - skills/plugins: the Claude Code plugin registry (`discoverPlugins`) and the
 *   session-start plugin scan cache, read without re-scanning;
 * - AI packages and model files: `scanProjectForAiComponents`;
 * - AI infrastructure services and their CVEs: a saved `aidr scan` report.
 *
 * The result is the redacted, snake_case inventory printed by
 * `aidr aibom --format json` and the input of `buildCycloneDxBom`.
 */

import { homedir } from "node:os";
import { sep } from "node:path";
import type { AigInfraScanSummary } from "../aig-infra-scan.js";
import { parseInfrastructureScanReport } from "../aig-policy.js";
import { resolvePath } from "../config.js";
import { checkProductAgainstCveIndex, getCveStats } from "../cve-checker.js";
import { getFileContent } from "../file-utils.js";
import { classifyMcpTool, loadAigMcpCategories } from "../mcp-aig-categories.js";
import { discoverMcpServers } from "../mcp-discovery.js";
import { defaultMcpConfigPaths } from "../mcp-inventory.js";
import { cacheKey, loadScanCache } from "../plugin-scan-cache.js";
import { discoverPlugins } from "../plugin-scanner.js";
import { normalizePostureSeverity, type PostureSeverity } from "../posture-events.js";
import { skillRiskTypeForThreatId } from "../skill-risk-types.js";
import { redactTelemetryString } from "../telemetry-redaction.js";
import type { PluginFindingData } from "../types.js";
import { VERSION } from "../version.js";
import {
	type AiProjectModelFile,
	type AiProjectPackage,
	compareText,
	scanProjectForAiComponents,
} from "./project-scan.js";

export const AI_INVENTORY_SCHEMA = "aidr-ai-inventory/v1";
export const PROJECT_REF = "project";

/** An agent host as reported by connector detection (`aidr status`). */
export interface AiBomAgentInput {
	id: string;
	label: string;
	/** Connector state, e.g. `installed` or `runtime_present_not_installed`. */
	state: string;
}

export interface AiInventoryAgent extends AiBomAgentInput {
	ref: string;
}

export interface AiInventoryMcpCategory {
	id: string;
	name: string;
	matched: boolean;
}

export interface AiInventoryMcpServer {
	ref: string;
	inventory_id: string;
	name: string;
	transport: "remote" | "stdio";
	/** Origin only for remote servers; null for stdio. */
	endpoint: string | null;
	/** Redacted command and arguments (stdio). */
	command: string | null;
	args: string[];
	/** Configuration file, home directory shown as `~`. */
	config_source: string;
	/**
	 * Claude Code project the server is scoped to (`~/.claude.json` `projects`),
	 * home directory shown as `~`; null for servers not scoped to a project.
	 */
	project: string | null;
	/** Agent the configuration belongs to, when it can be told from the path. */
	agent: string | null;
	configuration_sha256: string;
	attestation_status: string;
	risk_hints: string[];
	/** All MCP risk categories, each with whether it matched this server. */
	risk_categories: AiInventoryMcpCategory[];
	risk_level: string;
}

export interface AiInventoryPackage extends AiProjectPackage {
	ref: string;
	purl: string;
	/** Whether the package version was checked against the CVE index. */
	vulnerability_check:
		| "evaluated"
		| "not_evaluated_unpinned"
		| "not_in_cve_index"
		| "cve_index_unavailable";
}

export interface AiInventoryModelFile extends AiProjectModelFile {
	ref: string;
}

export interface AiInventoryPlugin {
	ref: string;
	key: string;
	version: string;
	last_updated: string | null;
	scan_status: "scanned" | "not_scanned";
	scanned_at: string | null;
	finding_count: number;
}

export interface AiInventoryInfrastructure {
	ref: string;
	endpoint: string;
	reachable: boolean;
	products: Array<{ product: string; version: string | null }>;
	scan_error: boolean;
}

export interface AiInventoryVulnerability {
	ref: string;
	/** CVE / GHSA / rule identifier; null for an advisory without one. */
	id: string | null;
	source: "cve-index" | "infrastructure-scan" | "skill-scan";
	severity: PostureSeverity;
	cvss: number | null;
	title: string | null;
	/** `confirmed` when the affected version was evaluated against the rule. */
	applicability: "confirmed" | "unconfirmed" | null;
	skill_risk_type: string | null;
	affects: Array<{ ref: string; version: string | null }>;
}

export type AiSourceStatus = "read" | "missing" | "invalid" | "not_configured";

export interface AiInventoryCoverage {
	mcp: {
		status: string;
		sources_read: number;
		sources_invalid: number;
		servers_not_enumerated: number;
	};
	manifests: Array<{ path: string; status: "read" | "invalid" }>;
	model_scan: "complete" | "truncated";
	plugin_registry: "read" | "missing";
	plugin_scan_cache: "read" | "missing";
	cve_index: "available" | "unavailable";
	infrastructure_report: AiSourceStatus;
}

export interface AiInventory {
	schema: typeof AI_INVENTORY_SCHEMA;
	generated_at: string;
	tool: { name: "Singularity AIDR"; version: string };
	project: { ref: typeof PROJECT_REF; name: string; version: string | null; path: string };
	agents: AiInventoryAgent[];
	mcp_servers: AiInventoryMcpServer[];
	packages: AiInventoryPackage[];
	model_files: AiInventoryModelFile[];
	plugins: AiInventoryPlugin[];
	infrastructure: AiInventoryInfrastructure[];
	vulnerabilities: AiInventoryVulnerability[];
	coverage: AiInventoryCoverage;
}

export interface CollectAiInventoryOptions {
	/** Project directory whose manifests and project-level MCP configs are read. */
	projectDir: string;
	/** Agent hosts from connector detection; `not_detected` entries are dropped. */
	agents?: AiBomAgentInput[];
	/** Explicit MCP configuration paths; defaults to the host and project defaults. */
	mcpConfigPaths?: string[];
	pluginRegistryPath?: string;
	pluginScanCachePath?: string;
	/** A saved `aidr scan --save-report` summary to include. */
	infrastructureReportPath?: string;
	now?: Date;
}

/** Show the home directory as `~` so an exported BOM does not name the local user. */
export function displayPath(path: string): string {
	const home = process.env.HOME?.trim() || homedir();
	if (home && (path === home || path.startsWith(`${home}${sep}`)))
		return `~${path.slice(home.length)}`;
	return path;
}

/** Which agent owns an MCP configuration file, from its path. */
const MCP_SOURCE_AGENTS: ReadonlyArray<readonly [RegExp, string]> = [
	[/(?:^|[\\/])\.claude\.json$|(?:^|[\\/])\.mcp\.json$/, "claude-code"],
	[/(?:^|[\\/])\.cursor[\\/]/, "cursor"],
	[/(?:^|[\\/])\.vscode[\\/]/, "vscode"],
	[/(?:^|[\\/])(?:\.config[\\/])?\.?opencode[\\/]/, "opencode"],
	[/(?:^|[\\/])\.openclaw[\\/]/, "openclaw"],
];

function agentForSource(source: string): string | null {
	for (const [pattern, agent] of MCP_SOURCE_AGENTS) if (pattern.test(source)) return agent;
	return null;
}

/** Package URL (purl) for an npm or PyPI package. */
export function packageUrl(pkg: {
	ecosystem: string;
	name: string;
	version: string | null;
}): string {
	const name =
		pkg.ecosystem === "npm" && pkg.name.startsWith("@")
			? `%40${pkg.name.slice(1).split("/").map(encodeURIComponent).join("/")}`
			: encodeURIComponent(pkg.name);
	return `pkg:${pkg.ecosystem}/${name}${pkg.version ? `@${encodeURIComponent(pkg.version)}` : ""}`;
}

const VULN_ID_RE = /^(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})$/;
const RULE_ID_RE = /^[A-Z][A-Z0-9_-]{1,63}$/;

function cvssScore(value: unknown): number | null {
	return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 10
		? Math.round(value * 10) / 10
		: null;
}

const SEVERITY_RANK: Record<PostureSeverity, number> = {
	unknown: 0,
	info: 1,
	low: 2,
	medium: 3,
	high: 4,
	critical: 5,
};

/** Merge vulnerabilities that share a source and identifier into one entry with several affects. */
class VulnerabilitySet {
	private readonly entries = new Map<string, AiInventoryVulnerability>();

	add(
		entry: Omit<AiInventoryVulnerability, "ref" | "affects">,
		affects: AiInventoryVulnerability["affects"][number],
		fallbackKey: string,
	): void {
		const key = entry.id
			? `${entry.source}:${entry.id}`
			: `${entry.source}:advisory:${fallbackKey}`;
		const existing = this.entries.get(key);
		if (existing) {
			if (!existing.affects.some((a) => a.ref === affects.ref && a.version === affects.version))
				existing.affects.push(affects);
			// Keep the strongest evidence seen for the identifier, independent of input order.
			if (entry.applicability === "confirmed") existing.applicability = "confirmed";
			if (SEVERITY_RANK[entry.severity] > SEVERITY_RANK[existing.severity])
				existing.severity = entry.severity;
			if (entry.cvss !== null && (existing.cvss === null || entry.cvss > existing.cvss))
				existing.cvss = entry.cvss;
			return;
		}
		this.entries.set(key, { ...entry, ref: `vuln:${key}`, affects: [affects] });
	}

	list(): AiInventoryVulnerability[] {
		return [...this.entries.values()]
			.map((entry) => ({
				...entry,
				affects: entry.affects.sort((a, b) =>
					compareText(`${a.ref}@${a.version ?? ""}`, `${b.ref}@${b.version ?? ""}`),
				),
			}))
			.sort((a, b) => compareText(a.ref, b.ref));
	}
}

async function collectMcpServers(
	paths: string[],
): Promise<{ servers: AiInventoryMcpServer[]; coverage: AiInventoryCoverage["mcp"] }> {
	const report = await discoverMcpServers(paths, { includeRedactedLaunch: true });
	const categories = loadAigMcpCategories();
	const seen = new Set<string>();
	const servers: AiInventoryMcpServer[] = [];
	for (const server of report.servers) {
		// The same file can be reached twice (a project directory that is the home directory).
		if (seen.has(server.inventory_id)) continue;
		seen.add(server.inventory_id);
		// Same name-based classification as the posture upload (`aidr discover --upload`).
		const classified = classifyMcpTool(server.name, "", {});
		const matched = new Set(classified.matchedCategories.map((category) => category.id));
		servers.push({
			ref: `mcp:${server.inventory_id}`,
			inventory_id: server.inventory_id,
			name: server.name,
			transport: server.transport,
			endpoint: server.endpoint,
			command: server.launch?.command ?? null,
			args: server.launch?.args ?? [],
			config_source: displayPath(server.source),
			project: server.project === undefined ? null : displayPath(server.project),
			agent: agentForSource(server.source),
			configuration_sha256: server.configuration_sha256,
			attestation_status: server.attestation.status,
			risk_hints: [...server.risk_hints].sort(compareText),
			risk_categories: categories.map((category) => ({
				id: category.id,
				name: category.name,
				matched: matched.has(category.id),
			})),
			risk_level: matched.size > 0 ? classified.riskLevel : "none",
		});
	}
	return {
		servers: servers.sort((a, b) => compareText(`${a.name}\0${a.ref}`, `${b.name}\0${b.ref}`)),
		coverage: {
			status: report.coverage.status,
			sources_read: report.coverage.read_sources,
			sources_invalid: report.coverage.invalid_sources,
			servers_not_enumerated: report.coverage.servers_not_enumerated,
		},
	};
}

async function fileExists(path: string): Promise<boolean> {
	try {
		await getFileContent(path);
		return true;
	} catch {
		return false;
	}
}

/** Skill-scan findings cached for one plugin; matched text and file paths never enter the BOM. */
function addSkillFindings(
	vulnerabilities: VulnerabilitySet,
	plugin: { key: string; version: string },
	findings: PluginFindingData[],
): void {
	for (const finding of findings) {
		vulnerabilities.add(
			{
				id: RULE_ID_RE.test(finding.threat_id) ? finding.threat_id : null,
				source: "skill-scan",
				severity: normalizePostureSeverity(finding.severity),
				cvss: null,
				title: finding.title ? redactTelemetryString(finding.title, 200) : null,
				applicability: null,
				skill_risk_type: skillRiskTypeForThreatId(finding.threat_id) ?? null,
			},
			{ ref: `plugin:${plugin.key}`, version: plugin.version || null },
			`${plugin.key}:${finding.threat_id}`,
		);
	}
}

async function collectPlugins(
	registryPath: string | undefined,
	cachePath: string | undefined,
	vulnerabilities: VulnerabilitySet,
): Promise<{
	plugins: AiInventoryPlugin[];
	registry: "read" | "missing";
	cache: "read" | "missing";
}> {
	const registry = registryPath ?? resolvePath("~/.claude/plugins/installed_plugins.json");
	const scanCache = cachePath ?? resolvePath("~/.singularity-aidr/plugin_scan_cache.json");
	const cache = await loadScanCache("", scanCache);
	const plugins = (await discoverPlugins(registry)).map((plugin): AiInventoryPlugin => {
		const cached = cache.entries[cacheKey(plugin.key, plugin.version, plugin.lastUpdated)];
		addSkillFindings(vulnerabilities, plugin, cached?.findings ?? []);
		return {
			ref: `plugin:${plugin.key}`,
			key: plugin.key,
			version: plugin.version,
			last_updated: plugin.lastUpdated || null,
			scan_status: cached ? "scanned" : "not_scanned",
			scanned_at: cached?.scannedAt ?? null,
			finding_count: cached?.findings.length ?? 0,
		};
	});
	return {
		plugins: plugins.sort((a, b) => compareText(a.ref, b.ref)),
		registry: (await fileExists(registry)) ? "read" : "missing",
		cache: (await fileExists(scanCache)) ? "read" : "missing",
	};
}

type InfraTarget = AigInfraScanSummary["targets"][number];

/** Fold one scanned target into its endpoint's service and record its CVEs. */
function addInfraTarget(
	byOrigin: Map<string, AiInventoryInfrastructure>,
	target: InfraTarget,
	vulnerabilities: VulnerabilitySet,
): void {
	const endpoint = new URL(target.url).origin;
	const ref = `infra:${endpoint}`;
	const service = byOrigin.get(endpoint) ?? {
		ref,
		endpoint,
		reachable: false,
		products: [],
		scan_error: false,
	};
	byOrigin.set(endpoint, service);
	service.reachable ||= target.reachable;
	service.scan_error ||= target.error !== null;
	for (const { product, version } of target.matched) {
		if (!service.products.some((p) => p.product === product && p.version === version))
			service.products.push({ product, version });
	}
	const versions = new Map(target.matched.map((m) => [m.product.toLowerCase(), m.version]));
	for (const cve of target.cves) {
		vulnerabilities.add(
			{
				id: VULN_ID_RE.test(cve.cveId) ? cve.cveId : null,
				source: "infrastructure-scan",
				severity: normalizePostureSeverity(cve.severity),
				cvss: cvssScore(cve.cvss),
				title: null,
				applicability: cve.evaluated ? "confirmed" : "unconfirmed",
				skill_risk_type: null,
			},
			{ ref, version: versions.get(cve.product.toLowerCase()) ?? null },
			`${endpoint}:${cve.product}:${cve.cveId}`,
		);
	}
}

async function collectInfrastructure(
	reportPath: string | undefined,
	now: Date,
	vulnerabilities: VulnerabilitySet,
): Promise<{ services: AiInventoryInfrastructure[]; status: AiSourceStatus }> {
	if (!reportPath) return { services: [], status: "not_configured" };
	let text: string;
	try {
		text = await getFileContent(resolvePath(reportPath));
	} catch {
		return { services: [], status: "missing" };
	}
	const report = parseInfrastructureScanReport(text, now.getTime());
	if (!report) return { services: [], status: "invalid" };
	const byOrigin = new Map<string, AiInventoryInfrastructure>();
	for (const target of report.targets) addInfraTarget(byOrigin, target, vulnerabilities);
	const services = [...byOrigin.values()].map((service) => ({
		...service,
		products: service.products.sort((a, b) =>
			compareText(`${a.product}@${a.version ?? ""}`, `${b.product}@${b.version ?? ""}`),
		),
	}));
	return { services: services.sort((a, b) => compareText(a.ref, b.ref)), status: "read" };
}

/** Check one catalog package against the CVE index; only an exact version is ever evaluated. */
function checkPackage(
	pkg: AiProjectPackage,
	purl: string,
	cveIndexAvailable: boolean,
	vulnerabilities: VulnerabilitySet,
): AiInventoryPackage["vulnerability_check"] {
	if (!pkg.cve_product) return "not_in_cve_index";
	if (!cveIndexAvailable) return "cve_index_unavailable";
	if (!pkg.version) return "not_evaluated_unpinned";
	for (const cve of checkProductAgainstCveIndex(pkg.cve_product, pkg.version)) {
		vulnerabilities.add(
			{
				id: VULN_ID_RE.test(cve.cve_id) ? cve.cve_id : null,
				source: "cve-index",
				severity: normalizePostureSeverity(cve.severity),
				cvss: cvssScore(cve.cvss_score),
				title: null,
				applicability: "confirmed",
				skill_risk_type: null,
			},
			{ ref: purl, version: pkg.version },
			`${purl}:${cve.cve_id}`,
		);
	}
	return "evaluated";
}

function packageVulnerabilities(
	packages: AiProjectPackage[],
	cveIndexAvailable: boolean,
	vulnerabilities: VulnerabilitySet,
): AiInventoryPackage[] {
	return packages.map((pkg) => {
		const purl = packageUrl(pkg);
		const check = checkPackage(pkg, purl, cveIndexAvailable, vulnerabilities);
		return { ...pkg, ref: purl, purl, vulnerability_check: check };
	});
}

/** Collect the redacted AI inventory for one project on this host. */
export async function collectAiInventory(options: CollectAiInventoryOptions): Promise<AiInventory> {
	const now = options.now ?? new Date();
	const vulnerabilities = new VulnerabilitySet();
	const project = await scanProjectForAiComponents(options.projectDir);
	const mcp = await collectMcpServers(
		options.mcpConfigPaths?.length
			? options.mcpConfigPaths
			: defaultMcpConfigPaths(options.projectDir),
	);
	const plugins = await collectPlugins(
		options.pluginRegistryPath,
		options.pluginScanCachePath,
		vulnerabilities,
	);
	const infrastructure = await collectInfrastructure(
		options.infrastructureReportPath,
		now,
		vulnerabilities,
	);
	const cveIndexAvailable = getCveStats().total > 0;
	const packages = packageVulnerabilities(project.packages, cveIndexAvailable, vulnerabilities);
	const agents = (options.agents ?? [])
		.filter((agent) => agent.state !== "not_detected")
		.map((agent) => ({
			ref: `agent:${agent.id}`,
			id: agent.id,
			label: agent.label,
			state: agent.state,
		}))
		.sort((a, b) => compareText(a.ref, b.ref));

	return {
		schema: AI_INVENTORY_SCHEMA,
		generated_at: now.toISOString(),
		tool: { name: "Singularity AIDR", version: VERSION },
		project: {
			ref: PROJECT_REF,
			name: project.name,
			version: project.version,
			path: displayPath(project.root),
		},
		agents,
		mcp_servers: mcp.servers,
		packages,
		model_files: project.model_files.map((file) => ({ ...file, ref: `model-file:${file.path}` })),
		plugins: plugins.plugins,
		infrastructure: infrastructure.services,
		vulnerabilities: vulnerabilities.list(),
		coverage: {
			mcp: mcp.coverage,
			manifests: project.manifests.map(({ path, status }) => ({ path, status })),
			model_scan: project.model_scan_complete ? "complete" : "truncated",
			plugin_registry: plugins.registry,
			plugin_scan_cache: plugins.cache,
			cve_index: cveIndexAvailable ? "available" : "unavailable",
			infrastructure_report: infrastructure.status,
		},
	};
}

/** Gaps that make the inventory incomplete (the CLI exits non-zero, like `aidr discover`). */
export function aiInventoryGaps(inventory: AiInventory): string[] {
	const gaps: string[] = [];
	const { coverage } = inventory;
	if (coverage.mcp.sources_invalid > 0)
		gaps.push(`${coverage.mcp.sources_invalid} MCP configuration file(s) could not be read`);
	if (coverage.mcp.servers_not_enumerated > 0)
		gaps.push(
			`${coverage.mcp.servers_not_enumerated} malformed MCP server entr(y/ies) not enumerated`,
		);
	for (const manifest of coverage.manifests.filter((m) => m.status === "invalid"))
		gaps.push(`manifest ${manifest.path} could not be parsed`);
	if (coverage.model_scan === "truncated")
		gaps.push("model file search stopped at its depth/size bound");
	if (coverage.infrastructure_report === "missing" || coverage.infrastructure_report === "invalid")
		gaps.push(`infrastructure scan report is ${coverage.infrastructure_report}`);
	return gaps;
}
