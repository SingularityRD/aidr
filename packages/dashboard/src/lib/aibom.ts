/**
 * Tenant-level AI-BOM (CycloneDX 1.6 JSON) built in the browser from data the
 * dashboard already reads under row-level security: the fleet's `agents`
 * check-ins and the tenant's `posture_findings`.
 *
 * It mirrors the component model of the CLI's `aidr aibom`
 * (`packages/core/src/aibom/cyclonedx.ts`); the dashboard deliberately does not
 * depend on `@singularityrd/aidr-core`, so the mapping is restated here. Only
 * what was reported is exported: identifiers, versions, severities, counts and
 * digests. Hosts, paths, arguments and matched text are never uploaded, so they
 * cannot appear in this BOM either.
 *
 * Mapping:
 * - agent runtimes (per runtime + version) → `application` components;
 * - AI infrastructure products from scans → `application` components;
 * - skills/plugins → `library` components;
 * - MCP servers → `services` with the 14 MCP risk-category flags;
 * - CVEs/advisories and skill rule findings → `vulnerabilities`.
 */

import type { PostureFindingRow } from "../ui/pages/PosturePage";

export const AIBOM_SPEC_VERSION = "1.6";
const SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json";
export const TENANT_REF = "tenant";

/** The 14 MCP risk categories (`mcp-01`…`mcp-14`) reported by MCP inventory uploads. */
export const MCP_RISK_CATEGORY_IDS: readonly string[] = Array.from(
	{ length: 14 },
	(_, index) => `mcp-${String(index + 1).padStart(2, "0")}`,
);

/** Local configuration indicators that can accompany the categories. */
const MCP_RISK_HINTS = new Set([
	"remote_mcp_url",
	"shell_wrapper_command",
	"broad_filesystem_access_arg",
]);

export type FleetAgentRow = {
	agent_runtime: string | null;
	agent_runtime_version: string | null;
	last_seen: string;
};

type Property = { name: string; value: string };

export type AiBomComponent = {
	type: "application" | "library";
	"bom-ref": string;
	name: string;
	version?: string;
	description?: string;
	properties: Property[];
};

export type AiBomService = {
	"bom-ref": string;
	name: string;
	description: string;
	"x-trust-boundary": boolean;
	properties: Property[];
};

export type AiBomVulnerability = {
	"bom-ref": string;
	id?: string;
	source: { name: string };
	ratings: Array<{ source: { name: string }; score?: number; severity: string }>;
	description?: string;
	affects: Array<{ ref: string; versions?: Array<{ version: string; status: "affected" }> }>;
	properties: Property[];
};

export type TenantAiBom = {
	$schema: string;
	bomFormat: "CycloneDX";
	specVersion: string;
	serialNumber: string;
	version: 1;
	metadata: {
		timestamp: string;
		lifecycles: Array<{ phase: "operations" }>;
		tools: {
			components: Array<{
				type: "application";
				"bom-ref": string;
				supplier: { name: string };
				name: string;
			}>;
		};
		component: { type: "application"; "bom-ref": string; name: string; description: string };
		properties: Property[];
	};
	components: AiBomComponent[];
	services: AiBomService[];
	dependencies: Array<{ ref: string; dependsOn: string[] }>;
	vulnerabilities: AiBomVulnerability[];
};

export type TenantAiBomInput = {
	tenant: { id: string; name: string };
	agents: FleetAgentRow[];
	/** Current posture findings (latest observation of each). */
	findings: PostureFindingRow[];
	/** Human labels for `agents.agent_runtime` values. */
	runtimeLabels: ReadonlyMap<string, string>;
	postureWindowDays: number;
	/** True when the posture query hit its row limit, so older observations were not read. */
	postureTruncated: boolean;
	generatedAt: string;
	serialNumber: string;
};

const INFRA_SOURCE = { name: "AI Security Posture infrastructure scan" };
const SKILL_SOURCE = { name: "Singularity AIDR skill and plugin scan" };

function prop(name: string, value: string | number | boolean): Property {
	return { name, value: String(value) };
}

/** Code-unit order, so the same data always produces the same document. */
function compareText(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

function byRef<T extends { "bom-ref": string }>(a: T, b: T): number {
	return compareText(a["bom-ref"], b["bom-ref"]);
}

function cvssOf(value: number | string | null): number | undefined {
	if (value === null || value === undefined) return undefined;
	const parsed = typeof value === "number" ? value : Number.parseFloat(value);
	return Number.isFinite(parsed) && parsed >= 0 && parsed <= 10
		? Math.round(parsed * 10) / 10
		: undefined;
}

function latest(a: string, b: string): string {
	return Date.parse(b) > Date.parse(a) ? b : a;
}

function agentComponents(
	agents: FleetAgentRow[],
	labels: ReadonlyMap<string, string>,
): AiBomComponent[] {
	const groups = new Map<
		string,
		{ runtime: string; version: string | null; count: number; lastSeen: string }
	>();
	for (const agent of agents) {
		const runtime = agent.agent_runtime ?? "unknown";
		const key = `${runtime}@${agent.agent_runtime_version ?? ""}`;
		const group = groups.get(key);
		if (group) {
			group.count += 1;
			group.lastSeen = latest(group.lastSeen, agent.last_seen);
		} else {
			groups.set(key, {
				runtime,
				version: agent.agent_runtime_version,
				count: 1,
				lastSeen: agent.last_seen,
			});
		}
	}
	return [...groups.values()].map((group) => ({
		type: "application",
		"bom-ref": `agent:${group.runtime}@${group.version ?? "unknown"}`,
		name:
			labels.get(group.runtime) ??
			(group.runtime === "unknown" ? "Unidentified runtime" : group.runtime),
		...(group.version ? { version: group.version } : {}),
		description: "AI agent runtime protected by Singularity AIDR",
		properties: [
			prop("aidr:component:kind", "ai-agent"),
			prop("aidr:agent:runtime", group.runtime),
			prop("aidr:fleet:device_count", group.count),
			prop("aidr:fleet:last_seen", group.lastSeen),
		],
	}));
}

function mcpService(row: PostureFindingRow): AiBomService {
	const categories = new Set(row.risk_categories ?? []);
	const hints = [...categories]
		.filter((category) => MCP_RISK_HINTS.has(category))
		.sort(compareText);
	return {
		"bom-ref": `mcp:${row.subject_digest ?? `${row.mcp_server_name ?? "withheld"}:${row.id}`}`,
		name: row.mcp_server_name ?? "(name withheld)",
		description: `MCP server (${row.mcp_transport ?? "transport not reported"})`,
		"x-trust-boundary": categories.has("remote_mcp_url"),
		properties: [
			prop("aidr:component:kind", "mcp-server"),
			...(row.mcp_transport ? [prop("aidr:mcp:transport", row.mcp_transport)] : []),
			prop("aidr:mcp:attestation", row.attestation_status ?? "not_reported"),
			prop("aidr:mcp:severity", row.severity),
			...hints.map((hint) => prop("aidr:mcp:risk_hint", hint)),
			...MCP_RISK_CATEGORY_IDS.map((id) => prop(`aidr:mcp:risk:${id}`, categories.has(id))),
			prop("aidr:posture:last_seen", row.observed_at),
		],
	};
}

type Rating = AiBomVulnerability["ratings"][number];

const SEVERITY_RANK: Record<string, number> = {
	unknown: 0,
	info: 1,
	low: 2,
	medium: 3,
	high: 4,
	critical: 5,
};

function isStronger(next: Rating | undefined, current: Rating | undefined): boolean {
	if (!next || !current) return false;
	const nextRank = SEVERITY_RANK[next.severity] ?? 0;
	const currentRank = SEVERITY_RANK[current.severity] ?? 0;
	return (
		nextRank > currentRank ||
		(nextRank === currentRank && (next.score ?? -1) > (current.score ?? -1))
	);
}

/**
 * Merge another observation of the same identifier. The record carries the most
 * severe rating and the strongest applicability seen, so the result does not
 * depend on row order.
 */
function mergeVulnerability(existing: AiBomVulnerability, candidate: AiBomVulnerability): void {
	for (const affected of candidate.affects)
		if (!existing.affects.some((a) => a.ref === affected.ref)) existing.affects.push(affected);
	if (isStronger(candidate.ratings[0], existing.ratings[0])) existing.ratings = candidate.ratings;
	const confirmed = candidate.properties.some(
		(p) => p.name === "aidr:applicability" && p.value === "confirmed",
	);
	if (!confirmed) return;
	for (const p of existing.properties) if (p.name === "aidr:applicability") p.value = "confirmed";
}

function infraVulnerability(row: PostureFindingRow, componentRef: string): AiBomVulnerability {
	const ref = row.vuln_id ? `vuln:${row.vuln_id}` : `vuln:advisory:${componentRef}`;
	const cvss = cvssOf(row.cvss);
	return {
		"bom-ref": ref,
		...(row.vuln_id ? { id: row.vuln_id } : {}),
		source: INFRA_SOURCE,
		ratings: [
			{
				source: INFRA_SOURCE,
				...(cvss !== undefined ? { score: cvss } : {}),
				severity: row.severity,
			},
		],
		...(row.vuln_id ? {} : { description: "Advisory without a CVE or GHSA identifier" }),
		affects: [
			{
				ref: componentRef,
				...(row.component_version
					? { versions: [{ version: row.component_version, status: "affected" as const }] }
					: {}),
			},
		],
		properties: [
			prop("aidr:finding:source", "infrastructure-scan"),
			prop("aidr:applicability", row.applicability === "confirmed" ? "confirmed" : "unconfirmed"),
		],
	};
}

function skillVulnerability(row: PostureFindingRow, pluginRef: string): AiBomVulnerability {
	return {
		"bom-ref": `vuln:skill:${row.rule_id ?? "unidentified-rule"}`,
		...(row.rule_id ? { id: row.rule_id } : {}),
		source: SKILL_SOURCE,
		ratings: [{ source: SKILL_SOURCE, severity: row.severity }],
		affects: [{ ref: pluginRef }],
		properties: [
			prop("aidr:finding:source", "skill-scan"),
			...(row.skill_risk_type ? [prop("aidr:skill_risk_type", row.skill_risk_type)] : []),
		],
	};
}

/** Components, services and vulnerabilities keyed by bom-ref while the findings are read. */
class TenantBomParts {
	readonly components = new Map<string, AiBomComponent>();
	readonly services = new Map<string, AiBomService>();
	readonly vulnerabilities = new Map<string, AiBomVulnerability>();
	private readonly infraTargets = new Map<string, Set<string>>();

	addFinding(row: PostureFindingRow): void {
		if (row.source === "mcp_inventory") {
			const service = mcpService(row);
			this.services.set(service["bom-ref"], service);
		} else if (row.source === "infra_scan") {
			this.addInfra(row);
		} else {
			this.addSkill(row);
		}
	}

	/** Each infrastructure component records how many distinct targets reported it. */
	finish(): void {
		for (const [ref, targets] of this.infraTargets)
			this.components.get(ref)?.properties.push(prop("aidr:infra:target_count", targets.size));
	}

	private addVulnerability(candidate: AiBomVulnerability): void {
		const existing = this.vulnerabilities.get(candidate["bom-ref"]);
		if (existing) mergeVulnerability(existing, candidate);
		else this.vulnerabilities.set(candidate["bom-ref"], candidate);
	}

	private addInfra(row: PostureFindingRow): void {
		const name = row.component ?? "unidentified component";
		const ref = `infra-component:${name}@${row.component_version ?? "unknown"}`;
		const targets = this.infraTargets.get(ref) ?? new Set<string>();
		targets.add(row.target_digest ?? `row-${row.id}`);
		this.infraTargets.set(ref, targets);
		this.components.set(ref, {
			type: "application",
			"bom-ref": ref,
			name,
			...(row.component_version ? { version: row.component_version } : {}),
			description: "AI infrastructure component identified by an AI Security Posture scan",
			properties: [prop("aidr:component:kind", "ai-infrastructure")],
		});
		if (row.finding_kind !== "exposed_component")
			this.addVulnerability(infraVulnerability(row, ref));
	}

	private addSkill(row: PostureFindingRow): void {
		const ref = row.plugin_key
			? `plugin:${row.plugin_key}`
			: `plugin:withheld:${row.subject_digest ?? row.id}`;
		this.components.set(ref, {
			type: "library",
			"bom-ref": ref,
			name: row.plugin_key ?? "(name withheld)",
			description: "Agent skill/plugin package",
			properties: [prop("aidr:component:kind", "agent-plugin")],
		});
		this.addVulnerability(skillVulnerability(row, ref));
	}
}

/** Build the tenant's AI-BOM. Pure: the same input always yields the same document. */
export function buildTenantAiBom(input: TenantAiBomInput): TenantAiBom {
	const parts = new TenantBomParts();
	for (const component of agentComponents(input.agents, input.runtimeLabels))
		parts.components.set(component["bom-ref"], component);
	for (const row of input.findings) parts.addFinding(row);
	parts.finish();
	const { components, services, vulnerabilities } = parts;

	const sortedComponents = [...components.values()].sort(byRef);
	const sortedServices = [...services.values()].sort(byRef);
	const sortedVulnerabilities = [...vulnerabilities.values()]
		.map((vulnerability) => ({
			...vulnerability,
			affects: [...vulnerability.affects].sort((a, b) => compareText(a.ref, b.ref)),
		}))
		.sort(byRef);

	return {
		$schema: SCHEMA_URL,
		bomFormat: "CycloneDX",
		specVersion: AIBOM_SPEC_VERSION,
		serialNumber: input.serialNumber,
		version: 1,
		metadata: {
			timestamp: input.generatedAt,
			lifecycles: [{ phase: "operations" }],
			tools: {
				components: [
					{
						type: "application",
						"bom-ref": "tool:singularity-aidr-dashboard",
						supplier: { name: "Singularity R&D" },
						name: "Singularity AIDR dashboard",
					},
				],
			},
			component: {
				type: "application",
				"bom-ref": TENANT_REF,
				name: input.tenant.name,
				description: "AI estate of this tenant as reported to Singularity AIDR",
			},
			properties: [
				prop("aidr:bom:scope", "tenant"),
				prop("aidr:tenant:id", input.tenant.id),
				prop("aidr:fleet:agent_count", input.agents.length),
				prop("aidr:posture:window_days", input.postureWindowDays),
				prop("aidr:posture:finding_count", input.findings.length),
				prop("aidr:posture:truncated", input.postureTruncated),
			],
		},
		components: sortedComponents,
		services: sortedServices,
		dependencies: [
			{
				ref: TENANT_REF,
				dependsOn: [...sortedComponents, ...sortedServices]
					.map((item) => item["bom-ref"])
					.sort(compareText),
			},
		],
		vulnerabilities: sortedVulnerabilities,
	};
}

/** A file name for the export, e.g. `aibom-acme-2026-09-25.cdx.json`. */
export function aiBomFileName(tenantName: string, generatedAt: string): string {
	const slug =
		tenantName
			.toLowerCase()
			.normalize("NFKD")
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-+|-+$/g, "")
			.slice(0, 48) || "tenant";
	return `aibom-${slug}-${generatedAt.slice(0, 10)}.cdx.json`;
}
