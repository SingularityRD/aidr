/**
 * CycloneDX 1.6 JSON rendering of the AI inventory.
 *
 * Mapping (CycloneDX component/service types used as the specification defines
 * them):
 * - the scanned project → `metadata.component` (`application`);
 * - agent hosts (Claude Code, Cursor, …) → `application` components;
 * - AI SDKs / frameworks / runtimes / packaged models from manifests →
 *   `library` / `framework` / `application` / `machine-learning-model`
 *   components with a purl;
 * - model weight files → `machine-learning-model` components;
 * - skills/plugins → `library` components;
 * - MCP servers and scanned AI infrastructure endpoints → `services`;
 * - CVEs and skill-scan rule findings → `vulnerabilities`, `affects` pointing
 *   at the bom-refs above;
 * - agent → MCP server / plugin and project → component edges → `dependencies`.
 *
 * Output is deterministic for a given inventory and serial number: every list
 * is sorted by bom-ref and properties are emitted in a fixed order.
 */

import { randomUUID } from "node:crypto";
import type {
	AiInventory,
	AiInventoryMcpServer,
	AiInventoryPackage,
	AiInventoryVulnerability,
} from "./inventory.js";
import { PROJECT_REF } from "./inventory.js";
import { compareText } from "./project-scan.js";

export const CYCLONEDX_SPEC_VERSION = "1.6";
const CYCLONEDX_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.6.schema.json";

export interface CycloneDxProperty {
	name: string;
	value: string;
}

export interface CycloneDxComponent {
	type: string;
	"bom-ref": string;
	supplier?: { name: string };
	group?: string;
	name: string;
	version?: string;
	description?: string;
	purl?: string;
	properties?: CycloneDxProperty[];
}

export interface CycloneDxService {
	"bom-ref": string;
	name: string;
	version?: string;
	description?: string;
	endpoints?: string[];
	"x-trust-boundary"?: boolean;
	properties?: CycloneDxProperty[];
}

export interface CycloneDxVulnerability {
	"bom-ref": string;
	id?: string;
	source: { name: string };
	ratings: Array<{ source: { name: string }; score?: number; severity: string }>;
	description?: string;
	affects: Array<{ ref: string; versions?: Array<{ version: string; status: "affected" }> }>;
	properties?: CycloneDxProperty[];
}

export interface CycloneDxBom {
	$schema: typeof CYCLONEDX_SCHEMA_URL;
	bomFormat: "CycloneDX";
	specVersion: typeof CYCLONEDX_SPEC_VERSION;
	serialNumber: string;
	version: 1;
	metadata: {
		timestamp: string;
		lifecycles: Array<{ phase: "discovery" }>;
		tools: { components: CycloneDxComponent[] };
		component: CycloneDxComponent;
		properties: CycloneDxProperty[];
	};
	components: CycloneDxComponent[];
	services: CycloneDxService[];
	dependencies: Array<{ ref: string; dependsOn: string[] }>;
	vulnerabilities: CycloneDxVulnerability[];
}

export interface BuildCycloneDxOptions {
	/** `urn:uuid:<uuid>`; a random UUID when omitted. */
	serialNumber?: string;
}

const SERIAL_RE = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const VULNERABILITY_SOURCES: Record<AiInventoryVulnerability["source"], string> = {
	"cve-index": "AI Security Posture CVE index",
	"infrastructure-scan": "AI Security Posture infrastructure scan",
	"skill-scan": "Singularity AIDR skill and plugin scan",
};

function prop(name: string, value: string | number | boolean): CycloneDxProperty {
	return { name, value: String(value) };
}

function byRef<T extends { "bom-ref": string }>(a: T, b: T): number {
	return compareText(a["bom-ref"], b["bom-ref"]);
}

/** npm `@scope/name` → group `@scope`, name `name` (CycloneDX convention). */
function splitPackageName(pkg: AiInventoryPackage): { group?: string; name: string } {
	if (pkg.ecosystem === "npm" && pkg.name.startsWith("@") && pkg.name.includes("/")) {
		const slash = pkg.name.indexOf("/");
		return { group: pkg.name.slice(0, slash), name: pkg.name.slice(slash + 1) };
	}
	return { name: pkg.name };
}

function packageComponent(pkg: AiInventoryPackage): CycloneDxComponent {
	const properties = [
		prop("aidr:component:kind", "ai-package"),
		prop("aidr:ai:category", pkg.category),
		prop("aidr:package:ecosystem", pkg.ecosystem),
	];
	if (pkg.declared !== null) properties.push(prop("aidr:package:declared_version", pkg.declared));
	if (pkg.version_source) properties.push(prop("aidr:package:version_source", pkg.version_source));
	for (const manifest of pkg.manifests) properties.push(prop("aidr:package:manifest", manifest));
	properties.push(prop("aidr:vulnerability_check", pkg.vulnerability_check));
	return {
		type: pkg.type,
		"bom-ref": pkg.ref,
		...(pkg.supplier ? { supplier: { name: pkg.supplier } } : {}),
		...splitPackageName(pkg),
		...(pkg.version ? { version: pkg.version } : {}),
		purl: pkg.purl,
		properties,
	};
}

function mcpService(server: AiInventoryMcpServer): CycloneDxService {
	const properties = [
		prop("aidr:component:kind", "mcp-server"),
		prop("aidr:mcp:transport", server.transport),
	];
	if (server.command !== null) properties.push(prop("aidr:mcp:command", server.command));
	// Arguments keep their order, so they travel as one JSON array.
	if (server.args.length > 0) properties.push(prop("aidr:mcp:args", JSON.stringify(server.args)));
	properties.push(
		prop("aidr:mcp:config_source", server.config_source),
		prop("aidr:mcp:configuration_sha256", server.configuration_sha256),
		prop("aidr:mcp:attestation", server.attestation_status),
		prop("aidr:mcp:risk_level", server.risk_level),
	);
	for (const hint of server.risk_hints) properties.push(prop("aidr:mcp:risk_hint", hint));
	for (const category of server.risk_categories)
		properties.push(prop(`aidr:mcp:risk:${category.id}`, category.matched));
	return {
		"bom-ref": server.ref,
		name: server.name,
		description: `MCP server (${server.transport})`,
		...(server.endpoint ? { endpoints: [server.endpoint] } : {}),
		"x-trust-boundary": server.risk_hints.includes("remote_mcp_url"),
		properties,
	};
}

function vulnerability(entry: AiInventoryVulnerability): CycloneDxVulnerability {
	const source = { name: VULNERABILITY_SOURCES[entry.source] };
	const properties: CycloneDxProperty[] = [prop("aidr:finding:source", entry.source)];
	if (entry.applicability) properties.push(prop("aidr:applicability", entry.applicability));
	if (entry.skill_risk_type) properties.push(prop("aidr:skill_risk_type", entry.skill_risk_type));
	return {
		"bom-ref": entry.ref,
		...(entry.id ? { id: entry.id } : {}),
		source,
		ratings: [
			{
				source,
				...(entry.cvss !== null ? { score: entry.cvss } : {}),
				severity: entry.severity,
			},
		],
		...(entry.title
			? { description: entry.title }
			: entry.id
				? {}
				: { description: "Advisory without a CVE or GHSA identifier" }),
		affects: entry.affects.map((affected) => ({
			ref: affected.ref,
			...(affected.version
				? { versions: [{ version: affected.version, status: "affected" as const }] }
				: {}),
		})),
		properties,
	};
}

/** Render an AI inventory as a CycloneDX 1.6 JSON BOM. */
export function buildCycloneDxBom(
	inventory: AiInventory,
	options: BuildCycloneDxOptions = {},
): CycloneDxBom {
	const serialNumber = options.serialNumber ?? `urn:uuid:${randomUUID()}`;
	if (!SERIAL_RE.test(serialNumber)) throw new Error("serialNumber must be urn:uuid:<uuid>");

	const components: CycloneDxComponent[] = [
		...inventory.agents.map((agent) => ({
			type: "application",
			"bom-ref": agent.ref,
			name: agent.label,
			description: "AI agent host",
			properties: [
				prop("aidr:component:kind", "ai-agent"),
				prop("aidr:agent:id", agent.id),
				prop("aidr:agent:protection_state", agent.state),
			],
		})),
		...inventory.packages.map(packageComponent),
		...inventory.model_files.map((file) => ({
			type: "machine-learning-model",
			"bom-ref": file.ref,
			name: file.path.slice(file.path.lastIndexOf("/") + 1),
			description: "Model weights file found in the project",
			properties: [
				prop("aidr:component:kind", "model-file"),
				prop("aidr:model:path", file.path),
				prop("aidr:model:format", file.format),
				prop("aidr:model:size_bytes", file.size_bytes),
			],
		})),
		...inventory.plugins.map((plugin) => ({
			type: "library",
			"bom-ref": plugin.ref,
			name: plugin.key,
			...(plugin.version && plugin.version !== "unknown" ? { version: plugin.version } : {}),
			description: "Agent skill/plugin package",
			properties: [
				prop("aidr:component:kind", "agent-plugin"),
				prop("aidr:plugin:scan_status", plugin.scan_status),
				...(plugin.scanned_at ? [prop("aidr:plugin:scanned_at", plugin.scanned_at)] : []),
				prop("aidr:plugin:finding_count", plugin.finding_count),
			],
		})),
	].sort(byRef);

	const services: CycloneDxService[] = [
		...inventory.mcp_servers.map(mcpService),
		...inventory.infrastructure.map((service) => ({
			"bom-ref": service.ref,
			name: service.products.map((p) => p.product).join(", ") || new URL(service.endpoint).host,
			...(service.products.length === 1 && service.products[0]?.version
				? { version: service.products[0].version }
				: {}),
			description: "AI infrastructure endpoint from an AI Security Posture scan",
			endpoints: [service.endpoint],
			properties: [
				prop("aidr:component:kind", "ai-infrastructure"),
				prop("aidr:infra:reachable", service.reachable),
				prop("aidr:infra:scan_error", service.scan_error),
				...service.products.map((p) =>
					prop("aidr:infra:product", p.version ? `${p.product}@${p.version}` : p.product),
				),
			],
		})),
	].sort(byRef);

	// Agent → its MCP servers and plugins; everything else hangs off the project.
	const agentRefs = new Set(inventory.agents.map((agent) => agent.ref));
	const agentEdges = new Map<string, Set<string>>();
	const projectEdges = new Set<string>();
	const attach = (agentId: string | null, ref: string) => {
		const agentRef = agentId ? `agent:${agentId}` : null;
		if (agentRef && agentRefs.has(agentRef)) {
			const edges = agentEdges.get(agentRef) ?? new Set<string>();
			edges.add(ref);
			agentEdges.set(agentRef, edges);
		} else projectEdges.add(ref);
	};
	for (const agent of inventory.agents) projectEdges.add(agent.ref);
	for (const pkg of inventory.packages) projectEdges.add(pkg.ref);
	for (const file of inventory.model_files) projectEdges.add(file.ref);
	for (const service of inventory.infrastructure) projectEdges.add(service.ref);
	for (const server of inventory.mcp_servers) attach(server.agent, server.ref);
	// The plugin registry read is Claude Code's.
	for (const plugin of inventory.plugins) attach("claude-code", plugin.ref);
	const dependencies = [
		{ ref: PROJECT_REF, dependsOn: [...projectEdges].sort(compareText) },
		...[...agentEdges.entries()].map(([ref, edges]) => ({
			ref,
			dependsOn: [...edges].sort(compareText),
		})),
	].sort((a, b) => compareText(a.ref, b.ref));

	const coverage = inventory.coverage;
	const metadataProperties = [
		prop("aidr:inventory:schema", inventory.schema),
		prop("aidr:coverage:mcp", coverage.mcp.status),
		prop("aidr:coverage:mcp_sources_invalid", coverage.mcp.sources_invalid),
		prop("aidr:coverage:mcp_servers_not_enumerated", coverage.mcp.servers_not_enumerated),
		...coverage.manifests.map((m) => prop(`aidr:coverage:manifest:${m.path}`, m.status)),
		prop("aidr:coverage:model_scan", coverage.model_scan),
		prop("aidr:coverage:plugin_registry", coverage.plugin_registry),
		prop("aidr:coverage:plugin_scan_cache", coverage.plugin_scan_cache),
		prop("aidr:coverage:cve_index", coverage.cve_index),
		prop("aidr:coverage:infrastructure_report", coverage.infrastructure_report),
		prop("aidr:project:path", inventory.project.path),
	];

	return {
		$schema: CYCLONEDX_SCHEMA_URL,
		bomFormat: "CycloneDX",
		specVersion: CYCLONEDX_SPEC_VERSION,
		serialNumber,
		version: 1,
		metadata: {
			timestamp: inventory.generated_at,
			lifecycles: [{ phase: "discovery" }],
			tools: {
				components: [
					{
						type: "application",
						"bom-ref": "tool:singularity-aidr",
						supplier: { name: "Singularity R&D" },
						name: inventory.tool.name,
						version: inventory.tool.version,
					},
				],
			},
			component: {
				type: "application",
				"bom-ref": PROJECT_REF,
				name: inventory.project.name,
				...(inventory.project.version ? { version: inventory.project.version } : {}),
			},
			properties: metadataProperties,
		},
		components,
		services,
		dependencies,
		vulnerabilities: inventory.vulnerabilities.map(vulnerability),
	};
}
