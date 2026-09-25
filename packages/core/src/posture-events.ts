/**
 * AI security posture telemetry: infrastructure CVE exposure, MCP server
 * inventory risk and skill/plugin package findings.
 *
 * These events are built for the managed control plane (`/v1/ingest`) and the
 * dashboard's /posture page. The same privacy rule applies as for runtime
 * telemetry: identifiers, enums, bounded numbers and digests only. Target URLs,
 * hostnames, file paths, server arguments, headers, matched text and any
 * credential stay on the machine. `supabase/functions/ingest/events.ts`
 * repeats this projection server-side for clients that bypass it.
 */

import { createHash } from "node:crypto";
import {
	AGENT_HOSTS,
	AGENT_POSTURE_CHECKS,
	type AgentEnvironmentReport,
} from "./agent-environment-posture.js";
import type { AigInfraScanSummary } from "./aig-infra-scan.js";
import { classifyMcpTool } from "./mcp-aig-categories.js";
import type { McpDiscoveryServer } from "./mcp-discovery.js";
import { skillRiskTypeForThreatId } from "./skill-risk-types.js";
import type { PluginScanResult } from "./types.js";

export const INFRA_SCAN_FINDING_EVENT = "infra_scan_finding";
export const MCP_INVENTORY_FINDING_EVENT = "mcp_inventory_finding";
export const AGENT_POSTURE_FINDING_EVENT = "agent_posture_finding";
/** Existing ingest type reused for skill/plugin package findings. */
export const PLUGIN_SCAN_FINDING_EVENT = "plugin_scan_finding";

const POSTURE_SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"] as const;
export type PostureSeverity = (typeof POSTURE_SEVERITIES)[number];

/** MCP risk indicators produced by `inspectMcpServerInventory`. */
const MCP_RISK_HINTS = [
	"remote_mcp_url",
	"shell_wrapper_command",
	"broad_filesystem_access_arg",
] as const;
const MCP_ATTESTATION_STATUSES = [
	"approved",
	"unapproved",
	"quarantined",
	"unsigned",
	"unverifiable",
	"rejected",
] as const;

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SENSITIVE_IDENTIFIER_PATTERN =
	/(?:^|[._:-])(?:api[_-]?key|access[_-]?token|authorization|bearer|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|client[_-]?secret|refresh[_-]?token|signature)(?:[._:-]|$)|^(?:sk[_-]|ghp_|github_pat_|xox[baprs]-|npm_|pypi-|AKIA)/i;
const JWT_LIKE_PATTERN = /^eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.(?:[A-Za-z0-9_-]{8,})?$/;
const PHONE_LIKE_PATTERN = /^(?:\d[.:-]?){8,15}$/;
const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
/** CVE and GitHub advisory identifiers; free-text AIG advisory titles are not exported. */
const VULN_ID_PATTERN = /^(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})$/;
/** Product / component labels as they appear in the AIG fingerprint data. */
const COMPONENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._+/-]{0,79}$/;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
/** Generated AIG ids are `mcp-01`…`mcp-14`; the offline fallback uses `aig-mcp-*`. */
const AIG_MCP_CATEGORY_PATTERN = /^(?:aig-)?mcp-[a-z0-9-]{1,48}$/;
const SKILL_RISK_TYPE_PATTERN = /^T0[1-9]$/;
const RULE_ID_PATTERN = /^[A-Z][A-Z0-9_-]{1,63}$/;

const FINDING_KINDS = [
	"cve",
	"advisory",
	"exposed_component",
	"mcp_server",
	"skill_rule",
	"agent_config",
] as const;
const MAX_FINDING_COUNT = 10_000;
const APPLICABILITY = ["confirmed", "unconfirmed"] as const;
const TRANSPORTS = ["remote", "stdio"] as const;
const MAX_RISK_CATEGORIES = 16;

function sha256Hex(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function digest(value: string): string {
	return `sha256:${sha256Hex(value)}`;
}

/** An identifier safe to store: bounded charset and not credential- or phone-shaped. */
function safePostureIdentifier(value: unknown): string | undefined {
	return typeof value === "string" &&
		IDENTIFIER_PATTERN.test(value) &&
		!SENSITIVE_IDENTIFIER_PATTERN.test(value) &&
		!JWT_LIKE_PATTERN.test(value) &&
		!PHONE_LIKE_PATTERN.test(value)
		? value
		: undefined;
}

function safeLabel(value: unknown, pattern: RegExp): string | undefined {
	return typeof value === "string" &&
		pattern.test(value) &&
		!SENSITIVE_IDENTIFIER_PATTERN.test(value) &&
		!JWT_LIKE_PATTERN.test(value)
		? value
		: undefined;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T | undefined {
	return typeof value === "string" && (allowed as readonly string[]).includes(value)
		? (value as T)
		: undefined;
}

/** Normalize an AIG / rule severity. Unrecognized values stay visibly unknown. */
export function normalizePostureSeverity(value: unknown): PostureSeverity {
	const lowered = typeof value === "string" ? value.trim().toLowerCase() : "";
	if (lowered === "moderate") return "medium";
	if (lowered === "informational") return "info";
	return oneOf(lowered, POSTURE_SEVERITIES) ?? "unknown";
}

/** The runtime ingest severity enum (`info|warning|high|critical`). */
function ingestSeverity(severity: PostureSeverity): "info" | "warning" | "high" | "critical" {
	if (severity === "critical" || severity === "high") return severity;
	if (severity === "info") return "info";
	return "warning";
}

const SEVERITY_RANK: Record<PostureSeverity, number> = {
	unknown: -1,
	info: 0,
	low: 1,
	medium: 2,
	high: 3,
	critical: 4,
};

function maxSeverity(values: PostureSeverity[]): PostureSeverity {
	return values.reduce<PostureSeverity>(
		(highest, value) => (SEVERITY_RANK[value] > SEVERITY_RANK[highest] ? value : highest),
		"info",
	);
}

function eventId(prefix: string, scanId: string, ...parts: string[]): string {
	return `${prefix}-${scanId}-${sha256Hex(JSON.stringify(parts)).slice(0, 24)}`;
}

/** A per-invocation scan id: every upload is a distinct observation for trend reporting. */
export function newPostureScanId(now: Date = new Date()): string {
	const stamp = now
		.toISOString()
		.replace(/[-:.TZ]/g, "")
		.slice(0, 14);
	return `${stamp}${sha256Hex(`${now.getTime()}:${Math.random()}:${process.pid}`).slice(0, 8)}`;
}

function targetDigest(target: string): string {
	// Digest the origin only: the path cannot change which host is exposed, and
	// a stable digest correlates repeated scans without exporting the host.
	try {
		return digest(`aidr-posture-target-v1\0${new URL(target).origin.toLowerCase()}`);
	} catch {
		return digest(`aidr-posture-target-v1\0${target.trim().toLowerCase()}`);
	}
}

/** A CVSS base score rounded to one decimal, or undefined outside 0-10. */
function cvssScore(value: unknown): number | undefined {
	return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 10
		? Math.round(value * 10) / 10
		: undefined;
}

/** `component`, `fingerprint` and `component_version`, each only when its label is safe. */
function componentFields(product: unknown, version: unknown): Record<string, string> {
	const component = safeLabel(product, COMPONENT_PATTERN);
	const componentVersion = safeLabel(version, VERSION_PATTERN);
	return {
		...(component ? { component, fingerprint: component.toLowerCase() } : {}),
		...(componentVersion ? { component_version: componentVersion } : {}),
	};
}

type InfraTarget = AigInfraScanSummary["targets"][number];

/** CVE/advisory events for one target, then one event per component with none. */
function infraTargetEvents(
	target: InfraTarget,
	scanId: string,
	timestamp: string,
): Record<string, unknown>[] {
	const target_digest = targetDigest(target.url);
	const versions = new Map(
		target.matched.map((match) => [match.product.toLowerCase(), match.version]),
	);
	const events: Record<string, unknown>[] = target.cves.map((cve) => {
		const findingSeverity = normalizePostureSeverity(cve.severity);
		const vulnId = safeLabel(cve.cveId, VULN_ID_PATTERN);
		const cvss = cvssScore(cve.cvss);
		return {
			event_id: eventId("infra", scanId, target_digest, cve.cveId, cve.product),
			type: INFRA_SCAN_FINDING_EVENT,
			timestamp,
			scan_id: scanId,
			finding_kind: vulnId ? "cve" : "advisory",
			severity: ingestSeverity(findingSeverity),
			finding_severity: findingSeverity,
			...(vulnId ? { vuln_id: vulnId } : {}),
			...(cvss !== undefined ? { cvss } : {}),
			...componentFields(cve.product, versions.get(cve.product.toLowerCase())),
			applicability: cve.evaluated ? "confirmed" : "unconfirmed",
			target_digest,
		};
	});
	const productsWithFindings = new Set(target.cves.map((cve) => cve.product.toLowerCase()));
	for (const match of target.matched) {
		if (productsWithFindings.has(match.product.toLowerCase())) continue;
		events.push({
			event_id: eventId("infra", scanId, target_digest, "component", match.product),
			type: INFRA_SCAN_FINDING_EVENT,
			timestamp,
			scan_id: scanId,
			finding_kind: "exposed_component",
			severity: "info",
			finding_severity: "info",
			...componentFields(match.product, match.version),
			target_digest,
		});
	}
	return events;
}

/** One event per matched CVE/advisory, plus one per identified component without any. */
export function buildInfraScanFindingEvents(
	summary: AigInfraScanSummary,
	scanId: string,
): Record<string, unknown>[] {
	return summary.targets.flatMap((target) => infraTargetEvents(target, scanId, summary.scannedAt));
}

const HINT_SEVERITY: Record<(typeof MCP_RISK_HINTS)[number], PostureSeverity> = {
	shell_wrapper_command: "high",
	broad_filesystem_access_arg: "high",
	remote_mcp_url: "medium",
};

/**
 * One inventory event per discovered MCP server. Risk categories are the local
 * configuration indicators plus the AIG MCP categories suggested by the server
 * name; attestation status is reported as evidence, never inferred.
 */
export function buildMcpInventoryFindingEvents(
	report: { scanned_at: string; servers: McpDiscoveryServer[] },
	scanId: string,
): Record<string, unknown>[] {
	return report.servers.map((server) => {
		const hints = server.risk_hints.filter((hint): hint is (typeof MCP_RISK_HINTS)[number] =>
			(MCP_RISK_HINTS as readonly string[]).includes(hint),
		);
		const classified = classifyMcpTool(server.name, "", {});
		const categories = classified.matchedCategories
			.map((category) => category.id)
			.filter((id) => AIG_MCP_CATEGORY_PATTERN.test(id));
		const attestation = oneOf(server.attestation.status, MCP_ATTESTATION_STATUSES);
		const severities: PostureSeverity[] = hints.map((hint) => HINT_SEVERITY[hint]);
		if (categories.length > 0) severities.push(classified.riskLevel);
		if (attestation === "rejected" || attestation === "quarantined") severities.push("high");
		const findingSeverity = maxSeverity(severities);
		const name = safePostureIdentifier(server.name);
		return {
			event_id: eventId("mcp", scanId, server.inventory_id),
			type: MCP_INVENTORY_FINDING_EVENT,
			timestamp: report.scanned_at,
			scan_id: scanId,
			finding_kind: "mcp_server",
			severity: ingestSeverity(findingSeverity),
			finding_severity: findingSeverity,
			...(name ? { mcp_server_name: name } : {}),
			mcp_transport: server.transport,
			risk_categories: [...new Set([...hints, ...categories])].slice(0, MAX_RISK_CATEGORIES),
			...(attestation ? { attestation_status: attestation } : {}),
			server_digest: `sha256:${server.inventory_id}`,
			configuration_digest: `sha256:${server.configuration_sha256}`,
		};
	});
}

/** One event per skill/plugin finding. Matched text and file paths are not exported. */
export function buildSkillScanFindingEvents(
	results: PluginScanResult[],
	scanId: string,
	scannedAt: string = new Date().toISOString(),
): Record<string, unknown>[] {
	const events: Record<string, unknown>[] = [];
	for (const result of results) {
		const pluginKey = safePostureIdentifier(result.plugin.key);
		const pluginVersion = safeLabel(result.plugin.version, VERSION_PATTERN);
		for (const finding of result.findings) {
			const findingSeverity = normalizePostureSeverity(finding.severity);
			const skillRiskType = skillRiskTypeForThreatId(finding.threatId);
			const ruleId = safeLabel(finding.threatId, RULE_ID_PATTERN);
			events.push({
				event_id: eventId(
					"skill",
					scanId,
					result.plugin.key,
					finding.threatId,
					finding.sourceFile,
					finding.artifact,
				),
				type: PLUGIN_SCAN_FINDING_EVENT,
				timestamp: scannedAt,
				scan_id: scanId,
				finding_kind: "skill_rule",
				severity: ingestSeverity(findingSeverity),
				finding_severity: findingSeverity,
				...(pluginKey ? { plugin_key: pluginKey } : {}),
				...(pluginVersion ? { plugin_version: pluginVersion } : {}),
				...(ruleId ? { matched_threat_id: ruleId } : {}),
				...(skillRiskType ? { skill_risk_type: skillRiskType } : {}),
				source_file_digest: digest(
					`aidr-posture-file-v1\0${result.plugin.key}\0${finding.sourceFile}`,
				),
			});
		}
	}
	return events;
}

/**
 * One event per agent environment finding: host, check id, severity and a count.
 * Config paths, key names, environment variable names and values stay local.
 */
export function buildAgentPostureFindingEvents(
	report: Pick<AgentEnvironmentReport, "scanned_at" | "findings">,
	scanId: string,
): Record<string, unknown>[] {
	return report.findings.map((finding, index) => ({
		event_id: eventId("agent", scanId, finding.host, finding.id, String(index)),
		type: AGENT_POSTURE_FINDING_EVENT,
		timestamp: report.scanned_at,
		scan_id: scanId,
		finding_kind: "agent_config",
		severity: ingestSeverity(finding.severity),
		finding_severity: finding.severity,
		agent_host: finding.host,
		check_id: finding.id,
		finding_count: findingCount(finding.count),
	}));
}

function findingCount(value: unknown): number | undefined {
	return typeof value === "number" &&
		Number.isInteger(value) &&
		value >= 0 &&
		value <= MAX_FINDING_COUNT
		? value
		: undefined;
}

/** Known risk hints and AIG MCP categories, deduplicated and bounded; undefined if not a list. */
function riskCategories(value: unknown): string[] | undefined {
	if (!Array.isArray(value)) return undefined;
	const known = value.filter(
		(item): item is string =>
			typeof item === "string" &&
			((MCP_RISK_HINTS as readonly string[]).includes(item) || AIG_MCP_CATEGORY_PATTERN.test(item)),
	);
	return [...new Set(known)].slice(0, MAX_RISK_CATEGORIES);
}

const postureDigest = (value: unknown): string | undefined =>
	typeof value === "string" && HASH_PATTERN.test(value) ? value : undefined;

/** Each posture field the ingest contract understands and its validator (undefined drops it). */
const POSTURE_FIELDS: ReadonlyArray<readonly [string, (value: unknown) => unknown]> = [
	["scan_id", safePostureIdentifier],
	["finding_kind", (value) => oneOf(value, FINDING_KINDS)],
	["finding_severity", (value) => oneOf(value, POSTURE_SEVERITIES)],
	["vuln_id", (value) => safeLabel(value, VULN_ID_PATTERN)],
	["cvss", cvssScore],
	["component", (value) => safeLabel(value, COMPONENT_PATTERN)],
	["fingerprint", (value) => safeLabel(value, COMPONENT_PATTERN)],
	["component_version", (value) => safeLabel(value, VERSION_PATTERN)],
	["applicability", (value) => oneOf(value, APPLICABILITY)],
	["mcp_server_name", safePostureIdentifier],
	["mcp_transport", (value) => oneOf(value, TRANSPORTS)],
	["risk_categories", riskCategories],
	["attestation_status", (value) => oneOf(value, MCP_ATTESTATION_STATUSES)],
	["plugin_version", (value) => safeLabel(value, VERSION_PATTERN)],
	["skill_risk_type", (value) => safeLabel(value, SKILL_RISK_TYPE_PATTERN)],
	["agent_host", (value) => oneOf(value, AGENT_HOSTS)],
	["check_id", (value) => oneOf(value, AGENT_POSTURE_CHECKS)],
	["finding_count", findingCount],
	["target_digest", postureDigest],
	["server_digest", postureDigest],
	["configuration_digest", postureDigest],
	["source_file_digest", postureDigest],
];

/**
 * Copy only the posture fields the ingest contract understands, re-validating
 * each one. Used by the telemetry boundary (`redactRemoteEvent`) so that a
 * caller cannot smuggle raw targets, paths or matched text under these keys.
 */
export function projectPostureFields(source: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [key, validate] of POSTURE_FIELDS) {
		const value = validate(source[key]);
		if (value !== undefined && value !== "") out[key] = value;
	}
	return out;
}
