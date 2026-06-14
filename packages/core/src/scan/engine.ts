/**
 * AIDR Scan — Engine orchestrator.
 *
 * Public API entry point for the AIDR Scan engine. Routes scan requests
 * to the appropriate sub-engine (CVE / MCP / Agent / Jailbreak / Threats),
 * unifies the result shape, and exposes engine stats.
 *
 * Usage:
 *   import { scan, getEngineStats } from "@singularityrd/aidr-core/scan";
 *
 *   const result = await scan({ type: "cve", target: { package, version, ecosystem } });
 *
 *   const stats = getEngineStats();
 *   // { cve: { total: 1354, by_severity: {...} }, mcp: { categories: 14 }, ... }
 *
 * Migrated and rebranded from the previous AIG aig-scan-client.ts.
 * Native in-process TS — no HTTP round-trip, no Go sidecar, sub-50ms cold.
 *
 * Closed-source: part of the AIDR Scan engine.
 */

import { randomUUID } from "node:crypto";
import type { ScanRequest, ScanResult, ScanType } from "./types.js";
import {
	checkFrameworkCves,
	checkPackageAgainstCveIndex,
	getCveStats,
	type CveStats,
} from "./cve.js";
import { runMcpScan, summarizeFindings, emptySummary } from "./mcp.js";
import { getAllCategories } from "./mcp-categories.js";
import { runAgentScan } from "./agent.js";
import { runJailbreakEval, getJailbreakTestCatalog } from "./jailbreak.js";
import { runThreatsScan, getThreatIndexStats, type ThreatIndexStats } from "./threats.js";

export type { ScanRequest, ScanResult, ScanType, Finding, Severity, PolicyAction } from "./types.js";
export { checkPackageAgainstCveIndex, checkFrameworkCves, getCveStats } from "./cve.js";
export {
	loadScanMcpCategories,
	classifyMcpTool,
	scanRiskToPolicyAction,
	getAllCategories,
	resetCategoryCache,
	type McpCategory,
	type RiskLevel,
} from "./mcp-categories.js";
export { runMcpScan, scanMcpTools, type CategoryBreakdown, type McpScanData } from "./mcp.js";
export { runAgentScan, type AgentScanData } from "./agent.js";
export { runJailbreakEval, getJailbreakTestCatalog, type JailbreakScanData } from "./jailbreak.js";
export {
	runThreatsScan,
	resetThreatIndexCache,
	type ThreatRule,
	type ThreatIndex,
	type ThreatsScanData,
} from "./threats.js";

export interface EngineStats {
	cve: CveStats;
	mcp: {
		categories: number;
		patterns: number;
	};
	agent: {
		pattern_count: number;
	};
	jailbreak: {
		test_catalog_size: number;
		suites: string[];
	};
	threats: ThreatIndexStats;
	version: string;
	generated_at: string;
}

/**
 * Engine version. Bump on every release.
 */
export const SCAN_ENGINE_VERSION = "1.0.0-sprint0";

/**
 * Engine build timestamp (set at build time, fallback to now).
 */
export const SCAN_ENGINE_GENERATED = new Date().toISOString();

/**
 * Run any AIDR Scan engine by type.
 */
export async function scan<R extends ScanResult = ScanResult>(request: ScanRequest): Promise<R> {
	switch (request.type) {
		case "cve":
			return (await runCveScan(request.target)) as R;
		case "mcp":
			return (await runMcpScan(request.target)) as R;
		case "agent":
			return (await runAgentScan(request.target)) as R;
		case "jailbreak":
			return (await runJailbreakEval(request.target)) as R;
		case "threats":
			return (await runThreatsScan(request.target)) as R;
	}
}

/**
 * CVE-specific scan — synchronous (no I/O), wraps result in standard shape.
 */
async function runCveScan(target: {
	package: string;
	version: string;
	ecosystem: string;
	framework?: string;
}): Promise<ScanResult> {
	const start = performance.now();
	const scanId = `aidr-scan-cve-${randomUUID()}`;
	const startedAt = new Date().toISOString();

	try {
		const results = target.framework
			? checkFrameworkCves(target.framework)
			: checkPackageAgainstCveIndex(target.package, target.version, target.ecosystem);

		const findings = results.map((r) => ({
			id: r.cve_id,
			engine: "cve" as const,
			category: "vulnerability",
			severity: (r.severity as "critical" | "high" | "medium" | "low") ?? "medium",
			confidence: 1.0,
			action:
				r.severity === "critical"
					? ("deny" as const)
					: r.severity === "high"
						? ("ask" as const)
						: ("audit" as const),
			title: `${r.cve_id} — ${r.package_name}@${r.matched_version}`,
			description: `CVE ${r.cve_id} matched ${r.package_name}@${r.matched_version} (${r.ecosystem}). CVSS ${r.cvss_score ?? "n/a"}.`,
			target: `${r.package_name}@${r.matched_version}`,
			metadata: {
				cve_id: r.cve_id,
				package_name: r.package_name,
				ecosystem: r.ecosystem,
				cvss_score: r.cvss_score,
				matched_version: r.matched_version,
			},
			remediation: `Upgrade ${r.package_name} to a version that does not satisfy the vulnerable range.`,
		}));

		const finishedAt = new Date().toISOString();
		const duration = performance.now() - start;

		return {
			scan_id: scanId,
			engine: "cve",
			status: "completed",
			started_at: startedAt,
			finished_at: finishedAt,
			duration_ms: Math.round(duration),
			findings,
			summary: summarizeFindings(findings),
			data: {
				package: target.package,
				version: target.version,
				ecosystem: target.ecosystem,
				matched: results.length,
			},
		};
	} catch (err) {
		const finishedAt = new Date().toISOString();
		const duration = performance.now() - start;
		return {
			scan_id: scanId,
			engine: "cve",
			status: "failed",
			started_at: startedAt,
			finished_at: finishedAt,
			duration_ms: Math.round(duration),
			findings: [],
			summary: emptySummary(),
			error: err instanceof Error ? err.message : String(err),
		};
	}
}

/**
 * Return aggregate stats across all engines.
 */
export function getEngineStats(): EngineStats {
	const cveStats = getCveStats();
	const categories = getAllCategories();
	const patternCount = categories.reduce(
		(sum, c) => sum + (c.detection_patterns?.length ?? 0),
		0,
	);
	const jailbreakCatalog = getJailbreakTestCatalog("en");

	return {
		cve: cveStats,
		mcp: {
			categories: categories.length,
			patterns: patternCount,
		},
		agent: {
			pattern_count: 17,
		},
		jailbreak: {
			test_catalog_size: jailbreakCatalog.length,
			suites: [...new Set(jailbreakCatalog.map((t) => t.suite))],
		},
		threats: getThreatIndexStats(),
		version: SCAN_ENGINE_VERSION,
		generated_at: SCAN_ENGINE_GENERATED,
	};
}
