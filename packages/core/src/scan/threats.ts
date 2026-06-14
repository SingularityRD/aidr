/**
 * AIDR Scan — Threats YAML loader.
 *
 * Loads the AIDR core's existing threats/*.yaml rule files at build
 * time and compiles them into a single JSON index for runtime use.
 *
 * This bridges the existing AIDR Edge Guard rule engine (URL Reputation,
 * Local Heuristics, Package Supply-Chain, Plugin Scanning) with the
 * AIDR Scan engine — both consume the same threats index.
 *
 * Migrated and rebranded from the previous AIG `sync-aig-threats.mjs`
 * integration. The 17 YAML files in `aidr/threats/` are now compiled
 * by `scripts/build-scan-index.mjs` into `scan-threats-index.json`.
 *
 * Closed-source: part of the AIDR Scan engine.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, ScanResult, ThreatsTarget } from "./types.js";
import { emptySummary, summarizeFindings } from "./mcp.js";

export interface ThreatRule {
	id: string;
	category: string;
	severity: "critical" | "high" | "medium" | "low";
	confidence: number;
	action: "block" | "require_approval" | "warn" | "monitor";
	pattern: string;
	match_on: "content" | "command" | "file_path" | "url";
	title: string;
	expires_at: string | null;
	revoked: boolean;
}

export interface ThreatIndex {
	version: number;
	generated: string;
	rule_count: number;
	rules: ThreatRule[];
}

export interface ThreatsScanData {
	rules_evaluated: number;
	rules_matched: number;
	match_on: string;
	summary: string;
}

const _dirname = (() => {
	try {
		if (typeof import.meta.dirname === "string") return import.meta.dirname;
	} catch {
		// fall through
	}
	try {
		return fileURLToPath(new URL(".", import.meta.url));
	} catch {
		return process.cwd();
	}
})();

const SCAN_THREATS_INDEX_PATH = join(_dirname, "..", "generated", "scan-threats-index.json");

/**
 * Resolves the threats index path, looking in both src/generated/ and
 * dist/generated/ so the engine works identically from source or built.
 */
function resolveThreatsIndexPath(): string {
	const candidates = [
		SCAN_THREATS_INDEX_PATH,
		join(_dirname, "generated", "scan-threats-index.json"),
	];
	for (const p of candidates) {
		if (existsSync(p)) return p;
	}
	return SCAN_THREATS_INDEX_PATH;
}

let _index: ThreatIndex | null | undefined;

function findProjectRoot(): string {
	const dir = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
	return dir;
}

function loadIndex(): ThreatIndex | null {
	if (_index !== undefined) return _index;
	const candidates = [
		resolveThreatsIndexPath(),
		join(findProjectRoot(), "src", "generated", "scan-threats-index.json"),
	];
	for (const candidatePath of candidates) {
		try {
			if (existsSync(candidatePath)) {
				const raw = readFileSync(candidatePath, "utf-8");
				const parsed = JSON.parse(raw) as ThreatIndex;
				if (Array.isArray(parsed?.rules) && typeof parsed.version === "number") {
					_index = parsed;
					return _index;
				}
			}
		} catch {
			// try next
		}
	}
	_index = null;
	return _index;
}

export function resetThreatIndexCache(): void {
	_index = undefined;
}

export interface ThreatIndexStats {
	rule_count: number;
	generated: string;
}

export function getThreatIndexStats(): ThreatIndexStats {
	const idx = loadIndex();
	if (!idx) return { rule_count: 0, generated: "" };
	return { rule_count: idx.rule_count, generated: idx.generated };
}

const POLICY_ACTION_MAP: Record<ThreatRule["action"], Finding["action"]> = {
	block: "deny",
	require_approval: "ask",
	warn: "audit",
	monitor: "allow",
};

/**
 * Run the threats rule engine against arbitrary content.
 */
export async function runThreatsScan(target: ThreatsTarget): Promise<ScanResult<ThreatsScanData>> {
	const start = performance.now();
	const scanId = `aidr-scan-threats-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
	const startedAt = new Date().toISOString();

	try {
		const index = loadIndex();
		const findings: Finding[] = [];
		let rulesEvaluated = 0;
		let rulesMatched = 0;

		if (index) {
			for (const rule of index.rules) {
				if (rule.revoked) continue;
				if (rule.expires_at && new Date(rule.expires_at) < new Date()) continue;
				// Skip rules without a pattern — they cannot match anything
				// and would cause a regex compile error or false positives.
				if (!rule.pattern || rule.pattern.trim() === "") continue;
				if (!rule.match_on.includes(target.matchOn) && rule.match_on !== target.matchOn) {
					// Some rules match on multiple types — accept that case
					const arr = Array.isArray(rule.match_on) ? rule.match_on : [rule.match_on];
					if (!arr.includes(target.matchOn)) continue;
				}

				rulesEvaluated++;
				try {
					const re = new RegExp(rule.pattern, "i");
					if (re.test(target.content)) {
						rulesMatched++;
						findings.push({
							id: rule.id,
							engine: "threats",
							category: rule.category,
							severity: rule.severity,
							confidence: rule.confidence,
							action: POLICY_ACTION_MAP[rule.action],
							title: rule.title,
							description: `Threat rule "${rule.id}" matched on ${target.matchOn}.`,
							target: target.content.slice(0, 100),
							metadata: { rule_id: rule.id, pattern: rule.pattern, match_on: target.matchOn },
						});
					}
				} catch {
					// Invalid regex — skip
				}
			}
		}

		const summary = `Threats scan complete. ${rulesMatched} of ${rulesEvaluated} rule(s) matched on ${target.matchOn}.`;

		const finishedAt = new Date().toISOString();
		const duration = performance.now() - start;

		return {
			scan_id: scanId,
			engine: "threats",
			status: "completed",
			started_at: startedAt,
			finished_at: finishedAt,
			duration_ms: Math.round(duration),
			findings,
			summary: summarizeFindings(findings),
			data: {
				rules_evaluated: rulesEvaluated,
				rules_matched: rulesMatched,
				match_on: target.matchOn,
				summary,
			},
		};
	} catch (err) {
		const finishedAt = new Date().toISOString();
		const duration = performance.now() - start;
		return {
			scan_id: scanId,
			engine: "threats",
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
