/**
 * AIDR Scan — Agent workflow security scanner.
 *
 * Analyzes AI agent configurations (Dify, Coze, custom HTTP, etc.) for
 * security risks: prompt injection, privilege escalation, data leakage,
 * tool abuse, and other agent-specific vulnerabilities.
 *
 * Migrated and rebranded from the previous AIG bridge `scan/agent` endpoint.
 * Native in-process TS — no HTTP round-trip, no Go sidecar, sub-50ms cold.
 *
 * Closed-source: part of the AIDR Scan engine.
 */

import { randomUUID } from "node:crypto";
import type { AgentTarget, Finding, ScanResult, ScanSummary, Severity } from "./types.js";
import { emptySummary, summarizeFindings } from "./mcp.js";

export interface AgentScanData {
	risk_score: number;
	scanned_config_keys: number;
	scanned_prompt_length: number;
	language: string;
	summary: string;
}

const PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; category: string; severity: Severity }> = [
	{ pattern: /ignore\s+(all|any|your)\s+(previous|prior|above)\s+instructions?/i, category: "prompt_injection", severity: "critical" },
	{ pattern: /you\s+are\s+now\s+(in\s+)?(developer|admin|root|dan|jailbreak)\s+mode/i, category: "jailbreak", severity: "critical" },
	{ pattern: /pretend\s+(you\s+are|to\s+be)\s+/i, category: "jailbreak", severity: "high" },
	{ pattern: /forget\s+(everything|all|your\s+rules?)/i, category: "memory_poisoning", severity: "critical" },
	{ pattern: /disregard\s+(all|any|the)\s+(rules?|guidelines?|safety)/i, category: "prompt_injection", severity: "critical" },
];

const PRIV_ESCALATION_PATTERNS: Array<{ pattern: RegExp; category: string; severity: Severity }> = [
	{ pattern: /sudo|su\s+-c|runas/i, category: "privilege_escalation", severity: "critical" },
	{ pattern: /chmod\s+\+s|chown\s+root/i, category: "privilege_escalation", severity: "critical" },
	{ pattern: /setuid|setgid/i, category: "privilege_escalation", severity: "high" },
	{ pattern: /container_exec|docker_exec|kubectl\s+exec/i, category: "privilege_escalation", severity: "high" },
];

const DATA_LEAK_PATTERNS: Array<{ pattern: RegExp; category: string; severity: Severity }> = [
	{ pattern: /api[_-]?key\s*[:=]\s*[\w-]{16,}/i, category: "credential_leak", severity: "high" },
	{ pattern: /secret[_-]?key\s*[:=]\s*[\w-]{16,}/i, category: "credential_leak", severity: "high" },
	{ pattern: /bearer\s+[\w-]{20,}/i, category: "credential_leak", severity: "high" },
	{ pattern: /sk-[a-zA-Z0-9]{20,}/i, category: "credential_leak", severity: "high" },
	{ pattern: /AKIA[0-9A-Z]{16}/i, category: "credential_leak", severity: "high" },
];

const TOOL_ABUSE_PATTERNS: Array<{ pattern: RegExp; category: string; severity: Severity }> = [
	{ pattern: /delete\s+(all|every|the)\s+(files?|records?|data)/i, category: "data_destruction", severity: "critical" },
	{ pattern: /format\s+(disk|drive|partition)/i, category: "data_destruction", severity: "critical" },
	{ pattern: /rm\s+-rf\s+\//, category: "data_destruction", severity: "critical" },
	{ pattern: /drop\s+(database|table|schema)/i, category: "data_destruction", severity: "critical" },
];

const ALL_PATTERNS = [
	...PROMPT_INJECTION_PATTERNS,
	...PRIV_ESCALATION_PATTERNS,
	...DATA_LEAK_PATTERNS,
	...TOOL_ABUSE_PATTERNS,
];

/**
 * Run the agent workflow security scan.
 */
export async function runAgentScan(target: AgentTarget): Promise<ScanResult<AgentScanData>> {
	const start = performance.now();
	const scanId = `aidr-scan-agent-${randomUUID()}`;
	const startedAt = new Date().toISOString();

	try {
		const configYaml = target.config ?? "";
		const prompt = target.prompt ?? "";
		const haystack = `${configYaml}\n${prompt}`;
		const language = target.language ?? "en";

		const findings: Finding[] = [];
		const matchedKeys = new Set<string>();

		for (const { pattern, category, severity } of ALL_PATTERNS) {
			const match = haystack.match(pattern);
			if (match) {
				const matchedText = match[0];
				findings.push({
					id: `aidr-agent-${category}-${findings.length + 1}`,
					engine: "agent",
					category,
					severity,
					confidence: 0.85,
					action: severity === "critical" ? "deny" : severity === "high" ? "ask" : "audit",
					title: `Agent config risk: ${category.replace(/_/g, " ")}`,
					description: `Detected "${matchedText}" matching pattern for ${category.replace(/_/g, " ")}.`,
					target: target.agentId ?? "inline-config",
					metadata: {
						pattern: pattern.source,
						matched_text: matchedText,
						language,
					},
					remediation: `Review the agent ${target.agentId ? `(${target.agentId})` : "config"} for ${category.replace(/_/g, " ")} and remove or restrict.`,
				});
				matchedKeys.add(category);
			}
		}

		const riskScore = computeAgentRiskScore(findings);
		const summary = summarizeAgent(findings, riskScore, language);

		const finishedAt = new Date().toISOString();
		const duration = performance.now() - start;

		return {
			scan_id: scanId,
			engine: "agent",
			status: "completed",
			started_at: startedAt,
			finished_at: finishedAt,
			duration_ms: Math.round(duration),
			findings,
			summary: summarizeFindings(findings),
			data: {
				risk_score: riskScore,
				scanned_config_keys: configYaml.split("\n").filter((l) => l.trim()).length,
				scanned_prompt_length: prompt.length,
				language,
				summary,
			},
		};
	} catch (err) {
		const finishedAt = new Date().toISOString();
		const duration = performance.now() - start;
		return {
			scan_id: scanId,
			engine: "agent",
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

function computeAgentRiskScore(findings: Finding[]): number {
	const weights: Record<Severity, number> = {
		critical: 25,
		high: 12,
		medium: 5,
		low: 2,
		info: 0,
	};
	let total = 0;
	for (const f of findings) {
		total += weights[f.severity];
	}
	return Math.min(100, total);
}

function summarizeAgent(findings: Finding[], score: number, language: string): string {
	if (findings.length === 0) {
		return `Agent scan (${language}) complete. No risks detected. Risk score: ${score}/100.`;
	}
	const cats = [...new Set(findings.map((f) => f.category))];
	return `Agent scan (${language}) complete. ${findings.length} finding(s) across ${cats.length} categor(ies): ${cats.join(", ")}. Risk score: ${score}/100.`;
}
