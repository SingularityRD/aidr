/**
 * AIDR Scan — shared types for the AIDR Scan engine.
 *
 * The engine is the orchestrator for 4 deep-scan capabilities:
 *   - CVE: semver-based vulnerability lookup against the compiled CVE index
 *   - MCP: 14-category MCP server/tool call risk scoring
 *   - Agent: AI agent workflow security analysis
 *   - Jailbreak: LLM red-team evaluation
 *
 * It also integrates with the existing threats/*.yaml rules via scan/threats.ts.
 *
 * Closed-source: this code is part of the AIDR Scan proprietary engine.
 * No source distribution. SBOM published per release.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type PolicyAction = "deny" | "ask" | "audit" | "allow";

export type ScanType = "cve" | "mcp" | "agent" | "jailbreak" | "threats";

/** A single finding produced by any scan engine. */
export interface Finding {
	/** Stable identifier (CVE-2024-XXXX, AIDR-MCP-code-exec, AIDR-LLM-INJ-001, etc.) */
	id: string;
	/** Engine that produced this finding */
	engine: ScanType | "cve" | "mcp" | "agent" | "jailbreak" | "threats";
	/** Category classification (e.g. "prompt_injection", "remote_code_execution", "data_exfiltration") */
	category: string;
	/** Severity level */
	severity: Severity;
	/** Confidence score 0-1 */
	confidence: number;
	/** Recommended policy action */
	action: PolicyAction;
	/** Short, human-readable title */
	title: string;
	/** Optional longer description */
	description?: string;
	/** Where the finding was detected (e.g. "package:lodash@4.17.20", "tool:mcp__fs__read_file") */
	target?: string;
	/** Additional structured data (CVE fields, MCP category, etc.) */
	metadata?: Record<string, unknown>;
	/** Remediation guidance, if available */
	remediation?: string;
}

export interface ScanSummary {
	total: number;
	critical: number;
	high: number;
	medium: number;
	low: number;
	info: number;
}

export interface ScanResult<T = unknown> {
	scan_id: string;
	engine: ScanType;
	status: "completed" | "failed";
	started_at: string;
	finished_at: string;
	duration_ms: number;
	findings: Finding[];
	summary: ScanSummary;
	/** Engine-specific data (e.g. CVE risk score, MCP category breakdown) */
	data?: T;
	error?: string;
}

export interface CveTarget {
	package: string;
	version: string;
	ecosystem: "npm" | "pypi" | "go" | "maven" | "rubygems" | "cargo" | string;
	framework?: string;
}

export interface McpTarget {
	/** Remote MCP server URL (sse/streamable-http) or local source path */
	url?: string;
	source?: string;
	/** MCP tool calls to scan (server name, tool name, args, description) */
	tools?: Array<{
		serverName: string;
		toolName: string;
		description?: string;
		args?: Record<string, unknown>;
	}>;
	/** Optional eval model for dynamic analysis */
	evalModel?: {
		model: string;
		baseUrl: string;
		token: string;
	};
	/** Risk categories to focus on (default: all 14) */
	categories?: string[];
}

export interface AgentTarget {
	/** YAML agent config or pre-saved agent_id */
	config?: string;
	agentId?: string;
	/** Free-form prompt for context */
	prompt?: string;
	language?: "en" | "zh";
}

export interface JailbreakTarget {
	/** LLM endpoint URL */
	endpoint: string;
	/** Model name */
	model: string;
	/** API token */
	token: string;
	/** Test suites to run */
	testSuites: string[];
	language?: "en" | "zh";
}

export interface ThreatsTarget {
	/** Content to scan (prompt, tool call, command, file path, etc.) */
	content: string;
	/** Type of content — controls which rule categories are applied */
	matchOn: "content" | "command" | "file_path" | "url";
}

export type ScanRequest =
	| { type: "cve"; target: CveTarget }
	| { type: "mcp"; target: McpTarget }
	| { type: "agent"; target: AgentTarget }
	| { type: "jailbreak"; target: JailbreakTarget }
	| { type: "threats"; target: ThreatsTarget };
