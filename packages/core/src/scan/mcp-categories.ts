/**
 * AIDR Scan — MCP risk categories.
 *
 * The 14 AIDR Scan MCP risk categories classify MCP server/tool calls by
 * the type and severity of risk they pose. Each category maps to an
 * AIDR policy action so the enforcement pipeline can block, ask, allow,
 * or audit accordingly.
 *
 * Categories are loaded from the generated JSON index at
 *   packages/core/src/generated/scan-mcp-categories.json
 * with a static fallback embedded here for offline/resilient operation.
 *
 * Migrated and rebranded from the previous AIG mcp-aig-categories.ts.
 *
 * Closed-source: part of the AIDR Scan engine.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// ── Types ───────────────────────────────────────────────────────────────────

export type RiskLevel = "critical" | "high" | "medium" | "low";
export type PolicyAction = "deny" | "ask" | "allow" | "audit";

export interface McpCategory {
	/** Unique category identifier, e.g. "aidr-mcp-code-exec" */
	id: string;
	/** Human-readable name */
	name: string;
	/** Short description of what this category covers */
	description: string;
	/** Inherent risk level */
	risk: RiskLevel;
	/** Keyword/regex patterns that trigger this category during classification */
	detection_patterns: string[];
	/** Default AIDR policy action when this category matches */
	aidr_policy_action: PolicyAction;
}

// ── Static fallback index ──────────────────────────────────────────────────
// These are the 14 canonical AIDR Scan MCP risk categories. They serve as the
// offline/resilient fallback when the generated JSON index is unavailable.

const FALLBACK_CATEGORIES: McpCategory[] = [
	{
		id: "aidr-mcp-code-exec",
		name: "Remote Code Execution",
		description:
			"MCP tool that can execute arbitrary code or shell commands on the host. This is the highest-risk category as it enables full remote code execution.",
		risk: "critical",
		detection_patterns: [
			"execute",
			"run_command",
			"shell_exec",
			"exec",
			"system",
			"popen",
			"subprocess",
			"bash",
			"sh_exec",
		],
		aidr_policy_action: "deny",
	},
	{
		id: "aidr-mcp-shell-access",
		name: "Shell / Terminal Access",
		description:
			"MCP tool that provides direct interactive shell or terminal access. Allows arbitrary command execution with full environment access.",
		risk: "critical",
		detection_patterns: ["terminal", "shell", "console", "command_line", "tty", "ssh_exec", "cmd"],
		aidr_policy_action: "deny",
	},
	{
		id: "aidr-mcp-file-write",
		name: "File System Write",
		description:
			"MCP tool that can create, modify, or delete files on the host file system. Risk depends on write scope — system paths are critical, project-local paths are lower.",
		risk: "high",
		detection_patterns: [
			"write_file",
			"create_file",
			"delete_file",
			"remove_file",
			"rename_file",
			"move_file",
			"copy_file",
			"mkdir",
			"rmdir",
			"file_write",
			"save_file",
		],
		aidr_policy_action: "ask",
	},
	{
		id: "aidr-mcp-file-read",
		name: "File System Read",
		description:
			"MCP tool that can read file contents from the host file system. May expose sensitive data such as credentials, keys, or proprietary code.",
		risk: "medium",
		detection_patterns: [
			"read_file",
			"file_read",
			"get_file",
			"load_file",
			"open_file",
			"readdir",
			"list_files",
			"glob",
			"find_file",
		],
		aidr_policy_action: "audit",
	},
	{
		id: "aidr-mcp-network-egress",
		name: "Network Egress / Internet Access",
		description:
			"MCP tool that makes outbound network requests. Can exfiltrate data, call remote APIs, or communicate with C2 infrastructure.",
		risk: "high",
		detection_patterns: [
			"http",
			"fetch",
			"request",
			"curl",
			"wget",
			"webhook",
			"api_call",
			"post_message",
			"send_data",
			"websocket",
			"web_request",
		],
		aidr_policy_action: "ask",
	},
	{
		id: "aidr-mcp-data-exfil",
		name: "Data Exfiltration",
		description:
			"MCP tool specifically designed to extract, copy, or transmit data outside the environment. Distinct from general network egress in intent.",
		risk: "critical",
		detection_patterns: [
			"exfiltrate",
			"upload",
			"export_data",
			"extract_data",
			"share_file",
			"send_file",
			"push_to_remote",
			"sync_data",
			"backup_upload",
		],
		aidr_policy_action: "deny",
	},
	{
		id: "aidr-mcp-auth-bypass",
		name: "Authentication / Authorization Bypass",
		description:
			"MCP tool that can bypass authentication checks, escalate privileges, or impersonate users.",
		risk: "critical",
		detection_patterns: [
			"impersonate",
			"sudo",
			"su_exec",
			"auth_bypass",
			"privilege_escalation",
			"token_generate",
			"session_steal",
			"run_as",
		],
		aidr_policy_action: "deny",
	},
	{
		id: "aidr-mcp-credential-access",
		name: "Credential / Secret Access",
		description:
			"MCP tool that can read environment variables, secrets stores, keychains, or credential files.",
		risk: "high",
		detection_patterns: [
			"get_secret",
			"read_env",
			"get_env",
			"credential",
			"keychain",
			"vault_read",
			"token_access",
			"password",
			"api_key",
			"secret_get",
		],
		aidr_policy_action: "deny",
	},
	{
		id: "aidr-mcp-privilege-escalation",
		name: "Privilege Escalation",
		description:
			"MCP tool that can escalate privileges beyond the initial scope, including container escape, namespace break, or user impersonation.",
		risk: "critical",
		detection_patterns: [
			"container_exec",
			"namespace_enter",
			"pod_exec",
			"k8s_exec",
			"docker_exec",
			"escalate",
			"become_user",
			"chown",
			"chmod",
		],
		aidr_policy_action: "deny",
	},
	{
		id: "aidr-mcp-persistence",
		name: "Persistence / Installation",
		description:
			"MCP tool that can install packages, services, daemons, or otherwise persist changes across restarts.",
		risk: "high",
		detection_patterns: [
			"install",
			"apt_install",
			"npm_install",
			"pip_install",
			"create_service",
			"cron_install",
			"startup_add",
			"daemonize",
			"register_service",
		],
		aidr_policy_action: "ask",
	},
	{
		id: "aidr-mcp-resource-exhaustion",
		name: "Resource Exhaustion / DoS",
		description:
			"MCP tool that can consume excessive CPU, memory, disk, or network resources, potentially causing denial of service.",
		risk: "low",
		detection_patterns: [
			"fork_bomb",
			"spawn_process",
			"large_write",
			"disk_fill",
			"memory_alloc",
			"infinite_loop",
			"stress_test",
		],
		aidr_policy_action: "audit",
	},
	{
		id: "aidr-mcp-info-disclosure",
		name: "Information Disclosure",
		description:
			"MCP tool that can enumerate system information, configuration, or metadata that may aid further attacks.",
		risk: "medium",
		detection_patterns: [
			"sys_info",
			"uname",
			"hostname",
			"whoami",
			"list_process",
			"ps_aux",
			"network_scan",
			"port_scan",
			"env_list",
			"config_get",
		],
		aidr_policy_action: "audit",
	},
	{
		id: "aidr-mcp-config-manipulation",
		name: "Configuration Manipulation",
		description:
			"MCP tool that can modify system, application, or security configuration. May weaken security posture or alter runtime behavior.",
		risk: "high",
		detection_patterns: [
			"config_write",
			"set_config",
			"update_config",
			"modify_settings",
			"change_policy",
			"disable_security",
			"toggle_feature",
			"set_env",
			"export_var",
		],
		aidr_policy_action: "ask",
	},
	{
		id: "aidr-mcp-supply-chain",
		name: "Supply Chain / Package Risk",
		description:
			"MCP tool that can install or modify packages from registries (npm, PyPI, etc.), potentially introducing malicious dependencies.",
		risk: "high",
		detection_patterns: [
			"npm_install",
			"pip_install",
			"gem_install",
			"cargo_install",
			"go_get",
			"add_dependency",
			"install_package",
			"package_add",
			"nuget_install",
		],
		aidr_policy_action: "ask",
	},
];

// ── In-memory cache ─────────────────────────────────────────────────────────

let _categories: McpCategory[] | null = null;

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Determine the project root directory relative to this source file.
 * Used to locate the generated scan-mcp-categories.json at build time.
 */
function findProjectRoot(): string {
	const dir = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
	return dir;
}

/**
 * Attempt to load the compiled AIDR Scan MCP categories JSON index.
 * Falls back to the static array if the file is missing or unparseable.
 */
function loadCategoriesJson(): McpCategory[] {
	const candidates = [
		// Development path: from src/ to generated/
		join(findProjectRoot(), "src", "generated", "scan-mcp-categories.json"),
		// Build output path: from dist/ to generated/ (relative to compiled output)
		join(findProjectRoot(), "dist", "generated", "scan-mcp-categories.json"),
	];

	for (const candidatePath of candidates) {
		try {
			if (existsSync(candidatePath)) {
				const raw = readFileSync(candidatePath, "utf-8");
				const parsed = JSON.parse(raw) as {
					version?: number;
					categories?: McpCategory[];
				};
				if (Array.isArray(parsed?.categories) && parsed.categories.length > 0) {
					return parsed.categories as McpCategory[];
				}
			}
		} catch {
			// Try next candidate
		}
	}

	return FALLBACK_CATEGORIES;
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Load AIDR Scan MCP categories from the generated JSON index (if available),
 * falling back to the embedded static set.
 */
export function loadScanMcpCategories(): McpCategory[] {
	if (_categories !== null) return _categories;
	_categories = loadCategoriesJson();
	return _categories;
}

/**
 * Given an MCP tool name and its properties, determine which AIDR Scan risk
 * categories match based on detection patterns.
 *
 * Tool names follow the convention `mcp__<serverName>__<toolName>` or
 * simply `<toolName>`. Both the server name and tool name are checked
 * against detection patterns.
 */
export function classifyMcpTool(
	toolName: string,
	toolDescription: string,
	toolArgs: Record<string, unknown>,
): { matchedCategories: McpCategory[]; riskLevel: RiskLevel } {
	const categories = loadScanMcpCategories();
	const matched: McpCategory[] = [];

	// Parse the tool name to extract server name and tool name
	// Format: "mcp__serverName__toolName" or just "toolName"
	const parts = toolName.split("__");
	const serverName = parts.length >= 3 && parts[1] ? parts[1].toLowerCase() : "";
	const rawToolName = parts.length >= 3 ? parts.slice(2).join("__") : toolName;
	const toolNameLower = rawToolName.toLowerCase();

	// Build a combined search text from all available inputs
	const combinedSearchText = [
		serverName,
		toolNameLower,
		toolDescription.toLowerCase(),
		...Object.keys(toolArgs).map((k) => k.toLowerCase()),
	].join(" ");

	for (const category of categories) {
		const isMatch = category.detection_patterns.some((pattern) => {
			const patternLower = pattern.toLowerCase();
			if (combinedSearchText.includes(patternLower)) return true;

			const toolNameRegex = new RegExp(
				`(?:^|_|\\s|[.-])${escapeRegex(patternLower)}(?:_|\\s|[.-]|$)`,
				"i",
			);
			if (toolNameRegex.test(toolNameLower)) return true;

			return false;
		});

		if (isMatch) {
			matched.push(category);
		}
	}

	let riskLevel: RiskLevel = "low";
	const riskOrder: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };
	for (const cat of matched) {
		if ((riskOrder[cat.risk] ?? 0) > (riskOrder[riskLevel] ?? 0)) {
			riskLevel = cat.risk;
		}
	}

	return { matchedCategories: matched, riskLevel };
}

/**
 * Map an AIDR Scan risk level to the corresponding AIDR policy action.
 */
export function scanRiskToPolicyAction(risk: RiskLevel): PolicyAction {
	switch (risk) {
		case "critical":
			return "deny";
		case "high":
			return "ask";
		case "medium":
			return "audit";
		case "low":
			return "allow";
	}
}

/**
 * Get all available AIDR Scan MCP categories (loaded or fallback).
 */
export function getAllCategories(): McpCategory[] {
	return loadScanMcpCategories();
}

/**
 * Reset the cached categories (e.g., after a JSON file update).
 */
export function resetCategoryCache(): void {
	_categories = null;
}

// ── Internal helpers ────────────────────────────────────────────────────────

function escapeRegex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
