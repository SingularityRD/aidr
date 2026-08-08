/**
 * AIG MCP Risk Categories
 *
 * The 14 AIG MCP risk categories classify MCP server/tool calls by the type
 * and severity of risk they pose. Each category maps to an AIDR policy action
 * so the enforcement pipeline can block, ask, allow, or audit accordingly.
 *
 * Categories are loaded from the generated JSON index at
 *   packages/core/src/generated/aig-mcp-categories.json
 * with a static fallback embedded here for offline/resilient operation.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// ── Types ───────────────────────────────────────────────────────────────────

export type AigRiskLevel = "critical" | "high" | "medium" | "low";
export type AigPolicyAction = "deny" | "ask" | "allow" | "audit" | "restrict" | "monitor";

export interface AigMcpDataStatus {
	source: "generated" | "fallback";
	valid: boolean;
	schema?: string;
	version?: number;
	error?: string;
}

export interface AigMcpCategory {
	/** Unique category identifier, e.g. "aig-mcp-code-exec" */
	id: string;
	/** Human-readable name */
	name: string;
	/** Short description of what this category covers */
	description: string;
	/** Inherent risk level */
	risk: AigRiskLevel;
	/** Keyword/regex patterns that trigger this category during classification */
	detection_patterns: string[];
	/** Default AIDR policy action when this category matches */
	aidr_policy_action: AigPolicyAction;
}

// ── Static fallback index ──────────────────────────────────────────────────
// These are the 14 canonical AIG MCP risk categories. They serve as the
// offline/resilient fallback when the generated JSON index is unavailable.

const _FALLBACK_CATEGORIES: AigMcpCategory[] = [
	{
		id: "aig-mcp-code-exec",
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
		id: "aig-mcp-shell-access",
		name: "Shell / Terminal Access",
		description:
			"MCP tool that provides direct interactive shell or terminal access. Allows arbitrary command execution with full environment access.",
		risk: "critical",
		detection_patterns: ["terminal", "shell", "console", "command_line", "tty", "ssh_exec", "cmd"],
		aidr_policy_action: "deny",
	},
	{
		id: "aig-mcp-file-write",
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
		id: "aig-mcp-file-read",
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
		id: "aig-mcp-network-egress",
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
		id: "aig-mcp-data-exfil",
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
		id: "aig-mcp-auth-bypass",
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
		id: "aig-mcp-credential-access",
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
		id: "aig-mcp-privilege-escalation",
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
		id: "aig-mcp-persistence",
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
		id: "aig-mcp-resource-exhaustion",
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
		id: "aig-mcp-info-disclosure",
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
		id: "aig-mcp-config-manipulation",
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
		id: "aig-mcp-supply-chain",
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

const CANONICAL_FALLBACK_CATEGORIES: AigMcpCategory[] = [
	{ id: "mcp-01", name: "Token Mismanagement & Secret Exposure", description: "Hardcoded keys, env var leaks, and sensitive credential theft from MCP configuration.", risk: "critical", detection_patterns: ["api_key", "secret", "token", "password", ".env", "mcp.json"], aidr_policy_action: "deny" },
	{ id: "mcp-02", name: "Privilege Escalation via Scope Creep", description: "Overly broad tool permissions allow unnecessary system control or data access.", risk: "high", detection_patterns: ["full_access", "admin", "wildcard", "root", "sudo"], aidr_policy_action: "restrict" },
	{ id: "mcp-03", name: "Tool Poisoning", description: "Tool logic is tampered with to manipulate model behavior or returned results.", risk: "critical", detection_patterns: ["override", "inject", "malicious", "backdoor", "trojan"], aidr_policy_action: "deny" },
	{ id: "mcp-04", name: "Software Supply Chain Attacks", description: "Dependency or build-script tampering introduces malicious behavior.", risk: "critical", detection_patterns: ["postinstall", "preinstall", "download", "curl", "wget", "npm install"], aidr_policy_action: "deny" },
	{ id: "mcp-05", name: "Command Injection & Execution", description: "Untrusted input reaches shell, process, or evaluator execution.", risk: "critical", detection_patterns: ["exec", "spawn", "shell", "eval", "subprocess", "child_process"], aidr_policy_action: "deny" },
	{ id: "mcp-06", name: "Prompt Injection via Contextual Payloads", description: "Injected instructions hijack model control flow.", risk: "high", detection_patterns: ["ignore instructions", "system prompt", "you are now", "do not"], aidr_policy_action: "monitor" },
	{ id: "mcp-07", name: "Insufficient Auth & Authorization", description: "Missing identity or authorization checks permit cross-agent access.", risk: "high", detection_patterns: ["no_auth", "skip_auth", "public", "unauthorized", "bypass"], aidr_policy_action: "deny" },
	{ id: "mcp-08", name: "Lack of Audit and Telemetry", description: "Missing tamper-evident audit and telemetry hinders forensics.", risk: "medium", detection_patterns: ["no_log", "disable_logging", "quiet", "silent"], aidr_policy_action: "monitor" },
	{ id: "mcp-09", name: "Shadow MCP Servers", description: "Unauthorized MCP instances run with insecure defaults.", risk: "high", detection_patterns: ["default_config", "unsecured", "shadow", "unauthorized"], aidr_policy_action: "deny" },
	{ id: "mcp-10", name: "Context Injection & Over-Sharing", description: "Sensitive context crosses sessions or agents.", risk: "high", detection_patterns: ["shared_context", "global_state", "cross_session", "broadcast"], aidr_policy_action: "restrict" },
	{ id: "mcp-11", name: "Name Confusion Attack", description: "Lookalike tools trick agents into invoking the wrong capability.", risk: "high", detection_patterns: ["typosquat", "lookalike", "similar_name", "confusion"], aidr_policy_action: "deny" },
	{ id: "mcp-12", name: "Rug Pull Attack", description: "A trusted service changes behavior or terminates unexpectedly.", risk: "high", detection_patterns: ["rate_limit", "kill", "shutdown", "terminate", "revoke"], aidr_policy_action: "deny" },
	{ id: "mcp-13", name: "Tool Shadowing Attack", description: "Duplicate tool names override legitimate behavior.", risk: "high", detection_patterns: ["override", "redefine", "shadow", "duplicate"], aidr_policy_action: "deny" },
	{ id: "mcp-14", name: "CORS Misconfiguration", description: "Wildcard cross-origin policy permits unauthorized access.", risk: "medium", detection_patterns: ["Access-Control-Allow-Origin: *", "credentials: true", "wildcard_origin"], aidr_policy_action: "restrict" },
];

let _categories: AigMcpCategory[] | null = null;
let _categoryStatus: AigMcpDataStatus | null = null;

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Determine the project root directory relative to this source file.
 * Used to locate the generated aig-mcp-categories.json at build time.
 */
function findProjectRoot(): string {
	let moduleDir = process.cwd();
	try {
		if (typeof import.meta.dirname === "string") {
			moduleDir = import.meta.dirname;
		} else if (typeof import.meta.url === "string") {
			moduleDir = dirname(fileURLToPath(import.meta.url));
		}
	} catch {
		// CommonJS bundles replace import.meta with an empty object.
	}
	return moduleDir;
}

/**
 * Attempt to load the compiled AIG MCP categories JSON index.
 * Falls back to the static array if the file is missing or unparseable.
 */
function isCategory(value: unknown): value is AigMcpCategory {
	if (!value || typeof value !== "object") return false;
	const item = value as Record<string, unknown>;
	return typeof item.id === "string" && typeof item.name === "string" &&
		typeof item.description === "string" &&
		["critical", "high", "medium", "low"].includes(String(item.risk)) &&
		Array.isArray(item.detection_patterns) && item.detection_patterns.every((pattern) => typeof pattern === "string") &&
		["deny", "ask", "allow", "audit", "restrict", "monitor"].includes(String(item.aidr_policy_action));
}

function loadCategoriesJson(): AigMcpCategory[] {
	const moduleDir = findProjectRoot();
	const candidates = [
		join(moduleDir, "generated", "aig-mcp-categories.json"),
		join(moduleDir, "..", "generated", "aig-mcp-categories.json"),
		join(moduleDir, "..", "src", "generated", "aig-mcp-categories.json"),
		...(process.env.AIG_GENERATED_DIR ? [join(process.env.AIG_GENERATED_DIR, "aig-mcp-categories.json")] : []),
	];

	for (const candidatePath of candidates) {
		try {
			if (!existsSync(candidatePath)) continue;
			const parsed = JSON.parse(readFileSync(candidatePath, "utf-8")) as { schema?: string; version?: number; categories?: unknown[] };
			if (parsed.schema === "aig-mcp-categories/v2" && parsed.version === 2 &&
				Array.isArray(parsed.categories) && parsed.categories.length > 0 && parsed.categories.every(isCategory)) {
				_categoryStatus = { source: "generated", valid: true, schema: parsed.schema, version: parsed.version };
				return parsed.categories;
			}
		} catch {
			// Try next candidate
		}
	}

	_categoryStatus = { source: "fallback", valid: false, error: "signed/generated MCP category index is missing or invalid" };
	return CANONICAL_FALLBACK_CATEGORIES;
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Load AIG MCP categories from the generated JSON index (if available),
 * falling back to the embedded static set.
 */
export function loadAigMcpCategories(): AigMcpCategory[] {
	if (_categories !== null) return _categories;
	_categories = loadCategoriesJson();
	return _categories;
}

/** Report whether the generated v2 category bundle was loaded. */
export function getAigMcpDataStatus(): AigMcpDataStatus {
	if (_categoryStatus === null) loadAigMcpCategories();
	return { ...(_categoryStatus as AigMcpDataStatus) };
}

export function isAigMcpDataReady(): boolean {
	return getAigMcpDataStatus().valid;
}

/**
 * Given an MCP tool name and its properties, determine which AIG risk
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
): { matchedCategories: AigMcpCategory[]; riskLevel: AigRiskLevel } {
	const categories = loadAigMcpCategories();
	const matched: AigMcpCategory[] = [];

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

	let riskLevel: AigRiskLevel = "low";
	const riskOrder: Record<AigRiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };
	for (const cat of matched) {
		if ((riskOrder[cat.risk] ?? 0) > (riskOrder[riskLevel] ?? 0)) {
			riskLevel = cat.risk;
		}
	}

	return { matchedCategories: matched, riskLevel };
}

/**
 * Map an AIG risk level to the corresponding AIDR policy action.
 */
export function aigRiskToPolicyAction(risk: AigRiskLevel): AigPolicyAction {
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
 * Get all available AIG MCP categories (loaded or fallback).
 */
export function getAllCategories(): AigMcpCategory[] {
	return loadAigMcpCategories();
}

/**
 * Reset the cached categories (e.g., after a JSON file update).
 */
export function resetCategoryCache(): void {
	_categories = null;
	_categoryStatus = null;
}

// ── Internal helpers ────────────────────────────────────────────────────────

function escapeRegex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
