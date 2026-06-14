#!/usr/bin/env node
/**
 * AIDR Scan — Build-time index compiler.
 *
 * Compiles YAML data sources into compact JSON indexes for the AIDR Scan
 * engine. Runs at build time; the resulting JSON is loaded at runtime.
 *
 * Sources:
 *   data/scan/vuln_en/...       → scan-cve-index.json     (~150 KB)
 *   data/scan/vuln/...          → scan-cve-index.json     (merged)
 *   data/scan/fingerprints/...  → scan-fingerprints.json  (~10 KB)
 *   data/scan/mcp/...           → scan-mcp-categories.json (~4 KB)
 *   threats/...                 → scan-threats-index.json  (~80 KB)
 *
 * Outputs:
 *   packages/core/src/generated/scan-*.json
 *   packages/core/dist/generated/scan-*.json
 *
 * Uses the `yaml` npm package for robust parsing of the heterogeneous
 * AIG schema. Closed-source tooling. Part of the AIDR Scan build pipeline.
 */

import {
	existsSync,
	readFileSync,
	writeFileSync,
	mkdirSync,
	readdirSync,
	statSync,
} from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = join(__dirname, "..");
const AIG = join(ROOT, "data", "scan");
const THREATS = join(ROOT, "threats");
const OUT = join(ROOT, "packages", "core", "src", "generated");
const DIST = join(ROOT, "packages", "core", "dist", "generated");

// yaml is a pnpm-workspace dep; resolve from the script directory
const require = createRequire(import.meta.url);
let parseYaml;
try {
	({ parse: parseYaml } = require("yaml"));
} catch {
	// Fallback: relative path resolution for pnpm
	const yamlPath = join(
		ROOT,
		"node_modules",
		".pnpm",
		"yaml@2.8.3",
		"node_modules",
		"yaml",
	);
	({ parse: parseYaml } = require(yamlPath));
}

// ─── File walking ────────────────────────────────────────────────────────

function walkYaml(dir) {
	if (!existsSync(dir)) return [];
	const results = [];
	const entries = readdirSync(dir);
	for (const entry of entries) {
		const full = join(dir, entry);
		const stat = statSync(full);
		if (stat.isDirectory()) {
			results.push(...walkYaml(full));
		} else if (entry.endsWith(".yaml") || entry.endsWith(".yml")) {
			results.push(full);
		}
	}
	return results;
}

function loadYaml(path) {
	try {
		const text = readFileSync(path, "utf-8");
		return parseYaml(text) ?? null;
	} catch (err) {
		console.warn(`[build-scan-index] skip ${path}: ${err.message}`);
		return null;
	}
}

// ─── CVE index builder ──────────────────────────────────────────────────

function buildCveIndex() {
	console.log("[build-scan-index] Compiling CVE index...");
	const cves = [];
	const frameworks = {};
	const ecosystems = {};

	const vulnDirs = [join(AIG, "vuln_en"), join(AIG, "vuln")];
	for (const dir of vulnDirs) {
		const files = walkYaml(dir);
		for (const file of files) {
			const data = loadYaml(file);
			if (!data?.info) continue;
			const info = data.info;
			const relPath = relative(dir, file);
			const pathParts = relPath.split(/[/\\]/);
			const packageName = pathParts[0] || info.name || "unknown";
			const ecosystem = inferEcosystem(packageName, info);

			const cveId =
				(info.cve && String(info.cve).trim()) ||
				`AIDR-${packageName.toUpperCase().replace(/[^A-Z0-9]/g, "-")}`;

			const severity = normalizeSeverity(info.severity);
			const semverRange = "*"; // AIG YAMLs don't carry explicit ranges

			cves.push({
				id: cveId,
				p: packageName,
				e: ecosystem,
				s: severity,
				r: semverRange,
				f: info.framework || undefined,
				c: info.cvss ? Number(info.cvss) : undefined,
			});

			const ecoKey = ecosystem.toLowerCase();
			ecosystems[ecoKey] = ecosystems[ecoKey] || [];
			if (!ecosystems[ecoKey].includes(cveId)) ecosystems[ecoKey].push(cveId);

			if (info.framework) {
				frameworks[info.framework] = frameworks[info.framework] || [];
				if (!frameworks[info.framework].includes(cveId)) {
					frameworks[info.framework].push(cveId);
				}
			}
		}
	}

	// Dedupe
	const seen = new Set();
	const deduped = cves.filter((c) => {
		const key = `${c.id}:${c.p}:${c.e}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});

	const index = {
		version: 1,
		generated: new Date().toISOString(),
		cves: deduped,
		frameworks,
		ecosystems,
	};

	const outPath = join(OUT, "scan-cve-index.json");
	writeFileSync(outPath, JSON.stringify(index));
	const distPath = join(DIST, "scan-cve-index.json");
	if (!existsSync(DIST)) mkdirSync(DIST, { recursive: true });
	writeFileSync(distPath, JSON.stringify(index));
	console.log(
		`[build-scan-index] CVE index: ${deduped.length} entries (${(JSON.stringify(index).length / 1024).toFixed(1)} KB) → ${outPath}`,
	);
	return deduped.length;
}

function inferEcosystem(packageName, info) {
	const lower = String(packageName).toLowerCase();
	if (
		lower.includes("pip") ||
		lower.includes("python") ||
		lower.includes("langchain") ||
		lower.includes("llamaindex") ||
		lower.includes("transformers") ||
		lower.includes("pytorch")
	)
		return "pypi";
	if (lower.includes("go-") || lower.includes("k8s") || lower.includes("triton"))
		return "go";
	if (lower.includes("maven") || lower.includes("java"))
		return "maven";
	return "npm"; // default
}

function normalizeSeverity(s) {
	const v = String(s ?? "").toLowerCase().trim();
	if (v === "critical" || v === "high" || v === "medium" || v === "low") return v;
	return "medium";
}

// ─── MCP categories index builder ───────────────────────────────────────

function buildMcpCategoriesIndex() {
	console.log("[build-scan-index] Compiling MCP categories index...");

	// Use the 14 canonical categories from the AIDR Scan engine.
	// The MCP YAML files in data/scan/mcp/ are prompt templates for the
	// LLM-driven eval mode — they are loaded lazily by the SaaS worker.
	// The edge engine ships the static 14-category taxonomy directly.
	const categories = [
		{
			id: "aidr-mcp-code-exec",
			name: "Remote Code Execution",
			description: "MCP tool that can execute arbitrary code or shell commands on the host.",
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
			description: "MCP tool that provides direct interactive shell or terminal access.",
			risk: "critical",
			detection_patterns: ["terminal", "shell", "console", "command_line", "tty", "ssh_exec", "cmd"],
			aidr_policy_action: "deny",
		},
		{
			id: "aidr-mcp-file-write",
			name: "File System Write",
			description: "MCP tool that can create, modify, or delete files on the host file system.",
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
			description: "MCP tool that can read file contents from the host file system.",
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
			description: "MCP tool that makes outbound network requests.",
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
			description: "MCP tool specifically designed to extract, copy, or transmit data outside the environment.",
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
			description: "MCP tool that can bypass authentication checks, escalate privileges, or impersonate users.",
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
			description: "MCP tool that can read environment variables, secrets stores, keychains, or credential files.",
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
			description: "MCP tool that can escalate privileges beyond the initial scope.",
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
			description: "MCP tool that can install packages, services, daemons, or otherwise persist changes across restarts.",
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
			description: "MCP tool that can consume excessive CPU, memory, disk, or network resources.",
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
			description: "MCP tool that can enumerate system information, configuration, or metadata.",
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
			description: "MCP tool that can modify system, application, or security configuration.",
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
			description: "MCP tool that can install or modify packages from registries.",
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

	const index = { version: 1, categories };
	const outPath = join(OUT, "scan-mcp-categories.json");
	writeFileSync(outPath, JSON.stringify(index));
	const distPath = join(DIST, "scan-mcp-categories.json");
	if (!existsSync(DIST)) mkdirSync(DIST, { recursive: true });
	writeFileSync(distPath, JSON.stringify(index));
	console.log(
		`[build-scan-index] MCP categories: ${categories.length} (${(JSON.stringify(index).length / 1024).toFixed(1)} KB) → ${outPath}`,
	);
	return categories.length;
}

// ─── Threats index builder ─────────────────────────────────────────────

function buildThreatsIndex() {
	console.log("[build-scan-index] Compiling threats index...");
	const rules = [];

	const threatFiles = walkYaml(THREATS);
	for (const file of threatFiles) {
		const data = loadYaml(file);
		if (!data) continue;

		// Each threat YAML is a list of rule objects at the top level.
		// The minimal YAML parser produces a dict where the list lives
		// under the first key (often the section heading), so flatten all
		// nested arrays of objects that look like rules.
		const candidates = [];
		if (Array.isArray(data)) candidates.push(...data);
		else {
			for (const v of Object.values(data)) {
				if (Array.isArray(v)) candidates.push(...v);
			}
		}

		for (const rule of candidates) {
			if (!rule || typeof rule !== "object") continue;
			if (!rule.id) continue;
			rules.push({
				id: rule.id,
				category: rule.category || "uncategorized",
				severity: normalizeSeverity(rule.severity),
				confidence: typeof rule.confidence === "number" ? rule.confidence : 0.5,
				action: rule.action || "warn",
				pattern: rule.pattern || "",
				match_on: rule.match_on || "content",
				title: rule.title || rule.id,
				expires_at: rule.expires_at || null,
				revoked: rule.revoked === true,
			});
		}
	}

	const index = {
		version: 1,
		generated: new Date().toISOString(),
		rule_count: rules.length,
		rules,
	};
	const outPath = join(OUT, "scan-threats-index.json");
	writeFileSync(outPath, JSON.stringify(index));
	const distPath = join(DIST, "scan-threats-index.json");
	if (!existsSync(DIST)) mkdirSync(DIST, { recursive: true });
	writeFileSync(distPath, JSON.stringify(index));
	console.log(
		`[build-scan-index] Threats index: ${rules.length} rules (${(JSON.stringify(index).length / 1024).toFixed(1)} KB) → ${outPath}`,
	);
	return rules.length;
}

// ─── Fingerprints index builder (placeholder for SaaS) ──────────────────

function buildFingerprintsIndex() {
	console.log("[build-scan-index] Compiling fingerprints index...");
	const fingerprints = [];

	const fpDir = join(AIG, "fingerprints");
	const files = walkYaml(fpDir);
	for (const file of files) {
		const data = loadYaml(file);
		if (!data?.info) continue;
		fingerprints.push({
			name: data.info.name,
			severity: normalizeSeverity(data.info.severity),
			product: data.info.metadata?.product,
			vendor: data.info.metadata?.vendor,
			author: data.info.author,
			desc: data.info.desc,
			http: data.http || [],
		});
	}

	const index = { version: 1, generated: new Date().toISOString(), count: fingerprints.length, fingerprints };
	const outPath = join(OUT, "scan-fingerprints.json");
	writeFileSync(outPath, JSON.stringify(index));
	const distPath = join(DIST, "scan-fingerprints.json");
	if (!existsSync(DIST)) mkdirSync(DIST, { recursive: true });
	writeFileSync(distPath, JSON.stringify(index));
	console.log(
		`[build-scan-index] Fingerprints: ${fingerprints.length} (${(JSON.stringify(index).length / 1024).toFixed(1)} KB) → ${outPath}`,
	);
	return fingerprints.length;
}

// ─── Main ─────────────────────────────────────────────────────────────

function main() {
	if (!existsSync(OUT)) mkdirSync(OUT, { recursive: true });
	if (!existsSync(DIST)) mkdirSync(DIST, { recursive: true });

	const start = Date.now();
	const cve = buildCveIndex();
	const mcp = buildMcpCategoriesIndex();
	const threats = buildThreatsIndex();
	const fp = buildFingerprintsIndex();
	const dur = Date.now() - start;

	console.log("");
	console.log("┌─ AIDR Scan build complete ─────────────────────");
	console.log(`│ CVE entries:        ${cve}`);
	console.log(`│ MCP categories:     ${mcp}`);
	console.log(`│ Threats rules:      ${threats}`);
	console.log(`│ Fingerprints:       ${fp}`);
	console.log(`│ Output:             ${relative(ROOT, OUT)}/ and dist/generated/`);
	console.log(`│ Duration:           ${dur}ms`);
	console.log("└────────────────────────────────────────────────");
}

main();
