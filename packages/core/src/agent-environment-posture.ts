/**
 * Agent environment and autonomy posture: static checks of the local agent
 * hosts' configuration and of the environment an agent inherits.
 *
 * Every check reads a documented configuration key; a key whose format could not
 * be verified for a host is not checked (see docs/agent-environment-posture.md).
 * Findings name hosts, check ids, config keys and environment variable NAMES.
 * Values (credentials, commands, paths inside settings) are never read into a
 * finding; uploads go through `buildAgentPostureFindingEvents`, which keeps only
 * the host, check id, severity and a count.
 */

import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { SecretDetector } from "./dlp/secret-detector.js";
import { parseJsonc } from "./jsonc.js";
import {
	detectUnprotectedAiTools,
	UNSUPPORTED_AI_TOOL_IDS,
	type UnprotectedAiTool,
} from "./unprotected-agents.js";

export const AGENT_HOSTS = [
	"claude-code",
	"cursor",
	"vscode",
	"codex",
	"opencode",
	"openclaw",
	"gemini-cli",
	"aider",
	"environment",
	// AI coding tools without an AIDR connector (unprotected-agents.ts).
	"windsurf",
	"jetbrains-ai",
	"cline",
	"roo-code",
	"copilot-cli",
	"amazon-q",
	"kiro",
	"zed",
] as const;
export type AgentHost = (typeof AGENT_HOSTS)[number];

export const AGENT_POSTURE_CHECKS = [
	"permission_bypass_mode",
	"broad_shell_allow_rule",
	"hooks_disabled",
	"aidr_hook_missing",
	"no_aidr_connector",
	"approval_policy_never",
	"sandbox_full_access",
	"permission_allow_all",
	"running_as_root",
	"docker_socket_writable",
	"cloud_credentials_in_env",
	"no_devcontainer",
	"mcp_plaintext_secret",
] as const;
export type AgentPostureCheck = (typeof AGENT_POSTURE_CHECKS)[number];

export type AgentPostureSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface AgentPostureFinding {
	id: AgentPostureCheck;
	severity: AgentPostureSeverity;
	host: AgentHost;
	title: string;
	remediation: string;
	/** Local-only evidence: the file and key inspected, or variable names. Never values. */
	evidence: { path?: string; key?: string; names?: string[] };
	/** How many items the finding covers (rules, variables, servers). */
	count: number;
}

export interface AgentHostDetection {
	host: Exclude<AgentHost, "environment">;
	detected: boolean;
	/** Whether AIDR has a connector for this host at all. */
	connector: boolean;
	evidence: string[];
}

export interface AgentEnvironmentReport {
	schema_version: 1;
	scanned_at: string;
	hosts: AgentHostDetection[];
	findings: AgentPostureFinding[];
	/** Configuration files that exist but could not be parsed: a coverage gap, not a clean result. */
	unreadable: string[];
	scope: string;
}

export interface AgentEnvironmentOptions {
	home: string;
	env?: Record<string, string | undefined>;
	/** Project directory checked for project-scoped settings and a devcontainer. */
	projectRoot?: string;
	/** Effective uid; undefined on platforms without one. */
	uid?: number;
	platform?: NodeJS.Platform;
	/** Hosts with a registered AIDR connector (from the CLI's connector status probe). */
	installedConnectors?: ReadonlySet<string>;
	/** MCP configuration files to check for plaintext secrets. */
	mcpConfigPaths?: string[];
	/** Docker socket path; overridable for tests. */
	dockerSocketPath?: string;
	/** AI tools without a connector; detected from `home`, `env` and PATH when omitted. */
	unprotectedTools?: UnprotectedAiTool[];
	now?: Date;
}

const SCOPE =
	"Static checks of local agent-host configuration files and of the current process environment. " +
	"A host whose config key format is not verified is reported for hook coverage only. " +
	"This is a posture snapshot, not proof of how an agent was actually launched.";

/**
 * Environment variables that hold long-lived cloud or cluster credentials. Only the
 * names are ever reported; their values are not read.
 */
const CLOUD_CREDENTIAL_ENV = [
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"GOOGLE_CREDENTIALS",
	"AZURE_CLIENT_SECRET",
	"AZURE_CLIENT_CERTIFICATE_PATH",
	"ARM_CLIENT_SECRET",
	"DIGITALOCEAN_ACCESS_TOKEN",
	"KUBECONFIG",
] as const;

type Json = Record<string, unknown>;

interface ReadResult {
	value: Json | null;
	/** The file exists but is not usable JSON/JSONC. */
	unreadable: boolean;
}

function asRecord(value: unknown): Json | null {
	return value && typeof value === "object" && !Array.isArray(value) ? (value as Json) : null;
}

function readJsonc(path: string): ReadResult {
	let content: string;
	try {
		content = readFileSync(path, "utf-8");
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		return { value: null, unreadable: code !== "ENOENT" && code !== "ENOTDIR" };
	}
	if (content.length > 2 * 1024 * 1024) return { value: null, unreadable: true };
	const parsed = parseJsonc(content);
	const record = parsed.status === "ok" ? asRecord(parsed.value) : null;
	return { value: record, unreadable: record === null };
}

function readText(path: string): { value: string | null; unreadable: boolean } {
	try {
		return { value: readFileSync(path, "utf-8"), unreadable: false };
	} catch (error) {
		const code = (error as NodeJS.ErrnoException).code;
		return { value: null, unreadable: code !== "ENOENT" && code !== "ENOTDIR" };
	}
}

class Collector {
	readonly findings: AgentPostureFinding[] = [];
	readonly unreadable: string[] = [];

	add(finding: AgentPostureFinding): void {
		this.findings.push(finding);
	}

	json(path: string): Json | null {
		const read = readJsonc(path);
		if (read.unreadable) this.unreadable.push(path);
		return read.value;
	}

	text(path: string): string | null {
		const read = readText(path);
		if (read.unreadable) this.unreadable.push(path);
		return read.value;
	}
}

// ── Claude Code ────────────────────────────────────────────────────────────

/** `Bash`, `Bash(*)`, `Bash(*:*)`, `Bash(:*)` and `*` allow every shell command. */
const BROAD_SHELL_RULE = /^(?:\*|Bash|Bash\(\s*(?:\*|:\*|\*:\*)\s*\))$/;

function checkClaudeSettings(path: string, collector: Collector): boolean {
	const settings = collector.json(path);
	if (!settings) return false;
	const permissions = asRecord(settings.permissions);
	if (permissions?.defaultMode === "bypassPermissions") {
		collector.add({
			id: "permission_bypass_mode",
			severity: "critical",
			host: "claude-code",
			title: "Claude Code runs with permission prompts bypassed",
			remediation:
				'Remove "defaultMode": "bypassPermissions" (use "default" or "acceptEdits"); AIDR hooks still run, but no human confirms any tool call.',
			evidence: { path, key: "permissions.defaultMode" },
			count: 1,
		});
	}
	const allow = Array.isArray(permissions?.allow) ? permissions.allow : [];
	const broad = allow.filter(
		(rule): rule is string => typeof rule === "string" && BROAD_SHELL_RULE.test(rule.trim()),
	);
	if (broad.length > 0) {
		collector.add({
			id: "broad_shell_allow_rule",
			severity: "high",
			host: "claude-code",
			title: "Claude Code pre-approves every shell command",
			remediation:
				"Replace unrestricted allow rules such as Bash(*) with specific command prefixes (for example Bash(npm run test:*)).",
			evidence: { path, key: "permissions.allow" },
			count: broad.length,
		});
	}
	if (settings.disableAllHooks === true) {
		collector.add({
			id: "hooks_disabled",
			severity: "critical",
			host: "claude-code",
			title: "Claude Code hooks are disabled, so AIDR does not run",
			remediation: 'Remove "disableAllHooks": true from the settings file.',
			evidence: { path, key: "disableAllHooks" },
			count: 1,
		});
	}
	return true;
}

function checkClaudeCode(home: string, projectRoot: string | undefined, collector: Collector) {
	const paths = [join(home, ".claude", "settings.json")];
	if (projectRoot) {
		paths.push(
			join(projectRoot, ".claude", "settings.json"),
			join(projectRoot, ".claude", "settings.local.json"),
		);
	}
	let detected = existsSync(join(home, ".claude"));
	for (const path of paths) detected = checkClaudeSettings(path, collector) || detected;
	return { detected, evidence: paths };
}

// ── Codex ──────────────────────────────────────────────────────────────────

/**
 * String values of `key` in `config.toml`, from the root table and from every
 * `[profiles.<name>]` table. Other tables are ignored: the same key name under
 * an unrelated table does not configure the agent.
 */
function tomlStringValues(raw: string, key: string): string[] {
	const values: string[] = [];
	let applies = true;
	const assignment = new RegExp(
		`^[ \\t]*${key}[ \\t]*=[ \\t]*(?:"([^"\\r\\n]*)"|'([^'\\r\\n]*)')[ \\t]*(?:#.*)?$`,
	);
	for (const line of raw.split(/\r?\n/)) {
		const table = line.match(/^[ \t]*\[\[?([^\]]+)\]\]?[ \t]*(?:#.*)?$/);
		if (table) {
			applies = /^profiles\.[A-Za-z0-9_-]+$/.test((table[1] ?? "").trim());
			continue;
		}
		if (!applies) continue;
		const match = line.match(assignment);
		if (match) values.push(match[1] ?? match[2] ?? "");
	}
	return values;
}

function checkCodex(home: string, collector: Collector) {
	const path = join(home, ".codex", "config.toml");
	const raw = collector.text(path);
	if (raw !== null) {
		const never = tomlStringValues(raw, "approval_policy").filter((v) => v === "never");
		if (never.length > 0) {
			collector.add({
				id: "approval_policy_never",
				severity: "high",
				host: "codex",
				title: "Codex never asks before running commands",
				remediation:
					'Set approval_policy = "on-request" (or "untrusted") in config.toml and in every profile.',
				evidence: { path, key: "approval_policy" },
				count: never.length,
			});
		}
		const fullAccess = tomlStringValues(raw, "sandbox_mode").filter(
			(v) => v === "danger-full-access",
		);
		if (fullAccess.length > 0) {
			collector.add({
				id: "sandbox_full_access",
				severity: "critical",
				host: "codex",
				title: "Codex sandbox is disabled (danger-full-access)",
				remediation:
					'Set sandbox_mode = "workspace-write" (or "read-only") so commands run inside the Codex sandbox.',
				evidence: { path, key: "sandbox_mode" },
				count: fullAccess.length,
			});
		}
	}
	return { detected: existsSync(join(home, ".codex")), evidence: [path] };
}

// ── OpenCode ───────────────────────────────────────────────────────────────

function checkOpenCode(
	home: string,
	env: Record<string, string | undefined>,
	projectRoot: string | undefined,
	collector: Collector,
) {
	const configDir = join(env.XDG_CONFIG_HOME?.trim() || join(home, ".config"), "opencode");
	const paths = [join(configDir, "opencode.json")];
	if (projectRoot) paths.push(join(projectRoot, "opencode.json"));
	for (const path of paths) {
		const config = collector.json(path);
		const permission = asRecord(config?.permission);
		if (!permission) continue;
		const allowed = ["bash", "edit"].filter((tool) => permission[tool] === "allow");
		if (allowed.length > 0) {
			collector.add({
				id: "permission_allow_all",
				severity: "high",
				host: "opencode",
				title: `OpenCode pre-approves ${allowed.join(" and ")} without asking`,
				remediation:
					'Set permission.bash and permission.edit to "ask" (or to per-command patterns) in opencode.json.',
				evidence: { path, key: allowed.map((tool) => `permission.${tool}`).join(", ") },
				count: allowed.length,
			});
		}
	}
	return { detected: existsSync(configDir), evidence: paths };
}

// ── MCP plaintext secrets ──────────────────────────────────────────────────

const SECRET_DETECTOR = new SecretDetector();
const SECRET_NAME = /(?:api[_-]?key|token|secret|password|passwd|credential|auth)/i;
/** `${VAR}`, `$VAR`, `{env:VAR}`, `env:VAR` and secret-manager references are not plaintext. */
const REFERENCE_VALUE =
	/^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{env:[^}]+\}|env:|op:\/\/|vault:|secret:)/;

function serverMaps(root: Json): Json[] {
	const mcp = asRecord(root.mcp);
	return [asRecord(root.mcpServers), asRecord(root.servers), asRecord(mcp?.servers), mcp].filter(
		(map): map is Json => map !== null,
	);
}

function hasSecret(value: string): boolean {
	return !SECRET_DETECTOR.scan(value).next().done;
}

/** A literal (non-reference) value that is credential-shaped or sits under a secret-named key. */
function isPlaintextSecret(name: string, value: unknown): boolean {
	if (typeof value !== "string") return false;
	const trimmed = value.trim();
	if (REFERENCE_VALUE.test(trimmed)) return false;
	return hasSecret(value) || (SECRET_NAME.test(name) && trimmed.length >= 8);
}

/** Literal credential values in one server's env/headers/args. Values are inspected, never kept. */
function plaintextSecretFields(server: Json): number {
	const named = ["env", "environment", "headers"].flatMap((field) =>
		Object.entries(asRecord(server[field]) ?? {}),
	);
	const args = Array.isArray(server.args) ? server.args : [];
	return (
		named.filter(([name, value]) => isPlaintextSecret(name, value)).length +
		args.filter((arg) => typeof arg === "string" && hasSecret(arg)).length
	);
}

/** Per-server plaintext credential counts in one MCP config (servers with none omitted). */
function secretCountsPerServer(root: Json): number[] {
	return serverMaps(root)
		.flatMap((map) => Object.values(map))
		.map((raw) => asRecord(raw))
		.filter((server): server is Json => server !== null)
		.map(plaintextSecretFields)
		.filter((found) => found > 0);
}

function checkMcpSecrets(paths: string[], collector: Collector): void {
	for (const path of paths) {
		const root = collector.json(path);
		if (!root) continue;
		const counts = secretCountsPerServer(root);
		const servers = counts.length;
		const fields = counts.reduce((sum, found) => sum + found, 0);
		if (servers > 0) {
			collector.add({
				id: "mcp_plaintext_secret",
				severity: "high",
				host: "environment",
				title: `${servers} MCP server(s) carry ${fields} plaintext credential value(s) in their config`,
				remediation:
					"Move the values to environment variables or a secret manager and reference them (for example ${API_TOKEN}); rotate any credential that was committed or shared.",
				evidence: { path },
				count: servers,
			});
		}
	}
}

// ── Process environment ────────────────────────────────────────────────────

function isWritable(path: string): boolean {
	try {
		accessSync(path, constants.W_OK);
		return true;
	} catch {
		return false;
	}
}

function checkEnvironment(options: AgentEnvironmentOptions, collector: Collector): void {
	const env = options.env ?? {};
	if (options.uid === 0) {
		collector.add({
			id: "running_as_root",
			severity: "high",
			host: "environment",
			title: "Agents on this machine run as root",
			remediation:
				"Run agent hosts as an unprivileged user; a root agent can rewrite AIDR's own configuration and hooks.",
			evidence: { key: "uid" },
			count: 1,
		});
	}
	const socket = options.dockerSocketPath ?? "/var/run/docker.sock";
	if (options.platform !== "win32" && existsSync(socket) && isWritable(socket)) {
		collector.add({
			id: "docker_socket_writable",
			severity: "high",
			host: "environment",
			title: "The Docker socket is writable by the agent user",
			remediation:
				"Remove the user from the docker group or use rootless Docker; write access to the socket is equivalent to root on the host.",
			evidence: { path: socket },
			count: 1,
		});
	}
	const names = CLOUD_CREDENTIAL_ENV.filter((name) => (env[name] ?? "").trim() !== "");
	if (names.length > 0) {
		collector.add({
			id: "cloud_credentials_in_env",
			severity: "medium",
			host: "environment",
			title: "Cloud credentials are exported into the environment agents inherit",
			remediation:
				"Do not export long-lived cloud credentials in shells that start agents; use short-lived, least-privilege credentials scoped to the task.",
			evidence: { names: [...names] },
			count: names.length,
		});
	}
}

function inContainer(env: Record<string, string | undefined>): boolean {
	return (
		existsSync("/.dockerenv") ||
		existsSync("/run/.containerenv") ||
		Boolean(env.REMOTE_CONTAINERS || env.CODESPACES || env.DEVCONTAINER)
	);
}

// ── Report ─────────────────────────────────────────────────────────────────

/** Run every static check. Reads files only; never executes a host binary. */
export function inspectAgentEnvironment(options: AgentEnvironmentOptions): AgentEnvironmentReport {
	const { home, projectRoot } = options;
	const env = options.env ?? {};
	const collector = new Collector();

	const claude = checkClaudeCode(home, projectRoot, collector);
	const codex = checkCodex(home, collector);
	const opencode = checkOpenCode(home, env, projectRoot, collector);
	const cursorDir = join(home, ".cursor");
	const vscodeDir = join(home, ".vscode");
	const openclawConfig = join(home, ".openclaw", "openclaw.json");
	const unprotected =
		options.unprotectedTools ?? detectUnprotectedAiTools({ home, env, platform: options.platform });

	const hosts: AgentHostDetection[] = [
		{ host: "claude-code", detected: claude.detected, connector: true, evidence: claude.evidence },
		{ host: "cursor", detected: existsSync(cursorDir), connector: true, evidence: [cursorDir] },
		{ host: "vscode", detected: existsSync(vscodeDir), connector: true, evidence: [vscodeDir] },
		{ host: "codex", detected: codex.detected, connector: true, evidence: codex.evidence },
		{ host: "opencode", detected: opencode.detected, connector: true, evidence: opencode.evidence },
		{
			host: "openclaw",
			detected: existsSync(openclawConfig),
			connector: true,
			evidence: [openclawConfig],
		},
		...UNSUPPORTED_AI_TOOL_IDS.map((id): AgentHostDetection => {
			const tool = unprotected.find((entry) => entry.id === id);
			return {
				host: id,
				detected: tool !== undefined,
				connector: false,
				evidence: tool?.evidence ?? [],
			};
		}),
	];

	for (const host of hosts) {
		if (!host.detected) continue;
		if (!host.connector) {
			collector.add({
				id: "no_aidr_connector",
				severity: "medium",
				host: host.host,
				title: `${host.host} is installed but AIDR has no connector for it`,
				remediation:
					"Tool calls from this agent are not inspected by AIDR. Route it through the AIDR MCP gateway where possible, or restrict its use by policy.",
				evidence: { path: host.evidence[0] },
				count: 1,
			});
		} else if (options.installedConnectors && !options.installedConnectors.has(host.host)) {
			collector.add({
				id: "aidr_hook_missing",
				severity: "high",
				host: host.host,
				title: `${host.host} is installed but no AIDR hook is registered`,
				remediation: "Run `aidr setup` and follow the connector guide for this host.",
				evidence: { path: host.evidence[0] },
				count: 1,
			});
		}
	}

	const editorDetected = hosts.some(
		(host) => (host.host === "vscode" || host.host === "cursor") && host.detected,
	);
	if (
		editorDetected &&
		projectRoot &&
		!existsSync(join(projectRoot, ".devcontainer", "devcontainer.json")) &&
		!existsSync(join(projectRoot, ".devcontainer.json")) &&
		!inContainer(env)
	) {
		collector.add({
			id: "no_devcontainer",
			severity: "low",
			host: "environment",
			title: "This project has no devcontainer and the agent runs directly on the host",
			remediation:
				"Add a .devcontainer/devcontainer.json so editor agents run in an isolated container with only the project mounted.",
			evidence: { path: projectRoot },
			count: 1,
		});
	}

	checkMcpSecrets(options.mcpConfigPaths ?? [], collector);
	checkEnvironment(options, collector);

	return {
		schema_version: 1,
		scanned_at: (options.now ?? new Date()).toISOString(),
		hosts,
		findings: collector.findings,
		unreadable: [...new Set(collector.unreadable)],
		scope: SCOPE,
	};
}
