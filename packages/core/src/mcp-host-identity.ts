/**
 * Host MCP tool identity → the canonical `mcp__<server>__<tool>` tool name.
 *
 * MCP server/tool policy (`policy.mcp.*`), agent profiles, toxic-flow and
 * context-poisoning all recognise an MCP call by the canonical name (or the
 * generic `MCP` tool with `tool_input.server`/`name`). Each host names MCP
 * tools differently, so without this mapping a server denial written once only
 * applied on the hosts that happen to use the canonical shape:
 *
 * | Host        | Host tool name                   | Separator / sanitization                       |
 * |-------------|----------------------------------|------------------------------------------------|
 * | Claude Code | `mcp__<server>__<tool>`          | canonical already                              |
 * | Codex       | `mcp__<server>__<tool>`          | canonical already                              |
 * | VS Code     | `mcp_<server>_<tool>`            | single `_`; server split needs known names     |
 * | Cursor      | `beforeMCPExecution`             | server field, else declared server matched by   |
 * |             |                                  | url / command line / config key in `command`;   |
 * |             |                                  | `preToolUse` carries no server identity          |
 * | OpenClaw    | `<server>__<tool>`               | `[^A-Za-z0-9_-]` → `-` (bundle MCP)            |
 * | OpenCode    | `<server>_<tool>`                | `[^A-Za-z0-9_-]` → `_`; needs known names       |
 *
 * Where the host separator is ambiguous, the server is chosen from the known
 * server names (the host's MCP configuration plus every server named in the
 * local MCP policy), preferring the longest match, so a server whose name
 * contains the separator still resolves to its policy id.
 */

import { loadConfig } from "./config.js";
import { inspectMcpServerInventory } from "./mcp-inventory.js";
import { parseLegacyMcpToolSelector } from "./mcp-tool-identity.js";

export interface McpToolIdentity {
	server: string;
	tool: string;
}

export const CANONICAL_MCP_PREFIX = "mcp__";

/** The canonical tool name core's MCP-aware layers recognise. */
export function canonicalMcpToolName(identity: McpToolIdentity): string {
	return `${CANONICAL_MCP_PREFIX}${identity.server}__${identity.tool}`;
}

/** OpenCode's tool-name sanitizer (`[^a-zA-Z0-9_-]` → `_`). */
export function sanitizeOpenCodeMcpName(name: string): string {
	return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}

/** OpenClaw bundle-MCP sanitizer (`[^A-Za-z0-9_-]` → `-`). */
export function sanitizeOpenClawMcpName(name: string): string {
	return name.replace(/[^A-Za-z0-9_-]/g, "-");
}

/**
 * Split `<server><sep><tool>` using the known server names (longest match
 * first, compared after `sanitize`); with no known match, fall back to the
 * first separator when `fallbackToFirstSeparator` is set.
 */
function splitWithKnownServers(
	name: string,
	separator: string,
	knownServers: Iterable<string>,
	sanitize: (value: string) => string,
	fallbackToFirstSeparator: boolean,
): McpToolIdentity | null {
	const candidates = [...new Set(knownServers)]
		.filter((server) => server.trim() !== "")
		.sort((a, b) => sanitize(b).length - sanitize(a).length);
	for (const server of candidates) {
		const prefix = `${sanitize(server)}${separator}`;
		if (name.startsWith(prefix) && name.length > prefix.length) {
			return { server, tool: name.slice(prefix.length) };
		}
	}
	if (!fallbackToFirstSeparator) return null;
	const index = name.indexOf(separator);
	if (index <= 0 || index + separator.length >= name.length) return null;
	return { server: name.slice(0, index), tool: name.slice(index + separator.length) };
}

/** `mcp__<server>__<tool>` (Claude Code, Codex). */
export function mcpIdentityFromCanonicalName(toolName: string): McpToolIdentity | null {
	if (!toolName.startsWith(CANONICAL_MCP_PREFIX)) return null;
	const rest = toolName.slice(CANONICAL_MCP_PREFIX.length);
	const index = rest.indexOf("__");
	if (index <= 0 || index + 2 >= rest.length) return null;
	return { server: rest.slice(0, index), tool: rest.slice(index + 2) };
}

/**
 * VS Code `mcp_<server>_<tool>`. Server names may contain `_`, so the known
 * names decide the split; otherwise the first `_` after the prefix is used.
 */
export function mcpIdentityFromVsCodeName(
	toolName: string,
	knownServers: Iterable<string> = [],
): McpToolIdentity | null {
	if (toolName.startsWith(CANONICAL_MCP_PREFIX)) return mcpIdentityFromCanonicalName(toolName);
	if (!toolName.startsWith("mcp_")) return null;
	return splitWithKnownServers(toolName.slice(4), "_", knownServers, (s) => s, true);
}

/**
 * OpenClaw bundle MCP `<server>__<tool>`. OpenClaw's built-in tools never
 * contain `__`, so any such name is an MCP tool.
 */
export function mcpIdentityFromOpenClawName(
	toolName: string,
	knownServers: Iterable<string> = [],
): McpToolIdentity | null {
	if (toolName.startsWith(CANONICAL_MCP_PREFIX)) return mcpIdentityFromCanonicalName(toolName);
	if (!toolName.includes("__")) return null;
	return splitWithKnownServers(toolName, "__", knownServers, sanitizeOpenClawMcpName, true);
}

/**
 * OpenCode `<server>_<tool>`. Built-in and plugin tools also use `_`, so a
 * name is only an MCP tool when it starts with a known (sanitized) server name.
 */
export function mcpIdentityFromOpenCodeName(
	toolName: string,
	knownServers: Iterable<string>,
): McpToolIdentity | null {
	if (toolName.startsWith(CANONICAL_MCP_PREFIX)) return mcpIdentityFromCanonicalName(toolName);
	return splitWithKnownServers(toolName, "_", knownServers, sanitizeOpenCodeMcpName, false);
}

/** A server entry from a host MCP configuration file, as far as matching needs. */
export interface McpServerDeclaration {
	name: string;
	command?: string | null;
	args?: readonly string[];
	url?: string | null;
}

function normalizeWhitespace(value: string): string {
	return value.trim().replace(/\s+/g, " ");
}

/**
 * Cursor's `beforeMCPExecution` carries the server's `command` or `url` but not
 * always its name. Find the declared server it belongs to: an exact URL match,
 * or a command line equal to the declaration's `command` + `args`.
 */
export function matchMcpServerDeclaration(
	declarations: readonly McpServerDeclaration[],
	payload: { command?: string; url?: string },
): string | null {
	const url = payload.url?.trim();
	const command = payload.command ? normalizeWhitespace(payload.command) : "";
	// Cursor builds have been observed sending the configuration key itself in
	// `command` (for stdio and remote servers alike); that is the server name.
	if (command && declarations.some((declaration) => declaration.name === command)) return command;
	for (const declaration of declarations) {
		if (url && declaration.url && declaration.url.trim() === url) return declaration.name;
		if (command && declaration.command) {
			const declared = normalizeWhitespace(
				[declaration.command, ...(declaration.args ?? [])].join(" "),
			);
			if (declared === command) return declaration.name;
		}
	}
	return null;
}

/**
 * Last-resort server identity when the host names none and no declaration
 * matched: the URL's host, else the command line. It will not match a policy
 * id written for the configured name, but it never invents a configured name.
 */
export function fallbackMcpServerIdentity(payload: {
	command?: string;
	url?: string;
}): string | null {
	if (payload.url?.trim()) {
		try {
			return new URL(payload.url.trim()).host || payload.url.trim();
		} catch {
			return payload.url.trim();
		}
	}
	const command = payload.command ? normalizeWhitespace(payload.command) : "";
	return command || null;
}

/** Every server id named by the MCP policy section (deny, approval, allow, tool selectors). */
export function mcpPolicyServerIds(mcpPolicy: {
	allow_servers?: readonly string[];
	deny_servers?: readonly string[];
	require_approval_servers?: readonly string[];
	deny_tools?: readonly string[];
	allow_tools?: readonly string[];
	require_approval_tools?: readonly string[];
}): string[] {
	const ids = new Set<string>();
	for (const list of [
		mcpPolicy.allow_servers,
		mcpPolicy.deny_servers,
		mcpPolicy.require_approval_servers,
	]) {
		for (const id of list ?? []) if (id.trim()) ids.add(id.trim());
	}
	for (const list of [
		mcpPolicy.deny_tools,
		mcpPolicy.allow_tools,
		mcpPolicy.require_approval_tools,
	]) {
		for (const selector of list ?? []) {
			const server = selectorServer(selector.trim());
			if (server) ids.add(server);
		}
	}
	return [...ids];
}

/** Server part of a tool selector: JSON `["server","tool"]` or legacy `server.tool`. */
function selectorServer(selector: string): string | null {
	if (selector.startsWith("[")) {
		try {
			const parsed: unknown = JSON.parse(selector);
			return Array.isArray(parsed) && typeof parsed[0] === "string" && parsed[0].trim()
				? parsed[0]
				: null;
		} catch {
			return null;
		}
	}
	return parseLegacyMcpToolSelector(selector)?.[0] ?? null;
}

/** Declared servers plus every server id the local MCP policy names. */
export interface KnownMcpServers {
	declarations: McpServerDeclaration[];
	/** Declared names and policy ids, for splitting ambiguous host tool names. */
	names: string[];
}

/**
 * Known MCP servers for resolving a host's tool name: the host's own MCP
 * configuration files and the local policy's server ids. Never throws; an
 * unreadable source contributes nothing (the name then falls back to the
 * host's default split, and an unidentifiable call is handled by policy as
 * an unknown server).
 */
export async function loadKnownMcpServers(
	configPaths: readonly string[],
): Promise<KnownMcpServers> {
	const declarations: McpServerDeclaration[] = [];
	const names = new Set<string>();
	try {
		const report = await inspectMcpServerInventory([...configPaths]);
		for (const item of report.items) {
			declarations.push({ name: item.name, command: item.command, args: item.args, url: item.url });
			names.add(item.name);
		}
	} catch {
		// Host configuration is a hint only.
	}
	try {
		const config = await loadConfig();
		for (const id of mcpPolicyServerIds(config.policy.mcp)) names.add(id);
	} catch {
		// Policy ids are a hint only.
	}
	return { declarations, names: [...names] };
}
