import { createHash } from "node:crypto";
import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";
import { parseJsonc } from "./jsonc.js";

export interface McpInventoryItem {
	name: string;
	command: string | null;
	url: string | null;
	args: string[];
	sourcePath: string;
	riskHints: string[];
	configurationSha256: string;
	status: "known" | "unknown";
}

function riskHintsFor(entry: { command?: unknown; url?: unknown; args?: unknown }): string[] {
	const hints: string[] = [];
	const command = typeof entry.command === "string" ? entry.command : "";
	const url = typeof entry.url === "string" ? entry.url : "";
	const args = Array.isArray(entry.args)
		? entry.args.filter((x): x is string => typeof x === "string")
		: [];

	if (url && /^https?:\/\//i.test(url) && !isTrustedLoopbackUrl(url)) {
		hints.push("remote_mcp_url");
	}
	if (/(^|\\|\/)(cmd|sh|bash|pwsh|powershell)(\.exe)?$/i.test(command)) {
		hints.push("shell_wrapper_command");
	}
	if (args.some((a) => /(--allow-all|--unsafe|--dangerous|\/$|^[A-Za-z]:\\$)/i.test(a))) {
		hints.push("broad_filesystem_access_arg");
	}
	return hints;
}

function isTrustedLoopbackUrl(value: string): boolean {
	try {
		const parsed = new URL(value);
		const hostname = parsed.hostname
			.toLowerCase()
			.replace(/^\[|\]$/g, "")
			.replace(/\.$/, "");
		return parsed.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(hostname);
	} catch {
		return false;
	}
}

function asRecord(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function stringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((x): x is string => typeof x === "string") : [];
}

function isMcpUrl(value: unknown): value is string {
	if (typeof value !== "string") return false;
	try {
		const url = new URL(value);
		return url.protocol === "http:" || url.protocol === "https:";
	} catch {
		return false;
	}
}

function inventoryItemFromEntry(
	name: string,
	raw: unknown,
	sourcePath: string,
): McpInventoryItem | null {
	const rec = asRecord(raw);
	if (!rec) return null;
	const commandParts = stringArray(rec.command);
	const command = typeof rec.command === "string" ? rec.command : (commandParts[0] ?? null);
	const url = typeof rec.url === "string" ? rec.url : null;
	const explicitArgs = stringArray(rec.args);
	const invalidCommandArray =
		Array.isArray(rec.command) && commandParts.length !== rec.command.length;
	const invalidArgs =
		rec.args !== undefined && (!Array.isArray(rec.args) || explicitArgs.length !== rec.args.length);
	// An unusable endpoint must remain a coverage gap, not a trusted inventory hit.
	if (
		(!command && !url) ||
		(rec.command !== undefined && !command?.trim()) ||
		invalidCommandArray ||
		(rec.url !== undefined && !isMcpUrl(rec.url)) ||
		invalidArgs
	) {
		return null;
	}
	const args = [...commandParts.slice(1), ...explicitArgs];
	const riskHints = riskHintsFor({ command, url, args });
	return {
		name,
		command,
		url,
		args,
		sourcePath,
		riskHints,
		configurationSha256: createHash("sha256").update(JSON.stringify(rec)).digest("hex"),
		status: riskHints.length > 0 ? "unknown" : "known",
	};
}

interface ParsedServers {
	items: McpInventoryItem[];
	/** Names present in the file that are not usable server records. */
	skippedNames: string[];
	/** A supported MCP server-map shape was present, including an empty map. */
	supportedShape: boolean;
}

type ParsedServerRecords = Pick<ParsedServers, "items" | "skippedNames">;

function parseServerRecord(
	servers: Record<string, unknown> | null | undefined,
	sourcePath: string,
): ParsedServerRecords {
	if (!servers) return { items: [], skippedNames: [] };
	const items: McpInventoryItem[] = [];
	const skippedNames: string[] = [];
	for (const [name, raw] of Object.entries(servers)) {
		const item = inventoryItemFromEntry(name, raw, sourcePath);
		if (item) items.push(item);
		else skippedNames.push(name);
	}
	return { items, skippedNames };
}

function parseMcpServers(data: unknown, sourcePath: string): ParsedServers {
	const root = asRecord(data);
	if (!root) return { items: [], skippedNames: [], supportedShape: false };

	const nestedMcp = asRecord(root.mcp);
	if (
		(Object.hasOwn(root, "mcpServers") && !asRecord(root.mcpServers)) ||
		(Object.hasOwn(root, "servers") && !asRecord(root.servers)) ||
		(Object.hasOwn(root, "mcp") && !nestedMcp) ||
		(nestedMcp && Object.hasOwn(nestedMcp, "servers") && !asRecord(nestedMcp.servers))
	)
		throw new Error("invalid_mcp_server_map");
	const nestedMcpServers = asRecord(nestedMcp?.servers);
	const hasNestedMcpServers = nestedMcp !== null && Object.hasOwn(nestedMcp, "servers");
	const candidates = [
		asRecord(root.mcpServers),
		nestedMcpServers,
		asRecord(root.servers),
		hasNestedMcpServers ? null : nestedMcp,
	];

	const byName = new Map<string, McpInventoryItem>();
	const conflictingNames = new Set<string>();
	const skippedNames = new Set<string>();
	for (const servers of candidates) {
		const parsed = parseServerRecord(servers, sourcePath);
		// A valid declaration elsewhere cannot resolve a malformed declaration
		// of the same alias; the host's effective config is ambiguous.
		for (const name of parsed.skippedNames) {
			skippedNames.add(name);
			byName.delete(name);
			conflictingNames.add(name);
		}
		for (const item of parsed.items) {
			if (conflictingNames.has(item.name)) continue;
			const existing = byName.get(item.name);
			if (existing && existing.configurationSha256 !== item.configurationSha256) {
				byName.delete(item.name);
				conflictingNames.add(item.name);
				continue;
			}
			byName.set(item.name, item);
		}
	}
	for (const name of conflictingNames) skippedNames.add(name);
	return {
		items: [...byName.values()],
		skippedNames: [...skippedNames],
		supportedShape: candidates.some((servers) => servers !== null),
	};
}

export type McpInventorySourceStatus = "read" | "missing" | "invalid";

/**
 * Aggregate readability of the configured inventory sources.
 *
 * `read` means every source that exists was enumerated (absent files are not a
 * gap: there is nothing to enumerate). `partial` / `invalid` mean at least one
 * present source could not be enumerated, so the item list is incomplete and
 * must never be treated as a full inventory.
 */
export type McpInventoryCoverageStatus = "read" | "missing" | "invalid" | "partial";

export interface McpInventoryCoverage {
	status: McpInventoryCoverageStatus;
	/** Configured sources examined. */
	totalSources: number;
	/** Sources enumerated successfully. */
	readSources: number;
	/** Configured sources that do not exist. */
	missingSources: number;
	/** Sources that exist but could not be parsed or read. */
	invalidSources: number;
	/**
	 * Server entries visible in a readable source that could not be turned into
	 * inventory items (malformed records).
	 */
	serversNotEnumerated: number;
	/**
	 * Sources whose server list is entirely unknown because the file could not
	 * be parsed. Each one is a coverage gap: it may declare any number of
	 * servers, including risky ones, so the true server count is unknowable.
	 */
	sourcesNotEnumerated: number;
}

export interface McpInventoryReport {
	items: McpInventoryItem[];
	sources: Array<{ path: string; status: McpInventorySourceStatus }>;
	coverage: McpInventoryCoverage;
}

interface InventorySourceRead {
	status: McpInventorySourceStatus;
	items: McpInventoryItem[];
	serversNotEnumerated: number;
}

/**
 * Enumerate one configured source.
 *
 * JSONC is the normal shape of `.vscode/mcp.json` and friends, so a strict
 * `JSON.parse` here would record a readable file as invalid and silently empty
 * the inventory.
 */
async function readInventorySource(path: string): Promise<InventorySourceRead> {
	try {
		const content = await getFileContent(path);
		if (content.length > 2 * 1024 * 1024) throw new Error("inventory_source_too_large");
		const parsed = parseJsonc(content);
		if (parsed.status !== "ok") throw new Error(`invalid_inventory_json:${parsed.error}`);
		if (!asRecord(parsed.value) || Array.isArray(parsed.value)) {
			throw new Error("invalid_inventory_root");
		}
		const servers = parseMcpServers(parsed.value, path);
		if (!servers.supportedShape) throw new Error("unsupported_inventory_shape");
		return {
			status: "read",
			items: servers.items,
			serversNotEnumerated: servers.skippedNames.length,
		};
	} catch (error) {
		return {
			status: (error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "invalid",
			items: [],
			serversNotEnumerated: 0,
		};
	}
}

function coverageStatus(
	readSources: number,
	invalidSources: number,
	serversNotEnumerated: number,
): McpInventoryCoverageStatus {
	if (invalidSources > 0) return readSources > 0 ? "partial" : "invalid";
	if (serversNotEnumerated > 0) return "partial";
	return readSources > 0 ? "read" : "missing";
}

/** MCP configuration files enumerated when no explicit path is given. */
export const DEFAULT_MCP_INVENTORY_PATHS: readonly string[] = Object.freeze([
	"~/.claude.json",
	".mcp.json",
	"~/.claude/claude_desktop_config.json",
	"~/.config/claude/claude_desktop_config.json",
	"~/.cursor/mcp.json",
	"~/.cursor/config.json",
	".cursor/mcp.json",
	".cursor/config.json",
	".vscode/mcp.json",
	"~/.config/opencode/opencode.json",
	".opencode/opencode.json",
	"~/.openclaw/openclaw.json",
	".openclaw/openclaw.json",
]);

export async function inspectMcpServerInventory(
	configPaths?: string[],
): Promise<McpInventoryReport> {
	const paths = (
		configPaths && configPaths.length > 0 ? configPaths : DEFAULT_MCP_INVENTORY_PATHS
	).map(resolvePath);
	const all: McpInventoryItem[] = [];
	const sources: McpInventoryReport["sources"] = [];
	let serversNotEnumerated = 0;
	for (const path of paths) {
		const read = await readInventorySource(path);
		all.push(...read.items);
		serversNotEnumerated += read.serversNotEnumerated;
		sources.push({ path, status: read.status });
	}

	const readSources = sources.filter((source) => source.status === "read").length;
	const missingSources = sources.filter((source) => source.status === "missing").length;
	const invalidSources = sources.filter((source) => source.status === "invalid").length;

	return {
		items: all,
		sources,
		coverage: {
			status: coverageStatus(readSources, invalidSources, serversNotEnumerated),
			totalSources: sources.length,
			readSources,
			missingSources,
			invalidSources,
			serversNotEnumerated,
			sourcesNotEnumerated: invalidSources,
		},
	};
}

export async function loadMcpServerInventory(configPaths?: string[]): Promise<McpInventoryItem[]> {
	return (await inspectMcpServerInventory(configPaths)).items;
}
