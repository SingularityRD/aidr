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
	status: "known" | "unknown";
}

function riskHintsFor(entry: { command?: unknown; url?: unknown; args?: unknown }): string[] {
	const hints: string[] = [];
	const command = typeof entry.command === "string" ? entry.command : "";
	const url = typeof entry.url === "string" ? entry.url : "";
	const args = Array.isArray(entry.args)
		? entry.args.filter((x): x is string => typeof x === "string")
		: [];

	if (url && /^https?:\/\//i.test(url) && !/^(https:\/\/(localhost|127\.0\.0\.1))/i.test(url)) {
		hints.push("remote_mcp_url");
	}
	if (/(^|\\|\/)(cmd|sh|bash|pwsh|powershell)(\.exe)?$/i.test(command)) {
		hints.push("shell_wrapper_command");
	}
	if (args.some((a) => /(--allow-all|--unsafe|--dangerous|\/$|^[A-Za-z]:\\$)/i.test(a))) {
		hints.push("broad_filesystem_access_arg");
	}
	if (!command && !url) hints.push("missing_command_or_url");

	return hints;
}

function asRecord(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
}

function stringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((x): x is string => typeof x === "string") : [];
}

function inventoryItemFromEntry(
	name: string,
	raw: unknown,
	sourcePath: string,
): McpInventoryItem | null {
	const rec = asRecord(raw);
	if (!rec) return null;
	const commandParts = stringArray(rec.command);
	const command = typeof rec.command === "string" ? rec.command : commandParts[0] ?? null;
	const url = typeof rec.url === "string" ? rec.url : null;
	const args = [...commandParts.slice(1), ...stringArray(rec.args)];
	const riskHints = riskHintsFor({ command, url, args });
	return {
		name,
		command,
		url,
		args,
		sourcePath,
		riskHints,
		status: riskHints.length > 0 ? "unknown" : "known",
	};
}

interface ParsedServers {
	items: McpInventoryItem[];
	/** Names present in the file that are not usable server records. */
	skippedNames: string[];
}

function parseServerRecord(
	servers: Record<string, unknown> | null | undefined,
	sourcePath: string,
): ParsedServers {
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
	if (!root) return { items: [], skippedNames: [] };

	const nestedMcp = asRecord(root.mcp);
	const nestedMcpServers = asRecord(nestedMcp?.servers);
	const candidates = [
		asRecord(root.mcpServers),
		nestedMcpServers,
		asRecord(root.servers),
		nestedMcpServers ? null : nestedMcp,
	];

	const items: McpInventoryItem[] = [];
	const seen = new Set<string>();
	const skippedNames = new Set<string>();
	for (const servers of candidates) {
		const parsed = parseServerRecord(servers, sourcePath);
		for (const name of parsed.skippedNames) skippedNames.add(name);
		for (const item of parsed.items) {
			const key = `${item.sourcePath}\0${item.name}`;
			if (seen.has(key)) continue;
			seen.add(key);
			items.push(item);
		}
	}
	// A name that was unusable in one config shape but enumerated in another is
	// not a gap.
	for (const item of items) skippedNames.delete(item.name);
	return { items, skippedNames: [...skippedNames] };
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
		return { status: "read", items: servers.items, serversNotEnumerated: servers.skippedNames.length };
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
): McpInventoryCoverageStatus {
	if (invalidSources > 0) return readSources > 0 ? "partial" : "invalid";
	return readSources > 0 ? "read" : "missing";
}

export async function inspectMcpServerInventory(configPaths?: string[]): Promise<McpInventoryReport> {
	const defaultPaths = [
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
	];
	const paths = (configPaths && configPaths.length > 0 ? configPaths : defaultPaths).map(
		resolvePath,
	);
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
			status: coverageStatus(readSources, invalidSources),
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
