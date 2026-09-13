import { resolvePath } from "./config.js";
import { getFileContent } from "./file-utils.js";

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

function parseServerRecord(
	servers: Record<string, unknown> | null | undefined,
	sourcePath: string,
): McpInventoryItem[] {
	if (!servers) return [];
	const items: McpInventoryItem[] = [];
	for (const [name, raw] of Object.entries(servers)) {
		const item = inventoryItemFromEntry(name, raw, sourcePath);
		if (item) items.push(item);
	}
	return items;
}

function parseMcpServers(data: unknown, sourcePath: string): McpInventoryItem[] {
	const root = asRecord(data);
	if (!root) return [];

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
	for (const servers of candidates) {
		for (const item of parseServerRecord(servers, sourcePath)) {
			const key = `${item.sourcePath}\0${item.name}`;
			if (seen.has(key)) continue;
			seen.add(key);
			items.push(item);
		}
	}
	return items;
}

export interface McpInventoryReport {
	items: McpInventoryItem[];
	sources: Array<{ path: string; status: "read" | "missing" | "invalid" }>;
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
	for (const path of paths) {
		try {
			const content = await getFileContent(path);
			if (content.length > 2 * 1024 * 1024) throw new Error("inventory_source_too_large");
			const parsed = JSON.parse(content) as unknown;
			if (!asRecord(parsed) || Array.isArray(parsed)) throw new Error("invalid_inventory_root");
			all.push(...parseMcpServers(parsed, path));
			sources.push({ path, status: "read" });
		} catch (error) {
			sources.push({ path, status: (error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "invalid" });
		}
	}
	return { items: all, sources };
}

export async function loadMcpServerInventory(configPaths?: string[]): Promise<McpInventoryItem[]> {
	return (await inspectMcpServerInventory(configPaths)).items;
}
