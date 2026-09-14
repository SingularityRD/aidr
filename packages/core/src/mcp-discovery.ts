import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { inspectMcpServerInventory } from "./mcp-inventory.js";

function inventoryId(sourcePath: string, name: string): string {
	const resolvedPath = resolve(sourcePath);
	const canonicalPath = process.platform === "win32" ? resolvedPath.toLowerCase() : resolvedPath;
	return createHash("sha256")
		.update("aidr-mcp-inventory-v1\0")
		.update(JSON.stringify([canonicalPath, name]))
		.digest("hex");
}

/** Public inventory never exports server arguments, credentials, headers or URL queries. */
export async function discoverMcpServers(paths?: string[]) {
	const report = await inspectMcpServerInventory(paths);
	return {
		schema_version: 1,
		scanned_at: new Date().toISOString(),
		scope:
			"Local JSON/JSONC MCP configurations; not cloud-wide discovery or tool-description attestation",
		sources: report.sources,
		// Coverage is published next to `servers` so an unreadable configuration
		// is reported as a gap instead of as an empty (but complete) inventory.
		coverage: {
			status: report.coverage.status,
			total_sources: report.coverage.totalSources,
			read_sources: report.coverage.readSources,
			missing_sources: report.coverage.missingSources,
			invalid_sources: report.coverage.invalidSources,
			servers_not_enumerated: report.coverage.serversNotEnumerated,
			sources_not_enumerated: report.coverage.sourcesNotEnumerated,
		},
		servers: report.items.map((item) => {
			let endpoint: string | null = null;
			try {
				if (item.url) endpoint = new URL(item.url).origin;
			} catch {
				/* Invalid URLs remain unverified. */
			}
			return {
				inventory_id: inventoryId(item.sourcePath, item.name),
				name: item.name,
				source: item.sourcePath,
				transport: item.url ? "remote" : "stdio",
				endpoint,
				risk_hints: item.riskHints,
				configuration_sha256: createHash("sha256")
					.update(JSON.stringify([item.command, item.args, item.url]))
					.digest("hex"),
			};
		}),
	};
}
