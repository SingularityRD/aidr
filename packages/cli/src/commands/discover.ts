import { discoverMcpServers } from "@singularityrd/aidr-core";

type DiscoveredServer = Awaited<ReturnType<typeof discoverMcpServers>>["servers"][number];

/** Human-readable lines for one server. Secret findings name locations, never values. */
export function describeDiscoveredServer(server: DiscoveredServer): string[] {
	const lines = [
		`  ${server.name}  ${server.transport}  ${server.endpoint ?? "local process"}`,
		`    ${server.source}`,
		`    ${server.risk_hints.join(", ") || "No configured risk indicator; trust is not verified"}`,
	];
	const categories = server.aig_categories;
	lines.push(
		categories.length > 0
			? `    AIG categories: ${categories
					.map((category) => `${category.id} ${category.name} (${category.risk}, ${category.basis})`)
					.join("; ")}`
			: "    AIG categories: none matched (not a safety verdict)",
	);
	for (const finding of server.secret_findings) {
		lines.push(
			`    Hardcoded secret: ${finding.location} ${finding.key} (${finding.kind}) - move it to a secret store or an env reference`,
		);
	}
	return lines;
}

export default async function discoverCommand(options: { config?: string[]; json?: boolean }): Promise<void> {
	const report = await discoverMcpServers(options.config);
	if (options.json) console.log(JSON.stringify(report, null, 2));
	else {
		console.log(`MCP discovery: ${report.servers.length} configured server(s)`);
		for (const server of report.servers) console.log(describeDiscoveredServer(server).join("\n"));
		for (const source of report.sources.filter((s) => s.status === "invalid")) console.error(`Unreadable or unsupported configuration: ${source.path}`);
		if (report.coverage.servers_not_enumerated > 0) {
			console.error(
				`Inventory coverage is ${report.coverage.status}; malformed server entries not enumerated: ${report.coverage.servers_not_enumerated}`,
			);
		}
		console.log(report.scope);
	}
	if (
		report.sources.some((s) => s.status === "invalid") ||
		report.coverage.servers_not_enumerated > 0 ||
		(options.config?.length && report.sources.some((s) => s.status === "missing"))
	) {
		process.exitCode = 1;
	}
}
