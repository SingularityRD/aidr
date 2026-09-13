import { discoverMcpServers } from "@singularityrd/aidr-core";

export default async function discoverCommand(options: { config?: string[]; json?: boolean }): Promise<void> {
	const report = await discoverMcpServers(options.config);
	if (options.json) console.log(JSON.stringify(report, null, 2));
	else {
		console.log(`MCP discovery: ${report.servers.length} configured server(s)`);
		for (const server of report.servers) console.log(`  ${server.name}  ${server.transport}  ${server.endpoint ?? "local process"}\n    ${server.source}\n    ${server.risk_hints.join(", ") || "No configured risk indicator; trust is not verified"}`);
		for (const source of report.sources.filter((s) => s.status === "invalid")) console.error(`Unreadable or unsupported configuration: ${source.path}`);
		console.log(report.scope);
	}
	if (report.sources.some((s) => s.status === "invalid") || (options.config?.length && report.sources.some((s) => s.status === "missing"))) process.exitCode = 1;
}
