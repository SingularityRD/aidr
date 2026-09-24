import {
	buildMcpInventoryFindingEvents,
	describePostureUploadError,
	discoverMcpServers,
	newPostureScanId,
	uploadPostureEvents,
} from "@singularityrd/aidr-core";

interface DiscoverOptions {
	config?: string[];
	json?: boolean;
	upload?: boolean;
}

/** Injectable collaborators, for tests. */
export interface DiscoverDependencies {
	upload?: typeof uploadPostureEvents;
}

export default async function discoverCommand(options: DiscoverOptions): Promise<void> {
	// Commander passes the Command as the second argument; never treat it as dependencies.
	await runDiscover(options);
}

export async function runDiscover(
	options: DiscoverOptions,
	dependencies: DiscoverDependencies = {},
): Promise<void> {
	const report = await discoverMcpServers(options.config);
	if (options.json) console.log(JSON.stringify(report, null, 2));
	else {
		console.log(`MCP discovery: ${report.servers.length} configured server(s)`);
		for (const server of report.servers)
			console.log(
				`  ${server.name}  ${server.transport}  ${server.endpoint ?? "local process"}\n    ${server.source}\n    ${server.risk_hints.join(", ") || "No configured risk indicator; trust is not verified"}`,
			);
		for (const source of report.sources.filter((s) => s.status === "invalid"))
			console.error(`Unreadable or unsupported configuration: ${source.path}`);
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

	if (options.upload) {
		// Server names, transport, risk categories, attestation status and digests
		// only: no source paths, endpoints, arguments, headers or environment.
		const events = buildMcpInventoryFindingEvents(report, newPostureScanId());
		const result = await (dependencies.upload ?? uploadPostureEvents)(events);
		const write = options.json ? console.error : console.log;
		if (result.ok) {
			write(`Uploaded ${result.delivered} MCP inventory finding(s) to the control plane.`);
		} else {
			console.error(
				`Upload failed: ${describePostureUploadError(result.error)}.` +
					(result.queued
						? ` ${result.total - result.delivered} finding(s) remain queued and will be retried on the next delivery.`
						: " Nothing was uploaded."),
			);
			process.exitCode = 1;
		}
	}
}
