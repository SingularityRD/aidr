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

type DiscoveryReport = Awaited<ReturnType<typeof discoverMcpServers>>;

function printReport(report: DiscoveryReport): void {
	console.log(`MCP discovery: ${report.servers.length} configured server(s)`);
	for (const server of report.servers)
		console.log(
			`  ${server.name}  ${server.transport}  ${server.endpoint ?? "local process"}\n    ${server.source}${server.project === undefined ? "" : ` (project ${server.project})`}\n    ${server.risk_hints.join(", ") || "No configured risk indicator; trust is not verified"}`,
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

/** A config was unreadable, entries were skipped, or an explicitly named config is missing. */
function isIncomplete(report: DiscoveryReport, explicitConfigs: boolean): boolean {
	return (
		report.sources.some((s) => s.status === "invalid") ||
		report.coverage.servers_not_enumerated > 0 ||
		(explicitConfigs && report.sources.some((s) => s.status === "missing"))
	);
}

async function uploadInventory(
	report: DiscoveryReport,
	json: boolean,
	upload: typeof uploadPostureEvents,
): Promise<void> {
	// Server names, transport, risk categories, attestation status and digests
	// only: no source paths, endpoints, arguments, headers or environment.
	const events = buildMcpInventoryFindingEvents(report, newPostureScanId());
	const result = await upload(events);
	const write = json ? console.error : console.log;
	if (result.ok) {
		write(`Uploaded ${result.delivered} MCP inventory finding(s) to the control plane.`);
		return;
	}
	console.error(
		`Upload failed: ${describePostureUploadError(result.error)}.` +
			(result.queued
				? ` ${result.total - result.delivered} finding(s) remain queued and will be retried on the next delivery.`
				: " Nothing was uploaded."),
	);
	process.exitCode = 1;
}

export async function runDiscover(
	options: DiscoverOptions,
	dependencies: DiscoverDependencies = {},
): Promise<void> {
	const report = await discoverMcpServers(options.config);
	if (options.json) console.log(JSON.stringify(report, null, 2));
	else printReport(report);
	if (isIncomplete(report, Boolean(options.config?.length))) process.exitCode = 1;
	if (options.upload) {
		await uploadInventory(
			report,
			options.json === true,
			dependencies.upload ?? uploadPostureEvents,
		);
	}
}
