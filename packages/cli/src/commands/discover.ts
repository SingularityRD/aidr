import {
	type AgentEnvironmentReport,
	buildAgentPostureFindingEvents,
	buildMcpInventoryFindingEvents,
	describePostureUploadError,
	discoverMcpServers,
	newPostureScanId,
	uploadPostureEvents,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { formatAgentFinding, scanAgentEnvironment } from "../utils/agent-posture.js";

interface DiscoverOptions {
	config?: string[];
	json?: boolean;
	upload?: boolean;
	/** Also report agent environment and autonomy posture. */
	agents?: boolean;
}

/** Injectable collaborators, for tests. */
export interface DiscoverDependencies {
	upload?: typeof uploadPostureEvents;
	agentEnvironment?: () => AgentEnvironmentReport;
}

export default async function discoverCommand(options: DiscoverOptions): Promise<void> {
	// Commander passes the Command as the second argument; never treat it as dependencies.
	await runDiscover(options);
}

type DiscoveryReport = Awaited<ReturnType<typeof discoverMcpServers>>;
type DiscoveredServer = DiscoveryReport["servers"][number];

/** Human-readable lines for one server. Secret findings name locations, never values. */
function describeDiscoveredServer(server: DiscoveredServer): string[] {
	const lines = [
		`  ${server.name}  ${server.transport}  ${server.endpoint ?? ct("discover.localProcess")}`,
		`    ${server.source}${server.project === undefined ? "" : ct("discover.project", { project: server.project })}`,
		`    ${server.risk_hints.join(", ") || ct("discover.noRiskHint")}`,
	];
	const categories = server.aig_categories;
	lines.push(
		categories.length > 0
			? ct("discover.aigCategories", {
					categories: categories
						.map(
							(category) => `${category.id} ${category.name} (${category.risk}, ${category.basis})`,
						)
						.join("; "),
				})
			: ct("discover.aigNone"),
	);
	for (const finding of server.secret_findings) {
		lines.push(
			ct("discover.secret", {
				location: finding.location,
				key: finding.key,
				kind: finding.kind,
			}),
		);
	}
	return lines;
}

function printReport(report: DiscoveryReport): void {
	console.log(ct("discover.header", { count: report.servers.length }));
	for (const server of report.servers) console.log(describeDiscoveredServer(server).join("\n"));
	for (const source of report.sources.filter((s) => s.status === "invalid"))
		console.error(ct("discover.unreadable", { path: source.path }));
	if (report.coverage.servers_not_enumerated > 0) {
		console.error(
			ct("discover.coverage", {
				status: report.coverage.status,
				count: report.coverage.servers_not_enumerated,
			}),
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

function printAgentReport(report: AgentEnvironmentReport): void {
	const detected = report.hosts.filter((host) => host.detected).map((host) => host.host);
	console.log(
		ct("discover.agents", {
			hosts: detected.length > 0 ? detected.join(", ") : ct("discover.noAgentHost"),
			count: report.findings.length,
		}),
	);
	for (const finding of report.findings) console.log(`  ${formatAgentFinding(finding)}`);
	for (const path of report.unreadable) console.error(ct("discover.unreadableAgent", { path }));
	console.log(report.scope);
}

async function uploadInventory(
	report: DiscoveryReport,
	agents: AgentEnvironmentReport | undefined,
	json: boolean,
	upload: typeof uploadPostureEvents,
): Promise<void> {
	// Server names, transport, risk categories, attestation status and digests
	// only: no source paths, endpoints, arguments, headers or environment.
	// Agent findings: host, check id, severity and a count; no paths, keys or names.
	const scanId = newPostureScanId();
	const events = [
		...buildMcpInventoryFindingEvents(report, scanId),
		...(agents ? buildAgentPostureFindingEvents(agents, scanId) : []),
	];
	const result = await upload(events);
	const write = json ? console.error : console.log;
	if (result.ok) {
		write(
			ct(agents ? "discover.uploadedAgents" : "discover.uploaded", { count: result.delivered }),
		);
		return;
	}
	console.error(
		ct("discover.uploadFailed", { reason: describePostureUploadError(result.error) }) +
			(result.queued
				? ct("discover.queued", { count: result.total - result.delivered })
				: ct("discover.nothingUploaded")),
	);
	process.exitCode = 1;
}

export async function runDiscover(
	options: DiscoverOptions,
	dependencies: DiscoverDependencies = {},
): Promise<void> {
	const report = await discoverMcpServers(options.config);
	const agents = options.agents
		? (dependencies.agentEnvironment ?? scanAgentEnvironment)()
		: undefined;
	if (options.json) {
		console.log(
			JSON.stringify(agents ? { ...report, agent_environment: agents } : report, null, 2),
		);
	} else {
		printReport(report);
		if (agents) printAgentReport(agents);
	}
	if (isIncomplete(report, Boolean(options.config?.length))) process.exitCode = 1;
	if (agents && agents.unreadable.length > 0) process.exitCode = 1;
	if (options.upload) {
		await uploadInventory(
			report,
			agents,
			options.json === true,
			dependencies.upload ?? uploadPostureEvents,
		);
	}
}
