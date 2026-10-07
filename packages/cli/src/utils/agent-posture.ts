import { cwd } from "node:process";
import {
	type AgentEnvironmentReport,
	defaultMcpConfigPaths,
	inspectAgentEnvironment,
	resolvePath,
} from "@singularityrd/aidr-core";
import { type ConnectorStatus, detectConnectorStatuses } from "./connector-status.js";

export interface AgentPostureContext {
	home?: string;
	projectRoot?: string;
	env?: Record<string, string | undefined>;
	connectors?: ConnectorStatus[];
}

/**
 * Agent environment posture for the current user and working directory. Hook
 * coverage comes from the same measured connector status `aidr status` prints.
 */
export function scanAgentEnvironment(context: AgentPostureContext = {}): AgentEnvironmentReport {
	const home = context.home ?? resolvePath("~");
	const projectRoot = context.projectRoot ?? cwd();
	const connectors = context.connectors ?? detectConnectorStatuses(home);
	return inspectAgentEnvironment({
		home,
		projectRoot,
		env: context.env ?? process.env,
		uid: typeof process.getuid === "function" ? process.getuid() : undefined,
		platform: process.platform,
		installedConnectors: new Set(
			connectors.filter((c) => c.state === "installed").map((c) => c.id),
		),
		// Same sources `aidr discover` inventories; `~/` resolves against the scanned home.
		mcpConfigPaths: defaultMcpConfigPaths(projectRoot).map((path) =>
			path.startsWith("~/") ? `${home}${path.slice(1)}` : path,
		),
	});
}

/** One line per finding: severity, host, title and the key or names inspected (never values). */
export function formatAgentFinding(finding: AgentEnvironmentReport["findings"][number]): string {
	const where = finding.evidence.names?.length
		? ` [${finding.evidence.names.join(", ")}]`
		: finding.evidence.key
			? ` [${finding.evidence.key}]`
			: "";
	return `${finding.severity.toUpperCase()} ${finding.host}: ${finding.title}${where}\n      Fix: ${finding.remediation}`;
}
