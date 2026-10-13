import { resolvePath } from "@singularityrd/aidr-core";
import type { Environment } from "./config-manager.js";
import { detectConnectorStatuses } from "./connector-status.js";

/**
 * The agent hosts on this machine, measured exactly as `aidr status` measures
 * them: from the user's home directory only.
 *
 * Setup used to fall back to the current directory (a repository containing
 * `.claude-plugin/plugin.json` made it print "claude detected") and to editor
 * environment variables, so it reported hosts that `aidr status` then called
 * "not detected" (PRD-14). Both now come from {@link detectConnectorStatuses}.
 */
export async function detectEnvironment(
	home: string = resolvePath("~"),
	env: NodeJS.ProcessEnv = process.env,
): Promise<Environment> {
	const statuses = detectConnectorStatuses(home, env);
	const present = statuses.filter((status) => status.state !== "not_detected");
	const primary = present.find((status) => status.state === "installed") ?? present[0];
	return {
		agent: primary ? (primary.id === "claude-code" ? "claude" : primary.id) : "unknown",
		detectedHosts: present.map((status) => status.id),
		hasNode: true,
		nodeVersion: process.version,
	};
}
