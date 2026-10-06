import { accessSync, constants } from "node:fs";
import { join } from "node:path";
import { cwd } from "node:process";
import { resolvePath } from "@singularityrd/aidr-core";
import type { Environment } from "./config-manager.js";
import { detectConnectorStatuses } from "./connector-status.js";

export async function detectEnvironment(
	home: string = resolvePath("~"),
	projectRoot: string = cwd(),
): Promise<Environment> {
	return {
		agent: detectAgent(home, projectRoot),
		hasNode: true,
		nodeVersion: process.version,
		projectRoot,
	};
}

function detectAgent(home: string, projectRoot: string): Environment["agent"] {
	// Check environment variables that indicate which agent is running
	if (process.env.CLAUDE_CODE_ROOT) {
		return "claude";
	}
	if (process.env.CURSOR_WORKSPACE_ROOT) {
		return "cursor";
	}
	if (process.env.VSCODE_CWD || process.env.VSCODE_PID) {
		return "vscode";
	}
	if (process.env.OPENCLAW_SESSION) {
		return "openclaw";
	}

	const statuses = detectConnectorStatuses(home);
	const detected = statuses.find((status) => status.state === "installed")
		?? statuses.find((status) => status.state !== "not_detected");
	if (detected) return detected.id === "claude-code" ? "claude" : detected.id;

	// Check for agent-specific files
	try {
		accessSync(join(projectRoot, ".claude-plugin", "plugin.json"), constants.F_OK);
		return "claude";
	} catch {
		// Not Claude
	}

	try {
		accessSync(join(projectRoot, ".cursor", "extensions"), constants.F_OK);
		return "cursor";
	} catch {
		// Not Cursor
	}

	return "unknown";
}
