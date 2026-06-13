import { execSync } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { cwd } from "node:process";
import type { Environment } from "./config-manager.js";

export async function detectEnvironment(): Promise<Environment> {
	const hasNode = checkNode();
	const nodeVersion = hasNode ? getNodeVersion() : "unknown";

	return {
		agent: detectAgent(),
		hasNode,
		nodeVersion,
		projectRoot: cwd(),
	};
}

function detectAgent(): Environment["agent"] {
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

	// Check for agent-specific files
	try {
		accessSync(".claude-plugin/plugin.json", constants.F_OK);
		return "claude";
	} catch {
		// Not Claude
	}

	try {
		accessSync(".cursor/extensions", constants.F_OK);
		return "cursor";
	} catch {
		// Not Cursor
	}

	return "unknown";
}

function checkNode(): boolean {
	try {
		execSync("node --version", { stdio: "pipe" });
		return true;
	} catch {
		return false;
	}
}

function getNodeVersion(): string {
	try {
		return execSync("node --version", { stdio: "pipe" }).toString().trim();
	} catch {
		return "unknown";
	}
}
