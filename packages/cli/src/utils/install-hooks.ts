import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Environment } from "./config-manager.js";
import { updateConfig } from "./config-manager.js";

const HOOKS_DIR = join(homedir(), ".singularity-aidr", "hooks");

export async function installHooks(env: Environment): Promise<void> {
	if (!existsSync(HOOKS_DIR)) {
		mkdirSync(HOOKS_DIR, { recursive: true });
	}

	// Install agent-specific hooks
	switch (env.agent) {
		case "claude":
			await installClaudeHooks();
			break;
		case "cursor":
		case "vscode":
			await installVSCodeHooks(env.agent);
			break;
		case "openclaw":
			await installOpenClawHooks();
			break;
		default:
			// Install generic hooks
			await installGenericHooks();
	}

	updateConfig({ hooksInstalled: true });
}

async function installClaudeHooks(): Promise<void> {
	const hookContent = {
		hooks: [
			{
				name: "aidr-pre-tool",
				entrypoint: "~/.singularity-aidr/hooks/pre-tool.js",
				event: "pre_tool_use",
			},
		],
	};

	writeFileSync(join(HOOKS_DIR, "claude-hooks.json"), JSON.stringify(hookContent, null, 2));
}

async function installVSCodeHooks(editor: "cursor" | "vscode"): Promise<void> {
	const settingsDir = join(homedir(), editor === "cursor" ? ".cursor" : ".vscode");

	if (!existsSync(settingsDir)) {
		mkdirSync(settingsDir, { recursive: true });
	}

	const settingsFile = join(settingsDir, "settings.json");
	let settings: Record<string, unknown> = {};

	if (existsSync(settingsFile)) {
		settings = JSON.parse(
			await import("node:fs").then((fs) => fs.readFileSync(settingsFile, "utf-8")),
		);
	}

	settings["aidr.enabled"] = true;
	settings["aidr.hooksPath"] = HOOKS_DIR;

	writeFileSync(settingsFile, JSON.stringify(settings, null, 2));
}

async function installOpenClawHooks(): Promise<void> {
	const configPath = join(homedir(), ".openclaw", "config.json");

	if (!existsSync(configPath)) {
		throw new Error("OpenClaw not configured. Please run 'openclaw setup' first.");
	}

	const config = JSON.parse(
		await import("node:fs").then((fs) => fs.readFileSync(configPath, "utf-8")),
	);
	config.plugins = config.plugins || [];

	if (!config.plugins.includes("@singularityrd/aidr-openclaw")) {
		config.plugins.push("@singularityrd/aidr-openclaw");
	}

	writeFileSync(configPath, JSON.stringify(config, null, 2));
}

async function installGenericHooks(): Promise<void> {
	// Create a generic hook template that users can manually integrate
	const template = `#!/usr/bin/env node
// AIDR Generic Hook
// Add this to your agent's hook system

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const input = fs.readFileSync(0, 'utf-8');
const result = execSync('aidr check', { input, encoding: 'utf-8' });
console.log(result);
`;

	writeFileSync(join(HOOKS_DIR, "generic-hook.js"), template);
}
