import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import { generateApiKey } from "./crypto.js";

const CONFIG_DIR = join(homedir(), ".singularity-aidr");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");

export interface Environment {
	agent: "claude" | "cursor" | "vscode" | "openclaw" | "unknown";
	hasNode: boolean;
	nodeVersion: string;
	projectRoot: string;
}

export interface Config {
	apiKey: string;
	environment: Environment;
	version: string;
	createdAt: string;
	hooksInstalled: boolean;
	agentConfigured: boolean;
}

export async function createConfig(env: Environment, force: boolean): Promise<string> {
	if (!existsSync(CONFIG_DIR)) {
		mkdirSync(CONFIG_DIR, { recursive: true });
	}

	if (existsSync(CONFIG_FILE) && !force) {
		return CONFIG_FILE;
	}

	const config: Config = {
		apiKey: generateApiKey(),
		environment: env,
		version: "1.0.0",
		createdAt: new Date().toISOString(),
		hooksInstalled: false,
		agentConfigured: false,
	};

	writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
	return CONFIG_FILE;
}

export function getConfig(): Config | null {
	if (!existsSync(CONFIG_FILE)) {
		return null;
	}
	return JSON.parse(readFileSync(CONFIG_FILE, "utf-8")) as Config;
}

export function updateConfig(updates: Partial<Config>): void {
	const config = getConfig();
	if (!config) {
		throw new Error("Config not found. Run 'aidr setup' first.");
	}
	writeFileSync(CONFIG_FILE, JSON.stringify({ ...config, ...updates }, null, 2));
}
