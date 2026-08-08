import chalk from "chalk";
import { type Config, getConfig, updateConfig } from "../utils/config-manager.js";

interface ConfigOptions {
	get?: string;
	set?: string[];
	list?: boolean;
}

async function configCommand(options: ConfigOptions): Promise<void> {
	const config = getConfig();

	if (!config) {
		console.log(chalk.yellow("⚠️  AIDR not configured. Run 'aidr setup' first."));
		return;
	}

	if (options.get) {
		const value = getNestedValue(config, options.get);
		console.log(value !== undefined ? value : chalk.gray("(not set)"));
		return;
	}

	if (options.set && options.set.length >= 2) {
		const [key, ...valueParts] = options.set;
		const value = valueParts.join(" ");
		setNestedValue(config, key, value);
		updateConfig(config);
		console.log(chalk.green(`✅ Set ${key} = ${value}`));
		return;
	}

	if (options.set && options.set.length === 1) {
		console.log(chalk.yellow("⚠️  Usage: aidr config -s <key> <value>"));
		return;
	}

	if (options.list) {
		console.log(chalk.blue("\n🛡️  AIDR Configuration\n"));
		printConfig(config);
		return;
	}

	console.log(chalk.gray("Usage:"));
	console.log("  aidr config -g <key>       Get value");
	console.log("  aidr config -s <key> <val> Set value");
	console.log("  aidr config -l             List all\n");
}

function getNestedValue(obj: Config, path: string): unknown {
	return path.split(".").reduce<unknown>((current, key) => {
		if (current && typeof current === "object" && key in current) {
			return (current as Record<string, unknown>)[key];
		}
		return undefined;
	}, obj);
}

function setNestedValue(obj: Config, path: string, value: string): void {
	const keys = path.split(".");
	const last = keys.pop();
	if (last === undefined) return;
	let current: Record<string, unknown> = obj as unknown as Record<string, unknown>;

	for (const key of keys) {
		if (!(key in current) || typeof current[key] !== "object") {
			current[key] = {};
		}
		current = current[key] as Record<string, unknown>;
	}

	current[last] = value;
}

function printConfig(config: Config, prefix = ""): void {
	for (const [key, value] of Object.entries(config)) {
		const fullKey = prefix ? `${prefix}.${key}` : key;
		if (typeof value === "object" && value !== null) {
			printConfig(value as Config, fullKey);
		} else {
			console.log(`  ${fullKey}: ${chalk.gray(String(value))}`);
		}
	}
}

export default configCommand;
