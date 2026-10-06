import { ConfigSchema } from "@singularityrd/aidr-core";
import { type Config, getConfig, replaceConfig } from "../utils/config-manager.js";
import {
	configPathParts,
	containsSecretConfigValue,
	displayConfigValue,
	isSecretConfigPath,
	parseConfigValue,
} from "../utils/config-values.js";
import { readHiddenInput } from "../utils/secret-prompt.js";

interface ConfigOptions {
	get?: string;
	set?: string[];
	list?: boolean;
}

async function configCommand(options: ConfigOptions): Promise<void> {
	let config: Config | null;
	try {
		config = getConfig();
	} catch {
		console.error("Local configuration could not be read. Check its permissions, JSON and credential store.");
		process.exitCode = 1;
		return;
	}

	if (!config) {
		console.log("⚠️  AIDR not configured. Run 'aidr setup' first.");
		process.exitCode = 1;
		return;
	}

	if (options.get) {
		try {
			const value = getNestedValue(config, options.get);
			console.log(value !== undefined ? displayConfigValue(options.get, value) : "(not set)");
		} catch {
			console.error("Invalid configuration path.");
			process.exitCode = 1;
		}
		return;
	}

	if (options.set && options.set.length > 0) {
		const [key, ...valueParts] = options.set;
		const secret = isSecretConfigPath(key);
		if (secret && valueParts.length > 0) {
			console.error(
				"Secret values cannot be passed as command-line arguments. Rerun without the value argument to enter it at the hidden prompt.",
			);
			process.exitCode = 1;
			return;
		}
		if (!secret && valueParts.length === 0) {
			console.log("⚠️  Usage: aidr config -s <key> <value> (secret values are prompted securely)");
			process.exitCode = 1;
			return;
		}

		let value: unknown;
		if (secret) {
			try {
				value = await readHiddenInput("Secret value: ");
			} catch (error: unknown) {
				console.error(error instanceof Error ? error.message : "Could not read secret input.");
				process.exitCode = 1;
				return;
			}
		} else {
			value = parseConfigValue(valueParts.join(" "));
			if (containsSecretConfigValue(value)) {
				console.error("Secret fields cannot be supplied inside object arguments. Set each secret field through its hidden prompt.");
				process.exitCode = 1;
				return;
			}
		}
		try {
			setNestedValue(config, key, value);
		} catch {
			console.error("Invalid or unknown configuration field; no changes saved.");
			process.exitCode = 1;
			return;
		}
		const checked = ConfigSchema.safeParse(config);
		if (!checked.success) {
			console.error("Invalid runtime configuration; no changes saved.");
			process.exitCode = 1;
			return;
		}
		if (getNestedValue(checked.data as unknown as Config, key) === undefined) {
			console.error("Unknown configuration field; no changes saved.");
			process.exitCode = 1;
			return;
		}
		// Persist only the schema-parsed runtime fields and the CLI's explicit
		// metadata. Spreading the full input here would retain unknown root keys,
		// even though Zod intentionally stripped them from `checked.data`.
		const normalized = {
			...checked.data,
			apiKey: config.apiKey,
			environment: config.environment,
			version: config.version,
			createdAt: config.createdAt,
			hooksInstalled: config.hooksInstalled,
			agentConfigured: config.agentConfigured,
			secretStore: config.secretStore,
			secretRef: config.secretRef,
			secretRotatedAt: config.secretRotatedAt,
			secretRevokedAt: config.secretRevokedAt,
		} as unknown as Config;
		try {
			replaceConfig(normalized);
		} catch {
			console.error("Configuration could not be saved. Check its permissions and credential store, then retry.");
			process.exitCode = 1;
			return;
		}
		console.log(`✅ Set ${key} = ${displayConfigValue(key, value)}`);
		return;
	}

	if (options.list) {
		console.log("\n🛡️  AIDR Configuration\n");
		printConfig(config);
		return;
	}

	console.log("Usage:");
	console.log("  aidr config -g <key>       Get value");
	console.log("  aidr config -s <key> <val> Set non-secret value");
	console.log("  aidr config -s <secret-key> Enter secret at hidden prompt");
	console.log("  aidr config -l             List all\n");
}

function getNestedValue(obj: Config, path: string): unknown {
	return configPathParts(path).reduce<unknown>((current, key) => {
		if (current && typeof current === "object" && Object.hasOwn(current, key)) {
			return (current as Record<string, unknown>)[key];
		}
		return undefined;
	}, obj);
}

function setNestedValue(obj: Config, path: string, value: unknown): void {
	const keys = configPathParts(path);
	if (!Object.hasOwn(ConfigSchema.shape, keys[0])) throw new Error("Unknown or read-only configuration field");
	const last = keys.pop();
	if (last === undefined) return;
	let current: Record<string, unknown> = obj as unknown as Record<string, unknown>;

	for (const key of keys) {
		if (!Object.hasOwn(current, key) || !current[key] || typeof current[key] !== "object" || Array.isArray(current[key])) {
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
			console.log(`  ${fullKey}: ${displayConfigValue(fullKey, value)}`);
		}
	}
}

export default configCommand;
