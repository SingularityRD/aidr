import { ConfigSchema, escapeTerminalText } from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { type Config, getConfig, replaceConfig } from "../utils/config-manager.js";
import {
	configPathParts,
	containsSecretConfigValue,
	displayConfigValue,
	isKnownConfigPath,
	isSecretConfigPath,
	parseConfigValue,
} from "../utils/config-values.js";
import {
	confirmOperatorAction,
	type OperatorCommandDeps,
	OperatorConfirmationError,
} from "../utils/operator-confirm.js";
import { isProtectionTightening } from "../utils/protection-change.js";
import { readHiddenInput } from "../utils/secret-prompt.js";

interface ConfigOptions {
	get?: string;
	set?: string[];
	list?: boolean;
	yes?: boolean;
}

async function configCommand(
	options: ConfigOptions,
	deps: OperatorCommandDeps = {},
): Promise<void> {
	let config: Config | null;
	try {
		config = getConfig();
	} catch {
		console.error(ct("config.unreadable"));
		process.exitCode = 1;
		return;
	}

	if (!config) {
		console.log(ct("config.notConfigured"));
		process.exitCode = 1;
		return;
	}

	if (options.get) {
		let parts: string[];
		try {
			parts = configPathParts(options.get);
		} catch {
			console.error("Invalid configuration path.");
			process.exitCode = 1;
			return;
		}
		if (!isKnownConfigPath(ConfigSchema, parts)) {
			console.error(
				`Unknown configuration key: ${escapeTerminalText(options.get)}. List the keys with 'aidr config -l'.`,
			);
			process.exitCode = 1;
			return;
		}
		try {
			// A field absent from config.json is still in effect at its schema
			// default (e.g. `mode` is "local"), so report the effective value.
			const value =
				getNestedValue(config, options.get) ?? getNestedValue(effectiveConfig(config), options.get);
			console.log(
				value !== undefined ? displayConfigValue(options.get, value) : ct("config.notSet"),
			);
		} catch {
			console.error(ct("config.invalidPath"));
			process.exitCode = 1;
		}
		return;
	}

	if (options.set && options.set.length > 0) {
		const [key, ...valueParts] = options.set;
		const secret = isSecretConfigPath(key);
		if (secret && valueParts.length > 0) {
			console.error(ct("config.secretArg"));
			process.exitCode = 1;
			return;
		}
		if (!secret && valueParts.length === 0) {
			console.log(ct("config.setUsage"));
			process.exitCode = 1;
			return;
		}

		// The value in effect before the change (stored, else its schema default),
		// captured before `setNestedValue` mutates the loaded config.
		let before: unknown;
		try {
			before = getNestedValue(config, key) ?? getNestedValue(effectiveConfig(config), key);
		} catch {
			console.error(ct("config.invalidPath"));
			process.exitCode = 1;
			return;
		}

		let value: unknown;
		if (secret) {
			try {
				value = await readHiddenInput(ct("config.secretPrompt"));
			} catch (error: unknown) {
				console.error(error instanceof Error ? error.message : ct("config.secretReadFailed"));
				process.exitCode = 1;
				return;
			}
		} else {
			value = parseConfigValue(valueParts.join(" "));
			if (containsSecretConfigValue(value)) {
				console.error(ct("config.secretInObject"));
				process.exitCode = 1;
				return;
			}
		}
		try {
			setNestedValue(config, key, value);
		} catch {
			console.error(ct("config.unknownField"));
			process.exitCode = 1;
			return;
		}
		const checked = ConfigSchema.safeParse(config);
		if (!checked.success) {
			console.error(ct("config.invalid"));
			// Name the allowed values, so the operator does not have to look them up.
			for (const line of invalidChoiceLines(checked.error.issues, value)) console.error(line);
			process.exitCode = 1;
			return;
		}
		const after = getNestedValue(checked.data as unknown as Config, key);
		if (after === undefined) {
			console.error(ct("config.unknownFieldOnly"));
			process.exitCode = 1;
			return;
		}
		// Anything that is not provably a tightening (heuristics off, a disabled
		// threat, a lower sensitivity, a check or policy off, a replaced endpoint
		// or credential) is an operator-only change, confirmed exactly like
		// `aidr allowlist add`, so an agent cannot switch protection off itself.
		if (!isProtectionTightening(key, before, after)) {
			try {
				await confirmOperatorAction({
					relaxesProtection: true,
					prompt: [
						ct("config.confirmTitle"),
						`  ${escapeTerminalText(key)}: ${describeForPrompt(key, before)} -> ${describeForPrompt(key, after)}`,
						ct("config.confirmEffect"),
					].join("\n"),
					word: "change",
					yes: options.yes,
					env: deps.env,
					streams: deps.streams,
				});
			} catch (error) {
				console.error(
					ct("config.noChanges", {
						error: error instanceof OperatorConfirmationError ? error.message : String(error),
					}),
				);
				process.exitCode = 1;
				return;
			}
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
			console.error(ct("config.saveFailed"));
			process.exitCode = 1;
			return;
		}
		console.log(ct("config.set", { key, value: displayConfigValue(key, value) }));
		return;
	}

	if (options.list) {
		console.log(`\n${ct("config.listTitle")}\n`);
		printConfig(config);
		return;
	}

	console.log(ct("config.usage"));
	console.log(ct("config.usageGet"));
	console.log(ct("config.usageSet"));
	console.log(ct("config.usageSecret"));
	console.log(`${ct("config.usageList")}\n`);
}

/** A schema issue that carries its allowed values (an enum such as `sensitivity`). */
interface ChoiceIssue {
	path: (string | number)[];
	options?: readonly unknown[];
	values?: readonly unknown[];
	received?: unknown;
}

/** One line per rejected enum value, naming the values that are accepted. */
function invalidChoiceLines(issues: readonly ChoiceIssue[], given?: unknown): string[] {
	return issues.flatMap((issue) => {
		const choices = issue.options ?? issue.values;
		if (!Array.isArray(choices) || choices.length === 0) return [];
		return [
			ct("config.invalidChoice", {
				key: escapeTerminalText(issue.path.join(".")),
				value: escapeTerminalText(String(issue.received ?? given)),
				choices: choices.map(String).join(", "),
			}),
		];
	});
}

/**
 * A value as the operator should see it in the confirmation: secrets redacted,
 * arrays of plain values (e.g. `disabled_threats`) spelled out (bounded),
 * other objects summarised — they may hold nested secrets — and control
 * characters escaped.
 */
function describeForPrompt(key: string, value: unknown): string {
	const plainArray =
		Array.isArray(value) &&
		value.every((item) => ["string", "number", "boolean"].includes(typeof item));
	if (isSecretConfigPath(key) || !plainArray) {
		return escapeTerminalText(displayConfigValue(key, value));
	}
	const json = JSON.stringify(value) ?? String(value);
	return escapeTerminalText(json.length > 400 ? `${json.slice(0, 400)}…` : json);
}

/** The config as the runtime sees it: stored values over schema defaults. */
function effectiveConfig(config: Config): Config {
	const parsed = ConfigSchema.safeParse(config);
	return (parsed.success ? parsed.data : ConfigSchema.parse({})) as unknown as Config;
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
	if (!Object.hasOwn(ConfigSchema.shape, keys[0]))
		throw new Error("Unknown or read-only configuration field");
	const last = keys.pop();
	if (last === undefined) return;
	let current: Record<string, unknown> = obj as unknown as Record<string, unknown>;

	for (const key of keys) {
		if (
			!Object.hasOwn(current, key) ||
			!current[key] ||
			typeof current[key] !== "object" ||
			Array.isArray(current[key])
		) {
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
