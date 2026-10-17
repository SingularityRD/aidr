import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";
import { resolvePath, VERSION } from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { type MachineHookState, machineHookStatus } from "./machine-hooks.js";

/**
 * Detect whether a connector is actually installed for each supported runtime.
 *
 * ## Why this exists
 *
 * `aidr status` used to print `Hooks: ${config.hooksInstalled}` — a value that
 * was written once as `false` by setup and never updated, so it reported "not
 * installed" on a correctly installed machine. It also printed a masked API key
 * unconditionally, showing `****` for a key that did not exist.
 *
 * The product's recurring failure class is reporting a state that was never
 * measured, so this module measures. Every claim it returns carries the evidence
 * that produced it (a file path and, where relevant, the config key found), so
 * the status output can show the user WHY it believes a connector is present
 * rather than asserting it.
 */

export type ConnectorState =
	/** Registration or package found; host execution has not been attested. */
	| "installed"
	/** Evidence could not be read, so installation state is unknown. */
	| "unavailable"
	/** The runtime is present but AIDR is not registered with it. */
	| "runtime_present_not_installed"
	/** Neither the runtime nor AIDR was found. */
	| "not_detected"
	/** Found, but the registration is present and unusable (e.g. rule data missing). */
	| "installed_but_degraded";

export interface ConnectorStatus {
	id: "claude-code" | "cursor" | "vscode" | "openclaw" | "opencode" | "codex";
	label: string;
	state: ConnectorState;
	/** Human-readable reason for the state, always concrete. */
	detail: string;
	/** Absolute paths inspected, so the user can verify the claim. */
	evidence: string[];
	/** What the user must do next, when action is required. */
	remedy?: string;
}

interface FileRead<T> {
	value: T | null;
	unavailable: boolean;
}

function isMissing(error: unknown): boolean {
	const code = (error as NodeJS.ErrnoException | undefined)?.code;
	return code === "ENOENT" || code === "ENOTDIR";
}

function readJson(path: string): FileRead<unknown> {
	try {
		return { value: JSON.parse(readFileSync(path, "utf-8")), unavailable: false };
	} catch (error) {
		return { value: null, unavailable: !isMissing(error) };
	}
}

function readText(path: string): FileRead<string> {
	try {
		return { value: readFileSync(path, "utf-8"), unavailable: false };
	} catch (error) {
		return { value: null, unavailable: !isMissing(error) };
	}
}

function listDirSafe(dir: string): FileRead<string[]> {
	try {
		return { value: readdirSync(dir) as string[], unavailable: false };
	} catch (error) {
		return { value: [], unavailable: !isMissing(error) };
	}
}

function unavailableStatus(
	id: ConnectorStatus["id"],
	label: string,
	evidence: string[],
	detail = ct("conn.unavailable"),
): ConnectorStatus {
	return {
		id,
		label,
		state: "unavailable",
		detail,
		evidence,
		remedy: ct("conn.unavailableRemedy"),
	};
}

/**
 * A registration in the host's system-wide managed policy (aidr machine-hooks)
 * applies to every user and cannot be switched off from user settings, so it
 * wins over whatever the user's own files say.
 */
function machinePolicyStatus(
	id: "claude-code" | "codex",
	label: string,
	machine: MachineHookState | undefined,
): ConnectorStatus | null {
	if (!machine?.registered) return null;
	return {
		id,
		label,
		state: "installed",
		detail: ct("conn.machinePolicy", {
			path: machine.path,
			locked: machine.otherHooksLocked ? ct("conn.machinePolicyLocked") : "",
		}),
		evidence: [machine.path],
	};
}

/**
 * Claude Code registers plugins through `~/.claude/settings.json` and/or an
 * enabled-plugins directory. A hook entry naming the aidr bundle is the signal
 * that enforcement will actually run.
 */
function detectClaudeCode(home: string, machine?: MachineHookState): ConnectorStatus {
	const settings = join(home, ".claude", "settings.json");
	const pluginsDir = join(home, ".claude", "plugins");
	const evidence = [settings, pluginsDir];
	const fromPolicy = machinePolicyStatus("claude-code", "Claude Code", machine);
	if (fromPolicy) return fromPolicy;

	const settingsRead = readJson(settings);
	if (settingsRead.unavailable) return unavailableStatus("claude-code", "Claude Code", evidence);
	const parsed = settingsRead.value as {
		disableAllHooks?: boolean;
		enabledPlugins?: Record<string, unknown>;
		hooks?: { PreToolUse?: Array<{ hooks?: Array<{ type?: string; command?: string }> }> };
	} | null;
	const enabled = Object.entries(parsed?.enabledPlugins ?? {}).some(
		([name, value]) => /aidr|singularity/i.test(name) && value === true,
	);
	const hooked =
		Array.isArray(parsed?.hooks?.PreToolUse) &&
		parsed.hooks.PreToolUse.some(
			(entry) =>
				Array.isArray(entry?.hooks) &&
				entry.hooks.some(
					(hook) =>
						hook?.type === "command" &&
						typeof hook.command === "string" &&
						/aidr|singularity/i.test(hook.command),
				),
		);
	if (parsed?.disableAllHooks !== true && (enabled || hooked)) {
		return {
			id: "claude-code",
			label: "Claude Code",
			state: "installed",
			detail: ct("conn.claude.installed"),
			evidence,
		};
	}

	// A fresh Claude Code install has ~/.claude/ and ~/.claude.json but no
	// settings.json until the user changes a setting.
	const present =
		existsSync(settings) ||
		existsSync(join(home, ".claude")) ||
		existsSync(join(home, ".claude.json"));
	if (present) {
		return {
			id: "claude-code",
			label: "Claude Code",
			state: "runtime_present_not_installed",
			detail: existsSync(settings)
				? ct("conn.claude.present")
				: ct("conn.claude.installedNoSettings"),
			evidence,
			remedy: ct("conn.claude.presentRemedy"),
		};
	}

	return {
		id: "claude-code",
		label: "Claude Code",
		state: "not_detected",
		detail: ct("conn.claude.none"),
		evidence,
		remedy: ct("conn.claude.noneRemedy"),
	};
}

/** Cursor and VS Code both register extensions under the editor's extensions dir. */
function detectEditor(
	id: "cursor" | "vscode",
	label: string,
	extDir: string,
	home: string,
): ConnectorStatus {
	const evidence = [extDir];
	const listing = listDirSafe(extDir);
	if (listing.unavailable) return unavailableStatus(id, label, evidence);
	const expectedName = id === "cursor" ? "aidr-cursor" : "aidr-vscode";
	const hits: string[] = [];
	for (const name of listing.value ?? []) {
		if (!/aidr|singularity/i.test(name)) continue;
		const manifest = readJson(join(extDir, name, "package.json"));
		if (manifest.unavailable) return unavailableStatus(id, label, evidence);
		if (!manifest.value || typeof manifest.value !== "object" || Array.isArray(manifest.value))
			continue;
		const value = manifest.value as Record<string, unknown>;
		if (
			typeof value.publisher === "string" &&
			value.publisher.toLowerCase() === "singularityrd" &&
			value.name === expectedName &&
			typeof value.version === "string"
		) {
			hits.push(name);
		}
	}
	if (hits.length > 0) {
		return {
			id,
			label,
			state: "installed",
			detail: ct("conn.editor.installed", { packages: hits.join(", ") }),
			evidence,
		};
	}
	if (existsSync(join(home, id === "cursor" ? ".cursor" : ".vscode"))) {
		return {
			id,
			label,
			state: "runtime_present_not_installed",
			detail: ct("conn.editor.present", { label }),
			evidence,
			remedy: ct("conn.editor.presentRemedy"),
		};
	}
	return {
		id,
		label,
		state: "not_detected",
		detail: ct("conn.editor.none", { label }),
		evidence,
	};
}

/** OpenClaw loads plugins listed in its own config file. */
function detectOpenClaw(home: string): ConnectorStatus {
	const cfg = join(home, ".openclaw", "openclaw.json");
	const evidence = [cfg];
	const read = readJson(cfg);
	if (read.unavailable) return unavailableStatus("openclaw", "OpenClaw", evidence);
	const config = read.value as {
		plugins?: {
			enabled?: boolean;
			allow?: string[];
			deny?: string[];
			entries?: Record<string, { enabled?: boolean } | null>;
		};
	} | null;
	const plugins = config?.plugins;
	const entry = plugins?.entries?.["aidr-openclaw"];
	const registered = !!entry && typeof entry === "object" && !Array.isArray(entry);
	const enabled =
		registered &&
		plugins?.enabled !== false &&
		entry.enabled !== false &&
		(!Array.isArray(plugins?.allow) || plugins.allow.includes("aidr-openclaw")) &&
		(!Array.isArray(plugins?.deny) || !plugins.deny.includes("aidr-openclaw"));
	if (registered) {
		return {
			id: "openclaw",
			label: "OpenClaw",
			state: enabled ? "installed" : "installed_but_degraded",
			detail: enabled ? ct("conn.openclaw.installed") : ct("conn.openclaw.disabled"),
			evidence,
			...(!enabled
				? {
						remedy: ct("conn.openclaw.disabledRemedy"),
					}
				: {}),
		};
	}
	if (existsSync(cfg)) {
		return {
			id: "openclaw",
			label: "OpenClaw",
			state: "runtime_present_not_installed",
			detail: ct("conn.openclaw.present"),
			evidence,
			remedy: ct("conn.openclaw.presentRemedy", { version: VERSION }),
		};
	}
	return {
		id: "openclaw",
		label: "OpenClaw",
		state: "not_detected",
		detail: ct("conn.openclaw.none"),
		evidence,
	};
}

/** OpenCode discovers plugins from a plugins directory. */
function detectOpenCode(home: string, env: NodeJS.ProcessEnv): ConnectorStatus {
	const configHome = env.XDG_CONFIG_HOME?.trim() || join(home, ".config");
	const configDir = join(configHome, "opencode");
	const dir = join(configDir, "plugins");
	const globalConfig = join(configDir, "opencode.json");
	const packageManifest = join(configDir, "package.json");
	const evidence = [globalConfig, packageManifest, dir];
	const configRead = readJson(globalConfig);
	const packageRead = readJson(packageManifest);
	if (configRead.unavailable || packageRead.unavailable) {
		return unavailableStatus("opencode", "OpenCode", evidence);
	}
	const config =
		configRead.value && typeof configRead.value === "object" && !Array.isArray(configRead.value)
			? (configRead.value as Record<string, unknown>)
			: {};
	const manifest =
		packageRead.value && typeof packageRead.value === "object" && !Array.isArray(packageRead.value)
			? (packageRead.value as Record<string, unknown>)
			: {};
	const dependencies =
		manifest.dependencies &&
		typeof manifest.dependencies === "object" &&
		!Array.isArray(manifest.dependencies)
			? (manifest.dependencies as Record<string, unknown>)
			: {};
	const configuredNpmPackage =
		Array.isArray(config.plugin) && config.plugin.includes("@singularityrd/aidr-opencode");
	const installedNpmPackage = typeof dependencies["@singularityrd/aidr-opencode"] === "string";
	if (configuredNpmPackage && installedNpmPackage) {
		return {
			id: "opencode",
			label: "OpenCode",
			state: "installed",
			detail: ct("conn.opencode.npm"),
			evidence,
		};
	}
	const listing = listDirSafe(dir);
	if (listing.unavailable) return unavailableStatus("opencode", "OpenCode", evidence);
	const localHits: string[] = [];
	for (const name of listing.value ?? []) {
		if (!/aidr|singularity/i.test(name)) continue;
		const path = join(dir, name);
		let isFile = false;
		try {
			isFile = lstatSync(path).isFile();
		} catch (error) {
			if (!isMissing(error)) return unavailableStatus("opencode", "OpenCode", evidence);
		}
		if (!isFile) continue;
		const source = readText(path);
		if (source.unavailable) return unavailableStatus("opencode", "OpenCode", evidence);
		if (source.value?.includes("Singularity AIDR OpenCode plugin")) localHits.push(name);
	}
	if (localHits.length > 0) {
		return {
			id: "opencode",
			label: "OpenCode",
			state: "installed",
			detail: ct("conn.opencode.local", { files: localHits.join(", ") }),
			evidence,
		};
	}
	return {
		id: "opencode",
		label: "OpenCode",
		state: existsSync(configDir) ? "runtime_present_not_installed" : "not_detected",
		detail: existsSync(configDir) ? ct("conn.opencode.present") : ct("conn.opencode.none"),
		evidence,
		remedy: ct("conn.opencode.remedy"),
	};
}

/**
 * The program a registered hook command starts, when it cannot be found. Codex
 * runs a hook it cannot start as if it allowed the call (fail-open), so a
 * registration whose program is gone is degraded, not installed.
 */
function missingHookProgram(command: string, env: NodeJS.ProcessEnv): string | null {
	const match = command.trim().match(/^"([^"]+)"|^'([^']+)'|^(\S+)/);
	const program = match?.[1] ?? match?.[2] ?? match?.[3];
	if (!program) return null;
	if (isAbsolute(program) || /^[A-Za-z]:[\\/]/.test(program)) {
		return existsSync(program) ? null : program;
	}
	const extensions =
		process.platform === "win32" ? ["", ...(env.PATHEXT ?? ".EXE;.CMD;.BAT").split(";")] : [""];
	const found = (env.PATH ?? env.Path ?? "")
		.split(delimiter)
		.filter(Boolean)
		.some((dir) => extensions.some((ext) => existsSync(join(dir, program + ext))));
	return found ? null : program;
}

function codexInstalled(
	source: string,
	command: string,
	env: NodeJS.ProcessEnv,
	evidence: string[],
): ConnectorStatus {
	const missing = missingHookProgram(command, env);
	if (missing) {
		return {
			id: "codex",
			label: "Codex",
			state: "installed_but_degraded",
			detail: ct("conn.codex.programMissing", { source, program: missing }),
			evidence,
			remedy: ct("conn.codex.programMissingRemedy"),
		};
	}
	return {
		id: "codex",
		label: "Codex",
		state: "installed",
		detail: ct(source.endsWith("config.toml") ? "conn.codex.toml" : "conn.codex.json"),
		evidence,
	};
}

/** Codex registers hooks in config.toml and/or hooks.json. */
function detectCodex(
	home: string,
	machine?: MachineHookState,
	env: NodeJS.ProcessEnv = process.env,
): ConnectorStatus {
	const cfg = join(home, ".codex", "config.toml");
	const hooksJson = join(home, ".codex", "hooks.json");
	const evidence = [cfg, hooksJson];
	const fromPolicy = machinePolicyStatus("codex", "Codex", machine);
	if (fromPolicy) return fromPolicy;

	// Codex requires the PascalCase event name; a lower-case table parses as valid
	// TOML and is then silently ignored, so checking for the substring "hooks" is
	// not enough to claim the connector will run.
	if (existsSync(cfg)) {
		const configRead = readText(cfg);
		if (configRead.unavailable) return unavailableStatus("codex", "Codex", evidence);
		const raw = configRead.value ?? "";
		let registered: string | undefined;
		for (const section of raw.split(/(?=^[ \t]*\[)/m)) {
			if (!/^[ \t]*\[\[hooks\.PreToolUse\.hooks\]\][ \t]*(?:#.*)?$/m.test(section)) continue;
			if (!/^[ \t]*type[ \t]*=[ \t]*["']command["'][ \t]*(?:#.*)?$/m.test(section)) continue;
			const command = section.match(
				/^[ \t]*command[ \t]*=[ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)')[ \t]*(?:#.*)?$/m,
			);
			const value = command?.[1] ?? command?.[2] ?? "";
			if (/\baidr-codex-hook\b/i.test(value)) {
				registered = value.replaceAll('\\"', '"');
				break;
			}
		}
		if (registered !== undefined) {
			return codexInstalled("~/.codex/config.toml", registered, env, evidence);
		}
		if (/hooks\.pre_tool_use/i.test(raw)) {
			return {
				id: "codex",
				label: "Codex",
				state: "installed_but_degraded",
				detail: ct("conn.codex.lowercase"),
				evidence,
				remedy: ct("conn.codex.lowercaseRemedy"),
			};
		}
	}
	const hooksRead = readJson(hooksJson);
	if (hooksRead.unavailable) return unavailableStatus("codex", "Codex", evidence);
	const parsed = hooksRead.value as {
		hooks?: { PreToolUse?: Array<{ hooks?: Array<{ type?: string; command?: string }> }> };
	} | null;
	const registeredCommand = (
		Array.isArray(parsed?.hooks?.PreToolUse) ? parsed.hooks.PreToolUse : []
	)
		.flatMap((entry) => (Array.isArray(entry?.hooks) ? entry.hooks : []))
		.find(
			(hook) =>
				hook?.type === "command" &&
				typeof hook.command === "string" &&
				/\baidr-codex-hook\b/i.test(hook.command),
		)?.command;
	if (registeredCommand !== undefined) {
		return codexInstalled("~/.codex/hooks.json", registeredCommand, env, evidence);
	}
	if (existsSync(join(home, ".codex"))) {
		return {
			id: "codex",
			label: "Codex",
			state: "runtime_present_not_installed",
			detail: ct("conn.codex.present"),
			evidence,
			remedy: ct("conn.codex.presentRemedy"),
		};
	}
	return {
		id: "codex",
		label: "Codex",
		state: "not_detected",
		detail: ct("conn.codex.none"),
		evidence,
	};
}

/**
 * Inspect every supported runtime. A caller must present the result as measured
 * state, including the evidence paths, rather than as a configuration claim.
 */
export function detectConnectorStatuses(
	home: string = resolvePath("~"),
	env: NodeJS.ProcessEnv = process.env,
	machine: readonly MachineHookState[] = machineHookStatus(),
): ConnectorStatus[] {
	return [
		detectClaudeCode(
			home,
			machine.find((entry) => entry.host === "claude-code"),
		),
		detectEditor("cursor", "Cursor", join(home, ".cursor", "extensions"), home),
		detectEditor("vscode", "VS Code", join(home, ".vscode", "extensions"), home),
		detectOpenClaw(home),
		detectOpenCode(home, env),
		detectCodex(
			home,
			machine.find((entry) => entry.host === "codex"),
			env,
		),
	];
}

/** True when at least one registration/package was detected; not execution proof. */
export function anyConnectorInstalled(statuses: ConnectorStatus[]): boolean {
	return statuses.some((s) => s.state === "installed");
}
