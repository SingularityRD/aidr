import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { resolvePath } from "@singularityrd/aidr-core";

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

function fileMentions(path: string, needles: string[]): boolean | null {
	const read = readText(path);
	if (read.unavailable) return null;
	if (read.value === null) return false;
	const raw = read.value.toLowerCase();
	return needles.some((n) => raw.includes(n.toLowerCase()));
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
	detail = "AIDR could not read the host registration; installation state is unknown",
): ConnectorStatus {
	return {
		id,
		label,
		state: "unavailable",
		detail,
		evidence,
		remedy: "Check the file permissions and rerun 'aidr status' as the host user",
	};
}

/**
 * Claude Code registers plugins through `~/.claude/settings.json` and/or an
 * enabled-plugins directory. A hook entry naming the aidr bundle is the signal
 * that enforcement will actually run.
 */
function detectClaudeCode(home: string): ConnectorStatus {
	const settings = join(home, ".claude", "settings.json");
	const pluginsDir = join(home, ".claude", "plugins");
	const evidence = [settings, pluginsDir];

	const settingsRead = readJson(settings);
	if (settingsRead.unavailable) return unavailableStatus("claude-code", "Claude Code", evidence);
	const parsed = settingsRead.value as { disableAllHooks?: boolean; enabledPlugins?: Record<string, unknown>; hooks?: { PreToolUse?: Array<{ hooks?: Array<{ type?: string; command?: string }> }> } } | null;
	const enabled = Object.entries(parsed?.enabledPlugins ?? {}).some(([name, value]) => /aidr|singularity/i.test(name) && value === true);
	const hooked = Array.isArray(parsed?.hooks?.PreToolUse) && parsed.hooks.PreToolUse.some((entry) => Array.isArray(entry.hooks) && entry.hooks.some((hook) => hook.type === "command" && typeof hook.command === "string" && /aidr|singularity/i.test(hook.command)));
	if (parsed?.disableAllHooks !== true && (enabled || hooked)) {
		return {
			id: "claude-code",
			label: "Claude Code",
			state: "installed",
			detail: "AIDR plugin enabled or PreToolUse handler registered; host execution unverified",
			evidence,
		};
	}

	if (existsSync(settings)) {
		return {
			id: "claude-code",
			label: "Claude Code",
			state: "runtime_present_not_installed",
			detail: "~/.claude/settings.json exists but does not reference AIDR",
			evidence,
			remedy: "Verify the publisher-signed release bundle before extracting the Claude plugin, add the extracted directory as a marketplace, then install aidr@aidr",
		};
	}

	return {
		id: "claude-code",
		label: "Claude Code",
		state: "not_detected",
		detail: "no ~/.claude/settings.json found",
		evidence,
		remedy: "Install the AIDR plugin from the Claude Code marketplace",
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
		if (!manifest.value || typeof manifest.value !== "object" || Array.isArray(manifest.value)) continue;
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
			detail: `extension package found: ${hits.join(", ")}; activation and hook execution unverified`,
			evidence,
		};
	}
	if (existsSync(join(home, id === "cursor" ? ".cursor" : ".vscode"))) {
		return {
			id,
			label,
			state: "runtime_present_not_installed",
			detail: `${label} config directory exists but no AIDR extension was found`,
			evidence,
			remedy: "Install the VSIX, then run 'Singularity AIDR: Enable protection' from the command palette",
		};
	}
	return {
		id,
		label,
		state: "not_detected",
		detail: `no ${label} configuration directory found`,
		evidence,
	};
}

/** OpenClaw loads plugins listed in its own config file. */
function detectOpenClaw(home: string): ConnectorStatus {
	const cfg = join(home, ".openclaw", "openclaw.json");
	const evidence = [cfg];
	const mentionsAidr = fileMentions(cfg, ["aidr", "singularity"]);
	if (mentionsAidr === null) return unavailableStatus("openclaw", "OpenClaw", evidence);
	if (mentionsAidr) {
		return {
			id: "openclaw",
			label: "OpenClaw",
			state: "installed",
			detail: "AIDR plugin listed in ~/.openclaw/openclaw.json",
			evidence,
		};
	}
	if (existsSync(cfg)) {
		return {
			id: "openclaw",
			label: "OpenClaw",
			state: "runtime_present_not_installed",
			detail: "~/.openclaw/openclaw.json exists but does not list AIDR",
			evidence,
			remedy: "Install the approved version: openclaw plugins install npm:@singularityrd/aidr-openclaw@VERSION (replace VERSION with the exact approved release version)",
		};
	}
	return {
		id: "openclaw",
		label: "OpenClaw",
		state: "not_detected",
		detail: "no ~/.openclaw/openclaw.json found",
		evidence,
	};
}

/** OpenCode discovers plugins from a plugins directory. */
function detectOpenCode(home: string): ConnectorStatus {
	const configHome = process.env.XDG_CONFIG_HOME?.trim() || join(home, ".config");
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
	const config = configRead.value && typeof configRead.value === "object" && !Array.isArray(configRead.value)
		? (configRead.value as Record<string, unknown>)
		: {};
	const manifest = packageRead.value && typeof packageRead.value === "object" && !Array.isArray(packageRead.value)
		? (packageRead.value as Record<string, unknown>)
		: {};
	const dependencies = manifest.dependencies && typeof manifest.dependencies === "object" && !Array.isArray(manifest.dependencies)
		? (manifest.dependencies as Record<string, unknown>)
		: {};
	const configuredNpmPackage = Array.isArray(config.plugin) && config.plugin.includes("@singularityrd/aidr-opencode");
	const installedNpmPackage = typeof dependencies["@singularityrd/aidr-opencode"] === "string";
	if (configuredNpmPackage && installedNpmPackage) {
		return {
			id: "opencode",
			label: "OpenCode",
			state: "installed",
			detail: "AIDR npm plugin is listed in OpenCode config; host execution unverified",
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
			detail: `AIDR local plugin file found: ${localHits.join(", ")}; host execution unverified`,
			evidence,
		};
	}
	return {
		id: "opencode",
		label: "OpenCode",
		state: existsSync(configDir) ? "runtime_present_not_installed" : "not_detected",
		detail: existsSync(configDir)
			? "OpenCode config contains no registered AIDR plugin"
			: "no OpenCode config directory found",
		evidence,
		remedy: "Add the approved @singularityrd/aidr-opencode version to package.json and register it in opencode.json",
	};
}

/** Codex registers hooks in config.toml and/or hooks.json. */
function detectCodex(home: string): ConnectorStatus {
	const cfg = join(home, ".codex", "config.toml");
	const hooksJson = join(home, ".codex", "hooks.json");
	const evidence = [cfg, hooksJson];

	// Codex requires the PascalCase event name; a lower-case table parses as valid
	// TOML and is then silently ignored, so checking for the substring "hooks" is
	// not enough to claim the connector will run.
	if (existsSync(cfg)) {
		const configRead = readText(cfg);
		if (configRead.unavailable) return unavailableStatus("codex", "Codex", evidence);
		const raw = configRead.value ?? "";
		const registered = raw.split(/(?=^[ \t]*\[)/m).some((section) => {
			if (!/^[ \t]*\[\[hooks\.PreToolUse\.hooks\]\][ \t]*(?:#.*)?$/m.test(section)) return false;
			if (!/^[ \t]*type[ \t]*=[ \t]*["']command["'][ \t]*(?:#.*)?$/m.test(section)) return false;
			const command = section.match(
				/^[ \t]*command[ \t]*=[ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)')[ \t]*(?:#.*)?$/m,
			);
			return /\baidr-codex-hook\b/i.test(command?.[1] ?? command?.[2] ?? "");
		});
		if (registered) {
			return {
				id: "codex",
				label: "Codex",
				state: "installed",
				detail:
					"AIDR PreToolUse handler registered in ~/.codex/config.toml; host trust and execution unverified",
				evidence,
			};
		}
		if (/hooks\.pre_tool_use/i.test(raw)) {
			return {
				id: "codex",
				label: "Codex",
				state: "installed_but_degraded",
				detail:
					"config.toml uses a lower-case hooks.pre_tool_use table, which Codex parses and then IGNORES - the hook will never run",
				evidence,
				remedy: "Rename the table to [[hooks.PreToolUse]] with a nested [[hooks.PreToolUse.hooks]] handler",
			};
		}
	}
	const hooksRead = readJson(hooksJson);
	if (hooksRead.unavailable) return unavailableStatus("codex", "Codex", evidence);
	const parsed = hooksRead.value as {
		hooks?: { PreToolUse?: Array<{ hooks?: Array<{ type?: string; command?: string }> }> };
	} | null;
	const registered =
		Array.isArray(parsed?.hooks?.PreToolUse) &&
		parsed.hooks.PreToolUse.some(
			(entry) =>
				Array.isArray(entry?.hooks) &&
				entry.hooks.some(
					(hook) =>
						hook?.type === "command" &&
						typeof hook.command === "string" &&
						/\baidr-codex-hook\b/i.test(hook.command),
				),
		);
	if (registered) {
		return {
			id: "codex",
			label: "Codex",
			state: "installed",
			detail:
				"AIDR PreToolUse handler registered in ~/.codex/hooks.json; host trust and execution unverified",
			evidence,
		};
	}
	if (existsSync(join(home, ".codex"))) {
		return {
			id: "codex",
			label: "Codex",
			state: "runtime_present_not_installed",
			detail: "Codex directory exists but registers no AIDR hook",
			evidence,
			remedy: "Add [[hooks.PreToolUse]] with a command handler pointing at aidr-codex-hook",
		};
	}
	return {
		id: "codex",
		label: "Codex",
		state: "not_detected",
		detail: "no ~/.codex configuration found",
		evidence,
	};
}

/**
 * Inspect every supported runtime. A caller must present the result as measured
 * state, including the evidence paths, rather than as a configuration claim.
 */
export function detectConnectorStatuses(home: string = resolvePath("~")): ConnectorStatus[] {
	return [
		detectClaudeCode(home),
		detectEditor("cursor", "Cursor", join(home, ".cursor", "extensions"), home),
		detectEditor("vscode", "VS Code", join(home, ".vscode", "extensions"), home),
		detectOpenClaw(home),
		detectOpenCode(home),
		detectCodex(home),
	];
}

/** True when at least one registration/package was detected; not execution proof. */
export function anyConnectorInstalled(statuses: ConnectorStatus[]): boolean {
	return statuses.some((s) => s.state === "installed");
}
