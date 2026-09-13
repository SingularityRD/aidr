import { existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

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

function readJson(path: string): unknown {
	try {
		return JSON.parse(readFileSync(path, "utf-8"));
	} catch {
		return null;
	}
}

function fileMentions(path: string, needles: string[]): boolean {
	try {
		const raw = readFileSync(path, "utf-8").toLowerCase();
		return needles.some((n) => raw.includes(n.toLowerCase()));
	} catch {
		return false;
	}
}

function listDirSafe(dir: string): string[] {
	try {
		return readdirSync(dir) as string[];
	} catch {
		return [];
	}
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

	const parsed = readJson(settings) as { disableAllHooks?: boolean; enabledPlugins?: Record<string, unknown>; hooks?: { PreToolUse?: Array<{ hooks?: Array<{ type?: string; command?: string }> }> } } | null;
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
			remedy: "Add the AIDR marketplace plugin: /plugin marketplace add <repo>, then /plugin install aidr@aidr",
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
	const hits = listDirSafe(extDir).filter((n) => /aidr|singularity/i.test(n));
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
	if (existsSync(cfg) && fileMentions(cfg, ["aidr", "singularity"])) {
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
			remedy: "openclaw plugins install @singularityrd/aidr-openclaw",
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
	const dir = join(home, ".config", "opencode", "plugins");
	const evidence = [dir];
	const hits = listDirSafe(dir).filter((n) => /aidr|singularity/i.test(n));
	if (hits.length > 0) {
		return {
			id: "opencode",
			label: "OpenCode",
			state: "installed",
			detail: `plugin present: ${hits.join(", ")}`,
			evidence,
		};
	}
	return {
		id: "opencode",
		label: "OpenCode",
		state: existsSync(dir) ? "runtime_present_not_installed" : "not_detected",
		detail: existsSync(dir)
			? "the OpenCode plugins directory exists but contains no AIDR plugin"
			: "no ~/.config/opencode/plugins directory found",
		evidence,
		remedy: "Install @singularityrd/aidr-opencode into the OpenCode plugins directory",
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
		const raw = readFileSync(cfg, "utf-8");
		const hasPascalPreToolUse = /\[\[?\s*hooks\.PreToolUse/.test(raw);
		const mentionsAidr = /aidr/i.test(raw);
		if (hasPascalPreToolUse && mentionsAidr) {
			return {
				id: "codex",
				label: "Codex",
				state: "installed",
				detail: "hooks.PreToolUse registered in ~/.codex/config.toml",
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
	if (existsSync(hooksJson) && fileMentions(hooksJson, ["aidr", "singularity"])) {
		return {
			id: "codex",
			label: "Codex",
			state: "installed",
			detail: "AIDR hook registered in ~/.codex/hooks.json",
			evidence,
		};
	}
	if (existsSync(cfg) || existsSync(hooksJson)) {
		return {
			id: "codex",
			label: "Codex",
			state: "runtime_present_not_installed",
			detail: "Codex configuration exists but registers no AIDR hook",
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
export function detectConnectorStatuses(home: string = homedir()): ConnectorStatus[] {
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
