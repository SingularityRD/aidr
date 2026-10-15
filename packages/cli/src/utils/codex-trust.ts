import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { CODEX_HOOK_PATTERN } from "./codex-hooks.js";

/**
 * Whether Codex will actually run the AIDR hook registered in the user's
 * `~/.codex/hooks.json`.
 *
 * Codex (verified in codex-rs at rust-v0.141.0, hooks/src/engine/discovery.rs)
 * runs a user-layer hook only when its trust record matches: the user's
 * `config.toml` holds `[hooks.state."<source path>:<event>:<group>:<handler>"]`
 * with `trusted_hash = "sha256:…"` (written by `/hooks`) and optionally
 * `enabled = false`. An untrusted hook is dropped silently, so the call
 * proceeds uninspected (fail-open). Hooks from the system layer
 * (`/etc/codex/hooks.json`, `%ProgramData%\OpenAI\Codex\hooks.json`) or from
 * managed `requirements.toml` are trusted by Codex without review.
 *
 * AIDR does not recompute Codex's hash (a SHA-256 over Codex's own normalised
 * TOML identity, which changes with Codex versions), so a recorded trust is
 * reported as "trust recorded", never as proven. A missing record is a
 * definite "untrusted".
 */

type CodexHandlerTrust = "trust_recorded" | "untrusted" | "disabled";

interface CodexHandlerState {
	/** Codex's state key: `<hooks.json path>:<event label>:<group>:<handler>`. */
	key: string;
	event: string;
	trust: CodexHandlerTrust;
}

export interface CodexTrustReport {
	hooksPath: string;
	configPath: string;
	/** AIDR handlers found in the user's hooks.json. */
	handlers: CodexHandlerState[];
	problems: string[];
}

const EVENT_LABELS: Record<string, string> = {
	PreToolUse: "pre_tool_use",
	PermissionRequest: "permission_request",
	PostToolUse: "post_tool_use",
	PreCompact: "pre_compact",
	PostCompact: "post_compact",
	SessionStart: "session_start",
	UserPromptSubmit: "user_prompt_submit",
	SubagentStart: "subagent_start",
	SubagentStop: "subagent_stop",
	Stop: "stop",
};

/** The Codex home: `$CODEX_HOME`, else `~/.codex`. */
function codexHome(home: string, env: NodeJS.ProcessEnv = process.env): string {
	return env.CODEX_HOME?.trim() || join(home, ".codex");
}

function unquoteTomlKey(raw: string): string | null {
	const text = raw.trim();
	if (text.startsWith('"') && text.endsWith('"')) {
		try {
			return JSON.parse(text) as string;
		} catch {
			return null;
		}
	}
	if (text.startsWith("'") && text.endsWith("'")) return text.slice(1, -1);
	return text;
}

/**
 * Parse the `hooks.state` entries of a Codex config.toml. Supports the two forms
 * Codex and people write: `[hooks.state."<key>"]` tables, and inline tables in a
 * `[hooks.state]` table (`"<key>" = { trusted_hash = "…", enabled = false }`).
 */
export function parseCodexHookStates(
	toml: string,
): Map<string, { trusted: boolean; enabled: boolean | null }> {
	const states = new Map<string, { trusted: boolean; enabled: boolean | null }>();
	let section: string | null = null;
	let inStateTable = false;
	for (const rawLine of toml.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (line === "" || line.startsWith("#")) continue;
		const header =
			/^\[\s*hooks\s*\.\s*state\s*\.\s*("(?:[^"\\]|\\.)*"|'[^']*')\s*\]\s*(?:#.*)?$/.exec(line);
		if (header) {
			section = unquoteTomlKey(header[1] ?? "");
			inStateTable = false;
			if (section !== null && !states.has(section))
				states.set(section, { trusted: false, enabled: null });
			continue;
		}
		if (/^\[\s*hooks\s*\.\s*state\s*\]\s*(?:#.*)?$/.test(line)) {
			section = null;
			inStateTable = true;
			continue;
		}
		if (line.startsWith("[")) {
			section = null;
			inStateTable = false;
			continue;
		}
		if (section !== null) {
			const entry = states.get(section) ?? { trusted: false, enabled: null };
			if (/^trusted_hash\s*=\s*["']sha256:[0-9a-f]{64}["']/.test(line)) entry.trusted = true;
			const enabled = /^enabled\s*=\s*(true|false)\b/.exec(line);
			if (enabled) entry.enabled = enabled[1] === "true";
			states.set(section, entry);
			continue;
		}
		if (inStateTable) {
			const inline = /^("(?:[^"\\]|\\.)*"|'[^']*')\s*=\s*\{(.*)\}\s*(?:#.*)?$/.exec(line);
			if (!inline) continue;
			const key = unquoteTomlKey(inline[1] ?? "");
			if (key === null) continue;
			const body = inline[2] ?? "";
			const enabled = /\benabled\s*=\s*(true|false)\b/.exec(body);
			states.set(key, {
				trusted: /\btrusted_hash\s*=\s*["']sha256:[0-9a-f]{64}["']/.test(body),
				enabled: enabled ? enabled[1] === "true" : null,
			});
		}
	}
	return states;
}

function readText(path: string): string | null {
	try {
		if (!lstatSync(path).isFile()) return null;
		return readFileSync(path, "utf8");
	} catch {
		return null;
	}
}

/**
 * AIDR handlers registered as TOML in config.toml, with Codex's indices:
 * `[[hooks.<Event>]]` opens group N of that event, `[[hooks.<Event>.hooks]]`
 * handler M of the current group.
 */
function tomlAidrHandlers(toml: string): Array<{ event: string; group: number; handler: number }> {
	const found: Array<{ event: string; group: number; handler: number }> = [];
	const groups = new Map<string, number>();
	let current: { event: string; group: number; handler: number } | null = null;
	let handlers = -1;
	for (const rawLine of toml.split(/\r?\n/)) {
		const line = rawLine.trim();
		const group = /^\[\[\s*hooks\s*\.\s*([A-Za-z]+)\s*\]\]\s*(?:#.*)?$/.exec(line);
		if (group) {
			const event = group[1] ?? "";
			groups.set(event, (groups.get(event) ?? -1) + 1);
			handlers = -1;
			current = null;
			continue;
		}
		const handler = /^\[\[\s*hooks\s*\.\s*([A-Za-z]+)\s*\.\s*hooks\s*\]\]\s*(?:#.*)?$/.exec(line);
		if (handler) {
			const event = handler[1] ?? "";
			handlers += 1;
			current = { event, group: groups.get(event) ?? 0, handler: handlers };
			continue;
		}
		if (line.startsWith("[")) {
			current = null;
			continue;
		}
		const command = /^command\s*=\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)')/.exec(line);
		if (current && command && CODEX_HOOK_PATTERN.test(command[1] ?? command[2] ?? ""))
			found.push(current);
	}
	return found;
}

function trustOf(
	state: { trusted: boolean; enabled: boolean | null } | undefined,
): CodexHandlerTrust {
	return state?.enabled === false ? "disabled" : state?.trusted ? "trust_recorded" : "untrusted";
}

/** Inspect the trust state of every AIDR handler in the user's Codex hooks.json and config.toml. */
export function inspectCodexHookTrust(
	home: string,
	env: NodeJS.ProcessEnv = process.env,
): CodexTrustReport {
	const dir = codexHome(home, env);
	const hooksPath = join(dir, "hooks.json");
	const configPath = join(dir, "config.toml");
	const report: CodexTrustReport = { hooksPath, configPath, handlers: [], problems: [] };
	const config = readText(configPath) ?? "";
	const states = parseCodexHookStates(config);
	for (const entry of tomlAidrHandlers(config)) {
		const label = EVENT_LABELS[entry.event];
		if (!label) continue;
		const key = `${configPath}:${label}:${entry.group}:${entry.handler}`;
		report.handlers.push({ key, event: entry.event, trust: trustOf(states.get(key)) });
	}
	const raw = readText(hooksPath);
	if (raw === null) return report;
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		report.problems.push(`${hooksPath} is not valid JSON`);
		return report;
	}
	const hooks = (parsed as { hooks?: unknown } | null)?.hooks;
	if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return report;
	for (const [event, groups] of Object.entries(hooks as Record<string, unknown>)) {
		const label = EVENT_LABELS[event];
		if (!label || !Array.isArray(groups)) continue;
		groups.forEach((group, groupIndex) => {
			const handlers = (group as { hooks?: unknown } | null)?.hooks;
			if (!Array.isArray(handlers)) return;
			handlers.forEach((handler, handlerIndex) => {
				const command = (handler as { command?: unknown } | null)?.command;
				if (typeof command !== "string" || !CODEX_HOOK_PATTERN.test(command)) return;
				const key = `${hooksPath}:${label}:${groupIndex}:${handlerIndex}`;
				report.handlers.push({ key, event, trust: trustOf(states.get(key)) });
			});
		});
	}
	return report;
}
