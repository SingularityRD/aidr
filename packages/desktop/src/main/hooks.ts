import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, win32 } from "node:path";
import { MANAGED_HOOK_MARKER } from "../../../cli/src/utils/install-hooks.js";

/**
 * Reading the hooks a host config registers, and turning a registered hook
 * command into a program + argument list that can be run without a shell.
 */

export interface RegisteredHook {
	event: string;
	command: string;
	/** Written by an AIDR installer (`statusMessage` is the managed marker). */
	managed: boolean;
	timeoutSeconds: number | null;
}

function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parse a JSON settings file: absent → null; unreadable or invalid → throws. */
export function readSettingsObject(path: string): Record<string, unknown> | null {
	if (!existsSync(path)) return null;
	const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
	if (!isObject(parsed)) throw new Error(`${path} is not a JSON object`);
	return parsed;
}

/** AIDR hook registrations (managed marker, or a command naming AIDR) of one event. */
export function aidrHooks(settings: Record<string, unknown> | null, event: string): RegisteredHook[] {
	const hooks = settings && isObject(settings.hooks) ? settings.hooks[event] : undefined;
	if (!Array.isArray(hooks)) return [];
	const found: RegisteredHook[] = [];
	for (const entry of hooks) {
		if (!isObject(entry) || !Array.isArray(entry.hooks)) continue;
		for (const hook of entry.hooks) {
			if (!isObject(hook) || typeof hook.command !== "string") continue;
			const managed = hook.statusMessage === MANAGED_HOOK_MARKER;
			if (!managed && !/aidr|singularity/i.test(hook.command)) continue;
			found.push({
				event,
				command: hook.command,
				managed,
				timeoutSeconds: typeof hook.timeout === "number" ? hook.timeout : null,
			});
		}
	}
	return found;
}

export interface ParsedCommand {
	file: string;
	args: string[];
}

/**
 * Split a registered hook command into program and arguments, accepting only
 * the forms AIDR installers write: double-quoted paths and plain words, e.g.
 * `"C:/…/bin/aidr.exe" hook pre-tool-use` (standalone bundle) or
 * `"C:/…/node.exe" "C:/…/dist/pre-tool-use.cjs"` (endpoint installer).
 * Anything a shell would interpret (variables, redirection, pipes, escapes) is
 * refused instead of being run, and the program must be an absolute path.
 */
export function parseHookCommand(command: string): ParsedCommand | null {
	const tokens: string[] = [];
	const pattern = /\s*(?:"([^"]*)"|([^\s"]+))/gy;
	let index = 0;
	while (index < command.length) {
		pattern.lastIndex = index;
		const match = pattern.exec(command);
		if (!match) {
			if (/^\s*$/.test(command.slice(index))) break;
			return null;
		}
		const token = match[1] ?? match[2] ?? "";
		if (/[$%`|&;<>()^\r\n]/.test(token)) return null;
		tokens.push(token);
		index = pattern.lastIndex;
	}
	const [file, ...args] = tokens;
	// Hook commands are written by the Windows installer (C:/... or C:\...);
	// accept those on every platform so the same check is testable everywhere.
	if (!file || !(isAbsolute(file) || win32.isAbsolute(file))) return null;
	return { file, args };
}

/** Whether a hook program exists as a regular file. */
export function programExists(file: string): boolean {
	try {
		return statSync(file).isFile();
	} catch {
		return false;
	}
}
