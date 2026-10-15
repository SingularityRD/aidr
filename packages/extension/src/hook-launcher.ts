/**
 * Stable hook launcher (bundled to `dist/aidr-hook-launcher.cjs` and copied to
 * `~/.singularity-aidr/extension-hooks/<host>/` by the extension).
 *
 * The managed hook command points at a shim next to the host's hooks file, and
 * the shim runs this launcher. Neither path contains the extension version, so
 * an extension update or removal can never leave the host with a command that
 * crashes (`Cannot find module`, exit 1, no verdict): hosts treat that as a
 * non-blocking error and run the tool uninspected.
 *
 * The launcher finds the hook runner in this order:
 *   1. `runner_path` from `runner.json`, written by the extension on every
 *      activation and on Enable protection;
 *   2. the newest `<extension_id>-<version>/dist/aidr-hook.cjs` under
 *      `extensions_dir` (covers the window between an update and the next
 *      activation, when the recorded version directory is already gone).
 * With no runner it answers with a deny in the host's format and exits 0.
 *
 * Keep this module free of core and `vscode` imports: it must load in a bare
 * Node/Electron-as-Node process in a few milliseconds.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { unansweredBlock } from "./hook-responses.js";

declare const __dirname: string;

export const LAUNCHER_FILE_NAME = "aidr-hook-launcher.cjs";
export const POINTER_FILE_NAME = "runner.json";
export const RUNNER_RELATIVE_PATH = join("dist", "aidr-hook.cjs");

export const MISSING_RUNNER_REASON =
	"Singularity AIDR hook runner was not found (the extension was updated, removed or damaged); execution was denied. Restart the editor so Singularity AIDR can repair its hooks, or run Singularity AIDR: Disable protection.";

/** `runner.json`: snake_case on disk like every other AIDR data file. */
export interface LauncherPointer {
	host?: string;
	runner_path?: string;
	extensions_dir?: string;
	extension_id?: string;
	version?: string;
	/** Hook files that carry this host's managed entries (cleaned on uninstall). */
	config_paths?: string[];
	/**
	 * The editor's display language (`vscode.env.language`, e.g. `tr`), recorded
	 * on every activation. The host starts the hook without the editor's
	 * environment, so the launcher passes it on as `AIDR_LOCALE`.
	 */
	display_language?: string;
}

const DISPLAY_LANGUAGE = /^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{1,8}){0,3}$/;

/**
 * Set `AIDR_LOCALE` from the recorded editor language unless the user or an
 * administrator already set it. Messages only: a locale never changes a verdict.
 */
export function applyDisplayLanguage(
	pointer: LauncherPointer,
	env: NodeJS.ProcessEnv = process.env,
): void {
	const language = pointer.display_language;
	if (env.AIDR_LOCALE?.trim()) return;
	if (typeof language !== "string" || !DISPLAY_LANGUAGE.test(language)) return;
	env.AIDR_LOCALE = language;
}

export function readLauncherPointer(launcherDir: string): LauncherPointer {
	try {
		const parsed: unknown = JSON.parse(readFileSync(join(launcherDir, POINTER_FILE_NAME), "utf8"));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as LauncherPointer)
			: {};
	} catch {
		return {};
	}
}

function isFile(filePath: string): boolean {
	try {
		return statSync(filePath).isFile();
	} catch {
		return false;
	}
}

function parseVersion(value: string): number[] | undefined {
	const match = /^(\d+)\.(\d+)\.(\d+)/.exec(value);
	return match ? match.slice(1, 4).map(Number) : undefined;
}

function compareVersions(a: number[], b: number[]): number {
	for (let i = 0; i < 3; i++) {
		const diff = (a[i] ?? 0) - (b[i] ?? 0);
		if (diff !== 0) return diff;
	}
	return 0;
}

/** Installed runners of this extension under `extensionsDir`, newest version first. */
export function findInstalledRunners(extensionsDir: string, extensionId: string): string[] {
	const prefix = `${extensionId.toLowerCase()}-`;
	let names: string[];
	try {
		names = readdirSync(extensionsDir);
	} catch {
		return [];
	}
	const found: Array<{ version: number[]; runner: string }> = [];
	for (const name of names) {
		if (!name.toLowerCase().startsWith(prefix)) continue;
		const version = parseVersion(name.slice(prefix.length));
		if (!version) continue;
		const runner = join(extensionsDir, name, RUNNER_RELATIVE_PATH);
		if (isFile(runner)) found.push({ version, runner });
	}
	return found.sort((a, b) => compareVersions(b.version, a.version)).map(({ runner }) => runner);
}

/** The runner this launcher would load, or undefined when none exists. */
export function resolveRunner(pointer: LauncherPointer): string | undefined {
	if (pointer.runner_path && isFile(pointer.runner_path)) return pointer.runner_path;
	if (pointer.extensions_dir && pointer.extension_id) {
		return findInstalledRunners(pointer.extensions_dir, pointer.extension_id)[0];
	}
	return undefined;
}

/** Drain stdin (so the host never sees EPIPE), answer with a deny, exit 0. */
function answerWithDeny(host: string | undefined, reason: string): void {
	const payload = `${JSON.stringify(unansweredBlock(host, reason))}\n`;
	let finished = false;
	const finish = () => {
		if (finished) return;
		finished = true;
		process.stdout.write(payload, () => process.exit(0));
	};
	process.stdin.on("data", () => {});
	process.stdin.on("end", finish);
	process.stdin.on("error", finish);
	setTimeout(finish, 2_000);
	process.stdin.resume();
}

export function runLauncher(
	argv: string[] = process.argv.slice(2),
	launcherDir: string = __dirname,
): void {
	const host = argv[0];
	const pointer = readLauncherPointer(launcherDir);
	applyDisplayLanguage(pointer);
	const runner = resolveRunner(pointer);
	if (runner && existsSync(runner)) {
		try {
			// The runner bootstrap starts the hook process on load and reads the
			// host argument from process.argv, which this launcher leaves intact.
			createRequire(runner)(runner);
			return;
		} catch {
			// A runner that cannot even be parsed: fall through to the deny.
		}
	}
	answerWithDeny(host, MISSING_RUNNER_REASON);
}

if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
	runLauncher();
}
