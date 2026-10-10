/**
 * OpenCode configuration file locations (https://opencode.ai/docs/config/).
 *
 * OpenCode reads both `opencode.json` and `opencode.jsonc` (JSON with comments
 * and trailing commas) in every config location. Every connector reader takes
 * its paths from here so a supported file name is never skipped in one place
 * and read in another; the core reader (`parseJsonc`) handles both formats.
 */

import { homedir } from "node:os";
import { join } from "node:path";

const OPENCODE_CONFIG_NAMES = ["opencode.json", "opencode.jsonc"] as const;

/** The user's OpenCode config directory (`$XDG_CONFIG_HOME/opencode`). */
export function openCodeUserConfigDir(): string {
	return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "opencode");
}

/** Every supported config file name in each directory. */
export function openCodeConfigFiles(dirs: readonly string[]): string[] {
	return dirs.flatMap((dir) => OPENCODE_CONFIG_NAMES.map((name) => join(dir, name)));
}

/**
 * OpenCode MCP configuration: the user config, the project's root and
 * `.opencode` config (each as `.json` and `.jsonc`), and a custom file named by
 * `OPENCODE_CONFIG`.
 */
export function openCodeMcpConfigPaths(directory?: string): string[] {
	const custom = process.env.OPENCODE_CONFIG?.trim();
	return [
		...openCodeConfigFiles([
			openCodeUserConfigDir(),
			...(directory ? [directory, join(directory, ".opencode")] : []),
		]),
		...(custom ? [custom] : []),
	];
}
