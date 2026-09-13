import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Environment } from "./config-manager.js";
import { updateConfig } from "./config-manager.js";

const AIDR_DIR = join(homedir(), ".singularity-aidr");

export interface HookInstallResult {
	/** Single line describing precisely what was and was not done. */
	summary: string;
	/** Extra lines shown to the user after setup (documented next steps). */
	followUp: string[];
}

/**
 * Records the local setup state and tells the user truthfully what still has to
 * happen for the agent to be protected.
 *
 * A previous version of this module wrote `claude-hooks.json`, `aidr.enabled` /
 * `aidr.hooksPath` editor settings and an OpenClaw `plugins` array, then reported
 * success. None of those files or keys are read by any shipped connector, so the
 * agent was never actually protected while the CLI claimed it was.
 *
 * Correct behaviour is to point at the documented, real installation path for
 * the detected runtime and never imply that protection is active when it is not.
 */
export async function installHooks(env: Environment): Promise<HookInstallResult> {
	if (!existsSync(AIDR_DIR)) {
		mkdirSync(AIDR_DIR, { recursive: true, mode: 0o700 });
	}

	// Record the detected runtime so `aidr status` can report it. This is state
	// only - it does not install anything.
	updateConfig({ hooksInstalled: false });

	const followUp = ["Protection is NOT yet active for your agent. Install the connector:"];

	switch (env.agent) {
		case "claude":
			followUp.push(
				"  Claude Code:  /plugin marketplace add https://github.com/singularityrd/aidr.git",
				"                /plugin install aidr@aidr",
			);
			break;
		case "cursor":
			followUp.push(
				"  Cursor:       build and install the VSIX, then run",
				"                'Singularity AIDR: Enable protection' from the command palette.",
			);
			break;
		case "vscode":
			followUp.push(
				"  VS Code:      build and install the VSIX, then enable protection",
				"                from the command palette.",
			);
			break;
		case "openclaw":
			followUp.push("  OpenClaw:     openclaw plugins install @singularityrd/aidr-openclaw");
			break;
		default:
			followUp.push(
				"  See docs/getting-started.md for the supported runtimes",
				"  (Claude Code, Cursor, VS Code, OpenClaw, OpenCode).",
			);
			break;
	}

	followUp.push("  Docs: https://aidr.singularityrd.com");

	return {
		summary:
			env.agent === "unknown"
				? "No supported agent detected - nothing installed"
				: `${env.agent} detected - connector install required`,
		followUp,
	};
}

/**
 * Writes a generic hook entry point for runtimes without a dedicated connector.
 * The script is self-contained: it invokes the packaged AIDR hook bundle rather
 * than a CLI subcommand that does not exist.
 */
export function writeGenericHookTemplate(hookBundlePath: string): string {
	const target = join(AIDR_DIR, "hooks", "generic-hook.cjs");
	mkdirSync(join(AIDR_DIR, "hooks"), { recursive: true, mode: 0o700 });

	const template = `#!/usr/bin/env node
// Singularity AIDR generic hook.
// Wire this into your agent's hook system: it reads a tool-call JSON payload on
// stdin and writes the AIDR verdict JSON to stdout.
const { spawnSync } = require("node:child_process");

const HOOK_BUNDLE = ${JSON.stringify(hookBundlePath)};

const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
	const input = Buffer.concat(chunks);
	const result = spawnSync(process.execPath, [HOOK_BUNDLE, "cursor"], { input });
	if (result.stdout) process.stdout.write(result.stdout);
	process.exit(0);
});
`;

	writeFileSync(target, template, { mode: 0o700 });
	return target;
}
