import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyHosts } from "../commands/verify.js";
import type { HookProbe } from "../utils/standalone.js";

const dirs: string[] = [];
afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** A home where AIDR is installed only as a Claude Code plugin (no settings.json hook). */
function pluginHome(): { home: string; root: string } {
	const home = mkdtempSync(join(tmpdir(), "aidr-verify-plugin-"));
	dirs.push(home);
	const root = join(home, ".claude", "plugins", "cache", "aidr", "aidr", "0.6.0");
	mkdirSync(join(root, "hooks"), { recursive: true });
	writeFileSync(
		join(root, "hooks", "hooks.json"),
		JSON.stringify({
			hooks: {
				PreToolUse: [
					{
						matcher: "*",
						hooks: [{ type: "command", command: 'node "${CLAUDE_PLUGIN_ROOT}/pre.cjs"' }],
					},
				],
			},
		}),
	);
	writeFileSync(
		join(home, ".claude", "settings.json"),
		JSON.stringify({ enabledPlugins: { "aidr@aidr": true } }),
	);
	writeFileSync(
		join(home, ".claude", "plugins", "installed_plugins.json"),
		JSON.stringify({
			version: 2,
			plugins: { "aidr@aidr": [{ scope: "user", installPath: root }] },
		}),
	);
	return { home, root };
}

describe("aidr verify with a Claude Code plugin install", () => {
	it("runs the plugin's own hook entry point instead of skipping it", () => {
		const { home, root } = pluginHome();
		const commands: string[] = [];
		const run = (command: string, payload: Record<string, unknown>): HookProbe => {
			commands.push(command);
			const shell = String((payload.tool_input as { command?: string }).command);
			return shell.includes("| bash")
				? { decision: "deny", detail: "canary blocked" }
				: { decision: "allow", detail: "allowed" };
		};
		const claude = verifyHosts({ home, env: {}, run }).find(
			(entry) => entry.host === "claude-code",
		);
		expect(claude?.outcome, claude?.detail).toBe("pass");
		expect(commands[0]).toBe(`node "${root.replaceAll("\\", "/")}/pre.cjs"`);
	});

	it("still skips when the plugin's install directory is unknown", () => {
		const { home } = pluginHome();
		writeFileSync(join(home, ".claude", "plugins", "installed_plugins.json"), "{}");
		const claude = verifyHosts({
			home,
			env: {},
			run: () => ({ decision: "deny", detail: "" }),
		}).find((entry) => entry.host === "claude-code");
		expect(claude?.outcome).toBe("skip");
	});
});
