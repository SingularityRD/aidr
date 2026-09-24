import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { detectConnectorStatuses } from "../utils/connector-status.js";
import { detectEnvironment } from "../utils/detect-env.js";

const homes: string[] = [];

function makeHome(): string {
	const home = mkdtempSync(join(tmpdir(), "aidr-detect-env-"));
	homes.push(home);
	vi.stubEnv("XDG_CONFIG_HOME", join(home, ".config"));
	for (const marker of [
		"CLAUDE_CODE_ROOT",
		"CURSOR_WORKSPACE_ROOT",
		"VSCODE_CWD",
		"VSCODE_PID",
		"OPENCLAW_SESSION",
	]) {
		vi.stubEnv(marker, undefined);
	}
	return home;
}

afterEach(() => {
	vi.unstubAllEnvs();
	for (const home of homes) rmSync(home, { recursive: true, force: true });
	homes.length = 0;
});

describe("setup agent detection", () => {
	it.each([
		["opencode", join(".config", "opencode", "opencode.json"), "{}"],
		["codex", join(".codex", "config.toml"), "# Codex host\n"],
	] as const)("recognizes an unprotected %s-only host", async (agent, file, content) => {
		const home = makeHome();
		const configPath = join(home, file);
		mkdirSync(dirname(configPath), { recursive: true });
		writeFileSync(configPath, content);
		const staleProjectPlugin = join(home, ".claude-plugin", "plugin.json");
		mkdirSync(dirname(staleProjectPlugin), { recursive: true });
		writeFileSync(staleProjectPlugin, "{}");

		expect(detectConnectorStatuses(home).find((status) => status.id === agent)?.state).toBe(
			"runtime_present_not_installed",
		);
		expect((await detectEnvironment(home, home)).agent).toBe(agent);
	});

	it("does not claim an agent for an empty profile", async () => {
		const home = makeHome();
		expect((await detectEnvironment(home, home)).agent).toBe("unknown");
	});

	it("recognizes Codex before its optional hook config exists", async () => {
		const home = makeHome();
		mkdirSync(join(home, ".codex"));
		expect(detectConnectorStatuses(home).find((status) => status.id === "codex")?.state).toBe(
			"runtime_present_not_installed",
		);
		expect((await detectEnvironment(home, home)).agent).toBe("codex");
	});
});
