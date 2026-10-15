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
		["claude", join(".claude", "settings.json"), "{}"],
		["openclaw", join(".openclaw", "openclaw.json"), "{}"],
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

		expect(
			detectConnectorStatuses(home).find(
				(status) => status.id === (agent === "claude" ? "claude-code" : agent),
			)?.state,
		).toBe("runtime_present_not_installed");
		expect((await detectEnvironment(home)).agent).toBe(agent);
	});

	it.each(["cursor", "vscode"] as const)(
		"recognizes a %s-only profile outside a project",
		async (agent) => {
			const home = makeHome();
			mkdirSync(join(home, `.${agent}`));
			expect((await detectEnvironment(home)).agent).toBe(agent);
		},
	);

	it("uses the active Node runtime when node is not on PATH", async () => {
		const home = makeHome();
		vi.stubEnv("PATH", "");
		expect(await detectEnvironment(home)).toMatchObject({
			hasNode: true,
			nodeVersion: process.version,
		});
	});

	it("does not claim an agent for an empty profile", async () => {
		const home = makeHome();
		expect((await detectEnvironment(home)).agent).toBe("unknown");
	});

	it("agrees with `aidr status`: never detects a host from the cwd or editor env vars (PRD-14)", async () => {
		const home = makeHome();
		// Running setup inside a repository that contains a Claude plugin, or from
		// an editor terminal, used to print "claude detected" while status said
		// "not detected".
		const repo = mkdtempSync(join(tmpdir(), "aidr-detect-repo-"));
		homes.push(repo);
		mkdirSync(join(repo, ".claude-plugin"), { recursive: true });
		writeFileSync(join(repo, ".claude-plugin", "plugin.json"), "{}");
		const cwd = vi.spyOn(process, "cwd").mockReturnValue(repo);
		vi.stubEnv("CLAUDE_CODE_ROOT", repo);
		vi.stubEnv("VSCODE_PID", "1234");
		try {
			const env = await detectEnvironment(home);
			expect(env.agent).toBe("unknown");
			expect(env.detectedHosts).toEqual([]);
			expect(env.projectRoot).toBeUndefined();
			const statusView = detectConnectorStatuses(home)
				.filter((status) => status.state !== "not_detected")
				.map((status) => status.id);
			expect(env.detectedHosts).toEqual(statusView);
		} finally {
			cwd.mockRestore();
		}
	});

	it("lists every detected host, in the order status prints them", async () => {
		const home = makeHome();
		mkdirSync(join(home, ".codex"));
		mkdirSync(join(home, ".cursor"));
		const env = await detectEnvironment(home);
		expect(env.detectedHosts).toEqual(["cursor", "codex"]);
	});

	it("recognizes Codex before its optional hook config exists", async () => {
		const home = makeHome();
		mkdirSync(join(home, ".codex"));
		expect(detectConnectorStatuses(home).find((status) => status.id === "codex")?.state).toBe(
			"runtime_present_not_installed",
		);
		expect((await detectEnvironment(home)).agent).toBe("codex");
	});
});
