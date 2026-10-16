/**
 * Tests for `aidr status` accuracy (AIDR-024).
 *
 * ## The defect these pin
 *
 * `aidr status` asserted three things it had never measured:
 *   - `Hooks: ${config.hooksInstalled}` — written once as `false` by setup and
 *     never updated, so a correctly installed machine was told its hooks were
 *     not installed;
 *   - a masked API key printed unconditionally, which rendered `****` when no key
 *     existed and read as "a key is configured";
 *   - `AIDR is configured`, which said nothing about whether anything was
 *     actually enforced.
 *
 * A customer running `aidr status` after a correct install was told the product
 * was not installed. That is the reporting failure this suite exists to prevent.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { anyConnectorInstalled, detectConnectorStatuses } from "../utils/connector-status.js";

let homes: string[] = [];
let originalXdgConfigHome: string | undefined;

beforeEach(() => {
	originalXdgConfigHome = process.env.XDG_CONFIG_HOME;
});

function makeHome(): string {
	const home = mkdtempSync(join(tmpdir(), "aidr-connector-status-"));
	homes.push(home);
	return home;
}

function write(home: string, relPath: string, content: string): void {
	const full = join(home, relPath);
	mkdirSync(join(full, ".."), { recursive: true });
	writeFileSync(full, content, "utf8");
}

afterEach(() => {
	for (const h of homes) rmSync(h, { recursive: true, force: true });
	homes = [];
	if (originalXdgConfigHome === undefined) delete process.env.XDG_CONFIG_HOME;
	else process.env.XDG_CONFIG_HOME = originalXdgConfigHome;
});

describe("connector detection reports measured state", () => {
	it("reports nothing installed for an empty home", () => {
		const statuses = detectConnectorStatuses(makeHome());
		expect(statuses).toHaveLength(6);
		expect(anyConnectorInstalled(statuses)).toBe(false);
		for (const s of statuses) expect(s.state).toBe("not_detected");
	});

	it("detects an installed Claude Code connector from settings.json", () => {
		const home = makeHome();
		write(
			home,
			join(".claude", "settings.json"),
			JSON.stringify({
				hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "aidr/pre-tool-use.cjs" }] }] },
			}),
		);

		const claude = detectConnectorStatuses(home).find((s) => s.id === "claude-code");
		expect(claude?.state).toBe("installed");
		expect(anyConnectorInstalled(detectConnectorStatuses(home))).toBe(true);
	});

	it("distinguishes 'runtime present but not installed' from 'not detected'", () => {
		const home = makeHome();
		write(home, join(".claude", "settings.json"), JSON.stringify({ hooks: {} }));

		const claude = detectConnectorStatuses(home).find((s) => s.id === "claude-code");
		expect(claude?.state).toBe("runtime_present_not_installed");
		// A runtime with no AIDR registration must NOT count as protected.
		expect(anyConnectorInstalled([claude!])).toBe(false);
	});

	it("describes every host in Turkish under AIDR_LOCALE=tr", () => {
		const home = makeHome();
		write(home, join(".claude", "settings.json"), JSON.stringify({ hooks: {} }));
		mkdirSync(join(home, ".codex"), { recursive: true });
		vi.stubEnv("AIDR_LOCALE", "tr");
		try {
			const statuses = detectConnectorStatuses(home, {}, []);
			const claude = statuses.find((s) => s.id === "claude-code");
			expect(claude?.detail).toBe("~/.claude/settings.json var ama AIDR'ye hiç başvurmuyor");
			expect(claude?.remedy).toContain("marketplace olarak ekleyin");
			expect(statuses.find((s) => s.id === "codex")?.remedy).toContain("işleyiciyle");
			// No English sentence is left in any detail or remedy.
			for (const status of statuses) {
				expect(`${status.detail} ${status.remedy ?? ""}`).not.toMatch(
					/\b(found|exists|registered|Install|Verify|Add|Check)\b/,
				);
			}
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it.each([
		{ enabledPlugins: { "aidr@aidr": false } },
		{ description: "aidr was uninstalled", hooks: {} },
		{ disableAllHooks: true, enabledPlugins: { "aidr@aidr": true } },
		{ hooks: { PostToolUse: [{ command: "aidr/post-tool-use.cjs" }] } },
		{ hooks: { PreToolUse: [null, { hooks: [null] }] } },
	])("does not mistake disabled or unrelated configuration for an enabled hook: %j", (settings) => {
		const home = makeHome();
		write(home, join(".claude", "settings.json"), JSON.stringify(settings));
		expect(detectConnectorStatuses(home).find((s) => s.id === "claude-code")?.state).toBe(
			"runtime_present_not_installed",
		);
	});

	it("detects installed Cursor and VS Code extensions", () => {
		const home = makeHome();
		write(
			home,
			join(".cursor", "extensions", "singularityrd.aidr-cursor-0.6.0", "package.json"),
			JSON.stringify({ publisher: "SingularityRD", name: "aidr-cursor", version: "0.6.0" }),
		);
		write(
			home,
			join(".vscode", "extensions", "singularityrd.aidr-vscode-0.6.0", "package.json"),
			JSON.stringify({ publisher: "SingularityRD", name: "aidr-vscode", version: "0.6.0" }),
		);

		const statuses = detectConnectorStatuses(home);
		expect(statuses.find((s) => s.id === "cursor")?.state).toBe("installed");
		expect(statuses.find((s) => s.id === "vscode")?.state).toBe("installed");
	});

	it("does not treat package-name directories as installed without the AIDR manifest", () => {
		const home = makeHome();
		write(
			home,
			join(".cursor", "extensions", "someone.aidr-cursor-1.0.0", "package.json"),
			JSON.stringify({ publisher: "SomeoneElse", name: "aidr-cursor", version: "1.0.0" }),
		);

		const cursor = detectConnectorStatuses(home).find((s) => s.id === "cursor");
		expect(cursor?.state).toBe("runtime_present_not_installed");
		expect(anyConnectorInstalled([cursor!])).toBe(false);
	});

	it("detects an OpenClaw plugin listed in its config", () => {
		const home = makeHome();
		write(
			home,
			join(".openclaw", "openclaw.json"),
			JSON.stringify({
				plugins: { entries: { "aidr-openclaw": { enabled: true } }, allow: ["aidr-openclaw"] },
			}),
		);

		expect(detectConnectorStatuses(home).find((s) => s.id === "openclaw")?.state).toBe("installed");
	});

	it.each([
		{ description: "aidr was uninstalled" },
		{ plugins: ["aidr"] },
		{ plugins: { entries: { "another-plugin": { config: { description: "singularity" } } } } },
	])(
		"does not mistake unrelated OpenClaw text or obsolete plugin arrays for registration: %j",
		(config) => {
			const home = makeHome();
			write(home, join(".openclaw", "openclaw.json"), JSON.stringify(config));
			expect(detectConnectorStatuses(home).find((s) => s.id === "openclaw")?.state).toBe(
				"runtime_present_not_installed",
			);
		},
	);

	it.each([
		{ enabled: false, entries: { "aidr-openclaw": { enabled: true } } },
		{ entries: { "aidr-openclaw": { enabled: false } } },
		{ entries: { "aidr-openclaw": { enabled: true } }, allow: ["other-plugin"] },
		{ entries: { "aidr-openclaw": { enabled: true } }, allow: [] },
		{ entries: { "aidr-openclaw": { enabled: true } }, deny: ["aidr-openclaw"] },
	])("reports a registered but disabled OpenClaw plugin as degraded: %j", (plugins) => {
		const home = makeHome();
		write(home, join(".openclaw", "openclaw.json"), JSON.stringify({ plugins }));
		const status = detectConnectorStatuses(home).find((s) => s.id === "openclaw");
		expect(status?.state).toBe("installed_but_degraded");
		expect(anyConnectorInstalled(detectConnectorStatuses(home))).toBe(false);
		expect(status?.remedy).toBeTruthy();
	});

	it("detects an OpenCode plugin", () => {
		const home = makeHome();
		write(
			home,
			join(".config", "opencode", "package.json"),
			JSON.stringify({ dependencies: { "@singularityrd/aidr-opencode": "0.6.0" } }),
		);
		write(
			home,
			join(".config", "opencode", "opencode.json"),
			JSON.stringify({ plugin: ["@singularityrd/aidr-opencode"] }),
		);

		expect(detectConnectorStatuses(home).find((s) => s.id === "opencode")?.state).toBe("installed");
	});

	it("uses XDG_CONFIG_HOME when probing OpenCode", () => {
		const home = makeHome();
		process.env.XDG_CONFIG_HOME = join(home, "xdg");
		write(
			home,
			join("xdg", "opencode", "package.json"),
			JSON.stringify({ dependencies: { "@singularityrd/aidr-opencode": "0.6.0" } }),
		);
		write(
			home,
			join("xdg", "opencode", "opencode.json"),
			JSON.stringify({ plugin: ["@singularityrd/aidr-opencode"] }),
		);

		expect(detectConnectorStatuses(home).find((s) => s.id === "opencode")?.state).toBe("installed");
	});

	it("reports unreadable host config as unavailable instead of throwing", () => {
		const home = makeHome();
		mkdirSync(join(home, ".claude", "settings.json"), { recursive: true });
		mkdirSync(join(home, ".codex", "config.toml"), { recursive: true });

		const statuses = detectConnectorStatuses(home);
		expect(statuses.find((s) => s.id === "claude-code")?.state).toBe("unavailable");
		expect(statuses.find((s) => s.id === "codex")?.state).toBe("unavailable");
	});
});

describe("Codex detection catches the configuration that silently does nothing", () => {
	it("marks a lower-case hooks.pre_tool_use table as BROKEN, not installed", () => {
		// Codex parses this as valid TOML and then ignores it, so the hook never
		// runs. Reporting it as "installed" would tell the operator they are
		// protected when they are not.
		const home = makeHome();
		write(
			home,
			join(".codex", "config.toml"),
			"[hooks.pre_tool_use]\ncommand = 'aidr-codex-hook'\n",
		);

		const codex = detectConnectorStatuses(home).find((s) => s.id === "codex");
		expect(codex?.state).toBe("installed_but_degraded");
		expect(codex?.detail).toMatch(/IGNORES/i);
		expect(codex?.remedy).toMatch(/hooks\.PreToolUse/);
		// Crucially, a broken registration must not count as protection.
		expect(anyConnectorInstalled([codex!])).toBe(false);
	});

	it("accepts the PascalCase table that Codex actually honours", () => {
		const home = makeHome();
		write(
			home,
			join(".codex", "config.toml"),
			'[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "aidr-codex-hook"\n',
		);

		expect(detectConnectorStatuses(home).find((s) => s.id === "codex")?.state).toBe("installed");
	});

	it("detects an AIDR hook registered through hooks.json", () => {
		const home = makeHome();
		write(
			home,
			join(".codex", "hooks.json"),
			JSON.stringify({
				hooks: {
					PreToolUse: [
						{ matcher: "^Bash$", hooks: [{ type: "command", command: "aidr-codex-hook" }] },
					],
				},
			}),
		);

		expect(detectConnectorStatuses(home).find((s) => s.id === "codex")?.state).toBe("installed");
	});

	it("does not count unrelated AIDR text as a Codex PreToolUse handler", () => {
		const tomlHome = makeHome();
		write(
			tomlHome,
			join(".codex", "config.toml"),
			'[[hooks.PreToolUse]]\nmatcher = "^Bash$"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "other-hook"\n# aidr-codex-hook was removed\n',
		);
		expect(detectConnectorStatuses(tomlHome).find((s) => s.id === "codex")?.state).toBe(
			"runtime_present_not_installed",
		);

		const jsonHome = makeHome();
		write(
			jsonHome,
			join(".codex", "hooks.json"),
			JSON.stringify({
				description: "aidr-codex-hook was removed",
				hooks: { PostToolUse: [{ hooks: [{ type: "command", command: "aidr-codex-hook" }] }] },
			}),
		);
		expect(detectConnectorStatuses(jsonHome).find((s) => s.id === "codex")?.state).toBe(
			"runtime_present_not_installed",
		);
	});
});

describe("every claim carries evidence", () => {
	it("returns the paths it inspected so the user can verify", () => {
		const statuses = detectConnectorStatuses(makeHome());
		for (const s of statuses) {
			expect(s.evidence.length).toBeGreaterThan(0);
			for (const p of s.evidence) expect(typeof p).toBe("string");
			expect(s.detail.length).toBeGreaterThan(0);
		}
	});

	it("offers a remedy whenever action is required", () => {
		const home = makeHome();
		write(home, join(".claude", "settings.json"), JSON.stringify({ hooks: {} }));
		write(home, join(".codex", "config.toml"), "[hooks.pre_tool_use]\n");

		for (const s of detectConnectorStatuses(home)) {
			if (s.state === "runtime_present_not_installed" || s.state === "installed_but_degraded") {
				expect(s.remedy, `${s.id} must tell the user what to do`).toBeTruthy();
			}
		}
	});
});
