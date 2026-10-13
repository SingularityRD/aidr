/**
 * `aidr setup` installs connectors and `aidr uninstall` removes them (CON-13,
 * PRD-9). Every case runs against a temporary HOME with fake host CLIs: the
 * runner below plays the host (it writes what `openclaw plugins install`,
 * `code --install-extension` or `claude plugin install` would write), so no
 * real agent host is touched. The result must always match the re-measured
 * `aidr status` state, never a claim.
 */
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	type ConnectorDeps,
	type HostCommandRunner,
	installConnectors,
	removeConnectors,
	stripCodexToml,
} from "../utils/connector-install.js";
import { detectConnectorStatuses } from "../utils/connector-status.js";

const VERSION = "9.8.7";
const roots: string[] = [];

afterEach(() => {
	for (const root of roots) rmSync(root, { recursive: true, force: true });
	roots.length = 0;
});

function writeJson(path: string, value: unknown): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(path: string): Record<string, unknown> {
	return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

/** A temporary home plus a bin dir holding fake host executables. */
function fixture(executables: string[] = []) {
	const root = mkdtempSync(join(tmpdir(), "aidr-connector-install-"));
	roots.push(root);
	const home = join(root, "home");
	const bin = join(root, "bin");
	mkdirSync(home, { recursive: true });
	mkdirSync(bin, { recursive: true });
	for (const name of executables) {
		const path = join(bin, process.platform === "win32" ? `${name}.cmd` : name);
		writeFileSync(path, "#!/bin/sh\nexit 0\n");
		chmodSync(path, 0o755);
	}
	const calls: string[][] = [];
	const env: NodeJS.ProcessEnv = {
		PATH: bin,
		XDG_CONFIG_HOME: join(home, ".config"),
		...(process.platform === "win32" ? { PATHEXT: ".CMD" } : {}),
	};
	return { root, home, bin, env, calls };
}

/** Plays each host CLI by writing the registration the real one writes. */
function fakeHosts(home: string, calls: string[][]): HostCommandRunner {
	return (command, args) => {
		const name = (command.split(/[\\/]/).pop() ?? "").replace(/\.cmd$/i, "");
		calls.push([name, ...args]);
		const openclaw = join(home, ".openclaw", "openclaw.json");
		const claude = join(home, ".claude", "settings.json");
		if (name === "openclaw" && args[1] === "install") {
			const config = existsSync(openclaw) ? readJson(openclaw) : {};
			writeJson(openclaw, {
				...config,
				plugins: { entries: { "aidr-openclaw": { enabled: true } } },
			});
		} else if (name === "openclaw" && args[1] === "uninstall") {
			writeJson(openclaw, { plugins: { entries: {} } });
		} else if ((name === "cursor" || name === "code") && args[0] === "--install-extension") {
			const host = name === "cursor" ? ".cursor" : ".vscode";
			const ext = name === "cursor" ? "aidr-cursor" : "aidr-vscode";
			writeJson(join(home, host, "extensions", `singularityrd.${ext}-${VERSION}`, "package.json"), {
				publisher: "singularityrd",
				name: ext,
				version: VERSION,
			});
		} else if ((name === "cursor" || name === "code") && args[0] === "--uninstall-extension") {
			rmSync(join(home, name === "cursor" ? ".cursor" : ".vscode", "extensions"), {
				recursive: true,
				force: true,
			});
		} else if (name === "claude" && args.join(" ") === "plugin install aidr@aidr") {
			writeJson(claude, { ...readJson(claude), enabledPlugins: { "aidr@aidr": true } });
		} else if (name === "claude" && args.join(" ") === "plugin uninstall aidr@aidr") {
			writeJson(claude, { ...readJson(claude), enabledPlugins: {} });
		}
		return { status: 0, stdout: "", stderr: "" };
	};
}

function deps(f: ReturnType<typeof fixture>): ConnectorDeps {
	return {
		home: f.home,
		env: f.env,
		run: fakeHosts(f.home, f.calls),
		version: VERSION,
		now: () => 1,
	};
}

function stateOf(f: ReturnType<typeof fixture>, host: string): string | undefined {
	return detectConnectorStatuses(f.home, f.env).find((status) => status.id === host)?.state;
}

describe("aidr setup installs the connector of every detected host (CON-13)", () => {
	it("registers the Codex hooks, keeps the user's own, and is idempotent", () => {
		const f = fixture(["aidr-codex-hook"]);
		const hooksPath = join(f.home, ".codex", "hooks.json");
		const own = { matcher: "Bash", hooks: [{ type: "command", command: "my-audit", timeout: 5 }] };
		writeJson(hooksPath, { hooks: { PreToolUse: [own] }, other: true });
		expect(stateOf(f, "codex")).toBe("runtime_present_not_installed");

		const dry = installConnectors(deps(f), { dryRun: true }).find((r) => r.host === "codex");
		expect(dry?.action).toBe("would_install");
		expect(readJson(hooksPath).hooks).toEqual({ PreToolUse: [own] });

		const first = installConnectors(deps(f)).find((r) => r.host === "codex");
		expect(first?.action).toBe("installed");
		expect(first?.state).toBe("installed");
		expect(stateOf(f, "codex")).toBe("installed");
		const written = readJson(hooksPath) as {
			other: boolean;
			hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ command: string }> }>>;
		};
		expect(written.other).toBe(true);
		expect(written.hooks.PreToolUse?.[0]).toEqual(own);
		expect(written.hooks.PreToolUse?.[1]?.matcher).toBe("^(Bash|apply_patch)$");
		expect(written.hooks.UserPromptSubmit?.[0]?.hooks[0]?.command).toBe("aidr-codex-hook");
		expect(written.hooks.PostToolUse?.[0]?.matcher).toBe("^(Bash|mcp__.+)$");
		expect(first?.followUp.join("\n")).toContain("/hooks");

		const backups = () => readdirSync(join(f.home, ".codex")).filter((n) => n.includes("backup"));
		expect(backups()).toHaveLength(1);
		const before = readFileSync(hooksPath, "utf8");
		const second = installConnectors(deps(f)).find((r) => r.host === "codex");
		expect(second?.action).toBe("already_installed");
		expect(readFileSync(hooksPath, "utf8")).toBe(before);
		expect(backups()).toHaveLength(1);
	});

	it("does not register a Codex hook whose command is missing (Codex would fail open)", () => {
		const f = fixture();
		mkdirSync(join(f.home, ".codex"));
		const outcome = installConnectors(deps(f)).find((r) => r.host === "codex");
		expect(outcome?.action).toBe("manual");
		expect(outcome?.followUp.join("\n")).toContain(`@singularityrd/aidr-codex@${VERSION}`);
		expect(existsSync(join(f.home, ".codex", "hooks.json"))).toBe(false);
	});

	it("never rewrites a host config it cannot parse", () => {
		const f = fixture(["aidr-codex-hook"]);
		const hooksPath = join(f.home, ".codex", "hooks.json");
		mkdirSync(dirname(hooksPath), { recursive: true });
		writeFileSync(hooksPath, "{ not json");
		const outcome = installConnectors(deps(f)).find((r) => r.host === "codex");
		expect(outcome?.action).toBe("manual");
		expect(readFileSync(hooksPath, "utf8")).toBe("{ not json");
	});

	it("pins the OpenCode plugin, updates an old pin and keeps other plugins", () => {
		const f = fixture();
		const dir = join(f.home, ".config", "opencode");
		writeJson(join(dir, "opencode.json"), { plugin: ["other-plugin"], theme: "dark" });
		writeJson(join(dir, "package.json"), {
			dependencies: { "@singularityrd/aidr-opencode": "0.0.1" },
		});

		const outcome = installConnectors(deps(f)).find((r) => r.host === "opencode");
		expect(outcome?.action).toBe("updated");
		expect(readJson(join(dir, "opencode.json"))).toEqual({
			plugin: ["other-plugin", "@singularityrd/aidr-opencode"],
			theme: "dark",
		});
		expect(readJson(join(dir, "package.json"))).toEqual({
			dependencies: { "@singularityrd/aidr-opencode": VERSION },
		});
		expect(stateOf(f, "opencode")).toBe("installed");
		expect(installConnectors(deps(f)).find((r) => r.host === "opencode")?.action).toBe(
			"already_installed",
		);
	});

	it("leaves an opencode.jsonc config to the operator", () => {
		const f = fixture();
		const dir = join(f.home, ".config", "opencode");
		mkdirSync(dir, { recursive: true });
		writeFileSync(join(dir, "opencode.jsonc"), "{ // comment\n}\n");
		const outcome = installConnectors(deps(f)).find((r) => r.host === "opencode");
		expect(outcome?.action).toBe("manual");
		expect(existsSync(join(dir, "opencode.json"))).toBe(false);
	});

	it("installs through the host CLIs (OpenClaw, Cursor, VS Code, Claude Code) and measures the result", () => {
		const f = fixture(["openclaw", "cursor", "code", "claude"]);
		writeJson(join(f.home, ".openclaw", "openclaw.json"), {});
		mkdirSync(join(f.home, ".cursor"));
		mkdirSync(join(f.home, ".vscode"));
		writeJson(join(f.home, ".claude", "settings.json"), {});
		const vsix = join(f.root, "aidr-cursor.vsix");
		writeFileSync(vsix, "vsix");
		const vscodeVsix = join(f.root, "aidr-vscode.vsix");
		writeFileSync(vscodeVsix, "vsix");
		const plugin = join(f.root, "aidr-claude-plugin");
		writeJson(join(plugin, ".claude-plugin", "marketplace.json"), { name: "aidr" });

		const results = installConnectors(deps(f), {
			cursorVsix: vsix,
			vscodeVsix,
			claudePluginDir: plugin,
		});
		const byHost = Object.fromEntries(results.map((r) => [r.host, r]));
		for (const host of ["openclaw", "cursor", "vscode", "claude-code"]) {
			expect(byHost[host]?.action, host).toBe("installed");
			expect(stateOf(f, host), host).toBe("installed");
		}
		expect(f.calls).toContainEqual([
			"openclaw",
			"plugins",
			"install",
			`npm:@singularityrd/aidr-openclaw@${VERSION}`,
		]);
		expect(f.calls).toContainEqual(["claude", "plugin", "marketplace", "add", plugin]);
		expect(byHost["codex"]?.action).toBe("skipped_not_detected");

		// Second run: nothing to do for any of them, no host command is re-run
		// except the explicit VSIX reinstall the operator asked for.
		f.calls.length = 0;
		const again = installConnectors(deps(f));
		for (const host of ["openclaw", "cursor", "vscode", "claude-code"]) {
			expect(again.find((r) => r.host === host)?.action, host).toBe("already_installed");
		}
		expect(f.calls).toEqual([]);
	});

	it("reports a manual step, never success, when the host CLI or artifact is missing", () => {
		const f = fixture();
		writeJson(join(f.home, ".openclaw", "openclaw.json"), {});
		mkdirSync(join(f.home, ".cursor"));
		writeJson(join(f.home, ".claude", "settings.json"), {});
		const results = installConnectors(deps(f));
		for (const host of ["openclaw", "cursor", "claude-code"]) {
			const entry = results.find((r) => r.host === host);
			expect(entry?.action, host).toBe("manual");
			expect(entry?.state, host).not.toBe("installed");
			expect(entry?.followUp.length, host).toBeGreaterThan(0);
		}
		expect(f.calls).toEqual([]);
	});

	it("reports a host CLI that exits 0 without registering AIDR as failed", () => {
		const f = fixture(["openclaw"]);
		writeJson(join(f.home, ".openclaw", "openclaw.json"), {});
		const outcome = installConnectors(
			{ ...deps(f), run: () => ({ status: 0, stdout: "", stderr: "" }) },
			{ hosts: ["openclaw"] },
		)[3];
		expect(outcome?.host).toBe("openclaw");
		expect(outcome?.action).toBe("failed");
	});

	it("installs an explicitly selected host that is not detected yet, and skips the rest", () => {
		const f = fixture(["aidr-codex-hook"]);
		writeJson(join(f.home, ".config", "opencode", "opencode.json"), {});
		const results = installConnectors(deps(f), { hosts: ["codex"] });
		expect(results.find((r) => r.host === "codex")?.action).toBe("installed");
		expect(results.find((r) => r.host === "opencode")?.action).toBe("skipped_not_detected");
		expect(existsSync(join(f.home, ".config", "opencode", "package.json"))).toBe(false);
	});
});

describe("connector removal for every host (PRD-9)", () => {
	it("removes only AIDR's Codex handlers from hooks.json and config.toml", () => {
		const f = fixture(["aidr-codex-hook"]);
		const own = { matcher: "Bash", hooks: [{ type: "command", command: "my-audit" }] };
		writeJson(join(f.home, ".codex", "hooks.json"), { hooks: { PreToolUse: [own] } });
		installConnectors(deps(f));
		const toml = [
			'model = "x"',
			"",
			"[[hooks.PreToolUse]]",
			'matcher = "^(Bash|apply_patch)$"',
			"",
			"[[hooks.PreToolUse.hooks]]",
			'type = "command"',
			'command = "aidr-codex-hook"',
			"timeout = 10",
			"",
			"[[hooks.PostToolUse]]",
			"[[hooks.PostToolUse.hooks]]",
			'type = "command"',
			'command = "my-post-hook"',
			"[[hooks.PostToolUse.hooks]]",
			'type = "command"',
			"command = 'aidr-codex-hook'",
			"",
			"[profiles.x]",
			'model = "y"',
			"",
		].join("\n");
		writeFileSync(join(f.home, ".codex", "config.toml"), toml);

		const dry = removeConnectors(deps(f), { dryRun: true }).find((r) => r.host === "codex");
		expect(dry?.action).toBe("would_remove");
		expect(readFileSync(join(f.home, ".codex", "config.toml"), "utf8")).toBe(toml);

		const removed = removeConnectors(deps(f)).find((r) => r.host === "codex");
		expect(removed?.action).toBe("removed");
		expect(stateOf(f, "codex")).not.toBe("installed");
		expect(readJson(join(f.home, ".codex", "hooks.json")).hooks).toEqual({ PreToolUse: [own] });
		const left = readFileSync(join(f.home, ".codex", "config.toml"), "utf8");
		expect(left).not.toContain("aidr-codex-hook");
		expect(left).not.toContain("[[hooks.PreToolUse]]");
		expect(left).toContain("my-post-hook");
		expect(left).toContain("[[hooks.PostToolUse]]");
		expect(left).toContain("[profiles.x]");
		expect(removeConnectors(deps(f)).find((r) => r.host === "codex")?.action).toBe(
			"nothing_to_remove",
		);
	});

	it("strips TOML handler tables without touching unrelated tables", () => {
		const { text, removed } = stripCodexToml(
			'[[hooks.UserPromptSubmit]]\n[[hooks.UserPromptSubmit.hooks]]\ntype = "command"\ncommand = "aidr-codex-hook"\n[x]\na = 1\n',
		);
		expect(removed).toBe(1);
		expect(text).toBe("[x]\na = 1\n");
	});

	it("removes the OpenCode, OpenClaw, editor and Claude Code registrations", () => {
		const f = fixture(["openclaw", "cursor", "code", "claude"]);
		const dir = join(f.home, ".config", "opencode");
		writeJson(join(dir, "opencode.json"), { plugin: ["other", "@singularityrd/aidr-opencode"] });
		writeJson(join(dir, "package.json"), {
			dependencies: { "@singularityrd/aidr-opencode": VERSION, other: "1.0.0" },
		});
		writeJson(join(f.home, ".openclaw", "openclaw.json"), {
			plugins: { entries: { "aidr-openclaw": { enabled: true } } },
		});
		for (const [host, ext] of [
			[".cursor", "aidr-cursor"],
			[".vscode", "aidr-vscode"],
		] as const) {
			writeJson(join(f.home, host, "extensions", `singularityrd.${ext}-1`, "package.json"), {
				publisher: "singularityrd",
				name: ext,
				version: "1",
			});
		}
		writeJson(join(f.home, ".claude", "settings.json"), { enabledPlugins: { "aidr@aidr": true } });

		const results = removeConnectors(deps(f));
		for (const host of ["opencode", "openclaw", "cursor", "vscode", "claude-code"]) {
			expect(results.find((r) => r.host === host)?.action, host).toBe("removed");
			expect(stateOf(f, host), host).not.toBe("installed");
		}
		expect(readJson(join(dir, "opencode.json")).plugin).toEqual(["other"]);
		expect(readJson(join(dir, "package.json")).dependencies).toEqual({ other: "1.0.0" });
		expect(f.calls).toContainEqual([
			"cursor",
			"--uninstall-extension",
			"singularityrd.aidr-cursor",
		]);
		expect(f.calls).toContainEqual(["claude", "plugin", "uninstall", "aidr@aidr"]);
	});

	it("reports a manual step when the host CLI is missing and nothing for absent hosts", () => {
		const f = fixture();
		writeJson(join(f.home, ".openclaw", "openclaw.json"), {
			plugins: { entries: { "aidr-openclaw": { enabled: true } } },
		});
		const results = removeConnectors(deps(f));
		expect(results.find((r) => r.host === "openclaw")?.action).toBe("manual");
		expect(results.find((r) => r.host === "codex")?.action).toBe("nothing_to_remove");
		expect(stateOf(f, "openclaw")).toBe("installed");
	});
});
