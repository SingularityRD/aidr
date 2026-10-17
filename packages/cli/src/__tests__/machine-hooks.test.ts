/**
 * C10: system-wide ("machine policy") hook deployment. Every case writes into a
 * temporary directory standing in for /etc/claude-code, /etc/codex and
 * /etc/systemd/user; no real host policy is touched.
 */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
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
import { dirname, join, relative } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { machineHooksInstallCommand, verifyMachineBundle } from "../commands/machine-hooks.js";
import { installConnectors } from "../utils/connector-install.js";
import { detectConnectorStatuses } from "../utils/connector-status.js";
import {
	claudeMachineDocument,
	installMachineHooks,
	MACHINE_HOOK_MARKER,
	type MachineHookPaths,
	machineHookPaths,
	machineHookStatus,
	removeMachineHooks,
	type ScheduleRunner,
	scheduleHeartbeat,
	windowsHeartbeatTaskXml,
} from "../utils/machine-hooks.js";
import { failClosedHookCommand } from "../utils/standalone.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots) rmSync(root, { recursive: true, force: true });
	roots.length = 0;
});

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "aidr-machine-hooks-"));
	roots.push(root);
	const paths: MachineHookPaths = {
		claudeDropIn: join(
			root,
			"etc",
			"claude-code",
			"managed-settings.d",
			"50-singularity-aidr.json",
		),
		codexHooks: join(root, "etc", "codex", "hooks.json"),
		codexRequirements: join(root, "etc", "codex", "requirements.toml"),
		cursorHooks: join(root, "etc", "cursor", "hooks.json"),
		systemdUserDir: join(root, "etc", "systemd", "user"),
	};
	const home = join(root, "home");
	mkdirSync(home, { recursive: true });
	return { root, paths, home, bundle: "/opt/singularity-aidr/bundle" };
}

const readJson = (path: string) =>
	JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;

describe("machineHookPaths", () => {
	it("uses the locations each host documents for system-wide policy", () => {
		expect(machineHookPaths("linux", {})).toMatchObject({
			claudeDropIn: "/etc/claude-code/managed-settings.d/50-singularity-aidr.json",
			codexHooks: "/etc/codex/hooks.json",
			codexRequirements: "/etc/codex/requirements.toml",
			cursorHooks: "/etc/cursor/hooks.json",
		});
		expect(machineHookPaths("win32", { ProgramData: "D:\\PD" })).toMatchObject({
			claudeDropIn: "C:\\Program Files\\ClaudeCode\\managed-settings.d\\50-singularity-aidr.json",
			codexHooks: "D:\\PD\\OpenAI\\Codex\\hooks.json",
			codexRequirements: "D:\\PD\\OpenAI\\Codex\\requirements.toml",
		});
	});
});

describe("Claude Code managed-settings drop-in", () => {
	it("registers the bundle hooks with the machine marker, and locks other hooks only when asked", () => {
		const open = claudeMachineDocument("/opt/aidr/bundle", {
			lockOtherHooks: false,
			platform: "linux",
		});
		expect(open).not.toHaveProperty("allowManagedHooksOnly");
		const pre = (
			open.hooks as Record<
				string,
				Array<{ matcher?: string; hooks: Array<Record<string, unknown>> }>
			>
		).PreToolUse;
		expect(pre?.[0]).toEqual({
			matcher: "*",
			hooks: [
				{
					type: "command",
					command: failClosedHookCommand('"/opt/aidr/bundle/bin/aidr" hook pre-tool-use', "linux"),
					timeout: 15,
					statusMessage: MACHINE_HOOK_MARKER,
				},
			],
		});
		expect(claudeMachineDocument("/opt/aidr/bundle", { lockOtherHooks: true })).toMatchObject({
			allowManagedHooksOnly: true,
		});
	});

	it("installs idempotently, reports status, and removes only its own file", () => {
		const { paths, bundle } = fixture();
		const first = installMachineHooks(
			{ bundleRoot: bundle, hosts: ["claude-code"], lockOtherHooks: true },
			{ paths, platform: "linux" },
		);
		expect(first).toMatchObject([{ host: "claude-code", action: "installed" }]);
		expect(readJson(paths.claudeDropIn)).toMatchObject({ allowManagedHooksOnly: true });
		const again = installMachineHooks(
			{ bundleRoot: bundle, hosts: ["claude-code"], lockOtherHooks: true },
			{ paths, platform: "linux" },
		);
		expect(again[0]?.action).toBe("already_installed");
		const status = machineHookStatus({ paths, platform: "linux" }).find(
			(s) => s.host === "claude-code",
		);
		expect(status).toMatchObject({ registered: true, otherHooksLocked: true });
		// A file others can write is never reported as tamper resistant.
		chmodSync(paths.claudeDropIn, 0o666);
		expect(
			machineHookStatus({ paths, platform: "linux" }).find((s) => s.host === "claude-code")
				?.tamperResistant,
		).toBe(false);
		chmodSync(paths.claudeDropIn, 0o644);
		expect(
			machineHookStatus({ paths, platform: "win32" }).find((s) => s.host === "claude-code")
				?.tamperResistant,
		).toBeNull();

		expect(removeMachineHooks({}, { paths })[0]).toMatchObject({
			host: "claude-code",
			action: "removed",
		});
		expect(machineHookStatus({ paths }).find((s) => s.host === "claude-code")?.registered).toBe(
			false,
		);
	});

	it("never overwrites a drop-in it does not own", () => {
		const { paths, bundle } = fixture();
		mkdirSync(dirname(paths.claudeDropIn), { recursive: true });
		writeFileSync(paths.claudeDropIn, '{"permissions":{"deny":["Bash(curl:*)"]}}\n');
		const [result] = installMachineHooks({ bundleRoot: bundle, hosts: ["claude-code"] }, { paths });
		expect(result?.action).toBe("failed");
		expect(readFileSync(paths.claudeDropIn, "utf8")).toContain("Bash(curl:*)");
		expect(removeMachineHooks({}, { paths })[0]?.action).toBe("nothing_to_remove");
	});
});

describe("Codex system layer", () => {
	it("merges AIDR's three handlers, keeps the administrator's own, and adds the lock line first", () => {
		const { paths, bundle } = fixture();
		mkdirSync(dirname(paths.codexHooks), { recursive: true });
		writeFileSync(
			paths.codexHooks,
			JSON.stringify({
				hooks: {
					PreToolUse: [
						{ matcher: "Bash", hooks: [{ type: "command", command: "/usr/local/bin/org-audit" }] },
					],
				},
			}),
		);
		writeFileSync(paths.codexRequirements, "[rules]\nprefix_rules = []\n");
		const [result] = installMachineHooks(
			{ bundleRoot: bundle, hosts: ["codex"], lockOtherHooks: true },
			{ paths, platform: "linux" },
		);
		expect(result?.action).toBe("updated");
		const hooks = readJson(paths.codexHooks).hooks as Record<
			string,
			Array<{ hooks: Array<{ command: string }> }>
		>;
		expect(hooks.PreToolUse?.map((group) => group.hooks[0]?.command)).toEqual([
			"/usr/local/bin/org-audit",
			failClosedHookCommand(
				'"/opt/singularity-aidr/bundle/bin/aidr" hook aidr-codex-hook',
				"linux",
			),
		]);
		expect(Object.keys(hooks).sort()).toEqual(["PostToolUse", "PreToolUse", "UserPromptSubmit"]);
		const requirements = readFileSync(paths.codexRequirements, "utf8");
		expect(requirements.startsWith("allow_managed_hooks_only = true")).toBe(true);
		expect(requirements).toContain("[rules]");
		expect(machineHookStatus({ paths }).find((s) => s.host === "codex")).toMatchObject({
			registered: true,
			otherHooksLocked: true,
		});

		const removed = removeMachineHooks({}, { paths }).find((r) => r.host === "codex");
		expect(removed?.action).toBe("removed");
		expect(readJson(paths.codexHooks)).toEqual({
			hooks: {
				PreToolUse: [
					{ matcher: "Bash", hooks: [{ type: "command", command: "/usr/local/bin/org-audit" }] },
				],
			},
		});
		expect(readFileSync(paths.codexRequirements, "utf8")).toBe("[rules]\nprefix_rules = []\n");
	});

	it("leaves an administrator's own allow_managed_hooks_only setting alone", () => {
		const { paths, bundle } = fixture();
		mkdirSync(dirname(paths.codexRequirements), { recursive: true });
		writeFileSync(paths.codexRequirements, "allow_managed_hooks_only = false\n");
		installMachineHooks({ bundleRoot: bundle, hosts: ["codex"], lockOtherHooks: true }, { paths });
		expect(readFileSync(paths.codexRequirements, "utf8")).toBe(
			"allow_managed_hooks_only = false\n",
		);
	});

	it("refuses to rewrite an unparsable hooks.json", () => {
		const { paths, bundle } = fixture();
		mkdirSync(dirname(paths.codexHooks), { recursive: true });
		writeFileSync(paths.codexHooks, "{ not json");
		expect(
			installMachineHooks({ bundleRoot: bundle, hosts: ["codex"] }, { paths })[0]?.action,
		).toBe("failed");
		expect(readFileSync(paths.codexHooks, "utf8")).toBe("{ not json");
	});
});

describe("per-user setup and status see the machine policy", () => {
	it("reports the host as installed by machine policy and does not add user hooks on top", () => {
		const { paths, bundle, home } = fixture();
		mkdirSync(join(home, ".codex"), { recursive: true });
		writeFileSync(join(home, ".claude.json"), "{}");
		mkdirSync(join(home, ".claude"), { recursive: true });
		writeFileSync(join(home, ".claude", "settings.json"), "{}\n");
		installMachineHooks({ bundleRoot: bundle }, { paths, platform: "linux" });
		const machine = machineHookStatus({ paths });
		const statuses = detectConnectorStatuses(home, {}, machine);
		expect(statuses.find((s) => s.id === "claude-code")).toMatchObject({ state: "installed" });
		expect(statuses.find((s) => s.id === "codex")?.detail).toContain("machine policy");

		const results = installConnectors(
			{ home, version: "9.9.9", machine, env: { PATH: "" } },
			{ hosts: ["claude-code", "codex"] },
		).filter((result) => result.host === "claude-code" || result.host === "codex");
		expect(results).toHaveLength(2);
		for (const result of results) {
			expect(result.action).toBe("already_installed");
			expect(result.changes).toEqual([]);
		}
		expect(readFileSync(join(home, ".claude", "settings.json"), "utf8")).toBe("{}\n");
	});
});

describe("heartbeat schedule", () => {
	it("writes systemd user units for every user and enables them globally", () => {
		const { paths, bundle } = fixture();
		const calls: string[][] = [];
		const run: ScheduleRunner = (command, args) => {
			calls.push([command, ...args]);
			return { status: 0 };
		};
		const installed = scheduleHeartbeat({ bundleRoot: bundle }, { paths, platform: "linux", run });
		expect(installed.action).toBe("installed");
		expect(readFileSync(join(paths.systemdUserDir, "aidr-heartbeat.service"), "utf8")).toContain(
			'ExecStart="/opt/singularity-aidr/bundle/bin/aidr" heartbeat --quiet',
		);
		expect(readFileSync(join(paths.systemdUserDir, "aidr-heartbeat.timer"), "utf8")).toContain(
			"OnUnitActiveSec=1h",
		);
		expect(calls).toEqual([["systemctl", "--global", "enable", "aidr-heartbeat.timer"]]);
		expect(
			scheduleHeartbeat({ bundleRoot: bundle }, { paths, platform: "linux", run }).action,
		).toBe("already_installed");
		expect(
			scheduleHeartbeat({ bundleRoot: bundle, remove: true }, { paths, platform: "linux", run })
				.action,
		).toBe("removed");
	});

	it("registers a Windows task that runs for whichever member of Users is logged on", () => {
		const { root, bundle } = fixture();
		const calls: string[][] = [];
		const run: ScheduleRunner = (command, args) => {
			calls.push([command, ...args]);
			return { status: 0 };
		};
		const result = scheduleHeartbeat(
			{ bundleRoot: "C:\\Program Files\\Singularity AIDR\\bundle" },
			{ platform: "win32", run, stagingDir: root },
		);
		expect(result.action).toBe("installed");
		expect(calls[0]?.slice(0, 3)).toEqual(["schtasks", "/Create", "/TN"]);
		const xml = windowsHeartbeatTaskXml(bundle);
		expect(xml).toContain("<GroupId>S-1-5-32-545</GroupId>");
		expect(xml).toContain("<Arguments>heartbeat --quiet</Arguments>");
		expect(xml).toContain("<Interval>PT1H</Interval>");
	});
});

/** A minimal standalone bundle: bin/aidr, one rule file, both manifests. */
function standaloneBundle(root: string): string {
	const bundle = join(root, "prefix", "bundle");
	mkdirSync(join(bundle, "bin"), { recursive: true });
	mkdirSync(join(bundle, "dist", "resources", "threats"), { recursive: true });
	writeFileSync(join(bundle, "bin", "aidr"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
	writeFileSync(join(bundle, "dist", "resources", "threats", "rules.yaml"), "- id: T\n");
	const list = (base: string, dir = base): string[] =>
		readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
			entry.isDirectory()
				? list(base, join(dir, entry.name))
				: [relative(base, join(dir, entry.name)).split("\\").join("/")],
		);
	const entries = (base: string) =>
		list(base)
			.filter((path) => !/^aidr-artifact\.manifest\./u.test(path))
			.sort()
			.map((path) => ({
				path,
				sha256: createHash("sha256")
					.update(readFileSync(join(base, path)))
					.digest("hex"),
			}));
	const write = (path: string, id: string, files: unknown) =>
		writeFileSync(path, `${JSON.stringify({ schema_version: 1, artifact_id: id, files })}\n`);
	write(
		join(bundle, "dist", "aidr-artifact.manifest.json"),
		"sea/dist",
		entries(join(bundle, "dist")),
	);
	write(join(bundle, "aidr-artifact.manifest.json"), "claude-code/sea", entries(bundle));
	return bundle;
}

function signStandalone(bundle: string): string {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const signFile = (file: string) =>
		`${sign(null, readFileSync(file), privateKey).toString("base64")}\n`;
	writeFileSync(
		join(bundle, "dist", "aidr-artifact.manifest.sig"),
		signFile(join(bundle, "dist", "aidr-artifact.manifest.json")),
	);
	const manifest = JSON.parse(readFileSync(join(bundle, "aidr-artifact.manifest.json"), "utf8"));
	const sigPath = "dist/aidr-artifact.manifest.sig";
	manifest.files.push({
		path: sigPath,
		sha256: createHash("sha256")
			.update(readFileSync(join(bundle, sigPath)))
			.digest("hex"),
	});
	manifest.files.sort((a: { path: string }, b: { path: string }) => a.path.localeCompare(b.path));
	writeFileSync(join(bundle, "aidr-artifact.manifest.json"), `${JSON.stringify(manifest)}\n`);
	writeFileSync(
		join(bundle, "aidr-artifact.manifest.sig"),
		signFile(join(bundle, "aidr-artifact.manifest.json")),
	);
	return publicKey.export({ type: "spki", format: "pem" }).toString();
}

describe("machine-hooks install verifies the bundle before registering it", () => {
	it("accepts an intact development bundle and a signed bundle with the installer's key", () => {
		const { root } = fixture();
		const bundle = standaloneBundle(root);
		expect(verifyMachineBundle(bundle, false).ok).toBe(true);
		// A release build must be signed.
		expect(verifyMachineBundle(bundle, true).ok).toBe(false);
		const pem = signStandalone(bundle);
		// Signed, but no key next to the bundle: nothing to verify against.
		expect(verifyMachineBundle(bundle, false).ok).toBe(false);
		mkdirSync(join(bundle, "..", "config"), { recursive: true });
		writeFileSync(join(bundle, "..", "config", "release-public.pem"), pem);
		const check = verifyMachineBundle(bundle, true);
		expect(check.problems).toEqual([]);
		expect(check.signature).toBe("verified");
		// A different key is not the signer.
		writeFileSync(
			join(bundle, "..", "config", "release-public.pem"),
			generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString(),
		);
		expect(verifyMachineBundle(bundle, false).ok).toBe(false);
	});

	it("refuses a modified bundle and writes no host policy", async () => {
		const { root, paths } = fixture();
		const bundle = standaloneBundle(root);
		writeFileSync(join(bundle, "dist", "resources", "threats", "rules.yaml"), "[]\n");
		const errors = vi.spyOn(console, "error").mockImplementation(() => {});
		const logs = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			await machineHooksInstallCommand(
				{ bundleRoot: bundle },
				{
					paths,
					isAdministrator: () => true,
					verifyBundle: (dir) => verifyMachineBundle(dir, false),
				},
			);
			expect(process.exitCode).toBe(1);
			expect(errors.mock.calls.flat().join("\n")).toContain("does not match its manifest digest");
			expect(existsSync(paths.claudeDropIn)).toBe(false);
			expect(existsSync(paths.codexHooks)).toBe(false);
		} finally {
			errors.mockRestore();
			logs.mockRestore();
			process.exitCode = 0;
		}
	});

	it("registers both hosts for a bundle that verifies", async () => {
		const { root, paths } = fixture();
		const bundle = standaloneBundle(root);
		const logs = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			await machineHooksInstallCommand(
				{ bundleRoot: bundle, lockOtherHooks: true },
				{
					paths,
					isAdministrator: () => true,
					verifyBundle: (dir) => verifyMachineBundle(dir, false),
				},
			);
			expect(process.exitCode ?? 0).toBe(0);
			expect(readJson(paths.claudeDropIn).allowManagedHooksOnly).toBe(true);
			expect(readFileSync(paths.codexHooks, "utf8")).toContain(join(bundle, "bin", "aidr"));
		} finally {
			logs.mockRestore();
			process.exitCode = 0;
		}
	});
});
