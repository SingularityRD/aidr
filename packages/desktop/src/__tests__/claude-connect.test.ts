import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { MANAGED_HOOK_MARKER } from "../../../cli/src/utils/install-hooks.js";
import { connectClaude, disconnectClaude, previewConnect } from "../main/claude.js";
import type { RunOptions, Runner } from "../main/exec.js";
import { runtimeBinary } from "../main/paths.js";
import { checkRuntime, ensureInstalledRuntime, installedRuntimeDir } from "../main/runtime.js";
import { fakeBundle, tempDir } from "./fixtures.js";

const cleanup: string[] = [];
afterEach(() => {
	for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});

function setup(settings?: unknown) {
	const home = tempDir("home");
	const bundle = fakeBundle();
	cleanup.push(home, bundle);
	if (settings !== undefined) {
		mkdirSync(join(home, ".claude"), { recursive: true });
		writeFileSync(
			join(home, ".claude", "settings.json"),
			typeof settings === "string" ? settings : `${JSON.stringify(settings, null, 2)}\n`,
		);
	}
	return { home, bundle };
}

const userSettings = {
	model: "opus",
	hooks: {
		PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo mine" }] }],
		Stop: [{ hooks: [{ type: "command", command: "notify-me" }] }],
	},
};

const run: Runner = async () => ({ exitCode: 0, signal: null, stdout: "", stderr: "", durationMs: 1, error: null });

describe("previewConnect (the settings merge aidr setup performs)", () => {
	it("adds the three AIDR hooks and keeps every user hook and key", () => {
		const { home, bundle } = setup(userSettings);
		const preview = previewConnect({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		expect(preview.blocker).toBeNull();
		expect(preview.changed).toBe(true);
		const added = preview.diff.filter((line) => line.kind === "add").map((line) => line.text).join("\n");
		const removed = preview.diff.filter((line) => line.kind === "remove");
		expect(added).toContain("hook pre-tool-use");
		expect(added).toContain("hook post-tool-use");
		expect(added).toContain("hook session-start");
		expect(added).toContain(MANAGED_HOOK_MARKER);
		// Only additions: nothing the user wrote is removed or rewritten.
		expect(removed.filter((line) => line.text.trim() !== "]" && line.text.trim() !== "}")).toEqual([]);
		const after = preview.diff.filter((line) => line.kind !== "remove").map((line) => line.text).join("\n");
		const parsed = JSON.parse(after);
		expect(parsed.model).toBe("opus");
		expect(parsed.hooks.Stop).toEqual(userSettings.hooks.Stop);
		expect(parsed.hooks.PreToolUse[0]).toEqual(userSettings.hooks.PreToolUse[0]);
		expect(preview.commands).toHaveLength(3);
		expect(preview.runtimeRoot).toBe(installedRuntimeDir(home, checkRuntime(bundle)));
	});

	it("replaces a previous AIDR registration instead of duplicating it", () => {
		const stale = {
			hooks: {
				PreToolUse: [
					{
						matcher: "*",
						hooks: [{ type: "command", command: '"C:/old/aidr.exe" hook pre-tool-use', statusMessage: MANAGED_HOOK_MARKER }],
					},
				],
			},
		};
		const { home, bundle } = setup(stale);
		const preview = previewConnect({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		const after = JSON.parse(preview.diff.filter((line) => line.kind !== "remove").map((line) => line.text).join("\n"));
		expect(after.hooks.PreToolUse).toHaveLength(1);
		expect(after.hooks.PreToolUse[0].hooks[0].command).not.toContain("C:/old");
	});

	it("is a no-op when the settings already hold exactly these hooks", () => {
		const { home, bundle } = setup(userSettings);
		const first = previewConnect({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		const desired = first.diff.filter((line) => line.kind !== "remove").map((line) => line.text).join("\n");
		writeFileSync(join(home, ".claude", "settings.json"), `${desired}\n`);
		const second = previewConnect({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		expect(second.changed).toBe(false);
	});

	it("creates the settings file when there is none", () => {
		const { home, bundle } = setup();
		const preview = previewConnect({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		expect(preview.settingsExists).toBe(false);
		expect(preview.diff.every((line) => line.kind === "add")).toBe(true);
	});

	it.each([
		["invalid JSON", "{ not json", /cannot be read as JSON/],
		["disableAllHooks", { disableAllHooks: true }, /disableAllHooks/],
		["the AIDR plugin enabled", { enabledPlugins: { "aidr@aidr": true } }, /plugin is already enabled/],
		["hooks that are not an object", { hooks: [] }, /not an object/],
	])("refuses to connect over %s", (_name, settings, message) => {
		const { home, bundle } = setup(settings);
		const preview = previewConnect({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		expect(preview.blocker).toMatch(message);
		expect(preview.diff).toEqual([]);
	});

	it("defers to a machine-wide registration", () => {
		const { home, bundle } = setup(userSettings);
		const preview = previewConnect({
			home,
			bundledRuntime: bundle,
			run,
			language: "en",
			machine: [{ host: "claude-code", path: "C:/ProgramData/managed-settings.json", registered: true } as never],
		});
		expect(preview.blocker).toMatch(/machine policy/);
	});

	it("refuses a bundled runtime that fails verification", () => {
		const { home, bundle } = setup(userSettings);
		writeFileSync(join(bundle, "dist", "response-worker.cjs"), "// tampered\n");
		const preview = previewConnect({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		expect(preview.blocker).toMatch(/failed verification/);
	});
});

describe("ensureInstalledRuntime", () => {
	it("copies the bundle once to a per-user, digest-addressed directory and verifies it", () => {
		const { home, bundle } = setup();
		const first = ensureInstalledRuntime(bundle, home);
		expect(first.copied).toBe(true);
		expect(first.root.startsWith(join(home, ".singularity-aidr", "desktop", "runtime"))).toBe(true);
		expect(checkRuntime(first.root).ok).toBe(true);
		const second = ensureInstalledRuntime(bundle, home);
		expect(second).toMatchObject({ root: first.root, copied: false });
	});

	it("replaces a tampered copy", () => {
		const { home, bundle } = setup();
		const { root } = ensureInstalledRuntime(bundle, home);
		writeFileSync(join(root, "dist", "response-worker.cjs"), "// tampered\n");
		const again = ensureInstalledRuntime(bundle, home);
		expect(again.copied).toBe(true);
		expect(readFileSync(join(again.root, "dist", "response-worker.cjs"), "utf8")).toBe("// worker\n");
	});
});

describe("connect and disconnect run the supported CLI paths", () => {
	it("connect runs `aidr setup --host claude-code` from the per-user copy and checks the result", async () => {
		const { home, bundle } = setup(userSettings);
		const calls: Array<{ file: string; args: readonly string[]; options?: RunOptions }> = [];
		const fakeSetup: Runner = async (file, args, options) => {
			calls.push({ file, args, options });
			const root = join(file, "..", "..");
			// What aidr setup writes: the registration and the receipt.
			writeFileSync(
				join(home, ".claude", "settings.json"),
				JSON.stringify({
					hooks: {
						PreToolUse: [
							{
								matcher: "*",
								hooks: [
									{
										type: "command",
										command: `"${file.replaceAll("\\", "/")}" hook pre-tool-use`,
										statusMessage: MANAGED_HOOK_MARKER,
									},
								],
							},
						],
					},
				}),
			);
			mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
			writeFileSync(join(home, ".singularity-aidr", "installation.json"), JSON.stringify({ path: root }));
			return { exitCode: 0, signal: null, stdout: "Setup complete", stderr: "", durationMs: 5, error: null };
		};
		const result = await connectClaude({ home, bundledRuntime: bundle, run: fakeSetup, language: "tr", machine: [] });
		expect(result.ok).toBe(true);
		expect(calls).toHaveLength(1);
		expect(calls[0]?.args).toEqual(["setup", "--host", "claude-code"]);
		expect(calls[0]?.file).toBe(runtimeBinary(installedRuntimeDir(home, checkRuntime(bundle))));
		expect(calls[0]?.options?.env?.AIDR_LOCALE).toBe("tr");
	});

	it("connect reports failure when the hooks were not registered, even with exit 0", async () => {
		const { home, bundle } = setup(userSettings);
		const result = await connectClaude({ home, bundledRuntime: bundle, run, language: "en", machine: [] });
		expect(result.ok).toBe(false);
		expect(result.message).toMatch(/not registered/);
	});

	it("disconnect runs the confirmed hooks-only uninstall and reports its backup", async () => {
		const { home, bundle } = setup(userSettings);
		const calls: Array<{ args: readonly string[]; env?: NodeJS.ProcessEnv }> = [];
		const fakeUninstall: Runner = async (_file, args, options) => {
			calls.push({ args, env: options?.env });
			return {
				exitCode: 0,
				signal: null,
				stdout: JSON.stringify({ outcome: "removed", removed: [{ event: "PreToolUse" }], backup_path: "C:/backup.json" }),
				stderr: "",
				durationMs: 3,
				error: null,
			};
		};
		const result = await disconnectClaude({ home, bundledRuntime: bundle, run: fakeUninstall, language: "en", machine: [] });
		expect(result).toMatchObject({ ok: true, backupPath: "C:/backup.json" });
		expect(calls[0]?.args).toEqual(["uninstall", "--hooks-only", "--yes", "--json"]);
		expect(calls[0]?.env?.AIDR_OPERATOR_NONINTERACTIVE).toBe("1");
	});

	it("disconnect surfaces a refusal", async () => {
		const { home, bundle } = setup(userSettings);
		const refusing: Runner = async () => ({
			exitCode: 1,
			signal: null,
			stdout: JSON.stringify({ outcome: "refused", reason: { code: "receipt_missing", detail: "No receipt" } }),
			stderr: "",
			durationMs: 3,
			error: null,
		});
		const result = await disconnectClaude({ home, bundledRuntime: bundle, run: refusing, language: "en", machine: [] });
		expect(result.ok).toBe(false);
		expect(result.message).toContain("No receipt");
		expect(existsSync(join(home, ".claude", "settings.json"))).toBe(true);
	});
});
