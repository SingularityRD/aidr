import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { renameWithRetry } from "./lib/atomic-write.mjs";

const repository = fileURLToPath(new URL("..", import.meta.url));
const installer = join(repository, "scripts", "endpoint-install.mjs");
const packageDir = join(repository, "packages", "claude-code");
const managedMarker = "Singularity AIDR managed installation";
const customerHook = { type: "command", command: "customer-command", timeout: 9 };

function temporaryHome(context) {
	const temporaryRoot = resolve(tmpdir());
	const home = mkdtempSync(join(temporaryRoot, "aidr-hook-lifecycle-"));
	context.after(() => {
		assert.equal(dirname(home), temporaryRoot);
		assert.ok(basename(home).startsWith("aidr-hook-lifecycle-"));
		rmSync(home, { recursive: true, force: true });
	});
	mkdirSync(join(home, ".claude"), { recursive: true });
	return home;
}

function writeMixedSettings(home) {
	const settingsPath = join(home, ".claude", "settings.json");
	writeFileSync(settingsPath, JSON.stringify({
		hooks: {
			PreToolUse: [{ matcher: "*", customFlag: "keep", hooks: [
				{ type: "command", command: "old-managed-command", statusMessage: managedMarker },
				customerHook,
			] }],
			PostToolUse: [{ hooks: [{ type: "command", command: "old-post-managed", statusMessage: managedMarker }] }],
		},
	}));
	return settingsPath;
}

function assertCustomerHookPreserved(settingsPath, managedExpected) {
	const settings = JSON.parse(readFileSync(settingsPath, "utf8"));
	const preToolUse = settings.hooks.PreToolUse;
	assert.deepEqual(preToolUse[0], { matcher: "*", customFlag: "keep", hooks: [customerHook] });
	assert.equal(preToolUse.length, managedExpected ? 2 : 1);
	if (managedExpected) assert.equal(preToolUse[1].hooks[0].statusMessage, managedMarker);
	else assert.ok(!JSON.stringify(settings).includes(managedMarker));
}

test("atomic settings replacement retries transient EPERM", () => {
	let attempts = 0;
	const sleeps = [];
	assert.doesNotThrow(() => renameWithRetry("staged-settings", "settings.json", {
		attempts: 4,
		delayMs: 7,
		rename: () => {
			attempts++;
			if (attempts < 3) {
				const error = new Error("sharing violation");
				error.code = "EPERM";
				throw error;
			}
		},
		sleep: (delay) => sleeps.push(delay),
	}));
	assert.equal(attempts, 3);
	assert.deepEqual(sleeps, [7, 7]);
});

test("fleet-staged installer runs without source-checkout sibling modules", (context) => {
	const home = temporaryHome(context);
	const stagedInstaller = join(home, "endpoint-install.mjs");
	copyFileSync(installer, stagedInstaller);
	const result = spawnSync(process.execPath, [stagedInstaller, "--package-dir", packageDir, "--home", home], {
		encoding: "utf8", timeout: 120000, cwd: home,
		env: { ...process.env, HOME: home, USERPROFILE: home },
	});
	assert.equal(result.status, 0, `staged installer failed: ${result.stderr || result.error?.message}`);
	assert.match(readFileSync(join(home, ".singularity-aidr", "installation.json"), "utf8"), /local_canary/);
});

test("reinstall preserves a customer hook alongside a managed hook", (context) => {
	const home = temporaryHome(context);
	const settingsPath = writeMixedSettings(home);
	const configPath = join(home, ".singularity-aidr", "config.json");
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
	const originalConfig = '{"policy":"customer-owned"}\n';
	writeFileSync(configPath, originalConfig);

	for (let attempt = 0; attempt < 2; attempt++) {
		const result = spawnSync(process.execPath, [installer, "--package-dir", packageDir, "--home", home], {
			encoding: "utf8", timeout: 120000, cwd: home,
			env: { ...process.env, HOME: home, USERPROFILE: home },
		});
		assert.equal(result.status, 0, `installer attempt ${attempt + 1} failed: ${result.stderr || result.error?.message}`);
		assertCustomerHookPreserved(settingsPath, true);
		assert.equal(readFileSync(configPath, "utf8"), originalConfig);
	}
	assert.equal(readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-backup-")).length, 1);
});

test("Unix uninstall removes only managed nested hooks", (context) => {
	const home = temporaryHome(context);
	const settingsPath = writeMixedSettings(home);
	const remover = join(repository, "deploy", "fleet", "unix", "remove-managed-hooks.mjs");
	const result = spawnSync(process.execPath, [remover, "--home", home], { encoding: "utf8", timeout: 30000 });
	assert.equal(result.status, 0, result.stderr || result.error?.message);
	assertCustomerHookPreserved(settingsPath, false);
	assert.equal(readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-backup-")).length, 1);
});

test("Windows uninstall removes only managed nested hooks", (context) => {
	const powershell = process.platform === "win32" ? "powershell.exe" : "pwsh";
	const available = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"], { encoding: "utf8" });
	if (available.error?.code === "ENOENT") return context.skip("PowerShell is unavailable on this host");
	assert.equal(available.status, 0, available.stderr || available.error?.message);
	const home = temporaryHome(context);
	const settingsPath = writeMixedSettings(home);
	const remover = join(repository, "deploy", "fleet", "windows", "Uninstall-Aidr.ps1");
	const result = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", remover, "-TargetHome", home, "-StateRoot", join(home, "fleet-state")], {
		encoding: "utf8", timeout: 30000, windowsHide: true,
	});
	assert.equal(result.status, 0, result.stderr || result.error?.message);
	assertCustomerHookPreserved(settingsPath, false);
	assert.equal(readdirSync(join(home, ".claude")).filter((name) => name.startsWith("settings.json.aidr-uninstall-backup-")).length, 1);
});
