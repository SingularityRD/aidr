import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const maintenance = join(repository, "deploy", "maintenance");
const doctorSource = readFileSync(join(repository, "scripts", "deployment-doctor.mjs"), "utf8");
const common = readFileSync(join(maintenance, "AidrMaintenanceTasks.Common.ps1"), "utf8");
const installer = readFileSync(join(maintenance, "Install-AidrMaintenanceTasks.ps1"), "utf8");
const uninstaller = readFileSync(join(maintenance, "Uninstall-AidrMaintenanceTasks.ps1"), "utf8");
const scripts = ["AidrMaintenanceTasks.Common.ps1", "Install-AidrMaintenanceTasks.ps1", "Uninstall-AidrMaintenanceTasks.ps1"];
const powershell = process.platform === "win32" ? "powershell.exe" : "pwsh";
const powershellAvailable = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"], { encoding: "utf8" }).status === 0;

function runPowerShell(t, body, args = []) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-maintenance-ps-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	const file = join(directory, "probe.ps1");
	writeFileSync(file, body);
	return spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file, ...args], { encoding: "utf8", timeout: 120_000 });
}

test("every systemd timer in deploy/maintenance has a fixed-name Windows scheduled task", () => {
	const timers = readdirSync(maintenance).filter((name) => name.endsWith(".timer")).map((name) => name.slice(0, -".timer".length)).sort();
	const tasks = [...common.matchAll(/Name = '([a-z-]+)'/g)].map((match) => match[1]).sort();
	assert.ok(timers.length > 0);
	assert.deepEqual(tasks, timers);
	assert.match(common, /\$script:AidrMaintenanceTaskPath = '\\AIDR\\'/);
	// The doctor must query exactly these names.
	for (const task of tasks) assert.match(doctorSource, new RegExp(`windowsSchedulerCheck\\("${task}"`));
});

test("Windows maintenance scripts keep strict, fail-closed PowerShell conventions", () => {
	assert.match(common, /^Set-StrictMode -Version Latest\r?\n\$ErrorActionPreference = 'Stop'/);
	for (const source of [installer, uninstaller]) {
		assert.match(source, /\. \(Join-Path \$PSScriptRoot 'AidrMaintenanceTasks\.Common\.ps1'\)/);
		assert.match(source, /Assert-AidrElevatedWindows/);
		assert.match(source, /exit 1\r?\n\}\s*$/);
		assert.doesNotMatch(source, /Invoke-Expression|\biex\b/i);
	}
	// Least privilege: a gMSA is the default parameter set and LocalSystem must be
	// requested explicitly; no stored password logon is ever registered.
	assert.match(installer, /DefaultParameterSetName = 'ServiceAccount'/);
	assert.match(installer, /-LogonType Password -RunLevel Limited/);
	assert.doesNotMatch(installer, /-Password\b|ConvertTo-SecureString/);
	// Same activation prerequisites as install-systemd.sh.
	for (const marker of ["AIDR_SIGNING_KEY_EXPIRES_AT", "AIDR_DELEGATION_SIGNING_KEY_EXPIRES_AT", "REPLACE_", "Configure at least one real durable queue source"]) {
		assert.ok(installer.includes(marker), `installer must enforce ${marker}`);
	}
	assert.match(installer, /Wait-AidrInitialRun -TaskName 'aidr-siem-delivery'/);
	assert.match(installer, /Disable-ScheduledTask/);
});

test("Windows maintenance scripts mirror the systemd schedules and commands", () => {
	const siemTimer = readFileSync(join(maintenance, "aidr-siem-delivery.timer"), "utf8");
	const retentionTimer = readFileSync(join(maintenance, "aidr-export-retention.timer"), "utf8");
	assert.match(siemTimer, /OnBootSec=30s/);
	assert.match(siemTimer, /OnUnitActiveSec=1min/);
	assert.match(installer, /\$boot\.Delay = 'PT30S'/);
	assert.match(installer, /-RepetitionInterval \(New-TimeSpan -Minutes 1\)/);
	assert.match(retentionTimer, /OnCalendar=hourly/);
	assert.match(retentionTimer, /RandomizedDelaySec=5min/);
	assert.match(installer, /-RepetitionInterval \(New-TimeSpan -Hours 1\) -RandomDelay \(New-TimeSpan -Minutes 5\)/);
	assert.match(readFileSync(join(maintenance, "aidr-siem-delivery.service"), "utf8"), /readiness-evidence-worker\.mjs/);
	assert.match(readFileSync(join(maintenance, "aidr-export-retention.service"), "utf8"), /deployment-maintenance\.mjs \/srv\/aidr --apply/);
	assert.match(installer, /--env-file=\$readinessEnvPath/);
	assert.match(installer, /"`"\$retentionScript`" `"\$deployment`" --apply"/);
	assert.match(common, /TimeLimit = New-TimeSpan -Minutes 5/);
	assert.match(common, /TimeLimit = New-TimeSpan -Minutes 15/);
});

test("Windows maintenance scripts parse without PowerShell syntax errors", { skip: !powershellAvailable && "PowerShell is not available" }, (t) => {
	const body = `param([string]$Directory)
$failed = $false
foreach ($name in @(${scripts.map((name) => `'${name}'`).join(", ")})) {
  $tokens = $null; $errors = $null
  [Management.Automation.Language.Parser]::ParseFile((Join-Path $Directory $name), [ref]$tokens, [ref]$errors) | Out-Null
  foreach ($e in $errors) { Write-Output "$($name): $($e.Message)"; $failed = $true }
}
if ($failed) { exit 1 }
`;
	const result = runPowerShell(t, body, [maintenance]);
	assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});

test("Windows maintenance installer fails closed before registering anything for a missing deployment", { skip: !powershellAvailable && "PowerShell is not available" }, (t) => {
	const missing = join(tmpdir(), `aidr-missing-deployment-${process.pid}`);
	const run = spawnSync(powershell, [
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", join(maintenance, "Install-AidrMaintenanceTasks.ps1"),
		"-DeploymentDirectory", missing, "-KitDirectory", missing, "-RunAsSystem",
	], { encoding: "utf8", timeout: 120_000 });
	assert.equal(run.status, 1);
	// PowerShell wraps error records at the console width; join the lines back up.
	const output = `${run.stdout}${run.stderr}`.replace(/\r?\n/g, "");
	assert.match(output, /failed closed/);
	assert.match(output, /must run on Windows|elevated administrator|Cannot find path|does not exist/);
});
