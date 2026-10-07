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

test("Windows notification dispatcher task is opt-in and mirrors its systemd units", () => {
	const service = readFileSync(join(maintenance, "aidr-notification-dispatch.service"), "utf8");
	const timer = readFileSync(join(maintenance, "aidr-notification-dispatch.timer"), "utf8");
	const linuxInstaller = readFileSync(join(maintenance, "install-systemd.sh"), "utf8");
	// Schedule: OnBootSec=45s, then every minute, never overlapping.
	assert.match(timer, /^OnBootSec=45s$/m);
	assert.match(timer, /^OnUnitActiveSec=1min$/m);
	assert.match(installer, /'aidr-notification-dispatch' \{[\s\S]*?\$boot\.Delay = 'PT45S'[\s\S]*?-RepetitionInterval \(New-TimeSpan -Minutes 1\)/);
	assert.match(installer, /-MultipleInstances IgnoreNew/);
	// Command and working directory: ExecStart=node <dir>/maintenance/notification-dispatch.mjs <dir>, no EnvironmentFile.
	assert.match(service, /^ExecStart=\/usr\/bin\/node \/srv\/aidr\/maintenance\/notification-dispatch\.mjs \/srv\/aidr$/m);
	assert.match(service, /^WorkingDirectory=\/srv\/aidr$/m);
	assert.doesNotMatch(service, /^EnvironmentFile=/m);
	assert.match(installer, /\$notificationWorker = Join-Path \$deployment 'maintenance\\notification-dispatch\.mjs'/);
	assert.match(installer, /-Argument "`"\$notificationWorker`" `"\$deployment`"" -WorkingDirectory \$deployment/);
	// Time limit equals TimeoutStartSec=2min.
	assert.match(service, /^TimeoutStartSec=2min$/m);
	assert.match(common, /Name = 'aidr-notification-dispatch'[\s\S]*?TimeLimit = New-TimeSpan -Minutes 2\r?\n\s*Optional = \$true/);
	assert.equal((common.match(/Optional = \$true/g) ?? []).length, 1, "only the notification dispatcher is opt-in");
	// Opt-in like --with-notifications, with the same fail-closed prerequisites.
	assert.match(linuxInstaller, /--with-notifications\) with_notifications=true/);
	assert.match(installer, /\[switch\]\$WithNotifications/);
	assert.match(installer, /Where-Object \{ -not \$_\.Optional \}/);
	for (const marker of ["aidr-notification-dispatch.service", "aidr-notification-dispatch.timer", "AIDR_NOTIFICATION_DISPATCH_TOKEN (32+ characters) is missing from .env.functions", "-lt 32", "AIDR_NOTIFICATION_ENCRYPTION_KEYS is missing from .env.functions", "^[a-z0-9][a-z0-9_-]*:"]) {
		assert.ok(installer.includes(marker), `installer must enforce ${marker}`);
	}
	assert.ok(linuxInstaller.includes("^AIDR_NOTIFICATION_ENCRYPTION_KEYS=[a-z0-9][a-z0-9_-]*:"));
	// One supervised dispatch after the evidence worker; a failure disables the task and exits non-zero.
	const siemRun = installer.indexOf("Wait-AidrInitialRun -TaskName 'aidr-siem-delivery'");
	const dispatchRegistration = installer.indexOf("Register-AidrMaintenanceTask $notificationDefinition");
	const dispatchRun = installer.indexOf("Wait-AidrInitialRun -TaskName 'aidr-notification-dispatch'");
	assert.ok(siemRun > 0 && siemRun < dispatchRegistration && dispatchRegistration < dispatchRun);
	assert.match(installer, /Disable-ScheduledTask -TaskPath \$script:AidrMaintenanceTaskPath -TaskName 'aidr-notification-dispatch'/);
	// The declaration lists only installed tasks; the doctor checks the opt-in task only when declared or installed.
	assert.match(installer, /tasks = \$declaredTasks/);
	assert.match(doctorSource, /windowsSchedulerCheck\("aidr-notification-dispatch", "notification-dispatch\.mjs", .*\{ optional: true \}\)/);
	assert.match(doctorSource, /optional && !state\.found && !windowsDeclaredTasks\.includes\(name\)/);
	assert.match(doctorSource, /name === "aidr-notification-dispatch" \? `"\$\{dir\}\\\\maintenance\\\\\$\{worker\}" "\$\{dir\}"`/);
	// No extra grant: the dispatcher only reads deployment.json and .env.functions, which are already granted read-only.
	assert.match(installer, /\$secretFiles = @\('deployment\.json', '\.env', '\.env\.functions'/);
	// The uninstaller iterates every definition, so the opt-in task is removed too.
	assert.match(uninstaller, /foreach \(\$definition in Get-AidrMaintenanceTaskDefinitions\)/);
});

test("Windows maintenance installer refuses registration over code a non-admin principal can replace", () => {
	// Trusted writers are exactly SYSTEM, Administrators and TrustedInstaller.
	assert.match(common, /\$script:AidrTrustedWriterSids = @\('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'\)/);
	assert.match(common, /function Get-AidrUntrustedWriterFinding \{/);
	assert.match(common, /function Assert-AidrTrustedWriterPaths \{/);
	assert.match(common, /\$Security\.GetOwner\(\[Security\.Principal\.SecurityIdentifier\]\)/);
	assert.match(common, /ReparsePoint\) \{ \$findings \+= "\$target is a symbolic link or junction" \}/);
	// node.exe is resolved to one explicit absolute path; first-hit PATH lookup is gone.
	assert.match(common, /Get-Command node\.exe -CommandType Application -All/);
	assert.match(common, /\$NodePath -notmatch '\^\[A-Za-z\]:\\\\'/);
	assert.doesNotMatch(installer, /Select-Object -First 1\)\.Source/);
	// Every executed path is checked, before the installer runs node.exe or registers anything.
	for (const path of ["$node, (Split-Path -Parent $node)", "$kit, (Join-Path $kit 'scripts'), $retentionScript", "$deployment, (Join-Path $deployment 'maintenance'), $worker, $readinessEnvPath", "if ($WithNotifications) { $taskCode += $notificationWorker }"]) {
		assert.ok(installer.includes(path), `installer must check ${path}`);
	}
	const assertion = installer.indexOf("Assert-AidrTrustedWriterPaths -Path $taskCode");
	assert.ok(assertion > 0);
	assert.ok(assertion < installer.indexOf("& $node --version"));
	assert.ok(assertion < installer.indexOf("Invoke-AidrIcacls @("));
	assert.ok(assertion < installer.indexOf("Register-ScheduledTask "));
	assert.ok(installer.indexOf("$notificationWorker = Join-Path") < assertion);
});

test("Windows maintenance ACL predicate rejects untrusted writers and accepts SYSTEM/Administrators-only ACLs", { skip: !powershellAvailable && "PowerShell is not available" }, (t) => {
	const body = `param([string]$Directory)
. (Join-Path $Directory 'AidrMaintenanceTasks.Common.ps1')
function New-Acl([string]$Owner, [object[]]$Rules) {
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($Owner))
  foreach ($r in $Rules) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($r[0]), [Security.AccessControl.FileSystemRights]$r[1], [Security.AccessControl.InheritanceFlags]$r[2], [Security.AccessControl.PropagationFlags]$r[3], [Security.AccessControl.AccessControlType]$r[4]))
  }
  return $acl
}
$trusted = @(@('S-1-5-18', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'), @('S-1-5-32-544', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'), @('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'FullControl', 'None', 'None', 'Allow'), @('S-1-5-32-545', 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'), @('S-1-3-0', 'FullControl', 'ContainerInherit,ObjectInherit', 'InheritOnly', 'Allow'), @('S-1-5-32-545', 'Modify', 'None', 'None', 'Deny'))
$cases = [ordered]@{
  'trusted-target' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-32-544' $trusted) -Path 'X:\\kit').Count
  'user-owner' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-32-545' $trusted) -Path 'X:\\kit').Count
  'users-modify' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-18' ($trusted + ,@('S-1-5-32-545', 'Modify', 'None', 'None', 'Allow'))) -Path 'X:\\kit') -join ' '
  'users-createfiles' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-18' ($trusted + ,@('S-1-5-11', 'CreateFiles', 'None', 'None', 'Allow'))) -Path 'X:\\kit').Count
  'users-inheritonly-target' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-18' ($trusted + ,@('S-1-5-32-545', 'Modify', 'ObjectInherit', 'InheritOnly', 'Allow'))) -Path 'X:\\kit').Count
  'users-inheritonly-ancestor' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-18' ($trusted + ,@('S-1-5-32-545', 'Modify', 'ObjectInherit', 'InheritOnly', 'Allow'))) -Path 'X:\\' -Ancestor).Count
  'users-createdirs-ancestor' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-18' ($trusted + ,@('S-1-5-11', 'CreateDirectories', 'None', 'None', 'Allow'))) -Path 'X:\\' -Ancestor).Count
  'users-delete-ancestor' = @(Get-AidrUntrustedWriterFinding -Security (New-Acl 'S-1-5-18' ($trusted + ,@('S-1-5-11', 'DeleteSubdirectoriesAndFiles', 'None', 'None', 'Allow'))) -Path 'X:\\' -Ancestor).Count
}
$userWritable = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('n'))
[IO.Directory]::CreateDirectory($userWritable) | Out-Null
try { Assert-AidrTrustedWriterPaths -Path @($userWritable); $cases['user-dir'] = 'accepted' } catch { $cases['user-dir'] = $_.Exception.Message } finally { Remove-Item -LiteralPath $userWritable -Force }
try { Resolve-AidrNodeExecutable -NodePath 'node.exe' | Out-Null; $cases['relative-node'] = 'accepted' } catch { $cases['relative-node'] = $_.Exception.Message }
$cases | ConvertTo-Json -Compress
`;
	const result = runPowerShell(t, body, [maintenance]);
	assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
	const cases = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
	assert.equal(cases["trusted-target"], 0);
	assert.equal(cases["user-owner"], 1);
	assert.match(cases["users-modify"], /^X:\\kit grants .*S-1-5-32-545\) Modify/);
	assert.equal(cases["users-createfiles"], 1);
	assert.equal(cases["users-inheritonly-target"], 1);
	assert.equal(cases["users-inheritonly-ancestor"], 0);
	assert.equal(cases["users-createdirs-ancestor"], 0);
	assert.equal(cases["users-delete-ancestor"], 1);
	assert.match(cases["user-dir"], /^Refusing to register tasks that run as LocalSystem or a gMSA/);
	assert.match(cases["user-dir"], /is owned by|grants/);
	assert.match(cases["relative-node"], /explicit absolute local path/);
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

test("Windows maintenance installer accepts -WithNotifications and still fails closed for a missing deployment", { skip: !powershellAvailable && "PowerShell is not available" }, (t) => {
	const missing = join(tmpdir(), `aidr-missing-deployment-${process.pid}-notifications`);
	const run = spawnSync(powershell, [
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", join(maintenance, "Install-AidrMaintenanceTasks.ps1"),
		"-DeploymentDirectory", missing, "-KitDirectory", missing, "-RunAsSystem", "-WithNotifications",
	], { encoding: "utf8", timeout: 120_000 });
	assert.equal(run.status, 1);
	const output = `${run.stdout}${run.stderr}`.replace(/\r?\n/g, "");
	assert.doesNotMatch(output, /parameter cannot be found|A parameter cannot be found/i);
	assert.match(output, /failed closed/);
});
