import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fleet = join(repo, "deploy", "fleet", "windows");
const ps = process.platform === "win32" ? "powershell.exe" : "pwsh";
const quote = (value) => value.replaceAll("'", "''");

function fixture(mode, scenario) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-response-task-"));
	const events = join(directory, "events.txt");
	const seed = join(directory, "seed.json");
	writeFileSync(seed, JSON.stringify({ schema_version: 1, tenant_id: "public-operator-fixture" }));
	const digest = createHash("sha256").update(readFileSync(seed)).digest("hex");
	const script = join(directory, "fixture.ps1");
	const source = readFileSync(join(fleet, `${mode}-AidrResponseWorker.ps1`), "utf8")
		.replace(". (Join-Path $PSScriptRoot 'Common.ps1')", "");
	const setup = String.raw`
$ErrorActionPreference='Stop'
. '${quote(join(fleet, "Common.ps1"))}'
$script:scenario='${scenario}'
$script:eventPath='${quote(events)}'
function Log-Event([string]$Value) { [IO.File]::AppendAllText($script:eventPath,$Value+[Environment]::NewLine) }
$script:context=[pscustomobject]@{TargetHome='C:\Users\enrolled';Sid='S-1-5-21-1-2-3-1001';Node='C:\node\node.exe';Worker='C:\Users\enrolled\.singularity-aidr\connectors\claude\candidate\dist\response-worker.cjs';TaskName='AIDR-Response-fixture';TaskPath='\SingularityAIDR\';Description='Singularity AIDR signed fleet response worker v1; owner_sid=S-1-5-21-1-2-3-1001';Configuration='${quote(join(directory, "config.json"))}'}
function Get-AidrResponseWorkerContext { return $script:context }
function Get-AidrResponseScheduledTask {
 if($script:scenario -eq 'query-failure'){throw 'scheduled task inventory unavailable'}
 if($script:scenario -in @('fresh','missing-pin','wrong-pin','initialize-failure')){return $null}
 return [pscustomobject]@{Description=$(if($script:scenario -eq 'foreign-task'){'customer task'}else{$script:context.Description});Principal=[pscustomobject]@{UserId=$script:context.Sid;LogonType='Interactive';RunLevel='Limited'};Actions=@([pscustomobject]@{Execute=$script:context.Node;Arguments='"'+$script:context.Worker+'"'})}
}
function Invoke-AidrResponseWorkerProvisioning {
 param($Context,[string]$Mode,[AllowNull()][string]$InputJson)
 Log-Event ('validate '+$Mode)
 if($script:scenario -in @('initialize-failure','unsafe-removal','validate-failure')){throw 'mock authenticated state unavailable'}
 if($Mode -eq '--initialize') { if($InputJson -notmatch 'public-operator-fixture'){throw 'missing bounded stdin seed'}; [IO.File]::WriteAllText($Context.Configuration,'{}') }
}
function New-ScheduledTaskAction { param($Execute,$Argument);Log-Event 'action';if($Execute -ne $script:context.Node -or $Argument -cne ('"'+$script:context.Worker+'"')){throw 'unexpected task executable or arguments'};return [pscustomobject]@{Execute=$Execute;Arguments=$Argument} }
function New-ScheduledTaskTrigger { param([switch]$AtLogOn,$User,[switch]$Once,$At,$RepetitionInterval);Log-Event $(if($AtLogOn){'logon'}else{'retry'});return [pscustomobject]@{} }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel);Log-Event ('principal '+$LogonType+' '+$RunLevel);if($UserId -ne $script:context.Sid -or $LogonType -ne 'Interactive'){throw 'credential principal mismatch'};return [pscustomobject]@{} }
function New-ScheduledTaskSettingsSet { param($MultipleInstances,[switch]$StartWhenAvailable,$ExecutionTimeLimit,$RestartCount,$RestartInterval,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries);Log-Event 'settings';if($MultipleInstances -ne 'IgnoreNew' -or $ExecutionTimeLimit.TotalSeconds -ne 0){throw 'unexpected scheduler settings'};return [pscustomobject]@{} }
function New-ScheduledTask { param($Action,$Trigger,$Principal,$Settings,$Description);Log-Event 'task';return [pscustomobject]@{} }
function Register-ScheduledTask { param($TaskPath,$TaskName,$InputObject,[switch]$Force,$ErrorAction);Log-Event 'register';return [pscustomobject]@{} }
function Start-ScheduledTask { param($TaskPath,$TaskName,$ErrorAction);Log-Event 'start' }
function Stop-ScheduledTask { param($TaskPath,$TaskName,$ErrorAction);Log-Event 'stop' }
function Unregister-ScheduledTask { param($TaskPath,$TaskName,$Confirm,$ErrorAction);Log-Event 'unregister' }
if($script:scenario -in @('existing','foreign-task','validate-failure','unsafe-removal','safe-removal','query-failure')){[IO.File]::WriteAllText($script:context.Configuration,'{}')}
$block=[scriptblock]::Create(@'
${source}
'@)
${mode === "Install" ? `& $block -TargetHome 'C:\\Users\\enrolled' -StateRoot '${quote(directory)}' -ResponseWorkerConfigPath '${quote(seed)}' ${scenario === "missing-pin" ? "" : `-ExpectedResponseWorkerConfigSha256 '${scenario === "wrong-pin" ? "0".repeat(64) : digest}'`}` : `& $block -TargetHome 'C:\\Users\\enrolled' -StateRoot '${quote(directory)}'`}
`;
	writeFileSync(script, setup);
	try {
		const result = spawnSync(ps, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script], { encoding: "utf8", timeout: 30_000, windowsHide: true });
		return { ...result, events: (() => { try { return readFileSync(events, "utf8").trim().split(/\r?\n/); } catch { return []; } })() };
	} finally { rmSync(directory, { recursive: true, force: true }); }
}

test("fresh activation validates pinned seed and initial journal before registering an interactive user task", () => {
	const result = fixture("Install", "fresh");
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(result.events.slice(0, 2), ["validate --initialize", "validate --validate"]);
	assert.ok(result.events.includes("principal Interactive Limited"));
	assert.deepEqual(result.events.slice(-2), ["register", "start"]);
});

test("upgrade validates existing authenticated state and rebinds the task without initializing running", () => {
	const result = fixture("Install", "existing");
	assert.equal(result.status, 0, result.stderr);
	assert.equal(result.events.includes("validate --initialize"), false);
	assert.equal(result.events[0], "validate --validate");
	assert.deepEqual(result.events.slice(-3), ["stop", "register", "start"]);
});

for (const scenario of ["missing-pin", "wrong-pin", "foreign-task", "query-failure", "initialize-failure", "validate-failure"]) {
	test(`installation fails closed before task mutation for ${scenario}`, () => {
		const result = fixture("Install", scenario);
		assert.notEqual(result.status, 0);
		assert.equal(result.events.includes("register"), false);
		assert.equal(result.events.includes("stop"), false);
		assert.equal(result.events.includes("start"), false);
	});
}

test("unsafe removal restarts owned task and never unregisters it", () => {
	const result = fixture("Uninstall", "unsafe-removal");
	assert.notEqual(result.status, 0);
	assert.deepEqual(result.events, ["stop", "validate --validate-safe-removal", "start"]);
});

test("safe removal observes authenticated idle after stopping and unregisters only the owned task", () => {
	const result = fixture("Uninstall", "safe-removal");
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(result.events, ["stop", "validate --validate-safe-removal", "unregister"]);
});

test("foreign task removal fails before stopping or unregistering", () => {
	const result = fixture("Uninstall", "foreign-task");
	assert.notEqual(result.status, 0);
	assert.deepEqual(result.events, []);
});

test("real context refuses a different profile before any vault, native or scheduler action", () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-response-principal-"));
	const script = join(directory, "principal.ps1");
	writeFileSync(script, `. '${quote(join(fleet, "Common.ps1"))}'\ntry { Get-AidrResponseWorkerContext -TargetHome '${quote(directory)}' -StateRoot '${quote(directory)}'; exit 0 } catch { Write-Output $_.Exception.Message; exit 1 }\n`);
	try {
		const result = spawnSync(ps, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script], { encoding: "utf8", timeout: 20_000, windowsHide: true });
		assert.notEqual(result.status, 0);
		assert.match(result.stdout, process.platform === "win32" ? /enrolled Windows user/ : /requires Windows/);
	} finally { rmSync(directory, { recursive: true, force: true }); }
});

test("Windows accepts the scheduler definition and exact ownership contract without registering a task", { skip: process.platform !== "win32" }, () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-response-task-definition-"));
	const script = join(directory, "definition.ps1");
	writeFileSync(script, String.raw`
$ErrorActionPreference='Stop'
. '${quote(join(fleet, "Common.ps1"))}'
$profile=[Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$node=(Get-Command node.exe -ErrorAction Stop).Source
$worker=Join-Path $profile '.singularity-aidr/connectors/claude/readonly-fixture/dist/response-worker.cjs'
$context=[pscustomobject]@{TargetHome=$profile;Sid=$sid;Node=$node;Worker=$worker;Description="Singularity AIDR signed fleet response worker v1; owner_sid=$sid"}
$action=New-ScheduledTaskAction -Execute $node -Argument ('"'+$worker+'"')
$logon=New-ScheduledTaskTrigger -AtLogOn -User $sid
$retry=New-ScheduledTaskTrigger -Once -At ([DateTime]::Now.AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 1)
$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$task=New-ScheduledTask -Action $action -Trigger @($logon,$retry) -Principal $principal -Settings $settings -Description $context.Description
Assert-AidrResponseTaskOwnership -Task $task -Context $context
if([string]$task.Principal.LogonType -ne 'Interactive' -or [string]$task.Principal.RunLevel -ne 'Limited' -or @($task.Triggers).Count -ne 2 -or [string]$task.Settings.ExecutionTimeLimit -ne 'PT0S'){throw 'unexpected task definition'}
Write-Output 'readonly task definition accepted'
`);
	try {
		const result = spawnSync(ps, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script], { encoding: "utf8", timeout: 20_000, windowsHide: true });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(result.stdout.trim(), "readonly task definition accepted");
	} finally { rmSync(directory, { recursive: true, force: true }); }
});
