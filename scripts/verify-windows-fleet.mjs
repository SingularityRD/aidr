#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, copyFileSync, existsSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = repo;
const fleet = join(repo, "deploy", "fleet", "windows");
const powershell = process.platform === "win32" ? "powershell.exe" : "pwsh";
const tar = process.platform === "win32" ? "tar.exe" : "tar";
const parentDevelopmentMode = process.env.AIDR_DEVELOPMENT_MODE;
const fleetFixtureEnv = Object.freeze({ AIDR_DEVELOPMENT_MODE: "true" });
const required = [
	"Common.ps1",
	"Install-Aidr.ps1",
	"Install-AidrResponseWorker.ps1",
	"Uninstall-AidrResponseWorker.ps1",
	"Invoke-AidrResponseAction.ps1",
	"Update-Aidr.ps1",
	"Rollback-Aidr.ps1",
	"Uninstall-Aidr.ps1",
	"Invoke-AidrRemediation.ps1",
	"Test-AidrDetection.ps1",
	"Test-AidrFleetScriptSignatures.ps1",
	"New-AidrFleetManifest.ps1",
	"aidr-fleet-manifest.schema.json",
	"README.md",
];
const checks = [];
const work = mkdtempSync(join(tmpdir(), "aidr-windows-fleet-"));
if (process.env.AIDR_KEEP_FLEET_FIXTURE === "1") console.error(`Fleet verifier fixture: ${work}`);

try {
	for (const name of required) assert.ok(existsSync(join(fleet, name)), `missing ${name}`);
	checks.push("all Windows fleet delivery files exist");

	const syntaxScript = join(work, "syntax.ps1");
	writeFileSync(
		syntaxScript,
		`param([string]$Directory)\n$errors=@()\nGet-ChildItem -LiteralPath $Directory -Filter *.ps1 | ForEach-Object { $t=$null; $e=$null; [Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e)|Out-Null; $errors += $e }\nif($errors.Count){$errors|ForEach-Object{$_.Message};exit 1}\n`,
	);
	runPs(syntaxScript, [fleet]);
	checks.push("all PowerShell entrypoints parse without errors");

	if (process.platform === "win32") {
		const oversizedSource = join(work, "expanded-over-limit.bin");
		const oversizedArchive = join(work, "expanded-over-limit.tgz");
		const file = openSync(oversizedSource, "w");
		try { ftruncateSync(file, 536870913); } finally { closeSync(file); }
		execFileSync(tar, ["-czf", oversizedArchive, "-C", work, "expanded-over-limit.bin"], { stdio: "pipe" });
		assert.ok(statSync(oversizedArchive).size < 536870912, "fixture must be a compressed archive bomb, not an oversized transport");
		const expandScript = join(work, "expand-archive.ps1");
		writeFileSync(expandScript, [
			"param([string]$Archive,[string]$Destination)",
			"$ErrorActionPreference='Stop'",
			". '" + join(fleet, "Common.ps1").replaceAll("'", "''") + "'",
			"try { Expand-AidrVerifiedArchive -Archive $Archive -Destination $Destination } catch { Write-Error $_; exit 1 }",
		].join("\n") + "\n");
		const expandedDestination = join(work, "expanded-output");
		const expansion = runPs(expandScript, [oversizedArchive, expandedDestination], false);
		assert.notEqual(expansion.status, 0);
		assert.match(`${expansion.stdout}\n${expansion.stderr}`, /512 MiB/);
		assert.equal(existsSync(expandedDestination), false, "oversized content must be rejected before extraction creates a destination");
		checks.push("compressed archive bomb is rejected by its advertised expanded size before extraction");
	}

	const developmentModeProbe = join(work, "development-mode.ps1");
	writeFileSync(developmentModeProbe, `Write-Output $env:AIDR_DEVELOPMENT_MODE\n`);
	assert.equal(runPs(developmentModeProbe, [], true, fleetFixtureEnv).trim(), "true");
	assert.equal(process.env.AIDR_DEVELOPMENT_MODE, parentDevelopmentMode);
	checks.push("development mode was passed only to a spawned test child, not set process-wide");

	const rejectedPreflight = runPs(join(fleet, "Test-AidrFleetScriptSignatures.ps1"), [
		"-ExpectedThumbprint",
		"0".repeat(40),
	], false);
	assert.notEqual(rejectedPreflight.status, 0);
	assert.match(
		`${rejectedPreflight.stdout}\n${rejectedPreflight.stderr}`,
		process.platform === "win32" ? /NotSigned|pinned management-script certificate|Could not inspect Authenticode/ : /must run on Windows/,
	);
	checks.push("Authenticode preflight failed closed for unsigned, unpinned, or unavailable signatures");

	const package1 = makePackage("1.0.0", "v1");
	const package2 = makePackage("1.0.1", "v2");
	const signerScript = join(work, "sign.ps1");
	writeFileSync(
		signerScript,
		String.raw`param([string]$Artifact1,[string]$Artifact2)
$ErrorActionPreference='Stop'
try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop } catch { Add-Type -AssemblyName System.Security -ErrorAction Stop }
$rsa=[Security.Cryptography.RSA]::Create(2048)
$request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=AIDR Offline Fleet Verification',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddHours(1))
foreach($artifact in @($Artifact1,$Artifact2)){
  $content=[Security.Cryptography.Pkcs.ContentInfo]::new([IO.File]::ReadAllBytes($artifact))
  $cms=[Security.Cryptography.Pkcs.SignedCms]::new($content,$true)
  $signer=[Security.Cryptography.Pkcs.CmsSigner]::new($cert)
  $signer.IncludeOption=[Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
  $cms.ComputeSignature($signer)
  [IO.File]::WriteAllBytes("$artifact.p7s",$cms.Encode())
}
$cert.Thumbprint
`,
	);
	const signerThumbprint = runPs(signerScript, [package1, package2]).trim().split(/\r?\n/).at(-1);
	assert.match(signerThumbprint, /^[A-F0-9]{40,128}$/i);
	checks.push("ephemeral offline CMS signer created for workflow verification");

	const config = join(work, "agent-config.json");
	const secretMarker = "OFFLINE_FIXTURE_SECRET_MUST_NOT_APPEAR_IN_LOGS";
	writeFileSync(config, `${JSON.stringify({ schema_version: 1, api_key: secretMarker, policy: { remote_policy_required: true } }, null, 2)}\n`);
	const deployment1 = generateManifest(package1, "1.0.0", signerThumbprint, config);
	const deployment2 = generateManifest(package2, "1.0.1", signerThumbprint, config);
	checks.push("manifest generator pinned artifact, installer, configuration and signer identity");

	const target = join(work, "user-profile");
	const stateRoot = join(work, "protected-state");
	mkdirSync(join(target, ".claude"), { recursive: true });
	mkdirSync(join(target, ".singularity-aidr"), { recursive: true });
	const unrelatedStatus = "Unrelated customer hook";
	writeFileSync(join(target, ".claude", "settings.json"), `${JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "safe-customer-hook", statusMessage: unrelatedStatus }] }] } }, null, 2)}\n`);
	const preservedConfig = `${JSON.stringify({ schema_version: 1, existing: "preserve-me" }, null, 2)}\n`;
	writeFileSync(join(target, ".singularity-aidr", "config.json"), preservedConfig);

	runFleet("Install-Aidr.ps1", ["-ManifestPath", deployment1.manifest, "-ExpectedManifestSha256", deployment1.sha, "-TargetHome", target, "-StateRoot", stateRoot]);
	const detected1 = JSON.parse(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"]));
	assert.equal(detected1.detected, true);
	assert.equal(detected1.version, "1.0.0");
	assert.equal(detected1.host_execution, "unverified");
	checks.push("install and Intune/SCCM detection workflow passed with a local deny canary");

	runFleet("Update-Aidr.ps1", ["-ManifestPath", deployment2.manifest, "-ExpectedManifestSha256", deployment2.sha, "-TargetHome", target, "-StateRoot", stateRoot]);
	const detected2 = JSON.parse(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"]));
	assert.equal(detected2.version, "1.0.1");
	checks.push("upgrade accepted only a newer semantic version");

	runFleet("Rollback-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot]);
	const rolledBack = JSON.parse(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"]));
	assert.equal(rolledBack.version, "1.0.0");
	checks.push("rollback revalidated and restored the retained signed candidate");
	const statePath = join(stateRoot, "targets", targetId(target), "state.json");
	const rollbackState = JSON.parse(readFileSync(statePath, "utf8"));
	assert.deepEqual(rollbackState.history.map((candidate) => candidate.manifest_sha256), [deployment2.sha]);
	runFleet("Rollback-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot]);
	assert.equal(JSON.parse(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"])).version, "1.0.1");
	runFleet("Rollback-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot]);
	assert.equal(JSON.parse(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"])).version, "1.0.0");
	checks.push("rollback history preserves recency and never retains its active manifest as a candidate");

	assert.equal(readFileSync(join(target, ".singularity-aidr", "config.json"), "utf8"), preservedConfig);
	const settings = JSON.parse(readFileSync(join(target, ".claude", "settings.json"), "utf8"));
	assert.ok(settings.hooks.PreToolUse.some((entry) => entry.hooks.some((hook) => hook.statusMessage === unrelatedStatus)));
	checks.push("existing agent configuration and unrelated hooks were preserved");

	const activeState = JSON.parse(readFileSync(statePath, "utf8"));
	const activeBundle = join(activeState.active.connector_path, "dist", "pre-tool-use.cjs");
	const activeBundleBytes = readFileSync(activeBundle);
	writeFileSync(activeBundle, Buffer.concat([activeBundleBytes, Buffer.from("//tamper\n")]));
	const modifiedInstall = runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"], false);
	assert.notEqual(modifiedInstall.status, 0);
	writeFileSync(activeBundle, activeBundleBytes);
	const restoredInstall = JSON.parse(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"]));
	assert.equal(restoredInstall.detected, true);
	checks.push("detection rejected modified installed connector bytes");

	const wrongManifest = runFleet("Install-Aidr.ps1", ["-ManifestPath", deployment1.manifest, "-ExpectedManifestSha256", "0".repeat(64), "-TargetHome", target, "-StateRoot", stateRoot], false);
	assert.notEqual(wrongManifest.status, 0);
	checks.push("incorrect command-line manifest digest failed closed");

	const originalArtifact = readFileSync(join(deployment1.directory, "payload", "aidr-claude-1.0.0.tgz"));
	writeFileSync(join(deployment1.directory, "payload", "aidr-claude-1.0.0.tgz"), Buffer.concat([originalArtifact, Buffer.from("tamper")]));
	const tampered = runFleet("Install-Aidr.ps1", ["-ManifestPath", deployment1.manifest, "-ExpectedManifestSha256", deployment1.sha, "-TargetHome", target, "-StateRoot", stateRoot], false);
	assert.notEqual(tampered.status, 0);
	checks.push("tampered artifact failed SHA-256 validation before extraction");

	const signatureManifest = JSON.parse(readFileSync(deployment2.manifest, "utf8"));
	signatureManifest.artifact.allowed_signer_thumbprints = ["0".repeat(40)];
	writeFileSync(deployment2.manifest, `${JSON.stringify(signatureManifest, null, 2)}\n`);
	const signatureManifestSha = sha256(deployment2.manifest);
	const wrongSigner = runFleet("Install-Aidr.ps1", ["-ManifestPath", deployment2.manifest, "-ExpectedManifestSha256", signatureManifestSha, "-TargetHome", target, "-StateRoot", stateRoot], false);
	assert.notEqual(wrongSigner.status, 0);
	checks.push("unapproved CMS signer failed closed");

	const traversalManifest = JSON.parse(readFileSync(deployment2.manifest, "utf8"));
	traversalManifest.artifact.path = "../outside.tgz";
	writeFileSync(deployment2.manifest, `${JSON.stringify(traversalManifest, null, 2)}\n`);
	const traversal = runFleet("Install-Aidr.ps1", ["-ManifestPath", deployment2.manifest, "-ExpectedManifestSha256", sha256(deployment2.manifest), "-TargetHome", target, "-StateRoot", stateRoot], false);
	assert.notEqual(traversal.status, 0);
	checks.push("manifest path traversal failed before filesystem access");

	const unsafeTarget = runFleet("Test-AidrDetection.ps1", ["-TargetHome", parse(target).root, "-StateRoot", stateRoot, "-Json"], false);
	assert.notEqual(unsafeTarget.status, 0);
	checks.push("filesystem-root TargetHome was rejected");

	const protectedPathsScript = join(work, "protected-paths.ps1");
	writeFileSync(protectedPathsScript, String.raw`param([string]$Common,[string]$Fixture)
. $Common
foreach ($root in @($env:windir, $env:ProgramData, $env:ProgramFiles, [Environment]::GetEnvironmentVariable('ProgramFiles(x86)'))) {
  if (-not $root) { continue }
  $child = Get-ChildItem -LiteralPath $root -Directory | Select-Object -First 1
  if ($null -eq $child) { throw "No test child under $root" }
  try { $null = Get-AidrValidatedTargetHome $child.FullName; throw "Accepted protected child $($child.FullName)" }
  catch { if ($_.Exception.Message -like 'Accepted protected child*') { throw } }
}
$file = Join-Path $Fixture 'concurrent-settings.json'
[IO.File]::WriteAllText($file, '{"customer":1}')
$original = [IO.File]::ReadAllBytes($file)
[IO.File]::WriteAllText($file, '{"customer":2}')
try { Assert-AidrFileUnchanged -Path $file -OriginalBytes $original; throw 'Accepted a concurrent customer edit' }
catch { if ($_.Exception.Message -eq 'Accepted a concurrent customer edit') { throw } }
`);
	runPs(protectedPathsScript, [join(fleet, "Common.ps1"), work]);
	checks.push("protected system descendants and concurrent customer-byte changes were rejected");

	const logs = readFileSync(join(stateRoot, "logs", `${targetId(target)}.jsonl`), "utf8");
	assert.ok(!logs.includes(secretMarker));
	assert.ok(!/(api[_-]?key|bearer|password|secret)/i.test(logs));
	checks.push("structured fleet logs excluded configuration and credential material");

	const settingsPath = join(target, ".claude", "settings.json");
	const installedSettings = JSON.parse(readFileSync(settingsPath, "utf8"));
	const managedMarker = "Singularity AIDR managed installation";
	const preToolEntry = (value) => value.hooks.PreToolUse.find((entry) => entry.hooks.some((hook) => hook.statusMessage === managedMarker));
	const managedHook = (entry) => entry.hooks.find((hook) => hook.statusMessage === managedMarker);
	const invalidRegistrations = [
		["non-executing echo command", (entry) => { managedHook(entry).command = `echo ${managedHook(entry).command}`; }],
		["additional shell command", (entry) => { managedHook(entry).command += " & echo skipped"; }],
		["prompt hook type", (entry) => { managedHook(entry).type = "prompt"; }],
		["asynchronous security hook", (entry) => { managedHook(entry).async = true; }],
		["restrictive tool matcher", (entry) => { entry.matcher = "Read"; }],
		["shortened hook timeout", (entry) => { managedHook(entry).timeout = 1; }],
	];
	for (const [label, mutate] of invalidRegistrations) {
		const invalid = structuredClone(installedSettings);
		mutate(preToolEntry(invalid));
		writeFileSync(settingsPath, `${JSON.stringify(invalid)}\n`);
		assert.notEqual(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"], false).status, 0, label);
		assert.notEqual(runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-DetectionOnly", "-Json"], false).status, 0, label);
		assert.equal(JSON.parse(runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"])).outcome, "repaired", label);
	}
	checks.push("detection and remediation reject and repair non-executing, asynchronous, and restricted security hooks");
	const globallyDisabled = { ...structuredClone(installedSettings), disableAllHooks: true };
	const globallyDisabledBytes = `${JSON.stringify(globallyDisabled)}\n`;
	writeFileSync(settingsPath, globallyDisabledBytes);
	assert.notEqual(runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"], false).status, 0);
	assert.equal(JSON.parse(runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"], false).stdout).reason.code, "host_hooks_disabled");
	assert.equal(readFileSync(settingsPath, "utf8"), globallyDisabledBytes);
	checks.push("globally disabled host hooks are unhealthy and cannot be silently re-enabled");
	for (const malformed of ['"customer"\n', "true\n", "42\n", '{"hooks":"customer"}\n']) {
		writeFileSync(settingsPath, malformed);
		assert.notEqual(runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"], false).status, 0, malformed);
		assert.equal(readFileSync(settingsPath, "utf8"), malformed);
		assert.notEqual(runFleet("Uninstall-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot], false).status, 0, malformed);
		assert.equal(readFileSync(settingsPath, "utf8"), malformed);
	}
	checks.push("remediation and uninstall refuse scalar or malformed settings without reinterpreting customer bytes");
	writeFileSync(settingsPath, `${JSON.stringify(installedSettings)}\n`);
	const deepValue = (depth) => {
		let value = { leaf: "customer-value" };
		for (let i = 0; i < depth; i++) value = { nested: value };
		return value;
	};
	const assertDeepLeaf = (value, depth) => {
		for (let i = 0; i < depth; i++) value = value.nested;
		assert.equal(value.leaf, "customer-value");
	};
	const removeManagedEvent = (value) => { delete value.hooks.PostToolUse; return value; };
	let customerSettings = JSON.parse(readFileSync(settingsPath, "utf8"));
	preToolEntry(customerSettings).hooks.push({ type: "command", command: "safe-case-variant-customer-hook", statusMessage: managedMarker.toLowerCase() });
	customerSettings.customerDeep = deepValue(35);
	writeFileSync(settingsPath, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`${JSON.stringify(removeManagedEvent(customerSettings), null, 2)}\n`)]));
	const repaired = JSON.parse(runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"]));
	assert.equal(repaired.outcome, "repaired");
	const repairedSettings = JSON.parse(readFileSync(settingsPath, "utf8"));
	assertDeepLeaf(repairedSettings.customerDeep, 35);
	assert.ok(repairedSettings.hooks.PreToolUse.some((entry) => entry.hooks.some((hook) => hook.command === "safe-case-variant-customer-hook")));
	checks.push("remediation accepted UTF-8 BOM settings and preserved deep JSON and exact customer hook ownership");
	const canarySettings = `${JSON.stringify(removeManagedEvent(structuredClone(repairedSettings)))}\n`;
	writeFileSync(settingsPath, canarySettings);
	writeFileSync(activeBundle, 'process.stdout.write(JSON.stringify({hookSpecificOutput:{permissionDecision:"deny",permissionDecisionReason:"Internal error"},systemMessage:"Detection unavailable"}));\n');
	const degradedCanary = runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"], false);
	assert.notEqual(degradedCanary.status, 0);
	assert.equal(JSON.parse(degradedCanary.stdout).reason.code, "deny_canary_failed");
	assert.equal(readFileSync(settingsPath, "utf8"), canarySettings);
	writeFileSync(activeBundle, 'setInterval(() => {}, 1000);\n');
	const hungCanary = runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"], false);
	assert.notEqual(hungCanary.status, 0);
	assert.equal(JSON.parse(hungCanary.stdout).reason.code, "deny_canary_failed");
	assert.match(JSON.parse(hungCanary.stdout).reason.detail, /timed out/);
	assert.equal(readFileSync(settingsPath, "utf8"), canarySettings);
	writeFileSync(activeBundle, activeBundleBytes);
	checks.push("remediation rejected an internal-error deny instead of treating unavailable detection as a passed threat canary");
	checks.push("a hung remediation hook is terminated after its canary deadline without changing customer settings");

	customerSettings = removeManagedEvent(JSON.parse(readFileSync(settingsPath, "utf8")));
	writeFileSync(settingsPath, `${JSON.stringify(customerSettings, null, 2)}\n`);
	const concurrentContent = '{"customerConcurrentChange":true}\n';
	const conflict = runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"], false, {
		AIDR_TEST_EDIT_SETTINGS: settingsPath,
	});
	assert.notEqual(conflict.status, 0);
	assert.equal(JSON.parse(conflict.stdout).reason.code, "settings_changed_during_operation");
	assert.equal(readFileSync(settingsPath, "utf8"), concurrentContent);
	checks.push("remediation refused a customer edit made during the deny canary");

	customerSettings = removeManagedEvent(structuredClone(repairedSettings));
	customerSettings.customerDeep = deepValue(101);
	const overlyDeepRepair = `${JSON.stringify(customerSettings)}\n`;
	writeFileSync(settingsPath, overlyDeepRepair);
	assert.notEqual(runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", target, "-Json"], false).status, 0);
	assert.equal(readFileSync(settingsPath, "utf8"), overlyDeepRepair);
	checks.push("remediation failed closed beyond safe JSON nesting depth");

	customerSettings = structuredClone(repairedSettings);
	customerSettings.customerDeep = deepValue(101);
	const overlyDeepUninstall = `${JSON.stringify(customerSettings)}\n`;
	writeFileSync(settingsPath, overlyDeepUninstall);
	assert.notEqual(runFleet("Uninstall-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot], false).status, 0);
	assert.equal(readFileSync(settingsPath, "utf8"), overlyDeepUninstall);
	checks.push("uninstall failed closed beyond safe JSON nesting depth");

	writeFileSync(settingsPath, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`${JSON.stringify(repairedSettings)}\n`)]));
	const responseRequiredConfig = `${JSON.stringify({ schema_version: 1, control_plane: { response_worker_required: true } })}\n`;
	writeFileSync(join(target, ".singularity-aidr", "config.json"), responseRequiredConfig);
	const protectedHooks = readFileSync(settingsPath);
	const protectedFleetState = readFileSync(statePath);
	const protectedReceipt = readFileSync(join(target, ".singularity-aidr", "installation.json"));
	const unsupportedRollback = runFleet("Install-Aidr.ps1", ["-ManifestPath", deployment1.manifest, "-ExpectedManifestSha256", deployment1.sha, "-TargetHome", target, "-StateRoot", stateRoot], false);
	assert.notEqual(unsupportedRollback.status, 0);
	assert.deepEqual(readFileSync(settingsPath), protectedHooks);
	assert.deepEqual(readFileSync(statePath), protectedFleetState);
	assert.deepEqual(readFileSync(join(target, ".singularity-aidr", "installation.json")), protectedReceipt);
	checks.push("a required response worker refuses a signed older package without its pause gate before replacing hooks or fleet state");
	assert.notEqual(runFleet("Uninstall-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot], false).status, 0);
	assert.deepEqual(readFileSync(settingsPath), protectedHooks);
	assert.equal(readFileSync(join(target, ".singularity-aidr", "config.json"), "utf8"), responseRequiredConfig);
	checks.push("missing authenticated response state prevents uninstall from clearing required-worker hooks");
	writeFileSync(join(target, ".singularity-aidr", "config.json"), preservedConfig);

	runFleet("Uninstall-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot]);
	const afterUninstall = runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"], false);
	assert.notEqual(afterUninstall.status, 0);
	const settingsAfter = JSON.parse(readFileSync(join(target, ".claude", "settings.json"), "utf8"));
	assert.ok(settingsAfter.hooks.PreToolUse.some((entry) => entry.hooks.some((hook) => hook.statusMessage === unrelatedStatus)));
	assert.ok(!JSON.stringify(settingsAfter).includes("Singularity AIDR managed installation"));
	assert.ok(settingsAfter.hooks.PreToolUse.some((entry) => entry.hooks.some((hook) => hook.command === "safe-case-variant-customer-hook")));
	assertDeepLeaf(settingsAfter.customerDeep, 35);
	assert.equal(readFileSync(join(target, ".singularity-aidr", "config.json"), "utf8"), preservedConfig);
	checks.push("uninstall removed only managed hooks and preserved deep customer configuration");
	if (process.platform === "win32") {
		const linkedTarget = join(work, "junction-profile");
		const outsideSettings = join(work, "junction-customer-settings");
		mkdirSync(linkedTarget);
		mkdirSync(outsideSettings);
		const outsideSettingsPath = join(outsideSettings, "settings.json");
		const outsideBytes = `${JSON.stringify(repairedSettings)}\n`;
		writeFileSync(outsideSettingsPath, outsideBytes);
		const junctionScript = join(work, "junction.ps1");
		writeFileSync(junctionScript, "param([string]$Link,[string]$Target)\nNew-Item -ItemType Junction -Path $Link -Target $Target -ErrorAction Stop | Out-Null\n");
		runPs(junctionScript, [join(linkedTarget, ".claude"), outsideSettings]);
		for (const script of ["Uninstall-Aidr.ps1", "Invoke-AidrRemediation.ps1"]) {
			const args = ["-TargetHome", linkedTarget, ...(script === "Uninstall-Aidr.ps1" ? ["-StateRoot", stateRoot] : ["-Json"])];
			assert.notEqual(runFleet(script, args, false).status, 0, script);
			assert.equal(readFileSync(outsideSettingsPath, "utf8"), outsideBytes);
		}
		checks.push("fleet uninstall and remediation reject managed-directory junctions before touching customer files");
		const connectorLinkedTarget = join(work, "connector-junction-profile");
		const linkedConnector = join(connectorLinkedTarget, ".singularity-aidr", "connectors", "claude", activeState.active.connector_digest);
		mkdirSync(dirname(linkedConnector), { recursive: true });
		runPs(junctionScript, [linkedConnector, activeState.active.connector_path]);
		writeFileSync(join(connectorLinkedTarget, ".singularity-aidr", "installation.json"), `${JSON.stringify({ schema_version: 1, connector: "claude-code", local_canary: "deny", artifact_sha256: activeState.active.connector_digest, path: linkedConnector })}\n`);
		const linkedReceipt = runFleet("Invoke-AidrRemediation.ps1", ["-TargetHome", connectorLinkedTarget, "-Json"], false);
		assert.notEqual(linkedReceipt.status, 0);
		assert.equal(JSON.parse(linkedReceipt.stdout).reason.code, "receipt_path_reparse");
		assert.equal(existsSync(join(connectorLinkedTarget, ".claude", "settings.json")), false);
		checks.push("remediation refuses a receipt whose digest-addressed connector directory is a junction");
	}

	assert.match(readFileSync(join(fleet, "README.md"), "utf8"), /not an Intune\/SCCM certification claim/i);
	checks.push("documentation keeps real MDM and native-host acceptance external");

	console.log(JSON.stringify({ passed: true, checks: checks.length, assertions: checks }, null, 2));
} finally {
	if (process.env.AIDR_KEEP_FLEET_FIXTURE !== "1") rmSync(work, { recursive: true, force: true });
}

function makePackage(version, marker) {
	const source = join(work, `source-${version}`);
	const root = join(source, "package");
	mkdirSync(join(root, "dist"), { recursive: true });
	mkdirSync(join(root, "resources", "threats"), { recursive: true });
	mkdirSync(join(root, "resources", "allowlists"), { recursive: true });
	writeFileSync(join(root, "package.json"), `${JSON.stringify({ name: "@singularityrd/aidr-claude-code", version, type: "commonjs" }, null, 2)}\n`);
	writeFileSync(join(root, "dist", "pre-tool-use.cjs"), `if(process.env.AIDR_TEST_EDIT_SETTINGS)require("node:fs").writeFileSync(process.env.AIDR_TEST_EDIT_SETTINGS,'{"customerConcurrentChange":true}\\n');process.stdout.write(JSON.stringify({hookSpecificOutput:{permissionDecision:"deny",permissionDecisionReason:"🛡️ Singularity AIDR: Threat Blocked"},systemMessage:"Remote code execution via curl pipe to shell (${marker})"}));\n`);
	writeFileSync(join(root, "dist", "post-tool-use.cjs"), `process.stdout.write("${marker}");\n`);
	writeFileSync(join(root, "dist", "session-start.cjs"), `process.stdout.write("${marker}");\n`);
	// endpoint-install.mjs refuses to register hooks on Windows when the
	// packaged native AMSI payload is absent: it loads `amsi.dll` through that
	// addon before touching hook configuration. The fixture therefore has to
	// carry the real staged payload. Skipping the check would turn the
	// command-line installer into something it is not.
	const stagedKoffi = join(root, "dist", "vendor", "koffi");
	const realKoffi = join(sourceRoot, "packages", "claude-code", "dist", "vendor", "koffi");
	const archFolder = process.arch === "arm64" ? "win32_arm64" : "win32_x64";
	for (const relative of [
		"index.js",
		"package.json",
		"LICENSE.txt",
		join("build", "koffi", archFolder, "koffi.node"),
	]) {
		const from = join(realKoffi, relative);
		if (!existsSync(from)) {
			throw new Error(
				`the staged Windows AMSI payload is missing (${relative}); run \`pnpm build\` before the fleet gate (expected under ${realKoffi})`,
			);
		}
		const to = join(stagedKoffi, relative);
		mkdirSync(dirname(to), { recursive: true });
		copyFileSync(from, to);
	}
	writeFileSync(join(root, "resources", "threats", "fixture.json"), "{}\n");
	writeFileSync(join(root, "resources", "allowlists", "fixture.json"), "{}\n");
	const artifact = join(work, `aidr-claude-${version}.tgz`);
	execFileSync(tar, ["-czf", artifact, "-C", source, "package"], { stdio: "pipe" });
	return artifact;
}

function generateManifest(artifact, version, thumbprint, config) {
	const directory = join(work, `deployment-${version}`);
	const output = runPs(join(fleet, "New-AidrFleetManifest.ps1"), [
		"-ArtifactPath", artifact,
		"-ArtifactSignaturePath", `${artifact}.p7s`,
		"-InstallerPath", join(repo, "scripts", "endpoint-install.mjs"),
		"-PublisherThumbprint", thumbprint,
		"-PackageVersion", version,
		"-OutputDirectory", directory,
		"-AgentConfigPath", config,
	]);
	const sha = output.trim().split(/\r?\n/).at(-1);
	assert.match(sha, /^[a-f0-9]{64}$/);
	return { directory, manifest: join(directory, "aidr-fleet-manifest.json"), sha };
}

function runPs(script, args, success = true, extraEnv = {}) {
	const result = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, ...args], {
		cwd: repo,
		env: { ...process.env, ...extraEnv },
		encoding: "utf8",
		windowsHide: true,
		timeout: 60_000,
	});
	if (success && result.status !== 0) throw new Error(`PowerShell fixture failed (${result.status}): ${sanitize(result.stderr || result.stdout)}`);
	return success ? result.stdout : result;
}

function runFleet(script, args, success = true, extraEnv = {}) {
	// The generated endpoint archive is intentionally unsigned test data. Keep
	// its local-rehearsal flag confined to each spawned fixture process.
	const result = runPs(join(fleet, script), args, success, { ...extraEnv, ...fleetFixtureEnv });
	assert.equal(process.env.AIDR_DEVELOPMENT_MODE, parentDevelopmentMode);
	return result;
}

function sha256(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function targetId(path) {
	return createHash("sha256").update(path.toLowerCase(), "utf8").digest("hex");
}

function sanitize(value) {
	return String(value).replaceAll(work, "<temp>").slice(0, 800);
}
