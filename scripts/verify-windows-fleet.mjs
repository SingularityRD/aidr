#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoot = repo;
const fleet = join(repo, "deploy", "fleet", "windows");
const powershell = process.platform === "win32" ? "powershell.exe" : "pwsh";
const tar = process.platform === "win32" ? "tar.exe" : "tar";
const required = [
	"Common.ps1",
	"Install-Aidr.ps1",
	"Update-Aidr.ps1",
	"Rollback-Aidr.ps1",
	"Uninstall-Aidr.ps1",
	"Test-AidrDetection.ps1",
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

	assert.equal(readFileSync(join(target, ".singularity-aidr", "config.json"), "utf8"), preservedConfig);
	const settings = JSON.parse(readFileSync(join(target, ".claude", "settings.json"), "utf8"));
	assert.ok(settings.hooks.PreToolUse.some((entry) => entry.hooks.some((hook) => hook.statusMessage === unrelatedStatus)));
	checks.push("existing agent configuration and unrelated hooks were preserved");

	const statePath = join(stateRoot, "targets", targetId(target), "state.json");
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

	const logs = readFileSync(join(stateRoot, "logs", `${targetId(target)}.jsonl`), "utf8");
	assert.ok(!logs.includes(secretMarker));
	assert.ok(!/(api[_-]?key|bearer|password|secret)/i.test(logs));
	checks.push("structured fleet logs excluded configuration and credential material");

	runFleet("Uninstall-Aidr.ps1", ["-TargetHome", target, "-StateRoot", stateRoot]);
	const afterUninstall = runFleet("Test-AidrDetection.ps1", ["-TargetHome", target, "-StateRoot", stateRoot, "-Json"], false);
	assert.notEqual(afterUninstall.status, 0);
	const settingsAfter = JSON.parse(readFileSync(join(target, ".claude", "settings.json"), "utf8"));
	assert.ok(settingsAfter.hooks.PreToolUse.some((entry) => entry.hooks.some((hook) => hook.statusMessage === unrelatedStatus)));
	assert.ok(!JSON.stringify(settingsAfter).includes("Singularity AIDR managed installation"));
	assert.equal(readFileSync(join(target, ".singularity-aidr", "config.json"), "utf8"), preservedConfig);
	checks.push("uninstall removed only managed hooks and preserved configuration");

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
	writeFileSync(join(root, "dist", "pre-tool-use.cjs"), `process.stdout.write(JSON.stringify({hookSpecificOutput:{permissionDecision:"deny",reason:"${marker}"}}));\n`);
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

function runPs(script, args, success = true) {
	const result = spawnSync(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, ...args], {
		cwd: repo,
		encoding: "utf8",
		windowsHide: true,
		timeout: 60_000,
	});
	if (success && result.status !== 0) throw new Error(`PowerShell fixture failed (${result.status}): ${sanitize(result.stderr || result.stdout)}`);
	return success ? result.stdout : result;
}

function runFleet(script, args, success = true) {
	return runPs(join(fleet, script), args, success);
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
