#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { closeSync, copyFileSync, existsSync, ftruncateSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { KOFFI_RUNTIME_FILES, hostKoffiWindowsArch, koffiNativeBinary } from "./stage-windows-koffi.mjs";

const root = resolve(import.meta.dirname, "..");
const required = [
	"deploy/fleet/unix/aidr-fleet.sh",
	"deploy/fleet/unix/remove-managed-hooks.mjs",
	"deploy/fleet/unix/fleet-health.mjs",
	"deploy/fleet/unix/aidr-remediate.mjs",
	"deploy/fleet/linux/install.sh",
	"deploy/fleet/linux/upgrade.sh",
	"deploy/fleet/linux/rollback.sh",
	"deploy/fleet/linux/uninstall.sh",
	"deploy/fleet/linux/verify.sh",
	"deploy/fleet/linux/build-offline-bundle.sh",
	"deploy/fleet/linux/install-systemd.sh",
	"deploy/fleet/linux/aidr-fleet-health.sh",
	"deploy/fleet/linux/systemd/aidr-fleet-health.service",
	"deploy/fleet/linux/systemd/aidr-fleet-health.timer",
	"deploy/fleet/macos/install.sh",
	"deploy/fleet/macos/upgrade.sh",
	"deploy/fleet/macos/rollback.sh",
	"deploy/fleet/macos/uninstall.sh",
	"deploy/fleet/macos/verify.sh",
	"deploy/fleet/macos/jamf-policy.sh",
	"deploy/fleet/macos/pkg/build-pkg.sh",
	"deploy/fleet/macos/pkg/scripts/preinstall",
	"deploy/fleet/macos/pkg/scripts/postinstall",
];
const checks = [];
const check = (condition, message) => { assert.ok(condition, message); checks.push(message); };
const run = (command, args, options = {}) => {
	const result = spawnSync(command, args, { encoding: "utf8", timeout: 30_000, ...options });
	if (result.error) throw result.error;
	if (result.status !== 0) throw new Error(`${command} failed (${result.status}): ${result.stderr || result.stdout}`);
	return result;
};
const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
const bash = process.platform === "win32" && existsSync(gitBash) ? gitBash : "bash";
const bashAvailable = process.platform === "win32" && existsSync(gitBash)
	? true
	: spawnSync(bash, ["--version"], { encoding: "utf8" }).status === 0;
check(required.every((path) => existsSync(join(root, path))), "all macOS, Jamf, PKG, Linux and systemd fleet templates exist");

const shellTemplates = required.filter((path) => path.endsWith(".sh") || path.endsWith("/preinstall") || path.endsWith("/postinstall"));
if (bashAvailable) for (const path of shellTemplates) run(bash, ["-n", join(root, path)]);
check(bashAvailable, "shell templates pass offline bash syntax validation");
process.stderr.write("fleet verifier: syntax checked\n");
for (const path of required.filter((path) => path.endsWith(".mjs"))) run(process.execPath, ["--check", join(root, path)]);
check(true, "fleet JavaScript helpers pass Node syntax validation");

const manager = readFileSync(join(root, "deploy/fleet/unix/aidr-fleet.sh"), "utf8");
check(manager.includes("openssl dgst -sha256 -verify") && manager.includes("artifact SHA-256 mismatch"), "lifecycle manager fails closed on SHA-256 and detached publisher signature");
check(manager.includes("unsafe archive path") && manager.includes("regular files/directories") && manager.includes("536870912"), "lifecycle manager rejects traversal, links, special entries and oversized expansions before extraction");
const archiveSizeGuard = manager.match(/LC_ALL=C tar -tvzf "\$ARTIFACT" \| awk '([^']+)'/);
assert.ok(archiveSizeGuard, "the actual archive expanded-size guard must be available for the portable listing regression");
for (const listing of [
	"-rw-r--r-- root/root 42 2026-01-01 00:00 package/package.json\n",
	"-rw-r--r-- 0 root wheel 42 Jan 1 00:00 package/package.json\n",
]) run(bash, ["-c", 'awk "$1"', "bash", archiveSizeGuard[1]], { input: listing });
for (const listing of [
	"-rw-r--r-- root/root 536870913 2026-01-01 00:00 package/package.json\n",
	"-rw-r--r-- 0 root wheel 536870913 Jan 1 00:00 package/package.json\n",
	"lrwxrwxrwx 0 root wheel 1 Jan 1 00:00 package/link -> /etc/passwd\n",
]) {
	const result = spawnSync(bash, ["-c", 'awk "$1"', "bash", archiveSizeGuard[1]], { input: listing, encoding: "utf8" });
	check(result.status !== 0, "GNU/BSD archive size/type guard rejects an oversized or linked entry");
}
check(true, "GNU and macOS BSD tar formats share the same working expanded-size guard");
const macHomeParser = manager.match(/TARGET_HOME=\$\(dscl [^\n]+ \| sed -n '([^']+)'/);
assert.ok(macHomeParser, "macOS home lookup parser must be available for its space-preservation regression");
const parsedHome = run(bash, ["-c", 'sed -n "$1"', "bash", macHomeParser[1]], { input: "NFSHomeDirectory: /Volumes/Company Homes/fixture-user\n" });
check(parsedHome.stdout.trim() === "/Volumes/Company Homes/fixture-user", "macOS directory-service home lookup preserves paths containing spaces");
const rootGuard = manager.slice(manager.indexOf("require_root_for_changes()"), manager.indexOf("LOCK_HELD="));
const runnerStart = manager.indexOf("run_for_user()");
const userRunner = manager.slice(runnerStart, manager.indexOf("\n}", runnerStart));
check(
	rootGuard.includes("test-root mode is unavailable to privileged installations") &&
	rootGuard.indexOf("[ \"$(id -u)\" -ne 0 ]") < rootGuard.indexOf("return") &&
		userRunner.includes("AIDR_FLEET_TEST_ROOT") && userRunner.includes("[ \"$(id -u)\" -ne 0 ]"),
	"root execution cannot use the test-root privilege bypass or run a target-user installer as the caller",
);
check(manager.includes("trap 'release_lock; exit 1' HUP INT TERM"), "lifecycle signal handling exits before releasing its mutual-exclusion lock");
check(manager.includes("release public key and directory must be owned by root") && manager.includes("group/world writable") && manager.includes("release public key must not be a symlink"), "production key pin and directory must be real, root-owned and non-writable by group or world");
check(manager.includes("write_pending_state") && readFileSync(join(root, "deploy/fleet/unix/fleet-health.mjs"), "utf8").includes("lifecycle_pending"), "interrupted lifecycle work is persisted and forces unhealthy fleet evidence");
check(manager.includes("Existing agent configuration") || readFileSync(join(root, "scripts/endpoint-install.mjs"), "utf8").includes("Existing agent configuration preserved"), "existing agent configuration has an explicit preservation guard");
const remover = readFileSync(join(root, "deploy/fleet/unix/remove-managed-hooks.mjs"), "utf8");
check(remover.includes("Singularity AIDR managed installation") && remover.includes("aidr-backup"), "uninstall removes only marked AIDR hooks with an atomic settings backup");
const remediator = readFileSync(join(root, "deploy/fleet/unix/aidr-remediate.mjs"), "utf8");
check(
	remediator.includes("Singularity AIDR managed installation") &&
		remediator.includes("aidr-remediate-backup") &&
		remediator.includes("deny_canary_failed"),
	"local remediation re-runs the deny canary and repairs only marked AIDR hooks, backing up the settings it rewrites",
);
const unit = readFileSync(join(root, "deploy/fleet/linux/systemd/aidr-fleet-health.service"), "utf8");
check(["User=aidr-health", "NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet=", "RestrictAddressFamilies=AF_UNIX"].every((entry) => unit.includes(entry)), "systemd health job uses a dedicated identity and a restricted sandbox");
const pkg = readFileSync(join(root, "deploy/fleet/macos/pkg/build-pkg.sh"), "utf8");
check(pkg.includes("productsign --sign") && pkg.includes("pkgutil --check-signature") && pkg.includes("verify.sh"), "macOS PKG build requires artifact verification and an Apple Installer signature");
const jamf = readFileSync(join(root, "deploy/fleet/macos/jamf-policy.sh"), "utf8");
check(jamf.includes("install|upgrade") && jamf.includes("rollback") && jamf.includes("uninstall"), "Jamf policy exposes install, upgrade, rollback and uninstall actions");
process.stderr.write("fleet verifier: static contracts checked\n");

const work = mkdtempSync(join(tmpdir(), "aidr-fleet-verify-"));
const toBash = (path) => {
	if (process.platform !== "win32") return path;
	return path.replace(/^([A-Za-z]):/, (_match, drive) => `/${drive.toLowerCase()}`).replaceAll("\\", "/");
};
try {
	const packageRoot = join(work, "fixture", "package");
	mkdirSync(join(packageRoot, "dist"), { recursive: true });
	mkdirSync(join(packageRoot, "resources", "threats"), { recursive: true });
	mkdirSync(join(packageRoot, "resources", "allowlists"), { recursive: true });
	writeFileSync(join(packageRoot, "package.json"), '{"name":"@singularityrd/aidr-claude-code","version":"1.0.0"}\n');
	writeFileSync(join(packageRoot, "resources", "threats", "fixture.yaml"), "patterns: []\n");
	writeFileSync(join(packageRoot, "resources", "allowlists", "fixture.yaml"), "domains: []\n");
	writeFileSync(join(packageRoot, "dist", "pre-tool-use.cjs"), `let x="";process.stdin.on("data",d=>x+=d);process.stdin.on("end",()=>console.log(JSON.stringify({hookSpecificOutput:{permissionDecision:"deny",permissionDecisionReason:"🛡️ Singularity AIDR: Threat Blocked"},systemMessage:"Remote code execution via curl pipe to shell"})));\n`);
	for (const name of ["post-tool-use.cjs", "session-start.cjs"]) writeFileSync(join(packageRoot, "dist", name), "process.exit(0);\n");
	// `endpoint-install.mjs` runs under the host Node even when the fleet script
	// is executed through Git bash on Windows, so it applies the Windows rule and
	// refuses a package without the native AMSI payload. That refusal is correct;
	// the fixture therefore carries the real staged payload instead of the gate
	// pretending the requirement does not exist.
	if (process.platform === "win32") {
		const realKoffi = join(root, "packages", "claude-code", "dist", "vendor", "koffi");
		for (const relative of [...KOFFI_RUNTIME_FILES, koffiNativeBinary(hostKoffiWindowsArch())]) {
			const from = join(realKoffi, relative);
			if (!existsSync(from)) {
				throw new Error(
					`the staged Windows AMSI payload is missing (${relative}); run \`pnpm build\` before the fleet gate (expected under ${realKoffi})`,
				);
			}
			const to = join(packageRoot, "dist", "vendor", "koffi", relative);
			mkdirSync(dirname(to), { recursive: true });
			copyFileSync(from, to);
		}
	}
	const integrityKeys = generateKeyPairSync("ed25519");
	const integrityPublicPem = integrityKeys.publicKey.export({ type: "spki", format: "pem" });
	const signPackage = (version) => {
		const files = [];
		const walk = (directory, prefix) => {
			for (const entry of readdirSync(directory, { withFileTypes: true })) {
				const name = `${prefix}/${entry.name}`;
				if (entry.isDirectory()) walk(join(directory, entry.name), name);
				else files.push(name);
			}
		};
		walk(join(packageRoot, "dist"), "dist");
		walk(join(packageRoot, "resources"), "resources");
		files.push("package.json");
		const manifest = Buffer.from(`${JSON.stringify({
			schema_version: 1, artifact_id: "claude-code/package", artifact_version: version,
			key_fingerprint: createHash("sha256").update(integrityKeys.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
			files: files.sort().map((path) => ({ path, sha256: createHash("sha256").update(readFileSync(join(packageRoot, path))).digest("hex") })),
		})}\n`);
		writeFileSync(join(packageRoot, "aidr-artifact.manifest.json"), manifest);
		writeFileSync(join(packageRoot, "aidr-artifact.manifest.sig"), `${sign(null, manifest, integrityKeys.privateKey).toString("base64")}\n`);
	};
	signPackage("1.0.0");
	const artifact = join(work, "connector-v1.tgz");
	const privateKey = join(work, "release-private.pem");
	const publicKey = join(work, "release-public.pem");
	const signature = `${artifact}.sig`;
	run(bash, ["-lc", 'tar -C "$1" -czf "$2" package', "bash", toBash(dirname(packageRoot)), toBash(artifact)]);
	run(bash, ["-lc", 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" >/dev/null 2>&1 && openssl pkey -in "$1" -pubout -out "$2" >/dev/null 2>&1 && openssl dgst -sha256 -sign "$1" -out "$3" "$4"', "bash", toBash(privateKey), toBash(publicKey), toBash(signature), toBash(artifact)]);
	const digest = createHash("sha256").update(readFileSync(artifact)).digest("hex");
	const engine = toBash(join(root, "deploy/fleet/unix/aidr-fleet.sh"));
	const baseEnv = { ...process.env, AIDR_DEVELOPMENT_MODE: "false", AIDR_FLEET_PLATFORM: "linux", AIDR_FLEET_TEST_ROOT: toBash(work), AIDR_NODE_BIN: toBash(process.execPath) };
	const common = ["--artifact", toBash(artifact), "--sha256", digest, "--signature", toBash(signature), "--public-key", toBash(publicKey)];
	run(bash, [engine, "verify", ...common], { env: baseEnv });
	check(true, "offline cryptographic fixture passes SHA-256, signature and archive checks");
	const oversizedSource = join(work, "expanded-over-limit.bin");
	const oversizedArchive = join(work, "expanded-over-limit.tgz");
	const oversizedFile = openSync(oversizedSource, "w");
	try { ftruncateSync(oversizedFile, 536870913); } finally { closeSync(oversizedFile); }
	run(bash, ["-lc", 'tar -czf "$1" -C "$2" expanded-over-limit.bin && openssl dgst -sha256 -sign "$3" -out "$4" "$1"', "bash", toBash(oversizedArchive), toBash(work), toBash(privateKey), toBash(`${oversizedArchive}.sig`)]);
	assert.ok(readFileSync(oversizedArchive).length < 268435456, "fixture must fit the compressed transport limit");
	const oversizedDigest = createHash("sha256").update(readFileSync(oversizedArchive)).digest("hex");
	const oversizedResult = spawnSync(bash, [engine, "verify", "--artifact", toBash(oversizedArchive), "--sha256", oversizedDigest, "--signature", toBash(`${oversizedArchive}.sig`), "--public-key", toBash(publicKey)], { encoding: "utf8", env: baseEnv, timeout: 30_000 });
	check(oversizedResult.status !== 0 && oversizedResult.stderr.includes("512 MiB expanded limit"), "compressed archive bomb is rejected by its advertised expanded size before extraction");
	try {
		const linkedKey = join(work, "linked-public.pem");
		symlinkSync(publicKey, linkedKey, "file");
		const linkedResult = spawnSync(bash, [engine, "verify", ...common.map((value) => value === toBash(publicKey) ? toBash(linkedKey) : value)], { encoding: "utf8", env: baseEnv });
		check(linkedResult.status !== 0 && linkedResult.stderr.includes("release public key must not be a symlink"), "publisher key symlink fails closed before signature verification");
	} catch (error) {
		if (process.platform !== "win32" || !["EPERM", "EACCES"].includes(error.code)) throw error;
	}
	process.stderr.write("fleet verifier: signed fixture checked\n");
	const bad = spawnSync(bash, [engine, "verify", ...common.map((value) => value === digest ? "0".repeat(64) : value)], { encoding: "utf8", env: baseEnv });
	check(bad.status !== 0 && bad.stderr.includes("SHA-256 mismatch"), "offline negative fixture rejects a mismatched digest before installation");
	const badSignature = join(work, "connector-invalid.sig");
	const badSignatureBytes = readFileSync(signature);
	badSignatureBytes[0] ^= 0xff;
	writeFileSync(badSignature, badSignatureBytes);
	const invalidSignatureArgs = common.map((value) => value === toBash(signature) ? toBash(badSignature) : value);
	const badPublisher = spawnSync(bash, [engine, "verify", ...invalidSignatureArgs], { encoding: "utf8", env: baseEnv, timeout: 30_000 });
	check(badPublisher.status !== 0 && badPublisher.stderr.includes("publisher signature verification failed"), "offline negative fixture rejects an invalid publisher signature");

	const userHome = join(work, "home");
	const installRoot = join(work, "install");
	const stateRoot = join(work, "state");
	mkdirSync(join(userHome, ".claude"), { recursive: true });
	mkdirSync(join(userHome, ".singularity-aidr"), { recursive: true });
	const originalConfig = `${JSON.stringify({ tenant: "preserve-me", integrity: { enabled: true, verify_on_start: true, public_keys_pem: [integrityPublicPem] } })}\n`;
	writeFileSync(join(userHome, ".singularity-aidr", "config.json"), originalConfig);
	writeFileSync(join(userHome, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "other-hook", statusMessage: "Customer hook" }] }] } }, null, 2));
	const lifecycleBase = ["--user", "fixture-user", "--home", toBash(userHome), "--install-root", toBash(installRoot), "--state-root", toBash(stateRoot), "--endpoint-installer", toBash(join(root, "scripts/endpoint-install.mjs"))];
	const lifecycle = [...lifecycleBase, ...common];
	const optionUser = spawnSync(bash, [engine, "install", ...lifecycle.map((value) => value === "fixture-user" ? "-r" : value)], { encoding: "utf8", env: baseEnv });
	check(optionUser.status !== 0 && optionUser.stderr.includes("unsafe user name") && !existsSync(installRoot), "option-like user names are rejected before any privileged lifecycle mutation");
	const offlineBundle = join(work, "offline-bundle.tgz");
	run(bash, [toBash(join(root, "deploy/fleet/linux/build-offline-bundle.sh")), toBash(artifact), digest, toBash(signature), toBash(publicKey), toBash(offlineBundle)], { env: baseEnv });
	const offlineRoot = join(work, "offline");
	mkdirSync(offlineRoot);
	run(bash, ["-c", 'tar -xzf "$1" -C "$2"', "bash", toBash(offlineBundle), toBash(offlineRoot)]);
	const offlineFleet = join(offlineRoot, "aidr-fleet");
	check(readFileSync(join(offlineFleet, "libexec", "endpoint-install.mjs")).equals(readFileSync(join(root, "scripts/endpoint-install.mjs"))), "offline Linux bundle carries the standalone endpoint installer it will execute");
	const systemdInstaller = readFileSync(join(offlineFleet, "linux", "install-systemd.sh"), "utf8");
	const systemdProbe = join(offlineFleet, "linux", "helper-resolution-check.sh");
	writeFileSync(systemdProbe, `#!/bin/sh\nset -eu\n${systemdInstaller.slice(systemdInstaller.indexOf("SCRIPT_DIR="), systemdInstaller.indexOf("\nINSTALL_ROOT="))}\n[ "$ENDPOINT_INSTALLER" = "$SCRIPT_DIR/../libexec/endpoint-install.mjs" ]\n`);
	run(bash, [toBash(systemdProbe)]);
	check(systemdInstaller.includes('"$ENDPOINT_INSTALLER" "$INSTALL_ROOT/libexec/endpoint-install.mjs"'), "systemd installer resolves and installs the helper from the extracted offline bundle");
	check(systemdInstaller.includes('find "$STATE_ROOT/users" -type d -exec chgrp aidr-health') && systemdInstaller.includes('find "$STATE_ROOT/users" -type f -exec chgrp aidr-health'), "systemd timer installation gives its dedicated account read access to existing lifecycle state");
	const offlineHome = join(work, "offline-home");
	mkdirSync(join(offlineHome, ".singularity-aidr"), { recursive: true });
	writeFileSync(join(offlineHome, ".singularity-aidr", "config.json"), originalConfig);
	const offlineCommon = common.map((value) => value === toBash(artifact) ? toBash(join(offlineFleet, "payload", "connector.tgz")) : value === toBash(signature) ? toBash(join(offlineFleet, "payload", "connector.tgz.sig")) : value);
	run(bash, [toBash(join(offlineFleet, "linux", "install.sh")), "--user", "fixture-user", "--home", toBash(offlineHome), "--install-root", toBash(join(work, "offline-install")), "--state-root", toBash(join(work, "offline-state")), ...offlineCommon], { env: baseEnv });
	check(JSON.parse(readFileSync(join(offlineHome, ".singularity-aidr", "installation.json"))).package_integrity === "signature_verified", "extracted offline Linux bundle installs using its packaged helper and signed manifest without a source-checkout override");
	run(bash, [engine, "install", ...lifecycle], { env: baseEnv });
	process.stderr.write("fleet verifier: lifecycle install completed\n");
	let settings = JSON.parse(readFileSync(join(userHome, ".claude", "settings.json"), "utf8"));
	check(settings.hooks.PreToolUse.some((entry) => entry.hooks?.some((hook) => hook.statusMessage === "Customer hook")), "install preserves unrelated customer hooks");
	check(readFileSync(join(userHome, ".singularity-aidr", "config.json"), "utf8") === originalConfig, "install preserves an existing agent configuration");

	check(JSON.parse(readFileSync(join(userHome, ".singularity-aidr", "installation.json"))).package_integrity === "signature_verified", "fleet activation verifies the signed package manifest with independently provisioned integrity trust");
	writeFileSync(join(packageRoot, "package.json"), '{"name":"@singularityrd/aidr-claude-code","version":"2.0.0"}\n');
	signPackage("2.0.0");
	const artifact2 = join(work, "connector-v2.tgz");
	const signature2 = `${artifact2}.sig`;
	run(bash, ["-lc", 'tar -C "$1" -czf "$2" package && openssl dgst -sha256 -sign "$3" -out "$4" "$2"', "bash", toBash(dirname(packageRoot)), toBash(artifact2), toBash(privateKey), toBash(signature2)]);
	const digest2 = createHash("sha256").update(readFileSync(artifact2)).digest("hex");
	const common2 = ["--artifact", toBash(artifact2), "--sha256", digest2, "--signature", toBash(signature2), "--public-key", toBash(publicKey)];
	const release2 = join(installRoot, "releases", digest2);
	mkdirSync(release2, { recursive: true });
	writeFileSync(join(release2, "interrupted-publish.marker"), "preserve for inspection\n");
	const interruptedPublish = spawnSync(bash, [engine, "upgrade", ...lifecycleBase, ...common2], { encoding: "utf8", env: baseEnv });
	const priorState = readFileSync(join(stateRoot, "users", Buffer.from("fixture-user").toString("hex"), "release-state"), "utf8");
	check(
		interruptedPublish.status !== 0 && interruptedPublish.stderr.includes("existing release directory is incomplete") &&
			priorState === `current=${digest}\nprevious=\n` && !existsSync(join(stateRoot, "users", Buffer.from("fixture-user").toString("hex"), "pending")) &&
			existsSync(join(release2, "interrupted-publish.marker")) && !readdirSync(join(installRoot, "releases")).some((name) => name.startsWith(`.staging-${digest2}-`)),
		"an interrupted same-digest publish fails closed without changing active state or nesting/overwriting its evidence",
	);
	rmSync(release2, { recursive: true, force: true });
	run(bash, [engine, "upgrade", ...lifecycleBase, ...common2], { env: baseEnv });
	const stateKey = Buffer.from("fixture-user").toString("hex");
	let releaseState = readFileSync(join(stateRoot, "users", stateKey, "release-state"), "utf8");
	check(releaseState === `current=${digest2}\nprevious=${digest}\n`, "upgrade atomically tracks the new and immediately prior verified releases");
	run(bash, [engine, "rollback", ...lifecycleBase, "--public-key", toBash(publicKey)], { env: baseEnv });
	releaseState = readFileSync(join(stateRoot, "users", stateKey, "release-state"), "utf8");
	check(releaseState === `current=${digest}\nprevious=${digest2}\n`, "rollback re-verifies and atomically reactivates the immediately prior release");
	check(readFileSync(join(userHome, ".singularity-aidr", "config.json"), "utf8") === originalConfig, "upgrade and rollback preserve existing policy and agent configuration");
	const health = run(process.execPath, [join(root, "deploy/fleet/unix/fleet-health.mjs"), "--state-root", stateRoot, "--install-root", installRoot]);
	check(JSON.parse(health.stdout).healthy === true && JSON.parse(health.stdout).registered_users === 1, "fleet health evidence reports the active verified release without reading user secrets");
	const activeSessionBundle = join(installRoot, "releases", digest, "package", "dist", "session-start.cjs");
	const sessionBundleBytes = readFileSync(activeSessionBundle);
	rmSync(activeSessionBundle);
	const incompleteHealth = spawnSync(process.execPath, [join(root, "deploy/fleet/unix/fleet-health.mjs"), "--state-root", stateRoot, "--install-root", installRoot], { encoding: "utf8" });
	check(incompleteHealth.status === 2 && JSON.parse(incompleteHealth.stdout).healthy === false, "fleet health rejects a partial installation missing any managed hook bundle");
	writeFileSync(activeSessionBundle, sessionBundleBytes);
	const activeStatePath = join(stateRoot, "users", stateKey, "release-state");
	writeFileSync(activeStatePath, `${releaseState}current=${digest2}\n`);
	const malformedHealth = spawnSync(process.execPath, [join(root, "deploy/fleet/unix/fleet-health.mjs"), "--state-root", stateRoot, "--install-root", installRoot], { encoding: "utf8" });
	check(malformedHealth.status === 2 && JSON.parse(malformedHealth.stdout).healthy === false, "fleet health rejects malformed or duplicate release state records");
	writeFileSync(activeStatePath, releaseState);
	check(!existsSync(join(stateRoot, "users", stateKey, "pending")), "successful lifecycle operations clear their interruption marker");
	const pendingPath = join(stateRoot, "users", stateKey, "pending");
	writeFileSync(pendingPath, `action=upgrade\ntarget=${digest2}\n`);
	const interruptedHealth = spawnSync(process.execPath, [join(root, "deploy/fleet/unix/fleet-health.mjs"), "--state-root", stateRoot, "--install-root", installRoot], { encoding: "utf8" });
	check(interruptedHealth.status === 2 && JSON.parse(interruptedHealth.stdout).healthy === false, "an interrupted lifecycle marker makes fleet health fail closed");
	rmSync(pendingPath);
	process.stderr.write("fleet verifier: lifecycle upgrade and rollback completed\n");

	run(bash, [engine, "uninstall", "--user", "fixture-user", "--home", toBash(userHome), "--install-root", toBash(installRoot), "--state-root", toBash(stateRoot)], { env: baseEnv });
	process.stderr.write("fleet verifier: lifecycle uninstall completed\n");
	settings = JSON.parse(readFileSync(join(userHome, ".claude", "settings.json"), "utf8"));
	check(!JSON.stringify(settings).includes("Singularity AIDR managed installation") && JSON.stringify(settings).includes("Customer hook"), "uninstall removes managed hooks while retaining unrelated hooks");
	check(readFileSync(join(userHome, ".singularity-aidr", "config.json"), "utf8") === originalConfig, "uninstall preserves policy and agent configuration");
} finally {
	try { rmSync(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); }
	catch (error) { process.stderr.write(`fleet verifier: temporary cleanup deferred (${error.code ?? "error"})\n`); }
}

console.log(JSON.stringify({ passed: true, checks: checks.length, scope: "Offline template and local lifecycle verification; no Jamf/MDM or host execution acceptance." }));
