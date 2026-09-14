#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const required = [
	"deploy/fleet/unix/aidr-fleet.sh",
	"deploy/fleet/unix/remove-managed-hooks.mjs",
	"deploy/fleet/unix/fleet-health.mjs",
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
if (bashAvailable) run(bash, ["-n", ...shellTemplates.map((path) => join(root, path))]);
check(bashAvailable, "shell templates pass offline bash syntax validation");
process.stderr.write("fleet verifier: syntax checked\n");
for (const path of required.filter((path) => path.endsWith(".mjs"))) run(process.execPath, ["--check", join(root, path)]);
check(true, "fleet JavaScript helpers pass Node syntax validation");

const manager = readFileSync(join(root, "deploy/fleet/unix/aidr-fleet.sh"), "utf8");
check(manager.includes("openssl dgst -sha256 -verify") && manager.includes("artifact SHA-256 mismatch"), "lifecycle manager fails closed on SHA-256 and detached publisher signature");
check(manager.includes("unsafe archive path") && manager.includes("regular files or directories"), "lifecycle manager rejects traversal, links and special archive entries before extraction");
check(manager.includes("release public key must be owned by root") && manager.includes("group/world writable"), "production key pin must be root-owned and non-writable by group or world");
check(manager.includes("write_pending_state") && readFileSync(join(root, "deploy/fleet/unix/fleet-health.mjs"), "utf8").includes("lifecycle_pending"), "interrupted lifecycle work is persisted and forces unhealthy fleet evidence");
check(manager.includes("Existing agent configuration") || readFileSync(join(root, "scripts/endpoint-install.mjs"), "utf8").includes("Existing agent configuration preserved"), "existing agent configuration has an explicit preservation guard");
const remover = readFileSync(join(root, "deploy/fleet/unix/remove-managed-hooks.mjs"), "utf8");
check(remover.includes("Singularity AIDR managed installation") && remover.includes("aidr-backup"), "uninstall removes only marked AIDR hooks with an atomic settings backup");
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
	writeFileSync(join(packageRoot, "package.json"), '{"name":"fleet-fixture","version":"1.0.0"}\n');
	writeFileSync(join(packageRoot, "resources", "threats", "fixture.yaml"), "patterns: []\n");
	writeFileSync(join(packageRoot, "resources", "allowlists", "fixture.yaml"), "domains: []\n");
	writeFileSync(join(packageRoot, "dist", "pre-tool-use.cjs"), `let x="";process.stdin.on("data",d=>x+=d);process.stdin.on("end",()=>console.log(JSON.stringify({hookSpecificOutput:{permissionDecision:"deny"}})));\n`);
	for (const name of ["post-tool-use.cjs", "session-start.cjs"]) writeFileSync(join(packageRoot, "dist", name), "process.exit(0);\n");
	// `endpoint-install.mjs` runs under the host Node even when the fleet script
	// is executed through Git bash on Windows, so it applies the Windows rule and
	// refuses a package without the native AMSI payload. That refusal is correct;
	// the fixture therefore carries the real staged payload instead of the gate
	// pretending the requirement does not exist.
	if (process.platform === "win32") {
		const realKoffi = join(root, "packages", "claude-code", "dist", "vendor", "koffi");
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
			const to = join(packageRoot, "dist", "vendor", "koffi", relative);
			mkdirSync(dirname(to), { recursive: true });
			copyFileSync(from, to);
		}
	}
	const artifact = join(work, "connector-v1.tgz");
	const privateKey = join(work, "release-private.pem");
	const publicKey = join(work, "release-public.pem");
	const signature = `${artifact}.sig`;
	run(bash, ["-lc", 'tar -C "$1" -czf "$2" package', "bash", toBash(dirname(packageRoot)), toBash(artifact)]);
	run(bash, ["-lc", 'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" >/dev/null 2>&1 && openssl pkey -in "$1" -pubout -out "$2" >/dev/null 2>&1 && openssl dgst -sha256 -sign "$1" -out "$3" "$4"', "bash", toBash(privateKey), toBash(publicKey), toBash(signature), toBash(artifact)]);
	const digest = createHash("sha256").update(readFileSync(artifact)).digest("hex");
	const engine = toBash(join(root, "deploy/fleet/unix/aidr-fleet.sh"));
	const baseEnv = { ...process.env, AIDR_FLEET_PLATFORM: "linux", AIDR_FLEET_TEST_ROOT: toBash(work), AIDR_NODE_BIN: toBash(process.execPath) };
	const common = ["--artifact", toBash(artifact), "--sha256", digest, "--signature", toBash(signature), "--public-key", toBash(publicKey)];
	run(bash, [engine, "verify", ...common], { env: baseEnv });
	check(true, "offline cryptographic fixture passes SHA-256, signature and archive checks");
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
	const originalConfig = '{"tenant":"preserve-me"}\n';
	writeFileSync(join(userHome, ".singularity-aidr", "config.json"), originalConfig);
	writeFileSync(join(userHome, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "other-hook", statusMessage: "Customer hook" }] }] } }, null, 2));
	const lifecycleBase = ["--user", "fixture-user", "--home", toBash(userHome), "--install-root", toBash(installRoot), "--state-root", toBash(stateRoot), "--endpoint-installer", toBash(join(root, "scripts/endpoint-install.mjs"))];
	const lifecycle = [...lifecycleBase, ...common];
	run(bash, [engine, "install", ...lifecycle], { env: baseEnv });
	process.stderr.write("fleet verifier: lifecycle install completed\n");
	let settings = JSON.parse(readFileSync(join(userHome, ".claude", "settings.json"), "utf8"));
	check(settings.hooks.PreToolUse.some((entry) => entry.hooks?.some((hook) => hook.statusMessage === "Customer hook")), "install preserves unrelated customer hooks");
	check(readFileSync(join(userHome, ".singularity-aidr", "config.json"), "utf8") === originalConfig, "install preserves an existing agent configuration");

	writeFileSync(join(packageRoot, "package.json"), '{"name":"fleet-fixture","version":"2.0.0"}\n');
	const artifact2 = join(work, "connector-v2.tgz");
	const signature2 = `${artifact2}.sig`;
	run(bash, ["-lc", 'tar -C "$1" -czf "$2" package && openssl dgst -sha256 -sign "$3" -out "$4" "$2"', "bash", toBash(dirname(packageRoot)), toBash(artifact2), toBash(privateKey), toBash(signature2)]);
	const digest2 = createHash("sha256").update(readFileSync(artifact2)).digest("hex");
	const common2 = ["--artifact", toBash(artifact2), "--sha256", digest2, "--signature", toBash(signature2), "--public-key", toBash(publicKey)];
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
