/**
 * node --test for the machine scope of deploy/fleet/unix/aidr-fleet.sh: the
 * signed standalone (SEA) bundle installed into a root-owned release store and
 * registered for every user through `aidr machine-hooks install`, with no
 * Node.js on the endpoint.
 *
 * Each case runs the real script under its non-root test-root mode. The bundle
 * is a stand-in whose bin/aidr is a shell script recording how the lifecycle
 * manager called it (the real command's own verification and host writes are
 * covered by packages/cli/src/__tests__/machine-hooks.test.ts). The machine
 * policy directory is redirected into the test tree; nothing outside a
 * temporary directory is touched.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const engine = join(here, "aidr-fleet.sh");
const repository = resolve(here, "..", "..", "..");
const posix = process.platform !== "win32";
const tools = posix && ["bash", "openssl", "tar"].every((tool) => spawnSync(tool, ["--version"], { encoding: "utf8" }).error === undefined);
const privileged = posix && typeof process.getuid === "function" && process.getuid() === 0;
const skip = !tools ? "bash, openssl and tar are required" : privileged ? "test-root mode refuses uid 0; run as an unprivileged user" : false;

// Records "<binary> <args>" for every call; AIDR_STUB_FAIL makes it fail.
const STUB = `#!/bin/sh
printf '%s %s\\n' "$0" "$*" >> "$AIDR_STUB_LOG"
[ -z "\${AIDR_STUB_FAIL:-}" ] || { echo "stub failure" >&2; exit 1; }
exit 0
`;

let work;
let privateKey;
let publicKey;
let bundleKey;
let enrollmentKey;
const run = (command, args, options = {}) => spawnSync(command, args, { encoding: "utf8", timeout: 60_000, ...options });
const must = (command, args, options) => {
	const result = run(command, args, options);
	assert.equal(result.status, 0, `${command} ${args.join(" ")}\n${result.stderr}${result.stdout}`);
	return result;
};
const digestOf = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

/** A signed SEA-bundle artifact (aidr-sea/ top directory, like build-sea.mjs output). */
function bundleArtifact(name, version) {
	const source = join(work, `src-${name}`);
	const bundle = join(source, "aidr-sea");
	mkdirSync(join(bundle, "bin"), { recursive: true });
	mkdirSync(join(bundle, "dist", "resources", "threats"), { recursive: true });
	writeFileSync(join(bundle, "bin", "aidr"), STUB);
	writeFileSync(join(bundle, "dist", "resources", "threats", "rules.yaml"), `- id: T-${version}\n`);
	writeFileSync(join(bundle, "dist", "aidr-artifact.manifest.json"), `{"artifact_id":"sea/dist","artifact_version":"${version}","files":[]}\n`);
	writeFileSync(join(bundle, "aidr-artifact.manifest.json"), `{"artifact_id":"claude-code/sea","artifact_version":"${version}","files":[]}\n`);
	const artifact = join(work, `${name}.tgz`);
	must("tar", ["-C", source, "-czf", artifact, "aidr-sea"]);
	must("openssl", ["dgst", "-sha256", "-sign", privateKey, "-out", `${artifact}.sig`, artifact]);
	return { artifact, signature: `${artifact}.sig`, digest: digestOf(artifact) };
}

/** A signed per-user npm connector artifact (package/), for the scope mismatch case. */
function packageArtifact() {
	const source = join(work, "src-package");
	mkdirSync(join(source, "package", "dist"), { recursive: true });
	mkdirSync(join(source, "package", "resources"), { recursive: true });
	writeFileSync(join(source, "package", "package.json"), '{"name":"@singularityrd/aidr-claude-code","version":"1.0.0"}\n');
	for (const file of ["pre-tool-use.cjs", "pre-tool-use.bundle.cjs"]) writeFileSync(join(source, "package", "dist", file), "\n");
	const artifact = join(work, "package.tgz");
	must("tar", ["-C", source, "-czf", artifact, "package"]);
	must("openssl", ["dgst", "-sha256", "-sign", privateKey, "-out", `${artifact}.sig`, artifact]);
	return { artifact, signature: `${artifact}.sig`, digest: digestOf(artifact) };
}

function fleet(action, release, extra = [], env = {}) {
	const args = [engine, action, "--install-root", join(work, "install"), "--state-root", join(work, "state")];
	if (release) args.push("--artifact", release.artifact, "--sha256", release.digest, "--signature", release.signature);
	args.push("--public-key", publicKey, ...extra);
	return run("bash", args, {
		env: {
			PATH: process.env.PATH,
			AIDR_FLEET_PLATFORM: "linux",
			AIDR_FLEET_TEST_ROOT: work,
			AIDR_FLEET_POLICY_DIR: join(work, "etc", "singularity-aidr"),
			// No Node.js: the machine scope must not need one.
			AIDR_NODE_BIN: join(work, "no-node"),
			AIDR_STUB_LOG: join(work, "stub.log"),
			...env,
		},
	});
}

const stubLog = () => (existsSync(join(work, "stub.log")) ? readFileSync(join(work, "stub.log"), "utf8").trim().split("\n") : []);
const clearLog = () => rmSync(join(work, "stub.log"), { force: true });
const machineState = () => readFileSync(join(work, "state", "machine", "release-state"), "utf8");
const bundleRoot = (digest) => join(work, "install", "releases", digest, "bundle");
const policyFile = () => join(work, "etc", "singularity-aidr", "managed.json");

let v1;
let v2;
before(() => {
	if (skip) return;
	work = mkdtempSync(join(tmpdir(), "aidr-fleet-machine-"));
	privateKey = join(work, "release-private.pem");
	publicKey = join(work, "keys", "release-public.pem");
	mkdirSync(dirname(publicKey));
	must("openssl", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", privateKey]);
	must("openssl", ["pkey", "-in", privateKey, "-pubout", "-out", publicKey]);
	bundleKey = join(work, "keys", "bundle-release-public.pem");
	must("openssl", ["genpkey", "-algorithm", "ED25519", "-out", join(work, "ed-private.pem")]);
	must("openssl", ["pkey", "-in", join(work, "ed-private.pem"), "-pubout", "-out", bundleKey]);
	enrollmentKey = join(work, "keys", "enrollment-key");
	writeFileSync(enrollmentKey, `aidr_fleet_${"A1b2".repeat(6)}\n`);
	v1 = bundleArtifact("v1", "1.0.0");
	v2 = bundleArtifact("v2", "2.0.0");
});
after(() => {
	if (work) rmSync(work, { recursive: true, force: true });
});

test("refuses bad options before anything is staged", { skip }, () => {
	const badUrl = fleet("install", v1, ["--control-plane-url", "http://aidr.corp.example"]);
	assert.notEqual(badUrl.status, 0);
	assert.match(badUrl.stderr, /must be an https:\/\/ URL/);
	const badKey = join(work, "keys", "bad-key");
	writeFileSync(badKey, "aidr_enroll_short\n");
	const badEnrollment = fleet("install", v1, ["--enrollment-key-file", badKey]);
	assert.match(badEnrollment.stderr, /fleet enrollment key/);
	assert.match(fleet("install", v1, ["--protection-locked", "yes"]).stderr, /must be true or false/);
	assert.match(fleet("install", v1, ["--scope", "machine", "--user", "alice"]).stderr, /per-user scope/);
	assert.match(fleet("install", v1, ["--heartbeat"], { AIDR_FLEET_PLATFORM: "macos" }).stderr, /Linux only/);
	assert.ok(!existsSync(join(work, "install", "releases")), "no release was staged");
	assert.ok(!existsSync(policyFile()), "no policy was written");
});

test("a per-user npm package is not installed machine-wide", { skip }, () => {
	const result = fleet("install", packageArtifact());
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /not a standalone AIDR bundle/);
	assert.ok(!existsSync(join(work, "state", "machine", "release-state")));
});

test("install stages the bundle root-style and registers it machine-wide without Node.js", { skip }, () => {
	clearLog();
	const result = fleet("install", v1, [
		"--bundle-public-key", bundleKey,
		"--control-plane-url", "https://aidr.corp.example/functions/v1",
		"--enrollment-key-file", enrollmentKey,
		"--protection-locked", "true",
	]);
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /completed machine-wide/);
	const root = bundleRoot(v1.digest);
	assert.deepEqual(stubLog(), [`${root}/bin/aidr machine-hooks install --bundle-root ${root}`]);
	assert.equal(statSync(join(root, "bin", "aidr")).mode & 0o777, 0o755, "the multi-call binary stays executable");
	assert.equal(statSync(join(root, "dist", "resources", "threats", "rules.yaml")).mode & 0o777, 0o644);
	assert.equal(readFileSync(join(root, "..", "config", "release-public.pem"), "utf8"), readFileSync(bundleKey, "utf8"), "the bundle key sits where machine-hooks and aidr setup look for it");
	assert.equal(machineState(), `current=${v1.digest}\nprevious=\n`);
	assert.ok(!existsSync(join(work, "state", "machine", "pending")));
	assert.equal(readFileSync(join(work, "state", "machine", "options"), "utf8"), "lock_other_hooks=0\nheartbeat=0\n");
	const launcher = readFileSync(join(work, "install", "bin", "aidr"), "utf8");
	assert.ok(launcher.includes(`exec "${root}/bin/aidr" "$@"`), launcher);
	const policy = JSON.parse(readFileSync(policyFile(), "utf8"));
	assert.deepEqual(policy, {
		control_plane_url: "https://aidr.corp.example/functions/v1",
		enrollment_key: `aidr_fleet_${"A1b2".repeat(6)}`,
		protection_locked: true,
	});
	assert.equal(statSync(policyFile()).mode & 0o777, 0o644);
	assert.ok(existsSync(join(work, "etc", "singularity-aidr", "mdm-managed")), "updates are left to device management");
});

test("a repeated install is idempotent and keeps the policy", { skip }, () => {
	clearLog();
	const policyBefore = readFileSync(policyFile(), "utf8");
	const result = fleet("install", v1, ["--bundle-public-key", bundleKey]);
	assert.equal(result.status, 0, result.stderr);
	assert.equal(machineState(), `current=${v1.digest}\nprevious=\n`);
	assert.equal(stubLog().length, 1);
	assert.equal(readFileSync(policyFile(), "utf8"), policyBefore, "no policy option: managed.json is kept as is");
	const otherKey = join(work, "keys", "other-bundle.pem");
	writeFileSync(otherKey, readFileSync(publicKey));
	const rekeyed = fleet("install", v1, ["--bundle-public-key", otherKey]);
	assert.notEqual(rekeyed.status, 0);
	assert.match(rekeyed.stderr, /different \(or no\) bundle key/);
});

test("upgrade, persisted lock and rollback", { skip }, () => {
	clearLog();
	const upgraded = fleet("upgrade", v2, ["--lock-other-hooks"]);
	assert.equal(upgraded.status, 0, upgraded.stderr);
	assert.equal(machineState(), `current=${v2.digest}\nprevious=${v1.digest}\n`);
	assert.deepEqual(stubLog(), [`${bundleRoot(v2.digest)}/bin/aidr machine-hooks install --bundle-root ${bundleRoot(v2.digest)} --lock-other-hooks`]);
	clearLog();
	const rolledBack = fleet("rollback", null);
	assert.equal(rolledBack.status, 0, rolledBack.stderr);
	assert.equal(machineState(), `current=${v1.digest}\nprevious=${v2.digest}\n`);
	assert.deepEqual(stubLog(), [`${bundleRoot(v1.digest)}/bin/aidr machine-hooks install --bundle-root ${bundleRoot(v1.digest)} --lock-other-hooks`], "the lock survives a rollback without the flag");
	assert.ok(readFileSync(join(work, "install", "bin", "aidr"), "utf8").includes(bundleRoot(v1.digest)));
	const health = must(process.execPath, [join(here, "fleet-health.mjs"), "--state-root", join(work, "state"), "--install-root", join(work, "install")]);
	assert.deepEqual(JSON.parse(health.stdout).machine, { release_sha256: v1.digest, release_present: true, lifecycle_pending: false });
	const status = fleet("status", null);
	assert.equal(status.status, 0, status.stderr);
	assert.match(status.stdout, new RegExp(`current=${v1.digest}`));
	assert.match(stubLog().at(-1), /machine-hooks status$/);
});

test("a failed registration leaves the active state and a pending marker", { skip }, () => {
	const failed = fleet("upgrade", v2, [], { AIDR_STUB_FAIL: "1" });
	assert.notEqual(failed.status, 0);
	assert.match(failed.stderr, /machine-wide hook registration failed/);
	assert.equal(machineState(), `current=${v1.digest}\nprevious=${v2.digest}\n`);
	assert.ok(existsSync(join(work, "state", "machine", "pending")), "health fails closed until a run completes");
	const health = run(process.execPath, [join(here, "fleet-health.mjs"), "--state-root", join(work, "state"), "--install-root", join(work, "install")]);
	assert.equal(health.status, 2);
	assert.equal(fleet("status", null).status, 2);
	assert.equal(fleet("upgrade", v2).status, 0, "a retry completes it");
	assert.ok(!existsSync(join(work, "state", "machine", "pending")));
});

test("a tampered retained release is not rolled back to", { skip }, () => {
	const retained = join(work, "install", "releases", v1.digest, "artifact.tgz");
	const original = readFileSync(retained);
	writeFileSync(retained, Buffer.concat([original, Buffer.from("x")]));
	const result = fleet("rollback", null);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /SHA-256 mismatch/);
	writeFileSync(retained, original);
	chmodSync(retained, 0o644);
});

test("uninstall removes only the machine-wide registration", { skip }, () => {
	clearLog();
	const result = fleet("uninstall", null);
	assert.equal(result.status, 0, result.stderr);
	assert.deepEqual(stubLog(), [`${bundleRoot(v2.digest)}/bin/aidr machine-hooks remove`]);
	assert.ok(!existsSync(join(work, "install", "bin", "aidr")));
	assert.ok(!existsSync(join(work, "state", "machine", "release-state")));
	assert.ok(existsSync(join(work, "state", "machine", "uninstalled-release-state")));
	assert.ok(existsSync(bundleRoot(v1.digest)) && existsSync(bundleRoot(v2.digest)), "shared releases are kept");
	assert.ok(existsSync(policyFile()), "machine policy is kept");
	assert.match(fleet("uninstall", null).stderr, /no machine-wide installation/);
	assert.equal(fleet("install", v2).status, 0, "a later install re-registers");
});

test("the macOS PKG postinstall installs a bundle payload machine-wide and only verifies an npm payload", { skip }, () => {
	const pkgRoot = join(work, "pkg-root");
	mkdirSync(join(pkgRoot, "fleet", "unix"), { recursive: true });
	mkdirSync(join(pkgRoot, "payload"), { recursive: true });
	mkdirSync(join(pkgRoot, "config"), { recursive: true });
	writeFileSync(join(pkgRoot, "fleet", "unix", "aidr-fleet.sh"), readFileSync(engine), { mode: 0o755 });
	writeFileSync(join(pkgRoot, "config", "release-public.pem"), readFileSync(publicKey));
	writeFileSync(join(pkgRoot, "config", "bundle-release-public.pem"), readFileSync(bundleKey));
	const source = readFileSync(join(repository, "deploy", "fleet", "macos", "pkg", "scripts", "postinstall"), "utf8");
	const rendered = join(work, "postinstall");
	writeFileSync(rendered, source.replace(/^ROOT=.*$/m, `ROOT="${pkgRoot}"`), { mode: 0o755 });
	const env = {
		PATH: process.env.PATH,
		AIDR_FLEET_TEST_ROOT: work,
		AIDR_FLEET_INSTALL_ROOT: join(work, "pkg-install"),
		AIDR_FLEET_STATE_ROOT: join(work, "pkg-state"),
		AIDR_FLEET_POLICY_DIR: join(work, "pkg-etc"),
		AIDR_NODE_BIN: join(work, "no-node"),
		AIDR_STUB_LOG: join(work, "pkg-stub.log"),
	};
	const stage = (release) => {
		writeFileSync(join(pkgRoot, "payload", "connector.tgz"), readFileSync(release.artifact));
		writeFileSync(join(pkgRoot, "payload", "connector.tgz.sig"), readFileSync(release.signature));
		writeFileSync(join(pkgRoot, "payload", "connector.tgz.sha256"), `${release.digest}\n`);
	};
	stage(v1);
	const installed = run("sh", [rendered, "fixture.pkg", "/", "/"], { env });
	assert.equal(installed.status, 0, installed.stderr);
	const root = join(work, "pkg-install", "releases", v1.digest, "bundle");
	assert.equal(readFileSync(join(work, "pkg-stub.log"), "utf8"), `${root}/bin/aidr machine-hooks install --bundle-root ${root}\n`);
	assert.equal(readFileSync(join(root, "..", "config", "release-public.pem"), "utf8"), readFileSync(bundleKey, "utf8"));
	assert.equal(run("sh", [rendered, "fixture.pkg", "/", "/"], { env }).status, 0, "re-running the PKG is idempotent");
	assert.equal(readFileSync(join(work, "pkg-state", "machine", "release-state"), "utf8"), `current=${v1.digest}\nprevious=\n`);
	stage(packageArtifact());
	const npm = run("sh", [rendered, "fixture.pkg", "/", "/"], { env });
	assert.equal(npm.status, 0, npm.stderr);
	assert.match(npm.stdout, /per-user connector payload verified/);
	assert.equal(readFileSync(join(work, "pkg-state", "machine", "release-state"), "utf8"), `current=${v1.digest}\nprevious=\n`);
});

test("the Jamf policy maps its parameters onto the machine and per-user scopes", { skip }, () => {
	const scripts = join(work, "jamf-scripts");
	mkdirSync(scripts, { recursive: true });
	for (const name of ["install", "upgrade", "rollback", "uninstall"]) {
		writeFileSync(join(scripts, `${name}.sh`), `#!/bin/sh\necho "${name}"\nfor arg in "$@"; do echo "[$arg]"; done\n`, { mode: 0o755 });
	}
	const config = join(work, "jamf-config");
	mkdirSync(config, { recursive: true });
	writeFileSync(join(config, "bundle-release-public.pem"), readFileSync(bundleKey));
	const jamf = (...params) =>
		run("sh", [join(repository, "deploy", "fleet", "macos", "jamf-policy.sh"), "/", "computer", "admin", ...params], {
			env: { PATH: process.env.PATH, AIDR_JAMF_SCRIPT_DIR: scripts, AIDR_JAMF_CONFIG_DIR: config },
		});
	const lines = (result) => result.stdout.trim().split("\n");
	const machine = jamf("install", "/p/a.tgz", "a".repeat(64), "/p/a.sig", "/p/key.pem", "https://aidr.corp.example", "/etc/singularity-aidr/enrollment-key", "protection_locked, lock_other_hooks");
	assert.equal(machine.status, 0, machine.stderr);
	assert.deepEqual(lines(machine), [
		"install", "[--scope]", "[machine]", "[--artifact]", "[/p/a.tgz]", "[--sha256]", `[${"a".repeat(64)}]`,
		"[--signature]", "[/p/a.sig]", "[--public-key]", "[/p/key.pem]",
		"[--bundle-public-key]", `[${join(config, "bundle-release-public.pem")}]`,
		"[--control-plane-url]", "[https://aidr.corp.example]", "[--enrollment-key-file]", "[/etc/singularity-aidr/enrollment-key]",
		"[--protection-locked]", "[true]", "[--lock-other-hooks]",
	]);
	assert.deepEqual(lines(jamf("rollback", "", "", "", "/p/key.pem")), ["rollback", "[--scope]", "[machine]", "[--public-key]", "[/p/key.pem]"]);
	assert.deepEqual(lines(jamf("uninstall")), ["uninstall", "[--scope]", "[machine]"]);
	const perUser = jamf("upgrade-user", "/p/a.tgz", "b".repeat(64), "/p/a.sig", "/p/key.pem", "/p/agent.json", "alice");
	assert.deepEqual(lines(perUser).slice(0, 1), ["upgrade"]);
	assert.ok(lines(perUser).includes("[--user]") && lines(perUser).includes("[alice]") && lines(perUser).includes("[/p/agent.json]"));
	assert.notEqual(jamf("install", "/p/a.tgz", "", "/p/a.sig").status, 0, "install needs the SHA-256");
	assert.notEqual(jamf("install", "/p/a.tgz", "a".repeat(64), "/p/a.sig", "/p/k", "", "", "fail_open").status, 0, "unknown switches are refused");
});
