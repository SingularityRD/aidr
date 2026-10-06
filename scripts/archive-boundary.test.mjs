import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, hkdfSync } from "node:crypto";
import { chmodSync, copyFileSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { afterEach, test } from "node:test";
import { gzipSync } from "node:zlib";
import { copyReviewedRuntime, createTarBoundaryValidator, inspectAuthenticatedInstallation, inspectReviewedRuntime } from "./archive-boundary.mjs";
import { hardenRecoveryKeyFile } from "./deployment-restore-drill.mjs";

const workspaces = [];
afterEach(() => {
	for (const path of workspaces.splice(0)) rmSync(path, { recursive: true, force: true });
});

function octal(value, length) {
	return `${value.toString(8).padStart(length - 1, "0")}\0`;
}

function header(name, { type = "0", body = Buffer.alloc(0), link = "" } = {}) {
	const block = Buffer.alloc(512);
	block.write(name, 0, 100, "utf8");
	block.write(octal(0o600, 8), 100, 8, "ascii");
	block.write(octal(0, 8), 108, 8, "ascii");
	block.write(octal(0, 8), 116, 8, "ascii");
	block.write(octal(body.length, 12), 124, 12, "ascii");
	block.write(octal(0, 12), 136, 12, "ascii");
	block.fill(0x20, 148, 156);
	block.write(type, 156, 1, "ascii");
	block.write(link, 157, 100, "utf8");
	block.write("ustar\0", 257, 6, "ascii");
	block.write("00", 263, 2, "ascii");
	const sum = block.reduce((total, byte) => total + byte, 0);
	block.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
	return block;
}

function archive(entries, end = true) {
	const chunks = [];
	for (const entry of entries) {
		const body = Buffer.from(entry.body ?? "");
		chunks.push(header(entry.name, { ...entry, body }), body);
		const padding = (512 - (body.length % 512)) % 512;
		if (padding) chunks.push(Buffer.alloc(padding));
	}
	if (end) chunks.push(Buffer.alloc(1024));
	return Buffer.concat(chunks);
}

async function validate(bytes) {
	await pipeline(Readable.from([bytes]), createTarBoundaryValidator());
}

test("accepts a canonical regular-file and directory archive", async () => {
	await validate(archive([{ name: "./data/", type: "5" }, { name: "./data/value", body: "safe" }]));
});

test("rejects links and every special tar entry type", async () => {
	for (const type of ["1", "2", "3", "4", "6", "7", "g", "K", "S"]) {
		await assert.rejects(validate(archive([{ name: `entry-${type}`, type }])), /not a regular file or directory/);
	}
});

function pax(key, value) {
	const record = ` ${key}=${value}\n`;
	let length = Buffer.byteLength(record) + 1;
	while (Buffer.byteLength(`${length}${record}`) !== length) length = Buffer.byteLength(`${length}${record}`);
	return `${length}${record}`;
}

test("accepts portable PAX and GNU long names while validating their effective paths", async () => {
	const longName = `nested/${"object-".repeat(30)}`;
	for (const type of ["x", "L"]) {
		const body = type === "x" ? pax("path", longName) + pax("mtime", "1.5") : `${longName}\0`;
		await validate(archive([{ name: "extended", type, body }, { name: "truncated", body: "safe" }]));
		for (const name of ["../escape", "/absolute", "./C:/windows", "././C:/windows", "file:stream", "safe\\escape"]) {
			const unsafe = type === "x" ? pax("path", name) : `${name}\0`;
			await assert.rejects(validate(archive([{ name: "extended", type, body: unsafe }, { name: "safe" }])), /entry path/);
		}
		await assert.rejects(validate(archive([{ name: "extended", type, body }])), /no following entry/);
		await assert.rejects(validate(archive([{ name: "extended", type, body }, { name: "truncated" }, { name: "extended-again", type, body }, { name: "truncated-again" }])), /duplicate entry path/);
	}
	for (const key of ["linkpath", "size", "GNU.sparse.map", "SCHILY.xattr.security.capability"]) {
		await assert.rejects(validate(archive([{ name: "extended", type: "x", body: pax(key, "unsafe") }, { name: "safe" }])), /unsupported PAX field/);
	}
	for (const body of ["999 path=safe\n", "0 path=safe\n", "12 path=bad", pax("path", "first") + pax("path", "second")]) {
		await assert.rejects(validate(archive([{ name: "extended", type: "x", body }, { name: "safe" }])), /PAX/);
	}
});

test("validates a native tar long-filename backup in bounded stream chunks", async () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-long-backup-path-"));
	workspaces.push(root);
	mkdirSync(join(root, "nested"));
	writeFileSync(join(root, "nested", "object-" + "a".repeat(110)), "safe");
	const tar = spawnSync("tar", ["-C", root, "-cf", "-", "."], { encoding: null });
	assert.equal(tar.status, 0, tar.stderr?.toString());
	const chunks = [];
	for (let offset = 0; offset < tar.stdout.length; offset += 137) chunks.push(tar.stdout.subarray(offset, offset + 137));
	await pipeline(Readable.from(chunks), createTarBoundaryValidator());
});

test("rejects traversal, absolute, Windows and duplicate paths", async () => {
	for (const name of ["../escape", "/absolute", "C:/windows", "safe\\..\\escape", "a/../b", "a//b"]) {
		await assert.rejects(validate(archive([{ name }])), /entry path/);
	}
	await assert.rejects(validate(archive([{ name: "same" }, { name: "./same" }])), /duplicate entry path/);
	await assert.rejects(validate(archive([{ name: "parent" }, { name: "parent/child" }])), /descends from a regular file/);
	await assert.rejects(validate(archive([{ name: "parent/child" }, { name: "parent" }])), /replaces an existing directory path/);
});

test("rejects malformed checksums and truncated archives", async () => {
	const corrupt = archive([{ name: "value", body: "safe" }]);
	corrupt[10] ^= 1;
	await assert.rejects(validate(corrupt), /checksum mismatch/);
	await assert.rejects(validate(archive([{ name: "value", body: "safe" }], false)), /complete end marker/);
	await assert.rejects(validate(archive([{ name: "value", body: "safe" }]).subarray(0, 513)), /truncated/);
});

function runtimeFixture(commit = "a".repeat(40)) {
	const root = mkdtempSync(join(tmpdir(), "aidr-reviewed-runtime-"));
	workspaces.push(root);
	for (const directory of ["auth-templates", "backup", "migrations", "volumes/functions", "dashboard", "ingress", "maintenance", "health"]) mkdirSync(join(root, directory), { recursive: true });
	writeFileSync(join(root, ".env"), "POSTGRES_PASSWORD=fixture\n");
	writeFileSync(join(root, ".env.functions"), "AIDR_FIXTURE=true\n");
	writeFileSync(join(root, ".env.ingress"), "AIDR_INGRESS_FIXTURE=true\n");
	writeFileSync(join(root, ".env.readiness"), "AIDR_HEALTH_STATE_DIR=/srv/aidr/health\n");
	writeFileSync(join(root, "agent-config.json"), "{}\n");
	writeFileSync(join(root, "compose.yml"), "services: {}\n");
	const migrationName = "20260922000000_fixture.sql";
	writeFileSync(join(root, "migrations", migrationName), "select 1;\n");
	writeFileSync(join(root, "dashboard", "index.html"), "safe dashboard\n");
	writeFileSync(join(root, "ingress", "proxy.conf"), "safe ingress\n");
	writeFileSync(join(root, "backup", "timer.service"), "safe timer\n");
	writeFileSync(join(root, "maintenance", "readiness.service"), "safe readiness\n");
	writeFileSync(join(root, "auth-templates", "recovery.html"), "safe recovery\n");
	writeFileSync(join(root, "volumes/functions", "index.ts"), "safe function\n");
	const fileHash = (path) => createHash("sha256").update(readFileSync(join(root, path))).digest("hex");
	writeFileSync(join(root, "deployment.json"), JSON.stringify({
		schema_version: 1, mode: "self-hosted", source_has_changes: false, source_commit: commit,
		migrations: [{ name: migrationName, sha256: fileHash(`migrations/${migrationName}`) }],
		artifacts: ["auth-templates/recovery.html", "backup/timer.service", "dashboard/index.html", "ingress/proxy.conf", "maintenance/readiness.service", "volumes/functions/index.ts"].map((path) => ({ path, sha256: fileHash(path) })),
	}));
	return root;
}

test("copies only a clean reviewed runtime bound to the backup commit", () => {
	const commit = "b".repeat(40);
	const source = runtimeFixture(commit);
	const output = join(mkdtempSync(join(tmpdir(), "aidr-recovery-output-")), "runtime");
	workspaces.push(dirname(output));
	const binding = copyReviewedRuntime(source, output, { sourceCommit: commit });
	assert.equal(createHash("sha256").update(readFileSync(join(output, "compose.yml"))).digest("hex"), createHash("sha256").update("services: {}\n").digest("hex"));
	assert.equal(binding.source_commit, commit);
	assert.equal(binding.runtime_deployment_sha256, createHash("sha256").update(readFileSync(join(source, "deployment.json"))).digest("hex"));
	assert.equal(readFileSync(join(output, ".env.functions"), "utf8"), "AIDR_FIXTURE=true\n");
});

test("reviewed runtime fails closed on commit drift, extra roots and hardlinks", () => {
	const source = runtimeFixture();
	assert.throws(() => copyReviewedRuntime(source, join(source, "nested"), { sourceCommit: "a".repeat(40) }), /separate directories/);
	assert.throws(() => copyReviewedRuntime(source, join(tmpdir(), `aidr-out-${Date.now()}`), { sourceCommit: "b".repeat(40) }), /not bound/);
	mkdirSync(join(source, "upstream"));
	writeFileSync(join(source, "upstream", "unexpected"), "no");
	assert.throws(() => copyReviewedRuntime(source, join(tmpdir(), `aidr-out-${Date.now()}-extra`), { sourceCommit: "a".repeat(40) }), /unexpected root entries: upstream/);
	rmSync(join(source, "upstream"), { recursive: true });
	rmSync(join(source, "agent-config.json"));
	linkSync(join(source, "compose.yml"), join(source, "agent-config.json"));
	assert.throws(() => copyReviewedRuntime(source, join(tmpdir(), `aidr-out-${Date.now()}-link`), { sourceCommit: "a".repeat(40) }), /link or special entry/);
});

test("reviewed runtime rejects changed and undeclared migration or artifact files", () => {
	const commit = "c".repeat(40);
	const source = runtimeFixture(commit);
	writeFileSync(join(source, "dashboard", "index.html"), "tampered\n");
	assert.throws(() => copyReviewedRuntime(source, join(tmpdir(), `aidr-out-${Date.now()}-tampered`), { sourceCommit: commit }), /artifact inventory differs/);
	writeFileSync(join(source, "dashboard", "index.html"), "safe dashboard\n");
	writeFileSync(join(source, "migrations", "20260922000001_extra.sql"), "select 2;\n");
	assert.throws(() => copyReviewedRuntime(source, join(tmpdir(), `aidr-out-${Date.now()}-migration`), { sourceCommit: commit }), /migration inventory differs/);
});

test("authenticated installation binding rejects secret/config mismatch and restores the exact tree", () => {
	const commit = "d".repeat(40);
	const reviewed = runtimeFixture(commit);
	const installation = runtimeFixture(commit);
	writeFileSync(join(installation, ".env"), "POSTGRES_PASSWORD=original-database-secret\n");
	const reviewedBinding = inspectReviewedRuntime(reviewed, { sourceCommit: commit });
	const installationBinding = inspectReviewedRuntime(installation, { sourceCommit: commit });
	const verified = inspectAuthenticatedInstallation(installation, {
		sourceCommit: commit,
		expectedTreeSha256: installationBinding.runtime_tree_sha256,
		reviewedDeployment: reviewedBinding.deployment,
	});
	assert.equal(verified.runtime_tree_sha256, installationBinding.runtime_tree_sha256);
	const output = join(mkdtempSync(join(tmpdir(), "aidr-exact-installation-")), "runtime");
	workspaces.push(dirname(output));
	copyReviewedRuntime(installation, output, { sourceCommit: commit });
	assert.equal(readFileSync(join(output, ".env"), "utf8"), "POSTGRES_PASSWORD=original-database-secret\n");
	writeFileSync(join(installation, ".env.functions"), "AIDR_FIXTURE=mismatched\n");
	assert.throws(() => inspectAuthenticatedInstallation(installation, {
		sourceCommit: commit,
		expectedTreeSha256: installationBinding.runtime_tree_sha256,
		reviewedDeployment: reviewedBinding.deployment,
	}), /differs from the backup manifest/);
});

test("recovery validates and extracts the exact authenticated installation before volumes", () => {
	const source = readFileSync(new URL("./deployment-backup.mjs", import.meta.url), "utf8");
	assert.match(source, /for \(const entry of manifest\.entries\)[\s\S]*await validateEncryptedTar\(entry, backup\)/);
	const extractInstallation = source.indexOf('await decryptTo(manifest.entries.find((entry) => entry.name === "installation.tar.gz.enc")');
	const authenticateInstallation = source.indexOf("installationBinding = inspectAuthenticatedInstallation(installationStaging");
	const restoreInstallation = source.indexOf("copyReviewedRuntime(installationStaging, output");
	const createVolumes = source.indexOf('command("docker", [...composeArgs(output, project), "create", "--build", "db", "storage"])');
	assert.ok(extractInstallation >= 0 && extractInstallation < authenticateInstallation);
	assert.ok(authenticateInstallation < restoreInstallation && restoreInstallation < createVolumes, "authenticated installation secrets/config must be restored before volumes are created");
	assert.match(source, /installation_runtime_tree_sha256: installationBinding\.runtime_tree_sha256/);
});

test("failed recovery removes only its own output and Docker project", async () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-recover-cleanup-"));
	workspaces.push(root);
	const commit = "e".repeat(40);
	const runtime = runtimeFixture(commit);
	const backup = join(root, "backup");
	const bin = join(root, "bin");
	mkdirSync(backup);
	mkdirSync(bin);
	const key = join(root, "recovery.key");
	const rawKey = Buffer.from("ab".repeat(32), "hex");
	writeFileSync(key, `${rawKey.toString("hex")}\n`, { mode: 0o600 });
	await hardenRecoveryKeyFile(key);
	const encKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "encryption", 32));
	const macKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "manifest", 32));
	const tar = spawnSync("tar", ["--format=ustar", "-C", runtime, "-czf", "-", "."], { encoding: null });
	assert.equal(tar.status, 0, tar.stderr?.toString());
	const entries = [];
	for (const [index, name] of ["database.tar.gz.enc", "storage.tar.gz.enc", "installation.tar.gz.enc"].entries()) {
		const iv = Buffer.alloc(12, index + 1);
		const cipher = createCipheriv("aes-256-gcm", encKey, iv);
		cipher.setAAD(Buffer.from(name));
		const encrypted = Buffer.concat([cipher.update(index === 2 ? tar.stdout : gzipSync(archive([{ name: "./", type: "5" }] ))), cipher.final()]);
		writeFileSync(join(backup, name), encrypted, { mode: 0o600 });
		entries.push({ name, iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), sha256: createHash("sha256").update(encrypted).digest("hex") });
	}
	const payload = JSON.stringify({ schema_version: 1, type: "aidr-cold-volumes", started_at: new Date().toISOString(), completed_at: new Date().toISOString(), source_project: "fixture", source_commit: commit, installation_runtime_sha256: inspectReviewedRuntime(runtime, { sourceCommit: commit }).runtime_tree_sha256, architecture: "test-arch", helper_image: "fixture", entries });
	writeFileSync(join(backup, "backup.json"), JSON.stringify({ payload, hmac_sha256: createHmac("sha256", macKey).update(payload).digest("hex") }));
	const fake = join(bin, "fake-docker.mjs");
	writeFileSync(fake, `
import { appendFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_DOCKER_LOG, args.join(" ") + "\\n");
if (args[0] === "info") { process.stdout.write("test-arch\\n"); process.exit(0); }
if (args.includes("--filter") && process.env.FAKE_COLLISION === "1") { process.stdout.write("preexisting\\n"); process.exit(0); }
if (args[0] === "volume" && args[1] === "inspect") process.exit(1);
if (args.includes("create") || args.includes("down")) process.exit(0);
if (args.includes("ps") && args.includes("--all") && args.includes("--quiet") && !args.includes("--filter")) process.exit(70);
process.exit(0);
`);
	let nodeOptions = process.env.NODE_OPTIONS ?? "";
	if (process.platform === "win32") {
		const preload = join(bin, "docker-preload.cjs");
		writeFileSync(preload, `
const { appendFileSync } = require("node:fs");
const { basename } = require("node:path");
if (basename(process.execPath).toLowerCase() !== "docker.exe") return;
const args = process.argv.slice(1); args[0] = basename(args[0]);
appendFileSync(process.env.FAKE_DOCKER_LOG, args.join(" ") + "\\n");
if (args[0] === "info") { process.stdout.write("test-arch\\n"); process.exit(0); }
if (args.includes("--filter") && process.env.FAKE_COLLISION === "1") { process.stdout.write("preexisting\\n"); process.exit(0); }
if (args[0] === "volume" && args[1] === "inspect") process.exit(1);
if (args.includes("create") || args.includes("down")) process.exit(0);
if (args.includes("ps") && args.includes("--all") && args.includes("--quiet") && !args.includes("--filter")) process.exit(70);
process.exit(0);
`);
		try { linkSync(process.execPath, join(bin, "docker.exe")); } catch { copyFileSync(process.execPath, join(bin, "docker.exe")); }
		nodeOptions = `${nodeOptions} --require "${preload.replaceAll("\\", "/")}"`.trim();
	} else {
		writeFileSync(join(bin, "docker"), `#!/bin/sh\nexec "${process.execPath}" "${fake}" "$@"\n`);
		chmodSync(join(bin, "docker"), 0o755);
	}
	const project = "aidr-recovery-1234567890abcdef";
	const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`, NODE_OPTIONS: nodeOptions, FAKE_DOCKER_LOG: join(root, "docker.log") };
	const run = (output, extraEnv = {}) => spawnSync(process.execPath, [resolve("scripts/deployment-backup.mjs"), "recover", "--backup", backup, "--output", output, "--key-file", key, "--runtime", runtime, "--project", project], { encoding: "utf8", env: { ...env, ...extraEnv }, windowsHide: true });
	const existing = join(root, "existing");
	mkdirSync(existing);
	writeFileSync(join(existing, "keep.txt"), "user-owned");
	const existingResult = run(existing);
	assert.notEqual(existingResult.status, 0);
	assert.match(existingResult.stderr, /new separate --output directory/);
	assert.equal(readFileSync(join(existing, "keep.txt"), "utf8"), "user-owned");
	const collision = run(join(root, "collision-output"), { FAKE_COLLISION: "1" });
	assert.notEqual(collision.status, 0);
	assert.match(collision.stderr, /already owns Docker resources/);
	assert.equal(existsSync(join(root, "collision-output")), false);
	const output = join(root, "failed-output");
	const failure = run(output);
	assert.notEqual(failure.status, 0);
	assert.match(failure.stderr, /docker compose failed/);
	assert.equal(existsSync(output), false);
	assert.match(readFileSync(join(root, "docker.log"), "utf8"), /down --volumes --remove-orphans/);
});
