import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, hkdfSync } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { cleanupAbandonedSpool, parseTarget, verifyFilesystemMountIdentity } from "./deployment-backup-offsite.mjs";
import { hardenRecoveryKeyFile } from "./deployment-restore-drill.mjs";

const SCRIPT = resolve("scripts/deployment-backup-offsite.mjs");
const FILES = ["database.tar.gz.enc", "storage.tar.gz.enc", "installation.tar.gz.enc"];
const TEST_MOUNT_IDENTITY = "UUID=aidr-test-uuid";
const TEST_RUNNER = `import { runOffsite } from ${JSON.stringify(pathToFileURL(SCRIPT).href)};
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
let targetChecks = 0;
const probe = async (path) => {
  if (path === ${JSON.stringify(sep)}) return { target: ${JSON.stringify(sep)}, uuid: "host-root-uuid", source: "/dev/host-root", fstype: "ext4" };
  targetChecks += 1;
  if (Number(process.env.AIDR_TEST_SWAP_CYCLE_ON_CHECK) === targetChecks) {
    const output = await readFile(process.env.AIDR_TEST_CYCLE_OUTPUT_FILE, "utf8");
    await rename(output, output + ".original");
    await mkdir(output);
    await writeFile(join(output, "keep.txt"), "operator-owned");
  }
  if (Number(process.env.AIDR_TEST_MOUNT_FAIL_AFTER_TARGET_CHECKS) === targetChecks) return { target: path, uuid: "wrong-uuid", source: "/dev/wrong", fstype: "ext4" };
  return { target: path, uuid: "aidr-test-uuid", source: "/dev/aidr-test", fstype: "ext4" };
};
await runOffsite(process.argv.slice(1), process.env, { findmnt: probe }).catch((error) => {
  console.error("AIDR offsite backup failed: " + error.message);
  process.exitCode = 1;
});`;

function digest(buffer) {
	return createHash("sha256").update(buffer).digest("hex");
}

async function fixture(t, completedAt = "2026-09-12T08:00:00Z", startedAt = completedAt) {
	const root = await mkdtemp(join(tmpdir(), "aidr-offsite-test-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const backup = join(root, "source");
	const target = join(root, "offsite");
	const keyFile = join(root, "custody", "recovery.key");
	const health = join(root, "health", "backup.json");
	await Promise.all([mkdir(backup), mkdir(target), mkdir(join(root, "custody"))]);
	const rawKey = Buffer.from("ab".repeat(32), "hex");
	await writeFile(keyFile, `${rawKey.toString("hex")}\n`, { mode: 0o600 });
	await hardenRecoveryKeyFile(keyFile);
	const encKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "encryption", 32));
	const macKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "manifest", 32));
	const validEmptyTarGzip = gzipSync(Buffer.alloc(1024));
	const entries = [];
	for (const [index, name] of FILES.entries()) {
		const iv = Buffer.alloc(12, index + 1);
		const cipher = createCipheriv("aes-256-gcm", encKey, iv);
		cipher.setAAD(Buffer.from(name));
		const encrypted = Buffer.concat([cipher.update(validEmptyTarGzip), cipher.final()]);
		await writeFile(join(backup, name), encrypted, { mode: 0o600 });
		entries.push({
			name,
			iv: iv.toString("hex"),
			tag: cipher.getAuthTag().toString("hex"),
			sha256: digest(encrypted),
		});
	}
	const payload = JSON.stringify({
		schema_version: 1,
		type: "aidr-cold-volumes",
		started_at: startedAt,
		completed_at: completedAt,
		source_project: "offsite-test",
		source_commit: "a".repeat(40),
		installation_runtime_sha256: "c".repeat(64),
		architecture: "test",
		helper_image: "test",
		entries,
	});
	const envelope = {
		payload,
		hmac_sha256: createHmac("sha256", macKey).update(payload).digest("hex"),
	};
	await writeFile(join(backup, "backup.json"), JSON.stringify(envelope), { mode: 0o600 });
	const backupId = digest(Buffer.from(JSON.stringify(envelope)));
	return { root, backup, target, keyFile, health, backupId };
}

async function command(args, expectedCode = 0, extraEnv = {}, cwd) {
	const result = await new Promise((done, fail) => {
		const child = spawn(process.execPath, ["--input-type=module", "--eval", TEST_RUNNER, ...args], { cwd, stdio: ["ignore", "pipe", "pipe"], windowsHide: true, env: { ...process.env, AIDR_BACKUP_FILESYSTEM_MOUNT_IDENTITY: TEST_MOUNT_IDENTITY, ...extraEnv } });
		let stdout = "";
		let stderr = "";
		child.stdout.setEncoding("utf8");
		child.stderr.setEncoding("utf8");
		child.stdout.on("data", (chunk) => { stdout += chunk; });
		child.stderr.on("data", (chunk) => { stderr += chunk; });
		child.once("error", fail);
		child.once("close", (code) => done({ code, stdout, stderr }));
	});
	assert.equal(result.code, expectedCode, `${result.stdout}\n${result.stderr}`);
	return result;
}

async function fakeAws(root) {
	const script = join(root, "fake-aws.mjs");
	await writeFile(script, `
import { appendFile, copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
const store = process.env.FAKE_S3_ROOT;
const args = process.argv.slice(2);
if (process.env.FAKE_AWS_LOG) await appendFile(process.env.FAKE_AWS_LOG, args.join(" ") + "\\n");
const serviceIndex = args.findIndex((value) => value === "s3" || value === "s3api");
if (serviceIndex < 0) process.exit(70);
const service = args[serviceIndex];
const command = args[serviceIndex + 1];
if ((command === "list-objects-v2" || command === "list-object-versions") && process.env.FAKE_S3_DENY_LIST === "1") process.exit(73);
const rest = args.slice(serviceIndex + 2);
const value = (name) => rest[rest.indexOf(name) + 1];
const uri = (text) => {
  const match = text.match(/^s3:\\/\\/([^/]+)\\/(.+)$/);
  if (!match) throw new Error("invalid fake uri");
  return { bucket: match[1], key: match[2], path: join(store, match[1], ...match[2].split("/")) };
};
const object = () => {
  const bucket = value("--bucket"); const key = value("--key");
  return { bucket, key, path: join(store, bucket, ...key.split("/")) };
};
const metaPath = (path) => path + ".fake-meta";
const loadMeta = async (path) => { try { return JSON.parse(await readFile(metaPath(path), "utf8")); } catch (error) { if (error.code === "ENOENT") return { Metadata: {} }; throw error; } };
const saveMeta = async (path, metadata) => writeFile(metaPath(path), JSON.stringify(metadata));
const metadata = (text) => Object.fromEntries((text || "").split(",").filter(Boolean).map((pair) => {
  const index = pair.indexOf("="); return [pair.slice(0, index), pair.slice(index + 1)];
}));
const output = (value) => process.stdout.write(JSON.stringify(value));
if (service === "s3" && command === "cp") {
  const source = rest[0].startsWith("s3://") ? uri(rest[0]) : { path: rest[0] };
  const target = uri(rest[1]);
  await mkdir(dirname(target.path), { recursive: true });
  await copyFile(source.path, target.path);
  if (rest.includes("--metadata")) await saveMeta(target.path, { Metadata: metadata(value("--metadata")) });
  else await copyFile(metaPath(source.path), metaPath(target.path));
  process.exit(0);
}
if (service !== "s3api") process.exit(71);
const current = object();
if (command === "put-object") {
  await mkdir(dirname(current.path), { recursive: true });
  await copyFile(value("--body"), current.path);
  const stored = { Metadata: metadata(value("--metadata")) };
  if (rest.includes("--object-lock-mode")) stored.Retention = { Mode: value("--object-lock-mode"), RetainUntilDate: value("--object-lock-retain-until-date") };
  await saveMeta(current.path, stored); output({});
} else if (command === "head-object") {
  const stored = await loadMeta(current.path); output({ ContentLength: (await stat(current.path)).size, Metadata: stored.Metadata, ObjectLockMode: stored.Retention?.Mode, ObjectLockRetainUntilDate: stored.Retention?.RetainUntilDate, ObjectLockLegalHoldStatus: process.env.FAKE_S3_LEGAL_HOLD === "1" ? "ON" : "OFF" });
} else if (command === "get-object") {
  const destination = rest[rest.indexOf("--key") + 2];
  await mkdir(dirname(destination), { recursive: true }); await copyFile(current.path, destination); output({});
} else if (command === "delete-object") {
  if (process.env.FAKE_S3_FAIL_DELETE_KEY && current.key.endsWith(process.env.FAKE_S3_FAIL_DELETE_KEY)) process.exit(75);
  if (process.env.FAKE_S3_IGNORE_DELETE !== "1" &&
      (!process.env.FAKE_S3_IGNORE_DELETE_KEY || !current.key.endsWith(process.env.FAKE_S3_IGNORE_DELETE_KEY))) {
    await rm(current.path, { force: true }); await rm(metaPath(current.path), { force: true });
  }
  output({});
} else if (command === "put-object-retention") {
  const stored = await loadMeta(current.path); stored.Retention = metadata(value("--retention")); await saveMeta(current.path, stored); output({});
} else if (command === "get-object-retention") {
  const stored = await loadMeta(current.path);
  const retention = stored.Retention && { ...stored.Retention };
  if (retention && process.env.FAKE_S3_RETENTION_DATE === "missing") delete retention.RetainUntilDate;
  else if (retention && process.env.FAKE_S3_RETENTION_DATE) retention.RetainUntilDate = process.env.FAKE_S3_RETENTION_DATE;
  output({ Retention: retention });
} else if (command === "list-objects-v2" || command === "list-object-versions") {
  const bucket = value("--bucket"); const prefix = value("--prefix"); const base = join(store, bucket);
  const keys = [];
  const walk = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (!entry.name.endsWith(".fake-meta")) keys.push(path.slice(base.length + 1).replaceAll("\\\\", "/"));
    }
  };
  try { await walk(base); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const contents = [];
  for (const Key of keys.filter((key) => key.startsWith(prefix))) {
    contents.push({ Key, LastModified: (await stat(join(base, ...Key.split("/")))).mtime.toISOString() });
  }
  output(command === "list-object-versions" ? { IsTruncated: false, Versions: contents.map((item) => ({ ...item, VersionId: "v1" })), DeleteMarkers: [] } : { IsTruncated: false, Contents: contents });
} else process.exit(72);
`);
	return script;
}

test("filesystem target publishes, verifies, downloads, and is idempotent", async (t) => {
	const f = await fixture(t);
	await mkdir(f.target, { recursive: true });
	const oldStaging = join(f.target, `.staging-${"1".repeat(64)}-${"2".repeat(12)}`);
	const freshStaging = join(f.target, `.staging-${"3".repeat(64)}-${"4".repeat(12)}`);
	const unownedStaging = join(f.target, `.staging-${"5".repeat(64)}-${"6".repeat(12)}`);
	await Promise.all([mkdir(oldStaging), mkdir(freshStaging), mkdir(unownedStaging)]);
	await writeFile(`${oldStaging}.aidr-owned`, "AIDR temporary backup v1\n");
	await utimes(oldStaging, new Date("2020-01-01T00:00:00Z"), new Date("2020-01-01T00:00:00Z"));
	await utimes(`${oldStaging}.aidr-owned`, new Date("2020-01-01T00:00:00Z"), new Date("2020-01-01T00:00:00Z"));
	await utimes(unownedStaging, new Date("2020-01-01T00:00:00Z"), new Date("2020-01-01T00:00:00Z"));
	const uploadArgs = [
		"upload",
		"--backup", f.backup,
		"--target", f.target,
		"--key-file", f.keyFile,
		"--key-reference", "vault://production/aidr-recovery-key",
		"--retention-days", "35",
		"--health-file", f.health,
	];
	const first = JSON.parse((await command(uploadArgs)).stdout);
	assert.equal(first.backup_id, f.backupId);
	assert.equal(first.verified, true);
	await assert.rejects(stat(oldStaging), /ENOENT/);
	assert.equal((await stat(freshStaging)).isDirectory(), true);
	assert.equal((await stat(unownedStaging)).isDirectory(), true);
	const commit = JSON.parse(await readFile(join(f.target, f.backupId, "COMMITTED.json"), "utf8"));
	assert.equal(commit.backup_id, f.backupId);
	assert.equal(commit.key_reference, "vault://production/aidr-recovery-key");
	assert.equal(commit.retention.days, 35);
	assert.equal(commit.retention.mode, "METADATA_ONLY");
	assert.deepEqual(commit.objects.map((entry) => entry.name).sort(), ["backup.json", ...FILES].sort());
	assert.equal(JSON.stringify(commit).includes("ab".repeat(32)), false);

	const health = JSON.parse(await readFile(f.health, "utf8"));
	assert.deepEqual(Object.keys(health), ["schema_version", "status", "recovery_point_at", "completed_at", "verified_at"]);
	assert.equal(health.schema_version, 2);
	assert.equal(health.status, "ok");
	assert.equal(health.recovery_point_at, "2026-09-12T08:00:00Z");
	assert.equal(health.completed_at, "2026-09-12T08:00:00Z");
	assert.ok(Number.isFinite(Date.parse(health.verified_at)));
	if (process.platform !== "win32") assert.equal((await stat(f.health)).mode & 0o777, 0o644);

	const second = JSON.parse((await command(uploadArgs)).stdout);
	assert.equal(second.backup_id, first.backup_id);
	const changedRetention = [...uploadArgs];
	changedRetention[changedRetention.indexOf("--retention-days") + 1] = "90";
	const mismatch = await command(changedRetention, 1);
	assert.match(mismatch.stderr, /retention differs from the requested policy/);
	assert.equal(JSON.parse(await readFile(join(f.target, f.backupId, "COMMITTED.json"), "utf8")).retention.days, 35);
	const output = join(f.root, "downloaded");
	await command([
		"download",
		"--backup-id", f.backupId,
		"--target", f.target,
		"--output", output,
		"--key-file", f.keyFile,
	]);
	for (const name of ["backup.json", ...FILES]) {
		assert.equal(await readFile(join(output, name), "hex"), await readFile(join(f.backup, name), "hex"));
	}
});

test("remote corruption fails before a readiness receipt can be written", async (t) => {
	const f = await fixture(t);
	await command([
		"upload", "--backup", f.backup, "--target", f.target,
		"--key-file", f.keyFile, "--key-reference", "hsm://aidr/recovery", "--retention-days", "30",
	]);
	await writeFile(join(f.target, f.backupId, "database.tar.gz.enc"), "modified");
	const health = join(f.root, "corrupt-health.json");
	const result = await command([
		"verify", "--backup-id", f.backupId, "--target", f.target,
		"--key-file", f.keyFile, "--health-file", health,
	], 1);
	assert.match(result.stderr, /copy verification failed|integrity/i);
	assert.equal(JSON.parse(await readFile(health, "utf8")).status, "failed");
	const output = join(f.root, "corrupt-download");
	await command([
		"download", "--backup-id", f.backupId, "--target", f.target,
		"--key-file", f.keyFile, "--output", output,
	], 1);
	await assert.rejects(stat(output), /ENOENT/, "failed download must not leave partial recovery input");
});

test("latest download selects a fresh authenticated backup for the reviewed commit", async (t) => {
	const f = await fixture(t, new Date().toISOString());
	await command([
		"upload", "--backup", f.backup, "--target", f.target,
		"--key-file", f.keyFile, "--key-reference", "vault://aidr/recovery", "--retention-days", "30",
	]);
	const output = join(f.root, "latest");
	const selected = JSON.parse((await command([
		"download-latest", "--target", f.target, "--output", output, "--key-file", f.keyFile,
		"--expected-source-commit", "a".repeat(40), "--max-age-minutes", "60",
	])).stdout);
	assert.equal(selected.backup_id, f.backupId);
	assert.equal(await readFile(join(output, "backup.json"), "hex"), await readFile(join(f.backup, "backup.json"), "hex"));
});

test("long archive duration cannot make a stale recovery point satisfy RPO freshness", async (t) => {
	const completed = new Date().toISOString();
	const started = new Date(Date.now() - 90 * 60000).toISOString();
	const f = await fixture(t, completed, started);
	await command([
		"upload", "--backup", f.backup, "--target", f.target,
		"--key-file", f.keyFile, "--key-reference", "vault://aidr/recovery", "--retention-days", "30", "--health-file", f.health,
	]);
	const health = JSON.parse(await readFile(f.health, "utf8"));
	assert.equal(health.recovery_point_at, started);
	assert.equal(health.completed_at, completed);
	const output = join(f.root, "stale-latest");
	const rejected = await command([
		"download-latest", "--target", f.target, "--output", output, "--key-file", f.keyFile,
		"--expected-source-commit", "a".repeat(40), "--max-age-minutes", "60",
	], 1);
	assert.match(rejected.stderr, /Authenticated recovery point exceeds the required maximum age/);
	await assert.rejects(stat(output), /ENOENT/);
});

test("recovery point later than archive completion is rejected before publication", async (t) => {
	const f = await fixture(t, "2026-09-12T08:00:00Z", "2026-09-12T09:00:00Z");
	const rejected = await command([
		"upload", "--backup", f.backup, "--target", f.target,
		"--key-file", f.keyFile, "--key-reference", "vault://aidr/recovery", "--retention-days", "30",
	], 1);
	assert.match(rejected.stderr, /recovery point is later than archive completion/);
	await assert.rejects(stat(join(f.target, f.backupId, "COMMITTED.json")), /ENOENT|ENOTDIR/);
});

test("download actions preserve an existing output and leave no candidate directory", async (t) => {
	const f = await fixture(t, new Date().toISOString());
	await command([
		"upload", "--backup", f.backup, "--target", f.target,
		"--key-file", f.keyFile, "--key-reference", "vault://aidr/recovery", "--retention-days", "30",
	]);
	const output = join(f.root, "owned-output");
	await mkdir(output);
	await writeFile(join(output, "keep.txt"), "user-owned");
	for (const action of [
		["download", "--backup-id", f.backupId],
		["download-latest", "--expected-source-commit", "a".repeat(40), "--max-age-minutes", "60"],
	]) {
		const result = await command([action[0], "--target", f.target, "--output", output, "--key-file", f.keyFile, ...action.slice(1)], 1);
		assert.match(result.stderr, /output must not already exist/i);
		assert.equal(await readFile(join(output, "keep.txt"), "utf8"), "user-owned");
	}
	assert.deepEqual((await readdir(f.root)).filter((name) => name.startsWith("owned-output.candidate-")), []);
});

test("forged commit freshness cannot publish RPO health", async (t) => {
	const f = await fixture(t);
	await command([
		"upload", "--backup", f.backup, "--target", f.target,
		"--key-file", f.keyFile, "--key-reference", "hsm://aidr/recovery", "--retention-days", "30",
	]);
	const commitPath = join(f.target, f.backupId, "COMMITTED.json");
	const commit = JSON.parse(await readFile(commitPath, "utf8"));
	commit.completed_at = new Date().toISOString();
	await writeFile(commitPath, JSON.stringify(commit));
	const result = await command([
		"verify", "--backup-id", f.backupId, "--target", f.target,
		"--key-file", f.keyFile, "--health-file", f.health,
	], 1);
	assert.match(result.stderr, /does not match the authenticated backup manifest/);
	assert.equal(JSON.parse(await readFile(f.health, "utf8")).status, "failed");
});

test("abandoned spool cleanup is age-bounded and ignores operator files", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-spool-cleanup-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const oldBackup = join(root, "2026-09-10T02-15-00-000Z-0123456789");
	const freshBackup = join(root, "2026-09-12T02-15-00-000Z-abcdef0123");
	const operatorDirectory = join(root, "keep-me");
	const matchingUnowned = join(root, "2026-09-10T02-15-00-000Z-9876543210");
	const completedBackup = join(root, "2026-09-10T02-15-00-000Z-1111111111");
	await Promise.all([mkdir(oldBackup), mkdir(freshBackup), mkdir(operatorDirectory), mkdir(matchingUnowned), mkdir(completedBackup)]);
	await writeFile(join(completedBackup, "backup.json"), "completed snapshot awaiting upload");
	await writeFile(`${completedBackup}.aidr-owned`, "AIDR temporary backup v1\n");
	await utimes(completedBackup, new Date("2026-09-10T00:00:00Z"), new Date("2026-09-10T00:00:00Z"));
	await utimes(`${completedBackup}.aidr-owned`, new Date("2026-09-10T00:00:00Z"), new Date("2026-09-10T00:00:00Z"));
	await writeFile(`${oldBackup}.aidr-owned`, "AIDR temporary backup v1\n");
	await utimes(oldBackup, new Date("2026-09-10T00:00:00Z"), new Date("2026-09-10T00:00:00Z"));
	await utimes(`${oldBackup}.aidr-owned`, new Date("2026-09-10T00:00:00Z"), new Date("2026-09-10T00:00:00Z"));
	await utimes(freshBackup, new Date("2026-09-12T12:00:00Z"), new Date("2026-09-12T12:00:00Z"));
	await utimes(matchingUnowned, new Date("2026-09-10T00:00:00Z"), new Date("2026-09-10T00:00:00Z"));
	assert.equal(await cleanupAbandonedSpool(root, Date.parse("2026-09-12T13:00:00Z")), 1);
	await assert.rejects(stat(oldBackup), /ENOENT/);
	assert.equal((await stat(freshBackup)).isDirectory(), true);
	assert.equal((await stat(operatorDirectory)).isDirectory(), true);
	assert.equal((await stat(matchingUnowned)).isDirectory(), true);
	assert.equal((await stat(completedBackup)).isDirectory(), true, "a completed snapshot must survive temporary spool retention until remote verification succeeds");
});

test("scheduled cycle retains completed snapshots on remote failure and removes only verified owned output", async (t) => {
	for (const scenario of ["upload-failure", "verify-failure", "verified", "replacement-output"]) {
		await t.test(scenario, async (t) => {
			const f = await fixture(t);
			const deployment = join(f.root, "deployment");
			const spool = join(f.root, "spool");
			const outputFile = join(f.root, "cycle-output.txt");
			await mkdir(deployment);
			const preload = join(f.root, "fake-cold-backup.cjs");
			await writeFile(preload, `
const { basename, join } = require("node:path");
const { copyFileSync, mkdirSync, writeFileSync } = require("node:fs");
if (basename(process.argv[1] || "") === "deployment-backup.mjs" && process.argv[2] === "backup") {
  const output = process.argv[process.argv.indexOf("--output") + 1];
  mkdirSync(output, { mode: 0o700 });
  for (const name of ["backup.json", "database.tar.gz.enc", "storage.tar.gz.enc", "installation.tar.gz.enc"]) copyFileSync(join(process.env.AIDR_TEST_COLD_SOURCE, name), join(output, name));
  writeFileSync(process.env.AIDR_TEST_CYCLE_OUTPUT_FILE, output);
  process.exit(0);
}
`);
			const env = {
				NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ""} --require "${preload.replaceAll("\\", "/")}"`.trim(),
				AIDR_TEST_COLD_SOURCE: f.backup,
				AIDR_TEST_CYCLE_OUTPUT_FILE: outputFile,
				...(scenario === "upload-failure" ? { AIDR_TEST_MOUNT_FAIL_AFTER_TARGET_CHECKS: "3" } : {}),
				...(scenario === "verify-failure" ? { AIDR_TEST_MOUNT_FAIL_AFTER_TARGET_CHECKS: "6" } : {}),
				...(scenario === "replacement-output" ? { AIDR_TEST_SWAP_CYCLE_ON_CHECK: "6" } : {}),
			};
			await command([
				"cycle", "--deployment", deployment, "--spool", spool, "--target", f.target, "--key-file", f.keyFile,
				"--key-reference", "vault://production/aidr-recovery-key", "--retention-days", "35", "--health-file", f.health,
			], scenario === "verified" ? 0 : 1, env);
			const output = await readFile(outputFile, "utf8");
			if (scenario === "verified") {
				await assert.rejects(stat(output), /ENOENT/);
				await assert.rejects(stat(`${output}.aidr-owned`), /ENOENT/);
			} else if (scenario === "replacement-output") {
				assert.equal(await readFile(join(output, "keep.txt"), "utf8"), "operator-owned");
				assert.equal(await readFile(join(`${output}.original`, "backup.json"), "utf8"), await readFile(join(f.backup, "backup.json"), "utf8"));
			} else {
				assert.equal(await readFile(join(output, "backup.json"), "utf8"), await readFile(join(f.backup, "backup.json"), "utf8"));
				assert.equal((await stat(`${output}.aidr-owned`)).isFile(), true);
			}
			assert.equal(JSON.parse(await readFile(f.health, "utf8")).status, scenario === "verified" ? "ok" : "failed");
		});
	}
});

test("scheduled cold backup places its recovery journal in the private spool", async () => {
	const source = await readFile(SCRIPT, "utf8");
	const service = await readFile(resolve("deploy/backup/aidr-backup-offsite.service"), "utf8");
	assert.match(source, /"--recovery-journal", join\(spool, "recovery-journal\.json"\)/);
	assert.match(service, /--spool \/var\/lib\/aidr-backup/);
});

test("retention is dry-run by default, scoped, and apply is idempotent", async (t) => {
	const f = await fixture(t, "2024-01-01T00:00:00Z");
	await command([
		"upload", "--backup", f.backup, "--target", f.target,
		"--key-file", f.keyFile, "--key-reference", "vault://aidr/recovery", "--retention-days", "30",
	]);
	const protectedRun = JSON.parse((await command(["prune", "--target", f.target, "--retention-days", "30"])).stdout);
	assert.deepEqual(protectedRun.candidates, [], "recorded retention deadline is enforced even for an old snapshot");
	const commitPath = join(f.target, f.backupId, "COMMITTED.json");
	const commit = JSON.parse(await readFile(commitPath, "utf8"));
	commit.retention.retain_until = "2024-02-01T00:00:00Z";
	await writeFile(commitPath, JSON.stringify(commit));
	const dry = JSON.parse((await command(["prune", "--target", f.target, "--retention-days", "30"])).stdout);
	assert.equal(dry.apply, false);
	assert.deepEqual(dry.candidates, [f.backupId]);
	assert.equal((await stat(join(f.target, f.backupId))).isDirectory(), true);
	const foreign = join(f.target, f.backupId, "operator-note");
	await writeFile(foreign, "not in committed inventory");
	const rejected = await command(["prune", "--target", f.target, "--retention-days", "30", "--apply"], 1);
	assert.match(rejected.stderr, /refused an unlisted or non-regular backup entry/);
	assert.equal(await readFile(foreign, "utf8"), "not in committed inventory");
	assert.equal((await stat(commitPath)).isFile(), true);
	await rm(foreign);
	const applied = JSON.parse((await command(["prune", "--target", f.target, "--retention-days", "30", "--apply"])).stdout);
	assert.deepEqual(applied.fully_removed, [f.backupId]);
	assert.deepEqual(applied.retained, []);
	await assert.rejects(stat(join(f.target, f.backupId)), /ENOENT/);
	const repeated = JSON.parse((await command(["prune", "--target", f.target, "--retention-days", "30", "--apply"])).stdout);
	assert.deepEqual(repeated.fully_removed, []);
	assert.deepEqual(repeated.candidates, []);
});

test("S3-compatible transport stages, promotes, locks, and downloads before readiness", async (t) => {
	const f = await fixture(t);
	const store = join(f.root, "fake-s3");
	const providerLog = join(f.root, "provider.log");
	const fake = await fakeAws(f.root);
	const foreignStaging = join(store, "company-backups", "aidr", "production", ".staging", "0".repeat(64), "1".repeat(16), "orphan.enc");
	const unverifiedStaging = join(store, "company-backups", "aidr", "production", ".staging", "2".repeat(64), "3".repeat(16), "database.tar.gz.enc");
	for (const path of [foreignStaging, unverifiedStaging]) {
		await mkdir(join(path, ".."), { recursive: true });
		await writeFile(path, "operator-owned");
		await utimes(path, new Date("2020-01-01T00:00:00Z"), new Date("2020-01-01T00:00:00Z"));
	}
	const previous = process.env.FAKE_S3_ROOT;
	const previousLog = process.env.FAKE_AWS_LOG;
	process.env.FAKE_S3_ROOT = store;
	process.env.FAKE_AWS_LOG = providerLog;
	t.after(() => {
		if (previous === undefined) delete process.env.FAKE_S3_ROOT;
		else process.env.FAKE_S3_ROOT = previous;
		if (previousLog === undefined) delete process.env.FAKE_AWS_LOG;
		else process.env.FAKE_AWS_LOG = previousLog;
	});
	const cli = ["--aws-cli", process.execPath, "--aws-cli-argument", fake];
	const uploadArgs = [
		"upload", "--backup", f.backup, "--target", "s3://company-backups/aidr/production",
		"--key-file", f.keyFile, "--key-reference", "hsm://aidr/recovery", "--retention-days", "35",
		"--object-lock-mode", "COMPLIANCE", "--health-file", f.health, ...cli,
	];
	const result = JSON.parse((await command(uploadArgs)).stdout);
	assert.equal(result.backup_id, f.backupId);
	for (const path of [foreignStaging, unverifiedStaging]) assert.equal(await readFile(path, "utf8"), "operator-owned", "ordinary upload must not prune old staging");
	const repeated = JSON.parse((await command([...uploadArgs, "--apply"])).stdout);
	assert.equal(repeated.backup_id, f.backupId);
	assert.equal(repeated.verified, true);
	for (const path of [foreignStaging, unverifiedStaging]) assert.equal(await readFile(path, "utf8"), "operator-owned", "upload --apply must not delete unverified staging");
	assert.equal((await stat(join(store, "company-backups", "aidr", "production", f.backupId, "COMMITTED.json"))).isFile(), true);
	const metadata = JSON.parse(await readFile(join(store, "company-backups", "aidr", "production", f.backupId, "COMMITTED.json.fake-meta"), "utf8"));
	assert.equal(metadata.Retention.Mode, "COMPLIANCE");
	assert.ok(Date.parse(metadata.Retention.RetainUntilDate) > Date.now());
	const health = JSON.parse(await readFile(f.health, "utf8"));
	assert.equal(health.status, "ok");
	const output = join(f.root, "s3-download");
	await command([
		"download", "--backup-id", f.backupId, "--target", "s3://company-backups/aidr/production",
		"--key-file", f.keyFile, "--output", output, ...cli,
	]);
	assert.equal(await readFile(join(output, "backup.json"), "hex"), await readFile(join(f.backup, "backup.json"), "hex"));
	const providerCommands = await readFile(providerLog, "utf8");
	assert.doesNotMatch(providerCommands, /s3api list-object-versions/, "upload does not enumerate old staging for deletion");
	assert.match(providerCommands, /s3api delete-object .*\.staging\//, "only this run's known temporary keys are cleaned");
	assert.match(providerCommands, /s3api get-object-retention/);
});

test("S3 Object Lock rejects missing, malformed and non-finite retention deadlines", async (t) => {
	for (const deadline of ["missing", "not-a-date", "2026-09-23T25:00:00Z"]) {
		const f = await fixture(t);
		const store = join(f.root, "fake-s3");
		const fake = await fakeAws(f.root);
		const result = await command([
			"upload", "--backup", f.backup, "--target", "s3://company-backups/aidr/production",
			"--key-file", f.keyFile, "--key-reference", "hsm://aidr/recovery", "--retention-days", "35",
			"--object-lock-mode", "COMPLIANCE", "--health-file", f.health,
			"--aws-cli", process.execPath, "--aws-cli-argument", fake,
		], 1, { FAKE_S3_ROOT: store, FAKE_S3_RETENTION_DATE: deadline });
		assert.match(result.stderr, /S3 Object Lock retention verification failed/);
		assert.equal(JSON.parse(await readFile(f.health, "utf8")).status, "failed");
		await assert.rejects(stat(join(store, "company-backups", "aidr", "production", f.backupId, "COMMITTED.json")), /ENOENT/);
	}
});

test("S3 commit lookup failure stops publication", async (t) => {
	const f = await fixture(t);
	const store = join(f.root, "fake-s3");
	const fake = await fakeAws(f.root);
	const result = await command([
		"upload", "--backup", f.backup, "--target", "s3://company-backups/aidr/production",
		"--key-file", f.keyFile, "--key-reference", "hsm://aidr/recovery", "--retention-days", "35",
		"--aws-cli", process.execPath, "--aws-cli-argument", fake,
	], 1, { FAKE_S3_ROOT: store, FAKE_S3_DENY_LIST: "1" });
	assert.match(result.stderr, /operation failed/);
	await assert.rejects(stat(join(store, "company-backups")), /ENOENT/);
});

test("S3 prune reports legal-hold retention and deletes eligible version IDs", async (t) => {
	const f = await fixture(t, "2024-01-01T00:00:00Z");
	const store = join(f.root, "fake-s3-prune");
	const providerLog = join(f.root, "prune-provider.log");
	const fake = await fakeAws(f.root);
	const cli = ["--aws-cli", process.execPath, "--aws-cli-argument", fake];
	const environment = { FAKE_S3_ROOT: store, FAKE_AWS_LOG: providerLog };
	await command([
		"upload", "--backup", f.backup, "--target", "s3://company-backups/aidr/production",
		"--key-file", f.keyFile, "--key-reference", "hsm://aidr/recovery", "--retention-days", "30", ...cli,
	], 0, environment);
	const marker = join(store, "company-backups", "aidr", "production", f.backupId, "COMMITTED.json");
	const commit = JSON.parse(await readFile(marker, "utf8"));
	commit.retention.retain_until = "2024-02-01T00:00:00Z";
	await writeFile(marker, JSON.stringify(commit));
	const foreign = join(store, "company-backups", "aidr", "production", f.backupId, "operator-note");
	await writeFile(foreign, "not in committed inventory");
	const unlisted = await command([
		"prune", "--target", "s3://company-backups/aidr/production", "--retention-days", "30", "--apply", ...cli,
	], 1, environment);
	assert.match(unlisted.stderr, /refused an unlisted object version/);
	assert.equal((await stat(foreign)).isFile(), true);
	assert.equal((await stat(marker)).isFile(), true);
	await rm(foreign);
	const held = JSON.parse((await command([
		"prune", "--target", "s3://company-backups/aidr/production", "--retention-days", "30", "--apply", ...cli,
	], 0, { ...environment, FAKE_S3_LEGAL_HOLD: "1" })).stdout);
	assert.deepEqual(held.fully_removed, []);
	assert.deepEqual(held.retained, [{ backup_id: f.backupId, reasons: ["legal-hold"] }]);
	const ignoredDelete = await command([
		"prune", "--target", "s3://company-backups/aidr/production", "--retention-days", "30", "--apply", ...cli,
	], 1, { ...environment, FAKE_S3_IGNORE_DELETE_KEY: "database.tar.gz.enc" });
	assert.match(ignoredDelete.stderr, /could not verify removal of every object version/);
	assert.equal((await stat(marker)).isFile(), true, "ignored payload deletion must not remove the commit marker");
	const interruptedDelete = await command([
		"prune", "--target", "s3://company-backups/aidr/production", "--retention-days", "30", "--apply", ...cli,
	], 1, { ...environment, FAKE_S3_FAIL_DELETE_KEY: "database.tar.gz.enc" });
	assert.match(interruptedDelete.stderr, /operation failed/);
	assert.equal((await stat(marker)).isFile(), true, "a partial prune must remain discoverable for retry");
	const removed = JSON.parse((await command([
		"prune", "--target", "s3://company-backups/aidr/production", "--retention-days", "30", "--apply", ...cli,
	], 0, environment)).stdout);
	assert.deepEqual(removed.fully_removed, [f.backupId]);
	assert.ok(removed.versions_deleted >= 1);
	await assert.rejects(stat(marker), /ENOENT/);
	const providerCommands = await readFile(providerLog, "utf8");
	assert.match(providerCommands, /s3api list-object-versions/);
	assert.match(providerCommands, /s3api head-object .*--version-id v1/);
	assert.match(providerCommands, /s3api delete-object .*--version-id v1/);
});

test("target and custody validation reject broad or secret-bearing configuration", () => {
	assert.throws(() => parseTarget("s3://bucket"), /scoped prefix/);
	assert.throws(() => parseTarget("s3://bucket/../"), /scoped prefix/);
	assert.throws(() => parseTarget("relative/backups"), /absolute path/);
	assert.equal(parseTarget("s3://company-backups/aidr/production").kind, "s3");
});

test("filesystem mount identity must match a separate non-root filesystem", async () => {
	const targetRoot = resolve("test-offsite");
	const offsiteMount = { target: targetRoot, uuid: "offsite-uuid", source: "/dev/offsite", fstype: "ext4" };
	const hostRootMount = { target: sep, uuid: "root-uuid", source: "/dev/root", fstype: "ext4" };
	const probe = async (path) => path === sep ? hostRootMount : offsiteMount;
	await assert.doesNotReject(verifyFilesystemMountIdentity(targetRoot, "UUID=OFFSITE-UUID", probe));
	await assert.doesNotReject(verifyFilesystemMountIdentity(targetRoot, "SOURCE=/dev/offsite", probe));
	await assert.rejects(verifyFilesystemMountIdentity(targetRoot, "UUID=wrong-uuid", probe), /does not match/);
	await assert.rejects(verifyFilesystemMountIdentity(targetRoot, "", probe), /require AIDR_BACKUP_FILESYSTEM_MOUNT_IDENTITY/);
	await assert.rejects(verifyFilesystemMountIdentity(targetRoot, "UUID=root-uuid", async (path) =>
		path === sep ? hostRootMount : { ...offsiteMount, uuid: "root-uuid" }), /shares the host root filesystem failure domain/);
	await assert.rejects(verifyFilesystemMountIdentity(targetRoot, "UUID=offsite-uuid", async () =>
		({ target: resolve(targetRoot, sep), uuid: "offsite-uuid", source: "/dev/offsite", fstype: "ext4" })), /host root filesystem/);
});

test("filesystem upload fails closed on a wrong mount identity without publishing", async (t) => {
	const f = await fixture(t);
	const result = await command([
		"upload", "--backup", f.backup, "--target", f.target, "--key-file", f.keyFile,
		"--key-reference", "vault://production/aidr-recovery-key", "--retention-days", "35",
	], 1, { AIDR_BACKUP_FILESYSTEM_MOUNT_IDENTITY: "UUID=wrong-uuid" });
	assert.match(result.stderr, /does not match the configured offsite identity/);
	await assert.rejects(stat(join(f.target, "1".repeat(64))), /ENOENT/);
});

test("filesystem upload never creates a missing configured target", async (t) => {
	const f = await fixture(t);
	await rm(f.target, { recursive: true });
	const result = await command([
		"upload", "--backup", f.backup, "--target", f.target, "--key-file", f.keyFile,
		"--key-reference", "vault://production/aidr-recovery-key", "--retention-days", "35",
	], 1);
	assert.match(result.stderr, /must already exist/);
	await assert.rejects(stat(f.target), /ENOENT/);
});

test("mount loss during remote verification cannot publish healthy backup readiness", async (t) => {
	const f = await fixture(t);
	const result = await command([
		"upload", "--backup", f.backup, "--target", f.target, "--key-file", f.keyFile,
		"--key-reference", "vault://production/aidr-recovery-key", "--retention-days", "35", "--health-file", f.health,
	], 1, { AIDR_TEST_MOUNT_FAIL_AFTER_TARGET_CHECKS: "6" });
	assert.match(result.stderr, /does not match the configured offsite identity/);
	assert.equal(JSON.parse(await readFile(f.health, "utf8")).status, "failed");
	assert.equal((await stat(join(f.target, f.backupId, "COMMITTED.json"))).isFile(), true);
});

test("invalid target and missing key invalidate prior healthy readiness", async (t) => {
	const f = await fixture(t);
	await mkdir(join(f.root, "health"));
	for (const args of [
		["upload", "--backup", f.backup, "--target", "relative-target", "--key-file", f.keyFile],
		["upload", "--backup", f.backup, "--target", f.target, "--key-file", join(f.root, "missing.key")],
	]) {
		await writeFile(f.health, JSON.stringify({ schema_version: 1, status: "ok", completed_at: "2026-09-12T08:00:00Z", verified_at: "2026-09-12T08:00:01Z" }));
		await command([...args, "--health-file", f.health], 1);
		assert.equal(JSON.parse(await readFile(f.health, "utf8")).status, "failed");
	}
});

test("relative health path is rejected without deleting a cwd file", async (t) => {
	const f = await fixture(t);
	const sentinel = join(f.root, "sentinel.json");
	await writeFile(sentinel, "operator-owned");
	await command([
		"upload", "--backup", f.backup, "--target", f.target, "--key-file", f.keyFile,
		"--key-reference", "vault://aidr/recovery", "--retention-days", "30", "--health-file", "sentinel.json",
	], 1, {}, f.root);
	assert.equal(await readFile(sentinel, "utf8"), "operator-owned");
});
