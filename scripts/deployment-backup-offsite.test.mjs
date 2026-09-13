import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, hkdfSync } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { parseTarget } from "./deployment-backup-offsite.mjs";

const SCRIPT = resolve("scripts/deployment-backup-offsite.mjs");
const FILES = ["database.tar.gz.enc", "storage.tar.gz.enc", "installation.tar.gz.enc"];

function digest(buffer) {
	return createHash("sha256").update(buffer).digest("hex");
}

async function fixture(t, completedAt = "2026-09-12T08:00:00Z") {
	const root = await mkdtemp(join(tmpdir(), "aidr-offsite-test-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const backup = join(root, "source");
	const target = join(root, "offsite");
	const keyFile = join(root, "custody", "recovery.key");
	const health = join(root, "health", "backup.json");
	await Promise.all([mkdir(backup), mkdir(join(root, "custody"))]);
	const rawKey = Buffer.from("ab".repeat(32), "hex");
	await writeFile(keyFile, `${rawKey.toString("hex")}\n`, { mode: 0o600 });
	const encKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "encryption", 32));
	const macKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "manifest", 32));
	const entries = [];
	for (const [index, name] of FILES.entries()) {
		const iv = Buffer.alloc(12, index + 1);
		const cipher = createCipheriv("aes-256-gcm", encKey, iv);
		cipher.setAAD(Buffer.from(name));
		const encrypted = Buffer.concat([cipher.update(Buffer.from(`fixture-${name}`)), cipher.final()]);
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
		started_at: completedAt,
		completed_at: completedAt,
		source_project: "offsite-test",
		source_commit: "test",
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

async function command(args, expectedCode = 0, extraEnv = {}) {
	const result = await new Promise((done, fail) => {
		const child = spawn(process.execPath, [SCRIPT, ...args], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, env: { ...process.env, ...extraEnv } });
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
import { copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
const store = process.env.FAKE_S3_ROOT;
const args = process.argv.slice(2);
const serviceIndex = args.findIndex((value) => value === "s3" || value === "s3api");
if (serviceIndex < 0) process.exit(70);
const service = args[serviceIndex];
const command = args[serviceIndex + 1];
if (command === "list-objects-v2" && process.env.FAKE_S3_DENY_LIST === "1") process.exit(73);
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
const loadMeta = async (path) => JSON.parse(await readFile(metaPath(path), "utf8"));
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
  const stored = await loadMeta(current.path); output({ ContentLength: (await stat(current.path)).size, Metadata: stored.Metadata });
} else if (command === "get-object") {
  const destination = rest[rest.indexOf("--key") + 2];
  await mkdir(dirname(destination), { recursive: true }); await copyFile(current.path, destination); output({});
} else if (command === "delete-object") {
  await rm(current.path, { force: true }); await rm(metaPath(current.path), { force: true }); output({});
} else if (command === "put-object-retention") {
  const stored = await loadMeta(current.path); stored.Retention = metadata(value("--retention")); await saveMeta(current.path, stored); output({});
} else if (command === "get-object-retention") {
  const stored = await loadMeta(current.path); output({ Retention: stored.Retention });
} else if (command === "list-objects-v2") {
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
  output({ IsTruncated: false, Contents: keys.filter((key) => key.startsWith(prefix)).map((Key) => ({ Key })) });
} else process.exit(72);
`);
	return script;
}

test("filesystem target publishes, verifies, downloads, and is idempotent", async (t) => {
	const f = await fixture(t);
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
	const commit = JSON.parse(await readFile(join(f.target, f.backupId, "COMMITTED.json"), "utf8"));
	assert.equal(commit.backup_id, f.backupId);
	assert.equal(commit.key_reference, "vault://production/aidr-recovery-key");
	assert.equal(commit.retention.days, 35);
	assert.equal(commit.retention.mode, "METADATA_ONLY");
	assert.deepEqual(commit.objects.map((entry) => entry.name).sort(), ["backup.json", ...FILES].sort());
	assert.equal(JSON.stringify(commit).includes("ab".repeat(32)), false);

	const health = JSON.parse(await readFile(f.health, "utf8"));
	assert.deepEqual(Object.keys(health), ["schema_version", "status", "completed_at", "verified_at"]);
	assert.equal(health.schema_version, 1);
	assert.equal(health.status, "ok");
	assert.equal(health.completed_at, "2026-09-12T08:00:00Z");
	assert.ok(Number.isFinite(Date.parse(health.verified_at)));

	const second = JSON.parse((await command(uploadArgs)).stdout);
	assert.equal(second.backup_id, first.backup_id);
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
	await assert.rejects(stat(health), /ENOENT/);
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
	await assert.rejects(stat(f.health), /ENOENT/);
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
	const applied = JSON.parse((await command(["prune", "--target", f.target, "--retention-days", "30", "--apply"])).stdout);
	assert.equal(applied.deleted, 1);
	await assert.rejects(stat(join(f.target, f.backupId)), /ENOENT/);
	const repeated = JSON.parse((await command(["prune", "--target", f.target, "--retention-days", "30", "--apply"])).stdout);
	assert.equal(repeated.deleted, 0);
	assert.deepEqual(repeated.candidates, []);
});

test("S3-compatible transport stages, promotes, locks, and downloads before readiness", async (t) => {
	const f = await fixture(t);
	const store = join(f.root, "fake-s3");
	const fake = await fakeAws(f.root);
	const previous = process.env.FAKE_S3_ROOT;
	process.env.FAKE_S3_ROOT = store;
	t.after(() => {
		if (previous === undefined) delete process.env.FAKE_S3_ROOT;
		else process.env.FAKE_S3_ROOT = previous;
	});
	const cli = ["--aws-cli", process.execPath, "--aws-cli-argument", fake];
	const uploadArgs = [
		"upload", "--backup", f.backup, "--target", "s3://company-backups/aidr/production",
		"--key-file", f.keyFile, "--key-reference", "hsm://aidr/recovery", "--retention-days", "35",
		"--object-lock-mode", "COMPLIANCE", "--health-file", f.health, ...cli,
	];
	const result = JSON.parse((await command(uploadArgs)).stdout);
	assert.equal(result.backup_id, f.backupId);
	const repeated = JSON.parse((await command(uploadArgs)).stdout);
	assert.equal(repeated.backup_id, f.backupId);
	assert.equal(repeated.verified, true);
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

test("target and custody validation reject broad or secret-bearing configuration", () => {
	assert.throws(() => parseTarget("s3://bucket"), /scoped prefix/);
	assert.throws(() => parseTarget("s3://bucket/../"), /scoped prefix/);
	assert.throws(() => parseTarget("relative/backups"), /absolute path/);
	assert.equal(parseTarget("s3://company-backups/aidr/production").kind, "s3");
});
