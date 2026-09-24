import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { delimiter, join, resolve } from "node:path";
import { chmod, copyFile, link, mkdtemp, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import test from "node:test";
import { assertRecoveryKeyFileAcl, hardenRecoveryKeyFile } from "./deployment-restore-drill.mjs";

const SCRIPT = resolve("scripts/deployment-backup.mjs");
const SERVICE = resolve("deploy/backup/aidr-backup-offsite.service");
const TIMER = resolve("deploy/backup/aidr-backup-offsite.timer");
const FAILURE_SERVICE = resolve("deploy/backup/aidr-backup-health-failed.service");
const FAILURE_SCRIPT = resolve("deploy/backup/deployment-backup-health-failed.mjs");
const MAINTENANCE_INSTALLER = resolve("deploy/maintenance/install-systemd.sh");
const BACKUP_ENV = resolve("deploy/backup/aidr-backup-offsite.env.example");
const BACKUP_README = resolve("deploy/backup/README.md");
const FIRST_CUSTOMER_GUIDE = resolve("deploy/FIRST_CUSTOMER.md");
const UPGRADE_GUIDE = resolve("deploy/UPGRADE.md");

async function command(root, env = {}) {
	const deployment = join(root, "deployment");
	const output = join(root, "backup");
	const key = join(root, "recovery.key");
	const journal = join(root, "state", "recovery-journal.json");
	await mkdir(deployment);
	await mkdir(join(root, "state"), { mode: 0o700 });
	for (const directory of ["auth-templates", "backup", "dashboard", "health", "ingress", "maintenance", "migrations", "volumes/functions"]) await mkdir(join(deployment, directory), { recursive: true });
	const files = {
		".env": "POSTGRES_PASSWORD=fixture\n",
		".env.functions": "AIDR_FIXTURE=true\n",
		".env.ingress": "AIDR_INGRESS_FIXTURE=true\n",
		".env.readiness": "AIDR_HEALTH_STATE_DIR=/srv/aidr/health\n",
		"agent-config.json": "{}\n",
		"compose.yml": "services:\n  db: {}\n  storage: {}\n  api: {}\n",
		"auth-templates/recovery.html": "safe\n",
		"backup/timer.service": "safe\n",
		"dashboard/index.html": "safe\n",
		"ingress/proxy.conf": "safe\n",
		"maintenance/readiness.service": "safe\n",
		"migrations/20260922000000_fixture.sql": "select 1;\n",
		"volumes/functions/index.ts": "safe\n",
	};
	for (const [name, content] of Object.entries(files)) await writeFile(join(deployment, name), content);
	const sha256 = (name) => createHash("sha256").update(files[name]).digest("hex");
	await writeFile(join(deployment, "deployment.json"), JSON.stringify({
		schema_version: 1, mode: "self-hosted", project_name: "test", source_commit: "a".repeat(40), source_has_changes: false,
		migrations: [{ name: "20260922000000_fixture.sql", sha256: sha256("migrations/20260922000000_fixture.sql") }],
		artifacts: ["auth-templates/recovery.html", "backup/timer.service", "dashboard/index.html", "ingress/proxy.conf", "maintenance/readiness.service", "volumes/functions/index.ts"].map((path) => ({ path, sha256: sha256(path) })),
	}));
	await writeFile(key, `${"ab".repeat(32)}\n`);
	await hardenRecoveryKeyFile(key);
	const fake = await fakeCommands(root);
	const state = join(root, "docker.state");
	const log = join(root, "docker.log");
	const child = spawn(process.execPath, [SCRIPT, "backup", "--deployment", deployment, "--output", output, "--key-file", key, "--recovery-journal", journal, "--maintenance"], {
		env: { ...process.env, PATH: `${fake.bin}${delimiter}${process.env.PATH}`, ...(fake.nodeOptions ? { NODE_OPTIONS: fake.nodeOptions } : {}), FAKE_DOCKER_LOG: log, FAKE_DOCKER_STATE: state, ...env },
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
	});
	let stderr = "";
	child.stderr.setEncoding("utf8");
	child.stderr.on("data", (chunk) => { stderr += chunk; });
	return { child, output, deployment, journal, key, state, fake, stderr: () => stderr, log };
}

function recoveryCommand(run) {
	return spawn(process.execPath, [SCRIPT, "recover-services", "--deployment", run.deployment, "--recovery-journal", run.journal], {
		env: { ...process.env, PATH: `${run.fake.bin}${delimiter}${process.env.PATH}`, ...(run.fake.nodeOptions ? { NODE_OPTIONS: run.fake.nodeOptions } : {}), FAKE_DOCKER_LOG: run.log, FAKE_DOCKER_STATE: run.state },
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
	});
}

async function fakeCommands(root) {
	const bin = join(root, "bin");
	await mkdir(bin);
	const dockerScript = join(bin, "fake-docker.mjs");
	const tarScript = join(bin, "fake-tar.mjs");
	await writeFile(dockerScript, `
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
const args = process.argv.slice(2);
await appendFile(process.env.FAKE_DOCKER_LOG, args.join(" ") + "\\n");
const state = async () => { try { return new Set((await readFile(process.env.FAKE_DOCKER_STATE, "utf8")).trim().split(",").filter(Boolean)); } catch { return new Set((process.env.FAKE_DOCKER_INITIAL_RUNNING || "db,storage,api").split(",").filter(Boolean)); } };
const has = (value) => args.includes(value);
const save = async (services) => writeFile(process.env.FAKE_DOCKER_STATE, [...services].sort().join(","));
if (args[0] === "image" || args[0] === "info" || has("pg_isready")) {
  if (args[0] === "info") process.stdout.write("x86_64\\n");
  process.exit(0);
}
if (has("ps") && has("--all") && has("--quiet")) {
  process.stdout.write(args.at(-1) === "db" ? "db-id\\n" : "storage-id\\n"); process.exit(0);
}
if (args[0] === "inspect") {
  const db = args[1] === "db-id";
  process.stdout.write(JSON.stringify([{ Mounts: [{ Destination: db ? "/var/lib/postgresql/data" : "/var/lib/storage", Type: "volume", Name: db ? "db-volume" : "storage-volume" }], Config: { Image: "postgres:test" } }]));
  process.exit(0);
}
if (has("config") && has("--services")) { process.stdout.write("db\\nstorage\\napi\\n"); process.exit(0); }
if (has("ps") && has("--services") && has("running")) {
  const services = await state();
  if (services.size) process.stdout.write([...services].sort().join("\\n") + "\\n");
  process.exit(0);
}
if (has("stop")) {
  const services = await state();
  for (const service of args.slice(args.indexOf("--timeout") + 2)) services.delete(service);
  await save(services);
  if (process.env.FAKE_HARD_CRASH_AFTER_STOP === "1") {
    if (process.platform === "win32") spawnSync("taskkill", ["/PID", String(process.ppid), "/F"], { stdio: "ignore" });
    else process.kill(process.ppid, "SIGKILL");
  }
  process.exit(0);
}
if (has("start")) { const services = await state(); for (const service of args.slice(args.indexOf("start") + 1)) services.add(service); await save(services); process.exit(0); }
if (args[0] === "run" && has("pg_controldata")) {
  if (process.env.FAKE_FAIL_AFTER_STOP === "1") process.exit(70);
  if (process.env.FAKE_BEFORE_ARCHIVE_MARKER) await writeFile(process.env.FAKE_BEFORE_ARCHIVE_MARKER, "ready");
  const preArchiveDelay = Number(process.env.FAKE_PRE_ARCHIVE_DELAY_MS || 0);
  if (preArchiveDelay) await new Promise((done) => setTimeout(done, preArchiveDelay));
  process.stdout.write("Database cluster state: shut down\\n"); process.exit(0);
}
if (args[0] === "run") {
  if (process.env.FAKE_ARCHIVE_MARKER) await writeFile(process.env.FAKE_ARCHIVE_MARKER, "started");
  const delay = Number(process.env.FAKE_ARCHIVE_DELAY_MS || 0);
  if (delay) await new Promise((done) => setTimeout(done, delay));
  process.stdout.write("archive"); process.exit(0);
}
process.exit(71);
`);
	await writeFile(tarScript, `if (process.argv.includes("--version")) process.stdout.write("tar test\\n"); else process.stdout.write("archive");`);
	if (platform() === "win32") {
		const preload = join(bin, "fake-cli.cjs");
		await writeFile(preload, `
const { appendFileSync, readFileSync, writeFileSync } = require("node:fs");
const { basename } = require("node:path");
const { spawnSync } = require("node:child_process");
const kind = basename(process.execPath).toLowerCase();
if (kind === "tar.exe") {
  if (process.argv.includes("--version")) process.stdout.write("tar test\\n"); else process.stdout.write("archive");
  process.exit(0);
}
if (kind !== "docker.exe") return;
const args = process.argv.slice(1); args[0] = basename(args[0]);
appendFileSync(process.env.FAKE_DOCKER_LOG, args.join(" ") + "\\n");
const state = () => { try { return new Set(readFileSync(process.env.FAKE_DOCKER_STATE, "utf8").trim().split(",").filter(Boolean)); } catch { return new Set((process.env.FAKE_DOCKER_INITIAL_RUNNING || "db,storage,api").split(",").filter(Boolean)); } };
const save = (services) => writeFileSync(process.env.FAKE_DOCKER_STATE, [...services].sort().join(","));
const has = (value) => args.includes(value);
if (args[0] === "image" || args[0] === "info" || has("pg_isready")) { if (args[0] === "info") process.stdout.write("x86_64\\n"); process.exit(0); }
if (has("ps") && has("--all") && has("--quiet")) { process.stdout.write(args.at(-1) === "db" ? "db-id\\n" : "storage-id\\n"); process.exit(0); }
if (args[0] === "inspect") { const db = args[1] === "db-id"; process.stdout.write(JSON.stringify([{ Mounts: [{ Destination: db ? "/var/lib/postgresql/data" : "/var/lib/storage", Type: "volume", Name: db ? "db-volume" : "storage-volume" }], Config: { Image: "postgres:test" } }])); process.exit(0); }
if (has("config") && has("--services")) { process.stdout.write("db\\nstorage\\napi\\n"); process.exit(0); }
if (has("ps") && has("--services") && has("running")) { const services = state(); if (services.size) process.stdout.write([...services].sort().join("\\n") + "\\n"); process.exit(0); }
if (has("stop")) {
  const services = state();
  for (const service of args.slice(args.indexOf("--timeout") + 2)) services.delete(service);
  save(services);
  if (process.env.FAKE_HARD_CRASH_AFTER_STOP === "1") spawnSync("taskkill", ["/PID", String(process.ppid), "/F"], { stdio: "ignore" });
  process.exit(0);
}
if (has("start")) { const services = state(); for (const service of args.slice(args.indexOf("start") + 1)) services.add(service); save(services); process.exit(0); }
if (args[0] === "run" && has("pg_controldata")) {
  if (process.env.FAKE_FAIL_AFTER_STOP === "1") process.exit(70);
  if (process.env.FAKE_BEFORE_ARCHIVE_MARKER) writeFileSync(process.env.FAKE_BEFORE_ARCHIVE_MARKER, "ready");
  setTimeout(() => { process.stdout.write("Database cluster state: shut down\\n"); process.exit(0); }, Number(process.env.FAKE_PRE_ARCHIVE_DELAY_MS || 0));
  return;
}
if (args[0] === "run") { if (process.env.FAKE_ARCHIVE_MARKER) writeFileSync(process.env.FAKE_ARCHIVE_MARKER, "started"); setTimeout(() => { process.stdout.write("archive"); process.exit(0); }, Number(process.env.FAKE_ARCHIVE_DELAY_MS || 0)); return; }
process.exit(71);
`);
		for (const name of ["docker.exe", "tar.exe"]) {
			try { await link(process.execPath, join(bin, name)); }
			catch { await copyFile(process.execPath, join(bin, name)); }
		}
		return { bin, nodeOptions: `${process.env.NODE_OPTIONS ?? ""} --require "${preload.replaceAll("\\", "/")}"`.trim() };
	} else {
		for (const [name, script] of [["docker", dockerScript], ["tar", tarScript]]) {
			const path = join(bin, name);
			await writeFile(path, `#!/bin/sh\nexec "${process.execPath}" "${script}" "$@"\n`);
			await chmod(path, 0o755);
		}
	}
	return { bin };
}

async function exit(child) {
	return new Promise((done, fail) => {
		child.once("error", fail);
		child.once("close", (code, signal) => done({ code, signal }));
	});
}

async function result(child) {
	let stdout = "";
	let stderr = "";
	child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
	child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
	return { ...(await exit(child)), stdout: () => stdout, stderr: () => stderr };
}

async function waitFor(path) {
	// The Windows fake Docker child may start slowly under parallel CI load.
	for (let attempt = 0; attempt < 400; attempt += 1) {
		try { await stat(path); return; } catch { await new Promise((done) => setTimeout(done, 25)); }
	}
	throw new Error(`Timed out waiting for ${path}`);
}

test("handled failure restarts every originally running service and removes partial output", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-backup-lifecycle-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const run = await command(root, { FAKE_FAIL_AFTER_STOP: "1" });
	const result = await exit(run.child);
	assert.notEqual(result.code, 0, run.stderr());
	const log = await readFile(run.log, "utf8").catch(() => assert.fail(`docker was not invoked\n${run.stderr()}`));
	for (const service of ["db", "storage", "api"]) assert.match(log, new RegExp(`start ${service}(?:\\r?\\n|$)`));
	await assert.rejects(stat(run.output), /ENOENT/);
});

test("boot recovery restores the exact pre-stop services after an abrupt backup interruption", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-backup-crash-recovery-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const run = await command(root, { FAKE_HARD_CRASH_AFTER_STOP: "1" });
	const interrupted = await exit(run.child);
	assert.notEqual(interrupted.code, 0, "the fixture should terminate the backup process without its finally handler");
	const journal = JSON.parse(await readFile(run.journal, "utf8"));
	assert.deepEqual(journal.services, ["api", "db", "storage"]);
	assert.equal((await readFile(run.state, "utf8")), "");
	const recovered = await result(recoveryCommand(run));
	assert.equal(recovered.code, 0, recovered.stderr());
	assert.deepEqual(JSON.parse(recovered.stdout()).recovered_services, ["api", "db", "storage"]);
	assert.equal(await readFile(run.state, "utf8"), "api,db,storage");
	await assert.rejects(stat(run.journal), /ENOENT/);
});

test("boot recovery leaves services stopped before maintenance stopped", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-backup-stopped-services-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const run = await command(root, { FAKE_DOCKER_INITIAL_RUNNING: "db,api", FAKE_HARD_CRASH_AFTER_STOP: "1" });
	const interrupted = await exit(run.child);
	assert.notEqual(interrupted.code, 0);
	const journal = JSON.parse(await readFile(run.journal, "utf8"));
	assert.deepEqual(journal.services, ["api", "db"]);
	const recovered = await result(recoveryCommand(run));
	assert.equal(recovered.code, 0, recovered.stderr());
	assert.equal(await readFile(run.state, "utf8"), "api,db");
	assert.doesNotMatch(await readFile(run.log, "utf8"), /start storage(?:\r?\n|$)/);
	await assert.rejects(stat(run.journal), /ENOENT/);
});

test("boot recovery refuses a different Compose project and retains its journal", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-backup-foreign-project-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const run = await command(root, { FAKE_HARD_CRASH_AFTER_STOP: "1" });
	const interrupted = await exit(run.child);
	assert.notEqual(interrupted.code, 0);
	const before = await readFile(run.log, "utf8");
	const originalManifest = await readFile(join(run.deployment, "deployment.json"));
	const deploymentManifest = JSON.parse(originalManifest);
	deploymentManifest.project_name = "foreign";
	await writeFile(join(run.deployment, "deployment.json"), JSON.stringify(deploymentManifest));
	const refused = await result(recoveryCommand(run));
	assert.notEqual(refused.code, 0);
	assert.match(refused.stderr(), /does not match the current deployment/);
	assert.equal(await readFile(run.log, "utf8"), before, "recovery must reject before invoking Compose");
	assert.ok((await readFile(run.journal, "utf8")).includes('"project_name":"test"'));
	assert.equal(await readFile(run.state, "utf8"), "");
});

test("backup refuses to remove a replacement output directory after path ownership changes", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-backup-output-swap-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	// Swap after the cold stop but before an archive stream opens, so Windows can
	// exercise the same identity guard without an OS-level open-file rename race.
	const marker = join(root, "backup.ready");
	const run = await command(root, { FAKE_BEFORE_ARCHIVE_MARKER: marker, FAKE_PRE_ARCHIVE_DELAY_MS: "1000" });
	await waitFor(marker);
	await rename(run.output, join(root, "original-output"));
	await mkdir(run.output);
	await writeFile(join(run.output, "keep.txt"), "user-owned");
	const result = await exit(run.child);
	assert.notEqual(result.code, 0);
	assert.match(run.stderr(), /backup output changed identity and was not removed/);
	assert.equal(await readFile(join(run.output, "keep.txt"), "utf8"), "user-owned");
	const log = await readFile(run.log, "utf8");
	for (const service of ["db", "storage", "api"]) assert.match(log, new RegExp(`start ${service}(?:\\r?\\n|$)`));
});

test("key generation protects the exact recovery key file", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-backup-keygen-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const key = join(root, "recovery.key");
	const result = spawnSync(process.execPath, [SCRIPT, "keygen", "--key-file", key], { encoding: "utf8", windowsHide: true });
	assert.equal(result.status, 0, result.stderr);
	assert.match(await readFile(key, "utf8"), /^[a-f0-9]{64}\n$/i);
	assert.equal(await assertRecoveryKeyFileAcl(key), platform() === "win32" ? "windows-current-user-only" : "posix-mode-checked-by-key-validator");
	if (platform() !== "win32") assert.equal((await stat(key)).mode & 0o777, 0o600);
});

test("backup action keeps SIGINT and SIGTERM handlers until restart cleanup finishes", async () => {
	const source = await readFile(SCRIPT, "utf8");
	for (const [signal, handler] of [["SIGINT", "onInterrupt"], ["SIGTERM", "onTerminate"]]) {
		assert.match(source, new RegExp(`process\\.on\\("${signal}", ${handler}\\)`));
		assert.match(source, new RegExp(`process\\.removeListener\\("${signal}", ${handler}\\)`));
	}
});

test("cold backup timer never replays a missed maintenance window at boot", async () => {
	const source = await readFile(TIMER, "utf8");
	assert.match(source, /^Persistent=false$/m);
	assert.doesNotMatch(source, /^Persistent=true$/m);
});

test("backup service can write only its spool and dashboard-visible health directory", async () => {
	const source = await readFile(SERVICE, "utf8");
	const recovery = await readFile(resolve("deploy/backup/aidr-backup-recover.service"), "utf8");
	const failure = await readFile(FAILURE_SERVICE, "utf8");
	const environment = await readFile(BACKUP_ENV, "utf8");
	const documentation = await readFile(BACKUP_README, "utf8");
	assert.doesNotMatch(source, /^ConditionPathExists=/m);
	assert.match(source, /^LoadCredential=aidr-recovery\.key:\/etc\/aidr\/aidr-recovery\.key$/m);
	assert.doesNotMatch(source, /^Requires=docker\.service$/m);
	assert.match(source, /^Wants=docker\.service network-online\.target$/m);
	assert.match(source, /^EnvironmentFile=-\/etc\/aidr\/backup-offsite\.env$/m);
	assert.match(source, /--key-file \$\{CREDENTIALS_DIRECTORY\}\/aidr-recovery\.key/);
	assert.match(source, /--key-source-file \/etc\/aidr\/aidr-recovery\.key/);
	assert.match(source, /^ReadOnlyPaths=\/srv\/aidr$/m);
	assert.match(source, /^ReadWritePaths=\/srv\/aidr\/health \/var\/lib\/aidr-backup -\/mnt\/aidr-offsite$/m);
	assert.match(source, /^TimeoutStopSec=1h$/m);
	assert.match(source, /--health-file \/srv\/aidr\/health\/backup\.json/);
	assert.doesNotMatch(source, /^ExecStart=.*--apply-retention/m, "scheduled backup must not delete expired backups automatically");
	assert.match(source, /^OnFailure=aidr-backup-health-failed\.service$/m);
	assert.match(source, /^Requires=aidr-backup-recover\.service$/m);
	assert.match(recovery, /^ConditionPathExists=\/var\/lib\/aidr-backup\/recovery-journal\.json$/m);
	assert.match(recovery, /^ExecStart=\/usr\/bin\/node \/srv\/aidr\/backup\/deployment-backup\.mjs recover-services --deployment \/srv\/aidr --recovery-journal \/var\/lib\/aidr-backup\/recovery-journal\.json$/m);
	assert.match(recovery, /^ExecStartPost=.*deployment-backup-health-failed\.mjs/m);
	assert.match(recovery, /^Before=aidr-backup-offsite\.service$/m);
	assert.match(source, /^After=aidr-backup-recover\.service$/m);
	assert.match(failure, /^ExecStart=\/usr\/bin\/node \/srv\/aidr\/backup\/deployment-backup-health-failed\.mjs --health-file \/srv\/aidr\/health\/backup\.json$/m);
	assert.match(failure, /^ReadWritePaths=\/srv\/aidr\/health$/m);
	assert.doesNotMatch(failure, /^LoadCredential=/m);
	assert.match(environment, /^# AIDR_BACKUP_TARGET=\/mnt\/aidr-offsite\/production$/m);
	assert.match(documentation, /--target \/mnt\/aidr-offsite\/production/);
	assert.doesNotMatch(documentation, /\/mnt\/offsite\/aidr\/production/);
	assert.match(documentation, /tenant_legal_holds` protects tenant\s+records/);
	assert.match(documentation, /do\s+not apply offsite pruning while any tenant hold is active/);
	assert.doesNotMatch(await readFile(resolve("scripts/deployment-backup-offsite.mjs"), "utf8"), /AIDR_BACKUP_APPLY_RETENTION/);
});

test("backup timer installation includes its startup failure handler", async () => {
	const installer = await readFile(MAINTENANCE_INSTALLER, "utf8");
	for (const name of ["aidr-backup-health-failed.service", "aidr-backup-recover.service", "deployment-backup-health-failed.mjs"]) {
		assert.match(installer, new RegExp(`\\[ -f "\\$deployment/backup/${name.replaceAll(".", "\\.")}" \\]`));
	}
	assert.match(installer, /install -m 0644 "\$deployment\/backup\/aidr-backup-health-failed\.service" \/etc\/systemd\/system\/aidr-backup-health-failed\.service/);
	assert.match(installer, /install -m 0644 "\$deployment\/backup\/aidr-backup-recover\.service" \/etc\/systemd\/system\/aidr-backup-recover\.service/);
	assert.match(installer, /systemctl enable aidr-backup-recover\.service/);
	assert.match(installer, /systemctl enable aidr-backup-recover\.service/);
	assert.match(installer, /run and verify one backup cycle before enabling aidr-backup-offsite\.timer/);
	assert.doesNotMatch(installer, /systemctl enable --now aidr-backup-offsite\.timer/, "the schedule stays disabled until a manual cycle and alert are verified");
});

test("operator cold-backup examples pass the required recovery journal", async () => {
	for (const guide of [FIRST_CUSTOMER_GUIDE, UPGRADE_GUIDE]) {
		const lines = (await readFile(guide, "utf8")).split(/\r?\n/).filter((line) => line.includes("node scripts/deployment-backup.mjs backup"));
		assert.equal(lines.length, 1, `${guide} should have one canonical cold-backup example`);
		assert.match(lines[0], /--recovery-journal \/var\/lib\/aidr-backup\/recovery-journal\.json(?:\s|$)/, `${guide} must use the installer-owned durable journal`);
		assert.match(lines[0], /--maintenance(?:\s|$)/, `${guide} must mark the cold-stop maintenance window`);
	}
});

test("backup startup failure helper atomically invalidates stale success health", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-backup-health-failed-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const health = join(root, "backup.json");
	await writeFile(health, JSON.stringify({ schema_version: 1, status: "ok", completed_at: "2026-01-01T00:00:00Z", verified_at: "2026-01-01T00:00:01Z" }));
	const result = spawnSync(process.execPath, [FAILURE_SCRIPT, "--health-file", health], { encoding: "utf8", windowsHide: true });
	assert.equal(result.status, 0, result.stderr);
	const receipt = JSON.parse(await readFile(health, "utf8"));
	assert.equal(receipt.status, "failed");
	assert.ok(Number.isFinite(Date.parse(receipt.verified_at)));
});

if (platform() !== "win32") {
	for (const [signal, exitCode] of [["SIGINT", 130], ["SIGTERM", 143]]) {
		test(`${signal} aborts the archive, restarts services, and removes partial output`, async (t) => {
			const root = await mkdtemp(join(tmpdir(), "aidr-backup-signal-"));
			t.after(() => rm(root, { recursive: true, force: true }));
			const marker = join(root, "archive.started");
			const run = await command(root, { FAKE_ARCHIVE_MARKER: marker, FAKE_ARCHIVE_DELAY_MS: "60000" });
			await waitFor(marker);
			run.child.kill(signal);
			const result = await exit(run.child);
			assert.equal(result.code, exitCode, run.stderr());
			const log = await readFile(run.log, "utf8").catch(() => assert.fail(`docker was not invoked\n${run.stderr()}`));
			for (const service of ["db", "storage", "api"]) assert.match(log, new RegExp(`start ${service}(?:\\r?\\n|$)`));
			await assert.rejects(stat(run.output), /ENOENT/);
		});
	}
}
