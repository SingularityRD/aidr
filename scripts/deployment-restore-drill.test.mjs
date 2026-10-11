import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { RECOVERY_MARKER, RUN_OWNER_MARKER, assertRecoveryKeyFileAcl, cleanupRestoreWorkRoot, conservativeBackupAgeMinutes, hardenRecoveryKeyFile, hardenWorkDirectory, loadCandidateBinding, parseRecoveryTargets, runOwnerRecord, validateLocation } from "./deployment-restore-drill.mjs";

test("RPO age starts before source shutdown, not after a lengthy archive", () => {
	const now = Date.parse("2026-09-12T10:00:00Z");
	assert.equal(conservativeBackupAgeMinutes({ started_at: "2026-09-12T08:00:00Z", completed_at: "2026-09-12T09:59:00Z" }, now), 120);
	assert.throws(() => conservativeBackupAgeMinutes({ completed_at: "2026-09-12T09:59:00Z" }, now), /timestamps are invalid/);
	assert.throws(() => conservativeBackupAgeMinutes({ started_at: "2026-09-12T10:01:00Z", completed_at: "2026-09-12T09:59:00Z" }, now), /timestamps are invalid or future-dated/);
});

test("restore retention leaves unmarked operator directories untouched", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-retention-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const unowned = join(root, "restore-2020-01-01T00-00-00-000Z-aaaaaaaaaa");
	await mkdir(unowned);
	await writeFile(join(unowned, "keep.txt"), "operator data");
	await utimes(unowned, new Date("2020-01-01"), new Date("2020-01-01"));
	assert.deepEqual(await cleanupRestoreWorkRoot(root, "1"), { sanitized: 0, expired: 0, active: 0, retention_days: 1 });
	assert.equal((await stat(join(unowned, "keep.txt"))).isFile(), true);
});

async function ownedRun(root, name, { owner = runOwnerRecord(), recovering = false, mtime = new Date("2020-01-01") } = {}) {
	const run = join(root, name);
	await mkdir(run);
	await writeFile(join(run, RUN_OWNER_MARKER), `${JSON.stringify(owner)}\n`);
	await writeFile(join(run, "restore-drill-evidence.json"), "{\"passed\":true}\n");
	if (recovering) {
		await writeFile(join(run, RECOVERY_MARKER), "aidr-recovery-0123456789abcdef\n");
		await mkdir(join(run, "downloaded"));
		await writeFile(join(run, "downloaded", "backup.tar"), "plaintext");
	}
	await utimes(run, mtime, mtime);
	return run;
}

const exists = (file) => stat(file).then(() => true, () => false);

test("restore retention expires completed AIDR drill evidence whose recovery marker was already removed", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-retention-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const expiredRun = await ownedRun(root, "restore-2020-01-01T00-00-00-000Z-aaaaaaaaaa");
	const freshRun = await ownedRun(root, "restore-2026-10-10T00-00-00-000Z-bbbbbbbbbb", { mtime: new Date() });
	assert.deepEqual(await cleanupRestoreWorkRoot(root, "1"), { sanitized: 0, expired: 1, active: 0, retention_days: 1 });
	assert.equal(await exists(expiredRun), false, "sanitized evidence past retention must be deleted");
	assert.equal(await exists(join(freshRun, "restore-drill-evidence.json")), true, "evidence within retention is kept");
	assert.equal(await exists(join(freshRun, RUN_OWNER_MARKER)), true);
});

test("restore drill writes the ownership marker at run creation and never removes it during sanitization", async () => {
	const source = await readFile(new URL("./deployment-restore-drill.mjs", import.meta.url), "utf8");
	const created = source.indexOf("await mkdir(workDir, { mode: 0o700 });");
	const owner = source.indexOf("await writeFile(join(workDir, RUN_OWNER_MARKER)");
	const recovery = source.indexOf("await writeFile(join(workDir, RECOVERY_MARKER)");
	assert.ok(created >= 0 && owner > created && recovery > owner, "ownership must be recorded before any recovery material exists");
	const sanitize = source.slice(source.indexOf("async function cleanupRecoveredRun"), source.indexOf("export async function cleanupRestoreWorkRoot"));
	assert.doesNotMatch(sanitize, /RUN_OWNER_MARKER/u, "sanitizing a run must not drop its ownership marker");
	assert.match(sanitize, /await rm\(marker, \{ force: true \}\);/u);
});

test("restore drill records the recovered Vault key status and fails when restored Vault secrets do not decrypt", async () => {
	const source = await readFile(new URL("./deployment-restore-drill.mjs", import.meta.url), "utf8");
	assert.match(source, /evidence\.vault = \{ root_key: receipt\.vault_root_key \?\? "VAULT_KEY_MISSING", \.\.\.\(await readVault\(db\.containerId\)\) \};/u);
	const probe = source.slice(source.indexOf("async function readVault"), source.indexOf("async function readStorage"));
	assert.match(probe, /SELECT count\(\*\) FROM vault\.decrypted_secrets WHERE decrypted_secret IS NOT NULL/u);
	assert.match(probe, /catch \{ throw new Error\("Recovered Vault secrets cannot be decrypted/u);
	assert.match(probe, /if \(decrypted !== secrets\) throw/u);
	assert.ok(source.indexOf("evidence.vault = ") < source.indexOf("evidence.passed = true"));
});

test("restore retention preserves an active recovery, sanitizes an interrupted one, and leaves foreign folders alone", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-retention-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const activeRun = await ownedRun(root, "restore-2020-01-01T00-00-00-000Z-cccccccccc", { owner: { ...runOwnerRecord(), pid: 424242 }, recovering: true });
	const crashedRun = await ownedRun(root, "restore-2026-10-10T00-00-00-000Z-dddddddddd", { owner: { ...runOwnerRecord(), pid: 535353 }, recovering: true, mtime: new Date() });
	const foreign = join(root, "restore-2020-01-01T00-00-00-000Z-eeeeeeeeee");
	await mkdir(foreign);
	await writeFile(join(foreign, RUN_OWNER_MARKER), "operator note, not a drill record\n");
	await writeFile(join(foreign, "keep.txt"), "operator data");
	await utimes(foreign, new Date("2020-01-01"), new Date("2020-01-01"));
	const other = join(root, "operator-backups");
	await mkdir(other);
	await writeFile(join(other, RUN_OWNER_MARKER), `${JSON.stringify(runOwnerRecord())}\n`);
	await utimes(other, new Date("2020-01-01"), new Date("2020-01-01"));
	const result = await cleanupRestoreWorkRoot(root, "1", Date.now(), { isProcessAlive: (pid) => pid === 424242 });
	assert.deepEqual(result, { sanitized: 1, expired: 0, active: 1, retention_days: 1 });
	assert.equal(await exists(join(activeRun, "downloaded", "backup.tar")), true, "an in-progress recovery must not be torn down");
	assert.equal(await exists(join(activeRun, RECOVERY_MARKER)), true);
	assert.equal(await exists(join(crashedRun, "downloaded")), false, "interrupted recovery material is removed");
	assert.equal(await exists(join(crashedRun, RECOVERY_MARKER)), false);
	assert.equal(await exists(join(crashedRun, RUN_OWNER_MARKER)), true, "the interrupted run stays expirable");
	assert.equal(await exists(join(foreign, "keep.txt")), true, "an invalid ownership marker does not make a folder AIDR-owned");
	assert.equal(await exists(join(other, RUN_OWNER_MARKER)), true, "names outside the run pattern are never considered");
});

test("restore retention adopts an interrupted pre-marker run so it is sanitized now and expires later", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-retention-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const legacy = join(root, "restore-2026-10-09T00-00-00-000Z-ffffffffff");
	await mkdir(join(legacy, "downloaded"), { recursive: true });
	await writeFile(join(legacy, RECOVERY_MARKER), "aidr-recovery-0123456789abcdef\n");
	await writeFile(join(legacy, "downloaded", "backup.tar"), "plaintext");
	assert.deepEqual(await cleanupRestoreWorkRoot(root, "30"), { sanitized: 1, expired: 0, active: 0, retention_days: 30 });
	assert.equal(await exists(join(legacy, "downloaded")), false);
	const owner = JSON.parse(await readFile(join(legacy, RUN_OWNER_MARKER), "utf8"));
	assert.equal(owner.adopted, true);
	assert.deepEqual(await cleanupRestoreWorkRoot(root, "1", Date.now() + 3 * 86400 * 1000), { sanitized: 0, expired: 1, active: 0, retention_days: 1 });
	assert.equal(await exists(legacy), false);
});

test("restore workspace stays outside key custody and filesystem backup target", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-location-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const target = join(root, "offsite");
	const custody = join(root, "custody");
	const work = join(root, "work");
	await Promise.all([mkdir(target), mkdir(custody)]);
	const key = join(custody, "recovery.key");
	await writeFile(key, "fixture\n");
	assert.equal(await validateLocation(work, key, { kind: "filesystem", root: target }), work);
	await assert.rejects(validateLocation(join(target, "unsafe"), key, { kind: "filesystem", root: target }), /separate from the backup target/);
	await assert.rejects(validateLocation(work, key, { kind: "filesystem", root: custody }), /recovery key separate from the backup target/);
	await mkdir(work);
	await assert.rejects(validateLocation(work, key, { kind: "filesystem", root: target }), /new, unused work directory/);
});

test("restore work directory ACL excludes inherited readers before secrets are written", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-acl-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const work = join(root, "work");
	await mkdir(work, { mode: 0o700 });
	assert.equal(await hardenWorkDirectory(work), platform() === "win32" ? "windows-current-user-only" : "posix-owner-only");
});

test("recovery key file ACL is restricted to the current Windows user and can be checked without mutation", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-key-acl-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const key = join(root, "recovery.key");
	await writeFile(key, "fixture\n");
	assert.equal(await hardenRecoveryKeyFile(key), platform() === "win32" ? "windows-current-user-only" : "posix-mode-checked-by-key-validator");
	assert.equal(await assertRecoveryKeyFileAcl(key), platform() === "win32" ? "windows-current-user-only" : "posix-mode-checked-by-key-validator");
});

test("restore evidence binding refuses unsigned or incomplete candidate material", async (t) => {
	const root = await mkdtemp(join(tmpdir(), "aidr-restore-binding-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	const runtime = join(root, "runtime");
	const candidate = join(root, "candidate");
	await Promise.all([mkdir(runtime), mkdir(candidate)]);
	const sourceCommit = "a".repeat(40);
	const inventoryBytes = Buffer.from(`${JSON.stringify({ schema_version: 1, artifacts: [{ staged_path: "aidr.tgz", sha256: "b".repeat(64) }] })}\n`);
	const policy = join(root, "signer-policy.json");
	await Promise.all([
		writeFile(join(runtime, "deployment.json"), `${JSON.stringify({ schema_version: 1, source_commit: sourceCommit, source_has_changes: false })}\n`),
		writeFile(join(candidate, "release-inventory.json"), inventoryBytes),
		writeFile(join(candidate, "release-metadata.json"), `${JSON.stringify({ schema_version: 1, git_sha: sourceCommit })}\n`),
		writeFile(policy, "{}\n"),
	]);
	await assert.rejects(loadCandidateBinding(runtime, join(candidate, "release-inventory.json")), /absolute paths/);
	await assert.rejects(loadCandidateBinding(runtime, join(candidate, "release-inventory.json"), policy), /metadata|inventory|artifact|bundle|policy/i);
});

test("periodic restore template requires runtime, candidate and explicit recovery objectives", async () => {
	assert.deepEqual(parseRecoveryTargets("60", "900"), { rpoTargetMinutes: 60, rtoTargetSeconds: 900 });
	assert.throws(() => parseRecoveryTargets(undefined, "900"), /--rpo-target-minutes/);
	assert.throws(() => parseRecoveryTargets("60", "0"), /--rto-target-seconds/);
	const service = await readFile(resolve("deploy/backup/aidr-restore-drill.service"), "utf8");
	const timer = await readFile(resolve("deploy/backup/aidr-restore-drill.timer"), "utf8");
	const environment = await readFile(resolve("deploy/backup/aidr-restore-drill.env.example"), "utf8");
	const drill = await readFile(resolve("scripts/deployment-restore-drill.mjs"), "utf8");
	for (const flag of ["--runtime", "--candidate-inventory", "--candidate-policy", "--rpo-target-minutes", "--rto-target-seconds", "--evidence-retention-days", "--work-root"]) assert.match(service, new RegExp(flag));
	assert.doesNotMatch(service, /^ConditionPathExists=/m);
	assert.match(service, /^LoadCredential=aidr-recovery\.key:\/etc\/aidr\/aidr-recovery\.key$/m);
	assert.match(service, /^WorkingDirectory=\/$/m);
	assert.doesNotMatch(service, /\/opt\/aidr-kit/);
	assert.match(service, /^ExecStart=.*\$\{AIDR_RESTORE_KIT_ROOT\}\/scripts\/deployment-restore-drill\.mjs/m);
	assert.match(service, /^ExecStopPost=.*\$\{AIDR_RESTORE_KIT_ROOT\}\/scripts\/deployment-restore-drill\.mjs/m);
	assert.doesNotMatch(service, /^Requires=docker\.service$/m);
	assert.match(service, /^Wants=docker\.service network-online\.target$/m);
	assert.match(service, /--key-file \$\{CREDENTIALS_DIRECTORY\}\/aidr-recovery\.key/);
	assert.match(service, /^ExecStopPost=.*--cleanup-only/m);
	assert.match(service, /^TimeoutStopSec=30min$/m);
	assert.match(timer, /Persistent=true/);
	assert.match(drill, /receipt\.reviewed_runtime_deployment_sha256 !== binding\.runtime_deployment_sha256/);
	assert.match(drill, /receipt\.installation_runtime_tree_sha256 !== manifest\.installation_runtime_sha256/);
	assert.match(drill, /receipt\.source_commit !== binding\.source_commit/);
	assert.match(drill, /await assertPrivateRecoveryKey\(keyFile\);\s*await assertRecoveryKeyFileAcl\(keyFile\);/);
	for (const name of ["AIDR_RESTORE_KIT_ROOT", "AIDR_RESTORE_RUNTIME", "AIDR_RESTORE_CANDIDATE_INVENTORY", "AIDR_RESTORE_CANDIDATE_POLICY", "AIDR_RESTORE_EVIDENCE_RETENTION_DAYS", "AIDR_RESTORE_RPO_TARGET_MINUTES", "AIDR_RESTORE_RTO_TARGET_SECONDS"]) assert.match(environment, new RegExp(`^${name}=`, "m"));
	assert.match(environment, /^AIDR_RESTORE_KIT_ROOT=\/srv\/aidr-staging\/aidr-kit-1$/m);
});

test("restore drill keeps signal protection through cleanup and evidence persistence", async () => {
	const source = await readFile(new URL("./deployment-restore-drill.mjs", import.meta.url), "utf8");
	assert.match(source, /if \(!cleaningUp\) activeChild\?\.kill\(signal\)/);
	const cleanup = source.indexOf("cleaningUp = true;");
	const evidence = source.indexOf("await writeFile(evidencePath");
	const handlerRemoval = source.indexOf('process.removeListener("SIGTERM", onTerminate)');
	assert.ok(cleanup >= 0 && evidence > cleanup && handlerRemoval > evidence);
});
