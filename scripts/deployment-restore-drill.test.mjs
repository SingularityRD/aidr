import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { platform, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { assertRecoveryKeyFileAcl, cleanupRestoreWorkRoot, conservativeBackupAgeMinutes, hardenRecoveryKeyFile, hardenWorkDirectory, loadCandidateBinding, parseRecoveryTargets, validateLocation } from "./deployment-restore-drill.mjs";

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
	assert.deepEqual(await cleanupRestoreWorkRoot(root, "1"), { sanitized: 0, expired: 0, retention_days: 1 });
	assert.equal((await stat(join(unowned, "keep.txt"))).isFile(), true);
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
