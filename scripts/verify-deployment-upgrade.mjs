#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import {
	cpSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = mkdtempSync(join(tmpdir(), "aidr-upgrade-tools-"));
const toolDir = join(root, "tools");
mkdirSync(toolDir);
mkdirSync(join(toolDir, "lib"));
cpSync("scripts/deployment-upgrade.mjs", join(toolDir, "deployment-upgrade.mjs"));
cpSync("scripts/lib/migration-contract.mjs", join(toolDir, "lib/migration-contract.mjs"));
cpSync("scripts/lib/migration-hash-compat.mjs", join(toolDir, "lib/migration-hash-compat.mjs"));

const backupStub = `
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const args=process.argv.slice(2), action=args[0], value=(name)=>args[args.indexOf(name)+1];
const marker=process.env.AIDR_TEST_BACKUP_FAILURE;
if(marker&&existsSync(marker)) process.exit(41);
if(!existsSync(value("--key-file"))||!existsSync(join(value("--backup"),"backup.json"))) process.exit(42);
const signal=process.env.AIDR_TEST_BACKUP_SIGNAL;
if(signal&&action==="verify"){process.kill(process.ppid,signal);await new Promise((done)=>setTimeout(done,5000));writeFileSync(process.env.AIDR_TEST_BACKUP_SIGNAL_MARKER,"verifier was not stopped");}
if(action==="recover") { const output=value("--output"); if(existsSync(output)) process.exit(43); mkdirSync(output,{recursive:true}); writeFileSync(join(output,"recovery-receipt.json"),JSON.stringify({services_started:false})); }
else if(action!=="verify") process.exit(44);
`;
const migrateStub = `
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
const deployment=process.argv[2], count=process.env.AIDR_TEST_MIGRATE_COUNT;
writeFileSync(count,String((Number(existsSync(count)?readFileSync(count,"utf8"):"0")||0)+1));
const fail=process.env.AIDR_TEST_MIGRATE_FAILURE;
if(fail&&existsSync(fail)){unlinkSync(fail);process.exit(51)}
const signal=process.env.AIDR_TEST_MIGRATE_SIGNAL;
if(signal){process.kill(process.ppid,signal);await new Promise((done)=>setTimeout(done,300));}
const manifest=JSON.parse(readFileSync(deployment+"/deployment.json","utf8"));
if(!manifest.migrations?.length) process.exit(52);
`;
const doctorStub = `
import { existsSync, readFileSync, writeFileSync } from "node:fs";
const args=process.argv.slice(2), deployment=args[args.indexOf("--deployment")+1];
if(!args.includes("--online"))process.exit(61);
if(!readFileSync(deployment+"/dashboard/version.txt","utf8").includes("target"))process.exit(62);
const count=process.env.AIDR_TEST_DOCTOR_COUNT;writeFileSync(count,String((Number(existsSync(count)?readFileSync(count,"utf8"):"0")||0)+1));
const fail=process.env.AIDR_TEST_DOCTOR_FAILURE;if(fail&&existsSync(fail))process.exit(63);
writeFileSync(deployment+"/doctor-evidence.json",JSON.stringify({passed:true,online:true}));
`;
writeFileSync(join(toolDir, "deployment-backup.mjs"), backupStub);
writeFileSync(join(toolDir, "deployment-migrate.mjs"), migrateStub);
writeFileSync(join(toolDir, "deployment-doctor.mjs"), doctorStub);

const dockerDriver = join(toolDir, "docker-driver.mjs");
writeFileSync(
	dockerDriver,
	`import { appendFileSync, existsSync, unlinkSync, writeFileSync } from "node:fs";
let input="";for await(const chunk of process.stdin)input+=chunk;
const args=process.argv.slice(2);appendFileSync(process.env.AIDR_TEST_DOCKER_LOG,args.join(" ")+"\\n");
if(args.includes("psql")){
	writeFileSync(process.env.AIDR_TEST_SQL_LOG,input);
	const fail=process.env.AIDR_TEST_DRY_RUN_FAILURE;if(fail&&existsSync(fail)){unlinkSync(fail);process.exit(71)}
	const signal=process.env.AIDR_TEST_DRY_RUN_SIGNAL;if(signal)process.kill(process.ppid,signal);
}
if(args.includes("ps")&&args.includes("--services"))process.stdout.write("db\\ndashboard\\nfunctions\\n");
`,
);

const sha = (value) => createHash("sha256").update(value).digest("hex");
const fileSha = (path) => sha(readFileSync(path));
const migrationHash = (entries) => sha(entries.map((entry) => `${entry.name}\0${entry.sha256}\n`).join(""));
const signingKeys = generateKeyPairSync("ed25519");
const signingPrivateB64 = signingKeys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
const signingPublicPem = signingKeys.publicKey.export({ type: "spki", format: "pem" });
const write = (path, value) => {
	mkdirSync(resolve(path, ".."), { recursive: true });
	writeFileSync(path, value);
};

function createDeployment(path, kind, options = {}) {
	mkdirSync(join(path, "dashboard"), { recursive: true });
	mkdirSync(join(path, "ingress"), { recursive: true });
	if (!options.legacy) {
		mkdirSync(join(path, "backup"), { recursive: true });
		mkdirSync(join(path, "maintenance"), { recursive: true });
		mkdirSync(join(path, "auth-templates"), { recursive: true });
	}
	mkdirSync(join(path, "volumes/functions/example"), { recursive: true });
	mkdirSync(join(path, "volumes/api"), { recursive: true });
	mkdirSync(join(path, "migrations"), { recursive: true });
	write(join(path, "dashboard/version.txt"), `${kind}\n`);
	write(join(path, "ingress/version.txt"), `${kind}\n`);
	if (!options.legacy) {
		write(join(path, "backup/version.txt"), `${kind}\n`);
		write(join(path, "maintenance/version.txt"), `${kind}\n`);
		write(join(path, "auth-templates/recovery.html"), `${kind}\n`);
	}
	write(join(path, "volumes/functions/example/index.ts"), `export const version = "${kind}";\n`);
	write(join(path, "volumes/api/config.yml"), `version: ${kind}\n`);
	const firstSql = options.changedFirst ? "SELECT 11;\n" : "SELECT 1;\n";
	write(join(path, "migrations/20260912000000_initial.sql"), firstSql);
	if (kind === "target") write(join(path, "migrations/20260913000000_upgrade.sql"), "CREATE TABLE IF NOT EXISTS public.upgrade_probe(id integer);\n");
	write(join(path, "agent-config.json"), JSON.stringify({ version: kind, licensing: { public_keys_pem: [signingPublicPem] } }));
	write(join(path, "compose.yml"), `name: ${kind}-project\nservices:\n  db: {}\n  dashboard: {}\n  functions: {}\n`);
	write(join(path, ".env"), "ANON_KEY=private\nSERVICE_ROLE_KEY=private\n");
	write(join(path, ".env.functions"), `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivateB64}\nAIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivateB64}\nAIDR_PACK_DOWNLOAD_GRANT_SECRET=test-only-not-a-production-secret\n`);
	write(join(path, ".env.ingress"), "AIDR_DEVICE_START_INGRESS_SECRET=private\n");
	const migrations = ["20260912000000_initial.sql", ...(kind === "target" ? ["20260913000000_upgrade.sql"] : [])].map((name) => ({ name, sha256: fileSha(join(path, "migrations", name)) }));
	const artifactPaths = [
		"dashboard/version.txt",
		"ingress/version.txt",
		...(!options.legacy ? ["backup/version.txt", "maintenance/version.txt", "auth-templates/recovery.html"] : []),
		"volumes/functions/example/index.ts",
	];
	const manifest = {
		schema_version: 1,
		project_name: kind === "current" ? "customer-project" : "candidate-project",
		mode: "self-hosted",
		development: true,
		prepared_at: new Date().toISOString(),
		source_commit: kind === "current" ? "a".repeat(40) : "b".repeat(40),
		source_has_changes: false,
		upstream_sha: "c".repeat(40),
		dashboard_url: "http://localhost:8080",
		supabase_url: "http://localhost:8000",
		migrations,
		artifacts: artifactPaths.map((entry) => ({ path: entry, sha256: fileSha(join(path, ...entry.split("/"))) })),
	};
	write(join(path, "deployment.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	return manifest;
}

function createScenario(name, mutate = () => {}, options = {}) {
	const dir = join(root, name);
	const current = join(dir, "current");
	const target = join(dir, "target");
	const backup = join(dir, "backup");
	const contractDir = join(dir, "contract");
	const key = join(dir, "recovery.key");
	const contractPath = join(contractDir, "upgrade-compatibility.json");
	const evidencePath = join(contractDir, "acceptance.json");
	const recovery = join(dir, "recovery");
	const recoveryRuntime = join(dir, "recovery-runtime");
	const currentManifest = createDeployment(current, "current", options.current);
	const targetManifest = createDeployment(target, "target");
	createDeployment(recoveryRuntime, "current");
	mkdirSync(backup, { recursive: true });
	write(key, `${"1".repeat(64)}\n`);
	write(evidencePath, `${JSON.stringify({ passed: true, cases: ["old-data", "new-schema", "target-app"] })}\n`);
	write(
		join(backup, "backup.json"),
		JSON.stringify({
			payload: JSON.stringify({
				type: "aidr-cold-volumes",
				source_project: currentManifest.project_name,
				source_commit: currentManifest.source_commit,
				started_at: new Date().toISOString(),
				completed_at: new Date().toISOString(),
			}),
			hmac_sha256: "verified-by-test-double",
		}),
	);
	const contract = {
		schema_version: 1,
		current_manifest_sha256: fileSha(join(current, "deployment.json")),
		target_manifest_sha256: fileSha(join(target, "deployment.json")),
		current_migration_set_sha256: migrationHash(currentManifest.migrations),
		target_migration_set_sha256: migrationHash(targetManifest.migrations),
		current_app_compatible_with_current_schema: true,
		target_app_compatible_with_target_schema: true,
		target_schema_accepts_existing_data: true,
		migrations_transactional: true,
		required_env_keys: ["ANON_KEY", "SERVICE_ROLE_KEY"],
		required_function_env_keys: ["AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", "AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64", "AIDR_PACK_DOWNLOAD_GRANT_SECRET"], // gitleaks:allow: environment variable names only, not credential values
		required_ingress_env_keys: ["AIDR_DEVICE_START_INGRESS_SECRET"],
		current_support_files: ["agent-config.json", "compose.yml"].map((path) => ({ path, sha256: fileSha(join(current, path)) })),
		target_support_files: ["agent-config.json", "compose.yml"].map((path) => ({ path, sha256: fileSha(join(target, path)) })),
		approved_by: "Release Owner",
		approved_at: new Date().toISOString(),
		acceptance_evidence: [{ path: "acceptance.json", sha256: fileSha(evidencePath) }],
	};
	write(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
	const scenario = { dir, current, target, backup, key, contractPath, evidencePath, recovery, recoveryRuntime, contract, currentManifest, targetManifest };
	mutate(scenario);
	return scenario;
}

const dockerLog = join(root, "docker.log");
const sqlLog = join(root, "migration-dry-run.sql");
const migrateCount = join(root, "migrate-count");
const doctorCount = join(root, "doctor-count");
const baseEnv = {
	...process.env,
	NODE_ENV: "test",
	AIDR_UPGRADE_TEST_DOCKER_DRIVER: dockerDriver,
	AIDR_TEST_DOCKER_LOG: dockerLog,
	AIDR_TEST_SQL_LOG: sqlLog,
	AIDR_TEST_MIGRATE_COUNT: migrateCount,
	AIDR_TEST_DOCTOR_COUNT: doctorCount,
};
function run(scenario, action, expectedSuccess = true, extraEnv = {}, extraArgs = []) {
	const result = spawnSync(
		process.execPath,
		[
			join(toolDir, "deployment-upgrade.mjs"),
			action,
			"--current",
			scenario.current,
			"--target",
			scenario.target,
			"--backup",
			scenario.backup,
			"--key-file",
			scenario.key,
			"--contract",
			scenario.contractPath,
			"--recovery-output",
			scenario.recovery,
			...(action === "recover" ? ["--recovery-runtime", scenario.recoveryRuntime] : []),
			...(["apply", "resume", "recover"].includes(action) ? ["--maintenance"] : []),
			...extraArgs,
		],
		{ encoding: "utf8", timeout: 180_000, env: { ...baseEnv, ...extraEnv } },
	);
	assert.equal(result.status === 0, expectedSuccess, `${action} unexpected exit ${result.status}: ${result.stderr}`);
	return result;
}

function saveInterruptedPhase(scenario, phase) {
	const path = join(scenario.current, ".aidr-upgrade/state.json");
	const state = JSON.parse(readFileSync(path, "utf8"));
	state.status = "running";
	state.last_completed_phase = phase;
	state.running_services = ["db", "dashboard", "functions"];
	write(path, `${JSON.stringify(state, null, 2)}\n`);
	return path;
}
const migrationRuns = () => existsSync(migrateCount) ? readFileSync(migrateCount, "utf8") : "0";

const checks = [];
const valid = createScenario("valid");
const existingEntitlement = Buffer.from(JSON.stringify({ tenant_id: "existing-tenant", seats: 5 }));
const existingSignature = sign(null, existingEntitlement, signingKeys.privateKey);
const currentAgentKey = JSON.parse(readFileSync(join(valid.current, "agent-config.json"), "utf8")).licensing.public_keys_pem[0];
assert.equal(verify(null, existingEntitlement, currentAgentKey, existingSignature), true);
const compatibilityCheck = spawnSync(
	process.execPath,
	[join(toolDir, "deployment-upgrade.mjs"), "check", "--current", valid.current, "--target", valid.target, "--contract", valid.contractPath],
	{ encoding: "utf8", timeout: 60_000, env: baseEnv },
);
assert.equal(compatibilityCheck.status, 0, compatibilityCheck.stderr);
const compatibility = JSON.parse(compatibilityCheck.stdout);
assert.equal(compatibility.compatible, true);
assert.equal(compatibility.current.manifest_sha256, valid.contract.current_manifest_sha256);
assert.deepEqual(compatibility.new_migrations, ["20260913000000_upgrade.sql"]);
assert.equal(compatibility.upgrade_state, null);
assert.equal(existsSync(join(valid.current, ".aidr-upgrade")), false);
assert.equal(existsSync(dockerLog), false);
checks.push("check validates manifests, append-only history and the contract without a backup, lock, state or Docker call");
run(valid, "preflight");
const ready = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(ready.status, "ready");
assert.equal(ready.current_manifest_sha256, valid.contract.current_manifest_sha256);
assert.equal(ready.target_manifest_sha256, valid.contract.target_manifest_sha256);
assert.equal(ready.checks.length, 5);
const backupMonitoring = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/monitoring/backup.json"), "utf8"));
assert.deepEqual(Object.keys(backupMonitoring).slice(0, 4), ["schema_version", "status", "completed_at", "verified_at"]);
assert.equal(backupMonitoring.status, "ok");
assert.equal(backupMonitoring.recovery_point_at, ready.backup.recovery_point_at);
checks.push("preflight binds exact current/target manifests, artifacts, compatibility evidence and backup");
checks.push("verified backup readiness is published atomically with the monitoring status/time contract");

assert.equal(existsSync(sqlLog), false);
checks.push("preflight performs no live database migration dry-run before writer drain");

const rotatedSigningKey = createScenario("rotated-signing-key", (scenario) => {
	const rotated = generateKeyPairSync("ed25519");
	write(join(scenario.target, "agent-config.json"), JSON.stringify({
		version: "target",
		licensing: { public_keys_pem: [rotated.publicKey.export({ type: "spki", format: "pem" })] },
	}));
	scenario.contract.target_support_files.find((entry) => entry.path === "agent-config.json").sha256 = fileSha(join(scenario.target, "agent-config.json"));
	write(scenario.contractPath, `${JSON.stringify(scenario.contract, null, 2)}\n`);
});
const keyCheck = spawnSync(
	process.execPath,
	[join(toolDir, "deployment-upgrade.mjs"), "check", "--current", rotatedSigningKey.current, "--target", rotatedSigningKey.target, "--contract", rotatedSigningKey.contractPath],
	{ encoding: "utf8", timeout: 60_000, env: baseEnv },
);
assert.notEqual(keyCheck.status, 0);
assert.match(keyCheck.stderr, /signing keys do not match/);
const keyFailure = run(rotatedSigningKey, "preflight", false);
assert.match(keyFailure.stderr, /signing keys do not match/);
assert.equal(existsSync(join(rotatedSigningKey.current, ".aidr-upgrade/state.json")), false);
checks.push("newly prepared signing keys cannot silently replace an installed verifier while old private keys remain");

const damagedBackupAfterPreflight = createScenario("damaged-backup-after-preflight");
run(damagedBackupAfterPreflight, "preflight");
const failBackupAfterPreflight = join(root, "fail-backup-after-preflight");
write(failBackupAfterPreflight, "fail");
writeFileSync(dockerLog, "");
run(damagedBackupAfterPreflight, "apply", false, { AIDR_TEST_BACKUP_FAILURE: failBackupAfterPreflight });
assert.equal(readFileSync(dockerLog, "utf8"), "");
assert.equal(JSON.parse(readFileSync(join(damagedBackupAfterPreflight.current, ".aidr-upgrade/state.json"), "utf8")).last_completed_phase, "preflight");
checks.push("apply re-verifies backup ciphertext before any Docker call or writer drain");

const changedSignerAfterPreflight = createScenario("changed-signer-after-preflight");
run(changedSignerAfterPreflight, "preflight");
const replacementSigner = generateKeyPairSync("ed25519");
const replacementPrivate = replacementSigner.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
write(join(changedSignerAfterPreflight.current, ".env.functions"), `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=${replacementPrivate}\nAIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${replacementPrivate}\nAIDR_PACK_DOWNLOAD_GRANT_SECRET=test-only-not-a-production-secret\n`);
writeFileSync(dockerLog, "");
const changedSignerFailure = run(changedSignerAfterPreflight, "apply", false);
assert.match(changedSignerFailure.stderr, /signing keys do not match/);
assert.equal(readFileSync(dockerLog, "utf8"), "");
checks.push("signing-key changes after preflight fail before Docker or writer drain");

for (const phase of ["writers_stopped", "migration_dry_run"]) {
	const scenario = createScenario(`resume-changed-signer-${phase}`);
	run(scenario, "preflight");
	const statePath = saveInterruptedPhase(scenario, phase);
	const savedState = readFileSync(statePath, "utf8");
	const replacement = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
	write(join(scenario.current, ".env.functions"), `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=${replacement}\nAIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${replacement}\nAIDR_PACK_DOWNLOAD_GRANT_SECRET=test-only-not-a-production-secret\n`);
	writeFileSync(dockerLog, "");
	const migrationsBefore = migrationRuns();
	assert.match(run(scenario, "resume", false).stderr, /signing keys do not match/);
	assert.equal(readFileSync(statePath, "utf8"), savedState);
	assert.equal(readFileSync(dockerLog, "utf8"), "");
	assert.equal(migrationRuns(), migrationsBefore);
	checks.push(`${phase} resume rejects a changed signing identity without advancing state or schema`);
}

const staleResumes = ["writers_stopped", "migration_dry_run"].map((phase) => {
	const scenario = createScenario(`resume-stale-backup-${phase}`);
	const freshnessArgs = ["--max-backup-age-hours", "0.001"];
	run(scenario, "preflight", true, {}, freshnessArgs);
	return { scenario, phase, freshnessArgs, statePath: saveInterruptedPhase(scenario, phase) };
});
await new Promise((resolveWait) => setTimeout(resolveWait, 4_000));
for (const { scenario, phase, freshnessArgs, statePath } of staleResumes) {
	const savedState = readFileSync(statePath, "utf8");
	writeFileSync(dockerLog, "");
	const migrationsBefore = migrationRuns();
	assert.match(run(scenario, "resume", false, {}, freshnessArgs).stderr, /outside the 0.001-hour upgrade window/);
	assert.equal(readFileSync(statePath, "utf8"), savedState);
	assert.equal(readFileSync(dockerLog, "utf8"), "");
	assert.equal(migrationRuns(), migrationsBefore);
	checks.push(`${phase} resume rejects a stale recovery point without advancing state or schema`);
}

const failedMigration = createScenario("migration-runner-failure");
run(failedMigration, "preflight");
const failOnce = join(root, "fail-migrate-once");
write(failOnce, "fail");
run(failedMigration, "apply", false, { AIDR_TEST_MIGRATE_FAILURE: failOnce });
const loggedSql = readFileSync(sqlLog, "utf8");
assert.match(loggedSql, /pg_try_advisory_xact_lock\(9112026\)/);
assert.match(loggedSql, /20260913000000_upgrade/);
assert.match(loggedSql, /ROLLBACK;/);
const orderedDockerCalls = readFileSync(dockerLog, "utf8").trim().split(/\r?\n/);
const stopIndex = orderedDockerCalls.findIndex((line) => line.includes(" stop "));
const dryRunIndex = orderedDockerCalls.findIndex((line) => line.includes(" psql "));
const restartIndex = orderedDockerCalls.findIndex((line) => line.includes(" start "));
assert.ok(stopIndex >= 0 && dryRunIndex > stopIndex && restartIndex === -1);
checks.push("writer drain precedes the locked rollback-only migration dry-run, and uncertain migration failure keeps writers stopped");
const failed = JSON.parse(readFileSync(join(failedMigration.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(failed.status, "failed");
assert.equal(failed.requires_restore, true);
assert.equal(failed.last_completed_phase, "migration_running");
assert.ok(existsSync(join(failedMigration.current, ".aidr-upgrade/rollback-plan.json")));
assert.ok(!existsSync(join(failedMigration.current, ".aidr-upgrade/migration-stage/.env")));
assert.equal(readFileSync(join(failedMigration.current, "dashboard/version.txt"), "utf8"), "current\n");
run(failedMigration, "resume", false);
checks.push("failed migration runner leaves source artifacts intact, removes staged secrets and requires isolated restore before resuming");

const dryRunFailure = createScenario("dry-run-failure");
run(dryRunFailure, "preflight");
const failDryRun = join(root, "fail-dry-run");
write(failDryRun, "fail");
writeFileSync(dockerLog, "");
run(dryRunFailure, "apply", false, { AIDR_TEST_DRY_RUN_FAILURE: failDryRun });
const dryRunFailureCalls = readFileSync(dockerLog, "utf8").trim().split(/\r?\n/);
assert.ok(dryRunFailureCalls.findIndex((line) => line.includes(" start ")) > dryRunFailureCalls.findIndex((line) => line.includes(" psql ")));
const dryRunFailedState = JSON.parse(readFileSync(join(dryRunFailure.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(dryRunFailedState.last_completed_phase, "preflight");
assert.equal(dryRunFailedState.requires_restore, false);
checks.push("dry-run failure restarts exactly the pre-maintenance writer set without requiring restore");

const dryRunSignal = createScenario("dry-run-signal");
run(dryRunSignal, "preflight");
writeFileSync(dockerLog, "");
if (process.platform === "win32") {
	const upgradeSource = readFileSync("scripts/deployment-upgrade.mjs", "utf8");
	assert.match(upgradeSource, /process\.on\(signal/);
	assert.match(upgradeSource, /throwIfInterrupted\(\);\s*saveState\(state, "migration_dry_run"\)/);
	checks.push("SIGINT/SIGTERM hooks share the tested pre-commit writer restart path (static assertion on Windows)");
} else {
	const signalRun = run(dryRunSignal, "apply", false, { AIDR_TEST_DRY_RUN_SIGNAL: "SIGTERM" });
	assert.equal(signalRun.status, 143);
	assert.match(signalRun.stderr, /Upgrade interrupted by SIGTERM/);
	const signalCalls = readFileSync(dockerLog, "utf8").trim().split(/\r?\n/);
	assert.ok(signalCalls.findIndex((line) => line.includes(" start ")) > signalCalls.findIndex((line) => line.includes(" psql ")));
	assert.match(signalCalls.find((line) => line.includes(" start ")), / start dashboard functions$/);
	const signalState = JSON.parse(readFileSync(join(dryRunSignal.current, ".aidr-upgrade/state.json"), "utf8"));
	assert.equal(signalState.status, "failed");
	assert.equal(signalState.last_completed_phase, "preflight");
	assert.equal(signalState.requires_restore, false);
	assert.equal(signalState.interrupted_by, "SIGTERM");
	assert.equal(readFileSync(join(dryRunSignal.current, "dashboard/version.txt"), "utf8"), "current\n");
	checks.push("SIGTERM during the drained dry-run restarts the original writers and exits 143 with resumable state");
}

run(dryRunFailure, "resume");
assert.equal(JSON.parse(readFileSync(join(dryRunFailure.current, ".aidr-upgrade/state.json"), "utf8")).status, "complete");
checks.push("pre-commit dry-run failure can resume safely after source writers were restarted");

run(valid, "apply");
const complete = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(complete.status, "complete");
assert.equal(readFileSync(join(valid.current, "dashboard/version.txt"), "utf8"), "target\n");
assert.equal(readFileSync(join(valid.current, "maintenance/version.txt"), "utf8"), "target\n");
assert.equal(readFileSync(join(valid.current, "auth-templates/recovery.html"), "utf8"), "target\n");
assert.equal(readFileSync(join(valid.current, ".env"), "utf8"), "ANON_KEY=private\nSERVICE_ROLE_KEY=private\n");
assert.equal(readFileSync(join(valid.current, ".env.functions"), "utf8"), `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivateB64}\nAIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivateB64}\nAIDR_PACK_DOWNLOAD_GRANT_SECRET=test-only-not-a-production-secret\n`);
const upgradedAgentKey = JSON.parse(readFileSync(join(valid.current, "agent-config.json"), "utf8")).licensing.public_keys_pem[0];
assert.equal(verify(null, existingEntitlement, upgradedAgentKey, existingSignature), true);
assert.equal(JSON.parse(readFileSync(join(valid.current, "deployment.json"), "utf8")).project_name, "customer-project");
assert.equal(readFileSync(migrateCount, "utf8"), "3");
assert.equal(readFileSync(doctorCount, "utf8"), "2");
assert.ok(existsSync(join(valid.current, ".aidr-upgrade/upgrade-receipt.json")));
checks.push("apply completes migration, artifact switch, service start and online doctor without replacing customer secrets or project identity");
checks.push("an existing signed entitlement still verifies against the installed agent key after upgrade");

run(valid, "resume");
assert.equal(readFileSync(migrateCount, "utf8"), "3");
assert.equal(readFileSync(doctorCount, "utf8"), "2");
checks.push("completed upgrade resume is idempotent");

const legacyCurrent = createScenario("legacy-current", () => {}, { current: { legacy: true } });
run(legacyCurrent, "preflight");
run(legacyCurrent, "apply");
assert.equal(readFileSync(join(legacyCurrent.current, "maintenance/version.txt"), "utf8"), "target\n");
assert.equal(readFileSync(join(legacyCurrent.current, "auth-templates/recovery.html"), "utf8"), "target\n");
checks.push("upgrade installs newly introduced artifact roots when the previous release did not contain them");

const interruptedInstall = createScenario("interrupted-install");
run(interruptedInstall, "preflight");
const interruptedStatePath = join(interruptedInstall.current, ".aidr-upgrade/state.json");
const interruptedState = JSON.parse(readFileSync(interruptedStatePath, "utf8"));
interruptedState.status = "running";
interruptedState.last_completed_phase = "database_migrated";
write(interruptedStatePath, `${JSON.stringify(interruptedState, null, 2)}\n`);
const savedDashboard = join(interruptedInstall.current, ".aidr-upgrade/previous/dashboard");
mkdirSync(resolve(savedDashboard, ".."), { recursive: true });
renameSync(join(interruptedInstall.current, "dashboard"), savedDashboard);
const migrationsBeforeResume = readFileSync(migrateCount, "utf8");
run(interruptedInstall, "resume");
assert.equal(readFileSync(join(interruptedInstall.current, "dashboard/version.txt"), "utf8"), "target\n");
assert.equal(readFileSync(join(savedDashboard, "version.txt"), "utf8"), "current\n");
assert.equal(readFileSync(migrateCount, "utf8"), migrationsBeforeResume);
checks.push("resume finishes an interrupted component rename only when the saved source and staged target match preflight hashes");

const changedPrevious = createScenario("changed-previous");
run(changedPrevious, "preflight");
const changedStatePath = join(changedPrevious.current, ".aidr-upgrade/state.json");
const changedState = JSON.parse(readFileSync(changedStatePath, "utf8"));
changedState.status = "running";
changedState.last_completed_phase = "database_migrated";
write(changedStatePath, `${JSON.stringify(changedState, null, 2)}\n`);
const changedSavedDashboard = join(changedPrevious.current, ".aidr-upgrade/previous/dashboard");
mkdirSync(resolve(changedSavedDashboard, ".."), { recursive: true });
renameSync(join(changedPrevious.current, "dashboard"), changedSavedDashboard);
write(join(changedSavedDashboard, "version.txt"), "changed\n");
run(changedPrevious, "resume", false);
assert.equal(existsSync(join(changedPrevious.current, "dashboard")), false);
checks.push("resume refuses an interrupted component rename when the saved source hash changed");

run(valid, "rollback-plan");
const plan = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/rollback-plan.json"), "utf8"));
assert.equal(plan.strategy, "authenticated encrypted backup recovery into a new isolated project");
assert.equal(plan.command.arguments.includes("recover"), true);
assert.equal(plan.scope.includes("No in-place down-migration"), true);
checks.push("rollback plan is exact, restore-only and requires isolated acceptance before traffic cutover");

run(valid, "recover");
assert.equal(JSON.parse(readFileSync(join(valid.recovery, "recovery-receipt.json"), "utf8")).services_started, false);
assert.equal(JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/state.json"), "utf8")).status, "recovered");
checks.push("recover delegates to the authenticated backup API and creates a new stopped recovery project");

const doctorFailure = createScenario("doctor-failure");
const failDoctor = join(root, "fail-doctor");
write(failDoctor, "fail");
run(doctorFailure, "apply", false, { AIDR_TEST_DOCTOR_FAILURE: failDoctor });
const doctorFailedState = JSON.parse(readFileSync(join(doctorFailure.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(doctorFailedState.requires_restore, true);
assert.equal(doctorFailedState.last_completed_phase, "artifacts_installed");
rmSync(failDoctor);
run(doctorFailure, "resume");
assert.equal(JSON.parse(readFileSync(join(doctorFailure.current, ".aidr-upgrade/state.json"), "utf8")).status, "complete");
checks.push("failed online doctor drains target writers, requires restore and resumes by restarting services before recheck");

const tamperedArtifact = createScenario("tampered-artifact");
write(join(tamperedArtifact.target, "dashboard/version.txt"), "tampered\n");
run(tamperedArtifact, "preflight", false);
checks.push("target artifact tampering fails closed");

const untrackedArtifact = createScenario("untracked-artifact");
write(join(untrackedArtifact.target, "dashboard/untracked.js"), "unexpected\n");
run(untrackedArtifact, "preflight", false);
checks.push("untracked application artifacts fail closed");

const changedSupport = createScenario("changed-support-file");
write(join(changedSupport.target, "compose.yml"), "name: unexpected\nservices: {}\n");
run(changedSupport, "preflight", false);
checks.push("compose and agent support files are bound to the compatibility contract");

const dirtyTarget = createScenario("dirty-target", (scenario) => {
	const manifest = JSON.parse(readFileSync(join(scenario.target, "deployment.json"), "utf8"));
	manifest.source_has_changes = true;
	write(join(scenario.target, "deployment.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	scenario.contract.target_manifest_sha256 = fileSha(join(scenario.target, "deployment.json"));
	write(scenario.contractPath, `${JSON.stringify(scenario.contract, null, 2)}\n`);
});
run(dirtyTarget, "preflight", false);
checks.push("target candidate prepared from a dirty source tree is rejected");

const changedHistory = createScenario("changed-history", (scenario) => {
	write(join(scenario.target, "migrations/20260912000000_initial.sql"), "SELECT 11;\n");
	const manifest = JSON.parse(readFileSync(join(scenario.target, "deployment.json"), "utf8"));
	manifest.migrations[0].sha256 = fileSha(join(scenario.target, "migrations/20260912000000_initial.sql"));
	write(join(scenario.target, "deployment.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	scenario.contract.target_manifest_sha256 = fileSha(join(scenario.target, "deployment.json"));
	scenario.contract.target_migration_set_sha256 = migrationHash(manifest.migrations);
	write(scenario.contractPath, `${JSON.stringify(scenario.contract, null, 2)}\n`);
});
run(changedHistory, "preflight", false);
checks.push("rewritten migration history is rejected even when candidate hashes are internally consistent");

const auditedCompatibility = createScenario("audited-compatibility", (scenario) => {
	const name = "20260916000003_policy_document_draft_cas.sql";
	const targetSql = readFileSync(join(process.cwd(), "supabase/migrations", name), "utf8");
	const installedSql = targetSql
		.replace("before applying this migration.", "before entering this transaction.")
		.replace("-- compilation with direct table writes. Read/delete policies are unchanged.\n\n", "-- compilation with direct table writes. Read/delete policies are unchanged.\nbegin;\n\n")
		.replace(/\n$/, "\n\ncommit;\n");
	for (const [directory, sql] of [[scenario.current, installedSql], [scenario.target, targetSql]]) {
		for (const oldName of ["20260912000000_initial.sql", "20260913000000_upgrade.sql"]) {
			rmSync(join(directory, "migrations", oldName), { force: true });
		}
		write(join(directory, "migrations", name), sql);
		const manifestPath = join(directory, "deployment.json");
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
		manifest.migrations = [{ name, sha256: fileSha(join(directory, "migrations", name)) }];
		write(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
	}
	scenario.currentManifest.migrations = JSON.parse(readFileSync(join(scenario.current, "deployment.json"), "utf8")).migrations;
	scenario.targetManifest.migrations = JSON.parse(readFileSync(join(scenario.target, "deployment.json"), "utf8")).migrations;
	scenario.contract.current_manifest_sha256 = fileSha(join(scenario.current, "deployment.json"));
	scenario.contract.target_manifest_sha256 = fileSha(join(scenario.target, "deployment.json"));
	scenario.contract.current_migration_set_sha256 = migrationHash(scenario.currentManifest.migrations);
	scenario.contract.target_migration_set_sha256 = migrationHash(scenario.targetManifest.migrations);
	write(scenario.contractPath, `${JSON.stringify(scenario.contract, null, 2)}\n`);
});
run(auditedCompatibility, "preflight");
checks.push("the exact audited legacy transaction-wrapper migration remains upgrade-compatible");

const unorderedHistory = createScenario("unordered-history", (scenario) => {
	const name = "20260914000000_upgrade_two.sql";
	write(join(scenario.target, "migrations", name), "SELECT 2;\n");
	const manifest = JSON.parse(readFileSync(join(scenario.target, "deployment.json"), "utf8"));
	manifest.migrations.splice(1, 0, { name, sha256: fileSha(join(scenario.target, "migrations", name)) });
	write(join(scenario.target, "deployment.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	scenario.contract.target_manifest_sha256 = fileSha(join(scenario.target, "deployment.json"));
	scenario.contract.target_migration_set_sha256 = migrationHash(manifest.migrations);
	write(scenario.contractPath, `${JSON.stringify(scenario.contract, null, 2)}\n`);
});
run(unorderedHistory, "preflight", false);
checks.push("out-of-order appended migrations are rejected before a dry run");

const wrongSource = createScenario("wrong-backup-source", (scenario) => {
	const envelope = JSON.parse(readFileSync(join(scenario.backup, "backup.json"), "utf8"));
	const payload = JSON.parse(envelope.payload);
	payload.source_project = "other-customer";
	envelope.payload = JSON.stringify(payload);
	write(join(scenario.backup, "backup.json"), JSON.stringify(envelope));
});
run(wrongSource, "preflight", false);
checks.push("authenticated backup from another project is rejected");

const staleBackup = createScenario("stale-backup", (scenario) => {
	const envelope = JSON.parse(readFileSync(join(scenario.backup, "backup.json"), "utf8"));
	const payload = JSON.parse(envelope.payload);
	payload.started_at = new Date(Date.now() - 25 * 3_600_000).toISOString();
	envelope.payload = JSON.stringify(payload);
	write(join(scenario.backup, "backup.json"), JSON.stringify(envelope));
});
run(staleBackup, "preflight", false);
checks.push("old backup recovery point fails the freshness window even when completion is recent");

const missingRecoveryPoint = createScenario("missing-recovery-point", (scenario) => {
	const envelope = JSON.parse(readFileSync(join(scenario.backup, "backup.json"), "utf8"));
	const payload = JSON.parse(envelope.payload);
	delete payload.started_at;
	envelope.payload = JSON.stringify(payload);
	write(join(scenario.backup, "backup.json"), JSON.stringify(envelope));
});
run(missingRecoveryPoint, "preflight", false);
checks.push("backup without authenticated recovery point fails closed");

const incompatible = createScenario("incompatible-contract", (scenario) => {
	scenario.contract.target_app_compatible_with_target_schema = false;
	write(scenario.contractPath, `${JSON.stringify(scenario.contract, null, 2)}\n`);
});
run(incompatible, "preflight", false);
checks.push("unapproved app/database compatibility fails closed");

const changedEvidence = createScenario("changed-evidence");
write(changedEvidence.evidencePath, "changed\n");
run(changedEvidence, "preflight", false);
checks.push("changed compatibility evidence fails closed");

const missingEnv = createScenario("missing-env", (scenario) => {
	scenario.contract.required_env_keys.push("NEW_REQUIRED_SECRET");
	write(scenario.contractPath, `${JSON.stringify(scenario.contract, null, 2)}\n`);
});
run(missingEnv, "preflight", false);
checks.push("missing target-required environment keys fail before maintenance");

const badBackup = createScenario("backup-verifier-failure");
const failBackup = join(root, "fail-backup");
write(failBackup, "fail");
run(badBackup, "preflight", false, { AIDR_TEST_BACKUP_FAILURE: failBackup });
checks.push("encrypted backup verifier failure blocks preflight");

const nested = createScenario("nested");
const nestedResult = spawnSync(
	process.execPath,
	[
		join(toolDir, "deployment-upgrade.mjs"),
		"preflight",
		"--current",
		nested.current,
		"--target",
		join(nested.current, "target"),
		"--backup",
		nested.backup,
		"--key-file",
		nested.key,
		"--contract",
		nested.contractPath,
	],
	{ encoding: "utf8", env: baseEnv },
);
assert.notEqual(nestedResult.status, 0);
checks.push("nested source/target paths are rejected");

for (const phase of ["writers_stopped", "migration_dry_run"]) {
	const scenario = createScenario(`resume-valid-${phase}`);
	run(scenario, "preflight");
	const statePath = saveInterruptedPhase(scenario, phase);
	writeFileSync(dockerLog, "");
	run(scenario, "resume");
	assert.equal(JSON.parse(readFileSync(statePath, "utf8")).status, "complete");
	const dockerCalls = readFileSync(dockerLog, "utf8");
	assert.doesNotMatch(dockerCalls, / stop /);
	assert.equal(dockerCalls.includes(" psql "), phase === "writers_stopped");
	checks.push(`${phase} resume revalidates and completes without repeating writer drain`);
}

if (process.platform !== "win32") {
	const verifySignal = createScenario("backup-reverify-signal");
	run(verifySignal, "preflight");
	const verifierMarker = join(root, "backup-verifier-not-stopped");
	writeFileSync(dockerLog, "");
	const verifySignalRun = run(verifySignal, "apply", false, { AIDR_TEST_BACKUP_SIGNAL: "SIGINT", AIDR_TEST_BACKUP_SIGNAL_MARKER: verifierMarker });
	assert.equal(verifySignalRun.status, 130);
	assert.equal(existsSync(verifierMarker), false);
	assert.equal(readFileSync(dockerLog, "utf8"), "");
	const verifySignalState = JSON.parse(readFileSync(join(verifySignal.current, ".aidr-upgrade/state.json"), "utf8"));
	assert.equal(verifySignalState.last_completed_phase, "preflight");
	assert.equal(verifySignalState.requires_restore, false);
	checks.push("SIGINT during backup re-verification stops the verifier and exits 130 before any Docker call or writer drain");

	const migrationSignal = createScenario("migration-signal");
	run(migrationSignal, "preflight");
	writeFileSync(dockerLog, "");
	const migrationsBeforeSignal = Number(migrationRuns());
	const migrationSignalRun = run(migrationSignal, "apply", false, { AIDR_TEST_MIGRATE_SIGNAL: "SIGTERM" });
	assert.equal(migrationSignalRun.status, 143);
	assert.equal(Number(migrationRuns()), migrationsBeforeSignal + 1);
	const migrationSignalCalls = readFileSync(dockerLog, "utf8");
	assert.doesNotMatch(migrationSignalCalls, / up /);
	assert.doesNotMatch(migrationSignalCalls, / start /);
	const migrationSignalState = JSON.parse(readFileSync(join(migrationSignal.current, ".aidr-upgrade/state.json"), "utf8"));
	assert.equal(migrationSignalState.last_completed_phase, "database_migrated");
	assert.equal(migrationSignalState.requires_restore, false);
	assert.equal(migrationSignalState.interrupted_by, "SIGTERM");
	assert.equal(readFileSync(join(migrationSignal.current, "dashboard/version.txt"), "utf8"), "current\n");
	run(migrationSignal, "resume");
	assert.equal(Number(migrationRuns()), migrationsBeforeSignal + 1);
	assert.equal(JSON.parse(readFileSync(join(migrationSignal.current, ".aidr-upgrade/state.json"), "utf8")).status, "complete");
	checks.push("SIGTERM during the atomic migration lets it finish, keeps writers drained, exits 143 and resumes without re-migrating");
}

const evidence = { passed: true, checked_at: new Date().toISOString(), checks, scope: "Isolated deterministic upgrade orchestration tests with process doubles; not a customer database or traffic cutover." };
write(join(root, "evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`${checks.length} deployment-upgrade checks passed. Evidence: ${join(root, "evidence.json")}`);
