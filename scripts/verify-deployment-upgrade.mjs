#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
cpSync("scripts/deployment-upgrade.mjs", join(toolDir, "deployment-upgrade.mjs"));

const backupStub = `
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const args=process.argv.slice(2), action=args[0], value=(name)=>args[args.indexOf(name)+1];
const marker=process.env.AIDR_TEST_BACKUP_FAILURE;
if(marker&&existsSync(marker)) process.exit(41);
if(!existsSync(value("--key-file"))||!existsSync(join(value("--backup"),"backup.json"))) process.exit(42);
if(action==="recover") { const output=value("--output"); if(existsSync(output)) process.exit(43); mkdirSync(output,{recursive:true}); writeFileSync(join(output,"recovery-receipt.json"),JSON.stringify({services_started:false})); }
else if(action!=="verify") process.exit(44);
`;
const migrateStub = `
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
const deployment=process.argv[2], count=process.env.AIDR_TEST_MIGRATE_COUNT;
writeFileSync(count,String((Number(existsSync(count)?readFileSync(count,"utf8"):"0")||0)+1));
const fail=process.env.AIDR_TEST_MIGRATE_FAILURE;
if(fail&&existsSync(fail)){unlinkSync(fail);process.exit(51)}
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
	`import { appendFileSync, writeFileSync } from "node:fs";
let input="";for await(const chunk of process.stdin)input+=chunk;
const args=process.argv.slice(2);appendFileSync(process.env.AIDR_TEST_DOCKER_LOG,args.join(" ")+"\\n");
if(args.includes("psql"))writeFileSync(process.env.AIDR_TEST_SQL_LOG,input);
if(args.includes("ps")&&args.includes("--services"))process.stdout.write("db\\ndashboard\\nfunctions\\n");
`,
);

const sha = (value) => createHash("sha256").update(value).digest("hex");
const fileSha = (path) => sha(readFileSync(path));
const migrationHash = (entries) => sha(entries.map((entry) => `${entry.name}\0${entry.sha256}\n`).join(""));
const write = (path, value) => {
	mkdirSync(resolve(path, ".."), { recursive: true });
	writeFileSync(path, value);
};

function createDeployment(path, kind, options = {}) {
	mkdirSync(join(path, "dashboard"), { recursive: true });
	mkdirSync(join(path, "volumes/functions/example"), { recursive: true });
	mkdirSync(join(path, "volumes/api"), { recursive: true });
	mkdirSync(join(path, "migrations"), { recursive: true });
	write(join(path, "dashboard/version.txt"), `${kind}\n`);
	write(join(path, "volumes/functions/example/index.ts"), `export const version = "${kind}";\n`);
	write(join(path, "volumes/api/config.yml"), `version: ${kind}\n`);
	const firstSql = options.changedFirst ? "SELECT 11;\n" : "SELECT 1;\n";
	write(join(path, "migrations/20260912000000_initial.sql"), firstSql);
	if (kind === "target") write(join(path, "migrations/20260913000000_upgrade.sql"), "CREATE TABLE IF NOT EXISTS public.upgrade_probe(id integer);\n");
	write(join(path, "agent-config.json"), JSON.stringify({ version: kind }));
	write(join(path, "compose.yml"), `name: ${kind}-project\nservices:\n  db: {}\n  dashboard: {}\n  functions: {}\n`);
	write(join(path, ".env"), "ANON_KEY=private\nSERVICE_ROLE_KEY=private\n");
	write(join(path, ".env.functions"), "AIDR_SIGNING_KEY=private\n");
	const migrations = ["20260912000000_initial.sql", ...(kind === "target" ? ["20260913000000_upgrade.sql"] : [])].map((name) => ({ name, sha256: fileSha(join(path, "migrations", name)) }));
	const artifactPaths = ["dashboard/version.txt", "volumes/functions/example/index.ts"];
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

function createScenario(name, mutate = () => {}) {
	const dir = join(root, name);
	const current = join(dir, "current");
	const target = join(dir, "target");
	const backup = join(dir, "backup");
	const contractDir = join(dir, "contract");
	const key = join(dir, "recovery.key");
	const contractPath = join(contractDir, "upgrade-compatibility.json");
	const evidencePath = join(contractDir, "acceptance.json");
	const recovery = join(dir, "recovery");
	const currentManifest = createDeployment(current, "current");
	const targetManifest = createDeployment(target, "target");
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
		required_function_env_keys: ["AIDR_SIGNING_KEY"],
		current_support_files: ["agent-config.json", "compose.yml"].map((path) => ({ path, sha256: fileSha(join(current, path)) })),
		target_support_files: ["agent-config.json", "compose.yml"].map((path) => ({ path, sha256: fileSha(join(target, path)) })),
		approved_by: "Release Owner",
		approved_at: new Date().toISOString(),
		acceptance_evidence: [{ path: "acceptance.json", sha256: fileSha(evidencePath) }],
	};
	write(contractPath, `${JSON.stringify(contract, null, 2)}\n`);
	const scenario = { dir, current, target, backup, key, contractPath, evidencePath, recovery, contract, currentManifest, targetManifest };
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
			...(["apply", "resume", "recover"].includes(action) ? ["--maintenance"] : []),
			...extraArgs,
		],
		{ encoding: "utf8", timeout: 180_000, env: { ...baseEnv, ...extraEnv } },
	);
	assert.equal(result.status === 0, expectedSuccess, `${action} unexpected exit ${result.status}: ${result.stderr}`);
	return result;
}

const checks = [];
const valid = createScenario("valid");
run(valid, "preflight");
const ready = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(ready.status, "ready");
assert.equal(ready.current_manifest_sha256, valid.contract.current_manifest_sha256);
assert.equal(ready.target_manifest_sha256, valid.contract.target_manifest_sha256);
assert.equal(ready.checks.length, 5);
const backupMonitoring = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/monitoring/backup.json"), "utf8"));
assert.deepEqual(Object.keys(backupMonitoring).slice(0, 4), ["schema_version", "status", "completed_at", "verified_at"]);
assert.equal(backupMonitoring.status, "ok");
checks.push("preflight binds exact current/target manifests, artifacts, compatibility evidence and backup");
checks.push("verified backup readiness is published atomically with the monitoring status/time contract");

const loggedSql = readFileSync(sqlLog, "utf8");
assert.match(loggedSql, /pg_try_advisory_xact_lock\(9112026\)/);
assert.match(loggedSql, /20260913000000_upgrade/);
assert.match(loggedSql, /ROLLBACK;/);
checks.push("migration candidate executes under the production advisory lock and rolls back during dry-run");

const failOnce = join(root, "fail-migrate-once");
write(failOnce, "fail");
run(valid, "apply", false, { AIDR_TEST_MIGRATE_FAILURE: failOnce });
const failed = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(failed.status, "failed");
assert.equal(failed.requires_restore, false);
assert.ok(existsSync(join(valid.current, ".aidr-upgrade/rollback-plan.json")));
assert.ok(!existsSync(join(valid.current, ".aidr-upgrade/migration-stage/.env")));
checks.push("failed atomic migration leaves source artifacts intact, removes staged secret copy and emits rollback plan");

run(valid, "resume");
const complete = JSON.parse(readFileSync(join(valid.current, ".aidr-upgrade/state.json"), "utf8"));
assert.equal(complete.status, "complete");
assert.equal(readFileSync(join(valid.current, "dashboard/version.txt"), "utf8"), "target\n");
assert.equal(readFileSync(join(valid.current, ".env"), "utf8"), "ANON_KEY=private\nSERVICE_ROLE_KEY=private\n");
assert.equal(JSON.parse(readFileSync(join(valid.current, "deployment.json"), "utf8")).project_name, "customer-project");
assert.equal(readFileSync(migrateCount, "utf8"), "2");
assert.equal(readFileSync(doctorCount, "utf8"), "1");
assert.ok(existsSync(join(valid.current, ".aidr-upgrade/upgrade-receipt.json")));
checks.push("resume completes migration, artifact switch, service start and online doctor without replacing customer secrets or project identity");

run(valid, "resume");
assert.equal(readFileSync(migrateCount, "utf8"), "2");
assert.equal(readFileSync(doctorCount, "utf8"), "1");
checks.push("completed upgrade resume is idempotent");

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
	payload.completed_at = new Date(Date.now() - 25 * 3_600_000).toISOString();
	envelope.payload = JSON.stringify(payload);
	write(join(scenario.backup, "backup.json"), JSON.stringify(envelope));
});
run(staleBackup, "preflight", false);
checks.push("backup outside the approved freshness window is rejected");

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

const evidence = { passed: true, checked_at: new Date().toISOString(), checks, scope: "Isolated deterministic upgrade orchestration tests with process doubles; not a customer database or traffic cutover." };
write(join(root, "evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`${checks.length} deployment-upgrade checks passed. Evidence: ${join(root, "evidence.json")}`);
