// Tests for scripts/onprem-upgrade.mjs (node --test).
//
// The orchestration runs the real scripts/deployment-upgrade.mjs (check,
// preflight, apply, resume) against fixture installations. Docker, the
// encrypted backup, the migration runner and the doctor are replaced by small
// test doubles, the same seams scripts/verify-deployment-upgrade.mjs uses,
// because this environment has no Docker daemon or Postgres.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { appendFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { buildPlan, classifyApplyFailure, parseOptions, refusalReasons, runChildProcess, runUpgrade, STAGES } from "./onprem-upgrade.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = mkdtempSync(join(tmpdir(), "aidr-onprem-upgrade-"));
after(() => rmSync(root, { recursive: true, force: true }));

const toolDir = join(root, "tools");
mkdirSync(join(toolDir, "lib"), { recursive: true });
cpSync(join(here, "deployment-upgrade.mjs"), join(toolDir, "deployment-upgrade.mjs"));
cpSync(join(here, "lib/migration-contract.mjs"), join(toolDir, "lib/migration-contract.mjs"));
cpSync(join(here, "lib/migration-hash-compat.mjs"), join(toolDir, "lib/migration-hash-compat.mjs"));

// Test doubles. Every one appends its action to AIDR_TEST_CALL_LOG.
writeFileSync(join(toolDir, "deployment-backup.mjs"), `
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const args=process.argv.slice(2), action=args[0], value=(name)=>args[args.indexOf(name)+1];
appendFileSync(process.env.AIDR_TEST_CALL_LOG, "backup:"+action+"\\n");
const fail=process.env.AIDR_TEST_BACKUP_FAIL; if(fail&&fail===action) process.exit(41);
if(!existsSync(value("--key-file"))) process.exit(42);
if(action==="backup"){
  const deployment=JSON.parse(readFileSync(join(value("--deployment"),"deployment.json"),"utf8"));
  const out=value("--output"); if(existsSync(out)) process.exit(43); mkdirSync(out);
  const now=new Date().toISOString();
  writeFileSync(join(out,"backup.json"),JSON.stringify({payload:JSON.stringify({type:"aidr-cold-volumes",source_project:deployment.project_name,source_commit:deployment.source_commit,started_at:now,completed_at:now}),hmac_sha256:"test-double"}));
} else if(action==="verify"){ if(!existsSync(join(value("--backup"),"backup.json"))) process.exit(44); }
else process.exit(45);
`);
writeFileSync(join(toolDir, "deployment-migrate.mjs"), `
import { appendFileSync } from "node:fs";
appendFileSync(process.env.AIDR_TEST_CALL_LOG, "migrate\\n");
`);
writeFileSync(join(toolDir, "deployment-doctor.mjs"), `
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
const args=process.argv.slice(2), deployment=args[args.indexOf("--deployment")+1];
appendFileSync(process.env.AIDR_TEST_CALL_LOG, "doctor\\n");
if(!args.includes("--online")) process.exit(61);
const fail=process.env.AIDR_TEST_DOCTOR_FAIL; if(fail&&existsSync(fail)) process.exit(63);
const version=readFileSync(deployment+"/dashboard/version.txt","utf8").trim();
writeFileSync(deployment+"/doctor-evidence.json",JSON.stringify({checked_at:new Date().toISOString(),passed:version==="target",online:true}));
if(version!=="target") process.exit(62);
`);
const dockerDriver = join(toolDir, "docker-driver.mjs");
writeFileSync(dockerDriver, `
import { appendFileSync, existsSync, unlinkSync } from "node:fs";
let input="";for await(const chunk of process.stdin)input+=chunk;
const args=process.argv.slice(2);
appendFileSync(process.env.AIDR_TEST_CALL_LOG, "docker:"+args.filter((a)=>["ps","stop","start","up","exec"].includes(a)).join(",")+"\\n");
if(args.includes("psql")){const fail=process.env.AIDR_TEST_DRY_RUN_FAIL;if(fail&&existsSync(fail)){unlinkSync(fail);process.exit(71)}}
if(args.includes("ps")&&args.includes("--services"))process.stdout.write("db\\ndashboard\\nfunctions\\n");
`);

const sha = (value) => createHash("sha256").update(value).digest("hex");
const fileSha = (path) => sha(readFileSync(path));
const signing = generateKeyPairSync("ed25519");
const signingPrivate = signing.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
const signingPublicPem = signing.publicKey.export({ type: "spki", format: "pem" });
const write = (path, value) => {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, value);
};

function createDeployment(path, kind) {
	for (const dir of ["dashboard", "ingress", "backup", "maintenance", "auth-templates", "volumes/functions/example", "migrations"]) mkdirSync(join(path, dir), { recursive: true });
	const artifacts = ["dashboard/version.txt", "ingress/version.txt", "backup/version.txt", "maintenance/version.txt", "auth-templates/recovery.html", "volumes/functions/example/index.ts"];
	for (const artifact of artifacts) write(join(path, artifact), `${kind}\n`);
	write(join(path, "migrations/20260912000000_initial.sql"), "SELECT 1;\n");
	if (kind === "target") write(join(path, "migrations/20260913000000_upgrade.sql"), "CREATE TABLE IF NOT EXISTS public.upgrade_probe(id integer);\n");
	write(join(path, "agent-config.json"), JSON.stringify({ version: kind, licensing: { public_keys_pem: [signingPublicPem] } }));
	write(join(path, "compose.yml"), `name: ${kind}-project\nservices:\n  db: {}\n  dashboard: {}\n  functions: {}\n`);
	write(join(path, ".env"), "ANON_KEY=private\nSERVICE_ROLE_KEY=private\n");
	write(join(path, ".env.functions"), `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivate}\nAIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64=${signingPrivate}\n`);
	write(join(path, ".env.ingress"), "AIDR_DEVICE_START_INGRESS_SECRET=private\n");
	mkdirSync(join(path, "health"), { recursive: true });
	const migrations = ["20260912000000_initial.sql", ...(kind === "target" ? ["20260913000000_upgrade.sql"] : [])].map((name) => ({ name, sha256: fileSha(join(path, "migrations", name)) }));
	const manifest = {
		schema_version: 1,
		project_name: kind === "current" ? "customer-project" : "candidate-project",
		mode: "self-hosted",
		development: true,
		source_commit: (kind === "current" ? "a" : "b").repeat(40),
		source_has_changes: false,
		upstream_sha: "c".repeat(40),
		dashboard_url: "http://localhost:8080",
		supabase_url: "http://localhost:8000",
		dashboard_image: `aidr-dashboard:${kind === "current" ? "0.6.0" : "0.6.1"}`,
		migrations,
		artifacts: artifacts.map((artifact) => ({ path: artifact, sha256: fileSha(join(path, artifact)) })),
	};
	write(join(path, "deployment.json"), `${JSON.stringify(manifest, null, 2)}\n`);
	return manifest;
}

let scenarioCount = 0;
function scenario() {
	const dir = join(root, `scenario-${scenarioCount++}`);
	const current = join(dir, "srv", "aidr");
	const target = join(dir, "srv", "aidr-target");
	const currentManifest = createDeployment(current, "current");
	const targetManifest = createDeployment(target, "target");
	const contractDir = join(dir, "secure", "aidr-upgrade");
	const evidence = join(contractDir, "rehearsal.json");
	write(evidence, "{\"passed\":true}\n");
	const migrationSet = (entries) => sha(entries.map((entry) => `${entry.name}\0${entry.sha256}\n`).join(""));
	const contract = join(contractDir, "upgrade-compatibility.json");
	write(contract, JSON.stringify({
		schema_version: 1,
		current_manifest_sha256: fileSha(join(current, "deployment.json")),
		target_manifest_sha256: fileSha(join(target, "deployment.json")),
		current_migration_set_sha256: migrationSet(currentManifest.migrations),
		target_migration_set_sha256: migrationSet(targetManifest.migrations),
		current_app_compatible_with_current_schema: true,
		target_app_compatible_with_target_schema: true,
		target_schema_accepts_existing_data: true,
		migrations_transactional: true,
		required_env_keys: ["ANON_KEY"],
		required_function_env_keys: [],
		required_ingress_env_keys: [],
		current_support_files: ["agent-config.json", "compose.yml"].map((path) => ({ path, sha256: fileSha(join(current, path)) })),
		target_support_files: ["agent-config.json", "compose.yml"].map((path) => ({ path, sha256: fileSha(join(target, path)) })),
		approved_by: "Release Owner",
		approved_at: new Date().toISOString(),
		acceptance_evidence: [{ path: "rehearsal.json", sha256: fileSha(evidence) }],
	}));
	const keyFile = join(dir, "secure", "aidr-recovery.key");
	write(keyFile, `${"1".repeat(64)}\n`);
	const backupRoot = join(dir, "backups");
	mkdirSync(backupRoot);
	const log = join(dir, "calls.log");
	writeFileSync(log, "");
	return { dir, current, target, contract, keyFile, backupRoot, log };
}

function optionsFor(s, extra = []) {
	return parseOptions([
		"--to", s.target, "--current", s.current, "--contract", s.contract, "--key-file", s.keyFile,
		"--backup-root", s.backupRoot, "--recovery-journal", join(s.dir, "journal.json"), "--recovery-output", join(s.dir, "recovery"),
		...extra,
	], {});
}

const html = () => Promise.resolve({ status: 200, headers: new Headers({ "content-type": "text/html; charset=utf-8" }) });

async function upgrade(s, { extra = [], env = {}, failStage = null, fetch = html } = {}) {
	const lines = [];
	const stages = [];
	const childEnv = { ...process.env, NODE_ENV: "test", AIDR_UPGRADE_TEST_DOCKER_DRIVER: dockerDriver, AIDR_TEST_CALL_LOG: s.log, ...env };
	const result = await runUpgrade(optionsFor(s, extra), {
		scriptsDir: toolDir,
		env: childEnv,
		fetch,
		out: (line) => lines.push(line),
		runChild: async (argv, options) => {
			const script = argv[1].split(/[\\/]/).at(-1);
			const stage = `${script.replace(/^deployment-|\.mjs$/g, "")}:${argv[2]}`;
			stages.push(stage);
			appendFileSync(s.log, `orchestrator ${stage}\n`);
			if (failStage === stage) return { code: 1, started: true, stdout: "" };
			return runChildProcess(argv, options);
		},
	});
	return { result, output: lines.join("\n"), stages, calls: readFileSync(s.log, "utf8").trim().split("\n") };
}

const version = (path) => readFileSync(join(path, "dashboard/version.txt"), "utf8").trim();

test("runs every step in order and writes a complete receipt", async () => {
	const s = scenario();
	const { result, output, stages, calls } = await upgrade(s);
	assert.equal(result.status, "complete", output);
	assert.deepEqual(stages, ["upgrade:check", "backup:backup", "backup:verify", "upgrade:preflight", "upgrade:apply", "doctor:--deployment"]);
	assert.deepEqual(result.receipt.stages.map((entry) => [entry.stage, entry.status]), [
		["check", "passed"], ["backup", "passed"], ["verify", "passed"], ["preflight", "passed"],
		["apply", "passed"], ["restart", "passed-in-apply"], ["doctor", "passed"], ["smoke", "passed"],
	]);
	// Inside apply: writers stopped, dry-run, atomic migration, target start, doctor.
	const apply = calls.slice(calls.indexOf("orchestrator upgrade:apply"), calls.indexOf("orchestrator doctor:--deployment"));
	const order = ["docker:ps", "docker:stop", "docker:exec", "migrate", "docker:up", "doctor"].map((entry) => apply.indexOf(entry));
	assert.ok(order.every((index, i) => index >= 0 && (i === 0 || index > order[i - 1])), apply.join(" | "));
	assert.equal(version(s.current), "target");
	const receipt = JSON.parse(readFileSync(join(s.current, ".aidr-upgrade/onprem-upgrade-receipt.json"), "utf8"));
	assert.equal(receipt.status, "complete");
	assert.equal(receipt.from.migrations, 1);
	assert.equal(receipt.to.migrations, 2);
	assert.match(receipt.upgrade_receipt_sha256, /^[a-f0-9]{64}$/);
	assert.match(output, /0\.6\.0 -> |Current 0\.6\.0, new 0\.6\.1/);
	assert.match(output, /Upgrade complete/);
});

test("stops at a failed backup without touching the installation", async () => {
	const s = scenario();
	const { result, output, stages } = await upgrade(s, { env: { AIDR_TEST_BACKUP_FAIL: "backup" } });
	assert.equal(result.status, "failed");
	assert.equal(result.failure.stage, "backup");
	assert.deepEqual(stages, ["upgrade:check", "backup:backup"]);
	assert.equal(version(s.current), "current");
	assert.equal(existsSync(join(s.current, ".aidr-upgrade/state.json")), false);
	assert.match(output, /step 2\/8/);
	assert.match(output, /deployment-backup\.mjs recover-services --deployment \S+ --recovery-journal/);
	assert.equal(JSON.parse(readFileSync(join(s.current, ".aidr-upgrade/onprem-upgrade-receipt.json"), "utf8")).failed_stage, "backup");
});

test("a failed preflight changes nothing and offers to reuse the verified backup", async () => {
	const s = scenario();
	const { result, output, stages } = await upgrade(s, { failStage: "upgrade:preflight" });
	assert.equal(result.failure.stage, "preflight");
	assert.deepEqual(stages, ["upgrade:check", "backup:backup", "backup:verify", "upgrade:preflight"]);
	assert.match(output, /Nothing was changed/);
	assert.match(output, new RegExp(`--backup ${result.receipt.backup.replaceAll("/", "\\/")}`));
	assert.equal(version(s.current), "current");
});

test("a failure before the schema commit restarts the old version and is resumable", async () => {
	const s = scenario();
	const marker = join(s.dir, "fail-dry-run");
	writeFileSync(marker, "1");
	const failed = await upgrade(s, { env: { AIDR_TEST_DRY_RUN_FAIL: marker } });
	assert.equal(failed.result.failure.stage, "apply");
	assert.equal(failed.result.failure.situation, "pre-commit");
	assert.match(failed.output, /database was not changed/);
	assert.match(failed.output, /What went wrong: deployment-upgrade\.mjs: locked migration dry-run failed/);
	assert.match(failed.output, /--resume/);
	assert.equal(version(s.current), "current");
	assert.ok(failed.calls.includes("docker:start"), "the previous services are started again");

	const resumed = await upgrade(s, { extra: ["--resume"] });
	assert.equal(resumed.result.status, "complete", resumed.output);
	assert.deepEqual(resumed.stages, ["upgrade:resume", "doctor:--deployment"]);
	assert.deepEqual(resumed.result.receipt.stages.filter((entry) => entry.status === "skipped").map((entry) => entry.stage), ["check", "backup", "verify", "preflight"]);
	assert.equal(version(s.current), "target");
});

test("a doctor failure after the schema commit points to resume and the isolated restore, never an automatic one", async () => {
	const s = scenario();
	const marker = join(s.dir, "fail-doctor");
	writeFileSync(marker, "1");
	const { result, output } = await upgrade(s, { env: { AIDR_TEST_DOCTOR_FAIL: marker } });
	assert.equal(result.failure.stage, "doctor");
	assert.equal(result.failure.situation, "post-commit");
	assert.match(output, /step 7\/8/);
	assert.match(output, /What went wrong: deployment-upgrade\.mjs: online deployment doctor failed/);
	assert.match(output, /deployment-upgrade\.mjs recover --current/);
	assert.match(output, /--recovery-runtime/);
	assert.match(output, /No automatic restore/);
	assert.ok(existsSync(join(s.current, ".aidr-upgrade/rollback-plan.json")));
	assert.deepEqual(result.receipt.stages.map((entry) => entry.stage), ["check", "backup", "verify", "preflight", "apply", "restart"]);

	// The live manifest is already the target's; --resume continues without the pre-upgrade check.
	rmSync(marker);
	const resumed = await upgrade(s, { extra: ["--resume"] });
	assert.equal(resumed.result.status, "complete", resumed.output);
	assert.deepEqual(resumed.stages, ["upgrade:resume", "doctor:--deployment"]);
	assert.equal(version(s.current), "target");

	const again = await upgrade(s, { extra: ["--resume"] });
	assert.equal(again.result.status, "complete", again.output);
	assert.match(again.output, /already completed/);
});

test("--resume refuses when there is nothing to continue or it belongs to another target", async () => {
	const s = scenario();
	const nothing = await upgrade(s, { extra: ["--resume"] });
	assert.equal(nothing.result.failure.stage, "check");
	assert.match(nothing.output, /no unfinished upgrade/);
	assert.deepEqual(nothing.stages, []);
	mkdirSync(join(s.current, ".aidr-upgrade"), { recursive: true });
	writeFileSync(join(s.current, ".aidr-upgrade/state.json"), JSON.stringify({ schema_version: 1, status: "failed", paths: { target: "/srv/other" } }));
	const other = await upgrade(s, { extra: ["--resume"] });
	assert.match(other.output, /was for \/srv\/other/);
	assert.deepEqual(other.stages, []);
});

test("a failed post-upgrade check reports an installed but unhealthy release", async () => {
	const s = scenario();
	const { result, output } = await upgrade(s, { fetch: () => Promise.resolve({ status: 503, headers: new Headers({ "content-type": "text/plain" }) }), extra: ["--lang", "tr"] });
	assert.equal(result.failure.stage, "smoke");
	assert.match(output, /8\/8\. adımda durdu/);
	assert.match(output, /Yeni sürüm kuruldu ve çalışıyor/);
	assert.match(output, /HTTP 503/);
	assert.equal(version(s.current), "target");
});

test("a finished earlier upgrade is archived; an unfinished one is resumed, not overwritten", async () => {
	const s = scenario();
	mkdirSync(join(s.current, ".aidr-upgrade"), { recursive: true });
	writeFileSync(join(s.current, ".aidr-upgrade/state.json"), JSON.stringify({ schema_version: 1, status: "failed", last_completed_phase: "preflight", paths: { target: s.target } }));
	const unfinished = await upgrade(s);
	assert.equal(unfinished.result.failure.stage, "check");
	assert.deepEqual(unfinished.stages, ["upgrade:check"]);
	assert.match(unfinished.output, /did not finish \(status failed, last step preflight\)/);
	assert.match(unfinished.output, /--resume/);

	writeFileSync(join(s.current, ".aidr-upgrade/state.json"), JSON.stringify({ schema_version: 1, status: "complete", last_completed_phase: "doctor_passed", completed_at: "2026-09-01T10:00:00.000Z", paths: { target: "/srv/older" } }));
	mkdirSync(join(s.current, ".aidr-upgrade/previous/dashboard"), { recursive: true });
	const next = await upgrade(s);
	assert.equal(next.result.status, "complete", next.output);
	const history = readdirSync(join(s.current, ".aidr-upgrade/history"));
	assert.deepEqual(history, ["20260901T100000000Z"]);
	assert.ok(existsSync(join(s.current, ".aidr-upgrade/history", history[0], "previous/dashboard")));
});

test("--dry-run prints the eight steps with their commands and runs nothing", () => {
	const s = scenario();
	const result = spawnSync(process.execPath, [join(here, "onprem-upgrade.mjs"), "--to", s.target, "--current", s.current, "--contract", s.contract, "--key-file", s.keyFile, "--backup-root", s.backupRoot, "--dry-run"], { encoding: "utf8", env: { ...process.env, AIDR_LANG: "en" } });
	assert.equal(result.status, 0, result.stderr);
	for (const [index, phrase] of ["Check that the new release", "encrypted backup", "Verify the backup", "Final checks", "one transaction", "Start the new version", "health check", "Post-upgrade checks"].entries()) {
		assert.match(result.stdout, new RegExp(`${index + 1}\\. .*${phrase}`));
	}
	assert.match(result.stdout, /deployment-upgrade\.mjs check --current/);
	assert.match(result.stdout, /deployment-backup\.mjs backup --deployment .* --maintenance/);
	assert.match(result.stdout, /deployment-upgrade\.mjs apply .* --maintenance/);
	assert.equal(readFileSync(s.log, "utf8"), "");
	assert.equal(existsSync(join(s.current, ".aidr-upgrade")), false);
	assert.deepEqual(readdirSync(s.backupRoot), []);
});

test("refuses the live directory, nested or used targets and missing inputs", () => {
	const s = scenario();
	const refuse = (args, lang = "en") => {
		const result = spawnSync(process.execPath, [join(here, "onprem-upgrade.mjs"), "--current", s.current, "--contract", s.contract, "--key-file", s.keyFile, "--backup-root", s.backupRoot, ...args], { encoding: "utf8", env: { ...process.env, AIDR_LANG: lang } });
		assert.equal(result.status, 2, result.stdout + result.stderr);
		return result.stdout;
	};
	assert.match(refuse(["--to", s.current]), /is the live installation/);
	assert.match(refuse(["--to", `${s.current}/`]), /is the live installation/);
	assert.match(refuse(["--to", join(s.current, "next")]), /inside each other/);
	assert.match(refuse(["--to", join(s.dir, "missing")]), /has no deployment\.json/);
	assert.match(refuse(["--to", s.current], "tr"), /çalışan kurulumun kendisi/);
	assert.match(refuse([]), /--to <prepared release directory> is required/);
	writeFileSync(join(s.target, "doctor-evidence.json"), "{}");
	assert.match(refuse(["--to", s.target]), /already been used as a running installation/);
	rmSync(join(s.target, "doctor-evidence.json"));
	assert.match(refuse(["--to", s.target, "--key-file", join(s.dir, "no.key")]), /backup key file .* does not exist/);
	assert.match(refuse(["--to", s.target, "--backup-root", join(s.dir, "nope"), "--dry-run"]), /install -d -m 0700/);
	assert.match(refuse(["--to", s.target, "--resume", "--backup", s.backupRoot]), /do not pass --backup/);
	assert.equal(readFileSync(s.log, "utf8"), "");
});

test("refusal reasons are pure and the plan follows the documented order", () => {
	const s = scenario();
	const options = optionsFor(s);
	assert.deepEqual(refusalReasons(options), []);
	const plan = buildPlan(options, { scriptsDir: "/kit/scripts", stamp: new Date("2026-10-13T08:30:00.000Z") });
	assert.deepEqual(plan.steps.map((step) => step.stage), STAGES);
	assert.equal(plan.backupDir, join(s.backupRoot, "aidr-pre-upgrade-20261013T083000Z"));
	assert.equal(plan.steps.find((step) => step.stage === "restart").argv, null);
	const reuse = buildPlan(optionsFor(s, ["--backup", join(s.dir, "old-backup")]));
	assert.equal(reuse.steps.find((step) => step.stage === "backup").argv, null);
	assert.ok(reuse.steps.find((step) => step.stage === "verify").argv.includes(join(s.dir, "old-backup")));
	assert.equal(resolve(parseOptions(["--to", "x"], { AIDR_DEPLOYMENT_DIR: "/opt/aidr" }).current), "/opt/aidr");
	assert.equal(parseOptions(["--to", "x"], { LANG: "tr_TR.UTF-8" }).lang, "tr");
});

test("apply failures map to the step that failed and whether a restore may be needed", () => {
	assert.deepEqual(classifyApplyFailure({ status: "failed", last_completed_phase: "preflight", requires_restore: false }), { stage: "apply", situation: "pre-commit" });
	assert.deepEqual(classifyApplyFailure({ status: "failed", last_completed_phase: "migration_running", requires_restore: true }), { stage: "apply", situation: "unknown-commit" });
	assert.deepEqual(classifyApplyFailure({ status: "failed", last_completed_phase: "artifacts_installed", requires_restore: true, last_error: "target service start failed (exit 1)" }), { stage: "restart", situation: "post-commit" });
	assert.deepEqual(classifyApplyFailure({ status: "failed", last_completed_phase: "artifacts_installed", requires_restore: true, last_error: "online deployment doctor failed (exit 1)" }), { stage: "doctor", situation: "post-commit" });
	assert.deepEqual(classifyApplyFailure({ status: "failed", last_completed_phase: "database_migrated", requires_restore: false, interrupted_by: "SIGTERM" }), { stage: "apply", situation: "interrupted" });
});
