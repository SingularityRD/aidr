#!/usr/bin/env node
/**
 * Run the noisy-neighbour workload against a live self-hosted installation.
 *
 * The acceptance criterion this addresses is tenant isolation under load: when
 * one tenant hammers the policy endpoint, the other tenant's latency must not
 * degrade. The repository shipped a staging template for this that needs two
 * enrolled tenant cohorts and an approved test plan, but nothing exercised it,
 * so "tenant noisy-neighbour tests" remained unproven even locally.
 *
 * This prepares what the template assumes: two independent tenants, a fresh API
 * key for each, and the environment the load-test runner reads its Authorization
 * headers from. The keys are revoked at the end, so the installation is left as
 * it was found.
 *
 * It does not size the host, and it says so in the evidence. A pass means the
 * endpoint kept the two tenants separated at this scale; it is not a capacity
 * result and not an SLA.
 *
 * Usage:
 *   node scripts/verify-noisy-neighbor-live.mjs --deployment <installed dir> [--profile <file>] [--keep-keys]
 */
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_PROFILE = "deploy/ha/workload.noisy-neighbor.local.json";
const LABEL = "noisy-neighbor-rehearsal";
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

class CliError extends Error {
	constructor(message, exitCode = 1) {
		super(message);
		this.exitCode = exitCode;
	}
}

function fail(message, code = 1) {
	throw new CliError(message, code);
}

process.on("uncaughtException", (error) => {
	console.error(`ERROR: ${error instanceof Error ? error.message : String(error)}`);
	process.exitCode = error instanceof CliError ? error.exitCode : 1;
});

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--help" || arg === "-h") values.help = true;
		else if (arg === "--keep-keys") values.keepKeys = true;
		else if (["--deployment", "--profile", "--evidence-dir", "--candidate-inventory"].includes(arg)) {
			const next = argv[++i];
			if (!next) fail(`${arg} requires a value`);
			values[arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = next;
		} else fail(`unknown argument: ${arg}`);
	}
	return values;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
	console.log("Usage: node scripts/verify-noisy-neighbor-live.mjs --deployment <installed dir> [--profile <file>] [--evidence-dir <dir>] [--candidate-inventory <release-inventory.json>] [--keep-keys]");
	process.exit(0);
}

function sha256Bytes(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

function sha256File(file) {
	return sha256Bytes(readFileSync(file));
}

function git(args) {
	const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8", timeout: 30_000 });
	if (result.status !== 0) fail(`git ${args.join(" ")} failed: ${String(result.stderr ?? "").trim().slice(-300)}`);
	return String(result.stdout ?? "").trim();
}

const deployment = path.resolve(ROOT, options.deployment ?? process.env.AIDR_DEPLOYMENT_DIR ?? ".aidr-deploy");
const manifestPath = path.join(deployment, "deployment.json");
if (!existsSync(manifestPath)) fail(`no installation at ${deployment} (deployment.json is missing)`, 3);
const manifestBytes = readFileSync(manifestPath);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
if (!GIT_SHA.test(String(manifest.source_commit ?? ""))) fail("deployment.json has no valid source_commit");
if (typeof manifest.supabase_url !== "string" || manifest.supabase_url.trim() === "") fail("deployment.json has no supabase_url");

const profilePath = path.resolve(ROOT, options.profile ?? DEFAULT_PROFILE);
if (!existsSync(profilePath)) fail(`workload profile not found: ${profilePath}`);
const sourceProfileBytes = readFileSync(profilePath);
const sourceProfile = JSON.parse(sourceProfileBytes.toString("utf8"));
if (sourceProfile.workload_class !== "noisy_neighbor") fail("workload profile must declare workload_class noisy_neighbor");

const runnerCommit = git(["rev-parse", "HEAD"]);
if (!GIT_SHA.test(runnerCommit)) fail("could not resolve the runner source commit");
const worktreeChanges = git(["status", "--porcelain=v1"])
	.split(/\r?\n/)
	.filter(Boolean)
	.filter((line) => !line.slice(3).replace(/\\/g, "/").startsWith(".release-evidence/"));

let candidate = null;
let effectiveProfilePath = profilePath;
const evidenceDir = path.resolve(ROOT, options.evidenceDir ?? ".release-evidence");
const outputPath = path.join(evidenceDir, "load-noisy-neighbor-local.json");
const recordPath = path.join(evidenceDir, "noisy-neighbor-live.json");
const effectiveProfileOutput = path.join(evidenceDir, "workload.noisy-neighbor.effective.json");
for (const output of [outputPath, recordPath, ...(options.candidateInventory ? [effectiveProfileOutput] : [])]) {
	if (existsSync(output)) fail(`evidence output already exists: ${output}`);
}

if (options.candidateInventory) {
	const inventoryPath = path.resolve(ROOT, options.candidateInventory);
	const metadataPath = path.join(path.dirname(inventoryPath), "release-metadata.json");
	if (!existsSync(inventoryPath)) fail(`candidate inventory not found: ${inventoryPath}`);
	if (!existsSync(metadataPath)) fail(`candidate release metadata not found beside inventory: ${metadataPath}`);
	const metadata = JSON.parse(readFileSync(metadataPath, "utf8"));
	if (!GIT_SHA.test(String(metadata.git_sha ?? ""))) fail("candidate release-metadata.json has no valid git_sha");
	if (metadata.git_sha !== manifest.source_commit) fail(`candidate source ${metadata.git_sha} does not match deployed source ${manifest.source_commit}`);
	if (runnerCommit !== manifest.source_commit) fail(`runner source ${runnerCommit} does not match deployed source ${manifest.source_commit}`);
	const digest = sha256File(inventoryPath);
	if (!SHA256.test(digest)) fail("could not digest candidate inventory");
	candidate = {
		digest,
		inventory_path: path.relative(ROOT, inventoryPath).replace(/\\/g, "/"),
		metadata_path: path.relative(ROOT, metadataPath).replace(/\\/g, "/"),
		metadata_sha256: sha256File(metadataPath),
		source_commit: metadata.git_sha,
	};
	if (sourceProfile.candidate_id !== undefined && sourceProfile.candidate_id !== digest) {
		fail(`profile candidate_id ${sourceProfile.candidate_id} does not match candidate inventory digest ${digest}`);
	}
	mkdirSync(evidenceDir, { recursive: true });
	writeFileSync(effectiveProfileOutput, `${JSON.stringify({ ...sourceProfile, candidate_id: digest }, null, 2)}\n`, { flag: "wx" });
	effectiveProfilePath = effectiveProfileOutput;
} else if (sourceProfile.candidate_id !== undefined) {
	fail("a profile with candidate_id requires --candidate-inventory so the binding can be verified");
}

/** Run SQL against the installation's own database. */
function psql(sql) {
	const shim = process.env.AIDR_NOISY_PSQL_SHIM;
	const command = shim ? process.execPath : "docker";
	const args = shim
		? [path.resolve(shim), sql]
		: ["compose", "--project-directory", deployment, "-f", path.join(deployment, "compose.yml"), "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-tAc", sql];
	const result = spawnSync(
		command,
		args,
		{ encoding: "utf8", timeout: 60_000 },
	);
	if (result.error || result.status !== 0) fail(`psql failed: ${result.error?.message ?? (result.stderr ?? "").trim().slice(-300)}`);
	return String(result.stdout ?? "").trim();
}

/** Mint an API key value and its stored hash. The plaintext never touches disk. */
function mintKey() {
	const result = spawnSync(
		process.execPath,
		["-e", `const {createHash,randomBytes}=require('crypto');const raw='aidr_noisy_'+randomBytes(24).toString('hex');process.stdout.write(createHash('sha256').update(raw).digest('hex')+' '+raw);`],
		{ encoding: "utf8" },
	);
	if (result.status !== 0) fail("could not mint an API key");
	const [hash, plaintext] = result.stdout.trim().split(" ");
	if (!SHA256.test(hash ?? "") || !/^aidr_noisy_[a-f0-9]{48}$/.test(plaintext ?? "")) fail("minted API key has an invalid shape");
	return { hash, plaintext };
}

/**
 * Two tenants that each have a member (so a key can be owned) and a published
 * runtime policy. The workload asserts HTTP 200 from `/functions/v1/policy`, and
 * that endpoint answers 404 `policy_not_published` for a tenant without one, so
 * picking tenants on membership alone would fail the run for a reason that has
 * nothing to do with load.
 */
const tenants = psql(
	`select t.id || '|' || m.user_id
	 from public.tenants t
	 cross join lateral (
	   select tm.user_id
	   from public.tenant_members tm
	   where tm.tenant_id = t.id
	     and tm.role in ('owner', 'admin', 'member')
	     and (tm.expires_at is null or tm.expires_at > now())
	   order by tm.user_id
	   limit 1
	 ) m
	 where t.status = 'active'
	   and exists (select 1 from public.tenant_runtime_policies p where p.tenant_id = t.id)
	 order by t.created_at, t.id
	 limit 2`,
)
	.split(/\r?\n/)
	.map((line) => line.trim())
	.filter(Boolean)
	.map((line) => {
		const [tenantId, userId] = line.split("|");
		return { tenantId, userId };
	});
if (tenants.length < 2) fail(`need two tenants with a member and a published policy for a noisy-neighbour run, found ${tenants.length}`);
if (new Set(tenants.map(({ tenantId }) => tenantId)).size !== 2) fail("tenant selection did not return two distinct tenants");
if (tenants.some(({ tenantId, userId }) => !UUID.test(tenantId) || !UUID.test(userId))) fail("tenant selection returned a malformed tenant or user id");
const [baseline, noisy] = tenants;

const keys = { baseline: mintKey(), noisy: mintKey() };
const issued = [];
const runLabel = `${LABEL}-${randomUUID()}`;
try {
	for (const [role, tenant, key] of [
		["baseline", baseline, keys.baseline],
		["noisy", noisy, keys.noisy],
	]) {
		// A failed psql process can have lost its connection after the INSERT
		// committed. Queue the hash for cleanup before sending the write so the
		// finally block also removes keys from an uncertain outcome.
		issued.push(key.hash);
		psql(
			`insert into public.api_keys (tenant_id, user_id, label, key_hash, revoked) values ('${tenant.tenantId}', '${tenant.userId}', '${runLabel}-${role}', '${key.hash}', false)`,
		);
	}
	console.log(`[noisy] issued rehearsal keys for tenants ${baseline.tenantId.slice(0, 8)} (baseline) and ${noisy.tenantId.slice(0, 8)} (noisy)`);

	// The workload asserts HTTP 200, so confirm the endpoint answers before
	// spending a minute of load on it. A 404 here would otherwise read as a load
	// failure rather than a missing published policy.
	const base = manifest.supabase_url;
	for (const [role, key] of [["baseline", keys.baseline], ["noisy", keys.noisy]]) {
		const probe = spawnSync(
			process.execPath,
			["-e", `fetch(process.argv[1]+'/functions/v1/policy',{headers:{Authorization:'Bearer '+process.argv[2]}}).then(async r=>{process.stdout.write(String(r.status)+' '+String(await r.text()).slice(0,120))})`, `${base}`, key.plaintext],
			{ encoding: "utf8", timeout: 30_000 },
		);
		if (probe.error || probe.status !== 0) fail(`${role} policy endpoint probe failed: ${probe.error?.message ?? String(probe.stderr ?? "").trim().slice(-200)}`);
		const [probeStatus] = String(probe.stdout ?? "").trim().split(" ");
		if (probeStatus !== "200") fail(`the policy endpoint answered ${probeStatus || "nothing"} for the ${role} tenant key: ${String(probe.stdout ?? "").slice(0, 200)}`);
		console.log(`[noisy] policy endpoint answers 200 for the ${role} tenant`);
	}

	mkdirSync(evidenceDir, { recursive: true });
	const run = spawnSync(
		process.execPath,
		["scripts/load-test.mjs", "--profile", effectiveProfilePath, "--output", outputPath],
		{
			cwd: ROOT,
			encoding: "utf8",
			stdio: "inherit",
			env: {
				...process.env,
				AIDR_LOAD_BASE_URL: base,
				AIDR_LOAD_BASELINE_AUTHORIZATION: `Bearer ${keys.baseline.plaintext}`,
				AIDR_LOAD_NOISY_AUTHORIZATION: `Bearer ${keys.noisy.plaintext}`,
			},
		},
	);
	if (run.error) fail(`load runner failed to start: ${run.error.message}`);
	if (![0, 2].includes(run.status) || !existsSync(outputPath)) {
		fail(`load runner produced no usable result (exit ${run.status ?? "unknown"})`);
	}
	const loadResult = JSON.parse(readFileSync(outputPath, "utf8"));
	const effectiveProfileSha256 = sha256File(effectiveProfilePath);
	const expectedOrigin = new URL(base).origin;
	if (loadResult.kind !== "aidr_load_test_result") fail("load result has the wrong kind");
	if (loadResult.workload?.profile_sha256 !== effectiveProfileSha256) fail("load result profile digest does not match the executed profile");
	if (loadResult.workload?.candidate_id !== (candidate?.digest ?? null)) fail("load result candidate binding does not match the selected candidate");
	if (loadResult.workload?.target_origin !== expectedOrigin) fail("load result target does not match the deployment manifest");
	if (loadResult.claims?.production_accepted !== false || loadResult.claims?.production_sla_proven !== false || loadResult.claims?.ha_proven !== false) {
		fail("load result contains a prohibited production, SLA or HA claim");
	}
	const candidateBindingStatus = candidate === null
		? "NOT_PROVIDED"
		: process.env.AIDR_NOISY_PSQL_SHIM
			? "UNBOUND_PSQL_SHIM"
			: worktreeChanges.length === 0 ? "BOUND" : "UNBOUND_RUNNER_DIRTY";
	const measurementPassed = run.status === 0 && loadResult.passed === true;
	const passed = measurementPassed && candidateBindingStatus === "BOUND";
	const baselineChecks = (loadResult.threshold_checks ?? []).filter(({ label }) => label === "scenario:baseline-tenant-policy");
	const baselineMetrics = loadResult.metrics?.cohorts?.baseline_tenant;
	const noisyMetrics = loadResult.metrics?.cohorts?.noisy_tenant;
	if (!baselineMetrics || !noisyMetrics || baselineChecks.length === 0) fail("load result is missing baseline/noisy isolation metrics or thresholds");

	// Record the run with the provenance the load-test artefact deliberately omits:
	// which tenants were involved, and what this does not establish.
	const composePath = path.join(deployment, "compose.yml");
	const record = {
		schema_version: 1,
		gate: "verify-noisy-neighbor-live",
		outcome: passed ? "passed" : "failed",
		passed,
		checked_at: new Date().toISOString(),
		source_commit: manifest.source_commit,
		candidate_digest: candidate?.digest ?? null,
		candidate_digest_source: candidate?.inventory_path ?? null,
		artifact_sha256: sha256File(outputPath),
		run: { load_exit_code: run.status, load_result_passed: measurementPassed, runner_commit: runnerCommit, runner_worktree_dirty: worktreeChanges.length > 0, psql_transport: process.env.AIDR_NOISY_PSQL_SHIM ? "shim" : "docker" },
		candidate_binding: candidate
			? { status: candidateBindingStatus, candidate_digest: candidate.digest, candidate_digest_source: candidate.inventory_path, candidate_metadata: candidate.metadata_path, candidate_metadata_sha256: candidate.metadata_sha256, source_commit: candidate.source_commit }
			: { status: "NOT_PROVIDED", candidate_digest: null, candidate_digest_source: null, candidate_metadata: null, candidate_metadata_sha256: null, source_commit: null },
		host: { hostname: os.hostname(), platform: process.platform, arch: process.arch, os_type: os.type(), os_release: os.release(), cpu_count: os.cpus().length, total_memory_bytes: os.totalmem() },
		deployment: {
			mode: manifest.mode,
			development: manifest.development,
			project_name: manifest.project_name ?? null,
			supabase_url: expectedOrigin,
			source_commit: manifest.source_commit,
			manifest_sha256: sha256Bytes(manifestBytes),
			compose_sha256: existsSync(composePath) ? sha256File(composePath) : null,
		},
		profile: {
			source_path: path.relative(ROOT, profilePath).replace(/\\/g, "/"),
			source_sha256: sha256Bytes(sourceProfileBytes),
			executed_path: path.relative(ROOT, effectiveProfilePath).replace(/\\/g, "/"),
			executed_sha256: effectiveProfileSha256,
		},
		tenants: { baseline: baseline.tenantId, noisy: noisy.tenantId },
		isolation: {
			baseline_thresholds_passed: baselineChecks.every(({ passed: checkPassed }) => checkPassed === true),
			baseline: baselineMetrics,
			noisy: noisyMetrics,
		},
		artefact: { path: path.relative(ROOT, outputPath).replace(/\\/g, "/"), sha256: sha256File(outputPath) },
		classification: "isolated local rehearsal against a self-hosted control plane; not a capacity result and not an SLA",
		limitations: [
			"One contended developer host, not a sized allocation; the thresholds are local-scale, not the staging template's 100000 requests.",
			"A pass shows only that the policy endpoint met the declared two-tenant thresholds at this local scale; it does not establish a monthly availability SLI, HA or failover.",
			"The two tenants share a database and an edge-function process, so a pass does not speak to cross-host isolation.",
		],
	};
	writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
	console.log(`AIDR_GATE_RESULT ${JSON.stringify(record)}`);
	process.exitCode = passed ? 0 : 2;
} finally {
	if (options.keepKeys) {
		console.warn(`[noisy] keeping ${issued.length} rehearsal keys (--keep-keys); revoke label '${runLabel}' afterwards`);
	} else if (issued.length > 0) {
		psql(`delete from public.api_keys where key_hash in (${issued.map((hash) => `'${hash}'`).join(",")})`);
		console.log(`[noisy] revoked ${issued.length} rehearsal keys`);
	}
}
