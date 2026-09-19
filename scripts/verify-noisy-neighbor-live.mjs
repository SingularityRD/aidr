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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_PROFILE = "deploy/ha/workload.noisy-neighbor.local.json";
const LABEL = "noisy-neighbor-rehearsal";

function fail(message, code = 1) {
	console.error(`ERROR: ${message}`);
	process.exit(code);
}

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--help" || arg === "-h") values.help = true;
		else if (arg === "--keep-keys") values.keepKeys = true;
		else if (["--deployment", "--profile", "--evidence-dir"].includes(arg)) {
			const next = argv[++i];
			if (!next) fail(`${arg} requires a value`);
			values[arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = next;
		} else fail(`unknown argument: ${arg}`);
	}
	return values;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
	console.log("Usage: node scripts/verify-noisy-neighbor-live.mjs --deployment <installed dir> [--profile <file>] [--evidence-dir <dir>] [--keep-keys]");
	process.exit(0);
}

const deployment = path.resolve(ROOT, options.deployment ?? process.env.AIDR_DEPLOYMENT_DIR ?? ".aidr-deploy");
const manifestPath = path.join(deployment, "deployment.json");
if (!existsSync(manifestPath)) fail(`no installation at ${deployment} (deployment.json is missing)`, 3);
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

const profilePath = path.resolve(ROOT, options.profile ?? DEFAULT_PROFILE);
if (!existsSync(profilePath)) fail(`workload profile not found: ${profilePath}`);

/** Run SQL against the installation's own database. */
function psql(sql) {
	const result = spawnSync(
		"docker",
		["compose", "--project-directory", deployment, "-f", path.join(deployment, "compose.yml"), "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-tAc", sql],
		{ encoding: "utf8", timeout: 60_000 },
	);
	if (result.status !== 0) fail(`psql failed: ${(result.stderr ?? "").trim().slice(-300)}`);
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
	 join public.tenant_members m on m.tenant_id = t.id
	 join public.tenant_runtime_policies p on p.tenant_id = t.id
	 order by t.created_at limit 2`,
)
	.split(/\r?\n/)
	.map((line) => line.trim())
	.filter(Boolean)
	.map((line) => {
		const [tenantId, userId] = line.split("|");
		return { tenantId, userId };
	});
if (tenants.length < 2) fail(`need two tenants with a member and a published policy for a noisy-neighbour run, found ${tenants.length}`);
const [baseline, noisy] = tenants;

const keys = { baseline: mintKey(), noisy: mintKey() };
const issued = [];
try {
	for (const [role, tenant, key] of [
		["baseline", baseline, keys.baseline],
		["noisy", noisy, keys.noisy],
	]) {
		psql(
			`insert into public.api_keys (tenant_id, user_id, label, key_hash, revoked) values ('${tenant.tenantId}', '${tenant.userId}', '${LABEL}-${role}', '${key.hash}', false)`,
		);
		issued.push(key.hash);
	}
	console.log(`[noisy] issued rehearsal keys for tenants ${baseline.tenantId.slice(0, 8)} (baseline) and ${noisy.tenantId.slice(0, 8)} (noisy)`);

	// The workload asserts HTTP 200, so confirm the endpoint answers before
	// spending a minute of load on it. A 404 here would otherwise read as a load
	// failure rather than a missing published policy.
	const base = manifest.supabase_url;
	const probe = spawnSync(
		process.execPath,
		["-e", `fetch(process.argv[1]+'/functions/v1/policy',{headers:{Authorization:'Bearer '+process.argv[2]}}).then(async r=>{process.stdout.write(String(r.status)+' '+String(await r.text()).slice(0,120))})`, `${base}`, keys.baseline.plaintext],
		{ encoding: "utf8", timeout: 30_000 },
	);
	const [probeStatus] = String(probe.stdout ?? "").trim().split(" ");
	if (probeStatus !== "200") fail(`the policy endpoint answered ${probeStatus || "nothing"} for a tenant key: ${String(probe.stdout ?? "").slice(0, 200)}`);
	console.log(`[noisy] policy endpoint answers 200 for the baseline tenant`);

	const outputPath = path.join(ROOT, ".release-evidence", "load-noisy-neighbor-local.json");
	const run = spawnSync(
		process.execPath,
		["scripts/load-test.mjs", "--profile", profilePath, "--output", outputPath, "--overwrite"],
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
	const passed = run.status === 0;

	// Record the run with the provenance the load-test artefact deliberately omits:
	// which tenants were involved, and what this does not establish.
	const evidenceDir = path.resolve(ROOT, options.evidenceDir ?? ".release-evidence");
	mkdirSync(evidenceDir, { recursive: true });
	const record = {
		schema_version: 1,
		gate: "verify-noisy-neighbor-live",
		outcome: passed ? "passed" : "failed",
		passed,
		checked_at: new Date().toISOString(),
		deployment: { mode: manifest.mode, development: manifest.development, supabase_url: base, source_commit: manifest.source_commit ?? null },
		profile: path.relative(ROOT, profilePath).replace(/\\/g, "/"),
		tenants: { baseline: baseline.tenantId, noisy: noisy.tenantId },
		artefact: path.relative(ROOT, outputPath).replace(/\\/g, "/"),
		classification: "isolated local rehearsal against a self-hosted control plane; not a capacity result and not an SLA",
		limitations: [
			"One contended developer host, not a sized allocation; the thresholds are local-scale, not the staging template's 100000 requests.",
			"This shows the policy endpoint kept two tenants separated at this scale; it does not establish a monthly availability SLI, HA or failover.",
			"The two tenants share a database and an edge-function process, so a pass does not speak to cross-host isolation.",
		],
	};
	writeFileSync(path.join(evidenceDir, "noisy-neighbor-live.json"), `${JSON.stringify(record, null, 2)}\n`, "utf8");
	console.log(`AIDR_GATE_RESULT ${JSON.stringify(record)}`);
	process.exitCode = passed ? 0 : 1;
} finally {
	if (options.keepKeys) {
		console.warn(`[noisy] keeping ${issued.length} rehearsal keys (--keep-keys); revoke label '${LABEL}' afterwards`);
	} else {
		psql(`delete from public.api_keys where label like '${LABEL}%'`);
		console.log(`[noisy] revoked ${issued.length} rehearsal keys`);
	}
}
