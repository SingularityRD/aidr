#!/usr/bin/env node
/**
 * Regressions for the noisy-neighbour rehearsal.
 *
 * The rehearsal drives real traffic, so these cover the part that must be right
 * before it does: the argument contract and the refusals. The most important one
 * is the pre-flight probe. The workload asserts HTTP 200 from the policy
 * endpoint, and that endpoint answers 404 `policy_not_published` for a tenant
 * without a published policy - so a rehearsal that skipped the probe would spend
 * a minute of load to discover a missing row, and would report it as a capacity
 * failure. Losing that distinction is how a test starts lying.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "verify-noisy-neighbor-live.mjs");

function run(args) {
	try {
		const stdout = execFileSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 120_000 });
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

function runAsync(args, env = {}) {
	return new Promise((resolveRun, reject) => {
		const child = spawn(process.execPath, [SCRIPT, ...args], { cwd: ROOT, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
		let output = "";
		child.stdout.on("data", (chunk) => { output += chunk; });
		child.stderr.on("data", (chunk) => { output += chunk; });
		child.on("error", reject);
		child.on("close", (status) => resolveRun({ status, output }));
	});
}

describe("noisy-neighbour rehearsal", () => {
	it("documents its arguments", () => {
		const result = run(["--help"]);
		assert.equal(result.status, 0);
		assert.match(result.output, /--deployment/);
		assert.match(result.output, /--profile/);
		assert.match(result.output, /--keep-keys/);
		assert.match(result.output, /--candidate-inventory/);
	});

	it("rejects an unknown argument instead of ignoring it", () => {
		const result = run(["--deployment", ".aidr-deploy", "--force"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /unknown argument/);
	});

	it("requires a value for every declared option", () => {
		const result = run(["--deployment"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /requires a value/);
	});

	it("reports a missing installation as blocked, not as a pass", () => {
		const result = run(["--deployment", ".release-evidence/absent-installation-for-test"]);
		assert.equal(result.status, 3, "a missing installation must exit with the blocked code");
		assert.match(result.output, /no installation at/);
		assert.doesNotMatch(result.output, /AIDR_GATE_RESULT/);
	});

	it("refuses an installation directory with no deployment manifest", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-noisy-test-"));
		try {
			const result = run(["--deployment", dir]);
			assert.equal(result.status, 3);
			assert.match(result.output, /deployment\.json is missing/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("refuses a missing workload profile before touching the installation", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-noisy-test-"));
		try {
			writeFileSync(join(dir, "deployment.json"), JSON.stringify({ mode: "self-hosted", source_commit: "a".repeat(40), supabase_url: "http://127.0.0.1:8000" }));
			const result = run(["--deployment", dir, "--profile", join(dir, "absent-profile.json")]);
			assert.equal(result.status, 1);
			assert.match(result.output, /workload profile not found/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("ships a local profile that declares itself a local rehearsal", () => {
		const profilePath = join(ROOT, "deploy", "ha", "workload.noisy-neighbor.local.json");
		assert.ok(existsSync(profilePath), "the local noisy-neighbour profile must exist");
		const profile = JSON.parse(readFileSync(profilePath, "utf8"));
		assert.equal(profile.workload_class, "noisy_neighbor");
		assert.equal(profile.environment_label, "isolated-local-rehearsal");
		assert.equal(profile.base_url_env, "AIDR_LOAD_BASE_URL");
		// Two cohorts is the point of the test: one baseline, one noisy.
		assert.equal(profile.scenarios.length, 2);
		const [baseline, noisy] = profile.scenarios;
		assert.equal(baseline.cohort, "baseline_tenant");
		assert.equal(noisy.cohort, "noisy_tenant");
		assert.ok(noisy.weight > baseline.weight, "the noisy cohort must carry the heavier weight");
		assert.deepEqual(baseline.expected_statuses, [200], "the protected baseline must remain fully successful");
		assert.deepEqual(noisy.expected_statuses, [200, 429], "the noisy cohort may hit the endpoint's designed subject quota");
		// The baseline cohort's own thresholds are the acceptance signal, and the
		// noisy cohort must not have laxer ones.
		assert.ok(baseline.thresholds, "the baseline cohort must declare thresholds");
		assert.equal(baseline.thresholds.max_p95_ms <= 500, true, "baseline p95 target must not be relaxed above the staging template's 500 ms");
		// A local profile must not borrow the staging candidate or environment.
		assert.equal(profile.candidate_id, undefined);
	});

	it("keeps the staging profile's isolation signal separate from designed quota rejection", () => {
		const profile = JSON.parse(readFileSync(join(ROOT, "deploy", "ha", "workload.noisy-neighbor.template.json"), "utf8"));
		const [baseline, noisy] = profile.scenarios;
		assert.deepEqual(baseline.expected_statuses, [200]);
		assert.deepEqual(noisy.expected_statuses, [200, 429]);
		assert.ok(baseline.thresholds.max_p95_ms <= 500);
	});

	it("rejects candidate evidence when release metadata names a different deployed source", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-noisy-candidate-"));
		try {
			const deployment = join(dir, "deployment");
			const candidate = join(dir, "candidate");
			mkdirSync(deployment);
			mkdirSync(candidate);
			writeFileSync(join(deployment, "deployment.json"), JSON.stringify({ mode: "self-hosted", source_commit: "a".repeat(40), supabase_url: "http://127.0.0.1:8000" }));
			writeFileSync(join(candidate, "release-inventory.json"), JSON.stringify({ schema_version: 1, artifacts: [] }));
			writeFileSync(join(candidate, "release-metadata.json"), JSON.stringify({ schema_version: 1, git_sha: "b".repeat(40) }));
			const result = run(["--deployment", deployment, "--candidate-inventory", join(candidate, "release-inventory.json"), "--evidence-dir", join(dir, "evidence")]);
			assert.equal(result.status, 1);
			assert.match(result.output, /candidate source .* does not match deployed source/);
			assert.equal(existsSync(join(dir, "evidence")), false);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("materializes the candidate-bound effective profile only in the requested evidence directory", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-noisy-candidate-"));
		try {
			const deployment = join(dir, "deployment");
			const candidate = join(dir, "candidate");
			const evidence = join(dir, "evidence");
			mkdirSync(deployment);
			mkdirSync(candidate);
			const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
			writeFileSync(join(deployment, "deployment.json"), JSON.stringify({ mode: "self-hosted", source_commit: head, supabase_url: "http://127.0.0.1:8000" }));
			const inventoryPath = join(candidate, "release-inventory.json");
			writeFileSync(inventoryPath, JSON.stringify({ schema_version: 1, artifacts: [] }));
			writeFileSync(join(candidate, "release-metadata.json"), JSON.stringify({ schema_version: 1, git_sha: head }));
			const result = run(["--deployment", deployment, "--candidate-inventory", inventoryPath, "--evidence-dir", evidence]);
			assert.equal(result.status, 1, result.output);
			assert.match(result.output, /psql failed/);
			const effective = JSON.parse(readFileSync(join(evidence, "workload.noisy-neighbor.effective.json"), "utf8"));
			const digest = createHash("sha256").update(readFileSync(inventoryPath)).digest("hex");
			assert.equal(effective.candidate_id, digest);
			assert.equal(existsSync(join(ROOT, ".release-evidence", "workload.noisy-neighbor.effective.json")), false);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("binds a candidate run and receipt to the requested profile, deployment, host and artifacts", async () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-noisy-receipt-"));
		const server = createServer((_request, response) => {
			response.writeHead(200, { "content-type": "application/json" });
			response.end(JSON.stringify({ policy_version: "1", runtime_policy: {} }));
		});
		await new Promise((done) => server.listen(0, "127.0.0.1", done));
		try {
			const address = server.address();
			assert.ok(address && typeof address === "object");
			const deployment = join(dir, "deployment");
			const candidate = join(dir, "candidate");
			const evidence = join(dir, "evidence");
			mkdirSync(deployment);
			mkdirSync(candidate);
			const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
			const manifestPath = join(deployment, "deployment.json");
			writeFileSync(manifestPath, JSON.stringify({ mode: "self-hosted", development: true, project_name: "fixture", source_commit: head, supabase_url: `http://127.0.0.1:${address.port}` }));
			writeFileSync(join(deployment, "compose.yml"), "name: fixture\n");
			const inventoryPath = join(candidate, "release-inventory.json");
			writeFileSync(inventoryPath, JSON.stringify({ schema_version: 1, artifacts: [] }));
			writeFileSync(join(candidate, "release-metadata.json"), JSON.stringify({ schema_version: 1, git_sha: head }));
			const profilePath = join(dir, "profile.json");
			writeFileSync(profilePath, JSON.stringify({
				schema_version: 1,
				workload_id: "noisy-receipt-fixture",
				workload_class: "noisy_neighbor",
				environment_label: "isolated-test-fixture",
				base_url_env: "AIDR_LOAD_BASE_URL",
				duration_seconds: 0.4,
				rate_per_second: 10,
				max_in_flight: 10,
				thresholds: { min_requests: 4, max_error_ratio: 0, max_loss_ratio: 0, max_p95_ms: 2000 },
				scenarios: [
					{ name: "baseline-tenant-policy", cohort: "baseline_tenant", method: "GET", path: "/functions/v1/policy", weight: 1, headers_env: { Authorization: "AIDR_LOAD_BASELINE_AUTHORIZATION" }, expected_statuses: [200], thresholds: { min_requests: 2, max_error_ratio: 0, max_loss_ratio: 0, max_p95_ms: 2000 } },
					{ name: "noisy-tenant-policy", cohort: "noisy_tenant", method: "GET", path: "/functions/v1/policy", weight: 1, headers_env: { Authorization: "AIDR_LOAD_NOISY_AUTHORIZATION" }, expected_statuses: [200, 429] },
				],
			}));
			const shim = join(dir, "psql-shim.mjs");
			writeFileSync(shim, `const sql=process.argv[2]??"";if(sql.includes("select t.id"))process.stdout.write("11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222\\n33333333-3333-4333-8333-333333333333|44444444-4444-4444-8444-444444444444\\n");`);
			const result = await runAsync([
				"--deployment", deployment,
				"--profile", profilePath,
				"--candidate-inventory", inventoryPath,
				"--evidence-dir", evidence,
			], { AIDR_NOISY_PSQL_SHIM: shim });
			assert.equal(result.status, 2, result.output);
			const inventoryDigest = createHash("sha256").update(readFileSync(inventoryPath)).digest("hex");
			const receipt = JSON.parse(readFileSync(join(evidence, "noisy-neighbor-live.json"), "utf8"));
			const load = JSON.parse(readFileSync(join(evidence, "load-noisy-neighbor-local.json"), "utf8"));
			assert.equal(load.passed, true);
			assert.equal(load.workload.candidate_id, inventoryDigest);
			assert.equal(receipt.candidate_binding.status, "UNBOUND_PSQL_SHIM");
			assert.equal(receipt.candidate_binding.candidate_digest, inventoryDigest);
			assert.equal(receipt.candidate_digest, inventoryDigest);
			assert.equal(receipt.candidate_digest_source, receipt.candidate_binding.candidate_digest_source);
			assert.equal(receipt.candidate_binding.source_commit, head);
			assert.equal(receipt.source_commit, head);
			assert.match(receipt.candidate_binding.candidate_metadata_sha256, /^[a-f0-9]{64}$/);
			assert.equal(receipt.run.load_exit_code, 0);
			assert.equal(receipt.run.load_result_passed, true);
			assert.equal(receipt.run.psql_transport, "shim");
			assert.equal(receipt.deployment.source_commit, head);
			assert.equal(receipt.deployment.supabase_url, `http://127.0.0.1:${address.port}`);
			assert.match(receipt.deployment.manifest_sha256, /^[a-f0-9]{64}$/);
			assert.equal(receipt.profile.executed_sha256, load.workload.profile_sha256);
			assert.match(receipt.artefact.sha256, /^[a-f0-9]{64}$/);
			assert.equal(receipt.artifact_sha256, receipt.artefact.sha256);
			assert.equal(receipt.isolation.baseline_thresholds_passed, true);
			assert.equal(receipt.passed, false, "a psql shim must never create candidate-bound PASS evidence");
		} finally {
			await new Promise((done) => server.close(done));
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("queues a key for cleanup before a psql insert with an uncertain outcome", async () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-noisy-cleanup-"));
		try {
			const deployment = join(dir, "deployment");
			const evidence = join(dir, "evidence");
			mkdirSync(deployment);
			const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
			writeFileSync(join(deployment, "deployment.json"), JSON.stringify({ mode: "self-hosted", source_commit: head, supabase_url: "http://127.0.0.1:8000" }));
			const logPath = join(dir, "psql.log");
			const shim = join(dir, "psql-shim.mjs");
			writeFileSync(shim, `import { appendFileSync } from "node:fs";
const sql = process.argv[2] ?? "";
appendFileSync(process.env.AIDR_TEST_PSQL_LOG, sql + "\\n");
if (sql.includes("select t.id")) process.stdout.write("11111111-1111-4111-8111-111111111111|22222222-2222-4222-8222-222222222222\\n33333333-3333-4333-8333-333333333333|44444444-4444-4444-8444-444444444444\\n");
else if (sql.includes("-noisy',")) process.exit(1);`);
			const result = await runAsync([
				"--deployment", deployment,
				"--evidence-dir", evidence,
			], { AIDR_NOISY_PSQL_SHIM: shim, AIDR_TEST_PSQL_LOG: logPath });
			assert.equal(result.status, 1, result.output);
			assert.match(result.output, /psql failed/);
			const statements = readFileSync(logPath, "utf8").trim().split("\n");
			const inserts = statements.filter((sql) => sql.startsWith("insert into public.api_keys"));
			assert.equal(inserts.length, 2);
			const cleanup = statements.find((sql) => sql.startsWith("delete from public.api_keys where key_hash in"));
			assert.ok(cleanup, "finally must attempt targeted key-hash cleanup");
			for (const insert of inserts) {
				const hash = insert.match(/, '([a-f0-9]{64})', false\)$/)?.[1];
				assert.ok(hash, "each inserted key has a hash");
				assert.ok(cleanup.includes(`'${hash}'`), "cleanup includes keys from both successful and uncertain writes");
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("does not present a local rehearsal as a capacity or SLA result", () => {
		const source = readFileSync(SCRIPT, "utf8");
		assert.match(source, /not a capacity result and not an SLA/);
		assert.match(source, /does not establish a monthly availability SLI, HA or failover/);
		assert.match(source, /policy_not_published/, "the probe must explain why a missing policy is caught before load");
	});

	it("selects tenants that have a published policy, not merely a member", () => {
		// The endpoint answers 404 for a tenant with no published policy, so
		// membership alone is the wrong predicate and would fail the run for a
		// reason unrelated to load.
		const source = readFileSync(SCRIPT, "utf8");
		assert.match(source, /tenant_runtime_policies/, "tenant selection must join the runtime policy table");
		assert.match(source, /cross join lateral/, "tenant selection must choose one member from each distinct tenant");
		assert.match(source, /tm\.role in \('owner', 'admin', 'member'\)/, "read-only viewers cannot hold API keys");
		assert.match(source, /tm\.expires_at is null or tm\.expires_at > now\(\)/, "expired memberships cannot hold API keys");
		assert.match(source, /t\.status = 'active'/, "suspended tenants are not valid load fixtures");
		assert.match(source, /\[\["baseline", keys\.baseline\], \["noisy", keys\.noisy\]\]/, "both tenant credentials must be probed before load");
		assert.match(source, /new Set\(tenants\.map/, "the selected identities must be checked for distinct tenants");
	});

	it("binds the executed profile, output and receipt to the requested evidence directory", () => {
		const source = readFileSync(SCRIPT, "utf8");
		assert.match(source, /"--profile", effectiveProfilePath, "--output", outputPath/);
		assert.match(source, /candidate_binding:/);
		assert.match(source, /manifest_sha256:/);
		assert.match(source, /executed_sha256:/);
		assert.match(source, /artefact: \{ path: .* sha256:/);
		assert.match(source, /host: \{ hostname:/);
		assert.match(source, /writeFileSync\(recordPath,.*flag: "wx"/s);
		assert.doesNotMatch(source, /"--overwrite"/);
	});

	it("revokes only its own rehearsal keys unless told to keep them", () => {
		const source = readFileSync(SCRIPT, "utf8");
		assert.match(source, /delete from public\.api_keys where key_hash in/);
		assert.doesNotMatch(source, /delete from public\.api_keys where label like/);
		assert.match(source, /--keep-keys/);
	});
});
