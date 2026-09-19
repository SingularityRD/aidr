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
import { execFileSync } from "node:child_process";
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

describe("noisy-neighbour rehearsal", () => {
	it("documents its arguments", () => {
		const result = run(["--help"]);
		assert.equal(result.status, 0);
		assert.match(result.output, /--deployment/);
		assert.match(result.output, /--profile/);
		assert.match(result.output, /--keep-keys/);
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
			writeFileSync(join(dir, "deployment.json"), JSON.stringify({ mode: "self-hosted", supabase_url: "http://127.0.0.1:8000" }));
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
		// The baseline cohort's own thresholds are the acceptance signal, and the
		// noisy cohort must not have laxer ones.
		assert.ok(baseline.thresholds, "the baseline cohort must declare thresholds");
		assert.equal(baseline.thresholds.max_p95_ms <= 500, true, "baseline p95 target must not be relaxed above the staging template's 500 ms");
		// A local profile must not borrow the staging candidate or environment.
		assert.equal(profile.candidate_id, undefined);
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
	});

	it("revokes its rehearsal keys unless told to keep them", () => {
		const source = readFileSync(SCRIPT, "utf8");
		assert.match(source, /delete from public\.api_keys where label like/);
		assert.match(source, /--keep-keys/);
	});
});
