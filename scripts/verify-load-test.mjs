#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

mkdirSync(".release-evidence", { recursive: true });
const evidenceDir = mkdtempSync(resolve(".release-evidence/load-harness-"));
const token = `private-self-test-${randomUUID()}`;
let unstableRequests = 0;
let observedHeader = false;
let observedBody = false;
const server = createServer((request, response) => {
	observedHeader ||= request.headers.authorization === token;
	let body = "";
	request.on("data", (chunk) => { body += chunk; });
	request.on("end", () => {
		observedBody ||= body.includes(token);
		if (request.url === "/slow") {
			setTimeout(() => { response.writeHead(200); response.end("slow"); }, 300);
			return;
		}
		unstableRequests += 1;
		const status = unstableRequests <= 4 ? 503 : 200;
		response.writeHead(status, { "content-type": "application/json" });
		response.end(JSON.stringify({ status: status === 200 ? "ok" : "unavailable" }));
	});
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const address = server.address();
assert.ok(address && typeof address === "object");

function run(args, env) {
	return new Promise((done, reject) => {
		const child = spawn(process.execPath, ["scripts/load-test.mjs", ...args], {
			cwd: resolve("."),
			env: { ...process.env, ...env },
			stdio: ["ignore", "pipe", "pipe"],
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => { stdout += chunk; });
		child.stderr.on("data", (chunk) => { stderr += chunk; });
		child.on("error", reject);
		child.on("close", (status) => done({ status, stdout, stderr }));
	});
}

const profilePath = join(evidenceDir, "profile.json");
const resultPath = join(evidenceDir, "result.json");
writeFileSync(profilePath, JSON.stringify({
	schema_version: 1,
	workload_id: "load-harness-self-test",
	workload_class: "failover",
	environment_label: "isolated-loopback-self-test",
	base_url_env: "AIDR_LOAD_BASE_URL",
	duration_seconds: 4,
	rate_per_second: 5,
	max_in_flight: 20,
	request_timeout_ms: 1000,
	max_response_bytes: 1024,
	max_latency_samples: 100,
	max_fault_event_samples: 100,
	scenarios: [{
		name: "recovering-endpoint",
		cohort: "test_tenant",
		method: "POST",
		path: "/unstable",
		weight: 1,
		headers_env: { Authorization: "AIDR_LOAD_SELF_TEST_SECRET" },
		body_json: { canary: { $env: "AIDR_LOAD_SELF_TEST_SECRET" }, sequence: { $sequence: true } },
		expected_statuses: [200],
		thresholds: { min_requests: 15, max_error_ratio: 0.25, max_loss_ratio: 0, max_p95_ms: 1000 },
	}],
	fault_windows: [{
		name: "synthetic-recovery",
		target: "loopback-fixture",
		scenario_names: ["recovering-endpoint"],
		start_seconds: 0,
		end_seconds: 1,
		recovery_confirmation_successes: 3,
		require_fault_observed: true,
		max_rto_ms: 3500,
	}],
	thresholds: { min_requests: 15, max_error_ratio: 0.25, max_loss_ratio: 0, min_availability_ratio: 0.75, max_p99_ms: 1000 },
}, null, 2));

const checks = [];
try {
	const runResult = await run(["--profile", profilePath, "--output", resultPath], {
		AIDR_LOAD_BASE_URL: `http://127.0.0.1:${address.port}`,
		AIDR_LOAD_SELF_TEST_SECRET: token,
	});
	assert.equal(runResult.status, 0, runResult.stderr);
	assert.ok(observedHeader && observedBody);
	checks.push("environment-backed headers and body templates reach the loopback fixture");

	const raw = readFileSync(resultPath, "utf8");
	assert.ok(!raw.includes(token));
	const result = JSON.parse(raw);
	assert.equal(result.kind, "aidr_load_test_result");
	assert.equal(result.passed, true);
	assert.ok(result.metrics.overall.completed >= 15);
	assert.equal(result.metrics.overall.transport_errors, 0);
	assert.equal(result.metrics.overall.dropped_requests, 0);
	assert.equal(result.fault_observations[0].status, "recovered");
	assert.ok(result.fault_observations[0].estimated_rto_ms <= 3500);
	assert.equal(result.diagnostics.failure_classes.overall.unexpected_status, 4);
	assert.equal(result.diagnostics.generator.schedule_lag_ms.observations, result.metrics.overall.scheduled);
	assert.ok(result.diagnostics.generator.peak_in_flight <= 20);
	assert.ok(result.threshold_checks.some((check) => check.label === "generator" && check.metric === "schedule_lag_ms.p95" && check.passed));
	checks.push("request, error, latency, cohort and failover recovery metrics are emitted without credentials");

	assert.deepEqual(result.claims, { production_accepted: false, production_sla_proven: false, ha_proven: false });
	assert.ok(result.limitations.some((item) => item.includes("monthly availability")));
	checks.push("a passing harness result cannot claim HA, production acceptance or a monthly SLA");

	const resultSchema = JSON.parse(readFileSync("deploy/ha/load-result.schema.json", "utf8"));
	const workloadSchema = JSON.parse(readFileSync("deploy/ha/workload-profile.schema.json", "utf8"));
	assert.deepEqual(workloadSchema.$defs.thresholds.anyOf, [
		{ required: ["max_loss_ratio"] },
		{ required: ["min_availability_ratio"] },
	]);
	checks.push("machine-readable workload schema requires loss or end-to-end availability bounds");
	for (const required of resultSchema.required) assert.ok(Object.hasOwn(result, required), `missing schema field ${required}`);
	assert.equal(resultSchema.properties.claims.properties.production_sla_proven.const, false);
	assert.ok(resultSchema.properties.diagnostics.$ref);
	assert.ok(resultSchema.$defs.failureClassCounts.properties.timeout);
	checks.push("machine-readable result schema covers the emitted diagnostics and fixes claim flags false");

	const escapedProfile = { ...JSON.parse(readFileSync(profilePath, "utf8")) };
	escapedProfile.scenarios[0].path = "/\\example.invalid/escape";
	const escapedProfilePath = join(evidenceDir, "escaped-profile.json");
	writeFileSync(escapedProfilePath, JSON.stringify(escapedProfile));
	const escaped = await run(["--profile", escapedProfilePath, "--output", join(evidenceDir, "escaped-result.json"), "--dry-run"], {
		AIDR_LOAD_BASE_URL: `http://127.0.0.1:${address.port}`,
		AIDR_LOAD_SELF_TEST_SECRET: token,
	});
	assert.equal(escaped.status, 1);
	assert.match(escaped.stderr, /escapes the authorized origin/);
	checks.push("URL-normalized backslash paths cannot escape the authorized target origin");

	const timeoutProfile = {
		...JSON.parse(readFileSync(profilePath, "utf8")),
		workload_id: "load-harness-timeout",
		workload_class: "load",
		duration_seconds: 0.3,
		rate_per_second: 10,
		max_in_flight: 5,
		request_timeout_ms: 100,
		fault_windows: [],
		thresholds: { min_requests: 1, max_error_ratio: 0, max_loss_ratio: 1 },
		scenarios: [{
			...JSON.parse(readFileSync(profilePath, "utf8")).scenarios[0],
			path: "/slow",
			method: "GET",
			body_json: undefined,
			thresholds: undefined,
		}],
	};
	const timeoutProfilePath = join(evidenceDir, "timeout-profile.json");
	const timeoutResultPath = join(evidenceDir, "timeout-result.json");
	writeFileSync(timeoutProfilePath, JSON.stringify(timeoutProfile));
	const timeoutRun = await run(["--profile", timeoutProfilePath, "--output", timeoutResultPath], {
		AIDR_LOAD_BASE_URL: `http://127.0.0.1:${address.port}`,
		AIDR_LOAD_SELF_TEST_SECRET: token,
	});
	assert.equal(timeoutRun.status, 2, timeoutRun.stderr);
	const timeoutResult = JSON.parse(readFileSync(timeoutResultPath, "utf8"));
	assert.equal(timeoutResult.diagnostics.failure_classes.overall.timeout, timeoutResult.metrics.overall.completed);
	assert.equal(timeoutResult.metrics.overall.transport_errors, timeoutResult.metrics.overall.completed);
	checks.push("timeouts are reported distinctly from HTTP status failures and fail thresholds");

	const bodyLimitProfile = {
		...timeoutProfile,
		workload_id: "load-harness-body-limit",
		duration_seconds: 0.2,
		rate_per_second: 5,
		request_timeout_ms: 1000,
		max_response_bytes: 1,
		scenarios: [{ ...timeoutProfile.scenarios[0], path: "/unstable" }],
	};
	const bodyLimitProfilePath = join(evidenceDir, "body-limit-profile.json");
	const bodyLimitResultPath = join(evidenceDir, "body-limit-result.json");
	writeFileSync(bodyLimitProfilePath, JSON.stringify(bodyLimitProfile));
	const bodyLimitRun = await run(["--profile", bodyLimitProfilePath, "--output", bodyLimitResultPath], {
		AIDR_LOAD_BASE_URL: `http://127.0.0.1:${address.port}`,
		AIDR_LOAD_SELF_TEST_SECRET: token,
	});
	assert.equal(bodyLimitRun.status, 2, bodyLimitRun.stderr);
	const bodyLimitResult = JSON.parse(readFileSync(bodyLimitResultPath, "utf8"));
	assert.equal(bodyLimitResult.diagnostics.failure_classes.overall.response_body_limit, 1);
	assert.equal(bodyLimitResult.metrics.overall.transport_errors, 1);
	assert.equal(bodyLimitResult.metrics.overall.status_counts["200"], 1);
	checks.push("a successful HTTP status with an oversized body still fails as a transport/body error");

	const refused = await run(["--profile", profilePath, "--output", join(evidenceDir, "refused.json"), "--dry-run"], {
		AIDR_LOAD_BASE_URL: "https://example.invalid",
		AIDR_LOAD_SELF_TEST_SECRET: token,
	});
	assert.equal(refused.status, 1);
	assert.match(refused.stderr, /not authorized/);
	checks.push("non-loopback traffic requires an explicit authorized host");

	const overwriteRefused = await run(["--profile", profilePath, "--output", resultPath], {
		AIDR_LOAD_BASE_URL: `http://127.0.0.1:${address.port}`,
		AIDR_LOAD_SELF_TEST_SECRET: token,
	});
	assert.equal(overwriteRefused.status, 1);
	assert.match(overwriteRefused.stderr, /already exists/);
	checks.push("existing evidence cannot be overwritten without an explicit flag");
} finally {
	await new Promise((done) => server.close(done));
}

const evidence = {
	schema_version: 1,
	passed: true,
	checked_at: new Date().toISOString(),
	checks,
	scope: "isolated loopback harness behavior only; no cloud, HA, scale or SLA acceptance",
};
const evidencePath = join(evidenceDir, "verification.json");
writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`${checks.length} load harness checks passed. Evidence: ${evidencePath}`);
