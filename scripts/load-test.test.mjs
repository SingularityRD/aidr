#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("telemetry workload can generate distinct string request identities", async () => {
	const ids = [];
	await withFixture((request, response) => {
		let text = "";
		request.on("data", chunk => { text += chunk; });
		request.on("end", () => {
			const id = JSON.parse(text).event_id;
			const valid = typeof id === "string" && /^[a-f0-9-]{36}$/.test(id);
			if (valid) ids.push(id);
			response.writeHead(valid ? 200 : 400); response.end();
		});
	}, async run => {
		const { status, result } = await run(profile({
			workload_class: "soak", duration_seconds: 0.5, rate_per_second: 10,
			fault_windows: [], thresholds: { min_requests: 4, max_error_ratio: 0, max_loss_ratio: 0 },
			scenarios: [{ name: "unique-events", cohort: "one", method: "POST", path: "/ingest", weight: 1, expected_statuses: [200], body_json: { event_id: { $request_id: true }, sequence: { $sequence: true } } }],
		}));
		assert.equal(status, 0); assert.equal(result.passed, true);
		assert.ok(ids.length >= 4); assert.equal(new Set(ids).size, ids.length);
	});
});

const harness = fileURLToPath(new URL("./load-test.mjs", import.meta.url));

test("a fast request still observes the full declared workload window", async () => {
	await withFixture((_request, response) => response.end(), async run => {
		const { status, result } = await run(profile({
			workload_class: "soak", duration_seconds: 0.3, rate_per_second: 1,
			fault_windows: [], scenarios: [{ name: "fast", cohort: "one", method: "GET", path: "/", weight: 1, expected_statuses: [200] }],
		}));
		assert.equal(status, 0);
		assert.ok(Date.parse(result.completed_at) - Date.parse(result.started_at) >= 300);
		assert.ok(result.diagnostics.generator.drain_finished_at_ms >= 300);
	});
});

async function withFixture(handler, check) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-load-test-"));
	const server = createServer(handler);
	await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
	try {
		const address = server.address();
		assert.ok(address && typeof address === "object");
		let sequence = 0;
		const run = async (profile, dryRun = false) => {
			const number = ++sequence;
			const profilePath = join(directory, `profile-${number}.json`);
			const resultPath = join(directory, `result-${number}.json`);
			writeFileSync(profilePath, JSON.stringify(profile));
			const args = [harness, "--profile", profilePath, "--output", resultPath];
			if (dryRun) args.push("--dry-run");
			const processResult = await new Promise((resolve, reject) => {
				const child = spawn(process.execPath, args, {
					env: { ...process.env, AIDR_LOAD_TEST_ORIGIN: `http://127.0.0.1:${address.port}` },
					stdio: ["ignore", "pipe", "pipe"],
				});
				let stderr = "";
				child.stderr.on("data", (chunk) => { stderr += chunk; });
				child.on("error", reject);
				child.on("close", (status) => resolve({ status, stderr }));
			});
			return { ...processResult, result: dryRun || processResult.status === 1 ? null : JSON.parse(readFileSync(resultPath, "utf8")) };
		};
		await check(run);
	} finally {
		await new Promise((resolve) => server.close(resolve));
		rmSync(directory, { recursive: true, force: true });
	}
}

function profile(overrides = {}) {
	return {
		schema_version: 1,
		workload_id: "isolated-failover-regression",
		workload_class: "failover",
		base_url_env: "AIDR_LOAD_TEST_ORIGIN",
		duration_seconds: 1.2,
		rate_per_second: 8,
		max_in_flight: 8,
		thresholds: { min_requests: 1, max_error_ratio: 1, max_loss_ratio: 1 },
		scenarios: [
			{ name: "failing", cohort: "one", method: "GET", path: "/down", weight: 1, expected_statuses: [200] },
			{ name: "healthy", cohort: "two", method: "GET", path: "/up", weight: 1, expected_statuses: [200] },
		],
		fault_windows: [{ name: "node-failure", target: "isolated-fixture", scenario_names: ["failing", "healthy"], start_seconds: 0, end_seconds: 0.8, recovery_confirmation_successes: 2, require_fault_observed: true }],
		...overrides,
	};
}

test("healthy scenario cannot establish recovery for a failing scenario", async () => {
	await withFixture((request, response) => {
		response.writeHead(request.url === "/down" ? 503 : 200);
		response.end();
	}, async (run) => {
		const { status, stderr, result } = await run(profile());
		assert.equal(status, 2, stderr);
		assert.equal(result.fault_observations[0].status, "not_recovered");
		assert.equal(result.fault_observations[0].fault_observed, true);
		assert.equal(result.fault_observations[0].estimated_rto_ms, null);
		assert.ok(result.threshold_checks.some((check) => check.metric === "observation_complete" && !check.passed));
	});
});

test("fault window without a sample from every scoped scenario fails closed", async () => {
	await withFixture((request, response) => {
		response.writeHead(request.url === "/down" ? 503 : 200);
		response.end();
	}, async (run) => {
		const candidate = profile({
			duration_seconds: 0.3,
			rate_per_second: 1,
			fault_windows: [{ name: "node-failure", target: "isolated-fixture", scenario_names: ["failing", "healthy"], start_seconds: 0, end_seconds: 0.2, require_fault_observed: true }],
		});
		const { status, stderr, result } = await run(candidate);
		assert.equal(status, 2, stderr);
		assert.equal(result.fault_observations[0].status, "insufficient_samples");
		assert.ok(result.threshold_checks.some((check) => check.metric === "observation_complete" && !check.passed));
	});
});

test("fault windows reject empty targets, zero-width intervals and non-boolean requirements", async () => {
	await withFixture((_request, response) => response.end(), async (run) => {
		for (const [override, expected] of [
			[{ target: " " }, /target must identify/],
			[{ end_seconds: 0 }, /end_seconds must be after/],
			[{ require_fault_observed: "false" }, /must be a boolean/],
		]) {
			const candidate = profile({ fault_windows: [{ ...profile().fault_windows[0], ...override }] });
			const { status, stderr } = await run(candidate, true);
			assert.equal(status, 1);
			assert.match(stderr, expected);
		}
	});
});

test("failover profiles cannot pass without a required observed fault", async () => {
	await withFixture((_request, response) => { response.writeHead(200); response.end(); }, async (run) => {
		for (const [faultWindows, expected] of [
			[[], /require at least one fault window/],
			[[{ ...profile().fault_windows[0], require_fault_observed: false }], /must be true for failover workloads/],
			[[{ ...profile().fault_windows[0], require_fault_observed: undefined }], /must be true for failover workloads/],
		]) {
			const { status, stderr } = await run(profile({ fault_windows: faultWindows }), true);
			assert.equal(status, 1);
			assert.match(stderr, expected);
		}
	});
});

test("load-shed requests require an explicit loss/availability bound and fail the run", async () => {
	await withFixture((_request, response) => {
		setTimeout(() => { response.writeHead(200); response.end(); }, 120);
	}, async (run) => {
		const base = profile({
			workload_class: "load",
			duration_seconds: 0.5,
			rate_per_second: 40,
			max_in_flight: 1,
			fault_windows: [],
			scenarios: [{ name: "slow", cohort: "one", method: "GET", path: "/slow", weight: 1, expected_statuses: [200] }],
			thresholds: { min_requests: 1, max_error_ratio: 0 },
		});
		const missingBound = await run(base, true);
		assert.equal(missingBound.status, 1);
		assert.match(missingBound.stderr, /generator-loss or end-to-end availability bound/);

		const bounded = {
			...base,
			thresholds: { min_requests: 1, max_error_ratio: 0, max_loss_ratio: 0 },
		};
		const { status, stderr, result } = await run(bounded);
		assert.equal(status, 2, stderr);
		assert.ok(result.metrics.overall.dropped_requests > 0);
		assert.ok(result.metrics.overall.loss_ratio > 0);
		assert.ok(result.threshold_checks.some((check) => check.label === "overall" && check.metric === "loss_ratio" && !check.passed));
	});
});

test("scenario thresholds also require a loss or end-to-end availability bound", async () => {
	await withFixture((_request, response) => response.end(), async (run) => {
		const candidate = profile({
			scenarios: [{ ...profile().scenarios[0], thresholds: { min_requests: 1, max_error_ratio: 0 } }],
		});
		const { status, stderr } = await run(candidate, true);
		assert.equal(status, 1);
		assert.match(stderr, /failing\.thresholds requires min_requests and a generator-loss or end-to-end availability bound/);
	});
});
