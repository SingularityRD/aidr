#!/usr/bin/env node
/**
 * Local self-check for the monthly SLI report contract.
 *
 * This verifies arithmetic, explicit absence states, claim guardrails and the
 * bounded load-test schema without contacting a service or creating evidence in
 * the repository.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	generateMonthlyReport,
	STATUS_FAIL,
	STATUS_NOT_RUN,
	STATUS_UNKNOWN,
	validateMonthlyInput,
	validateMonthlyReport,
} from "./monthly-sli-report.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const START = "2026-09-01T00:00:00.000Z";
const END = "2026-09-01T00:00:10.000Z";
const GENERATED = "2026-09-02T00:00:00.000Z";

function fixture(overrides = {}) {
	return {
		schema_version: 1,
		kind: "aidr_monthly_sli_observations",
		month: "2026-09",
		scope: { service: "managed-control-plane-and-dashboard-api", endpoints: ["dashboard-api"], regions: ["local"] },
		observation_window: { start_at: START, end_at: END },
		objective: { availability_ratio: 0.999, contractual: false, label: "internal_reference_only" },
		observations: [],
		exclusions: [],
		incidents: [],
		...structuredClone(overrides),
	};
}

function observation(startAt, endAt, status, reason = "fixture") {
	return { endpoint: "dashboard-api", region: "local", start_at: startAt, end_at: endAt, status, reason };
}

function expectValid(report) {
	const result = validateMonthlyReport(report);
	assert.equal(result.valid, true, result.errors.join("\n"));
}

export function runVerification() {
	const checks = [];
	const complete = generateMonthlyReport(fixture({ observations: [
		observation(START, "2026-09-01T00:00:09.000Z", "good"),
		observation("2026-09-01T00:00:09.000Z", END, "unavailable", "fixture outage"),
	] }), { sourceFile: "fixture.json", sourceSha256: "b".repeat(64), generatedAt: GENERATED });
	assert.equal(complete.status, STATUS_FAIL);
	assert.equal(complete.sli.good_seconds, 9);
	assert.equal(complete.sli.unavailable_seconds, 1);
	assert.equal(complete.error_budget.remaining_error_seconds, -0.99);
	expectValid(complete);
	checks.push("complete windows derive availability and error-budget counters");

	const notRun = generateMonthlyReport(fixture(), { generatedAt: GENERATED });
	assert.equal(notRun.status, STATUS_NOT_RUN);
	assert.equal(notRun.sli.availability_ratio, null);
	assert.equal(notRun.error_budget.allowed_error_seconds, null);
	assert.ok(notRun.series[0].intervals.every((interval) => interval.status === STATUS_NOT_RUN));
	expectValid(notRun);
	checks.push("missing observations are emitted as explicit NOT_RUN");

	const unknown = generateMonthlyReport(fixture({ observations: [observation(START, "2026-09-01T00:00:05.000Z", STATUS_UNKNOWN, "ambiguous local probe")] }), { generatedAt: GENERATED });
	assert.equal(unknown.status, STATUS_UNKNOWN);
	assert.equal(unknown.sli.unknown_seconds, 5);
	assert.equal(unknown.sli.not_run_seconds, 5);
	assert.equal(unknown.error_budget.allowed_error_seconds, null);
	expectValid(unknown);
	checks.push("ambiguous observations remain unknown and gaps remain NOT_RUN");

	const fakeClaim = structuredClone(complete);
	fakeClaim.claims.contractual_99_9_claim = true;
	const claimValidation = validateMonthlyReport(fakeClaim);
	assert.equal(claimValidation.valid, false);
	assert.ok(claimValidation.errors.some((error) => error.includes("contractual_99_9_claim must be false")));
	checks.push("contractual availability claims are hard-blocked");

	const fakeArithmetic = structuredClone(complete);
	fakeArithmetic.error_budget.remaining_error_seconds = 0;
	const arithmeticValidation = validateMonthlyReport(fakeArithmetic);
	assert.equal(arithmeticValidation.valid, false);
	assert.ok(arithmeticValidation.errors.some((error) => error.includes("error budget counters")));
	checks.push("report arithmetic is recomputed by the validator");

	const malformedInput = fixture({ objective: { availability_ratio: 0.999, contractual: true, label: "internal_reference_only" } });
	assert.match(validateMonthlyInput(malformedInput).join("\n"), /contractual.*false/);
	checks.push("input refuses a contractual objective declaration");

	const reportSchema = JSON.parse(readFileSync(resolve(ROOT, "deploy/ha/monthly-sli-report.schema.json"), "utf8"));
	const inputSchema = JSON.parse(readFileSync(resolve(ROOT, "deploy/ha/monthly-sli-observations.schema.json"), "utf8"));
	assert.deepEqual(reportSchema.$defs.status.enum, ["PASS", "FAIL", "NOT_RUN", "unknown"]);
	assert.equal(reportSchema.$defs.claims.properties.contractual_99_9_claim.const, false);
	assert.equal(reportSchema.properties.limitations.maxItems, 103);
	assert.equal(reportSchema.$defs.report_window.properties.series_count.maximum, 1000);
	assert.equal(reportSchema.$defs.series.properties.intervals.maxItems, 220001);
	assert.equal(inputSchema.properties.$schema.const, "https://singularity.example/schemas/aidr-monthly-sli-observations-v1.json");
	assert.equal(inputSchema.properties.observations.maxItems, 100000);
	assert.equal(inputSchema.properties.exclusions.maxItems, 10000);
	assert.equal(inputSchema.properties.incidents.maxItems, 10000);
	assert.equal(inputSchema.properties.limitations.maxItems, 100);
	checks.push("machine-readable input/report schemas keep unknown/NOT_RUN explicit, bounded collections and contractual claims false");

	const loadSchema = JSON.parse(readFileSync(resolve(ROOT, "deploy/ha/workload-profile.schema.json"), "utf8"));
	const loadLimits = {
		duration_seconds: [0.2, 604800],
		rate_per_second: [0.1, 10000],
		max_in_flight: [1, 10000],
		request_timeout_ms: [100, 120000],
		max_response_bytes: [0, 16777216],
		max_latency_samples: [100, 1000000],
		max_fault_event_samples: [100, 1000000],
	};
	for (const [property, [minimum, maximum]] of Object.entries(loadLimits)) {
		assert.equal(loadSchema.properties[property].minimum, minimum, `${property} minimum changed`);
		assert.equal(loadSchema.properties[property].maximum, maximum, `${property} maximum changed`);
	}
	checks.push("existing load-test duration, rate, concurrency, timeout, body and sample limits are unchanged");

	return { schema_version: 1, passed: true, checks, scope: "local monthly SLI generator and validator only; no contractual SLA acceptance" };
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		const result = runVerification();
		console.log(`${result.checks.length} monthly SLI verification checks passed.`);
	} catch (error) {
		console.error(`Monthly SLI verification failed: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	}
}
