import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
	generateMonthlyReport,
	STATUS_FAIL,
	STATUS_NOT_RUN,
	STATUS_PASS,
	STATUS_UNKNOWN,
	validateMonthlyInput,
	validateMonthlyReport,
} from "./monthly-sli-report.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(SCRIPT_DIR, "..");
const SCRIPT = resolve(SCRIPT_DIR, "monthly-sli-report.mjs");
const START = "2026-09-01T00:00:00.000Z";
const END = "2026-09-01T00:00:10.000Z";
const GENERATED = "2026-09-02T00:00:00.000Z";

function input(overrides = {}) {
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

function observation(startAt, endAt, status, reason) {
	return {
		endpoint: "dashboard-api",
		region: "local",
		start_at: startAt,
		end_at: endAt,
		status,
		...(reason ? { reason } : {}),
	};
}

function completeInput(status = "good") {
	return input({ observations: [observation(START, END, status, status === "good" ? undefined : "fixture outcome")] });
}

function assertValid(report) {
	const result = validateMonthlyReport(report);
	assert.equal(result.valid, true, result.errors.join("\n"));
}

test("a complete local window computes availability and error budget without a contractual claim", () => {
	const report = generateMonthlyReport(input({ observations: [
		observation(START, "2026-09-01T00:00:08.000Z", "good"),
		observation("2026-09-01T00:00:08.000Z", END, "unavailable", "synthetic outage"),
	] }), { sourceFile: "observations.json", sourceSha256: "a".repeat(64), generatedAt: GENERATED });

	assert.equal(report.status, STATUS_FAIL);
	assert.equal(report.sli.good_seconds, 8);
	assert.equal(report.sli.unavailable_seconds, 2);
	assert.equal(report.sli.eligible_seconds, 10);
	assert.equal(report.sli.availability_ratio, 0.8);
	assert.equal(report.error_budget.allowed_error_seconds, 0.01);
	assert.equal(report.error_budget.consumed_error_seconds, 2);
	assert.equal(report.error_budget.remaining_error_seconds, -1.99);
	assert.equal(report.claims.contractual_99_9_claim, false);
	assert.equal(report.claims.contractual_sla_claim, false);
	assert.equal(report.evidence.source_sha256, "a".repeat(64));
	assertValid(report);
});

test("empty observations are explicit NOT_RUN and do not publish an availability or budget duration", () => {
	const report = generateMonthlyReport(input(), { generatedAt: GENERATED });

	assert.equal(report.status, STATUS_NOT_RUN);
	assert.equal(report.coverage.status, STATUS_NOT_RUN);
	assert.equal(report.sli.availability_ratio, null);
	assert.equal(report.sli.not_run_seconds, 10);
	assert.equal(report.error_budget.allowed_error_seconds, null);
	assert.equal(report.error_budget.consumed_error_seconds, null);
	assert.ok(report.series[0].intervals.every((interval) => interval.status === STATUS_NOT_RUN));
	assert.equal(report.evidence.source_sha256, STATUS_UNKNOWN);
	assertValid(report);
});

test("an explicit unknown and an uncovered interval remain distinguishable", () => {
	const report = generateMonthlyReport(input({ observations: [
		observation(START, "2026-09-01T00:00:03.000Z", "good"),
		observation("2026-09-01T00:00:03.000Z", "2026-09-01T00:00:06.000Z", STATUS_UNKNOWN, "probe output was ambiguous"),
	] }), { generatedAt: GENERATED });

	assert.equal(report.status, STATUS_UNKNOWN);
	assert.equal(report.sli.good_seconds, 3);
	assert.equal(report.sli.unknown_seconds, 3);
	assert.equal(report.sli.not_run_seconds, 4);
	assert.deepEqual(report.series[0].intervals.map((interval) => interval.status), ["good", STATUS_UNKNOWN, STATUS_NOT_RUN]);
	assertValid(report);
});

test("approved maintenance is excluded, while an unapproved exclusion is rejected", () => {
	const maintenance = {
		endpoint: "dashboard-api",
		region: "local",
		start_at: "2026-09-01T00:00:04.000Z",
		end_at: "2026-09-01T00:00:06.000Z",
		category: "approved_maintenance",
		approved: true,
		reference: "maintenance-window-1",
	};
	const report = generateMonthlyReport(input({
		observations: [
			observation(START, "2026-09-01T00:00:04.000Z", "good"),
			observation("2026-09-01T00:00:04Z", "2026-09-01T00:00:06Z", "excluded", "maintenance-window-1"),
			observation("2026-09-01T00:00:06.000Z", END, "good"),
		],
		exclusions: [maintenance],
		incidents: [{ id: "incident-1", start_at: "2026-09-01T00:00:06.000Z", end_at: "2026-09-01T00:00:07.000Z", classification: "unavailable", evidence_status: "observed", reference: "local-incident-log" }],
	}), { generatedAt: GENERATED });
	assert.equal(report.status, STATUS_PASS);
	assert.equal(report.sli.excluded_seconds, 2);
	assert.equal(report.sli.eligible_seconds, 8);
	assert.equal(report.sli.availability_ratio, 1);
	assert.equal(report.incidents.length, 1);
	assertValid(report);

	const unapproved = input({ exclusions: [{ ...maintenance, approved: false }] });
	assert.match(validateMonthlyInput(unapproved).join("\n"), /unapproved exclusions/);
});

test("a scoped series with no eligible time keeps the overall report unknown", () => {
	const report = generateMonthlyReport(input({
		scope: { service: "managed-control-plane-and-dashboard-api", endpoints: ["dashboard-api", "worker-api"], regions: ["local"] },
		observations: [observation(START, END, "good")],
		exclusions: [{ endpoint: "worker-api", region: "local", start_at: START, end_at: END, category: "approved_maintenance", approved: true, reference: "worker-maintenance" }],
	}), { generatedAt: GENERATED });
	assert.equal(report.status, STATUS_UNKNOWN);
	assert.equal(report.coverage.complete, false);
	assert.equal(report.error_budget.allowed_error_seconds, null);
	assert.equal(report.series.find((entry) => entry.endpoint === "worker-api").status, STATUS_UNKNOWN);
	assertValid(report);
});

test("the validator rejects malformed schema markers, reversed or unlinked exclusions, and malformed intervals without throwing", () => {
	const report = generateMonthlyReport(input({
		observations: [observation(START, "2026-09-01T00:00:04.000Z", "good"), observation("2026-09-01T00:00:06.000Z", END, "good")],
		exclusions: [{ endpoint: "dashboard-api", region: "local", start_at: "2026-09-01T00:00:04.000Z", end_at: "2026-09-01T00:00:06.000Z", category: "approved_maintenance", approved: true, reference: "maintenance" }],
	}), { generatedAt: GENERATED });
	const badSchema = structuredClone(report);
	badSchema.$schema = 42;
	assert.equal(validateMonthlyReport(badSchema).valid, false);
	const badInputSchema = input({ $schema: 42 });
	assert.match(validateMonthlyInput(badInputSchema).join("\n"), /input\.\$schema must be https:\/\/singularity\.example\/schemas\/aidr-monthly-sli-observations-v1\.json/);
	const reversed = structuredClone(report);
	reversed.exclusions[0].start_at = END;
	reversed.exclusions[0].end_at = START;
	assert.match(validateMonthlyReport(reversed).errors.join("\n"), /end_at must be after start_at/);
	const missingLink = structuredClone(report);
	missingLink.exclusions = [];
	assert.match(validateMonthlyReport(missingLink).errors.join("\n"), /exactly one matching approved exclusion/);
	const unlinked = structuredClone(report);
	unlinked.exclusions.push({ endpoint: "dashboard-api", region: "local", start_at: START, end_at: "2026-09-01T00:00:01.000Z", category: "approved_maintenance", approved: true, reference: "not-linked" });
	assert.match(validateMonthlyReport(unlinked).errors.join("\n"), /must link to exactly one/);
	const nullInterval = structuredClone(report);
	nullInterval.series[0].intervals = [null];
	assert.doesNotThrow(() => validateMonthlyReport(nullInterval));
	assert.equal(validateMonthlyReport(nullInterval).valid, false);
	const duplicateIncidents = structuredClone(report);
	duplicateIncidents.incidents = [
		{ id: "duplicate", start_at: START, end_at: "2026-09-01T00:00:01.000Z", classification: "unavailable", evidence_status: "observed", reference: "first" },
		{ id: "duplicate", start_at: "2026-09-01T00:00:02.000Z", end_at: "2026-09-01T00:00:03.000Z", classification: "unavailable", evidence_status: "observed", reference: "second" },
	];
	assert.match(validateMonthlyReport(duplicateIncidents).errors.join("\n"), /duplicates incident duplicate/);
	const missingWindow = structuredClone(report);
	delete missingWindow.observation_window;
	assert.doesNotThrow(() => validateMonthlyReport(missingWindow));
	assert.equal(validateMonthlyReport(missingWindow).valid, false);
});

test("the validator catches arithmetic drift and any attempt to make a contractual claim", () => {
	const report = generateMonthlyReport(completeInput(), { generatedAt: GENERATED });
	const drifted = structuredClone(report);
	drifted.sli.availability_ratio = 0;
	drifted.claims.contractual_99_9_claim = true;
	const result = validateMonthlyReport(drifted);
	assert.equal(result.valid, false);
	assert.match(result.errors.join("\n"), /availability_ratio does not match/);
	assert.match(result.errors.join("\n"), /claims\.contractual_99_9_claim must be false/);
	const intervalTampered = structuredClone(report);
	intervalTampered.series[0].intervals[0].status = "unavailable";
	const intervalResult = validateMonthlyReport(intervalTampered);
	assert.equal(intervalResult.valid, false);
	assert.match(intervalResult.errors.join("\n"), /does not match interval statuses/);
});

test("the objective comparison does not round a just-below-target result up to PASS", () => {
	const start = Date.parse("2026-09-01T00:00:00.000Z");
	const longEnd = new Date(start + 2_000_000 * 1000).toISOString();
	const goodEnd = new Date(start + 1_997_998 * 1000).toISOString();
	const report = generateMonthlyReport(input({
		observation_window: { start_at: new Date(start).toISOString(), end_at: longEnd },
		observations: [observation(new Date(start).toISOString(), goodEnd, "good"), observation(goodEnd, longEnd, "unavailable", "boundary outage")],
	}), { generatedAt: GENERATED });
	assert.equal(report.sli.availability_ratio, 0.998999);
	assert.equal(report.status, STATUS_FAIL);
	assertValid(report);
});

test("the validator accepts a valid FAIL report but rejects a fake PASS status", () => {
	const report = generateMonthlyReport(completeInput("unavailable"), { generatedAt: GENERATED });
	assert.equal(report.status, STATUS_FAIL);
	assertValid(report);
	const fakePass = structuredClone(report);
	fakePass.status = STATUS_PASS;
	fakePass.coverage.status = STATUS_PASS;
	fakePass.sli.status = STATUS_PASS;
	fakePass.error_budget.status = STATUS_PASS;
	const result = validateMonthlyReport(fakePass);
	assert.equal(result.valid, false);
	assert.match(result.errors.join("\n"), /status fields do not match the counters/);
});

test("the CLI generates and validates a report from local files without overwriting evidence", () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-monthly-sli-"));
	try {
		const inputPath = join(directory, "observations.json");
		const outputPath = join(directory, "report.json");
		writeFileSync(inputPath, `${JSON.stringify(completeInput(), null, 2)}\n`);
		const generated = spawnSync(process.execPath, [SCRIPT, "--input", inputPath, "--output", outputPath, "--generated-at", GENERATED], { cwd: ROOT, encoding: "utf8" });
		assert.equal(generated.status, 0, generated.stderr);
		const report = JSON.parse(readFileSync(outputPath, "utf8"));
		assert.equal(report.evidence.source_file, "observations.json");
		assert.match(report.evidence.source_sha256, /^[a-f0-9]{64}$/);
		const validated = spawnSync(process.execPath, [SCRIPT, "validate", "--report", outputPath, "--input", inputPath], { cwd: ROOT, encoding: "utf8" });
		assert.equal(validated.status, 0, validated.stderr);
		const tamperedInputPath = join(directory, "tampered-observations.json");
		writeFileSync(tamperedInputPath, `${JSON.stringify({ ...completeInput(), limitations: ["changed after collection"] })}\n`);
		const tamperedValidation = spawnSync(process.execPath, [SCRIPT, "validate", "--report", outputPath, "--input", tamperedInputPath], { cwd: ROOT, encoding: "utf8" });
		assert.equal(tamperedValidation.status, 1);
		assert.match(tamperedValidation.stderr, /source file/);
		const positionalValidated = spawnSync(process.execPath, [SCRIPT, "validate", outputPath], { cwd: ROOT, encoding: "utf8" });
		assert.equal(positionalValidated.status, 0, positionalValidated.stderr);
		const flagValidated = spawnSync(process.execPath, [SCRIPT, "--validate", "--report", outputPath], { cwd: ROOT, encoding: "utf8" });
		assert.equal(flagValidated.status, 0, flagValidated.stderr);
		const second = spawnSync(process.execPath, [SCRIPT, "--input", inputPath, "--output", outputPath], { cwd: ROOT, encoding: "utf8" });
		assert.equal(second.status, 2);
		assert.match(second.stderr, /EEXIST|already exists/i);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});

test("the report schemas keep unknown/NOT_RUN explicit, bounded collections and contractual claim flags false", () => {
	const schema = JSON.parse(readFileSync(resolve(ROOT, "deploy/ha/monthly-sli-report.schema.json"), "utf8"));
	const inputSchema = JSON.parse(readFileSync(resolve(ROOT, "deploy/ha/monthly-sli-observations.schema.json"), "utf8"));
	assert.deepEqual(schema.$defs.status.enum, ["PASS", "FAIL", "NOT_RUN", "unknown"]);
	assert.equal(schema.$defs.claims.properties.contractual_99_9_claim.const, false);
	assert.equal(schema.$defs.target.properties.contractual.const, false);
	assert.equal(inputSchema.properties.$schema.const, "https://singularity.example/schemas/aidr-monthly-sli-observations-v1.json");
	assert.equal(inputSchema.properties.observations.maxItems, 100000);
	assert.equal(inputSchema.properties.limitations.maxItems, 100);
	assert.equal(schema.properties.series.maxItems, 1000);
	assert.equal(schema.$defs.report_window.properties.series_count.maximum, 1000);
	assert.equal(schema.properties.limitations.maxItems, 103);
	assert.equal(schema.$defs.series.properties.intervals.maxItems, 220001);
});

test("the load-test schema limits remain the existing bounded harness limits", () => {
	const schema = JSON.parse(readFileSync(resolve(ROOT, "deploy/ha/workload-profile.schema.json"), "utf8"));
	assert.equal(schema.properties.duration_seconds.minimum, 0.2);
	assert.equal(schema.properties.duration_seconds.maximum, 604800);
	assert.equal(schema.properties.rate_per_second.maximum, 10000);
	assert.equal(schema.properties.max_in_flight.maximum, 10000);
	assert.equal(schema.properties.request_timeout_ms.maximum, 120000);
	assert.equal(schema.properties.max_response_bytes.maximum, 16777216);
});
