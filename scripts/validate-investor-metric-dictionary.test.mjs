import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
	COMPLETENESS_FIELDS,
	HELD,
	NOT_HELD,
	ROOT,
	UNKNOWN,
	metricCompleteness,
	parseTemplateMetricIds,
	readInvestorMetricDictionary,
	validateAgainstSchema,
	validateMetricDictionary,
} from "./validate-investor-metric-dictionary.mjs";

const loaded = readInvestorMetricDictionary();
const template = readFileSync(join(ROOT, "docs/production-readiness/investor-metric-dictionary-template.md"), "utf8");
const EVIDENCE_REF = "docs/production-readiness/investor-metric-dictionary.schema.json";
const EVIDENCE_SHA256 = createHash("sha256").update(readFileSync(join(ROOT, EVIDENCE_REF))).digest("hex");

function fixture() {
	return {
		dictionary: structuredClone(loaded.dictionary),
		schema: structuredClone(loaded.schema),
		templateMetrics: structuredClone(loaded.templateMetrics),
		templateIds: structuredClone(loaded.templateIds),
	};
}

function fullySpecify(metric, status = HELD) {
	return Object.assign(metric, {
		formula: "activated enrolled agents / ordered entitlements",
		denominator: "ordered entitlements",
		source: "fixture source",
		source_query: "fixture query",
		candidate: "fixture-candidate",
		candidate_digest: EVIDENCE_SHA256,
		candidate_ref: EVIDENCE_REF,
		environment: "fixture environment",
		fixture_version: "fixture-v1",
		window: "2026-01-01/2026-01-31 UTC",
		sample_size: 1,
		target_actual_status: "target_met",
		confidence: "fixture confidence",
		owner: "Product",
		reviewer: "Independent Finance reviewer",
		evidence_ref: EVIDENCE_REF,
		evidence_sha256: EVIDENCE_SHA256,
		reviewed_at_utc: "2026-01-01T00:00:00.000Z",
		status,
	});
}

function failuresOf(input) {
	return validateMetricDictionary(input).failures.join("\n");
}

test("the shipped dictionary is schema-valid and honestly remains NOT_HELD", () => {
	const result = validateMetricDictionary(loaded);
	assert.deepEqual(result.failures, []);
	assert.equal(result.summary.metricCount, 9);
	assert.equal(result.summary.completeCount, 0);
	assert.equal(result.summary.incompleteCount, 9);
	assert.deepEqual(result.summary.statuses, { [NOT_HELD]: 9 });
	for (const metric of result.summary.incompleteMetrics) {
		assert.ok(metric.missing.length > 0);
		assert.equal(loaded.dictionary.metrics.find((item) => item.metric_id === metric.metric_id).status, NOT_HELD);
	}
});

test("the machine dictionary covers exactly the rows in the human template", () => {
	const templateIds = parseTemplateMetricIds(template);
	const dictionaryIds = loaded.dictionary.metrics.map((metric) => metric.metric_id);
	assert.deepEqual(templateIds, dictionaryIds);
	assert.deepEqual([...new Set(templateIds)], templateIds);
});

test("unknown is the only accepted sentinel for an incomplete required field", () => {
	const input = fixture();
	const metric = input.dictionary.metrics[0];
	metric.environment = UNKNOWN;
	assert.deepEqual(validateMetricDictionary(input).failures, []);

	metric.environment = "TBD";
	assert.match(failuresOf(input), /INV-M001: incomplete environment must be exactly "unknown"/);
	assert.match(failuresOf(input), /forbidden schema shape|oneOf subschema/);
});

test("a blank missing field cannot hide behind NOT_HELD", () => {
	const input = fixture();
	input.dictionary.metrics[1].window = "";
	const failures = failuresOf(input);
	assert.match(failures, /INV-M002: incomplete window must be exactly "unknown"/);
	assert.match(failures, /metrics\[1\]\.window/);
});

test("an incomplete metric cannot be promoted to HELD", () => {
	const input = fixture();
	input.dictionary.metrics[0].status = HELD;
	input.dictionary.status = HELD;
	const failures = failuresOf(input);
	assert.match(failures, /INV-M001: incomplete metric must remain NOT_HELD/);
	assert.match(failures, /INV-M001: HELD metric has incomplete required fields/);
	assert.match(failures, /dictionary with incomplete metrics must remain NOT_HELD/);
});

test("a fully specified metric may be HELD only with a distinct reviewer", () => {
	const input = fixture();
	const metric = fullySpecify(input.dictionary.metrics[0]);
	input.dictionary.metrics = [metric];
	input.dictionary.status = HELD;
	delete input.templateMetrics;
	delete input.templateIds;
	assert.deepEqual(validateMetricDictionary(input).failures, []);

	metric.reviewer = metric.owner;
	assert.match(failuresOf(input), /INV-M001: owner and reviewer must be different for a HELD metric/);
});

test("HELD evidence must be an existing repository file with the recorded hash", () => {
	const input = fixture();
	const metric = fullySpecify(input.dictionary.metrics[0]);
	input.dictionary.metrics = [metric];
	input.dictionary.status = HELD;
	delete input.templateMetrics;
	delete input.templateIds;

	metric.candidate_digest = "b".repeat(64);
	assert.match(failuresOf(input), /INV-M001: candidate_digest does not match/);

	metric.candidate_digest = EVIDENCE_SHA256;
	metric.candidate_ref = "docs/production-readiness/no-such-candidate.json";
	assert.match(failuresOf(input), /INV-M001: candidate_ref does not exist on disk/);

	metric.candidate_ref = EVIDENCE_REF;
	metric.evidence_sha256 = "b".repeat(64);
	assert.match(failuresOf(input), /INV-M001: evidence_sha256 does not match/);

	metric.evidence_sha256 = EVIDENCE_SHA256;
	metric.evidence_ref = "docs/production-readiness/no-such-evidence.json";
	assert.match(failuresOf(input), /INV-M001: evidence_ref does not exist on disk/);
});

test("template metric IDs must be unique and match the machine dictionary", () => {
	const input = fixture();
	delete input.templateMetrics;
	input.templateIds = [...input.templateIds, input.templateIds[0]];
	assert.match(failuresOf(input), /template contains duplicate metric IDs/);

	input.templateIds = loaded.templateIds.slice(1);
	assert.match(failuresOf(input), /dictionary metric IDs and template metric IDs differs/);
});

test("template content cannot drift from the canonical dictionary", () => {
	const input = fixture();
	input.templateMetrics[0].formula = "invented formula";
	assert.match(failuresOf(input), /INV-M001: template formula differs from dictionary/);

	input.templateMetrics[0].formula = loaded.templateMetrics[0].formula;
	input.templateMetrics[0].name = "invented metric";
	assert.match(failuresOf(input), /INV-M001: template name differs from dictionary/);
});

test("a missing template is a validation failure, not an unknown that passes", () => {
	const input = fixture();
	input.templateMetrics = null;
	delete input.templateIds;
	assert.match(failuresOf(input), /investor metric dictionary template .* could not be read/);
});

test("a complete definition can remain NOT_HELD until approval exists", () => {
	const input = fixture();
	const metric = fullySpecify(input.dictionary.metrics[0], NOT_HELD);
	delete input.templateMetrics;
	delete input.templateIds;
	assert.equal(metricCompleteness(metric).complete, true);
	assert.deepEqual(validateMetricDictionary(input).failures, []);
	assert.equal(input.dictionary.status, NOT_HELD);
	assert.equal(metric.status, NOT_HELD);
});

test("schema rejects missing required metadata and additional properties", () => {
	const input = fixture();
	delete input.dictionary.metrics[0].denominator;
	input.dictionary.metrics[0].unreviewed_value = 42;
	const schemaErrors = validateAgainstSchema(input.dictionary, input.schema);
	assert.ok(schemaErrors.some((error) => error.includes("missing required property 'denominator'")));
	assert.ok(schemaErrors.some((error) => error.includes("additional property 'unreviewed_value' is not allowed")));
	assert.match(failuresOf(input), /missing required property 'denominator'/);
});

test("the schema requires every completeness and evidence field", () => {
	const required = new Set(loaded.schema.$defs.metric.required);
	for (const field of [...COMPLETENESS_FIELDS, "limitations"]) assert.ok(required.has(field), `schema missing ${field}`);
});

test("the schema contract itself cannot drop a required completeness field", () => {
	const input = fixture();
	input.schema.$defs.metric.required = input.schema.$defs.metric.required.filter((field) => field !== "limitations");
	const failures = failuresOf(input);
	assert.match(failures, /metric dictionary schema must require limitations per metric/);
});

test("completeness fields stay explicit and ordered", () => {
	assert.deepEqual(COMPLETENESS_FIELDS, [
		"formula",
		"denominator",
		"source",
		"source_query",
		"candidate",
		"candidate_digest",
		"candidate_ref",
		"environment",
		"fixture_version",
		"window",
		"sample_size",
		"target_actual_status",
		"confidence",
		"owner",
		"reviewer",
		"evidence_ref",
		"evidence_sha256",
		"reviewed_at_utc",
	]);
});
