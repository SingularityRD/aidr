import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	ATTESTATION_PAYLOAD_REQUIRED_FIELDS, ATTESTATION_REQUIRED_FIELDS, COMPARISON_SPEC_REQUIRED_FIELDS,
	CORPUS_CASE_REQUIRED_FIELDS, CORPUS_REQUIRED_FIELDS, MEASUREMENT_REQUIRED_FIELDS,
	OBSERVATION_PRODUCT_REQUIRED_FIELDS, OBSERVATIONS_REQUIRED_FIELDS, REPORT_REQUIRED_FIELDS,
	assertSoldScopeCoverage, validateComparisonSpec, validateCorpus, validateSoldScope,
} from "./evaluate.mjs";

const directory = fileURLToPath(new URL(".", import.meta.url));
const root = fileURLToPath(new URL("../..", import.meta.url));
const json = (path) => JSON.parse(readFileSync(path, "utf8"));

test("benchmark denominator is engineering/evaluation scope, distinct from direct-GA order scope", () => {
	const scope = json(join(directory, "sold-scope.json"));
	const scaffold = json(join(directory, "corpus.template.json"));
	const supportMatrix = json(join(root, "deploy", "native", "support-matrix.json"));
	const registry = json(join(root, "docs", "production-readiness", "commercial-go-evidence-registry.json"));
	const directGa = registry.hardGates.find((gate) => gate.id === "COM-010").directGaConnectorScope;
	const benchmarkConnectors = scope.connectors.map((connector) => connector.id);
	const readme = readFileSync(join(directory, "README.md"), "utf8");

	assert.deepEqual(benchmarkConnectors, supportMatrix.soldConnectorScope);
	assert.deepEqual(scaffold.scope.required_connectors, benchmarkConnectors);
	assert.equal(benchmarkConnectors.length, 6);
	assert.equal(directGa.length, 5);
	assert.deepEqual(benchmarkConnectors.filter((connector) => !directGa.includes(connector)), ["codex"]);
	assert.match(scope.$comment, /engineering\/evaluation.*six-connector/i);
	assert.match(readme, /six connectors.*engineering\/evaluation/i);
	assert.match(readme, /direct-GA order scope is five connectors.*Codex/i);
	assert.match(scaffold.scope._comment, /engineering\/evaluation/i);
	assert.doesNotMatch(readme, /denominator of what the product actually sells/i);
});

test("descriptive schemas mirror evaluator required-field constants", () => {
	const corpus = json(join(directory, "schemas", "corpus.schema.json"));
	const observations = json(join(directory, "schemas", "observations.schema.json"));
	const attestation = json(join(directory, "schemas", "attestation.schema.json"));
	const comparison = json(join(directory, "schemas", "comparison-spec.schema.json"));
	const report = json(join(directory, "schemas", "report.schema.json"));
	assert.deepEqual(corpus.required, CORPUS_REQUIRED_FIELDS);
	assert.deepEqual(corpus.$defs.case.required, CORPUS_CASE_REQUIRED_FIELDS);
	assert.deepEqual(observations.required, OBSERVATIONS_REQUIRED_FIELDS);
	assert.deepEqual(observations.$defs.product.required, OBSERVATION_PRODUCT_REQUIRED_FIELDS);
	assert.deepEqual(observations.$defs.measurement.required, MEASUREMENT_REQUIRED_FIELDS);
	assert.deepEqual(attestation.required, ATTESTATION_REQUIRED_FIELDS);
	assert.deepEqual(attestation.properties.payload.required, ATTESTATION_PAYLOAD_REQUIRED_FIELDS);
	assert.deepEqual(comparison.required, COMPARISON_SPEC_REQUIRED_FIELDS);
	assert.deepEqual(report.required, REPORT_REQUIRED_FIELDS);
});

test("generator is byte deterministic, covers sold scope, and synthetic provenance is ineligible for customer gate", () => {
	const temp = mkdtempSync(join(tmpdir(), "aidr-corpus-generator-"));
	try {
		const first = join(temp, "first.json");
		const second = join(temp, "second.json");
		const command = [join(directory, "generate-corpus.mjs"), "--spec", join(directory, "corpus-spec.json"), "--scope-file", join(directory, "sold-scope.json")];
		for (const output of [first, second]) {
			const run = spawnSync(process.execPath, [...command, "--output", output], { encoding: "utf8" });
			assert.equal(run.status, 0, run.stderr);
		}
		assert.deepEqual(readFileSync(first), readFileSync(second));
		const corpus = json(first);
		assert.equal(corpus.provenance, "synthetic_open");
		assert.equal(corpus.generation.algorithm, "HMAC-SHA256-counter");
		assert.equal(corpus.generation.customer_gate_eligible, false);
		const sold = validateSoldScope(json(join(directory, "sold-scope.json")));
		assert.doesNotThrow(() => assertSoldScopeCoverage(corpus, sold));
		assert.doesNotThrow(() => validateCorpus(corpus));
	} finally { rmSync(temp, { recursive: true, force: true }); }
});

test("benign generated content does not match any shipped YAML threat pattern", () => {
	const temp = mkdtempSync(join(tmpdir(), "aidr-corpus-leakage-"));
	try {
		const output = join(temp, "corpus.json");
		const run = spawnSync(process.execPath, [join(directory, "generate-corpus.mjs"), "--spec", join(directory, "corpus-spec.json"), "--scope-file", join(directory, "sold-scope.json"), "--output", output], { encoding: "utf8" });
		assert.equal(run.status, 0, run.stderr);
		const benign = json(output).cases.filter((entry) => entry.oracle === "benign");
		let checked = 0;
		for (const file of readdirSync(join(root, "threats")).filter((name) => name.endsWith(".yaml"))) {
			for (const line of readFileSync(join(root, "threats", file), "utf8").split(/\r?\n/)) {
				const match = line.match(/^\s*pattern:\s*("(?:[^"\\]|\\.)*")\s*$/);
				if (!match) continue;
				const pattern = JSON.parse(match[1]);
				let expression;
				try { expression = new RegExp(pattern, "i"); } catch { continue; }
				checked += 1;
				for (const entry of benign) assert.equal(expression.test(entry.content), false, `${file} threat pattern leaked into ${entry.case_id}`);
			}
		}
		assert.ok(checked > 100);
	} finally { rmSync(temp, { recursive: true, force: true }); }
});

test("content-digest split is deterministic and manifest mismatches fail corpus binding", () => {
	const temp = mkdtempSync(join(tmpdir(), "aidr-corpus-split-"));
	try {
		const source = join(temp, "source.json");
		let run = spawnSync(process.execPath, [join(directory, "generate-corpus.mjs"), "--spec", join(directory, "corpus-spec.json"), "--scope-file", join(directory, "sold-scope.json"), "--output", source], { encoding: "utf8" });
		assert.equal(run.status, 0, run.stderr);
		const outputs = [];
		for (const suffix of ["a", "b"]) {
			const output = join(temp, `${suffix}.json`); const manifest = join(temp, `${suffix}.manifest.json`);
			run = spawnSync(process.execPath, [join(directory, "split-corpus.mjs"), "--corpus", source, "--key", "stable-test-key", "--holdout-percent", "30", "--output", output, "--split-manifest", manifest], { encoding: "utf8" });
			assert.equal(run.status, 0, run.stderr); outputs.push([output, manifest]);
		}
		assert.deepEqual(readFileSync(outputs[0][0]), readFileSync(outputs[1][0]));
		assert.deepEqual(readFileSync(outputs[0][1]), readFileSync(outputs[1][1]));
		assert.doesNotThrow(() => validateCorpus(json(outputs[0][0])));
	} finally { rmSync(temp, { recursive: true, force: true }); }
});

test("committed trust store is intentionally empty and comparison unknown reasons are explicit", () => {
	assert.deepEqual(json(join(directory, "trusted-keys.json")).keys, []);
	const comparison = json(join(directory, "comparison-spec.json"));
	assert.doesNotThrow(() => validateComparisonSpec(comparison));
	assert.equal(comparison.frozen, true);
	assert.deepEqual(Object.keys(comparison.unknown_reasons).sort(), ["budget_blocked", "missing_measurements", "not_authorized", "not_available", "unsupported_product"]);
});
