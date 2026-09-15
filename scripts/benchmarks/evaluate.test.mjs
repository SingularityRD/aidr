import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { MAX_ANALYSIS_MATRIX_CELLS, canonicalJson, evaluateBenchmark, validateCorpusStructure, validateSoldScope, assertSoldScopeCoverage } from "./evaluate.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");

function fixture() {
	const directory = mkdtempSync(join(tmpdir(), "aidr-benchmark-test-"));
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const corpus = {
		schema_version: 1, corpus_id: "synthetic-harness-only", version: "1",
		rule_author_id: "rule-team", oracle_reviewer_id: "oracle-reviewer",
		scope: { required_attack_families: ["injection", "exfiltration"], required_connectors: ["tool-a", "tool-b"], required_surfaces: ["input", "output"] },
		cases: [
			{ case_id: "attack-dev", partition: "development", oracle: "malicious", family: "injection", connector: "tool-a", surface: "input", content_sha256: hash("synthetic case attack-dev") },
			{ case_id: "attack-holdout", partition: "holdout", oracle: "malicious", family: "exfiltration", connector: "tool-a", surface: "output", content_sha256: hash("synthetic case attack-holdout") },
			{ case_id: "benign-dev", partition: "development", oracle: "benign", family: "ordinary-work", connector: "tool-a", surface: "input", content_sha256: hash("synthetic case benign-dev") },
			{ case_id: "benign-holdout", partition: "holdout", oracle: "benign", family: "ordinary-work", connector: "tool-b", surface: "output", content_sha256: hash("synthetic case benign-holdout") },
		],
	};
	const observations = {
		schema_version: 1, workload_id: "loopback-synthetic", trials_per_case: 2,
		environment: { environment_id: "synthetic", os: "test-os", hardware: "test-machine", runtime: "node", region: "local", concurrency: "1", workload_description: "self-test data only" },
		candidate_product_id: "candidate",
		products: [
			{ product_id: "candidate", version: "test", artifact_sha256: hash("candidate-binary") },
			{ product_id: "competitor", version: "test", artifact_sha256: hash("competitor-binary") },
		],
		measurements: [],
	};
	for (const entry of corpus.cases) for (const product of observations.products) for (let trial = 1; trial <= 2; trial++) {
		const file = `${entry.case_id}-${product.product_id}-${trial}.txt`;
		const raw = Buffer.from(`synthetic observation ${entry.case_id} ${product.product_id} ${trial}`);
		writeFileSync(join(directory, file), raw);
		const row = {
			case_id: entry.case_id, product_id: product.product_id, trial,
			action: entry.oracle === "malicious" ? "block" : "allow",
			phase: "warm_local", latency_ms: trial * 10,
			cpu_percent: 12.5 * trial, rss_mb: 64 + trial,
			raw_evidence_file: file, raw_evidence_sha256: hash(raw),
		};
		if (entry.oracle === "malicious") row.side_effect_occurred = false;
		observations.measurements.push(row);
	}
	function evaluate(soldScope = null, evaluationOptions = {}) {
		const corpusBytes = Buffer.from(JSON.stringify(corpus));
		const observationBytes = Buffer.from(JSON.stringify(observations));
		const observationsPath = join(directory, "observations.json");
		writeFileSync(observationsPath, observationBytes);
		const payload = {
			protocol_version: 1, corpus_sha256: hash(corpusBytes), observations_sha256: hash(observationBytes),
			candidate_artifact_sha256: observations.products[0].artifact_sha256,
			rule_author_id: corpus.rule_author_id, evaluator_id: "external-evaluator",
			evaluator_role: "independent_evaluator", completed_at: "2026-09-13T00:00:00Z",
			...(evaluationOptions.payloadExtra ?? {}),
		};
		const attestation = { schema_version: 1, payload, signature_base64: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64") };
		if (evaluationOptions.signatureBase64 !== undefined) attestation.signature_base64 = evaluationOptions.signatureBase64;
		return evaluateBenchmark({ corpus, observations, attestation, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }), corpusBytes, observationBytes, observationsPath, soldScope, trustedKeys: evaluationOptions.trustedKeys ?? null, splitManifest: evaluationOptions.splitManifest ?? null, splitManifestBytes: evaluationOptions.splitManifestBytes ?? null });
	}
	return { directory, corpus, observations, publicKey, privateKey, evaluate };
}

const soldScopePath = fileURLToPath(new URL("./sold-scope.json", import.meta.url));
const templatePath = fileURLToPath(new URL("./corpus.template.json", import.meta.url));

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

// The synthetic sold scope matches the fixture's own dimensions and keeps the committed
// minimums, so the scope check can be driven on the in-memory harness and on the real files.
function soldScopeFixture() {
	return validateSoldScope({
		schema_version: 1,
		scope_id: "synthetic-sold-scope",
		attack_families: [
			{ id: "injection", source: "synthetic harness fixture" },
			{ id: "exfiltration", source: "synthetic harness fixture" },
		],
		connectors: [
			{ id: "tool-a", source: "synthetic harness fixture" },
			{ id: "tool-b", source: "synthetic harness fixture" },
		],
		surfaces: [
			{ id: "input", posture: "enforce", required: true, source: "synthetic harness fixture" },
			{ id: "output", posture: "enforce", required: true, source: "synthetic harness fixture" },
		],
		required_scenarios_per_family: { minimum_malicious_cases: 2, minimum_benign_twins: 2 },
		out_of_scope_with_reason: [],
	});
}

// Synthetic coverage cases for a sold scope: the declared minimum of malicious cases and benign
// twins for every family, spread over every required connector and surface and both partitions.
// This is harness data, never a measurement.
function scopedCases(soldScope, { omitFamilies = [], dropBenignFamilies = [] } = {}) {
	const cases = [];
	let index = 0;
	const add = (oracle, family) => {
		const connector = soldScope.requiredConnectors[index % soldScope.requiredConnectors.length];
		const surface = soldScope.requiredSurfaces[index % soldScope.requiredSurfaces.length];
		const caseId = `${family}-${oracle}-${index}`;
		cases.push({
			case_id: caseId, partition: index % 2 === 0 ? "development" : "holdout",
			oracle, family, connector, surface, content_sha256: hash(`synthetic scoped case ${caseId}`),
		});
		index += 1;
	};
	for (const family of soldScope.requiredAttackFamilies.filter((name) => !omitFamilies.includes(name)))
		for (let count = 0; count < soldScope.minimums.malicious; count += 1) add("malicious", family);
	for (const family of soldScope.requiredAttackFamilies.filter((name) => !omitFamilies.includes(name) && !dropBenignFamilies.includes(name)))
		for (let count = 0; count < soldScope.minimums.benign; count += 1) add("benign", family);
	return cases;
}

test("signed fixture reports separate holdout, unsupported, false intervention and latency denominators", () => {
	const data = fixture();
	try {
		const candidate = data.observations.measurements;
		candidate.find((row) => row.case_id === "attack-holdout" && row.product_id === "candidate" && row.trial === 1).action = "unsupported";
		candidate.find((row) => row.case_id === "benign-holdout" && row.product_id === "candidate" && row.trial === 1).action = "approval";
		const report = data.evaluate();
		const result = report.coverage.candidate;
		assert.equal(result.overall.denominators.malicious, 4);
		assert.equal(result.overall.counts.prevented, 3);
		assert.equal(result.overall.counts.unsupported, 1);
		assert.equal(result.overall.rates.malicious_prevention, 0.75);
		assert.equal(result.overall.counts.false_approvals, 1);
		assert.equal(result.by_partition.holdout.counts.unsupported, 1);
		assert.equal(result.by_connector["tool-b"].counts.false_approvals, 1);
		assert.equal(result.overall.latency_by_phase.warm_local.observations, 7);
		assert.equal(result.overall.latency_by_phase.warm_local.p95_ms, 20);
		assert.equal(report.gates.complete_matrix, true);
		assert.equal(report.gates.declared_scope_covered, true);
		assert.equal(report.gates.candidate_1000_measured_benign_calls_per_connector, false);
		assert.ok(result.overall.confidence_intervals.benign_false_approval.high > result.overall.rates.benign_false_approval);
		assert.equal(report.production_accepted, false);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("signed but incomplete competitor matrix stays visible as missing", () => {
	const data = fixture();
	try {
		data.corpus.scope.required_attack_families.push("mcp-drift");
		data.observations.measurements = data.observations.measurements.filter((row) => !(row.case_id === "attack-holdout" && row.product_id === "competitor" && row.trial === 2));
		const report = data.evaluate();
		assert.equal(report.coverage.competitor.overall.counts.missing, 1);
		assert.equal(report.coverage.competitor.overall.rates.malicious_prevention, 0.75);
		assert.equal(report.gates.complete_matrix, false);
		assert.equal(report.gates.declared_scope_covered, false);
		assert.deepEqual(report.scope.uncovered_attack_families, ["mcp-drift"]);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("raw evidence tampering and side-effect ambiguity fail closed", () => {
	const data = fixture();
	try {
		const row = data.observations.measurements[0];
		const file = join(data.directory, row.raw_evidence_file);
		writeFileSync(file, "changed after measurement");
		assert.throws(() => data.evaluate(), /raw evidence hash mismatch/);
		writeFileSync(file, readFileSync(join(data.directory, data.observations.measurements[1].raw_evidence_file)));
		row.raw_evidence_sha256 = hash(readFileSync(file));
		delete row.side_effect_occurred;
		assert.throws(() => data.evaluate(), /side_effect_occurred must be observed/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("attestation and analysis CLIs run end to end and reject changed signed input", () => {
	const data = fixture();
	try {
		const corpusPath = join(data.directory, "corpus.json");
		const observationsPath = join(data.directory, "observations.json");
		const privatePath = join(data.directory, "evaluator-private.pem");
		const publicPath = join(data.directory, "evaluator-public.pem");
		const attestationPath = join(data.directory, "attestation.json");
		const reportPath = join(data.directory, "report.json");
		writeFileSync(corpusPath, JSON.stringify(data.corpus));
		writeFileSync(observationsPath, JSON.stringify(data.observations));
		writeFileSync(privatePath, data.privateKey.export({ type: "pkcs8", format: "pem" }));
		writeFileSync(publicPath, data.publicKey.export({ type: "spki", format: "pem" }));
		const attest = spawnSync(process.execPath, [fileURLToPath(new URL("./attest.mjs", import.meta.url)),
			"--corpus", corpusPath, "--observations", observationsPath,
			"--private-key", privatePath, "--evaluator-id", "external-evaluator", "--output", attestationPath], { encoding: "utf8" });
		assert.equal(attest.status, 0, attest.stderr);
		const command = [fileURLToPath(new URL("./evaluate.mjs", import.meta.url)),
			"--corpus", corpusPath, "--observations", observationsPath,
			"--attestation", attestationPath, "--public-key", publicPath, "--output", reportPath];
		const analyzed = spawnSync(process.execPath, command, { encoding: "utf8" });
		assert.equal(analyzed.status, 0, analyzed.stderr);
		const writtenReport = JSON.parse(readFileSync(reportPath, "utf8"));
		assert.equal(writtenReport.claim_status, "EVIDENCE_REVIEW_REQUIRED");
		assert.match(writtenReport.canonical_report_sha256, /^[a-f0-9]{64}$/);
		const reproduced = spawnSync(process.execPath, [...command.slice(0, -2), "--reproduce", reportPath], { encoding: "utf8" });
		assert.equal(reproduced.status, 0, reproduced.stderr);
		assert.equal(reproduced.stdout, readFileSync(reportPath, "utf8"));
		const overwriteRefused = spawnSync(process.execPath, command, { encoding: "utf8" });
		assert.equal(overwriteRefused.status, 1);
		assert.match(overwriteRefused.stderr, /EEXIST/);
		data.observations.workload_id = "changed-after-signature";
		writeFileSync(observationsPath, JSON.stringify(data.observations));
		const rejected = spawnSync(process.execPath, command, { encoding: "utf8" });
		assert.equal(rejected.status, 1);
		assert.match(rejected.stderr, /observations hash differs from signed attestation/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("measured candidate cpu and rss roll up as p50/p95/peak with an observation count", () => {
	const data = fixture();
	try {
		let index = 0;
		for (const row of data.observations.measurements) if (row.product_id === "candidate") {
			index += 1;
			row.cpu_percent = index;
			row.rss_mb = index * 10;
		}
		const report = data.evaluate();
		assert.equal(index, 8);
		const resources = report.coverage.candidate.overall.resources;
		assert.deepEqual(resources.cpu_percent, { measured: true, observations: 8, p50: 4, p95: 8, peak: 8 });
		assert.deepEqual(resources.rss_mb, { measured: true, observations: 8, p50: 40, p95: 80, peak: 80 });
		assert.deepEqual(report.coverage.candidate.overall.resources_by_phase.warm_local.cpu_percent, { measured: true, observations: 8, p50: 4, p95: 8, peak: 8 });
		assert.deepEqual(report.coverage.candidate.overall.resources_by_phase.warm_local.rss_mb, { measured: true, observations: 8, p50: 40, p95: 80, peak: 80 });
		assert.deepEqual(report.coverage.competitor.overall.resources.rss_mb, { measured: true, observations: 8, p50: 65, p95: 66, peak: 66 });
		assert.equal(report.gates.resource_measured, true);
		assert.equal(report.production_accepted, false);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("absent resource fields report unmeasured and never zero", () => {
	const data = fixture();
	try {
		for (const row of data.observations.measurements) {
			delete row.cpu_percent;
			delete row.rss_mb;
		}
		const report = data.evaluate();
		const resources = report.coverage.candidate.overall.resources;
		assert.deepEqual(resources.cpu_percent, { measured: false, observations: 0, p50: null, p95: null, peak: null });
		assert.deepEqual(resources.rss_mb, { measured: false, observations: 0, p50: null, p95: null, peak: null });
		assert.deepEqual(report.coverage.candidate.overall.resources_by_phase.warm_local.cpu_percent, { measured: false, observations: 0, p50: null, p95: null, peak: null });
		assert.equal(report.gates.resource_measured, false);
		for (const field of ["p50", "p95", "peak"]) assert.notEqual(resources.rss_mb[field], 0);
		for (const row of data.observations.measurements) row.cpu_percent = 5;
		const partial = data.evaluate();
		assert.equal(partial.coverage.candidate.overall.resources.cpu_percent.measured, true);
		assert.equal(partial.coverage.candidate.overall.resources.cpu_percent.observations, 8);
		assert.deepEqual(partial.coverage.candidate.overall.resources.rss_mb, { measured: false, observations: 0, p50: null, p95: null, peak: null });
		assert.equal(partial.gates.resource_measured, false);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("negative, NaN and infinite cpu or rss measurements fail closed", () => {
	const data = fixture();
	try {
		const row = data.observations.measurements[0];
		assert.equal(row.case_id, "attack-dev");
		for (const [field, value] of [["cpu_percent", -1], ["cpu_percent", Number.NaN], ["cpu_percent", Number.POSITIVE_INFINITY], ["rss_mb", -0.5], ["rss_mb", Number.NaN]]) {
			row[field] = value;
			assert.throws(() => data.evaluate(), new RegExp(`${field} for attack-dev/candidate must be a finite nonnegative number`));
			delete row[field];
		}
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("every case declares a real content digest and declared content is recomputed", () => {
	const data = fixture();
	try {
		const entry = data.corpus.cases[0];
		delete entry.content_sha256;
		assert.throws(() => data.evaluate(), /content_sha256 for attack-dev must be a SHA-256 hex digest/);
		entry.content_sha256 = "not-a-digest";
		assert.throws(() => data.evaluate(), /content_sha256 for attack-dev must be a SHA-256 hex digest/);
		entry.content = "line one\r\nline two   ";
		entry.content_sha256 = hash("line one\nline two");
		entry.derived_from_case_id = "benign-dev";
		const report = data.evaluate();
		assert.equal(report.gates.holdout_no_case_overlap, true);
		assert.equal(report.gates.holdout_partition_blind, true);
		entry.content = "tampered after hashing";
		assert.throws(() => data.evaluate(), /\[content_sha256_mismatch\] case attack-dev: declared content_sha256 .* does not match the normalized content digest/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("the same case_id or the same normalized content cannot appear in both partitions", () => {
	const data = fixture();
	try {
		const original = data.corpus.cases.slice();
		data.corpus.cases.push({ ...original[0], partition: "holdout" });
		assert.throws(() => data.evaluate(), /\[case_id_in_multiple_partitions\] case attack-dev: the same case_id is declared in partition development and partition holdout/);
		data.corpus.cases = [...original, { ...original[0], case_id: "attack-holdout-copy", partition: "holdout" }];
		assert.throws(() => data.evaluate(), /\[duplicate_case_content\] case attack-holdout-copy: normalized content is identical to case attack-dev in partition development/);
		data.corpus.cases = [...original];
		const withinDevelopment = data.corpus.cases[2];
		assert.equal(withinDevelopment.case_id, "benign-dev");
		withinDevelopment.content_sha256 = data.corpus.cases[0].content_sha256;
		assert.equal(data.evaluate().gates.holdout_no_case_overlap, true);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("cross-partition, unknown, duplicate and self derivation references are rejected", () => {
	const data = fixture();
	try {
		const holdout = data.corpus.cases.find((entry) => entry.case_id === "attack-holdout");
		holdout.derived_from_case_id = "attack-dev";
		assert.throws(() => data.evaluate(), /\[cross_partition_derivation\] case attack-holdout: partition holdout derives from case attack-dev in partition development/);
		holdout.derived_from_case_id = "no-such-case";
		assert.throws(() => data.evaluate(), /\[unknown_derivation_reference\] case attack-holdout: references undeclared case no-such-case/);
		holdout.derived_from_case_id = "attack-holdout";
		assert.throws(() => data.evaluate(), /\[self_derivation_reference\] case attack-holdout/);
		delete holdout.derived_from_case_id;
		holdout.development_derived_from = "attack-dev";
		assert.throws(() => data.evaluate(), /\[cross_partition_derivation\] case attack-holdout/);
		holdout.derived_from_case_id = "benign-holdout";
		assert.throws(() => data.evaluate(), /\[duplicate_derivation_field\] case attack-holdout: declares both derived_from_case_id and development_derived_from/);
		delete holdout.derived_from_case_id;
		delete holdout.development_derived_from;
		const development = data.corpus.cases.find((entry) => entry.case_id === "benign-dev");
		development.development_derived_from = "attack-holdout";
		assert.throws(() => data.evaluate(), /\[cross_partition_derivation\] case benign-dev/);
		delete development.development_derived_from;
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("an empty or single-oracle holdout is rejected", () => {
	const data = fixture();
	try {
		const original = data.corpus.cases;
		data.corpus.cases = original.filter((entry) => entry.case_id !== "attack-holdout");
		assert.throws(() => data.evaluate(), /\[holdout_single_oracle_class\] partition holdout: the holdout contains no malicious case/);
		data.corpus.cases = original.filter((entry) => entry.case_id !== "benign-holdout");
		assert.throws(() => data.evaluate(), /\[holdout_single_oracle_class\] partition holdout: the holdout contains no benign case/);
		data.corpus.cases = original.filter((entry) => entry.partition !== "holdout");
		assert.throws(() => data.evaluate(), /\[holdout_partition_empty\] partition holdout: the corpus declares no holdout case/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("a per-partition trial difference must be declared and match the observations", () => {
	const data = fixture();
	try {
		data.observations.trials_per_case_by_partition = { development: 2, holdout: 3 };
		assert.throws(() => data.evaluate(), /\[undeclared_partition_trial_difference\] partition trials: observations use development=2 and holdout=3 trials but the corpus does not declare trials_per_case_by_partition/);
		data.corpus.trials_per_case_by_partition = { development: 2, holdout: 2 };
		assert.throws(() => data.evaluate(), /\[declared_partition_trials_mismatch\] partition holdout: the corpus declares 2 trials but observations use 3/);
		data.corpus.trials_per_case_by_partition = { development: 2, holdout: 4 };
		data.observations.trials_per_case_by_partition = { development: 2, holdout: 3 };
		assert.throws(() => data.evaluate(), /\[declared_partition_trials_mismatch\] partition holdout: the corpus declares 4 trials but observations use 3/);
		data.corpus.trials_per_case_by_partition = { development: 2, holdout: 1 };
		assert.throws(() => data.evaluate(), /\[declared_partition_trials_mismatch\] partition holdout: the corpus declares 1 trials but observations use 3/);
		data.corpus.trials_per_case_by_partition = { development: 3, holdout: 3 };
		assert.throws(() => data.evaluate(), /\[declared_partition_trials_mismatch\] partition development: the corpus declares 3 trials but observations use 2/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("declared per-partition trials drive the matrix and keep the holdout blind", () => {
	const data = fixture();
	try {
		data.corpus.trials_per_case_by_partition = { development: 2, holdout: 1 };
		data.observations.trials_per_case_by_partition = { development: 2, holdout: 1 };
		data.observations.measurements = data.observations.measurements.filter((row) => !(row.trial === 2 && ["attack-holdout", "benign-holdout"].includes(row.case_id)));
		const report = data.evaluate();
		assert.deepEqual(report.trials_per_case_by_partition, { development: 2, holdout: 1 });
		assert.equal(report.coverage.candidate.by_partition.holdout.counts.total, 2);
		assert.equal(report.coverage.candidate.by_partition.development.counts.total, 4);
		assert.equal(report.gates.complete_matrix, true);
		assert.equal(report.gates.holdout_partition_blind, true);
		assert.equal(report.gates.holdout_no_case_overlap, true);
		assert.equal(report.gates.resource_measured, true);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("a blind, correctly formed corpus passes and reports every holdout guard", () => {
	const data = fixture();
	try {
		const report = data.evaluate();
		assert.equal(report.gates.development_and_holdout_present, true);
		assert.equal(report.gates.both_classes_in_each_partition, true);
		assert.equal(report.gates.complete_matrix, true);
		assert.equal(report.gates.holdout_partition_blind, true);
		assert.equal(report.gates.holdout_no_case_overlap, true);
		assert.equal(report.gates.resource_measured, true);
		assert.equal(report.gates.independent_acceptance, false);
		assert.equal(report.production_accepted, false);
		assert.equal(report.claim_status, "EVIDENCE_REVIEW_REQUIRED");
		assert.ok(report.limitations.some((line) => /absent value is reported as unmeasured/.test(line)));
		assert.ok(report.limitations.some((line) => /holdout guard is fail-closed/.test(line)));
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("the committed corpus scaffold is structurally valid, empty and outside the sold scope", () => {
	const template = readJson(templatePath);
	// Loading the sold scope also proves every declared entry carries a source path, because
	// validateSoldScope rejects an entry without one.
	const soldScope = validateSoldScope(readJson(soldScopePath));
	assert.doesNotThrow(() => validateCorpusStructure(template));
	assert.deepEqual(template.cases, []);
	assert.equal(template._scaffold.contains_measured_data, false);
	assert.equal(template._scaffold.cases_declared, 0);
	assert.deepEqual(template.scope.required_attack_families, soldScope.requiredAttackFamilies);
	assert.deepEqual(template.scope.required_connectors, soldScope.requiredConnectors);
	assert.deepEqual(template.scope.required_surfaces, soldScope.requiredSurfaces);
	assert.throws(
		() => assertSoldScopeCoverage(template, soldScope),
		/\[scope_attack_family_minimum_not_met\] attack family "prompt-injection-direct": the corpus declares 0 malicious case\(s\) but the sold scope requires at least 2/,
	);
	const cli = spawnSync(process.execPath, [fileURLToPath(new URL("./evaluate.mjs", import.meta.url)), "--corpus", templatePath, "--scope-file", soldScopePath], { encoding: "utf8" });
	assert.equal(cli.status, 1);
	assert.match(cli.stderr, /sold scope check failed \[scope_attack_family_minimum_not_met\] attack family "prompt-injection-direct"/);
});

test("a corpus that omits a sold family or declares it without cases fails the scope check", () => {
	const data = fixture();
	try {
		data.observations.measurements = [];
		const soldScope = soldScopeFixture();
		data.corpus.cases = scopedCases(soldScope);
		assert.doesNotThrow(() => assertSoldScopeCoverage(data.corpus, soldScope));
		data.corpus.scope.required_attack_families = ["injection"];
		assert.throws(
			() => data.evaluate(soldScope),
			/\[scope_attack_family_missing\] attack family "exfiltration": the sold scope "synthetic-sold-scope" requires it but corpus\.scope\.required_attack_families does not declare it/,
		);
		data.corpus.scope.required_attack_families = ["injection", "exfiltration"];
		data.corpus.cases = scopedCases(soldScope, { omitFamilies: ["exfiltration"] });
		assert.throws(
			() => data.evaluate(soldScope),
			/\[scope_attack_family_minimum_not_met\] attack family "exfiltration": the corpus declares 0 malicious case\(s\) but the sold scope requires at least 2/,
		);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("a sold family with malicious cases but no benign twin fails the scope check", () => {
	const data = fixture();
	try {
		data.observations.measurements = [];
		const soldScope = soldScopeFixture();
		data.corpus.cases = scopedCases(soldScope, { dropBenignFamilies: ["injection"] });
		assert.throws(
			() => data.evaluate(soldScope),
			/\[scope_attack_family_benign_twin_missing\] attack family "injection": the corpus declares 0 benign twin\(s\) but the sold scope requires at least 2/,
		);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("a corpus that declares a dimension the sold scope does not fails the scope check", () => {
	const data = fixture();
	try {
		data.observations.measurements = [];
		const soldScope = soldScopeFixture();
		data.corpus.cases = scopedCases(soldScope);
		data.corpus.scope.required_attack_families.push("mcp-drift");
		assert.throws(
			() => data.evaluate(soldScope),
			/\[scope_attack_family_extra\] attack family "mcp-drift": corpus\.scope\.required_attack_families declares it but the sold scope does not/,
		);
		data.corpus.scope.required_attack_families = ["injection", "exfiltration"];
		data.corpus.scope.required_connectors.push("tool-c");
		assert.throws(() => data.evaluate(soldScope), /\[scope_connector_extra\] connector "tool-c"/);
		data.corpus.scope.required_connectors = ["tool-a", "tool-b"];
		data.corpus.scope.required_surfaces.push("network-egress");
		assert.throws(() => data.evaluate(soldScope), /\[scope_surface_extra\] surface "network-egress"/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("classification metrics expose indeterminate outcomes and never invent absent-score ROC", () => {
	const data = fixture();
	try {
		const row = data.observations.measurements.find((entry) => entry.case_id === "attack-holdout" && entry.product_id === "candidate" && entry.trial === 1);
		row.action = "timeout";
		row.latency_ms = null;
		const report = data.evaluate();
		const classification = report.coverage.candidate.overall.classification;
		assert.deepEqual(classification.confusion_matrix, { true_positive: 3, false_positive: 0, true_negative: 4, false_negative: 0, indeterminate: 1 });
		assert.deepEqual(classification.roc, { measured: false, value: null, observations: 0 });
		assert.deepEqual(classification.roc_auc, { measured: false, value: null, observations: 0 });
		assert.equal(classification.precision.value, 1);
		assert.equal(classification.recall.value, 1);
		assert.equal(classification.f1.value, 1);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("benign side-effect metadata cannot hide a false-positive intervention", () => {
	const data = fixture();
	try {
		const row = data.observations.measurements.find((entry) => entry.case_id === "benign-dev" && entry.product_id === "candidate" && entry.trial === 1);
		row.action = "block";
		row.side_effect_occurred = true;
		const matrix = data.evaluate().coverage.candidate.overall.classification.confusion_matrix;
		assert.equal(matrix.false_positive, 1);
		assert.equal(matrix.true_negative, 3);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("scores measure development ROC only until a signed frozen holdout operating point exists", () => {
	const data = fixture();
	try {
		for (const row of data.observations.measurements) row.score = data.corpus.cases.find((entry) => entry.case_id === row.case_id).oracle === "malicious" ? 0.9 : 0.1;
		const report = data.evaluate();
		assert.deepEqual(report.coverage.candidate.overall.classification.roc_auc, { measured: false, value: null, observations: 0 });
		assert.deepEqual(report.coverage.candidate.by_partition.holdout.classification.roc_auc, { measured: false, value: null, observations: 0 });
		assert.deepEqual(report.coverage.candidate.by_partition.development.classification.roc_auc, { measured: true, value: 1, observations: 4 });
		delete data.observations.measurements.find((row) => row.product_id === "candidate" && row.case_id === "attack-dev").score;
		assert.deepEqual(data.evaluate().coverage.candidate.by_partition.development.classification.roc_auc, { measured: false, value: null, observations: 0 });
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("signed split manifest freezes holdout and any assignment mismatch fails closed", () => {
	const data = fixture();
	try {
		for (const row of data.observations.measurements) row.score = data.corpus.cases.find((entry) => entry.case_id === row.case_id).oracle === "malicious" ? 0.9 : 0.1;
		const partitionless = { ...data.corpus, cases: data.corpus.cases.map(({ partition: _partition, ...entry }) => entry) };
		const manifest = {
			schema_version: 1, kind: "aidr-content-digest-split-manifest", algorithm: "HMAC-SHA256-content-digest-v1", holdout_percent: 50,
			source_corpus_sha256: hash(Buffer.from(canonicalJson(partitionless))),
			assignments: data.corpus.cases.map((entry) => ({ content_sha256: entry.content_sha256, partition: entry.partition })),
		};
		let manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
		let report = data.evaluate(null, { payloadExtra: { split_manifest_sha256: hash(manifestBytes), frozen_operating_point: { frozen: true, threshold: 0.5 } }, splitManifest: manifest, splitManifestBytes: manifestBytes });
		assert.equal(report.gates.holdout_frozen, true);
		assert.deepEqual(report.coverage.candidate.by_partition.holdout.classification.roc_auc, { measured: true, value: 1, observations: 4 });
		manifest.assignments[0].partition = manifest.assignments[0].partition === "holdout" ? "development" : "holdout";
		manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
		assert.throws(() => data.evaluate(null, { payloadExtra: { split_manifest_sha256: hash(manifestBytes) }, splitManifest: manifest, splitManifestBytes: manifestBytes }), /split manifest partition mismatch/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("trust, customer and budget gates default closed; unknown keys and malformed signatures fail closed", () => {
	const data = fixture();
	try {
		data.corpus.provenance = "synthetic_open";
		data.observations.measurement_budget = { currency: "USD", ceiling: 100, spent: 25, authorization_ref: "external-budget-ticket" };
		let report = data.evaluate(null, { payloadExtra: { customer_corpus_authorized: true } });
		assert.equal(report.gates.attestation_trusted, false);
		assert.equal(report.gates.customer_corpus_authorized, false);
		assert.equal(report.gates.measurement_budget_authorized, false);
		assert.equal(report.measurement_budget.status, "BLOCKED_EXTERNAL");
		assert.equal(report.measurement_budget.authorization_ref, "external-budget-ticket");
		assert.equal(report.measurement_budget.authorization_verified, false);
		assert.equal(report.duty_separation.independent, false);
		assert.throws(() => data.evaluate(null, { payloadExtra: { signing_key_id: "unknown" }, trustedKeys: { schema_version: 1, keys: [] } }), /unknown, mismatched, or unauthorized attestation signing key/);
		const fingerprint = hash(data.publicKey.export({ type: "spki", format: "der" }));
		report = data.evaluate(null, { payloadExtra: { signing_key_id: "test-key", customer_corpus_authorized: true }, trustedKeys: { schema_version: 1, keys: [{ key_id: "test-key", public_key_sha256: fingerprint, roles: ["independent_evaluator"] }] } });
		assert.equal(report.gates.attestation_trusted, true);
		assert.equal(report.gates.customer_corpus_authorized, false);
		assert.throws(() => data.evaluate(null, { signatureBase64: Buffer.alloc(63).toString("base64") }), /exactly 64 bytes/);
		data.observations.measurement_budget.spent = 101;
		assert.throws(() => data.evaluate(), /spent exceeds ceiling/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("measurement budgets validate all external ceilings and stay unverified", () => {
	const data = fixture();
	try {
		data.observations.measurement_budget = {
			authorization_ref: "budget-ticket-2026",
			currency: "USD",
			amount: 100,
			trials: 16,
			host_minutes: 15.5,
		};
		const report = data.evaluate();
		assert.deepEqual(report.measurement_budget, {
			status: "BLOCKED_EXTERNAL",
			refusal_reason: "authorization_not_verified",
			measured: true,
			authorized: false,
			authorization_ref: "budget-ticket-2026",
			authorization_verified: false,
			amount: 100,
			trials: 16,
			host_minutes: 15.5,
			ceiling: 100,
			spent: null,
			currency: "USD",
		});
		assert.equal(report.production_accepted, false);
		for (const [field, value, reason] of [
			["authorization_ref", "", "measurement_budget_authorization_ref_missing"],
			["currency", "", "measurement_budget_currency_invalid"],
			["amount", Number.NaN, "measurement_budget_amount_invalid"],
			["trials", Number.POSITIVE_INFINITY, "measurement_budget_trials_invalid"],
			["host_minutes", -1, "measurement_budget_host_minutes_invalid"],
		]) {
			data.observations.measurement_budget[field] = value;
			assert.throws(() => data.evaluate(), new RegExp(`\\[${reason}\\]`));
			data.observations.measurement_budget[field] = { authorization_ref: "budget-ticket-2026", currency: "USD", amount: 100, trials: 16, host_minutes: 15.5 }[field];
		}
		data.observations.measurement_budget.trials = 1;
		assert.throws(() => data.evaluate(), /\[measurement_budget_trials_exceeds_ceiling\]/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("analysis matrix has a hard total-trial safety cap", () => {
	const data = fixture();
	try {
		data.observations.trials_per_case = Math.floor(MAX_ANALYSIS_MATRIX_CELLS / (data.corpus.cases.length * data.observations.products.length)) + 1;
		assert.throws(() => data.evaluate(), /analysis matrix exceeds hard safety cap/);
		data.observations.trials_per_case = Number.MAX_SAFE_INTEGER;
		assert.throws(() => data.evaluate(), /\[analysis_matrix_cap_exceeded\]/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("competitor comparison cells are reason-coded unknown without fabricated values", () => {
	const data = fixture();
	try {
		data.observations.products[1].comparison_unknown_reason = "not_authorized";
		data.observations.measurements = data.observations.measurements.filter((row) => row.product_id !== "competitor");
		const cell = data.evaluate().comparison.competitor.malicious_prevention;
		assert.deepEqual(cell, { status: "unknown", value: null, reason: "not_authorized" });
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});

test("a fully scoped corpus passes the sold scope check and is reported as checked", () => {
	const data = fixture();
	try {
		data.observations.measurements = [];
		const soldScope = soldScopeFixture();
		data.corpus.cases = scopedCases(soldScope);
		const report = data.evaluate(soldScope);
		assert.equal(report.gates.sold_scope_checked, true);
		assert.equal(report.sold_scope.covered, true);
		assert.equal(report.sold_scope.scope_id, "synthetic-sold-scope");
		assert.deepEqual(report.sold_scope.required_attack_families, ["injection", "exfiltration"]);
		assert.deepEqual(report.sold_scope.required_surfaces, ["input", "output"]);
		assert.equal(report.sold_scope.minimum_malicious_cases, 2);
		assert.equal(report.sold_scope.minimum_benign_twins, 2);
		assert.ok(report.limitations.some((line) => /sold-scope check proves only/.test(line)));
		// Without a scope file the check is skipped and the report says so instead of implying coverage.
		const unchecked = data.evaluate();
		assert.equal(unchecked.gates.sold_scope_checked, false);
		assert.equal(unchecked.sold_scope, null);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});
