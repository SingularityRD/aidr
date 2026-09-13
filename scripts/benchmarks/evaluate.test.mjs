import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { evaluateBenchmark } from "./evaluate.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");

function fixture() {
	const directory = mkdtempSync(join(tmpdir(), "aidr-benchmark-test-"));
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const corpus = {
		schema_version: 1, corpus_id: "synthetic-harness-only", version: "1",
		rule_author_id: "rule-team", oracle_reviewer_id: "oracle-reviewer",
		scope: { required_attack_families: ["injection", "exfiltration"], required_connectors: ["tool-a", "tool-b"], required_surfaces: ["input", "output"] },
		cases: [
			{ case_id: "attack-dev", partition: "development", oracle: "malicious", family: "injection", connector: "tool-a", surface: "input" },
			{ case_id: "attack-holdout", partition: "holdout", oracle: "malicious", family: "exfiltration", connector: "tool-a", surface: "output" },
			{ case_id: "benign-dev", partition: "development", oracle: "benign", family: "ordinary-work", connector: "tool-a", surface: "input" },
			{ case_id: "benign-holdout", partition: "holdout", oracle: "benign", family: "ordinary-work", connector: "tool-b", surface: "output" },
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
			raw_evidence_file: file, raw_evidence_sha256: hash(raw),
		};
		if (entry.oracle === "malicious") row.side_effect_occurred = false;
		observations.measurements.push(row);
	}
	function evaluate() {
		const corpusBytes = Buffer.from(JSON.stringify(corpus));
		const observationBytes = Buffer.from(JSON.stringify(observations));
		const observationsPath = join(directory, "observations.json");
		writeFileSync(observationsPath, observationBytes);
		const payload = {
			protocol_version: 1, corpus_sha256: hash(corpusBytes), observations_sha256: hash(observationBytes),
			candidate_artifact_sha256: observations.products[0].artifact_sha256,
			rule_author_id: corpus.rule_author_id, evaluator_id: "external-evaluator",
			evaluator_role: "independent_evaluator", completed_at: "2026-09-13T00:00:00Z",
		};
		const attestation = { schema_version: 1, payload, signature_base64: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64") };
		return evaluateBenchmark({ corpus, observations, attestation, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }), corpusBytes, observationBytes, observationsPath });
	}
	return { directory, corpus, observations, publicKey, privateKey, evaluate };
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
		assert.equal(JSON.parse(readFileSync(reportPath, "utf8")).claim_status, "EVIDENCE_REVIEW_REQUIRED");
		data.observations.workload_id = "changed-after-signature";
		writeFileSync(observationsPath, JSON.stringify(data.observations));
		const rejected = spawnSync(process.execPath, command, { encoding: "utf8" });
		assert.equal(rejected.status, 1);
		assert.match(rejected.stderr, /observations hash differs from signed attestation/);
	} finally { rmSync(data.directory, { recursive: true, force: true }); }
});
