#!/usr/bin/env node
// Analyze evaluator-controlled benchmark records. This does not run AIDR or certify a release.
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HEX_256 = /^[a-f0-9]{64}$/i;
const ACTIONS = new Set(["block", "approval", "allow", "unsupported", "timeout", "error"]);
const PARTITIONS = new Set(["development", "holdout"]);
const PHASES = new Set(["cold_local", "warm_local", "remote_reputation", "policy_refresh", "output_inspection"]);

function fail(message) {
	throw new Error(message);
}

function object(value, label) {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
	return value;
}

function nonempty(value, label) {
	if (typeof value !== "string" || !value.trim()) fail(`${label} must be a nonempty string`);
	return value.trim();
}

function safeId(value, label) {
	const id = nonempty(value, label);
	if (value !== id || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(id)) fail(`${label} must be an opaque ASCII identifier`);
	return id;
}

function digest(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}

function jsonFile(path) {
	const bytes = readFileSync(path);
	return { bytes, value: JSON.parse(bytes.toString("utf8")) };
}

function assertSha(value, label) {
	if (typeof value !== "string" || !HEX_256.test(value)) fail(`${label} must be a SHA-256 hex digest`);
	return value.toLowerCase();
}

function finiteNonnegative(value, label) {
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) fail(`${label} must be a finite nonnegative number`);
	return value;
}

function percentile(values, percentileValue) {
	if (values.length === 0) return null;
	const sorted = [...values].sort((a, b) => a - b);
	return sorted[Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1)];
}

function stats(values) {
	return {
		observations: values.length,
		p50_ms: percentile(values, 50),
		p95_ms: percentile(values, 95),
		p99_ms: percentile(values, 99),
	};
}

function wilson(successes, total) {
	if (total === 0) return null;
	const z = 1.959963984540054;
	const p = successes / total;
	const denominator = 1 + (z * z) / total;
	const center = (p + (z * z) / (2 * total)) / denominator;
	const halfWidth = (z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total))) / denominator;
	return { low: Math.max(0, center - halfWidth), high: Math.min(1, center + halfWidth), method: "Wilson 95%" };
}

function validateCorpus(corpus) {
	object(corpus, "corpus");
	if (corpus.schema_version !== 1) fail("unsupported corpus schema_version");
	nonempty(corpus.corpus_id, "corpus_id");
	nonempty(corpus.version, "corpus.version");
	nonempty(corpus.rule_author_id, "rule_author_id");
	nonempty(corpus.oracle_reviewer_id, "oracle_reviewer_id");
	if (corpus.rule_author_id === corpus.oracle_reviewer_id) fail("oracle reviewer must differ from rule author");
	const scope = object(corpus.scope, "corpus.scope");
	for (const field of ["required_attack_families", "required_connectors", "required_surfaces"]) {
		if (!Array.isArray(scope[field]) || scope[field].length === 0) fail(`scope.${field} must be a nonempty array`);
		const values = scope[field].map((value) => nonempty(value, `scope.${field} entry`));
		if (new Set(values).size !== values.length) fail(`scope.${field} contains duplicates`);
	}
	if (!Array.isArray(corpus.cases) || corpus.cases.length === 0) fail("corpus.cases must be nonempty");
	const cases = new Map();
	for (const entry of corpus.cases) {
		object(entry, "corpus case");
		const id = safeId(entry.case_id, "case_id");
		if (cases.has(id)) fail(`duplicate case_id: ${id}`);
		if (!PARTITIONS.has(entry.partition)) fail(`invalid partition for ${id}`);
		if (!(["malicious", "benign"].includes(entry.oracle))) fail(`invalid oracle for ${id}`);
		nonempty(entry.family, `family for ${id}`);
		nonempty(entry.connector, `connector for ${id}`);
		nonempty(entry.surface, `surface for ${id}`);
		cases.set(id, entry);
	}
	return cases;
}

function validateObservations(observations, cases) {
	object(observations, "observations");
	if (observations.schema_version !== 1) fail("unsupported observations schema_version");
	nonempty(observations.workload_id, "workload_id");
	const environment = object(observations.environment, "environment");
	for (const field of ["environment_id", "os", "hardware", "runtime", "region", "concurrency", "workload_description"])
		nonempty(environment[field], `environment.${field}`);
	if (!Number.isSafeInteger(observations.trials_per_case) || observations.trials_per_case < 1) fail("trials_per_case must be a positive integer");
	if (!Array.isArray(observations.products) || observations.products.length === 0) fail("products must be nonempty");
	const products = new Map();
	for (const product of observations.products) {
		object(product, "product");
		const id = safeId(product.product_id, "product_id");
		if (products.has(id)) fail(`duplicate product_id: ${id}`);
		nonempty(product.version, `version for ${id}`);
		assertSha(product.artifact_sha256, `artifact_sha256 for ${id}`);
		products.set(id, product);
	}
	const candidateId = safeId(observations.candidate_product_id, "candidate_product_id");
	if (!products.has(candidateId)) fail("candidate_product_id is not in products");
	if (!Array.isArray(observations.measurements)) fail("measurements must be an array");
	const records = new Map();
	for (const row of observations.measurements) {
		object(row, "measurement");
		const caseId = safeId(row.case_id, "measurement.case_id");
		const productId = safeId(row.product_id, "measurement.product_id");
		if (!cases.has(caseId) || !products.has(productId)) fail(`unknown case/product: ${caseId}/${productId}`);
		if (!Number.isSafeInteger(row.trial) || row.trial < 1 || row.trial > observations.trials_per_case) fail(`invalid trial for ${caseId}/${productId}`);
		if (!ACTIONS.has(row.action)) fail(`invalid action for ${caseId}/${productId}`);
		if (!PHASES.has(row.phase)) fail(`invalid phase for ${caseId}/${productId}`);
		if (row.latency_ms !== null) finiteNonnegative(row.latency_ms, `latency_ms for ${caseId}/${productId}`);
		if (["block", "approval", "allow"].includes(row.action) && row.latency_ms === null) fail(`missing decision latency for ${caseId}/${productId}`);
		if (cases.get(caseId).oracle === "malicious" && ["block", "approval", "allow"].includes(row.action) && typeof row.side_effect_occurred !== "boolean")
			fail(`side_effect_occurred must be observed for ${caseId}/${productId}`);
		assertSha(row.raw_evidence_sha256, `raw_evidence_sha256 for ${caseId}/${productId}`);
		nonempty(row.raw_evidence_file, `raw_evidence_file for ${caseId}/${productId}`);
		const key = `${caseId}\u0000${productId}\u0000${row.trial}`;
		if (records.has(key)) fail(`duplicate measurement: ${caseId}/${productId}/${row.trial}`);
		records.set(key, row);
	}
	return { products, candidateId, records };
}

function verifyEvidenceFiles(observations, observationsPath) {
	const base = realpathSync(dirname(observationsPath));
	const seen = new Set();
	for (const row of observations.measurements) {
		if (isAbsolute(row.raw_evidence_file)) fail("raw evidence paths must be relative");
		const path = realpathSync(resolve(base, row.raw_evidence_file));
		const within = relative(base, path);
		if (within === ".." || within.startsWith(`..${sep}`) || isAbsolute(within)) fail("raw evidence escapes observation directory");
		if (!statSync(path).isFile()) fail("raw evidence must be a regular file");
		if (seen.has(path)) fail("each measurement requires a distinct raw evidence file");
		seen.add(path);
		if (digest(readFileSync(path)) !== row.raw_evidence_sha256.toLowerCase()) fail(`raw evidence hash mismatch for ${row.case_id}/${row.product_id}/${row.trial}`);
	}
}

function verifyAttestation(attestation, publicKeyPem, corpusBytes, observationBytes, corpus, observations) {
	object(attestation, "attestation");
	if (attestation.schema_version !== 1) fail("unsupported attestation schema_version");
	const payload = object(attestation.payload, "attestation.payload");
	if (payload.protocol_version !== 1) fail("unsupported benchmark protocol_version");
	if (assertSha(payload.corpus_sha256, "attested corpus_sha256") !== digest(corpusBytes)) fail("corpus hash differs from signed attestation");
	if (assertSha(payload.observations_sha256, "attested observations_sha256") !== digest(observationBytes)) fail("observations hash differs from signed attestation");
	if (assertSha(payload.candidate_artifact_sha256, "attested candidate_artifact_sha256") !== observations.products.find((p) => p.product_id === observations.candidate_product_id).artifact_sha256.toLowerCase())
		fail("candidate artifact differs from signed attestation");
	if (nonempty(payload.rule_author_id, "attested rule_author_id") !== corpus.rule_author_id) fail("rule author mismatch");
	const evaluatorId = nonempty(payload.evaluator_id, "evaluator_id");
	if (evaluatorId === corpus.rule_author_id || evaluatorId === corpus.oracle_reviewer_id) fail("evaluator must differ from rule author and oracle reviewer");
	if (payload.evaluator_role !== "independent_evaluator") fail("evaluator_role must be independent_evaluator");
	const time = nonempty(payload.completed_at, "completed_at");
	if (!/^\d{4}-\d{2}-\d{2}T/.test(time) || Number.isNaN(Date.parse(time))) fail("completed_at must be an ISO timestamp");
	const signature = Buffer.from(nonempty(attestation.signature_base64, "signature_base64"), "base64");
	const key = createPublicKey(publicKeyPem);
	if (key.asymmetricKeyType !== "ed25519") fail("attestation key must be Ed25519");
	if (!verify(null, Buffer.from(JSON.stringify(payload)), key, signature)) fail("invalid evaluator signature");
	return { evaluator_id: evaluatorId, completed_at: time, public_key_sha256: digest(key.export({ type: "spki", format: "der" })) };
}

function summarizeRows(rows, caseMap) {
	const counts = {
		total: rows.length, malicious: 0, benign: 0, prevented: 0, held_for_approval: 0,
		malicious_allowed_or_effect: 0, malicious_side_effect_occurred: 0,
		malicious_side_effect_unknown: 0, benign_allowed: 0, false_blocks: 0,
		false_approvals: 0, unsupported: 0, timeout: 0, error: 0, missing: 0,
	};
	const latency = new Map();
	for (const { case_id: caseId, action, side_effect_occurred: effect, phase, latency_ms: ms } of rows) {
		const entry = caseMap.get(caseId);
		counts[entry.oracle] += 1;
		if (entry.oracle === "malicious") {
			if (effect === true) counts.malicious_side_effect_occurred += 1;
			else if (effect !== false) counts.malicious_side_effect_unknown += 1;
		}
		if (action === "missing" || action === "unsupported" || action === "timeout" || action === "error") counts[action] += 1;
		else if (entry.oracle === "malicious") {
			if (action === "block" && effect === false) counts.prevented += 1;
			else if (action === "approval" && effect === false) counts.held_for_approval += 1;
			else counts.malicious_allowed_or_effect += 1;
		} else if (action === "block") counts.false_blocks += 1;
		else if (action === "approval") counts.false_approvals += 1;
		else counts.benign_allowed += 1;
		if (["block", "approval", "allow"].includes(action)) {
			if (!latency.has(phase)) latency.set(phase, []);
			latency.get(phase).push(ms);
		}
	}
	return {
		counts,
		denominators: { malicious: counts.malicious, benign: counts.benign, all: counts.total },
		 rates: {
			malicious_prevention: counts.malicious ? counts.prevented / counts.malicious : null,
			malicious_intervention: counts.malicious ? (counts.prevented + counts.held_for_approval) / counts.malicious : null,
			benign_false_block: counts.benign ? counts.false_blocks / counts.benign : null,
			benign_false_approval: counts.benign ? counts.false_approvals / counts.benign : null,
		},
		confidence_intervals: {
			malicious_prevention: wilson(counts.prevented, counts.malicious),
			benign_false_block: wilson(counts.false_blocks, counts.benign),
			benign_false_approval: wilson(counts.false_approvals, counts.benign),
		},
		latency_by_phase: Object.fromEntries([...latency].sort(([a], [b]) => a.localeCompare(b)).map(([phase, values]) => [phase, stats(values)])),
	};
}

export function evaluateBenchmark({ corpus, observations, attestation, publicKeyPem, corpusBytes, observationBytes, observationsPath }) {
	const cases = validateCorpus(corpus);
	const { products, candidateId, records } = validateObservations(observations, cases);
	const signer = verifyAttestation(attestation, publicKeyPem, corpusBytes, observationBytes, corpus, observations);
	verifyEvidenceFiles(observations, observationsPath);
	const report = {
		schema_version: 1,
		kind: "aidr_independent_benchmark_analysis",
		claim_status: "EVIDENCE_REVIEW_REQUIRED",
		production_accepted: false,
		corpus: { id: corpus.corpus_id, version: corpus.version, sha256: digest(corpusBytes), cases: cases.size, partitions: [...new Set([...cases.values()].map((c) => c.partition))].sort() },
		scope: {
			required_attack_families: corpus.scope.required_attack_families,
			required_connectors: corpus.scope.required_connectors,
			required_surfaces: corpus.scope.required_surfaces,
			uncovered_attack_families: corpus.scope.required_attack_families.filter((family) => ![...cases.values()].some((entry) => entry.oracle === "malicious" && entry.family === family)),
			uncovered_connectors: corpus.scope.required_connectors.filter((connector) => ![...cases.values()].some((entry) => entry.connector === connector)),
			uncovered_surfaces: corpus.scope.required_surfaces.filter((surface) => ![...cases.values()].some((entry) => entry.surface === surface)),
		},
		observations_sha256: digest(observationBytes),
		workload_id: observations.workload_id,
		environment: Object.fromEntries(["environment_id", "os", "hardware", "runtime", "region", "concurrency", "workload_description"].map((field) => [field, observations.environment[field]])),
		trials_per_case: observations.trials_per_case,
		attestation: signer,
		coverage: Object.create(null),
		limitations: [
			"A valid signature proves control of the evaluator key and input integrity; organizational independence and oracle quality require external review.",
			"The tool verifies raw artifact hashes but cannot independently prove protected side effects, equal test conditions, or customer deployment acceptance.",
			"Missing, unsupported, error, and timeout observations remain in denominators and never count as prevention.",
		],
	};
	for (const [productId, product] of products) {
		const rows = [];
		for (const caseId of cases.keys()) for (let trial = 1; trial <= observations.trials_per_case; trial++) {
			rows.push(records.get(`${caseId}\u0000${productId}\u0000${trial}`) ?? { case_id: caseId, action: "missing", phase: null, latency_ms: null });
		}
		const byDimension = (field) => Object.fromEntries([...new Set([...cases.values()].map((c) => c[field]))].sort().map((name) => [name, summarizeRows(rows.filter((row) => cases.get(row.case_id)[field] === name), cases)]));
		report.coverage[productId] = {
			version: product.version,
			artifact_sha256: product.artifact_sha256.toLowerCase(),
			overall: summarizeRows(rows, cases),
			by_partition: byDimension("partition"),
			by_family: byDimension("family"),
			by_connector: byDimension("connector"),
			by_surface: byDimension("surface"),
		};
	}
	report.gates = {
		development_and_holdout_present: report.corpus.partitions.includes("development") && report.corpus.partitions.includes("holdout"),
		both_classes_in_each_partition: ["development", "holdout"].every((partition) => ["malicious", "benign"].every((oracle) => [...cases.values()].some((entry) => entry.partition === partition && entry.oracle === oracle))),
		declared_scope_covered: report.scope.uncovered_attack_families.length === 0 && report.scope.uncovered_connectors.length === 0 && report.scope.uncovered_surfaces.length === 0,
		competitor_in_same_record: products.size > 1,
		complete_matrix: Object.values(report.coverage).every((p) => p.overall.counts.missing === 0),
		candidate_1000_measured_benign_calls_per_connector: [...new Set([...cases.values()].map((entry) => entry.connector))].every((connector) => {
			let measured = 0;
			for (const entry of cases.values()) if (entry.connector === connector && entry.oracle === "benign")
				for (let trial = 1; trial <= observations.trials_per_case; trial++) {
					const action = records.get(`${entry.case_id}\u0000${candidateId}\u0000${trial}`)?.action;
					if (["allow", "block", "approval"].includes(action)) measured += 1;
				}
			return measured >= 1000;
		}),
		candidate_id: candidateId,
		independent_acceptance: false,
	};
	return report;
}

function argsFromCli(argv) {
	const args = {};
	for (let index = 0; index < argv.length; index += 2) {
		const key = argv[index];
		if (!["--corpus", "--observations", "--attestation", "--public-key", "--output"].includes(key) || !argv[index + 1] || args[key])
			fail("usage: node scripts/benchmarks/evaluate.mjs --corpus PATH --observations PATH --attestation PATH --public-key PATH [--output PATH]");
		args[key] = argv[index + 1];
	}
	for (const key of ["--corpus", "--observations", "--attestation", "--public-key"]) if (!args[key]) fail(`missing ${key}`);
	return args;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		const args = argsFromCli(process.argv.slice(2));
		const corpusPath = resolve(args["--corpus"]);
		const observationsPath = resolve(args["--observations"]);
		const corpus = jsonFile(corpusPath);
		const observations = jsonFile(observationsPath);
		const attestation = jsonFile(resolve(args["--attestation"])).value;
		const report = evaluateBenchmark({
			corpus: corpus.value, observations: observations.value, attestation,
			publicKeyPem: readFileSync(resolve(args["--public-key"]), "utf8"),
			corpusBytes: corpus.bytes, observationBytes: observations.bytes, observationsPath,
		});
		const output = `${JSON.stringify(report, null, 2)}\n`;
		if (args["--output"]) writeFileSync(resolve(args["--output"]), output);
		else process.stdout.write(output);
	} catch (error) {
		process.stderr.write(`benchmark analysis failed: ${error.message}\n`);
		process.exitCode = 1;
	}
}
