#!/usr/bin/env node
// Run on the independent evaluator's machine with a private key kept outside this repository.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { validateComparisonSpec } from "./evaluate.mjs";

function fail(message) { throw new Error(message); }
function sha(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
function safeId(value, label) {
	if (typeof value !== "string" || value.length === 0 || value.trim() !== value || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) fail(`${label} must be an opaque ASCII identifier`);
	return value;
}
function strictBase64(value, label, expectedBytes) {
	const message = `${label} must be canonical base64 encoding of exactly ${expectedBytes} bytes`;
	const expectedLength = Math.ceil(expectedBytes / 3) * 4;
	if (typeof value !== "string" || value.length !== expectedLength || !CANONICAL_BASE64.test(value)) fail(message);
	const decoded = Buffer.from(value, "base64");
	if (decoded.length !== expectedBytes || decoded.toString("base64") !== value) fail(message);
	return decoded;
}
function optionMap(argv) {
	const options = {};
	for (let index = 0; index < argv.length; index += 2) {
		const key = argv[index];
		if (!["--corpus", "--observations", "--comparison-spec", "--private-key", "--evaluator-id", "--split-manifest", "--signing-key-id", "--operating-point", "--output"].includes(key) || !argv[index + 1] || options[key])
			fail("usage: node scripts/benchmarks/attest.mjs --corpus PATH --observations PATH --comparison-spec PATH --private-key PATH --evaluator-id ID [--split-manifest PATH] [--signing-key-id ID] [--operating-point 0..1] --output PATH");
		options[key] = argv[index + 1];
	}
	for (const key of ["--corpus", "--observations", "--comparison-spec", "--private-key", "--evaluator-id", "--output"]) if (!options[key]) fail(`missing ${key}`);
	return options;
}

try {
	const options = optionMap(process.argv.slice(2));
	const corpusBytes = readFileSync(resolve(options["--corpus"]));
	const observationBytes = readFileSync(resolve(options["--observations"]));
	const comparisonSpecBytes = readFileSync(resolve(options["--comparison-spec"]));
	const comparisonSpec = JSON.parse(comparisonSpecBytes.toString("utf8"));
	validateComparisonSpec(comparisonSpec);
	const corpus = JSON.parse(corpusBytes.toString("utf8"));
	const observations = JSON.parse(observationBytes.toString("utf8"));
	const evaluatorId = safeId(options["--evaluator-id"], "evaluator identity");
	if (evaluatorId === corpus.rule_author_id || evaluatorId === corpus.oracle_reviewer_id)
		fail("evaluator identity must differ from rule author and oracle reviewer");
	const candidate = observations.products?.find((p) => p.product_id === observations.candidate_product_id);
	if (!candidate || !/^[a-f0-9]{64}$/i.test(candidate.artifact_sha256)) fail("candidate artifact digest is missing or invalid");
	const privateKey = createPrivateKey(readFileSync(resolve(options["--private-key"])));
	if (privateKey.asymmetricKeyType !== "ed25519") fail("private key must be Ed25519");
	const payload = {
		protocol_version: 1,
		corpus_sha256: sha(corpusBytes),
		observations_sha256: sha(observationBytes),
		comparison_spec_sha256: sha(comparisonSpecBytes),
		candidate_artifact_sha256: candidate.artifact_sha256.toLowerCase(),
		rule_author_id: corpus.rule_author_id,
		evaluator_id: evaluatorId,
		evaluator_role: "independent_evaluator",
		completed_at: new Date().toISOString(),
	};
	if (options["--signing-key-id"]) payload.signing_key_id = safeId(options["--signing-key-id"], "signing key id");
	if (options["--split-manifest"]) payload.split_manifest_sha256 = sha(readFileSync(resolve(options["--split-manifest"])));
	if (options["--operating-point"]) {
		if (!options["--split-manifest"]) fail("--operating-point requires --split-manifest");
		const threshold = Number(options["--operating-point"]);
		if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) fail("--operating-point must be between 0 and 1");
		payload.frozen_operating_point = { frozen: true, threshold };
	}
	const signatureBase64 = sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64");
	strictBase64(signatureBase64, "attestation signature", 64);
	const attestation = {
		schema_version: 1,
		payload,
		signature_base64: signatureBase64,
	};
	writeFileSync(resolve(options["--output"]), `${JSON.stringify(attestation, null, 2)}\n`, { flag: "wx" });
	const publicKey = createPublicKey(privateKey);
	process.stdout.write(`Attestation written. Evaluator public-key SHA-256: ${sha(publicKey.export({ type: "spki", format: "der" }))}\n`);
} catch (error) {
	process.stderr.write(`attestation failed: ${error.message}\n`);
	process.exitCode = 1;
}
