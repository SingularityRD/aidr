#!/usr/bin/env node
// node --test suite for the v8 evidence index generator.
//
// The suite drives the generator's exported functions directly, so it fails when
// the generator starts admitting a gap: an omitted gate, an empty-string field, a
// pass-like status next to a non-zero exit code, or a claim above the evidence
// level the artefacts actually substantiate.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

import {
	buildEvidenceIndex,
	buildGateRecord,
	CANDIDATE_DIGEST_SOURCE,
	candidateDigest,
	countStatuses,
	EVIDENCE_LEVEL_FLOOR,
	EVIDENCE_LEVELS,
	evidenceLevelRank,
	failClosedEvidenceLevel,
	GATES,
	INDEX_FILE,
	levelsAreSubstituted,
	LOG_DIR,
	ROOT,
	SCHEMA_FILE,
	serializeIndex,
	sha256Hex,
	resultBindingFailures,
	STATUS_NOT_RUN,
	UNKNOWN,
	verifyEvidenceIndex,
	writeResultFile,
} from "./generate-v8-evidence-index.mjs";

const schema = JSON.parse(readFileSync(resolve(ROOT, SCHEMA_FILE), "utf8"));

function clone(value) {
	return JSON.parse(JSON.stringify(value));
}

// Build once per test process: every probe in the generator spawns a tool, and
// the tests only mutate clones. The determinism test deliberately builds twice.
let cachedIndex = null;
function freshIndex() {
	cachedIndex ??= buildEvidenceIndex();
	return cachedIndex;
}

function errorText(result) {
	return result.errors.join("\n");
}

test("a complete valid index passes schema and semantic validation", () => {
	const index = freshIndex();
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, true, errorText(result));
	assert.equal(index.gates.length, GATES.length);
	assert.equal(index.gate_count, GATES.length);
	assert.deepEqual(
		index.gates.map((record) => record.gate_id),
		GATES.map((entry) => entry.gate_id),
	);
});

test("a record missing a required field fails", () => {
	const index = clone(freshIndex());
	delete index.gates[0].exit_code;
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /missing required property 'exit_code'/);
});

test("an empty-string field fails", () => {
	const index = clone(freshIndex());
	index.gates[0].observed_effect = "";
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /observed_effect/);
	assert.match(errorText(result), /minLength 1|empty string/);

	const nested = clone(freshIndex());
	nested.gates[0].limitations = [""];
	const nestedResult = verifyEvidenceIndex(nested, schema);
	assert.equal(nestedResult.ok, false);
	assert.match(errorText(nestedResult), /empty string|minLength 1/);
});

test("a record with an undeclared extra field fails", () => {
	const index = clone(freshIndex());
	index.gates[0].nice_to_have = "not in the schema";
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /additional property 'nice_to_have'/);
});

test('status "PASS" with a non-zero exit code fails', () => {
	const index = clone(freshIndex());
	index.gates[0].status = "PASS";
	index.gates[0].exit_code = 1;
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /pass-like but exit_code is 1/);
});

test("a lower evidence level cannot be recorded as a higher one", () => {
	// Ordering is total and strictly increasing across the declared vocabulary.
	for (let position = 1; position < EVIDENCE_LEVELS.length; position += 1) {
		assert.ok(evidenceLevelRank(EVIDENCE_LEVELS[position]) > evidenceLevelRank(EVIDENCE_LEVELS[position - 1]));
	}
	assert.equal(evidenceLevelRank(EVIDENCE_LEVEL_FLOOR), 0);
	assert.equal(evidenceLevelRank("not-a-level"), -1);

	assert.equal(levelsAreSubstituted("unit_contract", "native_host"), true);
	assert.equal(levelsAreSubstituted("native_host", "customer_observed"), true);
	assert.equal(levelsAreSubstituted("native_host", "unit_contract"), false);
	assert.equal(levelsAreSubstituted("native_host", "native_host"), false);

	// A claim above what the artefacts substantiate collapses to the substantiated
	// level; a deliberately weaker claim is preserved.
	assert.equal(failClosedEvidenceLevel("native_host", "unit_contract"), "unit_contract");
	assert.equal(failClosedEvidenceLevel("externally_approved", EVIDENCE_LEVEL_FLOOR), EVIDENCE_LEVEL_FLOOR);
	assert.equal(failClosedEvidenceLevel("source_inspection", "native_host"), "source_inspection");
	assert.throws(() => failClosedEvidenceLevel("almost_native", "native_host"), /unknown evidence level/);

	// The same rule is enforced on every emitted record: no record may claim a
	// level above its own ceiling.
	for (const record of freshIndex().gates) {
		assert.equal(
			levelsAreSubstituted(record.evidence_level_ceiling, record.evidence_level),
			false,
			`${record.gate_id}: ${record.evidence_level} exceeds ${record.evidence_level_ceiling}`,
		);
	}

	const index = clone(freshIndex());
	index.gates[0].evidence_level = "native_host";
	index.gates[0].evidence_level_ceiling = "source_inspection";
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /exceeds its ceiling/);
});

test("a missing log produces NOT_RUN instead of an omission", () => {
	const baseline = freshIndex();
	const context = {
		root: ROOT,
		commit_sha: baseline.commit_sha,
		candidate_digest: baseline.candidate_digest,
		environment: {
			platform: "test",
			arch: "test",
			os_type: "test",
			os_release: "test",
			hostname: "test",
			gate_host_provenance: UNKNOWN,
		},
		tool_versions: { node: "test", pnpm: "test", python: "test", docker: "test", os: "test" },
	};
	const missingGate = {
		gate_id: "99-missing-log-fixture",
		command: "node scripts/does-not-exist.mjs",
		log: "99-missing-log-fixture.log",
		artifact: null,
		counts: "none",
		pass: null,
		fail: null,
		task_ids: ["T35"],
		feature_ids: ["EVAL-01"],
		owner: "quality-engineering",
		evidence_level: "packaged_consumer",
		evidence_level_ceiling: "packaged_consumer",
		limitations: ["fixture gate that was never run"],
	};

	assert.equal(existsSync(resolve(ROOT, "01-git-diff-check.log")), false);
	const record = buildGateRecord(missingGate, context);
	assert.equal(record.status, STATUS_NOT_RUN);
	assert.equal(record.exit_code, UNKNOWN);
	assert.equal(record.log_sha256, UNKNOWN);
	assert.equal(record.evidence_level, EVIDENCE_LEVEL_FLOOR);
	assert.ok(record.observed_effect.length > 0);
	assert.ok(record.limitations.some((entry) => /no log at/.test(entry)));

	// The record is still schema-valid, and the declared gate is never omitted:
	// a full index always carries one record per declared gate.
	const index = clone(baseline);
	index.gates.push(record);
	index.gate_count = index.gates.length;
	index.status_counts = countStatuses(index.gates);
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, true, errorText(result));
});

test("a captured result file is read back as the authoritative exit status", () => {
	// Drives the same writer that --run/--record use, into a temp directory, so a
	// broken path cannot silently write the sidecar somewhere the index never reads.
	const directory = mkdtempSync(join(tmpdir(), "aidr-gate-capture-"));
	const target = {
		gateEntry: { gate_id: "fixture-gate", command: "node scripts/fixture.mjs" },
		absolute: join(directory, "fixture.log"),
	};
	const written = writeResultFile(target, {
		exit_code: 0,
		started_at_utc: "2026-09-13T00:00:00.000Z",
		ended_at_utc: "2026-09-13T00:00:02.000Z",
		duration_ms: 2000,
		captured_by: "record",
		// A result file must not be able to self-assert its own provenance, so the
		// writer is asked to record values that contradict the tree and must
		// replace every one of them.
		commit_sha: "caller-supplied",
		source_commit: "caller-supplied",
		candidate_digest: "caller-supplied",
		candidate_digest_source: "caller-supplied",
		log_sha256: "caller-supplied",
		artifact_sha256: "caller-supplied",
	});
	assert.equal(written.gate_id, "fixture-gate");
	const sidecar = JSON.parse(readFileSync(`${target.absolute}.result.json`, "utf8"));
	assert.equal(sidecar.exit_code, 0);
	assert.equal(sidecar.duration_ms, 2000);
	assert.equal(sidecar.provenance_version, 1);
	assert.match(sidecar.commit_sha, /^[0-9a-f]{40}$/);
	assert.equal(sidecar.source_commit, sidecar.commit_sha);
	// The candidate inventory is a local build artefact: it is absent in a fresh
	// clone and present once a rehearsal has run, so the binding is the digest of
	// whatever is on disk here rather than a fixed value. Asserting UNKNOWN
	// unconditionally made this test fail in exactly the tree that produces the
	// index, which is why it now asserts the derivation instead.
	assert.equal(sidecar.candidate_digest, candidateDigest(ROOT).digest);
	assert.equal(sidecar.candidate_digest_source, CANDIDATE_DIGEST_SOURCE);
	// No log was captured and the synthetic gate declares no artifact, so those
	// two bindings are the only ones that stay unknown.
	assert.equal(sidecar.log_sha256, UNKNOWN);
	assert.equal(sidecar.artifact_sha256, UNKNOWN);
	assert.equal(existsSync(join(process.cwd(), "undefined.result.json")), false);
});

test("a result file is preferred over a contradictory log marker", () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-gate-authority-"));
	const logDirectory = join(root, LOG_DIR);
	mkdirSync(logDirectory, { recursive: true });
	const logPath = join(logDirectory, "fixture.log");
	const logText = "ALL PASS - 3/3 cases behaved correctly\n";
	writeFileSync(logPath, logText);
	writeFileSync(
		`${logPath}.result.json`,
		`${JSON.stringify(
			{
				gate_id: "fixture-authority",
				command: "node scripts/fixture.mjs",
				provenance_version: 1,
				commit_sha: "0".repeat(40),
				source_commit: "0".repeat(40),
				candidate_digest: "1".repeat(64),
				candidate_digest_source: CANDIDATE_DIGEST_SOURCE,
				log_sha256: sha256Hex(Buffer.from(logText)),
				artifact_sha256: UNKNOWN,
				exit_code: 1,
				captured_by: "record",
			},
			null,
			2,
		)}\n`,
	);
	const record = buildGateRecord(
		{
			gate_id: "fixture-authority",
			command: "node scripts/fixture.mjs",
			log: "fixture.log",
			artifact: null,
			counts: "cases",
			pass: /ALL PASS - (\d+)\/(\d+) cases behaved correctly/,
			fail: null,
			task_ids: ["T35"],
			feature_ids: ["EVAL-01"],
			owner: "quality-engineering",
			evidence_level: "unit_contract",
			evidence_level_ceiling: "unit_contract",
			limitations: ["fixture"],
		},
		{
			root,
			commit_sha: "0".repeat(40),
			candidate_digest: "1".repeat(64),
			environment: {
				platform: "test",
				arch: "test",
				os_type: "test",
				os_release: "test",
				hostname: "test",
				gate_host_provenance: UNKNOWN,
			},
			tool_versions: { node: "test", pnpm: "test", python: "test", docker: "test", os: "test" },
		},
	);
	assert.equal(record.exit_code, 1);
	assert.equal(record.status, "FAIL");
});

test("result provenance rejects source-commit and candidate drift", () => {
	const failures = resultBindingFailures({
		gateEntry: { gate_id: "fixture-binding", command: "node scripts/fixture.mjs", artifact: null },
		resultFile: {
			gate_id: "fixture-binding",
			command: "node scripts/fixture.mjs",
			provenance_version: 1,
			commit_sha: "0".repeat(40),
			source_commit: "0".repeat(40),
			candidate_digest: "1".repeat(64),
			candidate_digest_source: CANDIDATE_DIGEST_SOURCE,
			log_sha256: "e".repeat(64),
			artifact_sha256: UNKNOWN,
			exit_code: 0,
		},
		logBytes: { sha256: "e".repeat(64) },
		artifact_sha256: UNKNOWN,
		commit_sha: "2".repeat(40),
		candidate_digest: "3".repeat(64),
	});
	assert.match(failures.join("\n"), /result source commit .*does not match current commit/);
	assert.match(failures.join("\n"), /result candidate digest .*does not match current candidate digest/);
});

test("a stale result sidecar cannot turn a PASS log into PASS evidence", () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-gate-stale-result-"));
	const logDirectory = join(root, LOG_DIR);
	mkdirSync(logDirectory, { recursive: true });
	const logPath = join(logDirectory, "fixture.log");
	const oldLog = "ALL PASS - 2/2 cases behaved correctly\n";
	const currentLog = "ALL PASS - 3/3 cases behaved correctly\n";
	writeFileSync(logPath, currentLog);
	writeFileSync(
		`${logPath}.result.json`,
		`${JSON.stringify(
			{
				gate_id: "fixture-stale",
				command: "node scripts/fixture.mjs",
				provenance_version: 1,
				commit_sha: "0".repeat(40),
				source_commit: "0".repeat(40),
				candidate_digest: "1".repeat(64),
				candidate_digest_source: CANDIDATE_DIGEST_SOURCE,
				log_sha256: sha256Hex(Buffer.from(oldLog)),
				artifact_sha256: UNKNOWN,
				exit_code: 0,
			},
			null,
			2,
		)}\n`,
	);
	const record = buildGateRecord(
		{
			gate_id: "fixture-stale",
			command: "node scripts/fixture.mjs",
			log: "fixture.log",
			artifact: null,
			counts: "cases",
			pass: /ALL PASS - (\d+)\/(\d+) cases behaved correctly/,
			fail: null,
			task_ids: ["T35"],
			feature_ids: ["EVAL-01"],
			owner: "quality-engineering",
			evidence_level: "unit_contract",
			evidence_level_ceiling: "unit_contract",
			limitations: ["fixture"],
		},
		{
			root,
			commit_sha: "0".repeat(40),
			candidate_digest: "1".repeat(64),
			environment: {
				platform: "test",
				arch: "test",
				os_type: "test",
				os_release: "test",
				hostname: "test",
				gate_host_provenance: UNKNOWN,
			},
			tool_versions: { node: "test", pnpm: "test", python: "test", docker: "test", os: "test" },
		},
	);
	assert.equal(record.status, "unknown");
	assert.equal(record.exit_code, UNKNOWN);
	assert.match(record.observed_effect, /ignored as stale or unprovable/);
	assert.ok(record.limitations.some((entry) => /ignored because it is stale or unprovable/.test(entry)));
});

test("every gate record stays bound to the index source and candidate", () => {
	const index = clone(freshIndex());
	index.gates[0].commit_sha = "0".repeat(40);
	index.gates[0].candidate_digest = "1".repeat(64);
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /commit_sha .*does not match index commit_sha/);
	assert.match(errorText(result), /candidate_digest .*does not match index candidate_digest/);
});

test("a summary that disagrees with its records fails", () => {
	const index = clone(freshIndex());
	index.status_counts.PASS += 1;
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /does not match the records/);
});

test("the generator is deterministic: running it twice produces byte-identical output", () => {
	const first = serializeIndex(buildEvidenceIndex());
	const second = serializeIndex(buildEvidenceIndex());
	assert.equal(first, second);
	assert.ok(first.endsWith("\n"));

	// Every field is stable, including the hashes and the parsed counts.
	const parsedFirst = JSON.parse(first);
	const parsedSecond = JSON.parse(second);
	assert.deepEqual(parsedFirst, parsedSecond);
});

test("the committed index validates and covers every declared gate", () => {
	// The committed file is checked for shape and completeness rather than for
	// byte-equality: the gate logs are written by other processes, so a byte
	// comparison here would report their churn as a generator defect.
	const committed = resolve(ROOT, INDEX_FILE);
	assert.equal(existsSync(committed), true, `${INDEX_FILE} is missing; run the generator first`);
	const index = JSON.parse(readFileSync(committed, "utf8"));
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, true, errorText(result));
	assert.equal(index.gates.length, GATES.length);
});

test("the --verify CLI exits non-zero for an invalid index", () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-evidence-index-"));
	const broken = join(directory, "broken-index.json");
	const index = clone(freshIndex());
	index.gates[1].status = "PASS";
	index.gates[1].exit_code = 3;
	writeFileSync(broken, serializeIndex(index));

	const result = spawnSync(
		process.execPath,
		["scripts/generate-v8-evidence-index.mjs", "--verify", "--index", broken],
		{ cwd: ROOT, encoding: "utf8" },
	);
	assert.notEqual(result.status, 0);
	assert.match(`${result.stderr}${result.stdout}`, /pass-like but exit_code is 3/);
});

test("the --verify CLI exits zero for the real index", () => {
	const result = spawnSync(process.execPath, ["scripts/generate-v8-evidence-index.mjs", "--verify"], {
		cwd: ROOT,
		encoding: "utf8",
	});
	assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
	assert.match(result.stdout, /validated against/);
});
