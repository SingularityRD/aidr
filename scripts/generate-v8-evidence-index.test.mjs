#!/usr/bin/env node
// node --test suite for the v8 evidence index generator.
//
// The suite drives the generator's exported functions directly, so it fails when
// the generator starts admitting a gap: an omitted gate, an empty-string field, a
// pass-like status next to a non-zero exit code, or a claim above the evidence
// level the artefacts actually substantiate.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
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
	normalizeCapturedLog,
	ROOT,
	SCHEMA_FILE,
	serializeIndex,
	sha256Hex,
	resultBindingFailures,
	STATUS_NOT_RUN,
	STATUS_PASS,
	STATUS_UNKNOWN,
	UNKNOWN,
	verifyEvidenceIndex,
	writeResultFile,
} from "./generate-v8-evidence-index.mjs";
import { PLACEHOLDER_IDENTITIES } from "./verify-repo-hygiene.mjs";

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

test("deployment preparation bindings remain local contract evidence", () => {
	const gate = GATES.find((entry) => entry.gate_id === "14-node-contracts");
	assert.ok(gate.command.includes("scripts/deployment-prepare.test.mjs"));
	assert.ok(gate.feature_ids.includes("DEP-01"));
	assert.ok(gate.feature_ids.includes("DEP-02"));
	assert.equal(gate.evidence_level_ceiling, "unit_contract");
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

test("a missing declared log produces NOT_RUN without omitting its registry entry", (t) => {
	const baseline = freshIndex();
	const missingGate = GATES.find((gate) => gate.log !== null && !existsSync(resolve(ROOT, LOG_DIR, gate.log)));
	if (!missingGate) {
		t.skip("all declared gate logs exist in this checkout");
		return;
	}
	const context = {
		root: ROOT,
		commit_sha: baseline.commit_sha,
		candidate_digest: baseline.candidate_digest,
		environment: baseline.environment,
		tool_versions: baseline.tool_versions,
	};
	const record = buildGateRecord(missingGate, context);
	assert.equal(record.status, STATUS_NOT_RUN);
	assert.equal(record.exit_code, UNKNOWN);
	assert.equal(record.log_sha256, UNKNOWN);
	assert.equal(record.evidence_level, EVIDENCE_LEVEL_FLOOR);
	assert.ok(record.observed_effect.length > 0);
	assert.ok(record.limitations.some((entry) => /no log at/.test(entry)));

	const index = clone(baseline);
	const position = index.gates.findIndex((entry) => entry.gate_id === missingGate.gate_id);
	assert.notEqual(position, -1, "missing-log gate must already be in the complete index");
	index.gates[position] = record;
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
	const originalSidecar = readFileSync(`${target.absolute}.result.json`, "utf8");
	assert.throws(() => writeResultFile(target, { exit_code: 1 }), /EEXIST/);
	assert.equal(readFileSync(`${target.absolute}.result.json`, "utf8"), originalSidecar);
});

test("captured logs are normalized so evidence never publishes a home directory", () => {
	// Gate output prints the absolute working directory, and the hygiene gate exists
	// to keep exactly those strings out of tracked files. Its allowlist cannot cover
	// evidence logs without sanctioning the leak, so the capture normalizes instead.
	const root = "C:\\Users\\somebody\\Desktop\\aidr";
	const raw = [
		"> @ quality:static C:\\Users\\somebody\\Desktop\\aidr",
		"> @ lint C:/Users/somebody/Desktop/aidr",
		'{"cwd":"C:\\\\Users\\\\somebody\\\\Desktop\\\\aidr"}',
		"cache: C:\\Users\\somebody\\AppData\\Local\\node\\corepack",
		"posix: /home/somebody/projects/aidr and /Users/somebody/src",
		"[aidr-gate] ended_at_utc=2026-09-20T00:00:00.000Z exit_code=0",
	].join("\n");

	const normalized = normalizeCapturedLog(raw, root);

	assert.equal(normalized.includes("somebody"), false, "the personal identity survived normalization");
	assert.match(normalized, /> @ quality:static <repo>/);
	assert.match(normalized, /> @ lint <repo>/);
	assert.match(normalized, /"cwd":"<repo>"/);
	assert.match(normalized, /cache: C:\\Users\\user\\AppData/);
	assert.match(normalized, /posix: \/home\/user\/projects\/aidr and \/Users\/user\/src/);
	// The markers the index parses must survive untouched.
	assert.match(normalized, /exit_code=0$/);
	// Nothing outside those prefixes is rewritten.
	assert.equal(normalizeCapturedLog("plain output, no paths", root), "plain output, no paths");
	assert.equal(normalizeCapturedLog("", root), "");
});

test("normalized log text is recognised as anonymous by the hygiene rule", () => {
	// The placeholder the capture writes must be one the repository hygiene gate
	// already treats as anonymous, otherwise the evidence would still be flagged.
	const identities = new Set([...PLACEHOLDER_IDENTITIES].map((value) => value.toLowerCase()));
	const root = "C:\\Users\\somebody\\Desktop\\aidr";
	// A path under the root is replaced outright, so no drive path survives at all.
	assert.equal(normalizeCapturedLog(`cwd ${root}\\packages`, root), "cwd <repo>\\packages");
	// A path outside the root keeps its shape but loses the identity, and the
	// segment left behind must be one the hygiene gate recognises as a placeholder.
	const outside = normalizeCapturedLog("cache C:\\Users\\somebody\\AppData\\Local\\node", root);
	const match = /[A-Za-z]:\\{1,2}Users\\{1,2}([^\\/\s"'<>|,;)\]]+)/.exec(outside);
	assert.ok(match, "the normalized path no longer matches the drive-path pattern at all");
	assert.ok(identities.has(match[1].toLowerCase()), `placeholder ${match[1]} is not in PLACEHOLDER_IDENTITIES`);
	assert.equal(outside.includes("somebody"), false);
});

test("skipped package runs cannot be reported as PASS from exit_code 0", () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-gate-package-skip-"));
	const logDirectory = join(root, LOG_DIR);
	mkdirSync(logDirectory, { recursive: true });
	const declaredGate = GATES.find((entry) => entry.gate_id === "27-empty-path-package-install");
	assert.ok(declaredGate);
	const gateEntry = { ...declaredGate, pass: /Package install verification:/m };
	const context = {
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
	};
	for (const [suffix, expectedStatus, logText, expectedExplanation] of [
		["skipped", STATUS_UNKNOWN, "SKIPPED_WITH_REASON packages/core — 0/1 runs\nPackage install verification: 4/10 PASS, 6 SKIPPED_WITH_REASON, 0 FAIL\n", /SKIPPED_WITH_REASON/],
		["complete", STATUS_UNKNOWN, "Package install verification: 10/10 PASS, 0 SKIPPED_WITH_REASON, 0 FAIL\n", /unbound exit_code=0 log marker cannot establish candidate-bound PASS/],
	]) {
		const logPath = join(logDirectory, `27-empty-path-package-install-${suffix}.log`);
		const declaredLogPath = join(logDirectory, gateEntry.log);
		writeFileSync(declaredLogPath, logText);
		const record = buildGateRecord(gateEntry, context);
		assert.equal(record.status, expectedStatus);
		assert.equal(record.exit_code, 0);
		assert.match(record.observed_effect, expectedExplanation);
		// Keep the declared filename stable while replacing its contents for the next case.
		void logPath;
	}
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

test("a passing result requires the declared log and artifact to exist", () => {
	const gateEntry = GATES.find((entry) => entry.gate_id === "02-feature-inventory");
	assert.ok(gateEntry?.artifact);
	const failures = resultBindingFailures({
		gateEntry,
		resultFile: {
			gate_id: gateEntry.gate_id,
			command: gateEntry.command,
			provenance_version: 1,
			commit_sha: "0".repeat(40),
			source_commit: "0".repeat(40),
			candidate_digest: "1".repeat(64),
			candidate_digest_source: CANDIDATE_DIGEST_SOURCE,
			log_sha256: UNKNOWN,
			artifact_sha256: UNKNOWN,
			exit_code: 0,
		},
		logBytes: null,
		artifact_sha256: UNKNOWN,
		commit_sha: "0".repeat(40),
		candidate_digest: "1".repeat(64),
	});
	assert.match(failures.join("\n"), /passing result requires its declared log to exist/);
	assert.match(failures.join("\n"), /passing result requires its declared artifact FEATURE_INVENTORY\.json to exist/);
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

test("verification rejects a stale declared artifact digest", () => {
	const index = clone(freshIndex());
	const record = index.gates.find((gate) => /^[0-9a-f]{64}$/.test(gate.artifact_sha256));
	assert.ok(record, "fixture needs a declared artifact present on disk");
	record.artifact_sha256 = "0".repeat(64);
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), new RegExp(`${record.gate_id}.*artifact_sha256.*current declared artifact`));
});

test("a summary that disagrees with its records fails", () => {
	const index = clone(freshIndex());
	index.status_counts.PASS += 1;
	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /does not match the records/);
});

test("verification rejects a forged PASS that is not derived from current candidate-bound evidence", () => {
	const index = clone(freshIndex());
	const record = index.gates.find((gate) => gate.status !== STATUS_PASS);
	assert.ok(record, "fixture needs a gate that is not already PASS");
	const derivedStatus = record.status;
	record.status = STATUS_PASS;
	record.exit_code = 0;
	index.status_counts = countStatuses(index.gates);

	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), new RegExp(`status \\\"PASS\\\" does not match status derived from current evidence \\\"${derivedStatus}\\\"`));
	assert.match(errorText(result), /PASS requires an existing candidate inventory|PASS requires a candidate-bound result file|PASS result file is stale or unprovable/);
});

test("verification accepts a PASS only when the result sidecar binds the current candidate artifacts", (t) => {
	const root = mkdtempSync(join(tmpdir(), "aidr-evidence-candidate-bound-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const runGit = (args) => {
		const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
		assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
	};
	runGit(["init", "--quiet"]);
	writeFileSync(join(root, "source.txt"), "candidate-bound fixture\n");
	runGit(["add", "source.txt"]);
	runGit(["-c", "user.name=AIDR Test", "-c", "user.email=aidr-test@example.invalid", "commit", "--quiet", "-m", "fixture"]);

	const inventoryPath = resolve(root, CANDIDATE_DIGEST_SOURCE);
	mkdirSync(dirname(inventoryPath), { recursive: true });
	writeFileSync(inventoryPath, '{"fixture":true}\n');

	const gateEntry = GATES.find((entry) => entry.gate_id === "01-git-diff-check");
	const logPath = resolve(root, LOG_DIR, gateEntry.log);
	mkdirSync(dirname(logPath), { recursive: true });
	writeFileSync(logPath, "fixture completed\n");
	writeResultFile(
		{ gateEntry, absolute: logPath },
		{
			exit_code: 0,
			started_at_utc: "2026-09-23T00:00:00.000Z",
			ended_at_utc: "2026-09-23T00:00:01.000Z",
			duration_ms: 1000,
			captured_by: "test",
		},
		{ root },
	);

	const index = buildEvidenceIndex({ root });
	const record = index.gates.find((gate) => gate.gate_id === gateEntry.gate_id);
	assert.equal(record.status, STATUS_PASS);
	assert.equal(record.exit_code, 0);
	const result = verifyEvidenceIndex(index, schema, { root });
	assert.equal(result.ok, true, errorText(result));
});

test("verification rejects records that are not in the canonical gate registry", () => {
	const index = clone(freshIndex());
	index.gates.push({ ...clone(index.gates[0]), gate_id: "99-undeclared-gate" });
	index.gate_count = index.gates.length;
	index.status_counts = countStatuses(index.gates);

	const result = verifyEvidenceIndex(index, schema);
	assert.equal(result.ok, false);
	assert.match(errorText(result), /99-undeclared-gate.*not declared in the canonical gate registry/);
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

test("the canonical index is generated evidence, not a tracked documentation duplicate", () => {
	assert.equal(INDEX_FILE, ".release-evidence/v8-evidence-index.json");
	assert.equal(existsSync(resolve(ROOT, "docs/production-readiness/v8-evidence-index.json")), false);
});

test("release bundle gate binds the inventory written by its own assembler", () => {
	const gate = GATES.find((entry) => entry.gate_id === "20-release-bundle");
	assert.equal(gate.command, "node .github/scripts/build-release-bundle.mjs");
	assert.equal(gate.artifact, "release-output/release-inventory.json");
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

test("the CLI generates and verifies an isolated index without modifying canonical evidence", () => {
	const canonical = resolve(ROOT, INDEX_FILE);
	const canonicalBefore = existsSync(canonical) ? readFileSync(canonical) : null;
	const directory = mkdtempSync(join(tmpdir(), "aidr-evidence-index-cli-"));
	const output = join(directory, "index.json");
	try {
		const generated = spawnSync(process.execPath, ["scripts/generate-v8-evidence-index.mjs", "--out", output], { cwd: ROOT, encoding: "utf8" });
		assert.equal(generated.status, 0, `${generated.stdout}${generated.stderr}`);
		assert.equal(existsSync(output), true);
		assert.match(generated.stdout, /Wrote .*index\.json/);

		const verified = spawnSync(process.execPath, ["scripts/generate-v8-evidence-index.mjs", "--verify", "--index", output], { cwd: ROOT, encoding: "utf8" });
		assert.equal(verified.status, 0, `${verified.stdout}${verified.stderr}`);
		assert.match(verified.stdout, /fresh gate record\(s\) validated against current evidence/);

		const staleIndex = JSON.parse(readFileSync(output, "utf8"));
		const staleRecord = staleIndex.gates.find((gate) => /^[0-9a-f]{64}$/.test(gate.artifact_sha256));
		assert.ok(staleRecord);
		staleRecord.artifact_sha256 = "0".repeat(64);
		writeFileSync(output, `${JSON.stringify(staleIndex, null, 2)}\n`);
		const staleVerification = spawnSync(process.execPath, ["scripts/generate-v8-evidence-index.mjs", "--verify", "--index", output], { cwd: ROOT, encoding: "utf8" });
		assert.notEqual(staleVerification.status, 0);
		assert.match(`${staleVerification.stdout}${staleVerification.stderr}`, /artifact_sha256.*current declared artifact/);

		const collision = spawnSync(process.execPath, ["scripts/generate-v8-evidence-index.mjs", "--out", output], { cwd: ROOT, encoding: "utf8" });
		assert.notEqual(collision.status, 0);
		assert.match(collision.stderr, /EEXIST/);
		if (canonicalBefore !== null) assert.deepEqual(readFileSync(canonical), canonicalBefore);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});
