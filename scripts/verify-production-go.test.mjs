/**
 * Tests for the candidate-bound production GO gate (scripts/verify-production-go.mjs).
 *
 *   node --test scripts/verify-production-go.test.mjs
 *
 * Closure test of audit item 14: NO-GO, an empty candidate, a wrong digest and
 * stale evidence each stop publication; only a GO record for the same
 * candidate opens it. The positive fixture is synthetic and lives in a temp
 * directory: no test writes the real registry or receipts.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { CANDIDATE_DIGEST_SOURCE } from "./generate-v8-evidence-index.mjs";
import { REGISTRY_FILE } from "./verify-commercial-gate-receipts.mjs";
import {
	DEFAULT_PROFILE,
	LEDGER_GENESIS,
	LEDGER_SCHEMA,
	appendLedger,
	bundleCandidate,
	evaluateProductionGo,
	evaluateRollback,
	ledgerEntryDigest,
	main,
	parseArgs,
	readLedger,
	verifyLedgerChain,
} from "./verify-production-go.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts/verify-production-go.mjs");
const NOW = new Date("2026-10-10T12:00:00.000Z");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const readRepoJson = (path) => JSON.parse(readFileSync(join(ROOT, path), "utf8"));

const realRegistry = readRepoJson(REGISTRY_FILE);
const receiptsPath = realRegistry.hardGateReceipts.receiptsPath;
const schemaPath = realRegistry.hardGateReceipts.schemaPath;
const realReceipts = readRepoJson(receiptsPath);
const schema = readRepoJson(schemaPath);

function makeBundle(dir, inventory = { schema_version: 1, artifacts: [{ name: "fixture.tgz" }] }) {
	mkdirSync(dir, { recursive: true });
	writeFileSync(join(dir, "release-inventory.json"), `${JSON.stringify(inventory)}\n`);
	writeFileSync(join(dir, "release-metadata.json"), `${JSON.stringify({ release_tag: "v9.9.9-rc.0", release_version: "9.9.9", git_sha: "a".repeat(40) })}\n`);
	return bundleCandidate(dir);
}

/**
 * A complete synthetic GO: every production-ga hard gate closed, receipts bound
 * to the bundle digest with in-root evidence, a current SEC-EXT-001 assessment
 * and a stubbed passing claim gate. Values are obviously fixture strings.
 */
function goFixture(t) {
	const root = mkdtempSync(join(tmpdir(), "aidr-production-go-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const candidate = makeBundle(join(root, "release-output"));
	const digest = candidate.digest;
	const evidence = "synthetic fixture evidence, not an approval\n";
	writeFileSync(join(root, "evidence.txt"), evidence);
	const report = "synthetic fixture report";
	const retest = "synthetic fixture retest";
	writeFileSync(join(root, "report.pdf"), report);
	writeFileSync(join(root, "retest.pdf"), retest);
	const assessment = JSON.stringify({
		schema_version: 1,
		candidate_digest: digest,
		assessor_name: "fixture-assessor",
		scope: ["tenant", "identity", "runtime", "distribution", "secrets"],
		started_at_utc: "2026-09-28T00:00:00.000Z",
		completed_at_utc: "2026-09-30T00:00:00.000Z",
		retest_at_utc: "2026-10-01T00:00:00.000Z",
		valid_until_utc: "2026-12-31T00:00:00.000Z",
		unresolved_critical: 0,
		unresolved_high: 0,
		signed_report: { path: "report.pdf", sha256: hash(report) },
		retest_letter: { path: "retest.pdf", sha256: hash(retest) },
	});
	writeFileSync(join(root, "assessment.json"), assessment);

	const registry = structuredClone(realRegistry);
	registry.decision = "GO";
	registry.releaseCandidate = digest;
	registry.lastReviewed = "2026-10-09";
	const profileGates = new Set(registry.hardGates.filter((gate) => gate.decisionProfiles.includes(DEFAULT_PROFILE)).map((gate) => gate.id));
	for (const gate of registry.hardGates) if (profileGates.has(gate.id)) gate.status = "closed";
	const receipts = structuredClone(realReceipts).map((receipt) => {
		if (!profileGates.has(receipt.gate_id)) return receipt;
		const assessed = receipt.gate_id === "SEC-EXT-001";
		return {
			...receipt,
			decision: "closed",
			owner_name: "fixture-owner",
			evidence_path: assessed ? "assessment.json" : "evidence.txt",
			evidence_sha256: hash(assessed ? assessment : evidence),
			candidate_digest: digest,
			effective_version: "9.9.9",
			recorded_at_utc: "2026-10-05T00:00:00.000Z",
			reviewer_name: "fixture-reviewer",
			reviewer_role: "Independent Reviewer",
		};
	});
	const claimReport = { result: "PASS", decision: "GO", candidate_digest: digest, registrySha256: "r".repeat(64), openHardGates: [] };
	const input = {
		registry,
		registrySha256: "r".repeat(64),
		receipts,
		schema,
		root,
		receiptsPath,
		schemaPath,
		bundleInventoryPath: candidate.inventoryPath,
		candidateDigest: digest,
		now: NOW,
		claimCheck: () => ({ exitCode: 0, report: claimReport }),
	};
	return { root, candidate, digest, input, claimReport };
}

const failuresOf = (input) => evaluateProductionGo(input).failures;
const expectNoGo = (input, pattern) => {
	const result = evaluateProductionGo(input);
	assert.equal(result.go, false, "the gate must refuse");
	assert.ok(result.failures.some((failure) => pattern.test(failure)), `expected ${pattern} in:\n${result.failures.join("\n")}`);
};

test("a fully closed, fresh GO record for the same candidate opens publication", (t) => {
	const { input } = goFixture(t);
	assert.deepEqual(failuresOf(input), []);
	assert.equal(evaluateProductionGo({ ...input, expectedCandidateDigest: input.candidateDigest }).go, true);
});

test("NO-GO (or any non-GO decision) stops publication", (t) => {
	for (const decision of ["NO-GO", "go", undefined, "CONDITIONAL-GO"]) {
		const { input } = goFixture(t);
		input.registry.decision = decision;
		expectNoGo(input, /registry decision is .*not "GO"/u);
	}
});

test("an empty release candidate stops publication", (t) => {
	for (const empty of [null, "", undefined]) {
		const { input } = goFixture(t);
		input.registry.releaseCandidate = empty;
		expectNoGo(input, /releaseCandidate is empty/u);
	}
	const { input } = goFixture(t);
	input.registry.releaseCandidate = "v9.9.9-rc.0";
	expectNoGo(input, /releaseCandidate must be the SHA-256/u);
});

test("a wrong digest stops publication: registry, --candidate-digest, receipts and claim scan", (t) => {
	const other = "e".repeat(64);
	{
		const { input } = goFixture(t);
		input.registry.releaseCandidate = other;
		expectNoGo(input, /is a different candidate than this bundle/u);
	}
	{
		const { input } = goFixture(t);
		expectNoGo({ ...input, expectedCandidateDigest: other }, /--candidate-digest .* is not the bundle's release-inventory digest/u);
	}
	{
		const { input } = goFixture(t);
		input.receipts.find((receipt) => receipt.gate_id === "COM-001").candidate_digest = other;
		expectNoGo(input, /COM-001: receipt is bound to candidate/u);
	}
	{
		// The same GO record shown a different (rebuilt) bundle.
		const { input, root } = goFixture(t);
		const rebuilt = makeBundle(join(root, "rebuilt"), { schema_version: 1, artifacts: [{ name: "rebuilt.tgz" }] });
		expectNoGo({ ...input, bundleInventoryPath: rebuilt.inventoryPath, candidateDigest: rebuilt.digest }, /different candidate than this bundle/u);
	}
	{
		const { input, claimReport } = goFixture(t);
		input.claimCheck = () => ({ exitCode: 0, report: { ...claimReport, candidate_digest: other } });
		expectNoGo(input, /claim-check scanned candidate/u);
	}
});

test("stale or future-dated evidence stops publication", (t) => {
	{
		const { input } = goFixture(t);
		input.receipts.find((receipt) => receipt.gate_id === "COM-002").recorded_at_utc = "2026-01-01T00:00:00.000Z";
		expectNoGo(input, /COM-002: receipt recorded_at_utc .* older than 90 day/u);
		assert.equal(evaluateProductionGo({ ...input, maxEvidenceAgeDays: 365 }).go, true, "the freshness window is the only reason for that refusal");
	}
	{
		const { input } = goFixture(t);
		input.receipts.find((receipt) => receipt.gate_id === "COM-003").recorded_at_utc = "2026-11-01T00:00:00.000Z";
		expectNoGo(input, /COM-003: receipt recorded_at_utc .* is in the future/u);
	}
	{
		const { input } = goFixture(t);
		input.registry.lastReviewed = "2026-05-01";
		expectNoGo(input, /registry lastReviewed .* older than/u);
	}
	{
		// An expired independent assessment is caught by the receipt verifier.
		const { input } = goFixture(t);
		expectNoGo({ ...input, now: new Date("2027-01-15T00:00:00.000Z"), maxEvidenceAgeDays: 3650 }, /SEC-EXT-001: assessment\/retest chronology is invalid or evidence has expired/u);
	}
});

test("an open profile gate, a failing claim gate or an unknown profile stops publication", (t) => {
	{
		const { input } = goFixture(t);
		input.registry.hardGates.find((gate) => gate.id === "COM-013").status = "in-review";
		expectNoGo(input, /COM-013: hard gate is in-review/u);
	}
	{
		const { input } = goFixture(t);
		input.claimCheck = () => ({ exitCode: 1, report: { result: "FAIL", openHardGates: [{ id: "INV-001" }] } });
		expectNoGo(input, /claim-check --mode=gate did not pass \(exit 1; open hard gates: INV-001\)/u);
	}
	{
		const { input } = goFixture(t);
		input.claimCheck = () => ({ exitCode: null, report: null, error: "spawn failed" });
		expectNoGo(input, /claim-check --mode=gate did not pass .*spawn failed/u);
	}
	{
		const { input } = goFixture(t);
		expectNoGo({ ...input, profile: "production" }, /no hard gate names decision profile "production"/u);
	}
});

test("the current repository state (NO-GO, releaseCandidate null) exits non-zero from the CLI", (t) => {
	assert.equal(realRegistry.decision, "NO-GO", "this test documents the shipped decision; it must stay NO-GO here");
	assert.equal(realRegistry.releaseCandidate, null);
	const dir = mkdtempSync(join(tmpdir(), "aidr-production-go-cli-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	const candidate = makeBundle(join(dir, "release-output"));
	const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
	const json = run("--bundle", join(dir, "release-output"), "--json");
	assert.equal(json.status, 1, json.stderr);
	const result = JSON.parse(json.stdout);
	assert.equal(result.go, false);
	assert.equal(result.candidate_digest, candidate.digest);
	assert.ok(result.failures.includes('registry decision is "NO-GO", not "GO"'));
	assert.ok(result.failures.includes("registry releaseCandidate is empty: no candidate has been approved"));
	assert.ok(result.failures.some((failure) => /claim-check --mode=gate did not pass/u.test(failure)), "the real claim gate must run and fail");
	assert.equal(run("--bundle", join(dir, "release-output"), "--candidate-digest", candidate.digest).status, 1);
	assert.equal(run("--bundle", join(dir, "missing")).status, 1, "a bundle without an inventory is NO-GO");
	assert.equal(run().status, 2, "--bundle is mandatory");
	assert.equal(run("--bundle", dir, "--candidate-digest", "not-a-digest").status, 2);
});

test("parseArgs enforces a well-formed invocation", () => {
	assert.equal(parseArgs(["--bundle", "b"]).profile, DEFAULT_PROFILE);
	assert.equal(parseArgs(["--bundle=b", "--max-evidence-age-days=30"]).maxEvidenceAgeDays, 30);
	assert.throws(() => parseArgs(["--bundle", "b", "--record"]), /--record needs --ledger/u);
	assert.throws(() => parseArgs(["--bundle", "b", "--rollback"]), /--rollback needs --ledger/u);
	assert.throws(() => parseArgs(["--bundle", "b", "--max-evidence-age-days", "0"]), /positive integer/u);
	assert.throws(() => parseArgs(["--bundle", "b", "--force"]), /Unknown argument: --force/u);
});

// ─── promotion ledger and rollback ───────────────────────────────────────

function writeTrustedRoot(root, input) {
	for (const [path, value] of [
		[REGISTRY_FILE, input.registry],
		[receiptsPath, input.receipts],
		[schemaPath, input.schema],
	]) {
		mkdirSync(dirname(join(root, path)), { recursive: true });
		writeFileSync(join(root, path), `${JSON.stringify(value, null, 2)}\n`);
	}
	return hash(readFileSync(join(root, REGISTRY_FILE)));
}

test("a GO promotion is recorded in the ledger, and rollback accepts only a recorded candidate", (t) => {
	const { root, input, candidate, claimReport } = goFixture(t);
	const registrySha256 = writeTrustedRoot(root, input);
	const ledger = join(root, "state", "production-go-ledger.json");
	mkdirSync(dirname(ledger), { recursive: true });
	const quiet = { log: () => {}, error: () => {} };
	const claimCheck = () => ({ exitCode: 0, report: { ...claimReport, registrySha256 } });
	const bundle = join(root, "release-output");
	assert.equal(main(["--bundle", bundle, "--root", root, "--ledger", ledger, "--record"], { now: NOW, claimCheck, ...quiet }), 0);
	const recorded = readLedger(ledger);
	assert.equal(recorded.schema, LEDGER_SCHEMA);
	assert.equal(recorded.entries.length, 1);
	assert.equal(recorded.entries[0].candidate_digest, candidate.digest);
	assert.equal(recorded.entries[0].registry_sha256, registrySha256);
	assert.equal(recorded.entries[0].release_version, "9.9.9");

	// Rollback to that candidate does not need the registry to still be GO.
	input.registry.decision = "NO-GO";
	writeTrustedRoot(root, input);
	assert.equal(main(["--rollback", "--bundle", bundle, "--ledger", ledger, "--expected-version", "9.9.9", "--expected-sha", "a".repeat(40)], { now: NOW, ...quiet }), 0);
	assert.equal(main(["--rollback", "--bundle", bundle, "--ledger", ledger, "--expected-version", "9.9.8"], { now: NOW, ...quiet }), 1);
	const unrecorded = join(root, "never-promoted");
	makeBundle(unrecorded, { schema_version: 1, artifacts: [{ name: "never.tgz" }] });
	assert.equal(main(["--rollback", "--bundle", unrecorded, "--ledger", ledger], { now: NOW, ...quiet }), 1);
	assert.equal(main(["--rollback", "--bundle", bundle, "--ledger", join(root, "state", "absent.json")], { now: NOW, ...quiet }), 1, "no ledger, no rollback");

	// A NO-GO promotion is refused and records nothing.
	assert.equal(main(["--bundle", bundle, "--root", root, "--ledger", ledger, "--record"], { now: NOW, claimCheck, ...quiet }), 1);
	assert.equal(readLedger(ledger).entries.length, 1);
});

/** A verified ledger built through appendLedger, one GO record per row. */
function chainedLedger(t, rows) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-ledger-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	const path = join(dir, "production-go-ledger.json");
	for (const row of rows) appendLedger(path, row);
	return { path, ledger: readLedger(path) };
}

function goRecord(overrides = {}) {
	return {
		decision: "GO",
		profile: DEFAULT_PROFILE,
		candidate_digest: "1".repeat(64),
		candidate_digest_source: CANDIDATE_DIGEST_SOURCE,
		release_version: "1.2.3",
		release_tag: "v1.2.3-rc.0",
		git_sha: "b".repeat(40),
		registry_sha256: "3".repeat(64),
		receipts_sha256: "4".repeat(64),
		trusted_verifier_commit: "c".repeat(40),
		verified_at_utc: "2026-10-01T00:00:00.000Z",
		...overrides,
	};
}

test("rollback refuses a candidate whose ledger entry is for another digest, version, tag or commit", (t) => {
	const candidate = { digest: "1".repeat(64), version: "1.2.3", gitSha: "b".repeat(40), tag: "v1.2.3-rc.0" };
	const ledgerWith = (overrides) => chainedLedger(t, [goRecord(overrides)]).ledger;
	assert.equal(evaluateRollback({ ledger: ledgerWith({}), candidate }).go, true);
	assert.equal(evaluateRollback({ ledger: ledgerWith({ candidate_digest: "2".repeat(64) }), candidate }).go, false);
	assert.equal(evaluateRollback({ ledger: ledgerWith({ release_version: "1.2.4", release_tag: "v1.2.4-rc.0" }), candidate }).go, false);
	assert.equal(evaluateRollback({ ledger: ledgerWith({ git_sha: "c".repeat(40) }), candidate }).go, false);
	assert.equal(evaluateRollback({ ledger: ledgerWith({}), candidate: { ...candidate, tag: "v1.2.3-rc.1" } }).go, false);
	assert.throws(() => ledgerWith({ decision: "NO-GO" }), /records decision "NO-GO"/u, "a NO-GO record cannot even be written");
	// An unchained in-memory ledger (the v1 shape) is never trusted.
	const loose = { decision: "GO", candidate_digest: candidate.digest, release_version: "1.2.3", git_sha: "b".repeat(40) };
	const unchained = evaluateRollback({ ledger: { schema: LEDGER_SCHEMA, entries: [loose], head_sha256: LEDGER_GENESIS }, candidate });
	assert.equal(unchained.go, false);
	assert.ok(unchained.failures.some((failure) => /promotion ledger does not verify/u.test(failure)));
	const dir = mkdtempSync(join(tmpdir(), "aidr-ledger-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	for (const document of ['{"entries":[]}', JSON.stringify({ schema: "aidr-production-go-ledger/v1", entries: [loose] })]) {
		writeFileSync(join(dir, "ledger.json"), document);
		assert.throws(() => readLedger(join(dir, "ledger.json")), /does not verify; refusing to use it: ledger is not an aidr-production-go-ledger\/v2 document/u);
	}
});

// ─── ledger hash chain: tampering is refused on read, record and rollback ──

const REHASH = Symbol("recompute this entry's own digest after the edit");

/** Apply `edit` to a copy of a good three-entry ledger and write it back. */
function tamperedLedger(t, edit) {
	const { path, ledger } = chainedLedger(t, [
		goRecord({ candidate_digest: "5".repeat(64), release_version: "1.0.0", release_tag: "v1.0.0-rc.0", verified_at_utc: "2026-08-01T00:00:00.000Z" }),
		goRecord({ verified_at_utc: "2026-09-01T00:00:00.000Z" }),
		goRecord({ candidate_digest: "6".repeat(64), release_version: "1.3.0", release_tag: "v1.3.0-rc.0", verified_at_utc: "2026-10-01T00:00:00.000Z" }),
	]);
	assert.deepEqual(verifyLedgerChain(ledger), []);
	const copy = structuredClone(ledger);
	const rehash = edit(copy);
	if (rehash === REHASH) for (const entry of copy.entries) entry.entry_sha256 = ledgerEntryDigest(entry);
	writeFileSync(path, `${JSON.stringify(copy, null, 2)}\n`);
	return { path, ledger: copy };
}

const TAMPERING = [
	["an entry field is edited", (ledger) => { ledger.entries[1].git_sha = "d".repeat(40); }, /entry 1 entry_sha256 does not match/u],
	["an entry is edited and its own digest recomputed", (ledger) => { ledger.entries[1].git_sha = "d".repeat(40); return REHASH; }, /entry 2 does not chain to entry 1/u],
	["a forged entry is inserted", (ledger) => { ledger.entries.splice(1, 0, structuredClone(ledger.entries[1])); }, /entry 1 does not chain|entry 1 has sequence|entry 2 has sequence/u],
	["an entry is removed", (ledger) => { ledger.entries.splice(1, 1); }, /entry 1 has sequence|entry 1 does not chain/u],
	["entries are reordered", (ledger) => { ledger.entries.reverse(); }, /entry 0 has sequence/u],
	["the last entry is truncated without fixing the head", (ledger) => { ledger.entries.pop(); }, /head_sha256 is not the digest of its last entry/u],
	["an entry gains an unknown field", (ledger) => { ledger.entries[0].approved_by = "attacker"; return REHASH; }, /entry 0 must have exactly the fields/u],
	["an entry loses its receipt binding", (ledger) => { delete ledger.entries[0].receipts_sha256; return REHASH; }, /entry 0 must have exactly the fields/u],
	["an entry records a malformed digest", (ledger) => { ledger.entries[2].registry_sha256 = "not-a-digest"; return REHASH; }, /entry 2 has an invalid registry_sha256/u],
	["an entry's tag does not match its version", (ledger) => { ledger.entries[0].release_tag = "v9.9.9-rc.0"; return REHASH; }, /release_tag .* does not match its version/u],
	["an entry is back-dated", (ledger) => { ledger.entries[2].verified_at_utc = "2026-07-01T00:00:00.000Z"; return REHASH; }, /entry 2 is dated before entry 1/u],
	["a non-GO decision is slipped in", (ledger) => { ledger.entries[1].decision = "NO-GO"; return REHASH; }, /entry 1 records decision "NO-GO"/u],
	["the ledger gains a top-level field", (ledger) => { ledger.trusted = true; }, /ledger must have exactly the fields/u],
];

for (const [label, edit, pattern] of TAMPERING) {
	test(`a ledger whose chain does not verify is refused: ${label}`, (t) => {
		const { path, ledger } = tamperedLedger(t, edit);
		assert.ok(verifyLedgerChain(ledger).some((problem) => pattern.test(problem)), `expected ${pattern} in:\n${verifyLedgerChain(ledger).join("\n")}`);
		assert.throws(() => readLedger(path), /does not verify; refusing to use it/u);
		assert.throws(() => appendLedger(path, goRecord({ verified_at_utc: "2026-10-05T00:00:00.000Z" })), /does not verify/u, "--record must not append to a tampered ledger");
		const candidate = { digest: "1".repeat(64), version: "1.2.3", gitSha: "b".repeat(40), tag: "v1.2.3-rc.0" };
		const rollback = evaluateRollback({ ledger, candidate });
		assert.equal(rollback.go, false, "--rollback must not trust a tampered ledger");
		assert.equal(rollback.entry, null);
	});
}

test("the CLI refuses rollback and record against a tampered ledger", (t) => {
	const { root, input, claimReport } = goFixture(t);
	const registrySha256 = writeTrustedRoot(root, input);
	const ledger = join(root, "state", "production-go-ledger.json");
	mkdirSync(dirname(ledger), { recursive: true });
	const quiet = { log: () => {}, error: () => {} };
	const claimCheck = () => ({ exitCode: 0, report: { ...claimReport, registrySha256 } });
	const bundle = join(root, "release-output");
	assert.equal(main(["--bundle", bundle, "--root", root, "--ledger", ledger, "--record"], { now: NOW, claimCheck, ...quiet }), 0);
	const recorded = readLedger(ledger);
	assert.equal(recorded.entries[0].receipts_sha256, hash(readFileSync(join(root, receiptsPath))), "the entry is bound to the receipt bytes the gate read");
	assert.equal(recorded.head_sha256, recorded.entries[0].entry_sha256);
	assert.equal(recorded.entries[0].previous_entry_sha256, LEDGER_GENESIS);

	// Forge a second GO entry for a never-promoted candidate without the chain.
	const forged = structuredClone(recorded);
	forged.entries.push({ ...structuredClone(recorded.entries[0]), sequence: 1, candidate_digest: "f".repeat(64) });
	writeFileSync(ledger, JSON.stringify(forged));
	const errors = [];
	assert.equal(main(["--rollback", "--bundle", bundle, "--ledger", ledger], { now: NOW, log: () => {}, error: (line) => errors.push(line) }), 1, "a genuine entry in a tampered ledger is not enough");
	assert.ok(errors.some((line) => /does not verify/u.test(line)));
	assert.equal(main(["--bundle", bundle, "--root", root, "--ledger", ledger, "--record"], { now: NOW, claimCheck, ...quiet }), 1, "--record refuses to extend a tampered ledger");
	assert.deepEqual(JSON.parse(readFileSync(ledger, "utf8")), forged, "a refused record leaves the ledger untouched");
});
