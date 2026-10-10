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
import { REGISTRY_FILE } from "./verify-commercial-gate-receipts.mjs";
import { DEFAULT_PROFILE, LEDGER_SCHEMA, bundleCandidate, evaluateProductionGo, evaluateRollback, main, parseArgs, readLedger } from "./verify-production-go.mjs";

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

test("rollback refuses a candidate whose ledger entry is for another digest, version or commit", () => {
	const candidate = { digest: "1".repeat(64), version: "1.2.3", gitSha: "b".repeat(40) };
	const entry = { decision: "GO", candidate_digest: candidate.digest, release_version: "1.2.3", git_sha: "b".repeat(40) };
	assert.equal(evaluateRollback({ ledger: { entries: [entry] }, candidate }).go, true);
	assert.equal(evaluateRollback({ ledger: { entries: [{ ...entry, candidate_digest: "2".repeat(64) }] }, candidate }).go, false);
	assert.equal(evaluateRollback({ ledger: { entries: [{ ...entry, release_version: "1.2.4" }] }, candidate }).go, false);
	assert.equal(evaluateRollback({ ledger: { entries: [{ ...entry, git_sha: "c".repeat(40) }] }, candidate }).go, false);
	assert.equal(evaluateRollback({ ledger: { entries: [{ ...entry, decision: "NO-GO" }] }, candidate }).go, false);
	assert.throws(() => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ledger-"));
		try {
			writeFileSync(join(dir, "ledger.json"), '{"entries":[]}');
			readLedger(join(dir, "ledger.json"));
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	}, /is not an aidr-production-go-ledger\/v1 document/u);
});
