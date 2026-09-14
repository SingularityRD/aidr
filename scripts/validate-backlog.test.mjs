import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
	DEFAULT_STATUS_VOCABULARY,
	PREVIOUSLY_OPEN_FINDINGS,
	resolveCommand,
	validateBacklog,
} from "./validate-backlog.mjs";

const repoRoot = path.resolve(import.meta.dirname, "..");

function finding(overrides = {}) {
	return {
		id: "AIDR-900",
		feature: "fixture feature",
		priority: "P2",
		status: "IN_PROGRESS",
		evidence: ["fixture"],
		acceptanceCriteria: "fixture criterion",
		remainingExternal: "fixture external input",
		...overrides,
	};
}

function record(findings, extra = {}) {
	return { statusVocabulary: [...DEFAULT_STATUS_VOCABULARY], findings, ...extra };
}

/**
 * A fixture record that also carries every previously-open finding, so a test
 * asserting an exact error set does not accidentally assert the
 * TRACKED_FINDING_MISSING failures instead.
 */
function scenario(findings, extra = {}) {
	const present = new Set(findings.map((item) => item.id));
	const tracked = PREVIOUSLY_OPEN_FINDINGS.filter((id) => !present.has(id)).map((id) =>
		finding({ id, status: "BLOCKED_EXTERNAL", localEvidence: [] }),
	);
	return record([...findings, ...tracked], extra);
}

const validEntry = {
	claim: "fixture claim",
	evidencePath: "package.json",
	command: "node scripts/validate-backlog.mjs",
	verifiedBy: "fixture",
};

function codes(result) {
	return result.errors.map((error) => error.code);
}

test("the shipped backlog satisfies every invariant", () => {
	const backlog = JSON.parse(readFileSync(path.join(repoRoot, "READINESS_BACKLOG.json"), "utf8"));
	const result = validateBacklog(backlog);
	assert.deepEqual(result.errors, []);
	assert.equal(result.ok, true);
});

test("every previously-open finding is still present with its honesty fields", () => {
	const backlog = JSON.parse(readFileSync(path.join(repoRoot, "READINESS_BACKLOG.json"), "utf8"));
	for (const id of PREVIOUSLY_OPEN_FINDINGS) {
		const found = backlog.findings.find((item) => item.id === id);
		assert.ok(found, `${id} disappeared from the backlog`);
		assert.ok(Array.isArray(found.localEvidence), `${id} has no localEvidence array`);
		if (found.status !== "VERIFIED_CLOSED") {
			assert.equal(typeof found.remainingExternal, "string", `${id} has no remainingExternal`);
			assert.notEqual(found.remainingExternal.trim(), "");
		}
	}
});

test("a valid record passes", () => {
	const result = validateBacklog(
		scenario([
			finding({ id: "AIDR-901", status: "VERIFIED_CLOSED", localEvidence: [validEntry] }),
			finding({ id: "AIDR-902" }),
		]),
	);
	assert.deepEqual(result.errors, []);
});

test("a localEvidence entry pointing at a non-existent file fails", () => {
	const result = validateBacklog(
		scenario([
			finding({
				status: "VERIFIED_CLOSED",
				localEvidence: [{ ...validEntry, evidencePath: "docs/production-readiness/ghost-evidence.json" }],
			}),
		]),
	);
	assert.deepEqual(codes(result), ["EVIDENCE_PATH_MISSING", "CLOSED_WITHOUT_EVIDENCE"]);
	assert.equal(result.ok, false);
});

test("a localEvidence entry naming an unknown command fails", () => {
	const unknownScript = validateBacklog(
		scenario([
			finding({
				status: "VERIFIED_CLOSED",
				localEvidence: [{ ...validEntry, command: "pnpm definitely-not-a-script" }],
			}),
		]),
	);
	assert.deepEqual(codes(unknownScript), ["COMMAND_UNRESOLVED", "CLOSED_WITHOUT_EVIDENCE"]);

	const unknownFile = validateBacklog(
		scenario([
			finding({
				status: "VERIFIED_CLOSED",
				localEvidence: [{ ...validEntry, command: "node scripts/ghost-gate.mjs" }],
			}),
		]),
	);
	assert.deepEqual(codes(unknownFile), ["COMMAND_UNRESOLVED", "CLOSED_WITHOUT_EVIDENCE"]);
});

test("a localEvidence entry with an unsupported command form fails", () => {
	const result = validateBacklog(
		scenario([
			finding({
				status: "VERIFIED_CLOSED",
				localEvidence: [{ ...validEntry, command: "git ls-files" }],
			}),
		]),
	);
	assert.deepEqual(codes(result), ["COMMAND_UNRESOLVED", "CLOSED_WITHOUT_EVIDENCE"]);
});

test("a localEvidence entry missing a field fails", () => {
	const result = validateBacklog(
		scenario([
			finding({
				status: "VERIFIED_CLOSED",
				localEvidence: [{ claim: "incomplete" }],
			}),
		]),
	);
	assert.deepEqual(codes(result), [
		"EVIDENCE_ENTRY_INVALID",
		"EVIDENCE_ENTRY_INVALID",
		"EVIDENCE_ENTRY_INVALID",
		"CLOSED_WITHOUT_EVIDENCE",
	]);
});

test("VERIFIED_CLOSED without localEvidence fails", () => {
	const undeclared = validateBacklog(
		scenario([finding({ status: "VERIFIED_CLOSED", localEvidence: [] })]),
	);
	assert.deepEqual(codes(undeclared), ["CLOSED_WITHOUT_EVIDENCE"]);

	const strict = validateBacklog(
		scenario([
			finding({ id: "AIDR-903", status: "VERIFIED_CLOSED" }),
			finding({ id: "AIDR-904", status: "VERIFIED_CLOSED", localEvidence: [validEntry] }),
		]),
		{ strictClosedEvidence: true },
	);
	assert.deepEqual(codes(strict), ["CLOSED_WITHOUT_EVIDENCE"]);
});

test("declared closed-without-evidence debt exempts a legacy closure, and strict mode ignores it", () => {
	const backlog = scenario([finding({ id: "AIDR-905", status: "VERIFIED_CLOSED" })], {
		closedWithoutLocalEvidence: {
			note: "legacy closure recorded before the field existed",
			findings: ["AIDR-905"],
		},
	});
	assert.deepEqual(validateBacklog(backlog).errors, []);
	assert.deepEqual(codes(validateBacklog(backlog, { strictClosedEvidence: true })), [
		"CLOSED_WITHOUT_EVIDENCE",
	]);
});

test("stale closed-without-evidence debt fails", () => {
	const result = validateBacklog(
		scenario([finding({ id: "AIDR-906", status: "VERIFIED_CLOSED", localEvidence: [validEntry] })], {
			closedWithoutLocalEvidence: { note: "stale", findings: ["AIDR-906"] },
		}),
	);
	assert.deepEqual(codes(result), ["CLOSED_DEBT_STALE"]);
});

test("a finding that is not VERIFIED_CLOSED must carry a residual", () => {
	for (const status of [
		"DISCOVERED",
		"CONFIRMED",
		"IN_PROGRESS",
		"IMPLEMENTED_UNVERIFIED",
		"BLOCKED_EXTERNAL",
		"REOPENED",
	]) {
		const result = validateBacklog(scenario([finding({ status, remainingExternal: "" })]));
		assert.deepEqual(codes(result), ["REMAINING_EXTERNAL_MISSING"], status);
	}
	const missing = validateBacklog(
		scenario([finding({ status: "IN_PROGRESS", remainingExternal: undefined })]),
	);
	assert.deepEqual(codes(missing), ["REMAINING_EXTERNAL_MISSING"]);
});

test("an unknown status fails", () => {
	const result = validateBacklog(scenario([finding({ status: "PROBABLY_FINE" })]));
	assert.deepEqual(codes(result), ["STATUS_UNKNOWN"]);
});

test("a duplicate id fails", () => {
	const result = validateBacklog(scenario([finding({ id: "AIDR-907" }), finding({ id: "AIDR-907" })]));
	assert.deepEqual(codes(result), ["DUPLICATE_ID"]);
});

test("a previously-open finding that disappears fails", () => {
	const result = validateBacklog(record([finding({ id: "AIDR-908" })]));
	const missing = result.errors.filter((error) => error.code === "TRACKED_FINDING_MISSING");
	assert.equal(missing.length, PREVIOUSLY_OPEN_FINDINGS.length);
});

test("a previously-open finding without the localEvidence field fails", () => {
	const result = validateBacklog(record([finding({ id: "AIDR-012" })]));
	assert.ok(codes(result).includes("TRACKED_FINDING_FIELD_MISSING"));
});

test("resolveCommand accepts pnpm scripts and node script files, and rejects everything else", () => {
	assert.equal(resolveCommand(repoRoot, "pnpm test").ok, true);
	assert.equal(
		resolveCommand(repoRoot, "pnpm test -- packages/core/src/__tests__/format.test.ts").ok,
		true,
	);
	assert.equal(resolveCommand(repoRoot, "pnpm run test").ok, true);
	assert.equal(resolveCommand(repoRoot, "node scripts/validate-backlog.mjs").ok, true);
	assert.equal(
		resolveCommand(
			repoRoot,
			"node --test scripts/deployment-restore-drill.test.mjs scripts/deployment-backup-offsite.test.mjs",
		).ok,
		true,
	);
	assert.equal(
		resolveCommand(
			repoRoot,
			"node scripts/verify-deployment-recovery.mjs --source <source> --recovered <recovered>",
		).ok,
		true,
	);
	assert.equal(resolveCommand(repoRoot, "pnpm no-such-script").ok, false);
	assert.equal(resolveCommand(repoRoot, "node scripts/no-such-file.mjs").ok, false);
	assert.equal(resolveCommand(repoRoot, "git ls-files").ok, false);
	assert.equal(resolveCommand(repoRoot, "").ok, false);
});
