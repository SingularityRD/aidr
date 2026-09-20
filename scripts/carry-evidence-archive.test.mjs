#!/usr/bin/env node
/**
 * Regressions for the evidence-archive carry step.
 *
 * The behaviour that matters: the archive is derived from the index and then
 * re-read to prove it still hashes to what the index recorded. A log that is
 * absent must be reported as NOT_CARRIED rather than invented or silently
 * skipped, and a file whose digest does not match must fail the command - an
 * archive that quietly disagrees with the index it accompanies is worse than no
 * archive, because it looks verifiable.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { carryArchive, carryPlan, renderSummary, renderVerdicts } from "./carry-evidence-archive.mjs";

let workDir;

before(() => {
	workDir = mkdtempSync(join(tmpdir(), "aidr-carry-archive-"));
});

after(() => {
	rmSync(workDir, { recursive: true, force: true });
});

const digest = (text) => createHash("sha256").update(Buffer.from(text)).digest("hex");

/** A synthetic rehearsal: two gates, one with a snapshot and one missing its log. */
function fixture() {
	const logsDir = join(workDir, "logs");
	const archiveDir = join(workDir, "archive");
	rmSync(logsDir, { recursive: true, force: true });
	rmSync(archiveDir, { recursive: true, force: true });
	mkdirSync(logsDir, { recursive: true });

	const firstLog = "[aidr-gate] ended_at_utc=2026-09-20T00:00:00.000Z exit_code=0\n";
	const snapshot = '{"numTotalTests":3}\n';
	writeFileSync(join(logsDir, "01-alpha.log"), firstLog);
	writeFileSync(join(logsDir, "01-alpha.log.result.json"), '{"gate_id":"01-alpha"}\n');
	writeFileSync(join(logsDir, "01-alpha.test-results.json"), snapshot);
	// 02-beta declares a log that was never captured.

	const index = {
		commit_sha: "a".repeat(40),
		candidate_digest: "b".repeat(64),
		gates: [
			{ gate_id: "01-alpha", status: "PASS", exit_code: 0, log_sha256: digest(firstLog), artifact_sha256: digest(snapshot) },
			{ gate_id: "02-beta", status: "NOT_RUN", exit_code: "unknown", log_sha256: "unknown", artifact_sha256: "unknown" },
		],
	};
	return { index, logsDir, archiveDir };
}

describe("evidence archive carry", () => {
	it("plans the log, the sidecar and the gate-owned snapshot", () => {
		const { index, logsDir, archiveDir } = fixture();
		const plan = carryPlan(index, { logsDir, archiveDir });
		assert.deepEqual(
			plan.map((entry) => entry.name).sort(),
			["01-alpha.log", "01-alpha.log.result.json", "01-alpha.test-results.json", "02-beta.log"],
		);
		assert.equal(plan.find((entry) => entry.name === "01-alpha.log")?.kind, "log");
		assert.equal(plan.find((entry) => entry.name === "01-alpha.test-results.json")?.kind, "snapshot");
	});

	it("carries every present file and verifies it against the recorded digest", () => {
		const { index, logsDir, archiveDir } = fixture();
		const result = carryArchive(index, { logsDir, archiveDir });

		assert.equal(result.mismatched.length, 0);
		assert.equal(result.carried.length, 3);
		assert.equal(result.missing.length, 1, "the gate with no captured log must be reported, not skipped");
		assert.equal(result.missing[0].name, "02-beta.log");
		assert.ok(existsSync(join(archiveDir, "01-alpha.log")));
		assert.equal(readFileSync(join(archiveDir, "01-alpha.test-results.json"), "utf8"), '{"numTotalTests":3}\n');
		// The absent log must not be invented in the archive.
		assert.equal(existsSync(join(archiveDir, "02-beta.log")), false);
	});

	it("fails when the archive disagrees with the index", () => {
		const { index, logsDir, archiveDir } = fixture();
		// A log that hashes to something other than the recorded digest: the archive
		// would look complete while proving nothing.
		writeFileSync(join(logsDir, "01-alpha.log"), "tampered\n");
		const result = carryArchive(index, { logsDir, archiveDir });
		assert.equal(result.mismatched.length, 1);
		assert.equal(result.mismatched[0].name, "01-alpha.log");
	});

	it("writes nothing in check mode but still reports drift", () => {
		const { index, logsDir, archiveDir } = fixture();
		const result = carryArchive(index, { logsDir, archiveDir, check: true });
		assert.equal(existsSync(archiveDir), false, "--check created the archive directory");
		assert.equal(result.carried.length, 0);
		// Three files exist in the evidence directory but are absent from the
		// archive: that is drift the carry step can repair, and it is reported
		// separately from a file the rehearsal never produced.
		assert.equal(result.notCarried.length, 3);
		assert.equal(result.missing.length, 1);
	});

	it("summarises the run from the same records", () => {
		const { index } = fixture();
		const verdicts = renderVerdicts(index);
		assert.match(verdicts, /Rehearsal at commit `a{40}`/);
		assert.match(verdicts, /\| `01-alpha` \| PASS \| 0 \|/);
		assert.match(verdicts, /\| `02-beta` \| NOT_RUN \| unknown \|/);
		assert.match(verdicts, /Totals: 1 pass, 0 non-zero, 0 unknown, 1 not run\./);
		assert.match(verdicts, /1 of the 2 declared gates had no captured log/);

		const summary = JSON.parse(renderSummary(index));
		assert.equal(summary.commit_sha, index.commit_sha);
		assert.deepEqual(summary.counts, { PASS: 1, NOT_RUN: 1 });
	});

	it("states plainly when every declared gate has a log", () => {
		const verdicts = renderVerdicts({
			commit_sha: "c".repeat(40),
			candidate_digest: "d".repeat(64),
			gates: [{ gate_id: "01-alpha", status: "PASS", exit_code: 0 }],
		});
		assert.match(verdicts, /Every one of the 1 declared gates has a captured log\./);
		assert.match(verdicts, /Totals: 1 pass, 0 non-zero, 0 unknown, 0 not run\./);
	});
});
