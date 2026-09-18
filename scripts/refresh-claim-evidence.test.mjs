#!/usr/bin/env node
/**
 * Regressions for the claim-evidence refresh helper.
 *
 * The behaviour that matters: the helper must rewrite the bound records with the
 * current commit and candidate digest, must write them as BOM-free UTF-8 (a BOM
 * makes every downstream JSON.parse fail, which is the bug this script exists to
 * prevent), and must not report success when the scan itself reports open
 * findings.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "refresh-claim-evidence.mjs");
const CANDIDATE_SOURCE = ".release-evidence/customer-release-v8-local-20260916-r9/release-inventory.json";

/** Runs the helper and captures its status rather than throwing on exit 1. */
function run() {
	try {
		return { status: 0, output: execFileSync(process.execPath, [SCRIPT], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

const BOUND_RECORDS = [
	"v7-claim-inventory.json",
	"v7-claim-inventory-final.json",
	"v7-claim-gate.json",
	"v7-claim-gate-final.json",
];

describe("claim evidence refresh helper", () => {
	it("requires the claim-scan inputs to exist", () => {
		// The scan reads the registry and the candidate; if either is missing this
		// must fail loudly rather than write an empty record.
		assert.ok(existsSync(join(ROOT, "docs", "production-readiness", "commercial-go-evidence-registry.json")));
		assert.ok(existsSync(join(ROOT, CANDIDATE_SOURCE)), `candidate inventory missing: ${CANDIDATE_SOURCE}`);
	});

	it("rewrites every bound record with the current commit, candidate and BOM-free UTF-8", () => {
		const result = run();
		const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();

		for (const name of BOUND_RECORDS) {
			const full = join(ROOT, ".release-evidence", name);
			assert.ok(existsSync(full), `${name} was not written`);
			const bytes = readFileSync(full);
			// A UTF-8 BOM would make every consumer's JSON.parse throw.
			assert.notEqual(bytes[0], 0xef, `${name} starts with a UTF-8 BOM`);
			assert.notEqual(bytes[1], 0xbb, `${name} starts with a UTF-8 BOM`);

			const record = JSON.parse(bytes.toString("utf8"));
			assert.equal(record.source_commit, head, `${name} is not bound to the current commit`);
			assert.equal(record.candidate_digest_source, CANDIDATE_SOURCE, `${name} names the wrong candidate`);
			assert.match(String(record.candidate_digest ?? ""), /^[0-9a-f]{64}$/, `${name} has no candidate digest`);
		}

		// The helper reports the decision it observed; it must never claim a clean
		// scan when the gate mode found open findings.
		assert.match(result.output, /inventory: (PASS|FAIL)/);
		assert.match(result.output, /gate: (PASS|FAIL)/);
		if (/gate: FAIL/.test(result.output)) {
			assert.equal(result.status, 1, "an open gate must not exit zero");
			assert.match(result.output, /does not resolve/);
		}
	});

	it("produces records the freshness check accepts", () => {
		// The whole point of the refresh is that the freshness gate stops failing on
		// staleness. Whatever it reports, it must no longer report a binding
		// mismatch against the current commit.
		const result = spawnSyncQuiet(join(ROOT, "scripts", "check-claim-evidence-freshness.mjs"));
		assert.doesNotMatch(
			result.output,
			/does not match the current source commit/,
			"freshness check still sees a stale commit binding",
		);
		assert.doesNotMatch(
			result.output,
			/does not match the current candidate digest/,
			"freshness check still sees a stale candidate binding",
		);
	});
});

function spawnSyncQuiet(script) {
	try {
		const output = execFileSync(process.execPath, [script], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
		return { status: 0, output };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}
