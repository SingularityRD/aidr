#!/usr/bin/env node
/**
 * Rebind the claim-scan evidence records to the current commit and candidate.
 *
 * `docs/scripts/claim-check.mjs` stamps every record it writes with the source
 * commit and the candidate inventory digest it scanned, and
 * `scripts/check-claim-evidence-freshness.mjs` refuses any record whose stamps
 * do not match the tree it is verifying against. That refusal is correct: a
 * claim scan from another revision proves nothing about this one.
 *
 * The practical consequence is that the records have to be rewritten after
 * every commit, or `quality:static` fails on staleness rather than on a real
 * claim violation. Re-running the scan by hand and redirecting its stdout is
 * easy to get wrong - PowerShell redirection writes UTF-16 with a BOM, which
 * makes the JSON unreadable - so this script owns that step: it runs the scan
 * in both modes, writes the records as UTF-8 without a BOM, and prints the
 * decision each mode reached.
 *
 * A FAIL decision is reported and exits non-zero: those are real open claims or
 * hard gates, and this script must not be used to make them look resolved.
 */
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EVIDENCE_DIR = path.join(ROOT, ".release-evidence");

/** Mode -> the record file names that mode is expected to produce. */
const RECORDS = {
	inventory: ["v7-claim-inventory.json", "v7-claim-inventory-final.json"],
	gate: ["v7-claim-gate.json", "v7-claim-gate-final.json"],
};

function runScan(mode) {
	const result = spawnSync(process.execPath, ["docs/scripts/claim-check.mjs", `--mode=${mode}`, "--json"], {
		cwd: ROOT,
		encoding: "utf8",
		maxBuffer: 64 * 1024 * 1024,
	});
	// `gate` exits 1 when the registry has open hard gates. That is a finding to
	// report, not a failure of this script, so the output is what matters.
	if (result.error) throw new Error(`claim scan (${mode}) could not start: ${result.error.message}`);
	const raw = (result.stdout ?? "").trim();
	if (!raw) throw new Error(`claim scan (${mode}) produced no output: ${(result.stderr ?? "").trim().slice(-400)}`);
	let parsed;
	try {
		parsed = JSON.parse(raw);
	} catch (error) {
		throw new Error(`claim scan (${mode}) produced unparseable JSON: ${error.message}`);
	}
	for (const name of RECORDS[mode]) writeFileSync(path.join(EVIDENCE_DIR, name), `${raw}\n`, "utf8");
	return parsed;
}

let failed = false;
for (const mode of Object.keys(RECORDS)) {
	const record = runScan(mode);
	const decision = String(record.result ?? "unknown");
	console.log(
		`${mode}: ${decision} — commit ${String(record.source_commit ?? "").slice(0, 8)}, ` +
		`candidate ${String(record.candidate_digest ?? "").slice(0, 8)}, ` +
		`hits ${record.hits?.length ?? 0}, unapproved ${record.unapprovedHits?.length ?? 0}, ` +
		`open hard gates ${record.openHardGates?.length ?? 0}`,
	);
	if (decision === "FAIL") failed = true;
}

if (failed) {
	console.error("Claim evidence was refreshed, but the claim gate reports open findings that this script does not resolve.");
	process.exitCode = 1;
}
