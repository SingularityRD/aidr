/**
 * Knip quality gate.
 *
 * The repository intentionally contains deploy-by-convention Supabase
 * functions and public library helpers that cannot be discovered from a
 * single JavaScript entry graph.  We still fail closed for dependency,
 * unlisted-package, binary, and unresolved-import drift; file/export/duplicate
 * findings remain visible as review debt until their owning product surface is
 * retired or promoted to an entry point.
 */

import { spawnSync } from "node:child_process";
import { createDependencyAuditor, evaluateReport } from "./knip-dependency-audit.mjs";

const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const result = spawnSync(command, ["exec", "knip", "--reporter", "json", "--no-exit-code"], {
	encoding: "utf8",
	maxBuffer: 32 * 1024 * 1024,
	shell: process.platform === "win32",
});

if (result.error || result.status !== 0) {
	console.error("Unable to run Knip:", result.error ?? result.stderr ?? `exit ${result.status}`);
	process.exit(1);
}

const output = (result.stdout ?? "").trim();
if (!output) {
	console.error("Knip produced no JSON report.");
	if (result.stderr) console.error(result.stderr.trim());
	process.exit(1);
}

let report;
try {
	report = JSON.parse(output);
} catch (error) {
	console.error("Unable to parse Knip JSON report:", error);
	process.exit(1);
}

const { counts, blocking } = evaluateReport(report, createDependencyAuditor(process.cwd()));

console.log(
	`Knip gate: review debt files=${counts.files}, exports=${counts.exports}, duplicates=${counts.duplicates}.`,
);

if (blocking.length > 0) {
	console.error("Knip gate failed on dependency/package graph issues:");
	for (const issue of blocking) console.error(`- ${issue}`);
	process.exit(1);
}

process.exit(0);
