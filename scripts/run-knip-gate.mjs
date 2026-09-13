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

const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const result = spawnSync(command, ["exec", "knip", "--reporter", "json", "--no-exit-code"], {
	encoding: "utf8",
	maxBuffer: 32 * 1024 * 1024,
	shell: process.platform === "win32",
});

if (result.error) {
	console.error("Unable to run Knip:", result.error);
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

const allowedReviewDebt = new Set(["files", "exports", "duplicates"]);
const counts = Object.fromEntries([...allowedReviewDebt].map((type) => [type, 0]));
counts.files = Array.isArray(report.files) ? report.files.length : 0;
const blocking = [];

function isApprovedWorkflowTool(issue, type, value) {
	return (
		type === "binaries" &&
		value?.name === "typedoc" &&
		String(issue.file ?? "").replaceAll("\\", "/") ===
			".github/workflows/docs-generation.yml"
	);
}

function isDenoTypeSpecifier(issue, type, value) {
	// Knip parses Deno's `npm:` URL scheme as an npm package named "npm".
	// These exact type-only imports are erased from the Edge runtime bundle.
	const denoTypeOnlyImports = new Set([
		"supabase/functions/_shared/identity-barrier.ts",
		"supabase/functions/team-invite/lifecycle.ts",
	]);
	return type === "unlisted" && value?.name === "npm" &&
		denoTypeOnlyImports.has(String(issue.file ?? "").replaceAll("\\", "/"));
}

for (const issue of report.issues ?? []) {
	for (const [type, values] of Object.entries(issue)) {
		if (!Array.isArray(values) || values.length === 0 || type === "file" || type === "owners") {
			continue;
		}
		if (values.every((value) => isApprovedWorkflowTool(issue, type, value) || isDenoTypeSpecifier(issue, type, value))) {
			continue;
		}
		if (allowedReviewDebt.has(type)) {
			counts[type] += values.length;
			continue;
		}
		for (const value of values) {
			blocking.push(`${issue.file ?? "<unknown>"}: ${type} ${JSON.stringify(value)}`);
		}
	}
}

console.log(
	`Knip gate: review debt files=${counts.files}, exports=${counts.exports}, duplicates=${counts.duplicates}.`,
);

if (blocking.length > 0) {
	console.error("Knip gate failed on dependency/package graph issues:");
	for (const issue of blocking) console.error(`- ${issue}`);
	process.exit(1);
}

process.exit(0);
