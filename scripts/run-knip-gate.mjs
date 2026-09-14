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
	// Knip parses Deno's `npm:` URL scheme as an npm package named "npm". The
	// specifier is resolved by the Deno Edge runtime, not by Node or pnpm, so
	// "unlisted" is a false positive for every Edge Function that imports it.
	// The allowlist is enumerated by file on purpose: a new file must be added
	// deliberately rather than inheriting a directory-wide exemption.
	const denoSpecifierFiles = new Set([
		"supabase/functions/_shared/identity-barrier.ts",
		"supabase/functions/team-invite/lifecycle.ts",
		"supabase/functions/autosecops-runtime/index.ts",
		"supabase/functions/billing-portal/index.ts",
		"supabase/functions/invoice-entitlement/index.ts",
		"supabase/functions/oauth-callback/index.ts",
		"supabase/functions/pilot-apply/index.ts",
		"supabase/functions/pilot-status/index.ts",
		"supabase/functions/policy-management/index.ts",
		"supabase/functions/team-invite/index.ts",
	]);
	const file = String(issue.file ?? "").replaceAll("\\", "/");
	if (type !== "unlisted") return false;
	if (value?.name === "npm") return denoSpecifierFiles.has(file);
	// The policy contract suite redirects Deno's `npm:yaml@2.8.3` to the copy the
	// repository already vendors for `@singularityrd/aidr-core`. The bare name is
	// the mock specifier, not an import of an undeclared dependency.
	if (value?.name === "yaml" && file === "supabase/functions/__tests__/policy-management-contract.test.ts") {
		return true;
	}
	return false;
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
