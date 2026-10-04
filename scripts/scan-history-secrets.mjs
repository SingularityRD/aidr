#!/usr/bin/env node
/**
 * Full-history secret scan wrapper (FCR-05 / AIDR-070).
 *
 * Runs gitleaks over every ref with `--no-textconv` (without it, Git for
 * Windows invokes `astextplain`/`docx2txt` for *.docx diffs, the scan aborts
 * with "stderr is not empty" and gitleaks reports only a PARTIAL result that
 * looks like a normal finding count). Findings are always written fully
 * redacted to a path outside the repository; this script never prints a match.
 *
 * Usage:
 *   node scripts/scan-history-secrets.mjs [--report <json>] [--gitleaks <exe>]
 *
 * Exit: 0 no findings, 1 findings present (triage required), 2 scan error or
 * incomplete scan.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function summarize(findings) {
	const byRule = {};
	for (const f of findings) byRule[f.RuleID] = (byRule[f.RuleID] ?? 0) + 1;
	return {
		findings: findings.length,
		commits: new Set(findings.map((f) => f.Commit)).size,
		files: new Set(findings.map((f) => f.File)).size,
		byRule: Object.fromEntries(Object.entries(byRule).sort((a, b) => b[1] - a[1])),
	};
}

/** True when gitleaks output shows it aborted part-way (result is not a full-history result). */
export function isPartialScan(output) {
	return /partial scan|failed to scan Git repository/i.test(output);
}

function main() {
	const argv = process.argv.slice(2);
	const arg = (name) => {
		const i = argv.indexOf(name);
		return i >= 0 ? argv[i + 1] : undefined;
	};
	const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
	const exe = arg("--gitleaks") ?? process.env.GITLEAKS_BIN ?? "gitleaks";
	const report = path.resolve(arg("--report") ?? path.join(mkdtempSync(path.join(tmpdir(), "aidr-hist-")), "report.json"));
	const run = spawnSync(
		exe,
		[
			"detect", "--source", repoRoot, "--config", path.join(repoRoot, ".gitleaks.toml"),
			"--log-opts=--all --no-textconv", "--redact=100", "--report-format", "json",
			"--report-path", report, "--no-banner",
		],
		{ encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
	);
	const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
	if (run.error || isPartialScan(output) || (run.status !== 0 && run.status !== 1) || !existsSync(report)) {
		console.error(`History scan did not complete (${run.error?.message ?? `exit ${run.status}`}); result is NOT a clean or full-history result.`);
		process.exit(2);
	}
	const summary = summarize(JSON.parse(readFileSync(report, "utf8") || "[]"));
	console.log(JSON.stringify({ status: summary.findings ? "findings" : "clean", report, ...summary }));
	process.exit(summary.findings ? 1 : 0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
