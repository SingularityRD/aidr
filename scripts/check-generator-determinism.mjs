#!/usr/bin/env node
/**
 * Prove the inventory generators are deterministic, ignoring provenance stamps.
 *
 * The previous check was `git diff --exit-code` on the generated files. That can
 * never pass, and the reason is worth stating plainly: every generator writes
 * `source_commit` from `git rev-parse HEAD` and `worktree_has_changes` from the
 * working tree state, so regenerating at a different commit always differs in
 * exactly those fields. They are stamps describing *when* the generator ran, not
 * content it derived, so comparing them measures the commit rather than the
 * generator.
 *
 * What this checks instead: run each generator twice and require the two outputs
 * to be byte-identical apart from those stamps, and additionally require the
 * committed file to match a fresh run apart from the same stamps. That still
 * catches the defect the gate exists for - a hand edit that makes an inventory
 * disagree with the source it claims to summarise - while no longer failing on a
 * field that is supposed to change.
 *
 * Usage:
 *   node scripts/check-generator-determinism.mjs
 */
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Fields that record which revision the generator ran at. Excluded from the
 * comparison, and each exclusion is named so a reader can audit the decision.
 */
const PROVENANCE_FIELDS = ["source_commit", "worktree_has_changes"];

/** generator script -> the tracked files it owns. */
const GENERATORS = [
	{
		script: "scripts/generate-feature-inventory.mjs",
		outputs: ["FEATURE_INVENTORY.json", "FEATURE_INVENTORY.md"],
		json: ["FEATURE_INVENTORY.json"],
	},
	{
		script: "scripts/generate-production-sales-gap-audit.mjs",
		outputs: ["PRODUCTION_SALES_GAPS.json", "PRODUCTION_SALES_GAPS.md"],
		json: ["PRODUCTION_SALES_GAPS.json"],
	},
];

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}

/** Remove the provenance stamps from a JSON document, recursively. */
function strip(value) {
	if (Array.isArray(value)) return value.map(strip);
	if (value && typeof value === "object") {
		const out = {};
		for (const [key, entry] of Object.entries(value)) {
			if (PROVENANCE_FIELDS.includes(key)) continue;
			out[key] = strip(entry);
		}
		return out;
	}
	return value;
}

/** Strip the same stamps from a markdown report, which quotes them as lines. */
function stripMarkdown(text) {
	return text
		.split(/\r?\n/)
		.filter((line) => !PROVENANCE_FIELDS.some((field) => line.includes(field)))
		.join("\n");
}

function snapshot(files) {
	const out = {};
	for (const relative of files) {
		const full = path.join(ROOT, relative);
		let text;
		try {
			text = readFileSync(full, "utf8");
		} catch {
			fail(`${relative} is missing; run the generator first`);
		}
		out[relative] = relative.endsWith(".json") ? JSON.stringify(strip(JSON.parse(text))) : stripMarkdown(text);
	}
	return out;
}

const problems = [];
const checked = [];

for (const generator of GENERATORS) {
	const scriptPath = path.join(ROOT, generator.script);
	// Back up the committed files so the run leaves the tree exactly as it found it.
	const backups = new Map();
	for (const relative of generator.outputs) {
		backups.set(relative, readFileSync(path.join(ROOT, relative), "utf8"));
	}

	// The committed content, with stamps removed.
	const committed = snapshot(generator.outputs);

	const runOnce = () => {
		const result = spawnSync(process.execPath, [scriptPath], { cwd: ROOT, encoding: "utf8" });
		if (result.status !== 0) {
			fail(`${generator.script} failed with exit ${result.status}: ${(result.stderr ?? "").trim().slice(-300)}`);
		}
		return snapshot(generator.outputs);
	};

	const first = runOnce();
	const second = runOnce();

	for (const relative of generator.outputs) {
		if (first[relative] !== second[relative]) {
			problems.push(`${relative}: two consecutive generator runs produced different content`);
		}
		if (committed[relative] !== first[relative]) {
			problems.push(`${relative}: the committed file disagrees with a fresh generator run (apart from ${PROVENANCE_FIELDS.join(", ")})`);
		}
	}
	checked.push(`${generator.script} -> ${generator.outputs.length} file(s), stable across two runs and matching the committed content`);

	// Restore, so a failing gate still leaves a clean tree for the next one.
	for (const [relative, text] of backups) writeFileSync(path.join(ROOT, relative), text, "utf8");
}

rmSync(path.join(tmpdir(), "aidr-generator-determinism-unused"), { recursive: true, force: true });

if (problems.length > 0) {
	console.error("Generator determinism failed:");
	for (const problem of problems) console.error(`- ${problem}`);
	process.exit(1);
}

console.log(`Generator determinism PASS (${checked.length} generator(s); ${PROVENANCE_FIELDS.join(" and ")} excluded as provenance stamps).`);
for (const line of checked) console.log(`- ${line}`);
