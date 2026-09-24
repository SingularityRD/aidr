#!/usr/bin/env node
/**
 * Prove the inventory generators are deterministic, ignoring provenance stamps.
 *
 * The previous check was `git diff --exit-code` on the generated files. That can
 * never pass because generators write source/worktree and current-generation
 * stamps. Those fields describe which checkout/date the generator ran against,
 * not content it derived, so comparing them measures the run context rather
 * than the generator.
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
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const COMMITTED_ROOT = process.env.AIDR_COMMITTED_OUTPUT_DIR ?? ROOT;
const OUTPUT_ROOT = mkdtempSync(path.join(tmpdir(), "aidr-generator-check-"));
process.on("exit", () => rmSync(OUTPUT_ROOT, { recursive: true, force: true }));

/**
 * Provenance fields excluded from comparisons, named so a reader can audit the
 * decision. Dates are checked separately against the current local date.
 */
const PROVENANCE_FIELDS = ["source_commit", "worktree_has_changes", "generated_on"];
const MARKDOWN_PROVENANCE_PREFIXES = ["Otomatik üretim tarihi:", "Otomatik rapor üretim tarihi:"];

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
		.filter((line) => !MARKDOWN_PROVENANCE_PREFIXES.some((prefix) => line.trimStart().startsWith(prefix)))
		.join("\n");
}

function snapshot(files, root = ROOT) {
	const out = {};
	for (const relative of files) {
		const full = path.join(root, relative);
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
let runNumber = 0;

for (const generator of GENERATORS) {
	const scriptPath = path.join(ROOT, generator.script);
	// The committed content, with stamps removed.
	const committed = snapshot(generator.outputs, COMMITTED_ROOT);

	const runOnce = () => {
		const outputDir = path.join(OUTPUT_ROOT, `run-${runNumber++}`);
		mkdirSync(outputDir);
		const result = spawnSync(process.execPath, [scriptPath], {
			cwd: ROOT,
			encoding: "utf8",
			env: { ...process.env, AIDR_GENERATOR_OUTPUT_DIR: outputDir },
		});
		if (result.status !== 0) {
			fail(`${generator.script} failed with exit ${result.status}: ${(result.stderr ?? "").trim().slice(-300)}`);
		}
		return snapshot(generator.outputs, outputDir);
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
}

if (problems.length > 0) {
	console.error("Generator determinism failed:");
	for (const problem of problems) console.error(`- ${problem}`);
	process.exit(1);
}

console.log(`Generator determinism PASS (${checked.length} generator(s); ${PROVENANCE_FIELDS.join(" and ")} excluded as provenance stamps).`);
for (const line of checked) console.log(`- ${line}`);
