#!/usr/bin/env node
/**
 * Regressions for the generator-determinism checker.
 *
 * The property under test is narrow and easy to lose: the checker must catch a
 * real disagreement between a generated file and the source it summarises, while
 * NOT failing on the provenance stamps that are supposed to change with every
 * run. A checker that fails on `source_commit` is useless (it can never pass); a
 * checker that strips too much is worse, because it reports PASS while a hand
 * edit sits in the tree.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import { tmpdir } from "node:os";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "check-generator-determinism.mjs");

/** Temporary committed-output fixtures; tests never write into the repository. */
const guarded = ["FEATURE_INVENTORY.json", "FEATURE_INVENTORY.md", "PRODUCTION_SALES_GAPS.json", "PRODUCTION_SALES_GAPS.md"];
const fixtureDirs = new Set();

afterEach(() => {
	for (const directory of fixtureDirs) rmSync(directory, { recursive: true, force: true });
	fixtureDirs.clear();
});

function makeFixture() {
	const directory = mkdtempSync(join(tmpdir(), "aidr-generator-test-"));
	fixtureDirs.add(directory);
	for (const relative of guarded) {
		const target = join(directory, relative);
		mkdirSync(dirname(target), { recursive: true });
		writeFileSync(target, readFileSync(join(ROOT, relative), "utf8"), "utf8");
	}
	return directory;
}

function run(committedOutputDir) {
	try {
		return {
			status: 0,
			output: execFileSync(process.execPath, [SCRIPT], {
				cwd: ROOT,
				encoding: "utf8",
				stdio: ["ignore", "pipe", "pipe"],
				env: { ...process.env, ...(committedOutputDir ? { AIDR_COMMITTED_OUTPUT_DIR: committedOutputDir } : {}) },
			}),
		};
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

describe("generator determinism checker", () => {
	it("records the actual Git worktree state in both generated registries", () => {
		// Run the generators into a scratch directory and check the stamps they write.
		// Comparing the committed files instead cannot hold: committing a regenerated
		// record flips worktree_has_changes, and generated_on changes every day - which
		// is exactly why the checker treats both as provenance stamps.
		const outputDir = mkdtempSync(join(tmpdir(), "aidr-generator-stamps-"));
		fixtureDirs.add(outputDir);
		const actualChanges = execFileSync("git", ["status", "--porcelain", "--untracked-files=normal"], { cwd: ROOT, encoding: "utf8" }).trim().length > 0;
		for (const generator of ["generate-feature-inventory.mjs", "generate-production-sales-gap-audit.mjs"]) {
			execFileSync(process.execPath, [join(ROOT, "scripts", generator)], { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, AIDR_GENERATOR_OUTPUT_DIR: outputDir } });
		}
		const generatedOn = new Intl.DateTimeFormat("en-CA", {
			timeZone: "Europe/Istanbul",
			year: "numeric",
			month: "2-digit",
			day: "2-digit",
		}).format(new Date());
		const inventory = JSON.parse(readFileSync(join(outputDir, "FEATURE_INVENTORY.json"), "utf8"));
		const salesGaps = JSON.parse(readFileSync(join(outputDir, "PRODUCTION_SALES_GAPS.json"), "utf8"));
		// Generating into a scratch directory must not have changed the tree it describes.
		assert.equal(execFileSync("git", ["status", "--porcelain", "--untracked-files=normal"], { cwd: ROOT, encoding: "utf8" }).trim().length > 0, actualChanges);
		assert.equal(inventory.worktree_has_changes, actualChanges);
		assert.equal(salesGaps.worktree_has_changes, actualChanges);
		assert.equal(inventory.generated_on, generatedOn);
		assert.equal(salesGaps.generated_on, generatedOn);
	});

	it("passes on a tree whose inventories match their generators", () => {
		const result = run();
		assert.equal(result.status, 0, result.output);
		assert.match(result.output, /Generator determinism PASS/);
	});

	it("names the provenance fields it excludes, so the exclusion is auditable", () => {
		const result = run();
		assert.match(result.output, /source_commit/);
		assert.match(result.output, /worktree_has_changes/);
		assert.match(result.output, /generated_on/);
	});

	it("does not fail on the provenance stamps alone", () => {
		const fixture = makeFixture();
		const parsed = JSON.parse(readFileSync(join(fixture, "FEATURE_INVENTORY.json"), "utf8"));
		parsed.source_commit = "0".repeat(40);
		parsed.worktree_has_changes = !parsed.worktree_has_changes;
		parsed.generated_on = "1900-01-01";
		writeFileSync(join(fixture, "FEATURE_INVENTORY.json"), `${JSON.stringify(parsed, null, 2)}\n`, "utf8");

		const result = run(fixture);
		assert.equal(result.status, 0, `provenance stamps must not fail the check:\n${result.output}`);
	});

	it("fails when a generated inventory is hand-edited", () => {
		const fixture = makeFixture();
		const parsed = JSON.parse(readFileSync(join(fixture, "FEATURE_INVENTORY.json"), "utf8"));
		// Change content the generator derives, not a stamp.
		parsed.decision = parsed.decision === "NO-GO" ? "GO" : "NO-GO";
		writeFileSync(join(fixture, "FEATURE_INVENTORY.json"), `${JSON.stringify(parsed, null, 2)}\n`, "utf8");

		const result = run(fixture);
		assert.equal(result.status, 1, "a hand-edited inventory must be caught");
		assert.match(result.output, /disagrees with a fresh generator run/);
	});

	it("leaves the tree as it found it, whether it passes or fails", () => {
		const fixture = makeFixture();
		const inventory = join(fixture, "FEATURE_INVENTORY.json");
		const parsed = JSON.parse(readFileSync(inventory, "utf8"));
		parsed.decision = "TAMPERED";
		const tampered = `${JSON.stringify(parsed, null, 2)}\n`;
		writeFileSync(inventory, tampered, "utf8");

		const result = run(fixture);
		assert.equal(result.status, 1, "a tampered inventory must be reported");

		// The checker reads this fixture but only writes fresh generator output to
		// a separate temporary directory. It must not silently repair the input it
		// was asked to judge.
		assert.equal(readFileSync(inventory, "utf8"), tampered, "the checker must not silently rewrite the file it judged");
	});

	it("reports mismatches for markdown output too, not only JSON", () => {
		const fixture = makeFixture();
		const markdown = join(fixture, "FEATURE_INVENTORY.md");
		const original = readFileSync(markdown, "utf8");
		writeFileSync(markdown, `${original}\n<!-- hand edit -->\n`, "utf8");

		const result = run(fixture);
		assert.equal(result.status, 1, "a hand-edited markdown inventory must be caught");
		assert.match(result.output, /FEATURE_INVENTORY\.md/);
	});
});
