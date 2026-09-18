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
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "check-generator-determinism.mjs");
const INVENTORY = join(ROOT, "FEATURE_INVENTORY.json");

/** Files the checker rewrites and restores; every test must leave them as found. */
const guarded = ["FEATURE_INVENTORY.json", "FEATURE_INVENTORY.md", "PRODUCTION_SALES_GAPS.json", "PRODUCTION_SALES_GAPS.md"];
const originals = new Map(guarded.map((relative) => [relative, readFileSync(join(ROOT, relative), "utf8")]));

afterEach(() => {
	for (const [relative, text] of originals) writeFileSync(join(ROOT, relative), text, "utf8");
});

function run() {
	try {
		return { status: 0, output: execFileSync(process.execPath, [SCRIPT], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

describe("generator determinism checker", () => {
	it("passes on a tree whose inventories match their generators", () => {
		const result = run();
		assert.equal(result.status, 0, result.output);
		assert.match(result.output, /Generator determinism PASS/);
	});

	it("names the provenance fields it excludes, so the exclusion is auditable", () => {
		const result = run();
		assert.match(result.output, /source_commit/);
		assert.match(result.output, /worktree_has_changes/);
	});

	it("does not fail on the provenance stamps alone", () => {
		// Rewrite only the stamps. A checker that compares whole files fails here,
		// which is the defect this replaces: the stamps change with every commit by
		// design, so a whole-file comparison can never pass in a healthy tree.
		const parsed = JSON.parse(readFileSync(INVENTORY, "utf8"));
		parsed.source_commit = "0".repeat(40);
		parsed.worktree_has_changes = !parsed.worktree_has_changes;
		writeFileSync(INVENTORY, `${JSON.stringify(parsed, null, 2)}\n`, "utf8");

		const result = run();
		assert.equal(result.status, 0, `provenance stamps must not fail the check:\n${result.output}`);
	});

	it("fails when a generated inventory is hand-edited", () => {
		const parsed = JSON.parse(readFileSync(INVENTORY, "utf8"));
		// Change content the generator derives, not a stamp.
		parsed.decision = parsed.decision === "NO-GO" ? "GO" : "NO-GO";
		writeFileSync(INVENTORY, `${JSON.stringify(parsed, null, 2)}\n`, "utf8");

		const result = run();
		assert.equal(result.status, 1, "a hand-edited inventory must be caught");
		assert.match(result.output, /disagrees with a fresh generator run/);
	});

	it("leaves the tree as it found it, whether it passes or fails", () => {
		const parsed = JSON.parse(readFileSync(INVENTORY, "utf8"));
		parsed.decision = "TAMPERED";
		const tampered = `${JSON.stringify(parsed, null, 2)}\n`;
		writeFileSync(INVENTORY, tampered, "utf8");

		const result = run();
		assert.equal(result.status, 1, "a tampered inventory must be reported");

		// The checker restores the files it rewrote from a backup taken before it
		// ran. It must not silently repair the tampering: a gate that fixes the
		// defect it was asked to report is worse than one that only reports it,
		// because the next reader sees a clean tree and no record of the edit.
		assert.equal(readFileSync(INVENTORY, "utf8"), tampered, "the checker must not silently rewrite the file it judged");
	});

	it("reports mismatches for markdown output too, not only JSON", () => {
		const markdown = join(ROOT, "FEATURE_INVENTORY.md");
		const original = readFileSync(markdown, "utf8");
		writeFileSync(markdown, `${original}\n<!-- hand edit -->\n`, "utf8");

		const result = run();
		assert.equal(result.status, 1, "a hand-edited markdown inventory must be caught");
		assert.match(result.output, /FEATURE_INVENTORY\.md/);
	});
});
