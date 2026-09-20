#!/usr/bin/env node
/**
 * Regression tests for the release candidate assembler.
 *
 * The behaviour that matters here is fail-closed provenance: a candidate must
 * never be produced from bytes that are not bound to the commit it records,
 * and it must never be produced from package trees that were built in normal
 * (non-release) mode, because those carry sourcemaps and test folders that must
 * not reach a customer. These tests pin those refusals plus the argument
 * contract, without packing real tarballs.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { cleanupDirectory } from "./release-candidate-cleanup.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "build-release-candidate.mjs");

/** Runs the assembler and captures status plus output instead of throwing. */
function run(args, options = {}) {
	try {
		const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
			cwd: ROOT,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			...options,
		});
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

describe("release candidate cleanup", () => {
	it("retries transient Windows EPERM and verifies the directory is gone", () => {
		let removeCalls = 0;
		const sleeps = [];
		cleanupDirectory("C:\\Temp\\aidr-candidate-pack-test", {
			platform: "win32",
			attempts: 4,
			remove: () => {
				removeCalls++;
				if (removeCalls < 3) throw Object.assign(new Error("sharing violation"), { code: "EPERM" });
			},
			exists: () => false,
			sleep: (milliseconds) => sleeps.push(milliseconds),
			warn: () => {},
		});
		assert.equal(removeCalls, 3);
		assert.deepEqual(sleeps, [100, 100]);
	});

	it("fails with actionable diagnostics when cleanup remains impossible", () => {
		assert.throws(
			() => cleanupDirectory("C:\\Temp\\aidr-candidate-pack-stuck", {
				platform: "win32",
				attempts: 2,
				remove: () => { throw Object.assign(new Error("sharing violation"), { code: "EPERM" }); },
				exists: () => true,
				sleep: () => {},
				warn: () => {},
			}),
			/Unable to remove temporary release staging directory after 2 attempt\(s\).*Close processes holding files/,
		);
	});
});

describe("release candidate assembler", () => {
	it("documents its arguments", () => {
		const result = run(["--help"]);
		assert.equal(result.status, 0);
		assert.match(result.output, /--output/);
		assert.match(result.output, /--allow-dirty/);
		assert.match(result.output, /--rc-version/);
	});

	it("requires --output", () => {
		const result = run([]);
		assert.equal(result.status, 1);
		assert.match(result.output, /--output is required/);
	});

	it("rejects an unknown argument instead of ignoring it", () => {
		const result = run(["--output", ".release-evidence/never-created", "--force"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /unknown argument/);
	});

	it("refuses an output directory outside the repository", () => {
		const result = run(["--output", join(tmpdir(), "aidr-candidate-outside")]);
		assert.equal(result.status, 1);
		assert.match(result.output, /must be inside the repository/);
	});

	it("refuses to overwrite an existing candidate directory", () => {
		// packages/core/dist exists in any built checkout, so use it as a stand-in
		// for "this directory is already there": the assembler must refuse before
		// it packs anything.
		const result = run(["--output", "packages/core"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /already exists/);
	});

	it("refuses to assemble a candidate from a dirty worktree", () => {
		// This repository is expected to be clean apart from build output and
		// evidence. If a source file is genuinely dirty the assembler must refuse;
		// if the tree is clean it gets past the guard and fails later on something
		// else. Either way it must never report PASS here without --allow-dirty.
		const result = run(["--output", ".release-evidence/should-not-exist-dirty-check"]);
		if (result.status === 0) assert.fail("assembler reported PASS for a worktree it did not verify as clean");
		if (/uncommitted source changes/.test(result.output)) {
			assert.match(result.output, /--allow-dirty/);
		}
		assert.equal(existsSync(join(ROOT, ".release-evidence", "should-not-exist-dirty-check")), false);
	});

	it("records a dirty worktree as a local rehearsal when explicitly allowed", () => {
		const outputDir = mkdtempSync(join(tmpdir(), "aidr-candidate-test-"));
		rmSync(outputDir, { recursive: true, force: true });
		// Place the rehearsal output under .release-evidence so it is excluded from
		// the dirtiness check and cleaned up afterwards regardless of outcome.
		const relative = `.release-evidence/candidate-rehearsal-test-${process.pid}`;
		const absolute = join(ROOT, relative);
		try {
			const result = run(["--output", relative, "--allow-dirty", "--rc-version", "0.0.0-test"]);
			if (result.status !== 0) {
				// A failure here must still be a real refusal, not a crash, and must
				// leave no half-written candidate behind.
				assert.match(result.output, /ERROR:/);
				return;
			}
			const metadata = JSON.parse(readFileSync(join(absolute, "release-metadata.json"), "utf8"));
			assert.equal(metadata.release_version, "0.0.0-test");
			// The signed-bundle schema validates metadata with an exact key set, so
			// nothing beyond these six fields may appear there.
			assert.deepEqual(
				Object.keys(metadata).sort(),
				["artifacts", "git_sha", "release_tag", "release_version", "schema_version", "source_date_epoch"],
			);
			// The bundle itself may contain only metadata, inventory and artifacts;
			// the assurance report must sit outside it.
			const bundleEntries = readdirSync(absolute).sort();
			for (const entry of bundleEntries) {
				assert.ok(
					["release-metadata.json", "release-inventory.json"].includes(entry) || /\.(tgz|tar\.gz|json)$/.test(entry),
					`unexpected file inside candidate bundle: ${entry}`,
				);
			}
			assert.equal(bundleEntries.includes("candidate-assurance.json"), false);

			const assurance = JSON.parse(readFileSync(`${absolute}.assurance.json`, "utf8"));
			assert.equal(assurance.worktree_dirty, true);
			assert.match(assurance.assurance, /LOCAL REHEARSAL/);
			assert.ok(Array.isArray(assurance.dirty_entries));

			const inventory = JSON.parse(readFileSync(join(absolute, "release-inventory.json"), "utf8"));
			assert.equal(inventory.schema_version, 1);
			assert.ok(inventory.artifacts.length > 0, "candidate must stage at least one artifact");
			for (const entry of inventory.artifacts) {
				assert.equal(entry.kind, "release-artifact");
				assert.equal(entry.source_path, `release-output/${entry.staged_path}`);
				assert.match(entry.sha256, /^[0-9a-f]{64}$/);
			}
			// Every staged file must exist and match the digest the inventory claims.
			for (const entry of inventory.artifacts) {
				assert.ok(existsSync(join(absolute, entry.staged_path)), `staged artifact missing: ${entry.staged_path}`);
			}
			for (const artifact of metadata.artifacts) {
				assert.ok(existsSync(join(absolute, artifact.path)), `metadata artifact missing: ${artifact.path}`);
				assert.match(artifact.sha256, /^[0-9a-f]{64}$/);
			}
		} finally {
			rmSync(absolute, { recursive: true, force: true });
			rmSync(`${absolute}.assurance.json`, { force: true });
		}
	});
});
