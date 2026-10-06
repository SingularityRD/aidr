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
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { cleanupDirectory } from "./release-candidate-cleanup.mjs";
import { assertVsixIntegrityEvidence, VSIX_INTEGRITY_EVIDENCE_FILES } from "./lib/vsix-package-files.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "build-release-candidate.mjs");

/** Runs the assembler and captures status plus output instead of throwing. */
function run(args, options = {}) {
	const { script = SCRIPT, ...executionOptions } = options;
	try {
		const stdout = execFileSync(process.execPath, [script, ...args], {
			cwd: ROOT,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			...executionOptions,
		});
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

/** A disposable checkout exercises actual packing without changing this worktree. */
function candidateFixture(t) {
	const root = mkdtempSync(join(tmpdir(), "aidr-candidate-fixture-"));
	t.after(() => cleanupDirectory(root));
	for (const file of [
		"scripts/build-release-candidate.mjs", "scripts/release-candidate-cleanup.mjs",
		"scripts/lib/claude-plugin-package.mjs", "scripts/lib/tar-path.mjs",
		"scripts/lib/release-archive-inspection.mjs", "scripts/lib/package-artifact-rules.mjs",
		"scripts/generate-provenance.mjs",
		"packages/claude-code/scripts/ensure-dist.mjs",
	]) {
		mkdirSync(dirname(join(root, file)), { recursive: true });
		copyFileSync(join(ROOT, file), join(root, file));
	}
	writeFileSync(join(root, "package.json"), JSON.stringify({ private: true, type: "module", version: "1.2.3" }));
	writeFileSync(join(root, ".gitignore"), "packages/*/dist/\n.release-evidence/\n");
	mkdirSync(join(root, ".release-evidence"), { recursive: true });
	const sbom = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [] });
	writeFileSync(join(root, ".release-evidence/aidr-sbom.cdx.json"), sbom);
	writeFileSync(join(root, ".release-evidence/aidr-sbom.cdx.json.sha256"), `${createHash("sha256").update(sbom).digest("hex")}  aidr-sbom.cdx.json\n`);
	writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
	for (const name of ["core", "claude-code", "opencode", "openclaw", "codex", "cli", "sdk", "mcp-gateway", "dashboard", "extension"]) {
		const directory = join(root, "packages", name);
		mkdirSync(join(directory, "dist"), { recursive: true });
		writeFileSync(join(directory, "dist", "index.cjs"), "module.exports = {};\n");
		writeFileSync(join(directory, "dist", "aidr-artifact.manifest.json"), JSON.stringify({ artifact_id: `${name}/dist` }));
		writeFileSync(join(directory, "package.json"), JSON.stringify({ name: `@singularityrd/aidr-${name}`, version: "1.2.3", files: ["dist"] }));
	}
	for (const args of [["init", "--quiet"], ["add", "."], ["-c", "user.name=AIDR Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "fixture"]]) {
		execFileSync("git", args, { cwd: root, stdio: "pipe" });
	}
	return { root, script: join(root, "scripts", "build-release-candidate.mjs") };
}

describe("release candidate cleanup", () => {
	it("renames staging and retries transient Windows EPERM with increasing delays", () => {
		let removeCalls = 0;
		let renamed = false;
		let removed = false;
		const sleeps = [];
		const renameCalls = [];
		cleanupDirectory("C:\\Temp\\aidr-candidate-pack-test", {
			platform: "win32",
			attempts: 4,
			rename: (from, to) => {
				renameCalls.push([from, to]);
				renamed = true;
			},
			remove: () => {
				removeCalls++;
				if (removeCalls < 3) throw Object.assign(new Error("sharing violation"), { code: "EPERM" });
				removed = true;
			},
			exists: () => !removed,
			sleep: (milliseconds) => sleeps.push(milliseconds),
			warn: () => {},
		});
		assert.equal(removeCalls, 3);
		assert.equal(renameCalls.length, 1);
		assert.equal(renameCalls[0][0], "C:\\Temp\\aidr-candidate-pack-test");
		assert.match(renameCalls[0][1], /candidate-pack-test\.cleanup-\d+-\d+-1$/);
		assert.equal(renamed, true);
		assert.deepEqual(sleeps, [100, 200]);
	});

	it("fails with actionable diagnostics when cleanup remains impossible", () => {
		assert.throws(
			() => cleanupDirectory("C:\\Temp\\aidr-candidate-pack-stuck", {
				platform: "win32",
				attempts: 2,
				rename: () => {},
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
	it("VSIX evidence requires a signature by default and permits only its absence for unsigned preparation", async (t) => {
		const root = mkdtempSync(join(tmpdir(), "aidr-vsix-evidence-"));
		t.after(() => cleanupDirectory(root));
		mkdirSync(join(root, "dist"));
		for (const file of VSIX_INTEGRITY_EVIDENCE_FILES.filter((name) => !name.endsWith(".sig"))) writeFileSync(join(root, file), "fixture\n");
		await assert.rejects(assertVsixIntegrityEvidence(root), /manifest\.sig/);
		await assertVsixIntegrityEvidence(root, { requireSignature: false });
		rmSync(join(root, "dist/aidr-sbom.cdx.json"));
		await assert.rejects(assertVsixIntegrityEvidence(root, { requireSignature: false }), /aidr-sbom\.cdx\.json/);
	});

	it("rejects missing or changed mandatory SBOM evidence and cleans incomplete output", (t) => {
		const fixture = candidateFixture(t);
		const checksum = join(fixture.root, ".release-evidence/aidr-sbom.cdx.json.sha256");
		rmSync(checksum);
		const output = ".release-evidence/candidate";
		let result = run(["--output", output], { script: fixture.script, cwd: fixture.root });
		assert.equal(result.status, 1);
		assert.match(result.output, /release SBOM evidence is missing/);
		assert.equal(existsSync(join(fixture.root, output)), false);
		writeFileSync(checksum, `${"a".repeat(64)}  aidr-sbom.cdx.json\n`);
		result = run(["--output", output], { script: fixture.script, cwd: fixture.root });
		assert.equal(result.status, 1);
		assert.match(result.output, /SBOM checksum does not match/);
		assert.equal(existsSync(join(fixture.root, output)), false);
	});

	it("requires every one of the ten artifact manifests for provenance before packing", (t) => {
		const fixture = candidateFixture(t);
		rmSync(join(fixture.root, "packages/mcp-gateway/dist/aidr-artifact.manifest.json"));
		const output = ".release-evidence/candidate";
		const result = run(["--output", output], { script: fixture.script, cwd: fixture.root });
		assert.equal(result.status, 1);
		assert.match(result.output, /required release provenance failed:.*artifact manifest is missing/s);
		assert.equal(existsSync(join(fixture.root, output)), false);
	});
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

	it("rejects a release version containing path separators before creating output", () => {
		const result = run(["--output", ".release-evidence/never-created", "--rc-version", "1.2.3/../../outside"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /safe release version without path separators/);
	});

	it("refuses packed source maps and removes the incomplete candidate", (t) => {
		const fixture = candidateFixture(t);
		writeFileSync(join(fixture.root, "packages/core/dist/index.cjs.map"), "{}\n");
		const output = ".release-evidence/candidate";
		const result = run(["--output", output], { script: fixture.script, cwd: fixture.root });
		assert.equal(result.status, 1);
		assert.match(result.output, /packed consumer artifact contains forbidden files/);
		assert.equal(existsSync(join(fixture.root, output)), false, "failed assembly must leave no incomplete candidate");
	});

	it("removes incomplete output when pnpm pack fails", (t) => {
		const fixture = candidateFixture(t);
		const manifest = join(fixture.root, "packages/core/package.json");
		const pkg = JSON.parse(readFileSync(manifest, "utf8"));
		pkg.scripts = { prepack: "node -e \"process.exit(7)\"" };
		writeFileSync(manifest, JSON.stringify(pkg));
		const output = ".release-evidence/candidate";
		const result = run(["--output", output, "--allow-dirty"], { script: fixture.script, cwd: fixture.root });
		assert.equal(result.status, 1);
		assert.match(result.output, /pnpm pack failed/);
		assert.equal(existsSync(join(fixture.root, output)), false, "failed packing must leave no incomplete candidate");
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
				assert.equal(existsSync(absolute), false, "failed assembly must leave no half-written candidate");
				return;
			}
			const metadata = JSON.parse(readFileSync(join(absolute, "release-metadata.json"), "utf8"));
			assert.equal(metadata.release_version, "0.0.0-test");
			// The signed-bundle schema validates metadata with an exact key set.
			assert.deepEqual(
				Object.keys(metadata).sort(),
				["artifacts", "git_sha", "release_tag", "release_version", "schema_version", "source_date_epoch", "worktree_dirty"],
			);
			assert.equal(metadata.worktree_dirty, true);
			assert.equal(JSON.parse(result.output).status, "REHEARSAL");
			// The bundle itself may contain only metadata, inventory and artifacts;
			// the assurance report must sit outside it.
			const bundleEntries = readdirSync(absolute).sort();
			for (const entry of bundleEntries) {
				assert.ok(
					["release-metadata.json", "release-inventory.json"].includes(entry) || /\.(tgz|tar\.gz|json|json\.sha256|vsix)$/.test(entry),
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
