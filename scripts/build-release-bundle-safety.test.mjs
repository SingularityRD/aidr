import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "..");
const builder = path.join(repoRoot, ".github", "scripts", "build-release-bundle.mjs");

function run(outputDirectory) {
	return spawnSync(process.execPath, [builder], {
		cwd: repoRoot,
		encoding: "utf8",
		windowsHide: true,
		env: {
			...process.env,
			RELEASE_OUTPUT_DIR: outputDirectory,
			SOURCE_DATE_EPOCH: "0",
			AIDR_RELEASE_VERSION: "1.2.3",
			AIDR_RELEASE_TAG: "v1.2.3-rc.0",
			AIDR_GIT_SHA: "a".repeat(40),
		},
	});
}

test("release assembly refuses paths that could overwrite workspace or Git data", () => {
	const gitHead = path.join(repoRoot, ".git", "HEAD");
	assert.ok(existsSync(gitHead), "test requires the repository's Git metadata directory");
	const originalHead = readFileSync(gitHead);
	const result = run(path.join(repoRoot, ".git"));
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /direct child directory named release-output/u);
	assert.deepEqual(readFileSync(gitHead), originalHead);
});

test("release assembly preserves an existing output directory instead of recursively deleting it", (t) => {
	const outputDirectory = path.join(repoRoot, `release-output-audit-test-${process.pid}`);
	assert.equal(existsSync(outputDirectory), false, "test output path must be unique");
	mkdirSync(outputDirectory);
	t.after(() => rmSync(outputDirectory, { recursive: true, force: true }));
	const marker = path.join(outputDirectory, "keep-me.txt");
	writeFileSync(marker, "existing customer evidence\n");

	const result = run(outputDirectory);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /Release output already exists/u);
	assert.equal(readFileSync(marker, "utf8"), "existing customer evidence\n");
});
