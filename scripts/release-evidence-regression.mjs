/**
 * Focused regression checks for release-evidence content validation.
 *
 * Run with:
 *   node scripts/release-evidence-regression.mjs
 *
 * The fixtures live in an OS temp directory and are removed on completion;
 * no test credential is written to the repository.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const repoRoot = path.resolve(import.meta.dirname, "..");
const generator = path.join(repoRoot, "scripts", "generate-artifact-manifest.mjs");
let fixtureRoot;

try {
	fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "aidr-release-evidence-"));

	await writeFile(
		path.join(fixtureRoot, "comment.d.ts"),
		`/**\n * Public documentation example (not a credential): AKIAIOSFODNN7EXAMPLE\n */\nexport type Example = string;\n`,
		"utf8",
	);
	const documented = runGenerator(fixtureRoot);
	assert.equal(documented.status, 0, `documentation fixture should pass:\n${formatResult(documented)}`);

	await writeFile(path.join(fixtureRoot, "detector.js"), 'export const pattern = /\\bAKIA[0-9A-Z]{16}\\b/g;\n', "utf8");
	const detectorPattern = runGenerator(fixtureRoot);
	assert.equal(detectorPattern.status, 0, `detector regex literals should pass:\n${formatResult(detectorPattern)}`);

	await writeFile(
		path.join(fixtureRoot, "bundle.cjs"),
		`// ../../node_modules/.pnpm/example@1.0.0/node_modules/example/index.js\nexport const moduleId = "../../node_modules/.pnpm/example@1.0.0/node_modules/example/index.js";\n`,
		"utf8",
	);
	const generatedMetadata = runGenerator(fixtureRoot);
	assert.equal(generatedMetadata.status, 0, `relative bundler metadata should pass:\n${formatResult(generatedMetadata)}`);

	await writeFile(path.join(fixtureRoot, "actual.js"), 'export const token = "AKIAIOSFODNN7EXAMPLE";\n', "utf8");
	const executable = runGenerator(fixtureRoot);
	assert.notEqual(executable.status, 0, "a token in executable source must be rejected");
	assert.match(`${executable.stdout}\n${executable.stderr}`, /Secret-like content/i);

	await rm(path.join(fixtureRoot, "actual.js"), { force: true });
	await writeFile(path.join(fixtureRoot, "absolute-path.js"), 'export const pathLeak = "/home/demo/node_modules/.pnpm/pkg@1.0.0";\n', "utf8");
	const absolutePath = runGenerator(fixtureRoot);
	assert.notEqual(absolutePath.status, 0, "absolute dependency-store paths must be rejected");
	assert.match(`${absolutePath.stdout}\n${absolutePath.stderr}`, /Host-path leak/i);

	await rm(path.join(fixtureRoot, "absolute-path.js"), { force: true });
	await writeFile(path.join(fixtureRoot, "source.js.map"), '{"version":3,"sources":[]}\n', "utf8");
	const sourceMap = runGenerator(fixtureRoot);
	assert.notEqual(sourceMap.status, 0, "source maps must be rejected from release artifacts");
	assert.match(`${sourceMap.stdout}\n${sourceMap.stderr}`, /Source map/i);

	console.log("Release evidence scanner regression checks passed.");
} finally {
	if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
}

function runGenerator(dir) {
	return spawnSync(
		process.execPath,
		[generator, "--dir", dir, "--id", "regression-fixture", "--version", "0.0.0"],
		{ cwd: repoRoot, encoding: "utf8" },
	);
}

function formatResult(result) {
	return `status=${result.status}\nstdout=${result.stdout ?? ""}\nstderr=${result.stderr ?? ""}`;
}
