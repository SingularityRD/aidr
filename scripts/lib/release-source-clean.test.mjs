import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { assertReleaseSourceClean } from "./release-source-clean.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

function git(root, ...args) {
	const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
	assert.equal(result.status, 0, result.stderr || result.error?.message);
}

function fixture(t) {
	const root = mkdtempSync(join(tmpdir(), "aidr-release-source-clean-"));
	t.after(() => {
		const absolute = resolve(root);
		assert.ok(absolute.startsWith(`${resolve(tmpdir())}${sep}`));
		assert.match(absolute.split(sep).at(-1), /^aidr-release-source-clean-/u);
		rmSync(absolute, { recursive: true, force: true });
	});
	git(root, "init", "-q");
	mkdirSync(join(root, "src"));
	mkdirSync(join(root, "packages", "claude-code", "dist"), { recursive: true });
	writeFileSync(join(root, "src", "index.ts"), "export const source = 1;\n");
	writeFileSync(join(root, "packages", "claude-code", "dist", "health.cjs"), "module.exports = 1;\n");
	git(root, "add", ".");
	git(root, "-c", "user.name=AIDR Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture");
	return root;
}

test("tracked dist edits and exact generated outputs do not mask dirty source", (t) => {
	const root = fixture(t);
	writeFileSync(join(root, "packages", "claude-code", "dist", "health.cjs"), "module.exports = 2;\n");
	writeFileSync(join(root, "packages", "claude-code", "aidr-artifact.manifest.json"), "{}\n");
	mkdirSync(join(root, ".release-evidence"));
	writeFileSync(join(root, ".release-evidence", "index.json"), "{}\n");
	mkdirSync(join(root, "release-output"));
	writeFileSync(join(root, "release-output", "bundle.tgz"), "fixture\n");
	assert.doesNotThrow(() => assertReleaseSourceClean(root));

	writeFileSync(join(root, "src", "untracked.ts"), "export const rogue = true;\n");
	assert.throws(() => assertReleaseSourceClean(root), /src\/untracked\.ts/u);
	rmSync(join(root, "src", "untracked.ts"));
	writeFileSync(join(root, "src", "index.ts"), "export const source = 2;\n");
	assert.throws(() => assertReleaseSourceClean(root), /src\/index\.ts/u);
});

test("output override cannot exempt arbitrary source directories", (t) => {
	const root = fixture(t);
	for (const outputRelative of ["src", "../src", "packages/core/dist", "release-output/../src", "C:\\src"]) {
		assert.throws(() => assertReleaseSourceClean(root, { outputRelative }), /release output must be a direct child/u);
	}
	mkdirSync(join(root, "release-output-rc"));
	writeFileSync(join(root, "release-output-rc", "candidate.tgz"), "fixture\n");
	assert.doesNotThrow(() => assertReleaseSourceClean(root, { outputRelative: "release-output-rc" }));
	assert.throws(() => assertReleaseSourceClean(root), /release-output-rc\/candidate\.tgz/u);
});

test("lookalike output paths and source-to-dist renames remain dirty", (t) => {
	const root = fixture(t);
	mkdirSync(join(root, "packages", "unlisted", "dist"), { recursive: true });
	writeFileSync(join(root, "packages", "unlisted", "dist", "payload.js"), "fixture\n");
	assert.throws(() => assertReleaseSourceClean(root), /packages\/unlisted\/dist\/payload\.js/u);
	rmSync(join(root, "packages", "unlisted", "dist", "payload.js"));
	git(root, "mv", "src/index.ts", "packages/claude-code/dist/index.ts");
	assert.throws(() => assertReleaseSourceClean(root), /clean source worktree/u);
});

test("release workflow and assemblers use the shared source-clean proof", () => {
	const workflow = readFileSync(join(repositoryRoot, ".github", "workflows", "release-rc.yml"), "utf8");
	const builder = readFileSync(join(repositoryRoot, ".github", "scripts", "build-release-bundle.mjs"), "utf8");
	const manifests = readFileSync(join(repositoryRoot, "scripts", "release-artifact-manifests.mjs"), "utf8");
	assert.equal((workflow.match(/node scripts\/lib\/release-source-clean\.mjs/gu) ?? []).length, 3);
	assert.match(builder, /import[^;]*release-source-clean\.mjs/su);
	assert.match(builder, /assertReleaseSourceClean\(/u);
	assert.match(manifests, /import[^;]*release-source-clean\.mjs/su);
	assert.match(manifests, /assertReleaseSourceClean\(/u);
});
