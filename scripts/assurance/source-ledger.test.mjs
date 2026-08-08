import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

import { buildLedger } from "./source-ledger.mjs";

const temporaryDirectories = [];

afterEach(async () => {
	await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

test("source assurance ledger is deterministic and reports critical exclusions", async () => {
	const rootDir = await makeFixture({
		"packages/alpha/src/z.ts": "z\n\n",
		"packages/alpha/src/a.ts": "a\nb\n",
		"packages/alpha/src/critical.ts": "critical\n",
		"packages/alpha/src/__tests__/ignored.test.ts": "ignored\n",
		"packages/alpha/src/ignored.test.ts": "ignored\n",
		"vitest.config.ts": `coverage: { exclude: [\n\t\t\"packages/alpha/src/critical.ts\",\n\t] }`,
	});

	const options = {
		rootDir,
		exclusionRegistry: { "packages/alpha/src/critical.ts": { reason: "dedicated evidence" } },
	};
	const first = await buildLedger(options);
	const second = await buildLedger(options);

	assert.deepEqual(second, first);
	assert.deepEqual(first.totals, { files: 3, lines: 5 });
	assert.deepEqual(first.files.map(({ path: filePath }) => filePath), [
		"packages/alpha/src/a.ts",
		"packages/alpha/src/critical.ts",
		"packages/alpha/src/z.ts",
	]);
	assert.deepEqual(first.files.map(({ lines }) => lines), [2, 1, 2]);
	assert.deepEqual(first.critical_files, [
		{ path: "packages/alpha/src/critical.ts", lines: 1, reason: "dedicated evidence", coverageExcluded: true },
	]);
});

test("fails closed when a first-party coverage exclusion has no accounting entry", async () => {
	const rootDir = await makeFixture({
		"packages/alpha/src/unaccounted.ts": "export const value = 1;\n",
		"vitest.config.ts": `coverage: { exclude: [\n\t\t\"packages/alpha/src/unaccounted.ts\",\n\t] }`,
	});

	await assert.rejects(
		buildLedger({ rootDir, exclusionRegistry: {} }),
		/Unaccounted first-party coverage exclusion: packages\/alpha\/src\/unaccounted\.ts/,
	);
});

test("classifies generated files and records traceability fields without inventing coverage", async () => {
	const rootDir = await makeFixture({
		"packages/alpha/src/index.ts": "export const value = 1;\n",
		"packages/alpha/src/generated/data.json": "{\"value\":1}\n",
		"services/aig-bridge/app/main.py": "def main():\n    return True\n",
		"supabase/functions/ping/index.ts": "export const ping = true;\n",
	});

	const ledger = await buildLedger({ rootDir, coverageConfigPath: null, exclusionRegistry: {} });
	const generated = ledger.files.find(({ path: filePath }) => filePath.endsWith("generated/data.json"));
	const firstParty = ledger.files.find(({ path: filePath }) => filePath.endsWith("src/index.ts"));

	assert.equal(generated.classification, "generated");
	assert.equal(firstParty.classification, "first-party");
	assert.match(firstParty.hash, /^sha256:[a-f0-9]{64}$/);
	assert.equal(firstParty.line_count, 1);
	assert.equal(firstParty.coverage.status, "not-recorded");
	assert.equal(firstParty.coverage.lines, null);
	assert.equal(typeof firstParty.risk, "string");
	assert.equal(typeof firstParty.owner, "string");
	assert.ok(Array.isArray(firstParty.requirements));
	assert.ok(Array.isArray(firstParty.tests));
	assert.deepEqual(ledger.source_roots, ["packages", "services/aig-bridge/app", "supabase/functions"]);
});

test("fails closed when a coverage glob excludes an unaccounted source file", async () => {
	const rootDir = await makeFixture({
		"packages/alpha/src/critical.ts": "export const value = 1;\n",
	});

	await assert.rejects(
		buildLedger({
			rootDir,
			coverageExclusions: ["packages/alpha/src/*.ts"],
			exclusionRegistry: {},
		}),
		/Unaccounted first-party coverage exclusion: packages\/alpha\/src\/critical\.ts/,
	);
});

async function makeFixture(files) {
	const rootDir = await mkdtemp(path.join(os.tmpdir(), "aidr-source-ledger-"));
	temporaryDirectories.push(rootDir);
	for (const [relativePath, contents] of Object.entries(files)) {
		const filePath = path.join(rootDir, ...relativePath.split("/"));
		await mkdir(path.dirname(filePath), { recursive: true });
		await writeFile(filePath, contents, "utf8");
	}
	return rootDir;
}
