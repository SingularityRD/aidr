import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { GATES } from "./generate-v8-evidence-index.mjs";

const runnerSource = readFileSync(fileURLToPath(new URL("./run-evidence-gates.mjs", import.meta.url)), "utf8");

function run(...args) {
	return spawnSync(process.execPath, ["scripts/run-evidence-gates.mjs", ...args], { encoding: "utf8" });
}

test("evidence runner refuses collisions without recursive deletion or rename sweeps", () => {
	assert.match(runnerSource, /protectedOutputs/);
	assert.match(runnerSource, /fixed output paths already contain prior artifacts/);
	assert.doesNotMatch(runnerSource, /\b(?:rmSync|renameSync)\s*\(/);
	assert.doesNotMatch(runnerSource, /\.locked-\\d/);
	assert.ok(runnerSource.indexOf("const collisions = existingOutputPaths(protectedOutputs)") < runnerSource.indexOf('console.log("[gates] pnpm build:release")'));
});

test("first-customer local profile declares every gate without running or silently passing field gates", () => {
	const result = run("--profile", "first-customer-local", "--list");
	assert.equal(result.status, 0, result.stderr);
	const lines = result.stdout.trim().split(/\r?\n/);
	const selected = lines.filter((line) => line.startsWith("RUN ")).map((line) => line.slice(4));
	const deferred = lines.filter((line) => line.startsWith("NOT_RUN ")).map((line) => line.split(" ")[1]);
	assert.deepEqual(deferred, ["18-native-host", "19-release-e2e", "25-customer-onboarding", "30-commercial-gates"]);
	assert.match(lines[0], /26 local gates; 4 field\/approval gates remain NOT_RUN/);
	assert.match(result.stdout, /NOT_RUN 30-commercial-gates \(direct-GA commercial approvals required\)/);
	assert.deepEqual([...selected, ...deferred].sort(), GATES.map((gate) => gate.gate_id).sort());
	assert.equal(new Set(selected).size, selected.length);
});

test("profile rejects an unknown name and shortcuts that would weaken candidate binding", () => {
	for (const args of [
		["--profile", "unknown", "--list"],
		["--profile", "first-customer-local", "--skip-build", "--list"],
		["--profile", "first-customer-local", "--only", "01-git-diff-check", "--list"],
		["--only", "not-a-gate"],
	]) {
		const result = run(...args);
		assert.equal(result.status, 1, `${args.join(" ")}: ${result.stdout}`);
		assert.match(result.stderr, /invalid gate selection/);
	}
});
