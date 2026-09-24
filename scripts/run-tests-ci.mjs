#!/usr/bin/env node
/**
 * Deterministic test gate: build once, then run Vitest without rebuilding.
 *
 * ## Why
 *
 * The connectors' `build` scripts each start with `pnpm -C ../core build`, whose
 * first action is `rmrf dist`. When several package builds run concurrently - or
 * when every Vitest process rebuilds - they delete and recreate the same
 * `packages/core/dist` tree, and anything importing `@singularityrd/aidr-core`
 * during that window fails with "Failed to resolve entry for package". The
 * result is a red suite that has nothing to do with the code under test
 * (tracked as AIDR-014).
 *
 * This gate removes the race by construction:
 *   1. build the whole workspace once, in dependency order (core first);
 *   2. run the suite with AIDR_TEST_NO_BUILD=1, which makes the Vitest global
 *      setup verify the artifacts exist instead of rebuilding them.
 *
 * A missing artifact therefore fails loudly rather than being rebuilt under a
 * running test suite.
 */

import { spawnSync } from "node:child_process";
import { resolvePnpmEntry } from "./build-workspace.mjs";

function run(command, args, env) {
	const useWindowsPnpmEntry = process.platform === "win32" && command === "pnpm";
	const result = spawnSync(
		useWindowsPnpmEntry ? process.execPath : command,
		useWindowsPnpmEntry ? [resolvePnpmEntry(), ...args] : args,
		{
			stdio: "inherit",
			shell: false,
			env: { ...process.env, ...env },
		},
	);
	if (result.error) {
		console.error(`[test:ci] failed to run ${command}: ${result.error.message}`);
		process.exit(1);
	}
	return result.status ?? 1;
}

console.log("[test:ci] 1/2 building the workspace once, in dependency order");
const buildStatus = run("pnpm", ["build"]);
if (buildStatus !== 0) {
	console.error(`[test:ci] build failed with exit code ${buildStatus}; not running tests`);
	process.exit(buildStatus);
}

console.log("[test:ci] 2/2 running the test suite against the built artifacts");
const testStatus = run("pnpm", ["exec", "vitest", "run", ...process.argv.slice(2)], {
	AIDR_TEST_NO_BUILD: "1",
});
process.exit(testStatus);
