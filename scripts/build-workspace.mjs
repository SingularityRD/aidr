#!/usr/bin/env node
/**
 * Workspace build with the core dependency sequenced.
 *
 * ## Why this exists instead of `pnpm -r run build`
 *
 * Every connector's build bundles `packages/core/dist/**` into its own artifact
 * (esbuild reads the emitted JavaScript directly), and every connector's build
 * script used to start with `pnpm -C ../core build` - which begins by deleting
 * that same directory. Under `pnpm -r` the packages run concurrently, so those
 * rebuilds raced each other and the bundlers: the build failed intermittently
 * with esbuild "Build failed with N errors" and, during a test run, with
 * "Failed to resolve entry for package @singularityrd/aidr-core" (AIDR-014).
 *
 * The fix is to stop expressing a dependency as "rebuild core" and sequence it
 * instead:
 *
 *   1. build core exactly once, to completion;
 *   2. build every other package with core's output already final and untouched.
 *
 * `--if-present` keeps packages without a build script from failing the run.
 */

import { spawnSync } from "node:child_process";

function pnpm(args, extraEnv) {
	const result = spawnSync("pnpm", args, {
		stdio: "inherit",
		shell: process.platform === "win32",
		env: { ...process.env, ...extraEnv },
	});
	if (result.error) {
		console.error(`[build] failed to run pnpm ${args.join(" ")}: ${result.error.message}`);
		process.exit(1);
	}
	return result.status ?? 1;
}

console.log("[build] 0/2 compiling AIG data indexes");
// Core's own build copies src/generated into dist, so the data must be compiled
// before core is built.
const aigStatus = pnpm(["run", "compile:aig"]);
if (aigStatus !== 0) {
	console.error(`[build] AIG data compilation failed with exit code ${aigStatus}`);
	process.exit(aigStatus);
}

console.log("[build] 1/2 building @singularityrd/aidr-core");
const releaseMode = process.argv.includes("--release");
const coreBuild = pnpm([
	"--filter",
	"@singularityrd/aidr-core",
	"run",
	releaseMode ? "build:release" : "build",
]);
if (coreBuild !== 0) {
	console.error(`[build] core build failed with exit code ${coreBuild}`);
	process.exit(coreBuild);
}

console.log("[build] 2/2 building the remaining packages");
// No `--if-present`: pnpm forwards an unrecognised trailing flag to the script
// itself (it reached `vite build "--if-present"`), and every workspace package
// defines a build script, so the flag is unnecessary.
const rest = pnpm(
	["-r", "--filter", "!@singularityrd/aidr-core", "run", releaseMode ? "build:release" : "build"],
	// Core is already final. Tell the per-package guard not to rebuild it, so no
	// sibling build can delete core/dist while another is bundling it.
	{ AIDR_WORKSPACE_BUILD: "1" },
);
process.exit(rest);
