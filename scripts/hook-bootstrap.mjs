// Build tiny per-call hook bootstraps that enable Node's on-disk compile cache
// before loading the real (multi-megabyte) hook bundle.
//
// `module.enableCompileCache()` only affects modules loaded after the call, so
// it cannot live inside the bundle it is meant to speed up. Each connector
// therefore ships:
//
//   dist/<name>.cjs         the stable, host-referenced entry (this bootstrap)
//   dist/<name>.bundle.cjs  the real hook bundle, required by the bootstrap
//
// The bootstrap is bundled with esbuild so it carries its own copy of core's
// `enableHookCompileCache` (and the private-directory helper it uses) without
// pulling in the rest of core. Enabling the cache is best-effort and silent
// (it never throws or prints); the bundle's own verdict and error handling are
// untouched, and a bundle that fails to load fails closed (see below).

import { chmodSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORE_MODULE = join(repoRoot, "packages", "core", "dist", "hook-compile-cache.js");

// A bundle that cannot be loaded (missing next to the bootstrap, unreadable,
// or throwing during module initialisation) must block, not pass the call
// through. Exit 2 with a stderr reason is the blocking-error answer of every
// host these bootstraps serve (Claude Code, Codex, Cursor and VS Code hooks);
// the default Node crash (exit 1) is a non-blocking error for them.
const LOAD_FAILURE_EXIT_CODE = 2;
const LOAD_FAILURE_MESSAGE = "Singularity AIDR hook failed to load; execution was denied.";

/** `pre-tool-use.cjs` -> `pre-tool-use.bundle.cjs`. */
export function hookBundleName(bootstrapName) {
	if (!bootstrapName.endsWith(".cjs")) throw new Error(`hook bootstrap must be a .cjs file: ${bootstrapName}`);
	return `${bootstrapName.slice(0, -".cjs".length)}.bundle.cjs`;
}

/** Source of one bootstrap. `runExport` names a function the bundle exports to start the hook. */
function hookBootstrapSource(bundleName, { runExport } = {}) {
	if (!/^[\w.-]+\.bundle\.cjs$/.test(bundleName)) throw new Error(`unexpected hook bundle name: ${bundleName}`);
	const load = `require(require("node:path").join(__dirname, ${JSON.stringify(bundleName)}))`;
	return [
		`import { enableHookCompileCache } from ${JSON.stringify(CORE_MODULE)};`,
		"enableHookCompileCache();",
		"try {",
		runExport ? `\t${load}.${runExport}();` : `\t${load};`,
		"} catch {",
		`\tprocess.stderr.write(${JSON.stringify(`${LOAD_FAILURE_MESSAGE}\n`)});`,
		`\tprocess.exitCode = ${LOAD_FAILURE_EXIT_CODE};`,
		"}",
		"",
	].join("\n");
}

/**
 * Build one bootstrap per entry with the caller's esbuild instance.
 *
 * @param {{ build: (options: object) => Promise<unknown> }} esbuild the caller's esbuild module
 * @param {object} shared esbuild options shared with the connector's bundles
 * @param {{ outfile: string, runExport?: string }[]} entries outfile is the stable `dist/<name>.cjs`
 * @returns {Promise<string[]>} the bootstrap outfiles
 */
export async function buildHookBootstraps(esbuild, shared, entries) {
	await Promise.all(
		entries.map(({ outfile, runExport }) =>
			esbuild.build({
				...shared,
				// Hosts and npm bin shims execute this file directly, like the bundles
				// it replaces as the entry point.
				banner: { ...shared.banner, js: "#!/usr/bin/env node" },
				stdin: {
					contents: hookBootstrapSource(hookBundleName(outfile.split(/[\\/]/).pop()), { runExport }),
					resolveDir: repoRoot,
					sourcefile: "hook-bootstrap.js",
					loader: "js",
				},
				outfile,
			}),
		),
	);
	// Executable like the hashbang bundles esbuild emits (npm bin shims link to it).
	if (process.platform !== "win32") for (const { outfile } of entries) chmodSync(outfile, 0o755);
	return entries.map(({ outfile }) => outfile);
}
