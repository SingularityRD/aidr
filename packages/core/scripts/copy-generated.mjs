import { cp, mkdir, readdir, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Copy the compiled AIG dataset into `dist/generated/`.
 *
 * `tsc` only emits JavaScript for `.ts` inputs, so the generated JSON indexes
 * (CVE index, fingerprints, MCP categories, data manifest) were left behind in
 * `src/generated/`. Because the package publishes only `dist/`, a published
 * install would have shipped without any of its detection data and the native
 * scanner would have silently found nothing.
 *
 * The runtime already probes `<moduleDir>/generated` first, so copying here is
 * what makes the data resolve in a packaged install.
 */

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDir, "..");
const source = join(packageRoot, "src", "generated");
const target = join(packageRoot, "dist", "generated");

if (!existsSync(source)) {
	console.error(
		`[core] missing generated data at ${source}; run "pnpm compile:aig" before building`,
	);
	process.exit(1);
}

const files = (await readdir(source)).filter((name) => name.endsWith(".json"));
if (files.length === 0) {
	console.error(`[core] no generated JSON artifacts in ${source}`);
	process.exit(1);
}

// `dist/generated/` also holds tsc output (e.g. threat-parse-cache.js), so only
// the data files are replaced; wiping the directory would delete compiled code.
await mkdir(target, { recursive: true });
for (const stale of (await readdir(target)).filter((name) => name.endsWith(".json"))) {
	await rm(join(target, stale), { force: true });
}
for (const name of files) {
	await cp(join(source, name), join(target, name));
}

console.log(`[core] copied ${files.length} generated data file(s) to dist/generated/`);
