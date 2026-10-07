import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, rm } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { copyPackageLicense } from "../../../scripts/copy-package-license.mjs";
import { GATEWAY_ENTRIES, gatewayBundleOptions, readRuleSets } from "./bundle-options.mjs";

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageManifest = JSON.parse(await readFile(resolve(packageRoot, "package.json"), "utf8"));
// The gateway imports @singularityrd/aidr-core by package name; its export
// points at the compiled dist, so core must be built first.
if (!existsSync(resolve(packageRoot, "node_modules/@singularityrd/aidr-core/dist/index.js")))
  throw new Error("Build aidr-core before the MCP gateway");
const distDir = resolve(packageRoot, "dist");
if (relative(packageRoot, distDir) !== "dist") throw new Error("Unsafe gateway output directory");
const ruleSets = await readRuleSets();
await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });
await Promise.all(GATEWAY_ENTRIES.map(async ([entry, output]) => {
  await build({
    ...gatewayBundleOptions({ ruleSets }),
    entryPoints: [resolve(packageRoot, "src", entry)],
    outfile: resolve(distDir, output),
  });
}));
await copyPackageLicense({ packageRoot });
execFileSync(process.execPath, [
  resolve(packageRoot, "../../scripts/generate-artifact-manifest.mjs"),
  "--dir", distDir,
  "--artifact-id", "mcp-gateway/dist",
  "--version", packageManifest.version,
], { stdio: "inherit" });
