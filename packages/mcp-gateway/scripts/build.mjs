import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, rm } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { copyPackageLicense } from "../../../scripts/copy-package-license.mjs";

const packageRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageManifest = JSON.parse(await readFile(resolve(packageRoot, "package.json"), "utf8"));
const coreDist = resolve(packageRoot, "../core/dist");
for (const name of ["mcp-attestation.js", "mcp-transport.js", "output-scanner.js"]) {
  if (!existsSync(resolve(coreDist, name))) throw new Error("Build aidr-core before the MCP gateway");
}
const distDir = resolve(packageRoot, "dist");
if (relative(packageRoot, distDir) !== "dist") throw new Error("Unsafe gateway output directory");
await rm(distDir, { recursive: true, force: true });
await mkdir(distDir, { recursive: true });
await Promise.all([
  ["cli.mjs", "aidr-mcp-gateway.mjs"],
  ["approve.mjs", "aidr-mcp-approve.mjs"],
  ["stdio-cli.mjs", "aidr-mcp-stdio.mjs"],
].map(async ([entry, output]) => {
  await build({
    entryPoints: [resolve(packageRoot, "src", entry)],
    outfile: resolve(distDir, output),
    bundle: true,
    platform: "node",
    target: "node22.12",
    format: "esm",
    packages: "bundle",
    minify: false,
    sourcemap: false,
    legalComments: "none",
    logLevel: "warning",
  });
}));
await copyPackageLicense({ packageRoot });
execFileSync(process.execPath, [
  resolve(packageRoot, "../../scripts/generate-artifact-manifest.mjs"),
  "--dir", distDir,
  "--artifact-id", "mcp-gateway/dist",
  "--version", packageManifest.version,
], { stdio: "inherit" });
