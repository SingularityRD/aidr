import * as esbuild from "esbuild";
import { readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { buildHookBootstraps, hookBundleName } from "../../scripts/hook-bootstrap.mjs";
import { releaseMinifyOptions } from "../../scripts/lib/release-minify.mjs";

const pkg = JSON.parse(readFileSync("../core/package.json", "utf-8"));
const isRelease =
	process.argv.includes("--release") || process.env.npm_lifecycle_event === "build:release";

function stripSourceMappingUrl(filePath) {
	if (!isRelease) return;
	try {
		const raw = readFileSync(filePath, "utf8");
		if (!raw.includes("sourceMappingURL=")) return;
		const next = raw.replace(/^[ \t]*\/\/# sourceMappingURL=.*(?:\r?\n)?/gm, "");
		if (next !== raw) writeFileSync(filePath, next, "utf8");
	} catch {
		// Best-effort: build outputs should still be usable even if stripping fails.
	}
}

function removeReleaseSourceMaps(dir) {
	if (!isRelease) return;
	try {
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			if (entry.isFile() && entry.name.endsWith(".map")) {
				rmSync(`${dir}/${entry.name}`, { force: true });
			}
		}
	} catch {
		// Best-effort cleanup only.
	}
}

function stripBuildPathReferences(filePath) {
	if (!isRelease) return;
	try {
		const raw = readFileSync(filePath, "utf8");
		const next = raw.replace(/node_modules[\\/]\.pnpm[\\/]/g, "vendor/");
		const normalized = next.replace(/ {4}\t(?=- OR -)/g, "        ");
		if (normalized !== raw) writeFileSync(filePath, normalized, "utf8");
	} catch {
		// Best-effort cleanup; manifest validation remains fail-closed.
	}
}

const shared = {
	bundle: true,
	platform: "node",
	target: "node18",
	format: "cjs",
	// koffi is a native optional dependency reached through core's AMSI client.
	// It cannot be bundled, so it stays external exactly as the other connectors do.
	external: ["koffi"],
	sourcemap: isRelease ? false : true,
	sourcesContent: false,
	sourceRoot: "",
	legalComments: isRelease ? "none" : "eof",
	// Release: minified with function/class names kept (error.name checks, stack frames).
	...releaseMinifyOptions(isRelease),
	// This output is CJS, where __dirname is always available. Keep the
	// source's ESM fallback for the separately emitted package entrypoint.
	define: { __AIDR_VERSION__: JSON.stringify(pkg.version), "import.meta.url": "undefined" },
};

// Codex spawns `node dist/pre-tool-use.cjs` for every tool call. That stable
// file is a small bootstrap that enables the V8 compile cache and then
// requires the real hook bundle (scripts/hook-bootstrap.mjs).
const bundle = `dist/${hookBundleName("pre-tool-use.cjs")}`;
await esbuild.build({
	...shared,
	entryPoints: ["src/cli.ts"],
	outfile: bundle,
});
const outputs = [bundle, ...(await buildHookBootstraps(esbuild, shared, [{ outfile: "dist/pre-tool-use.cjs" }]))];

for (const out of outputs) {
	stripSourceMappingUrl(out);
	stripBuildPathReferences(out);
}
removeReleaseSourceMaps("dist");

console.log("Build complete.");
