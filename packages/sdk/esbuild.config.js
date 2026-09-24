import * as esbuild from "esbuild";
import { readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync("./package.json", "utf-8"));
const isRelease =
	process.argv.includes("--release") || process.env.npm_lifecycle_event === "build:release";

function stripSourceMappingUrl(filePath) {
	if (!isRelease) return;
	try {
		const raw = readFileSync(filePath, "utf8");
		if (!raw.includes("sourceMappingURL=")) return;
		const next = raw.replace(/^[ \t]*\/\/# sourceMappingURL=.*(?:\r?\n)?/gm, "");
		if (next !== raw) {
			writeFileSync(filePath, next, "utf8");
		}
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

// Build ESM bundle
await esbuild.build({
	bundle: true,
	platform: "node",
	target: "node22.12",
	format: "esm",
	outExtension: { ".js": ".mjs" },
	sourcemap: isRelease ? false : true,
	sourcesContent: false,
	sourceRoot: "",
	legalComments: isRelease ? "none" : "eof",
	// Keep the ESM entrypoint linked to the core package so consumers can
	// share one engine instance in a workspace or installation.
	external: ["@singularityrd/aidr-core", "koffi", "@sentry/node", "pino", "yaml", "zod"],
	entryPoints: ["src/index.ts"],
	outfile: "dist/index.mjs",
	define: { __AIDR_VERSION__: JSON.stringify(pkg.version) },
});

// Build CJS bundle
await esbuild.build({
	bundle: true,
	platform: "node",
	target: "node22.12",
	format: "cjs",
	sourcemap: isRelease ? false : true,
	sourcesContent: false,
	sourceRoot: "",
	legalComments: isRelease ? "none" : "eof",
	external: ["koffi"],
	entryPoints: ["src/index.ts"],
	outfile: "dist/index.cjs",
	define: { __AIDR_VERSION__: JSON.stringify(pkg.version) },
});

stripSourceMappingUrl("dist/index.mjs");
stripSourceMappingUrl("dist/index.cjs");
removeReleaseSourceMaps("dist");

console.log("Build complete.");
