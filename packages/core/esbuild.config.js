// esbuild config for test builds — transpiles TypeScript without type-checking.
// Vitest unit tests import @singularityrd/aidr-core which resolves to dist/index.js.
// This build produces that file quickly, ignoring type errors in source.
import * as esbuild from "esbuild";

await esbuild.build({
	entryPoints: ["src/index.ts"],
	bundle: true,
	platform: "node",
	target: "node18",
	format: "esm",
	outfile: "dist/index.js",
	sourcemap: false,
	// Keep all node_modules external — vitest resolves them at test time.
	external: [
		"@opentelemetry/*",
		"@sentry/node",
		"pino",
		"semver",
		"yaml",
		"zod",
		"koffi",
	],
	legalComments: "none",
	sourcesContent: false,
});

console.log("Core build (test) complete.");
