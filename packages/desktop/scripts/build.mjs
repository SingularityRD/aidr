#!/usr/bin/env node
// Bundle the desktop app with esbuild (the same bundler the connectors use):
//
//   dist/main/main.cjs        Electron main process (core + CLI modules bundled in)
//   dist/preload/preload.cjs  the sandboxed preload (typed IPC allowlist)
//   dist/renderer/            app.js, index.html, styles.css, icons/
//
// Electron itself and koffi (an optional native addon core can load, never on
// the code paths the app uses) stay external. No source maps ship.

import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(root, "..", "..");
const dist = join(root, "dist");
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

if (!existsSync(join(repo, "packages", "core", "dist", "index.js"))) {
	console.error("packages/core is not built; run `pnpm build` at the repository root first.");
	process.exit(1);
}

rmSync(dist, { recursive: true, force: true });

const common = {
	bundle: true,
	sourcemap: false,
	legalComments: "none",
	logLevel: "warning",
};

await esbuild.build({
	...common,
	entryPoints: [join(root, "src", "main", "main.ts")],
	outfile: join(dist, "main", "main.cjs"),
	platform: "node",
	target: "node22",
	format: "cjs",
	external: ["electron", "koffi"],
	// Core and the CLI are ESM; inside a CommonJS bundle `import.meta.url` must
	// still name the running file (core resolves its packaged resources from it).
	define: { "import.meta.url": "__aidrImportMetaUrl" },
	banner: { js: 'var __aidrImportMetaUrl = require("node:url").pathToFileURL(__filename).href;' },
});

await esbuild.build({
	...common,
	entryPoints: [join(root, "src", "preload", "preload.ts")],
	outfile: join(dist, "preload", "preload.cjs"),
	platform: "node",
	target: "node22",
	format: "cjs",
	external: ["electron"],
});

await esbuild.build({
	...common,
	entryPoints: [join(root, "src", "renderer", "app.ts")],
	outfile: join(dist, "renderer", "app.js"),
	platform: "browser",
	target: "chrome130",
	format: "iife",
});

for (const file of ["index.html", "styles.css"]) {
	copyFileSync(join(root, "src", "renderer", file), join(dist, "renderer", file));
}
const icons = join(dist, "renderer", "icons");
mkdirSync(icons, { recursive: true });
const iconSource = join(root, "assets", "icons");
if (existsSync(iconSource)) {
	for (const name of readdirSync(iconSource)) {
		if (/\.(png|ico)$/i.test(name)) copyFileSync(join(iconSource, name), join(icons, name));
	}
} else {
	console.warn("assets/icons is missing; run `pnpm --filter @singularityrd/aidr-desktop icons`.");
}
// The product mark (currentColor) is used as a CSS mask, so it takes the theme's colour.
writeFileSync(join(icons, "mark.svg"), readFileSync(join(repo, "branding", "singularity-mark.svg")));

console.log(`Built the desktop app ${version} into ${dist}`);
