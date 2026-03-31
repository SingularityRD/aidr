const esbuild = require("esbuild");
const { readdirSync, readFileSync, rmSync, writeFileSync } = require("node:fs");

const pkg = JSON.parse(readFileSync("../core/package.json", "utf-8"));
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

const shared = {
	bundle: true,
	platform: "node",
	target: "node18",
	format: "cjs",
	// Avoid shipping source maps in commercial / closed-source builds.
	sourcemap: isRelease ? false : true,
	// Even in dev builds, avoid embedding full source text into sourcemaps.
	sourcesContent: false,
	sourceRoot: "",
	// Avoid carrying third-party license/debug banners into closed-source bundles.
	legalComments: isRelease ? "none" : "eof",
	define: { __AIDR_VERSION__: JSON.stringify(pkg.version) },
};

async function build() {
	const outputs = [];
	await esbuild.build({
		...shared,
		entryPoints: ["src/cursor_extension.ts"],
		outfile: "dist/cursor_extension.js",
		external: ["vscode", "koffi"],
	});
	outputs.push("dist/cursor_extension.js");

	await esbuild.build({
		...shared,
		entryPoints: ["src/vscode_extension.ts"],
		outfile: "dist/vscode_extension.js",
		external: ["vscode", "koffi"],
	});
	outputs.push("dist/vscode_extension.js");

	await esbuild.build({
		...shared,
		entryPoints: ["src/aidr-hook.ts"],
		outfile: "dist/aidr-hook.cjs",
		external: ["koffi"],
	});
	outputs.push("dist/aidr-hook.cjs");

	for (const out of outputs) stripSourceMappingUrl(out);
	removeReleaseSourceMaps("dist");
}

build().then(
	() => {
		console.log("Build complete.");
	},
	(error) => {
		console.error(error);
		process.exitCode = 1;
	},
);
