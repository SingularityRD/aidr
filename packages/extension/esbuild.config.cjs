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

	// Cursor and VS Code spawn `node dist/aidr-hook.cjs <host>` for every hook
	// event. That stable file is a small bootstrap that enables the V8 compile
	// cache and then requires the real runner, `dist/aidr-hook.bundle.cjs`
	// (scripts/hook-bootstrap.mjs).
	const { buildHookBootstraps, hookBundleName } = await import("../../scripts/hook-bootstrap.mjs");
	const hookShared = { ...shared, external: ["koffi"] };
	const hookBundle = `dist/${hookBundleName("aidr-hook.cjs")}`;
	await esbuild.build({ ...hookShared, entryPoints: ["src/aidr-hook.ts"], outfile: hookBundle });
	outputs.push(hookBundle);
	outputs.push(
		...(await buildHookBootstraps(esbuild, hookShared, [
			{ outfile: "dist/aidr-hook.cjs", runExport: "runHookProcess" },
		])),
	);

	// Stable hook launcher, copied to ~/.singularity-aidr/extension-hooks/<host>/
	// so the managed hook command never names the versioned extension directory
	// (src/hook-launcher.ts). Node built-ins only; no source map next to the copy.
	await esbuild.build({
		...shared,
		sourcemap: false,
		entryPoints: ["src/hook-launcher.ts"],
		outfile: "dist/aidr-hook-launcher.cjs",
	});
	outputs.push("dist/aidr-hook-launcher.cjs");

	// `vscode:uninstall` hook. It runs in plain Node with no `vscode` module, so
	// the installers' `vscode` import resolves to an empty stub here.
	await esbuild.build({
		...shared,
		entryPoints: ["src/uninstall.ts"],
		outfile: "dist/aidr-uninstall.cjs",
		external: ["koffi"],
		plugins: [
			{
				name: "stub-vscode",
				setup(build) {
					build.onResolve({ filter: /^vscode$/ }, () => ({ path: "vscode", namespace: "stub" }));
					build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
						contents: "module.exports = {};",
						loader: "js",
					}));
				},
			},
		],
	});
	outputs.push("dist/aidr-uninstall.cjs");

	for (const out of outputs) stripSourceMappingUrl(out);
	removeReleaseSourceMaps("dist");

	// The hook runner loads the native AMSI addon from dist/vendor/koffi; without
	// it every Windows hook spawned PowerShell for AMSI (~400 ms per call). It is
	// covered by the dist integrity manifest like every other dist file.
	const { stageWindowsKoffi } = await import("../../scripts/stage-windows-koffi.mjs");
	stageWindowsKoffi(__dirname, { isRelease });
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
