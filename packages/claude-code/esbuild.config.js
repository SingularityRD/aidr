import * as esbuild from "esbuild";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stageWindowsKoffi } from "../../scripts/stage-windows-koffi.mjs";

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

// esbuild's bundled module labels include the pnpm virtual-store path in
// otherwise valid JavaScript comments and loader keys. Those machine-specific
// paths are not part of runtime behaviour, but release manifests correctly
// reject them as provenance leaks. Normalize only this generated prefix so
// release artifacts remain portable and deterministic without changing code.
function stripBuildPathReferences(filePath) {
	if (!isRelease) return;
	try {
		const raw = readFileSync(filePath, "utf8");
		const next = raw.replace(/node_modules[\\/]\.pnpm[\\/]/g, "vendor/");
		// Normalize the template literal's mixed indentation (four spaces + tab)
		// emitted by esbuild into stable spaces for diff/release scanners.
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
	external: ["koffi"],
	// Avoid shipping source maps in commercial / closed-source builds.
	sourcemap: isRelease ? false : true,
	// Even in dev builds, avoid embedding full source text into sourcemaps.
	sourcesContent: false,
	sourceRoot: "",
	// Avoid carrying third-party license/debug banners into closed-source bundles.
	legalComments: isRelease ? "none" : "eof",
	define: { __AIDR_VERSION__: JSON.stringify(pkg.version) },
};

const outputs = [
	"dist/pre-tool-use.cjs",
	"dist/post-tool-use.cjs",
	"dist/mcp-server.cjs",
	"dist/session-start.cjs",
	"dist/health.cjs",
	"dist/response-worker.cjs",
	"dist/user-prompt-submit.cjs",
];


await Promise.all([
	esbuild.build({ ...shared, entryPoints: ["src/pre-tool-use.ts"], outfile: outputs[0] }),
	esbuild.build({ ...shared, entryPoints: ["src/post-tool-use.ts"], outfile: outputs[1] }),
	esbuild.build({ ...shared, entryPoints: ["src/mcp-server.ts"], outfile: outputs[2] }),
	esbuild.build({ ...shared, entryPoints: ["src/session-start.ts"], outfile: outputs[3] }),
	esbuild.build({ ...shared, entryPoints: ["src/health.ts"], outfile: outputs[4] }),
	esbuild.build({ ...shared, entryPoints: ["src/response-worker.ts"], outfile: outputs[5] }),
	esbuild.build({ ...shared, entryPoints: ["src/user-prompt-submit.ts"], outfile: outputs[6] }),
]);

// The customer kit and endpoint installer intentionally omit node_modules:
// keep the native AMSI addon inside the manifest-covered dist.
stageWindowsKoffi(dirname(fileURLToPath(import.meta.url)), { isRelease });
// Keep the fixed native adapter inside the same integrity-verified connector.
mkdirSync(join("dist", "native"), { recursive: true });
for (const script of ["Invoke-AidrResponseAction.ps1", "Common.ps1"]) {
	copyFileSync(
		join("..", "..", "deploy", "fleet", "windows", script),
		join("dist", "native", script),
	);
}

for (const out of outputs) {
	stripSourceMappingUrl(out);
	stripBuildPathReferences(out);
}
removeReleaseSourceMaps("dist");

console.log("Build complete.");
