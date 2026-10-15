#!/usr/bin/env node
// Stage what the desktop app ships next to its own code (build/runtime/, packaged
// as extraResources):
//
//   build/runtime/aidr-sea/        the standalone AIDR runtime: one multi-call aidr.exe
//                                  serving the CLI and every hook, plus the rules it
//                                  loads; built by packages/claude-code/scripts/build-sea.mjs
//                                  from the connector bundles of the workspace build
//   build/runtime/browser-guard/   the unpacked Browser Guard extension for Chrome/Edge
//                                  (release build: minified, no source maps)
//
// Run `pnpm build` at the repository root first. Options:
//   --if-missing          keep an existing staging (used by `dev`)
//   --flavor release      wrap the commercial build (see build-sea.mjs); default development
//
// A development-flavour runtime is unsigned. Release signing (Ed25519 manifests,
// Authenticode) happens in the release pipeline; see README.md "Signing".

import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(root, "..", "..");
const out = join(root, "build", "runtime");
const sea = join(out, "aidr-sea");
const extension = join(out, "browser-guard");
const flavorIndex = process.argv.indexOf("--flavor");
const flavor = flavorIndex >= 0 ? process.argv[flavorIndex + 1] : "development";

if (
	process.argv.includes("--if-missing") &&
	existsSync(join(sea, "aidr-artifact.manifest.json")) &&
	existsSync(join(extension, "manifest.json"))
) {
	console.log(`Runtime already staged in ${out} (--if-missing).`);
	process.exit(0);
}

const required = [
	"packages/claude-code/dist/pre-tool-use.bundle.cjs",
	"packages/codex/dist/pre-tool-use.bundle.cjs",
	"packages/cli/dist/index.js",
];
const missing = required.filter((path) => !existsSync(join(repo, path)));
if (missing.length > 0) {
	console.error(`Missing workspace build output (${missing.join(", ")}); run \`pnpm build\` at the repository root first.`);
	process.exit(1);
}

function run(args, label) {
	console.log(`\n> ${label}`);
	const result = spawnSync(process.execPath, args, { cwd: repo, stdio: "inherit" });
	if (result.status !== 0) {
		console.error(`${label} failed (exit ${result.status}).`);
		process.exit(result.status ?? 1);
	}
}

// --prebuilt: wrap the connector bundles of the workspace build as they are,
// instead of rebuilding them in place (which would change other packages' dist).
run(
	["packages/claude-code/scripts/build-sea.mjs", "--prebuilt", "--flavor", flavor, "--out", sea],
	`AIDR standalone runtime (${flavor} flavour) -> ${sea}`,
);

const scratch = mkdtempSync(join(tmpdir(), "aidr-desktop-bg-"));
try {
	run(
		["packages/browser-guard/scripts/build.mjs", "--release", "--out", scratch],
		"Browser Guard extension (release build)",
	);
	rmSync(extension, { recursive: true, force: true });
	cpSync(join(scratch, "chrome"), extension, { recursive: true });
} finally {
	rmSync(scratch, { recursive: true, force: true });
}

console.log(`\nStaged the desktop runtime in ${out}`);
