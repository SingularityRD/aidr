/**
 * Generate (and optionally sign) artifact manifests for connector dist/ directories.
 *
 * This is intended for commercial / closed-source release pipelines.
 *
 * Env:
 * - AIDR_SIGNING_PRIVATE_KEY_PEM_PATH: if set, manifests are signed
 * - AIDR_SIGNING_KEY_ID: optional key id to embed in the manifest
 * - AIDR_WATERMARK_ID: optional watermark id (recommended for commercial lineage)
 * - AIDR_REQUIRE_SIGNING=1: fail if signing key is missing
 */

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

// This script is invoked from repo root in CI/release pipelines.
const repoRoot = process.cwd();

const keyPath = process.env.AIDR_SIGNING_PRIVATE_KEY_PEM_PATH;
const requireSigning = process.env.AIDR_REQUIRE_SIGNING === "1";
const keyId = process.env.AIDR_SIGNING_KEY_ID;

const targets = [
	{ pkg: "packages/claude-code/package.json", dir: "packages/claude-code/dist", artifactId: "claude-code/dist" },
	{ pkg: "packages/extension/package.json", dir: "packages/extension/dist", artifactId: "extension/dist" },
	{ pkg: "packages/openclaw/package.json", dir: "packages/openclaw/dist", artifactId: "openclaw/dist" },
	{ pkg: "packages/opencode/package.json", dir: "packages/opencode/dist", artifactId: "opencode/dist" },
];

if (requireSigning && !keyPath) {
	console.error("ERROR: AIDR_REQUIRE_SIGNING=1 but AIDR_SIGNING_PRIVATE_KEY_PEM_PATH is not set.");
	process.exit(1);
}

for (const t of targets) {
	const pkgPath = path.join(repoRoot, t.pkg);
	const distDir = path.join(repoRoot, t.dir);
	const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
	const version = String(pkg.version ?? "0.0.0");

	run([
		"scripts/generate-artifact-manifest.mjs",
		"--dir",
		distDir,
		"--id",
		t.artifactId,
		"--version",
		version,
		...(keyId ? ["--key-id", keyId] : []),
	]);

	if (keyPath) {
		run(["scripts/sign-artifact-manifest.mjs", "--dir", distDir, "--key", keyPath]);
	}
}

function run(argv) {
	const res = spawnSync(process.execPath, argv, {
		cwd: repoRoot,
		stdio: "inherit",
	});
	if (res.status !== 0) process.exit(res.status ?? 1);
}
