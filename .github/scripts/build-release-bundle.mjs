/**
 * Assemble the exact files promoted by the release workflow.
 *
 * This script deliberately packages from already-built dist directories. It
 * never runs a build or changes source files, making the promotion digest the
 * same digest that was tested and signed by the RC job.
 */

import { createHash } from "node:crypto";
import { copyFile, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "../..");
const outputDir = resolve(process.env.RELEASE_OUTPUT_DIR ?? join(repoRoot, "release-output"));
const sourceDateEpoch = Number(process.env.SOURCE_DATE_EPOCH ?? "");
const releaseVersion = process.env.AIDR_RELEASE_VERSION;
const releaseTag = process.env.AIDR_RELEASE_TAG;
const gitSha = process.env.AIDR_BUILD_ID;

if (!Number.isInteger(sourceDateEpoch) || sourceDateEpoch < 0) fail("SOURCE_DATE_EPOCH is required");
if (!releaseVersion || !releaseTag || !gitSha) fail("AIDR_RELEASE_VERSION, AIDR_RELEASE_TAG, and AIDR_BUILD_ID are required");

await rm(outputDir, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });

const sbomSource = join(repoRoot, ".release-evidence", "aidr-sbom.cdx.json");
const sbomChecksumSource = `${sbomSource}.sha256`;
await copyFile(sbomSource, join(outputDir, "aidr-sbom.cdx.json"));
await copyFile(sbomChecksumSource, join(outputDir, "aidr-sbom.cdx.json.sha256"));

const packageDirs = [
	"packages/core",
	"packages/claude-code",
	"packages/extension",
	"packages/openclaw",
	"packages/opencode",
	"packages/cli",
	"packages/sdk",
	"packages/dashboard",
];

for (const packageDir of packageDirs) {
	// Windows exposes pnpm as a .cmd shim; Node's direct spawn path can return
	// EINVAL for that shim (notably when stdio is inherited). Using the shell
	// only on Windows lets the same helper run in local release rehearsals while
	// keeping the Linux CI path as a direct, non-shell process.
	const result = spawnSync(process.platform === "win32" ? "pnpm.cmd" : "pnpm", ["-C", packageDir, "pack", "--pack-destination", outputDir], {
		cwd: repoRoot,
		encoding: "utf8",
		stdio: "inherit",
		shell: process.platform === "win32",
	});
	if (result.status !== 0) fail(`pnpm pack failed for ${packageDir}`);
}

createTarball(
	join(outputDir, `aidr-claude-plugin-${releaseVersion}.tar.gz`),
	[".claude-plugin", "packages/claude-code/dist", "packages/claude-code/package.json", "skills"],
);
createTarball(
	join(outputDir, `aidr-dashboard-dist-${releaseVersion}.tar.gz`),
	["packages/dashboard/dist", "packages/dashboard/package.json", "packages/dashboard/vercel.json"],
);

const artifacts = [];
for (const entry of await readdir(outputDir, { withFileTypes: true })) {
	if (!entry.isFile()) continue;
	const filePath = join(outputDir, entry.name);
	const bytes = await readFile(filePath);
	if (entry.name.endsWith(".map") || /(?:\.env|node_modules)/i.test(entry.name)) {
		fail(`forbidden artifact ${entry.name}`);
	}
	if (entry.name.endsWith(".tgz")) {
		const listing = tarList(filePath);
		if (/\.map(?:\s|$)|node_modules|(?:^|\/)\.env(?:\.|$)/i.test(listing)) {
			fail(`packed consumer artifact contains forbidden files: ${entry.name}`);
		}
	}
	artifacts.push({ path: entry.name, size: bytes.byteLength, sha256: createHash("sha256").update(bytes).digest("hex") });
}
artifacts.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

await writeFile(
	join(outputDir, "release-metadata.json"),
	`${JSON.stringify({ schema_version: 1, release_tag: releaseTag, release_version: releaseVersion, git_sha: gitSha, source_date_epoch: sourceDateEpoch, artifacts }, null, 2)}\n`,
	"utf8",
);

// The bundle manifest verifier treats release/bundle specially and requires a
// signed inventory that independently maps every staged file to its digest.
// Keep this inventory deliberately boring: the manifest itself and its
// signature are generated after this helper returns and must not self-reference.
await writeFile(
	join(outputDir, "release-inventory.json"),
	`${JSON.stringify(
		{
			schema_version: 1,
			artifacts: artifacts.map((entry) => ({
				source_path: `release-output/${entry.path}`,
				staged_path: entry.path,
				kind: "release-artifact",
				sha256: entry.sha256,
			})),
		},
		null,
	)}\n`,
	"utf8",
);

console.log(`Release bundle assembled in ${outputDir} (${artifacts.length} artifacts)`);

function createTarball(outputPath, paths) {
	const args = [
		"--sort=name",
		`--mtime=@${sourceDateEpoch}`,
		"--owner=0",
		"--group=0",
		"--numeric-owner",
		"-czf",
		outputPath,
		...paths,
	];
	const result = spawnSync("tar", args, {
		cwd: repoRoot,
		encoding: "utf8",
		stdio: "inherit",
		env: { ...process.env, GZIP: "-n" },
	});
	if (result.status !== 0) fail(`tar failed for ${outputPath}`);
}

function tarList(filePath) {
	const result = spawnSync("tar", ["-tzf", filePath], { encoding: "utf8" });
	if (result.status !== 0) fail(`unable to inspect ${filePath}`);
	return result.stdout ?? "";
}

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}
