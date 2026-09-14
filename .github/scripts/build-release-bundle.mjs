/**
 * Assemble the exact files promoted by the release workflow.
 *
 * This script deliberately packages from already-built dist directories. It
 * never runs a build or changes source files, making the promotion digest the
 * same digest that was tested and signed by the RC job. It also assembles an
 * unsigned in-toto/SLSA-style provenance statement beside the SBOM and
 * immediately re-verifies it against the manifests, lockfile and SBOM bytes.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { gzipSync, gunzipSync } from "node:zlib";
import { copyFile, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "../..");
const outputDir = resolve(process.env.RELEASE_OUTPUT_DIR ?? join(repoRoot, "release-output"));
const sourceDateEpoch = Number(process.env.SOURCE_DATE_EPOCH ?? "");
const releaseVersion = process.env.AIDR_RELEASE_VERSION;
const releaseTag = process.env.AIDR_RELEASE_TAG;
const gitSha = process.env.AIDR_BUILD_ID;

if (!Number.isInteger(sourceDateEpoch) || sourceDateEpoch < 0) fail("SOURCE_DATE_EPOCH is required");
if (!releaseVersion || !releaseTag || !gitSha) fail("AIDR_RELEASE_VERSION, AIDR_RELEASE_TAG, and AIDR_BUILD_ID are required");

const outputRelative = relative(repoRoot, outputDir);
if (!outputRelative || isAbsolute(outputRelative) || outputRelative === ".." || outputRelative.startsWith(`..${sep}`)) fail("Release output must be a child directory of the workspace");
const gitTar = join(process.env.ProgramFiles || "C:/Program Files", "Git/usr/bin/tar.exe");
const tarCommand = process.env.AIDR_TAR_BIN || (process.platform === "win32" && existsSync(gitTar) ? gitTar : "tar");
const tarVersion = spawnSync(tarCommand, ["--version"], { encoding: "utf8" });
if (tarVersion.status !== 0 || !tarVersion.stdout?.includes("GNU tar")) fail("Reproducible archives require GNU tar; configure AIDR_TAR_BIN (Git for Windows includes it)");

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
	"packages/codex",
	"packages/mcp-gateway",
];

// Locally constructed in-toto/SLSA-style provenance for the artifact manifests
// promoted from this build, bound to the lockfile and to the SBOM copied above.
// It is unsigned evidence, not a publisher attestation: generating it and then
// re-verifying it here means the bundle cannot ship a predicate that disagrees
// with the manifests, lockfile, or SBOM it accompanies.
const provenanceOutput = join(outputDir, "aidr-provenance.intoto.json");
const provenanceDirs = packageDirs
	.map((packageDir) => join(repoRoot, packageDir, "dist"))
	.filter((manifestDir) => existsSync(join(manifestDir, "aidr-artifact.manifest.json")));
if (provenanceDirs.length === 0) fail("no artifact manifests were found to build release provenance from");
const provenanceArguments = [
	...provenanceDirs.flatMap((manifestDir) => ["--artifact-dir", manifestDir]),
	"--lockfile",
	join(repoRoot, "pnpm-lock.yaml"),
	"--sbom",
	join(outputDir, "aidr-sbom.cdx.json"),
	"--output",
	provenanceOutput,
];
runNodeScript(join(repoRoot, "scripts", "generate-provenance.mjs"), provenanceArguments, "release provenance generation");
runNodeScript(
	join(repoRoot, "scripts", "generate-provenance.mjs"),
	["--verify-provenance", "--provenance", provenanceOutput, ...provenanceArguments],
	"release provenance verification",
);

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
	[".claude-plugin", "hooks", "packages/claude-code/dist", "packages/claude-code/resources", "packages/claude-code/package.json", "skills"],
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
		if (/\.map(?:\s|$)|node_modules|(?:^|\/)\.env(?:\.|$)|(?:^|\/)package\/(?:src|tests|__tests__)\/|(?:^|\/)__tests__\/|\.(?:test|spec)\.(?:[cm]?[jt]sx?|d\.ts)(?:\s|$)/im.test(listing)) {
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
		"-cf",
		`${outputPath}.tar-tmp`,
		...paths,
	];
	const result = spawnSync(tarCommand, ["--force-local", ...args], {
		cwd: repoRoot,
		encoding: "utf8",
		stdio: "inherit",
		env: { ...process.env, GZIP: "-n" },
	});
	if (result.status !== 0) fail(`tar failed for ${outputPath}`);
	// Node supplies deterministic gzip without depending on a separate Unix gzip
	// executable being on PATH when Git's GNU tar is used from PowerShell.
	writeFileSync(outputPath, gzipSync(readFileSync(`${outputPath}.tar-tmp`)));
	unlinkSync(`${outputPath}.tar-tmp`);
}

function tarList(filePath) {
	const result = spawnSync(tarCommand, ["-tf", "-"], { encoding: "utf8", input: gunzipSync(readFileSync(filePath)), maxBuffer: 8 * 1024 * 1024 });
	if (result.status !== 0) fail(`unable to inspect ${filePath}`);
	return result.stdout ?? "";
}

function runNodeScript(script, scriptArguments, label) {
	const result = spawnSync(process.execPath, [script, ...scriptArguments], {
		cwd: repoRoot,
		encoding: "utf8",
		stdio: "inherit",
	});
	if (result.error || result.status !== 0) fail(`${label} failed`);
}

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}
