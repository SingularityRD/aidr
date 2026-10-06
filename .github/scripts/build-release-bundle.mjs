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
import { gzipSync } from "node:zlib";
import { copyFile, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { isConsumerArchive } from "../../scripts/lib/package-artifact-rules.mjs";
import {
	claudePluginArchivePaths,
	assertClaudePluginPackage,
	assertClaudePluginResourcesCanonical,
	claudePluginRequiredFiles,
} from "../../scripts/lib/claude-plugin-package.mjs";
import { inspectReleaseArchive } from "../../scripts/lib/release-archive-inspection.mjs";
import { assertPackageReleaseEvidence } from "../../scripts/lib/release-evidence-digests.mjs";
import { assertReleaseSourceClean } from "../../scripts/lib/release-source-clean.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");
const outputDir = resolve(process.env.RELEASE_OUTPUT_DIR ?? join(repoRoot, "release-output"));
const sourceDateEpoch = Number(process.env.SOURCE_DATE_EPOCH ?? "");
const releaseVersion = process.env.AIDR_RELEASE_VERSION;
const releaseTag = process.env.AIDR_RELEASE_TAG;
const gitSha = process.env.AIDR_GIT_SHA ?? process.env.AIDR_BUILD_ID;
const evidenceFiles = ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig", "aidr-sbom.cdx.json", "aidr-sbom.cdx.json.sha256"];
const inspectedArchives = new Map();

if (!/^\d+$/u.test(process.env.SOURCE_DATE_EPOCH ?? "") || !Number.isSafeInteger(sourceDateEpoch)) fail("SOURCE_DATE_EPOCH must be an explicit nonnegative integer");
if (!releaseVersion || !releaseTag || !gitSha) fail("AIDR_RELEASE_VERSION, AIDR_RELEASE_TAG, and AIDR_BUILD_ID are required");

const outputRelative = relative(repoRoot, outputDir);
if (!outputRelative || isAbsolute(outputRelative) || outputRelative === ".." || outputRelative.startsWith(`..${sep}`)) fail("Release output must be a child directory of the workspace");
if (!/^release-output(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?$/u.test(outputRelative)) {
	fail("Release output must be a direct child directory named release-output or release-output-<suffix>");
}
if (existsSync(outputDir)) {
	fail(`Release output already exists; inspect and remove it manually before retrying: ${outputRelative}`);
}
assertReleaseSourceClean(repoRoot, { outputRelative: outputRelative.replaceAll("\\", "/") });
const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" });
if (head.status !== 0) fail(`unable to resolve release source commit: ${(head.stderr ?? "").trim()}`);
if (head.stdout.trim().toLowerCase() !== gitSha.toLowerCase()) fail("release source commit does not match AIDR_GIT_SHA");
const gitTar = join(process.env.ProgramFiles || "C:/Program Files", "Git/usr/bin/tar.exe");
const tarCommand = process.env.AIDR_TAR_BIN || (process.platform === "win32" && existsSync(gitTar) ? gitTar : "tar");
const tarVersion = spawnSync(tarCommand, ["--version"], { encoding: "utf8" });
if (tarVersion.status !== 0 || !tarVersion.stdout?.includes("GNU tar")) fail("Reproducible archives require GNU tar; configure AIDR_TAR_BIN (Git for Windows includes it)");

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
try {
	assertPackageReleaseEvidence(repoRoot, packageDirs);
} catch (error) {
	fail(error instanceof Error ? error.message : String(error));
}
const provenanceDirs = packageDirs.map((packageDir) => join(repoRoot, packageDir, "dist"));
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
	const evidenceBeforePack = snapshotEvidence(packageDir);
	const outputBeforePack = new Set(await readdir(outputDir));
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
	assertEvidenceUnchanged(packageDir, evidenceBeforePack);
	const produced = (await readdir(outputDir)).filter((name) => !outputBeforePack.has(name) && name.endsWith(".tgz"));
	if (produced.length !== 1) fail(`${packageDir}: expected pnpm pack to produce exactly one .tgz, found ${produced.length}`);
	const requiredPackageEntries = evidenceFiles.map((name) => `package/dist/${name}`);
	if (packageDir === "packages/claude-code") {
		for (const name of ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"]) {
			if (!existsSync(join(repoRoot, packageDir, name))) fail(`${packageDir}: signed package-root evidence is missing: ${name}`);
			requiredPackageEntries.push(`package/${name}`);
		}
	}
	inspectConsumerArchive(join(outputDir, produced[0]), requiredPackageEntries);
}

try {
	assertClaudePluginPackage(repoRoot);
	assertClaudePluginResourcesCanonical(repoRoot);
} catch (error) {
	fail(error instanceof Error ? error.message : String(error));
}
createTarball(
	join(outputDir, `aidr-claude-plugin-${releaseVersion}.tar.gz`),
	claudePluginArchivePaths(),
);
createTarball(
	join(outputDir, `aidr-dashboard-dist-${releaseVersion}.tar.gz`),
	["packages/dashboard/dist", "packages/dashboard/package.json", "packages/dashboard/vercel.json"],
);
inspectConsumerArchive(
	join(outputDir, `aidr-claude-plugin-${releaseVersion}.tar.gz`),
	claudePluginRequiredFiles(),
);
inspectConsumerArchive(
	join(outputDir, `aidr-dashboard-dist-${releaseVersion}.tar.gz`),
	evidenceFiles.map((name) => `packages/dashboard/dist/${name}`),
);

const artifacts = [];
for (const entry of await readdir(outputDir, { withFileTypes: true })) {
	if (!entry.isFile()) continue;
	const filePath = join(outputDir, entry.name);
	const bytes = await readFile(filePath);
	if (entry.name.endsWith(".map") || /(?:\.env|node_modules)/i.test(entry.name)) {
		fail(`forbidden artifact ${entry.name}`);
	}
	if (isConsumerArchive(entry.name)) {
		inspectConsumerArchive(filePath);
	}
	artifacts.push({ path: entry.name, size: bytes.byteLength, sha256: createHash("sha256").update(bytes).digest("hex") });
}
artifacts.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

await writeFile(
	join(outputDir, "release-metadata.json"),
	`${JSON.stringify({ schema_version: 1, release_tag: releaseTag, release_version: releaseVersion, git_sha: gitSha, source_date_epoch: sourceDateEpoch, worktree_dirty: false, artifacts }, null, 2)}\n`,
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

function snapshotEvidence(packageDir) {
	const dist = join(repoRoot, packageDir, "dist");
	return new Map(evidenceFiles.map((name) => {
		const file = join(dist, name);
		if (!existsSync(file)) fail(`${packageDir}: signed release evidence is missing before pnpm pack: ${name}`);
		return [name, createHash("sha256").update(readFileSync(file)).digest("hex")];
	}));
}

function assertEvidenceUnchanged(packageDir, before) {
	const after = snapshotEvidence(packageDir);
	for (const [name, digest] of before) {
		if (after.get(name) !== digest) fail(`${packageDir}: pnpm pack changed signed release evidence: ${name}`);
	}
}

function inspectConsumerArchive(filePath, requiredEntries = []) {
	let inspection = inspectedArchives.get(filePath);
	if (!inspection) {
		try {
			inspection = inspectReleaseArchive(filePath, { tarCommand, requiredEntries });
		} catch (error) {
			fail(error instanceof Error ? error.message : String(error));
		}
		inspectedArchives.set(filePath, inspection);
	}
	for (const required of requiredEntries) {
		if (!inspection.entries.has(required)) fail(`packed consumer artifact is missing signed evidence ${required}: ${filePath}`);
	}
	return inspection.listing;
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
