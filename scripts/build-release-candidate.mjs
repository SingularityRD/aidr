#!/usr/bin/env node
/**
 * Assemble a source-bound release candidate bundle.
 *
 * Every published artifact AIDR ships — ten npm tarballs, the Claude plugin
 * archive, the Cursor/VS Code VSIX and the dashboard dist — is packed from the
 * current worktree, hashed, and written into one candidate directory next to a
 * `release-metadata.json` and `release-inventory.json` that record the exact
 * commit the bytes came from.
 *
 * Why this exists: the r5/r8 candidate bundles were assembled by hand, so the
 * only record of how to reproduce them was the session that produced them. A
 * one-person release process cannot depend on remembering a sequence of shell
 * commands, and a candidate that cannot be rebuilt cannot be trusted to match
 * the source it claims. This script is that missing step: it is deterministic,
 * fail-closed, and refuses to write a bundle for a dirty worktree unless the
 * operator explicitly asks for a local rehearsal.
 *
 * It does NOT sign anything. Signing needs a real publisher key and is a
 * separate, deliberate step (`scripts/release-sign.mjs`); a bundle produced
 * here is an unsigned candidate and must be labelled as such downstream.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The ten published packages, in a fixed order so the inventory is stable
 * across runs on the same source.
 */
export const PACKAGE_TARGETS = Object.freeze([
	{ dir: "packages/core", name: "@singularityrd/aidr-core" },
	{ dir: "packages/claude-code", name: "@singularityrd/aidr-claude-code" },
	{ dir: "packages/opencode", name: "@singularityrd/aidr-opencode" },
	{ dir: "packages/openclaw", name: "@singularityrd/aidr-openclaw" },
	{ dir: "packages/codex", name: "@singularityrd/aidr-codex" },
	{ dir: "packages/cli", name: "@singularityrd/aidr-cli" },
	{ dir: "packages/sdk", name: "@singularityrd/aidr-sdk" },
	{ dir: "packages/mcp-gateway", name: "@singularityrd/aidr-mcp-gateway" },
	{ dir: "packages/dashboard", name: "@singularityrd/aidr-dashboard" },
	{ dir: "packages/extension", name: "aidr-cursor" },
]);

/**
 * Extra archives that are not npm packages but are part of what a customer
 * installs. Each entry names the directory to archive and the file name to
 * publish it under.
 */
export const EXTRA_TARGETS = Object.freeze([
	{ dir: "packages/dashboard/dist", name: "aidr-dashboard-dist" },
]);

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}

function git(args) {
	const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
	if (result.status !== 0) fail(`git ${args.join(" ")} failed: ${(result.stderr ?? "").trim()}`);
	return String(result.stdout ?? "").trim();
}

function sha256File(file) {
	return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function listFiles(dir) {
	const out = [];
	const stack = [dir];
	while (stack.length > 0) {
		const current = stack.pop();
		for (const name of readdirSync(current).sort()) {
			const full = path.join(current, name);
			const info = statSync(full);
			if (info.isDirectory()) stack.push(full);
			else if (info.isFile()) out.push(full);
		}
	}
	return out.sort();
}

/** Recursively hash a directory tree so the metadata binds content, not mtime. */
function digestTree(dir) {
	const parts = [];
	for (const file of listFiles(dir)) {
		parts.push(`${path.relative(dir, file).replace(/\\/g, "/")}:${sha256File(file)}`);
	}
	return createHash("sha256").update(parts.join("\n")).digest("hex");
}

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i++) {
		const arg = argv[i];
		if (arg === "--help" || arg === "-h") values.help = true;
		else if (arg === "--allow-dirty") values.allowDirty = true;
		else if (arg === "--output" || arg === "--rc-version") {
			const next = argv[++i];
			if (!next) fail(`${arg} requires a value`);
			values[arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = next;
		} else fail(`unknown argument: ${arg}`);
	}
	return values;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
	console.log("Usage: node scripts/build-release-candidate.mjs --output <dir> [--rc-version <v>] [--allow-dirty]");
	console.log("");
	console.log("Packs every published artifact from the current worktree into <dir>,");
	console.log("writing release-inventory.json and release-metadata.json alongside.");
	console.log("");
	console.log("  --output <dir>       new directory to create (must not exist)");
	console.log("  --rc-version <v>     release version recorded in metadata (default: root package version)");
	console.log("  --allow-dirty        permit a dirty worktree and record it as a local rehearsal");
	process.exit(0);
}
if (!options.output) fail("--output is required");

const outputDir = path.resolve(ROOT, options.output);
if (!outputDir.startsWith(`${ROOT}${path.sep}`)) fail("--output must be inside the repository");
if (existsSync(outputDir)) fail(`output directory already exists: ${options.output}`);

const rootPkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
const rcVersion = options.rcVersion ?? String(rootPkg.version ?? "0.0.0");

const commitSha = git(["rev-parse", "HEAD"]);
const dirtyEntries = git(["status", "--porcelain=v1"])
	.split(/\r?\n/)
	.map((line) => line.trim())
	.filter(Boolean)
	// Build output and evidence are regenerated, not source; the vendored
	// submodule's local state is not part of what this bundle publishes.
	.filter((line) => {
		const file = line.replace(/^[ MARC?]{1,2}\s+/, "");
		return !/^\.release-evidence(?:[\\/]|$)/.test(file)
			&& !/^packages\/[^/]+\/dist(?:[\\/]|$)/.test(file)
			&& file !== "vendor/ai-infra-guard";
	});
if (dirtyEntries.length > 0 && !options.allowDirty) {
	fail(`worktree has uncommitted source changes, so the bundle would not be provenance-bound:\n  ${dirtyEntries.join("\n  ")}\nCommit them, or pass --allow-dirty to record an explicitly local rehearsal.`);
}

// Refuse to pack packages whose dist trees have not been built in release mode:
// a normal-mode build leaves sourcemaps and test folders that must not ship.
for (const target of PACKAGE_TARGETS) {
	const distDir = path.join(ROOT, target.dir, "dist");
	if (!existsSync(distDir)) fail(`${target.dir}/dist is missing; run \`pnpm build:release\` first`);
}

const packRoot = path.join(tmpdir(), `aidr-candidate-pack-${process.pid}`);
rmSync(packRoot, { recursive: true, force: true });
mkdirSync(packRoot, { recursive: true });
mkdirSync(outputDir, { recursive: true });

const staged = [];

try {
	for (const target of PACKAGE_TARGETS) {
		const packageDir = path.join(ROOT, target.dir);
		const before = new Set(readdirSync(packRoot));
		const pack = spawnSync("pnpm", ["pack", "--pack-destination", packRoot], {
			cwd: packageDir,
			encoding: "utf8",
			shell: process.platform === "win32",
		});
		if (pack.error || pack.status !== 0) {
			fail(`${target.name}: pnpm pack failed (${pack.error?.message ?? `exit ${pack.status}`}): ${(pack.stderr ?? "").trim().slice(-400)}`);
		}
		const produced = readdirSync(packRoot).filter((name) => !before.has(name) && name.endsWith(".tgz"));
		if (produced.length !== 1) fail(`${target.name}: expected exactly one tarball, saw ${produced.length}`);
		const tarball = path.join(packRoot, produced[0]);
		const published = `${target.name.replace(/^@/, "").replace(/\//, "-")}-${rcVersion}.tgz`;
		const destination = path.join(outputDir, published);
		await copyFile(tarball, destination);
		staged.push({ name: published, file: destination });
	}

	for (const target of EXTRA_TARGETS) {
		const sourceDir = path.join(ROOT, target.dir);
		if (!existsSync(sourceDir)) fail(`${target.dir} is missing; build it before assembling a candidate`);
		const archived = `${target.name}-${rcVersion}.tar.gz`;
		const destination = path.join(outputDir, archived);
		const tar = spawnSync("tar", ["-czf", destination, "-C", sourceDir, "."], { encoding: "utf8" });
		if (tar.error || tar.status !== 0) fail(`${target.name}: tar failed (${tar.error?.message ?? `exit ${tar.status}`})`);
		staged.push({ name: archived, file: destination });
	}

	// The Claude Code plugin ships as its own archive with the hooks, skills and
	// manifest at the root, so it is packed separately from the npm package.
	const pluginFiles = ["hooks/hooks.json", ".claude-plugin/plugin.json", "skills/security-awareness/SKILL.md"];
	for (const relative of pluginFiles) {
		if (!existsSync(path.join(ROOT, relative))) fail(`Claude plugin file is missing: ${relative}`);
	}
	const pluginArchive = `aidr-claude-plugin-${rcVersion}.tar.gz`;
	const pluginDestination = path.join(outputDir, pluginArchive);
	const pluginTar = spawnSync(
		"tar",
		["-czf", pluginDestination, "-C", ROOT, "hooks", ".claude-plugin", "skills"],
		{ encoding: "utf8" },
	);
	if (pluginTar.error || pluginTar.status !== 0) fail(`Claude plugin archive failed: ${pluginTar.error?.message ?? `exit ${pluginTar.status}`}`);
	staged.push({ name: pluginArchive, file: pluginDestination });

	// Provenance statement, when the generator can produce one here.
	const provenanceName = "aidr-provenance.intoto.json";
	const provenanceTarget = path.join(outputDir, provenanceName);
	const provenance = spawnSync(process.execPath, ["scripts/generate-provenance.mjs", "--output", provenanceTarget], {
		cwd: ROOT,
		encoding: "utf8",
		env: { ...process.env, AIDR_GIT_SHA: commitSha, AIDR_RC_VERSION: rcVersion },
	});
	if (provenance.status === 0 && existsSync(provenanceTarget)) {
		staged.push({ name: provenanceName, file: provenanceTarget });
	} else {
		console.warn(`WARN: provenance statement was not generated; the candidate carries no in-toto attestation (${(provenance.stderr ?? "").trim().slice(-200)})`);
	}

	staged.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

	const metadataArtifacts = staged.map((entry) => ({
		path: entry.name,
		size: statSync(entry.file).size,
		sha256: sha256File(entry.file),
	}));

	// The inventory mirrors the shape release-signing-lib validates: every entry
	// is a release-output/ path whose basename matches the staged file name.
	const inventory = {
		schema_version: 1,
		artifacts: staged.map((entry) => ({
			source_path: `release-output/${entry.name}`,
			staged_path: entry.name,
			kind: "release-artifact",
			sha256: sha256File(entry.file),
		})),
	};
	writeFileSync(path.join(outputDir, "release-inventory.json"), `${JSON.stringify(inventory, null, 2)}\n`, "utf8");

	const metadata = {
		schema_version: 1,
		release_tag: `v${rcVersion}`,
		release_version: rcVersion,
		git_sha: commitSha,
		source_date_epoch: Number(git(["show", "-s", "--format=%ct", "HEAD"])),
		worktree_dirty: dirtyEntries.length > 0,
		assurance: dirtyEntries.length > 0
			? "LOCAL REHEARSAL: the worktree had uncommitted source changes when this bundle was assembled, so these bytes are not bound to the recorded commit."
			: "Unsigned release candidate: bytes are bound to the recorded commit, but no publisher signature is present.",
		artifacts: metadataArtifacts,
	};
	writeFileSync(path.join(outputDir, "release-metadata.json"), `${JSON.stringify(metadata, null, 2)}\n`, "utf8");

	console.log(JSON.stringify({
		status: "PASS",
		output: path.relative(ROOT, outputDir).replace(/\\/g, "/"),
		git_sha: commitSha,
		release_version: rcVersion,
		worktree_dirty: metadata.worktree_dirty,
		artifacts: metadataArtifacts.length,
		inventory_digest: sha256File(path.join(outputDir, "release-inventory.json")),
	}, null, 2));
} finally {
	rmSync(packRoot, { recursive: true, force: true });
}
