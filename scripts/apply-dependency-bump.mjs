#!/usr/bin/env node
/**
 * Apply a dependabot version bump without merging its branch.
 *
 * Every one of these branches changes exactly two kinds of file: `package.json`
 * manifests and `pnpm-lock.yaml`. Merging them therefore conflicts on the lock
 * file every time, and resolving a lock file by hand is how a dependency tree
 * silently diverges from the manifests.
 *
 * The only thing a bump branch actually contributes is a version string, so this
 * reads that string from the branch and applies it to the current manifest, then
 * the caller regenerates the lock with `pnpm install`. That produces the same
 * result as a clean merge, without a manual conflict resolution anywhere.
 *
 * Usage:
 *   node scripts/apply-dependency-bump.mjs --branch <ref> [--dry-run]
 */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}

const argv = process.argv.slice(2);
let branch;
let dryRun = false;
for (let i = 0; i < argv.length; i += 1) {
	if (argv[i] === "--branch") branch = argv[++i];
	else if (argv[i] === "--dry-run") dryRun = true;
	else if (argv[i] === "--help" || argv[i] === "-h") {
		console.log("Usage: node scripts/apply-dependency-bump.mjs --branch <ref> [--dry-run]");
		process.exit(0);
	} else fail(`unknown argument: ${argv[i]}`);
}
if (!branch) fail("--branch is required");

const git = (args) => {
	const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
	if (result.status !== 0) fail(`git ${args.join(" ")} failed: ${(result.stderr ?? "").trim()}`);
	return result.stdout ?? "";
};

/** The manifests the branch changes, excluding the lock file. */
const manifests = git(["diff", "--name-only", `master...${branch}`])
	.split(/\r?\n/)
	.map((line) => line.trim())
	.filter((line) => line.endsWith("package.json"));
if (manifests.length === 0) fail(`${branch} changes no package.json`);

const applied = [];
const skipped = [];

for (const relative of manifests) {
	const diff = git(["diff", `master...${branch}`, "--", relative]);
	// Pairs of `-"name": "old"` / `+"name": "new"` inside a dependencies block. The
	// diff is small and regular for a bump, so a line scan is sufficient and it
	// keeps the change attributable to the branch rather than to a whole-file copy.
	const removed = [...diff.matchAll(/^-\s*"([^"]+)":\s*"([^"]+)",?$/gm)].map((m) => ({ name: m[1], version: m[2] }));
	const added = [...diff.matchAll(/^\+\s*"([^"]+)":\s*"([^"]+)",?$/gm)].map((m) => ({ name: m[1], version: m[2] }));
	if (removed.length === 0 || removed.length !== added.length) {
		fail(`${relative}: could not pair ${removed.length} removed with ${added.length} added version lines`);
	}

	const full = path.join(ROOT, relative);
	let text = readFileSync(full, "utf8");
	for (let i = 0; i < removed.length; i += 1) {
		const from = removed[i];
		const to = added[i];
		if (from.name !== to.name) fail(`${relative}: ${from.name} paired with ${to.name}`);
		const needle = `"${from.name}": "${from.version}"`;
		if (!text.includes(needle)) {
			// Master already moved past this bump, or a different range style is in use.
			skipped.push(`${relative}: ${from.name} is not at ${from.version} any more`);
			continue;
		}
		text = text.replace(needle, `"${to.name}": "${to.version}"`);
		applied.push(`${path.relative(ROOT, full)}: ${from.name} ${from.version} -> ${to.version}`);
	}
	if (!dryRun) writeFileSync(full, text, "utf8");
}

for (const line of applied) console.log(`  applied  ${line}`);
for (const line of skipped) console.log(`  skipped  ${line}`);
if (applied.length === 0) fail(`${branch}: nothing to apply (already current?)`);
console.log(`${branch}: ${applied.length} version(s) ${dryRun ? "would be" : ""} applied`);
