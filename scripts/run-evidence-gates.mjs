#!/usr/bin/env node
/**
 * Run every declared gate at the current commit and freeze the evidence index.
 *
 * This exists because regenerating the index by hand has a loop in it, documented
 * in `docs/production-readiness/evidence-index-regeneration.md`: the generated
 * inventories embed their own `source_commit`, so committing them moves HEAD;
 * every gate result is stamped with the commit it ran against; and the index
 * refuses to derive a PASS from a result whose stamp does not match the tree it
 * describes. Run the gates, commit anything the run dirtied, and every stamp is
 * immediately stale.
 *
 * The order that terminates is: settle the tree, then run everything, then
 * generate the index and stop. This script performs exactly that sequence so a
 * release rehearsal is one command instead of a remembered ritual, and so the
 * gate stamps inside the index always describe the commit the index names.
 *
 * It deliberately keeps the index under `.release-evidence/`. CI uploads that
 * directory as a run artifact; committing it would move HEAD and invalidate the
 * stamps it just recorded.
 *
 * Usage:
 *   node scripts/run-evidence-gates.mjs [--only <gate_id>...] [--skip-build]
 *   node scripts/run-evidence-gates.mjs --profile first-customer-local [--list]
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { GATES, INDEX_FILE } from "./generate-v8-evidence-index.mjs";
import { evidenceRunnerOutputs, existingOutputPaths } from "./lib/evidence-output-guard.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CANDIDATE_DIR = path.join(ROOT, ".release-evidence", "customer-release-v8-local-20260916-r9");
const KIT_DIRS = ["aidr-customer-kit-v8-local-20260916-r9", "aidr-envelope-v8-local-20260916-r9"];
// These require a host/deployment or named commercial approvals, not just this
// checkout. They remain declared as NOT_RUN in the local evaluation profile.
const DEFERRED_GATES = new Map([
	["18-native-host", "installed native host required"],
	["19-release-e2e", "installed editor hosts and external receipts required"],
	["25-customer-onboarding", "deployed stack required"],
	["30-commercial-gates", "direct-GA commercial approvals required"],
]);

/**
 * Environment a full local rehearsal needs. Every entry is optional: a gate
 * whose prerequisites are absent reports itself blocked, which is the honest
 * outcome and is preserved rather than worked around.
 */
function rehearsalEnv() {
	const env = { ...process.env };
	const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).stdout.trim();
	const epoch = spawnSync("git", ["show", "-s", "--format=%ct", "HEAD"], { cwd: ROOT, encoding: "utf8" }).stdout.trim();
	env.AIDR_BUILD_ID = env.AIDR_BUILD_ID ?? head;
	env.SOURCE_DATE_EPOCH = env.SOURCE_DATE_EPOCH ?? epoch;
	env.AIDR_RELEASE_VERSION = env.AIDR_RELEASE_VERSION ?? JSON.parse(readFileSync(path.join(ROOT, "packages", "core", "package.json"), "utf8")).version;
	env.AIDR_RELEASE_TAG = env.AIDR_RELEASE_TAG ?? `v${env.AIDR_RELEASE_VERSION}-rc.0`;
	env.AIDR_AIG_PYTHON = env.AIDR_AIG_PYTHON ?? path.join(ROOT, ".release-evidence", "aig-bridge-venv", "Scripts", "python.exe");
	env.AIDR_E2E_ENABLE_IDE_HOST = env.AIDR_E2E_ENABLE_IDE_HOST ?? "1";
	env.AIDR_CURSOR_PATH = env.AIDR_CURSOR_PATH ?? path.join(process.env.LOCALAPPDATA ?? "", "Programs", "cursor", "Cursor.exe");
	env.AIDR_VSCODE_PATH = env.AIDR_VSCODE_PATH ?? path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Microsoft VS Code", "Code.exe");
	env.DASHBOARD_SMOKE_BASE_URL = env.DASHBOARD_SMOKE_BASE_URL ?? "http://127.0.0.1:8080";
	return env;
}

function git(args) {
	const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
	if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.error?.message ?? result.stderr}`);
	return result.stdout.trim();
}

/** Source paths the gate run itself rewrites; committing them is expected, not source drift. */
const GENERATED = /^(?:FEATURE_INVENTORY\.(?:json|md)|PRODUCTION_SALES_GAPS\.(?:json|md)|packages\/core\/src\/generated\/aig-.+|packages\/[^/]+\/dist\/)$/;

function importantDirt() {
	return git(["status", "--porcelain=v1"])
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => line.replace(/^[ MARC?]{1,2}\s+/, ""))
		.filter((file) => !/^\.release-evidence(?:[\\/]|$)/.test(file))
		.filter((file) => !/^\.e2e-artifacts(?:[\\/]|$)/.test(file))
		.filter((file) => !/^release-output(?:[\\/]|$)/.test(file))
		.filter((file) => !GENERATED.test(file) && !/^packages\/[^/]+\/dist\//.test(file));
}

const argv = process.argv.slice(2);
const only = [];
let skipBuild = false;
let profile = null;
let list = false;
for (let i = 0; i < argv.length; i += 1) {
	if (argv[i] === "--only") only.push(argv[++i]);
	else if (argv[i] === "--profile") profile = argv[++i];
	else if (argv[i] === "--list") list = true;
	else if (argv[i] === "--skip-build") skipBuild = true;
	else if (argv[i] === "--help" || argv[i] === "-h") {
		console.log("Usage: node scripts/run-evidence-gates.mjs [--only <gate_id>...] [--skip-build] | --profile first-customer-local [--list]");
		process.exit(0);
	} else {
		console.error(`ERROR: unknown argument: ${argv[i]}`);
		process.exit(1);
	}
}
const declaredIds = declaredGateIds();
if (only.some((id) => !declaredIds.includes(id)) || (profile !== null && profile !== "first-customer-local") ||
	(profile && (only.length > 0 || skipBuild)) || (list && !profile)) {
	console.error("ERROR: invalid gate selection; --profile first-customer-local cannot be combined with --only or --skip-build");
	process.exit(1);
}
const selectedIds = profile ? declaredIds.filter((id) => !DEFERRED_GATES.has(id)) : only.length > 0 ? only : declaredIds;
if (list) {
	console.log(`Profile ${profile}: ${selectedIds.length} local gates; ${DEFERRED_GATES.size} field/approval gates remain NOT_RUN`);
	for (const id of selectedIds) console.log(`RUN ${id}`);
	for (const [id, reason] of DEFERRED_GATES) console.log(`NOT_RUN ${id} (${reason})`);
	process.exit(0);
}

const env = rehearsalEnv();

// This runner currently uses fixed output paths. Never clear, rename, or
// overwrite a prior evidence artifact to make a new run fit those paths.
const protectedOutputs = evidenceRunnerOutputs(ROOT, env);
const collisions = existingOutputPaths(protectedOutputs);
if (collisions.length > 0) {
	console.error("ERROR: evidence runner fixed output paths already contain prior artifacts; they were left untouched:");
	for (const target of collisions) console.error(`  ${path.relative(ROOT, target)}`);
	console.error("This runner no longer deletes or overwrites prior evidence. Retry only from a fresh isolated worktree.");
	process.exit(1);
}

// Check before the expensive build too. Candidate assembly has the same clean
// source requirement, so a dirty tree cannot yield commit-bound release proof.
const initialDirt = importantDirt();
if (initialDirt.length > 0) {
	console.error(`ERROR: ${initialDirt.length} uncommitted source path(s); commit or set them aside before a commit-bound gate run:`);
	for (const file of initialDirt.slice(0, 20)) console.error(`  ${file}`);
	if (initialDirt.length > 20) console.error(`  ... ${initialDirt.length - 20} more`);
	process.exit(1);
}

// 1. Settle the tree first. A release build rewrites the AIG indexes and clears
//    normal-mode source maps, so running it after the gates would stale them.
if (!skipBuild) {
	console.log("[gates] pnpm build:release");
	const build = spawnSync("pnpm", ["build:release"], { cwd: ROOT, env, stdio: "inherit", shell: process.platform === "win32" });
	if (build.status !== 0) {
		console.error("ERROR: release build failed; gates would describe a tree that cannot build");
		process.exit(1);
	}
	const dirt = importantDirt();
	if (dirt.length > 0) {
		console.error("ERROR: the release build left source changes that are not generated output:");
		for (const file of dirt) console.error(`  ${file}`);
		console.error("Commit or revert them, then re-run. Gate stamps must describe a settled tree.");
		process.exit(1);
	}
	console.log("[gates] the tree is settled; running gates");
}

// 2. Refresh the release candidate before anything that binds to its digest.
//    Claim records are stamped with the candidate inventory digest they scanned,
//    and `quality:static` refuses a record whose stamp does not match the current
//    candidate. Rebuilding the candidate after the claim refresh therefore
//    invalidates the records the refresh just wrote, which is what made
//    `quality:static` fail with "no valid candidate_digest binding" even though
//    the claims themselves were fine.
console.log("[gates] rebuilding the release candidate from the settled release dist");
const candidate = spawnSync(
	process.execPath,
	["scripts/build-release-candidate.mjs", "--output", path.relative(ROOT, CANDIDATE_DIR), "--rc-version", env.AIDR_RELEASE_VERSION],
	{ cwd: ROOT, env, stdio: "inherit" },
);
if (candidate.status !== 0) {
	console.error("ERROR: the release candidate could not be rebuilt; kit gates would describe a different revision");
	process.exit(candidate.status ?? 1);
}

// Every external receipt and E2E result must name these exact candidate bytes.
// Computing the binding here avoids a caller accidentally supplying a digest
// from an older candidate with the same Git commit.
const candidateInventoryPath = path.join(CANDIDATE_DIR, "release-inventory.json");
const candidateDigest = createHash("sha256").update(readFileSync(candidateInventoryPath)).digest("hex");
env.AIDR_E2E_RC_DIGEST = candidateDigest;
env.AIDR_CANDIDATE_SHA256 = candidateDigest;
env.AIDR_RELEASE_CANDIDATE_SHA256 = candidateDigest;
console.log(`[gates] candidate digest ${candidateDigest}`);

// 3. Rebind the claim records to the candidate that will be described. A non-zero
//    exit here means the claim gate has open findings; that is recorded, not
//    worked around.
const refresh = spawnSync(process.execPath, ["scripts/refresh-claim-evidence.mjs"], { cwd: ROOT, env, encoding: "utf8" });
process.stdout.write(refresh.stdout ?? "");
if (refresh.error || !/^inventory: PASS\b/m.test(refresh.stdout ?? "") || !/^gate: (?:PASS|FAIL)\b/m.test(refresh.stdout ?? "")) {
	process.stderr.write(refresh.stderr ?? "");
	console.error("ERROR: claim evidence refresh did not complete both scans; gate results would be incomplete");
	process.exit(1);
}
if (refresh.status !== 0) console.log("[gates] claim records were rebound, but the claim gate reports open findings (expected)");

// A profile is a fresh self-run. Keep prior captures recoverable, but do not
// let a skipped field gate inherit an earlier PASS from this same candidate.
if (profile) {
	const logs = path.join(ROOT, ".release-evidence", "v8-logs");
	mkdirSync(logs, { recursive: true });
}

// 4. Run every gate, sequentially. Running them together races on the core build
//    lock and on the shared dist trees, which produces failures that look like
//    product defects.
//
// The generator-determinism gate asserts that the inventories on disk match what
// the generators produce, by running `git diff --exit-code` against them. Gates
// 02 and 03 regenerate those very files, so the determinism gate only passes if
// it runs after them and after anything else that rewrites tracked output. It is
// therefore ordered last rather than wherever it was declared.
const ORDERING_LAST = ["26-generator-determinism"];
// Gates that inspect the published `dist` trees must run while those trees are
// in release state. The test gates perform a normal build as part of their own
// global setup, which restores source maps and test folders, so any package
// gate scheduled after them inspects a contaminated tree and reports
// SOURCE_MAP_PRESENT - a real finding about the tree, but one this run created.
// Rebuild in release mode immediately before the first such gate.
const NEEDS_RELEASE_DIST = ["27-empty-path-package-install"];
let releaseDistFresh = false;
// The kit and envelope gates refuse an existing output directory by design: a
// silent overwrite could mix two assemblies. The preflight above protects the
// fixed paths, and this per-gate check catches anything that appeared meanwhile.
const KIT_GATES = new Set(["20-customer-kit"]);
const gateIds = [...selectedIds.filter((id) => !ORDERING_LAST.includes(id)), ...selectedIds.filter((id) => ORDERING_LAST.includes(id))];
for (const id of gateIds) {
	if (NEEDS_RELEASE_DIST.includes(id) && !releaseDistFresh) {
		console.log("[gates] rebuilding release artifacts: an earlier test gate left normal-mode output");
		const rebuild = spawnSync("pnpm", ["build:release"], { cwd: ROOT, env, stdio: "inherit", shell: process.platform === "win32" });
		if (rebuild.status !== 0) {
			console.error("ERROR: could not restore release dist state before a package gate");
			process.exit(1);
		}
		releaseDistFresh = true;
	}
	if (KIT_GATES.has(id)) {
		if (KIT_DIRS.some((name) => existsSync(path.join(ROOT, ".release-evidence", name)))) {
			console.error("ERROR: customer kit or envelope appeared after preflight; preserving it and stopping before assembly");
			process.exit(1);
		}
	}
	const result = spawnSync(process.execPath, ["scripts/generate-v8-evidence-index.mjs", "--run", id], { cwd: ROOT, env, encoding: "utf8" });
	const line = (result.stdout ?? "").split(/\r?\n/).find((entry) => entry.startsWith("Captured ")) ?? `Captured ${id}: no output`;
	console.log(line.trim());
}

// 5. Generate the index and report what it says. Do not commit it.
const index = spawnSync(process.execPath, ["scripts/generate-v8-evidence-index.mjs", "--out", INDEX_FILE], { cwd: ROOT, env, encoding: "utf8" });
process.stdout.write(index.stdout ?? "");
if (index.status !== 0) {
	process.stderr.write(index.stderr ?? "");
	process.exit(index.status ?? 1);
}

const parsed = JSON.parse(readFileSync(path.join(ROOT, INDEX_FILE), "utf8"));
const counts = {};
for (const record of parsed.gates ?? []) counts[record.status] = (counts[record.status] ?? 0) + 1;
console.log(`[gates] index describes commit ${String(parsed.commit_sha).slice(0, 8)}: ${JSON.stringify(counts)}`);
for (const record of parsed.gates ?? []) {
	if (record.status !== "PASS") console.log(`[gates]   ${record.status.padEnd(7)} ${record.gate_id}`);
}
console.log("[gates] generated evidence is under .release-evidence for CI artifact upload; it is never committed.");
writeFileSync(path.join(ROOT, ".release-evidence", "gate-run-summary.json"), `${JSON.stringify({ profile: profile ?? "all", commit_sha: parsed.commit_sha, candidate_digest: parsed.candidate_digest, counts, deferred_gate_ids: profile ? [...DEFERRED_GATES.keys()] : [] }, null, 2)}\n`, { encoding: "utf8", flag: "wx" });

// A gate that did not pass is a finding, not a failure of this script: the index
// records it and the operator reads it. Exit non-zero only when the index could
// not be produced at all, which the earlier check already handled.
process.exitCode = 0;

/** Gate ids in declaration order, read from the generator so the two cannot drift. */
function declaredGateIds() {
	return GATES.map((gate) => gate.gate_id);
}
