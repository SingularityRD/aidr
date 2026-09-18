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
 * It deliberately does NOT commit the index. Committing it moves HEAD and
 * invalidates the stamps it just recorded; that trade-off is the operator's
 * call, and the doc explains it.
 *
 * Usage:
 *   node scripts/run-evidence-gates.mjs [--only <gate_id>...] [--skip-build]
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const INDEX_FILE = "docs/production-readiness/v8-evidence-index.json";

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
	env.AIDR_RELEASE_VERSION = env.AIDR_RELEASE_VERSION ?? "0.6.0-rc.10";
	env.AIDR_RELEASE_TAG = env.AIDR_RELEASE_TAG ?? "v0.6.0-rc.10";
	env.AIDR_AIG_PYTHON = env.AIDR_AIG_PYTHON ?? path.join(ROOT, ".release-evidence", "aig-bridge-venv", "Scripts", "python.exe");
	env.AIDR_E2E_ENABLE_IDE_HOST = env.AIDR_E2E_ENABLE_IDE_HOST ?? "1";
	env.AIDR_CURSOR_PATH = env.AIDR_CURSOR_PATH ?? path.join(process.env.LOCALAPPDATA ?? "", "Programs", "cursor", "Cursor.exe");
	env.AIDR_VSCODE_PATH = env.AIDR_VSCODE_PATH ?? path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Microsoft VS Code", "Code.exe");
	env.DASHBOARD_SMOKE_BASE_URL = env.DASHBOARD_SMOKE_BASE_URL ?? "http://127.0.0.1:8080";
	return env;
}

function git(args) {
	return spawnSync("git", args, { cwd: ROOT, encoding: "utf8" }).stdout.trim();
}

/** Source paths the gate run itself rewrites; committing them is expected, not source drift. */
const GENERATED = /^(?:FEATURE_INVENTORY\.(?:json|md)|PRODUCTION_SALES_GAPS\.(?:json|md)|READINESS_BACKLOG\.json|packages\/core\/src\/generated\/aig-.+|docs\/production-readiness\/v8-evidence-index\.json|packages\/[^/]+\/dist\/)$/;

function importantDirt() {
	return git(["status", "--porcelain=v1"])
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean)
		.map((line) => line.replace(/^[ MARC?]{1,2}\s+/, ""))
		.filter((file) => !/^\.release-evidence(?:[\\/]|$)/.test(file))
		.filter((file) => !/^\.e2e-artifacts(?:[\\/]|$)/.test(file))
		.filter((file) => !/^release-output(?:[\\/]|$)/.test(file))
		.filter((file) => file !== "vendor/ai-infra-guard")
		.filter((file) => !GENERATED.test(file) && !/^packages\/[^/]+\/dist\//.test(file));
}

const argv = process.argv.slice(2);
const only = [];
let skipBuild = false;
for (let i = 0; i < argv.length; i += 1) {
	if (argv[i] === "--only") only.push(argv[++i]);
	else if (argv[i] === "--skip-build") skipBuild = true;
	else if (argv[i] === "--help" || argv[i] === "-h") {
		console.log("Usage: node scripts/run-evidence-gates.mjs [--only <gate_id>...] [--skip-build]");
		process.exit(0);
	} else {
		console.error(`ERROR: unknown argument: ${argv[i]}`);
		process.exit(1);
	}
}

const env = rehearsalEnv();

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

// 2. Refresh the claim records. They are stamped with the commit and candidate
//    digest they scanned, so they must be rebound before the gates that read
//    them run, or `quality:static` fails on staleness rather than on a real
//    finding. A non-zero exit here means the claim gate has open findings; that
//    is recorded, not worked around.
const refresh = spawnSync(process.execPath, ["scripts/refresh-claim-evidence.mjs"], { cwd: ROOT, env, encoding: "utf8" });
process.stdout.write(refresh.stdout ?? "");
if (refresh.status !== 0) console.log("[gates] claim records were rebound, but the claim gate reports open findings (expected)");

// 3. Ensure the release candidate exists and matches this commit. The kit and
//    envelope gates read it, and they refuse a candidate built from another
//    revision, so a missing or stale candidate would block them for the wrong
//    reason.
const candidateDir = path.join(ROOT, ".release-evidence", "customer-release-v8-local-20260916-r9");
let candidateMatches = false;
try {
	candidateMatches = JSON.parse(readFileSync(path.join(candidateDir, "release-metadata.json"), "utf8")).git_sha === git(["rev-parse", "HEAD"]);
} catch {
	candidateMatches = false;
}
if (!candidateMatches) {
	console.log("[gates] rebuilding the release candidate for this commit");
	// On Windows a directory delete can fail while an antivirus or indexer still
	// holds a handle; maxRetries makes that a delay rather than a hard failure.
	rmSync(candidateDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
	if (existsSync(candidateDir)) {
		console.error(`ERROR: could not clear the previous candidate at ${path.relative(ROOT, candidateDir)}`);
		process.exit(1);
	}
	const candidate = spawnSync(
		process.execPath,
		["scripts/build-release-candidate.mjs", "--output", ".release-evidence/customer-release-v8-local-20260916-r9", "--rc-version", env.AIDR_RELEASE_VERSION],
		{ cwd: ROOT, env, stdio: "inherit" },
	);
	if (candidate.status !== 0) {
		console.error("ERROR: the release candidate could not be rebuilt; kit gates would describe a different revision");
		process.exit(candidate.status ?? 1);
	}
}

// The kit and envelope gates refuse an existing output directory, so clear the
// previous assembly. They are derived artifacts, regenerated below.
for (const stale of ["aidr-customer-kit-v8-local-20260916-r9", "aidr-envelope-v8-local-20260916-r9"]) {
	rmSync(path.join(ROOT, ".release-evidence", stale), { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}

// 4. Run every gate, sequentially. Running them together races on the core build
//    lock and on the shared dist trees, which produces failures that look like
//    product defects.
const gateIds = only.length > 0 ? only : declaredGateIds();
for (const id of gateIds) {
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
console.log("[gates] the index is written but NOT committed: committing it moves HEAD and would stale every stamp inside it.");
writeFileSync(path.join(ROOT, ".release-evidence", "gate-run-summary.json"), `${JSON.stringify({ commit_sha: parsed.commit_sha, candidate_digest: parsed.candidate_digest, counts }, null, 2)}\n`, "utf8");

// A gate that did not pass is a finding, not a failure of this script: the index
// records it and the operator reads it. Exit non-zero only when the index could
// not be produced at all, which the earlier check already handled.
process.exitCode = 0;

/** Gate ids in declaration order, read from the generator so the two cannot drift. */
function declaredGateIds() {
	const source = readFileSync(path.join(ROOT, "scripts", "generate-v8-evidence-index.mjs"), "utf8");
	return [...source.matchAll(/gate_id:\s*"([^"]+)"/g)].map((match) => match[1]);
}
