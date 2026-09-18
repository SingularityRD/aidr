#!/usr/bin/env node
/**
 * Workspace build with the core dependency sequenced and locked.
 *
 * Core is built exactly once before the connectors. A repository-local lock is
 * held until the complete release pipeline (including manifests and release
 * checks) finishes, so a concurrent normal workspace/connector build cannot
 * replace release-mode core output with source-map-enabled output.
 */

import { randomUUID } from "node:crypto";
import { closeSync, existsSync, openSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = resolve(scriptDir, "..");

function command(executable, args, extraEnv, cwd) {
	const result = spawnSync(executable, args, {
		cwd,
		stdio: "inherit",
		shell: process.platform === "win32" && executable === "pnpm",
		env: { ...process.env, ...extraEnv },
	});
	if (result.error) {
		console.error(`[build] failed to run ${executable} ${args.join(" ")}: ${result.error.message}`);
		return 1;
	}
	return result.status ?? 1;
}

function processExists(pid) {
	if (!Number.isSafeInteger(pid) || pid <= 0) return false;
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return error?.code === "EPERM";
	}
}

export function acquireCoreBuildLock(repoRoot, purpose) {
	const lockPath = join(repoRoot, "packages", "core", ".aidr-build.lock");
	const token = randomUUID();
	for (let attempt = 0; attempt < 2; attempt += 1) {
		try {
			const fd = openSync(lockPath, "wx");
			try {
				writeFileSync(fd, `${JSON.stringify({ pid: process.pid, token, purpose, createdAt: new Date().toISOString() })}\n`);
			} finally {
				closeSync(fd);
			}
			return { path: lockPath, token };
		} catch (error) {
			if (error?.code !== "EEXIST") throw error;
			let owner;
			try {
				owner = JSON.parse(readFileSync(lockPath, "utf8"));
			} catch {
				owner = null;
			}
			if (owner && processExists(owner.pid)) {
				throw new Error(`core build is locked by pid ${owner.pid} (${owner.purpose ?? "unknown build"})`);
			}
			unlinkSync(lockPath);
		}
	}
	throw new Error("could not acquire the core build lock");
}

export function releaseCoreBuildLock(lock) {
	if (!lock || !existsSync(lock.path)) return;
	try {
		const owner = JSON.parse(readFileSync(lock.path, "utf8"));
		if (owner.token !== lock.token) return;
	} catch {
		return;
	}
	unlinkSync(lock.path);
}

/**
 * Every workspace package whose `dist/` is published in a release artifact.
 * Core is only the first one: the same contamination is possible in any package
 * whenever a non-release build (a test run, `pnpm check`, another package's
 * `build`) recompiles that package after release finalization has finished.
 */
const RELEASE_DIST_PACKAGES = [
	"core",
	"claude-code",
	"extension",
	"openclaw",
	"opencode",
	"cli",
	"sdk",
	"dashboard",
	"codex",
	"mcp-gateway",
];

/** Source-map files under one package's `dist/`, relative to that `dist/`. */
export function sourceMapsInPackageDist(repoRoot, packageName) {
	const dist = join(repoRoot, "packages", packageName, "dist");
	const maps = [];
	const walk = (dir) => {
		if (!existsSync(dir)) return;
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			const full = join(dir, entry.name);
			if (entry.isDirectory()) walk(full);
			else if (entry.name.toLowerCase().endsWith(".map")) maps.push(relative(dist, full).replaceAll("\\", "/"));
		}
	};
	walk(dist);
	return maps;
}

export function assertNoCoreSourceMaps(repoRoot) {
	const maps = sourceMapsInPackageDist(repoRoot, "core");
	if (maps.length > 0) throw new Error(`release core output was contaminated by source maps: ${maps.join(", ")}`);
}

/**
 * Release artifacts are the published packages, so a source map left in ANY
 * package's `dist/` is the same defect as one left in core. Checking only core
 * let a concurrent non-release rebuild of another package (observed: 363 maps
 * across cli, opencode, core, claude-code, extension, sdk, codex, openclaw)
 * silently poison an assembled release candidate.
 */
export function assertNoReleaseSourceMaps(repoRoot) {
	const contaminated = [];
	for (const packageName of RELEASE_DIST_PACKAGES) {
		const maps = sourceMapsInPackageDist(repoRoot, packageName);
		if (maps.length > 0) contaminated.push(`${packageName}: ${maps.slice(0, 5).join(", ")}${maps.length > 5 ? ` (+${maps.length - 5} more)` : ""}`);
	}
	if (contaminated.length > 0) {
		throw new Error(`release output was contaminated by source maps in ${contaminated.length} package(s) — ${contaminated.join(" | ")}`);
	}
}

const releaseFinalization = [
	["scripts/release-artifact-manifests.mjs"],
	["scripts/check-package-contracts.mjs", "packages/core", "packages/claude-code", "packages/extension", "packages/openclaw", "packages/opencode", "packages/cli", "packages/sdk", "packages/dashboard", "packages/codex", "packages/mcp-gateway"],
	["scripts/check-package-consumers.mjs"],
	["scripts/check-no-sourcemaps.mjs", "packages"],
	["scripts/check-no-leaky-paths.mjs", "packages/core/dist", "packages/claude-code/dist", "packages/extension/dist", "packages/openclaw/dist", "packages/opencode/dist", "packages/cli/dist", "packages/sdk/dist", "packages/dashboard/dist", "packages/codex/dist", "packages/mcp-gateway/dist"],
];

export function runWorkspaceBuild({
	releaseMode = false,
	repoRoot = defaultRepoRoot,
	runPnpm = (args, env) => command("pnpm", args, env, repoRoot),
	runNode = (args, env) => command(process.execPath, args, env, repoRoot),
	finalizeRelease = true,
} = {}) {
	let lock;
	try {
		lock = acquireCoreBuildLock(repoRoot, releaseMode ? "release workspace build" : "workspace build");
		const workspaceEnv = {
			AIDR_WORKSPACE_BUILD: "1",
			AIDR_CORE_BUILD_LOCK_TOKEN: lock.token,
			AIDR_CORE_BUILD_MODE: releaseMode ? "release" : "normal",
		};

		console.log("[build] 0/2 compiling AIG data indexes");
		let status = runPnpm(["run", "compile:aig"], workspaceEnv);
		if (status !== 0) throw new Error(`AIG data compilation failed with exit code ${status}`);

		console.log("[build] 1/2 building @singularityrd/aidr-core");
		status = runPnpm(["--filter", "@singularityrd/aidr-core", "run", releaseMode ? "build:release" : "build"], workspaceEnv);
		if (status !== 0) throw new Error(`core build failed with exit code ${status}`);
		// Only core has been rebuilt at this point. Checking every package here
		// would fail a valid release build whenever another package's dist still
		// held maps from an earlier normal build, because that package has not had
		// its release rebuild yet. The all-package check belongs after the
		// remaining packages have been rebuilt, below.
		if (releaseMode) assertNoCoreSourceMaps(repoRoot);

		console.log("[build] 2/2 building the remaining packages");
		status = runPnpm(["-r", "--filter", "!@singularityrd/aidr-core", "run", releaseMode ? "build:release" : "build"], workspaceEnv);
		if (status !== 0) throw new Error(`remaining package build failed with exit code ${status}`);
		if (releaseMode) assertNoReleaseSourceMaps(repoRoot);

		if (releaseMode && finalizeRelease) {
			console.log("[build] finalizing release artifacts while core remains locked");
			for (const args of releaseFinalization) {
				status = runNode(args, workspaceEnv);
				if (status !== 0) throw new Error(`${args[0]} failed with exit code ${status}`);
				assertNoReleaseSourceMaps(repoRoot);
			}
		}
		return 0;
	} catch (error) {
		console.error(`[build] ${error.message}`);
		return 1;
	} finally {
		releaseCoreBuildLock(lock);
	}
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exitCode = runWorkspaceBuild({ releaseMode: process.argv.includes("--release") });
