#!/usr/bin/env node
/**
 * Build `packages/core` only when it actually needs building.
 *
 * Workspace orchestration builds core once before connectors. Standalone
 * connector builds use the same repository-local lock, preventing a normal
 * rebuild from replacing release-mode output while release manifests are being
 * generated.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { acquireCoreBuildLock, releaseCoreBuildLock } from "./build-workspace.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultRepoRoot = resolve(scriptDir, "..");

function digest(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function newestMtime(dir, filter) {
	if (!existsSync(dir)) return 0;
	let newest = 0;
	const walk = (current) => {
		for (const entry of readdirSync(current, { withFileTypes: true })) {
			const full = join(current, entry.name);
			if (entry.isDirectory()) walk(full);
			else if (!filter || filter(entry.name)) newest = Math.max(newest, statSync(full).mtimeMs);
		}
	};
	walk(dir);
	return newest;
}

export function coreBuildReason(repoRoot = defaultRepoRoot) {
	const coreDir = join(repoRoot, "packages", "core");
	const requiredOutputs = [join(coreDir, "dist", "index.js"), join(coreDir, "dist", "index.d.ts")];
	for (const output of requiredOutputs) {
		if (!existsSync(output)) return "a required output is missing";
	}

	const generatedSource = join(coreDir, "src", "generated");
	const generatedOutput = join(coreDir, "dist", "generated");
	if (!existsSync(generatedSource) || !existsSync(generatedOutput)) return "generated data is missing";
	const generatedFiles = readdirSync(generatedSource).filter((name) => name.endsWith(".json"));
	if (generatedFiles.length === 0) return "generated data is empty";
	for (const name of generatedFiles) {
		const output = join(generatedOutput, name);
		if (!existsSync(output) || digest(join(generatedSource, name)) !== digest(output)) {
			return `generated data is missing or changed: ${name}`;
		}
	}

	const sourceMtime = newestMtime(join(coreDir, "src"), (name) => name.endsWith(".ts"));
	const config = join(coreDir, "tsconfig.json");
	const configMtime = existsSync(config) ? statSync(config).mtimeMs : 0;
	const inputMtime = Math.max(sourceMtime, configMtime);
	const oldestOutput = Math.min(...requiredOutputs.map((output) => statSync(output).mtimeMs));
	if (inputMtime === 0) return "no source inputs found (refusing to assume freshness)";
	if (inputMtime > oldestOutput) return "a source input is newer than the build output";
	return null;
}

function ownsWorkspaceLock(repoRoot, env) {
	if (!env.AIDR_CORE_BUILD_LOCK_TOKEN) return false;
	try {
		const owner = JSON.parse(readFileSync(join(repoRoot, "packages", "core", ".aidr-build.lock"), "utf8"));
		return owner.token === env.AIDR_CORE_BUILD_LOCK_TOKEN;
	} catch {
		return false;
	}
}

export function ensureCoreBuild({
	repoRoot = defaultRepoRoot,
	env = process.env,
	runBuild = (coreDir) =>
		execFileSync("pnpm", ["run", "build"], {
			cwd: coreDir,
			stdio: "inherit",
			shell: process.platform === "win32",
		}),
} = {}) {
	let reason = coreBuildReason(repoRoot);
	if (reason === null) {
		console.log("[core] up to date; skipping rebuild");
		return 0;
	}

	if (env.AIDR_WORKSPACE_BUILD === "1") {
		const mode = env.AIDR_CORE_BUILD_MODE ?? "unknown";
		const lockDetail = ownsWorkspaceLock(repoRoot, env) ? "workspace lock is held" : "workspace lock token is invalid";
		console.error(
			`[core] refusing to rebuild during a ${mode} workspace build (${reason}; ${lockDetail}).\n` +
				"Core is built once, before the other packages, by scripts/build-workspace.mjs.",
		);
		return 1;
	}

	let lock;
	try {
		lock = acquireCoreBuildLock(repoRoot, "standalone connector core ensure");
		// Another waiter may have completed the build before this process acquired
		// the lock. Re-check under the lock to avoid an unnecessary rebuild.
		reason = coreBuildReason(repoRoot);
		if (reason === null) {
			console.log("[core] up to date after waiting; skipping rebuild");
			return 0;
		}
		console.log(`[core] building (${reason})`);
		runBuild(join(repoRoot, "packages", "core"));
		return 0;
	} catch (error) {
		console.error(`[core] ${error.message}`);
		return 1;
	} finally {
		releaseCoreBuildLock(lock);
	}
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exitCode = ensureCoreBuild();
