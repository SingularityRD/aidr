#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SOURCE_MAPPING_DIRECTIVE_RE, SOURCE_URL_DIRECTIVE_RE } from "../../../scripts/lib/package-artifact-rules.mjs";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "..", "..");

export const REQUIRED_RUNTIME_FILES = Object.freeze([
	"health.cjs",
	"mcp-server.cjs",
	"post-tool-use.cjs",
	"post-tool-use.bundle.cjs",
	"pre-tool-use.cjs",
	"pre-tool-use.bundle.cjs",
	"session-start.cjs",
	"session-start.bundle.cjs",
	"user-prompt-submit.cjs",
	"user-prompt-submit.bundle.cjs",
]);

export const SIGNED_EVIDENCE_FILES = Object.freeze([
	"aidr-artifact.manifest.json",
	"aidr-artifact.manifest.sig",
	"aidr-sbom.cdx.json",
	"aidr-sbom.cdx.json.sha256",
]);

function releaseHygieneFailures(dist) {
	if (!existsSync(dist)) return [];
	const failures = [];
	const visit = (directory) => {
		for (const entry of readdirSync(directory, { withFileTypes: true })) {
			const full = path.join(directory, entry.name);
			if (entry.isDirectory()) {
				visit(full);
				continue;
			}
			if (!entry.isFile()) continue;
			const relative = path.relative(dist, full).replaceAll("\\", "/");
			if (entry.name.endsWith(".map")) failures.push(`${relative} is a source map`);
			if (!/\.(?:c|m)?js$|\.css$/iu.test(entry.name)) continue;
			const source = readFileSync(full, "utf8");
			if (SOURCE_MAPPING_DIRECTIVE_RE.test(source)) failures.push(`${relative} contains sourceMappingURL`);
			if (/\.(?:c|m)?js$/iu.test(entry.name) && SOURCE_URL_DIRECTIVE_RE.test(source)) failures.push(`${relative} contains sourceURL`);
		}
	};
	visit(dist);
	return failures;
}

export function inspectClaudeCodeDist(root = packageRoot) {
	const dist = path.join(root, "dist");
	const missingRuntime = REQUIRED_RUNTIME_FILES.filter((name) => !existsSync(path.join(dist, name)));
	const manifest = path.join(dist, "aidr-artifact.manifest.json");
	const signed = existsSync(path.join(dist, "aidr-artifact.manifest.sig"));
	const missingEvidence = signed ? SIGNED_EVIDENCE_FILES.filter((name) => !existsSync(path.join(dist, name))) : [];
	const hygieneFailures = releaseHygieneFailures(dist);

	if (signed && (missingRuntime.length > 0 || missingEvidence.length > 0 || hygieneFailures.length > 0)) {
		throw new Error(
			`Signed Claude Code dist is incomplete or contaminated; refusing to rebuild signed evidence (${[
				...missingRuntime.map((name) => `missing dist/${name}`),
				...missingEvidence.map((name) => `missing dist/${name}`),
				...hygieneFailures,
			].join(", ")})`,
		);
	}

	const problems = [
		...missingRuntime.map((name) => `missing dist/${name}`),
		...(!existsSync(manifest) ? ["missing dist/aidr-artifact.manifest.json"] : []),
		...hygieneFailures,
	];
	return { ready: problems.length === 0, signed, problems };
}

export function coreReleaseReady(root = repositoryRoot) {
	const dist = path.join(root, "packages", "core", "dist");
	for (const name of ["index.js", "index.d.ts", "build-flavor.js"]) {
		if (!existsSync(path.join(dist, name))) return false;
	}
	if (!readFileSync(path.join(dist, "build-flavor.js"), "utf8").includes('const EMBEDDED_BUILD_FLAVOR = "commercial"')) return false;
	const stack = [dist];
	while (stack.length > 0) {
		const current = stack.pop();
		for (const entry of readdirSync(current, { withFileTypes: true })) {
			if (entry.isDirectory()) stack.push(path.join(current, entry.name));
			else if (entry.isFile() && entry.name.endsWith(".map")) return false;
		}
	}
	return true;
}

export function resolveSourceDateEpoch({ env = process.env, repoRoot = repositoryRoot, readGitEpoch } = {}) {
	const configured = env.SOURCE_DATE_EPOCH?.trim();
	if (/^\d+$/u.test(configured ?? "")) return configured;
	const value = (readGitEpoch ?? (() => execFileSync("git", ["show", "-s", "--format=%ct", "HEAD"], { cwd: repoRoot, encoding: "utf8" })) )().trim();
	if (!/^\d+$/u.test(value)) throw new Error("Cannot determine deterministic SOURCE_DATE_EPOCH for the Claude Code package build");
	return value;
}

function runPnpm(args, { cwd, env }) {
	const npmExecPath = process.env.npm_execpath;
	if (!npmExecPath || !path.isAbsolute(npmExecPath) || !existsSync(npmExecPath) || !statSync(npmExecPath).isFile()) {
		throw new Error("A pinned package-manager executable is unavailable; run this through pnpm");
	}
	execFileSync(process.execPath, [npmExecPath, ...args], { cwd, env, stdio: "inherit" });
}

export function ensureClaudeCodeDist({
	root = packageRoot,
	repoRoot = repositoryRoot,
	env = process.env,
	coreReady = coreReleaseReady,
	run = runPnpm,
	readGitEpoch,
} = {}) {
	const current = inspectClaudeCodeDist(root);
	if (current.ready) {
		console.log(`[claude-code] ${current.signed ? "signed" : "release"} dist is complete; preserving it byte-for-byte`);
		return { built: false, signed: current.signed };
	}

	const buildEnv = {
		...env,
		AIDR_DETERMINISTIC_MANIFEST: "1",
		SOURCE_DATE_EPOCH: resolveSourceDateEpoch({ env, repoRoot, readGitEpoch }),
	};
	if (!coreReady(repoRoot)) {
		run(["--filter", "@singularityrd/aidr-core", "run", "build:release"], { cwd: repoRoot, env: buildEnv });
	}
	run(["run", "build:release"], { cwd: root, env: buildEnv });

	const built = inspectClaudeCodeDist(root);
	if (!built.ready) throw new Error(`Claude Code release build did not produce a packable dist (${built.problems.join(", ")})`);
	return { built: true, signed: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	ensureClaudeCodeDist();
}
