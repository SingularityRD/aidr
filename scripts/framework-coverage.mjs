#!/usr/bin/env node
/**
 * Security framework coverage matrix (OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS).
 *
 * Reads threats/*.yaml and threats/mappings/frameworks.yaml through the core
 * package (the same loader and resolver the runtime uses), validates that every
 * rule is mapped and every assessment agrees with the rule counts, then renders:
 *
 *   docs/framework-coverage.md                                 (human matrix)
 *   packages/dashboard/src/generated/framework-coverage.json   (bundled into the dashboard)
 *
 *   pnpm coverage:frameworks               # drift check: non-zero exit when stale or invalid
 *   pnpm coverage:frameworks -- --write    # regenerate both files
 *
 * Core is built first when its dist/ is missing or older than its sources.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ensureCoreBuild } from "./ensure-core-build.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
export const COVERAGE_DOC_PATH = join(root, "docs", "framework-coverage.md");
export const COVERAGE_ARTIFACT_PATH = join(
	root,
	"packages",
	"dashboard",
	"src",
	"generated",
	"framework-coverage.json",
);
const THREATS_DIR = join(root, "threats");

/** Render both outputs from the repository rules; throws with every problem found. */
export async function renderFrameworkCoverage(core) {
	const mappingPath = join(THREATS_DIR, "mappings", "frameworks.yaml");
	const { mappings, errors } = core.parseFrameworkMappingsYaml(readFileSync(mappingPath, "utf8"));
	if (!mappings) throw new Error(`Invalid ${relative(root, mappingPath)}:\n  ${errors.join("\n  ")}`);
	const rules = core.toCoverageRules(await core.loadThreats(THREATS_DIR));
	const problems = core.validateFrameworkMappingsAgainstRules(mappings, rules);
	if (problems.length > 0) {
		throw new Error(`Framework mapping is inconsistent with the rules:\n  ${problems.join("\n  ")}`);
	}
	return {
		doc: core.renderCoverageDocument(core.buildCoverageMatrix(mappings, rules)),
		artifact: `${JSON.stringify(core.buildDashboardCoverageArtifact(mappings, rules), null, 2)}\n`,
	};
}

function readOrEmpty(path) {
	try {
		return readFileSync(path, "utf8");
	} catch {
		return "";
	}
}

async function main(argv) {
	const write = argv.includes("--write");
	if (ensureCoreBuild() !== 0) return 1;
	const core = await import(pathToFileURL(join(root, "packages", "core", "dist", "index.js")).href);
	let outputs;
	try {
		outputs = await renderFrameworkCoverage(core);
	} catch (error) {
		console.error(error.message);
		return 1;
	}
	const targets = [
		[COVERAGE_DOC_PATH, outputs.doc],
		[COVERAGE_ARTIFACT_PATH, outputs.artifact],
	];
	if (write) {
		for (const [path, content] of targets) {
			mkdirSync(dirname(path), { recursive: true });
			writeFileSync(path, content);
			console.log(`wrote ${relative(root, path)}`);
		}
		return 0;
	}
	const stale = targets.filter(([path, content]) => readOrEmpty(path) !== content);
	if (stale.length > 0) {
		for (const [path] of stale) console.error(`stale: ${relative(root, path)}`);
		console.error("Run `pnpm coverage:frameworks -- --write` and commit the result.");
		return 1;
	}
	console.log("framework coverage is up to date");
	return 0;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exitCode = await main(process.argv.slice(2));
