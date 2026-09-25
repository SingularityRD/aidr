import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import {
	buildCoverageMatrix,
	coverageMatrixToJson,
	FRAMEWORK_MAPPINGS_RELATIVE_PATH,
	loadThreats,
	parseFrameworkMappingsYaml,
	renderCoverageMarkdown,
	renderCoverageTable,
	toCoverageRules,
	validateFrameworkMappingsAgainstRules,
} from "@singularityrd/aidr-core";
import { resolveBundledDataDirs } from "../utils/test-protection.js";

const COVERAGE_FORMATS = ["table", "json", "markdown"] as const;
type CoverageFormat = (typeof COVERAGE_FORMATS)[number];

export interface CoverageOptions {
	format?: string;
}

/** Test seams; production callers pass nothing. */
export interface CoverageDependencies {
	threatsDir?: string;
	out?: (text: string) => void;
	err?: (text: string) => void;
}

function fail(err: (text: string) => void, message: string): void {
	err(message);
	process.exitCode = 1;
}

/**
 * `aidr coverage [--format table|json|markdown]`
 *
 * Prints how the rules installed with this CLI map to OWASP Top 10 for LLM
 * Applications 2025, OWASP Top 10 for Agentic Applications 2026 and MITRE
 * ATLAS: per item the rule count, example rules and an honest status with its
 * rationale. It reads the same rule files and mapping the runtime loads, so the
 * numbers describe what is actually installed. Nothing leaves the machine.
 */
export async function runCoverage(
	options: CoverageOptions,
	dependencies: CoverageDependencies = {},
): Promise<void> {
	const out = dependencies.out ?? ((text: string) => process.stdout.write(text));
	const err = dependencies.err ?? ((text: string) => console.error(text));
	const format = (options.format ?? "table").toLowerCase();
	if (!COVERAGE_FORMATS.includes(format as CoverageFormat)) {
		fail(err, `Unknown format "${options.format}". Use one of: ${COVERAGE_FORMATS.join(", ")}.`);
		return;
	}

	const threatsDir = dependencies.threatsDir ?? resolveBundledDataDirs().threatsDir;
	const mappingPath = join(threatsDir, FRAMEWORK_MAPPINGS_RELATIVE_PATH);
	if (!existsSync(threatsDir) || !existsSync(mappingPath)) {
		fail(
			err,
			`No rule set with a framework mapping was found at ${threatsDir}. Reinstall or rebuild the CLI (its resources/threats directory ships ${FRAMEWORK_MAPPINGS_RELATIVE_PATH}).`,
		);
		return;
	}

	const { mappings, errors } = parseFrameworkMappingsYaml(readFileSync(mappingPath, "utf8"));
	if (!mappings) {
		fail(err, `The framework mapping at ${mappingPath} is invalid:\n  ${errors.join("\n  ")}`);
		return;
	}

	const rules = toCoverageRules(await loadThreats(threatsDir));
	if (rules.length === 0) {
		fail(err, `No detection rules loaded from ${threatsDir}; there is no coverage to report.`);
		return;
	}

	const matrix = buildCoverageMatrix(mappings, rules);
	if (format === "json") out(`${JSON.stringify(coverageMatrixToJson(matrix), null, 2)}\n`);
	else if (format === "markdown") out(renderCoverageMarkdown(matrix));
	else out(renderCoverageTable(matrix));

	// The matrix is still printed, but an inconsistent mapping is never reported
	// as a clean result: list the problems and exit non-zero.
	const problems = validateFrameworkMappingsAgainstRules(mappings, rules);
	if (problems.length > 0) {
		fail(
			err,
			`Warning: the framework mapping does not match the installed rules (${problems.length} problem(s)):\n  ${problems.join("\n  ")}`,
		);
	}
}

export default async function coverageCommand(options: CoverageOptions): Promise<void> {
	// Commander passes the Command as the second argument; never treat it as dependencies.
	await runCoverage(options);
}
