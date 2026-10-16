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
	type UnprotectedAiTool,
	validateFrameworkMappingsAgainstRules,
} from "@singularityrd/aidr-core";
import { ct } from "../i18n/index.js";
import { resolveBundledDataDirs } from "../utils/test-protection.js";
import { unprotectedAiTools } from "../utils/unprotected-tools.js";

const COVERAGE_FORMATS = ["table", "json", "markdown"] as const;
type CoverageFormat = (typeof COVERAGE_FORMATS)[number];

export interface CoverageOptions {
	format?: string;
}

/** Test seams; production callers pass nothing. */
export interface CoverageDependencies {
	threatsDir?: string;
	/** AI tools without an AIDR connector; detected from the home directory and PATH by default. */
	unprotectedTools?: UnprotectedAiTool[];
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
		fail(
			err,
			ct("coverage.badFormat", {
				format: String(options.format),
				formats: COVERAGE_FORMATS.join(", "),
			}),
		);
		return;
	}

	const threatsDir = dependencies.threatsDir ?? resolveBundledDataDirs().threatsDir;
	const mappingPath = join(threatsDir, FRAMEWORK_MAPPINGS_RELATIVE_PATH);
	if (!existsSync(threatsDir) || !existsSync(mappingPath)) {
		fail(
			err,
			ct("coverage.noMapping", { path: threatsDir, mapping: FRAMEWORK_MAPPINGS_RELATIVE_PATH }),
		);
		return;
	}

	const { mappings, errors } = parseFrameworkMappingsYaml(readFileSync(mappingPath, "utf8"));
	if (!mappings) {
		fail(err, ct("coverage.invalidMapping", { path: mappingPath, errors: errors.join("\n  ") }));
		return;
	}

	const rules = toCoverageRules(await loadThreats(threatsDir));
	if (rules.length === 0) {
		fail(err, ct("coverage.noRules", { path: threatsDir }));
		return;
	}

	const matrix = buildCoverageMatrix(mappings, rules);
	// The mapped coverage applies only to agents AIDR has a connector for: name the others.
	const unprotected = unprotectedAiTools(dependencies);
	const labels = unprotected.map((tool) => tool.label).join(", ");
	const unprotectedLine =
		unprotected.length > 0
			? ct("coverage.unprotected", { tools: labels })
			: ct("coverage.unprotectedNone");
	if (format === "json") {
		const json = {
			...coverageMatrixToJson(matrix),
			unprotected_ai_tools: unprotected.map((tool) => ({ id: tool.id, label: tool.label })),
		};
		out(`${JSON.stringify(json, null, 2)}\n`);
	} else if (format === "markdown") out(`${renderCoverageMarkdown(matrix)}\n${unprotectedLine}\n`);
	else out(`${renderCoverageTable(matrix)}\n${unprotectedLine}\n`);

	// The matrix is still printed, but an inconsistent mapping is never reported
	// as a clean result: list the problems and exit non-zero.
	const problems = validateFrameworkMappingsAgainstRules(mappings, rules);
	if (problems.length > 0) {
		fail(err, ct("coverage.mismatch", { count: problems.length, problems: problems.join("\n  ") }));
	}
}

export default async function coverageCommand(options: CoverageOptions): Promise<void> {
	// Commander passes the Command as the second argument; never treat it as dependencies.
	await runCoverage(options);
}
