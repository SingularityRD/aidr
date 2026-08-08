import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { CRITICAL_EXCLUSION_REGISTRY } from "./source-ledger.mjs";

export const DEFAULT_SEED = 424242;
export const DEFAULT_MINIMUM_SCORE = 0.85;
export const SECURITY_OPERATOR_CHECKS = Object.freeze([
	"authorization-boundary",
	"tenant-isolation",
	"fail-closed",
	"input-validation",
	"secret-redaction",
	"integrity-boundary",
]);
export const DEFAULT_MUTATION_TARGETS = Object.freeze(Object.keys(CRITICAL_EXCLUSION_REGISTRY).sort(compareStrings));

export function evaluateMutationReport(
	report,
	{ seed = DEFAULT_SEED, minimumScore = DEFAULT_MINIMUM_SCORE, requiredOperators = SECURITY_OPERATOR_CHECKS } = {},
) {
	if (minimumScore < DEFAULT_MINIMUM_SCORE) throw new Error(`Mutation threshold cannot be reduced below ${DEFAULT_MINIMUM_SCORE}`);
	const failures = [];
	const reportSeed = report?.seed ?? report?.random_seed;
	if (reportSeed !== undefined && Number(reportSeed) !== seed) failures.push(`Mutation report seed mismatch: expected ${seed}`);

	const reportedScore = readScore(report);
	if (reportedScore === null) failures.push("Mutation runner report has no numeric mutation score");
	else if (scoreRatio(reportedScore) < minimumScore) failures.push(`Mutation score below threshold: ${reportedScore} < ${minimumScore}`);

	const operatorChecks = readOperatorChecks(report);
	for (const operator of requiredOperators) {
		const check = operatorChecks.get(normalizeId(operator));
		if (!check) failures.push(`Missing security mutation operator check: ${operator}`);
		else if (!isPassingStatus(check.status)) failures.push(`Security mutation operator check failed: ${operator}`);
	}

	return {
		passed: failures.length === 0,
		failures: failures.sort(compareStrings),
		seed,
		minimum_score: minimumScore,
		reported_score: reportedScore,
		score_source: reportedScore === null ? null : "mutation-runner-report",
		operator_checks: [...operatorChecks.entries()]
			.sort(([left], [right]) => compareStrings(left, right))
			.map(([id, check]) => ({ id, status: check.status })),
	};
}

export async function runMutationGate({
	rootDir = process.cwd(),
	runner = process.env.AIDR_MUTATION_RUNNER,
	runnerArgs = [],
	seed = DEFAULT_SEED,
	minimumScore = DEFAULT_MINIMUM_SCORE,
	targets = DEFAULT_MUTATION_TARGETS,
	requiredOperators = SECURITY_OPERATOR_CHECKS,
	reportPath,
} = {}) {
	const normalizedSeed = normalizeSeed(seed);
	const normalizedTargets = [...targets].map(String).sort(compareStrings);
	const normalizedOperators = [...requiredOperators].map(String).sort(compareStrings);
	const command = resolveRunner(runner);
	let temporaryDirectory;
	let effectiveReportPath = reportPath;
	try {
		if (!effectiveReportPath) {
			temporaryDirectory = await mkdtemp(path.join(os.tmpdir(), "aidr-mutation-gate-"));
			effectiveReportPath = path.join(temporaryDirectory, "mutation-report.json");
		} else effectiveReportPath = path.resolve(rootDir, effectiveReportPath);

		const execution = await executeRunner(command, {
			cwd: path.resolve(rootDir),
			env: {
				AIDR_MUTATION_SEED: String(normalizedSeed),
				AIDR_MUTATION_OPERATORS: normalizedOperators.join(","),
				AIDR_MUTATION_TARGETS: JSON.stringify(normalizedTargets),
				AIDR_MUTATION_REPORT_PATH: effectiveReportPath,
			},
			args: runnerArgs,
		});
		if (execution.code !== 0) throw new Error(`Mutation runner failed with exit code ${execution.code}`);

		const report = await readMutationReport(effectiveReportPath, execution.stdout);
		return {
			...evaluateMutationReport(report, {
				seed: normalizedSeed,
				minimumScore,
				requiredOperators: normalizedOperators,
			}),
			runner: command,
			targets: normalizedTargets,
		};
	} finally {
		if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true });
	}
}

function normalizeSeed(value) {
	const seed = Number(value);
	if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) throw new Error("Mutation seed must be an unsigned 32-bit integer");
	return seed;
}

function resolveRunner(runner) {
	if (Array.isArray(runner)) {
		if (runner.length === 0 || !runner[0]) throw new Error("Mutation runner unavailable: configure AIDR_MUTATION_RUNNER");
		return runner.map(String);
	}
	if (typeof runner !== "string" || !runner.trim()) throw new Error("Mutation runner unavailable: configure AIDR_MUTATION_RUNNER");
	return tokenizeCommand(runner);
}

function tokenizeCommand(command) {
	const tokens = [...command.matchAll(/"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|([^\s]+)/g)].map((match) => match[1] ?? match[2] ?? match[3]);
	if (tokens.length === 0) throw new Error("Mutation runner unavailable: configure AIDR_MUTATION_RUNNER");
	return tokens;
}

function executeRunner(command, { cwd, env, args }) {
	return new Promise((resolve, reject) => {
		let settled = false;
		const child = spawn(command[0], [...command.slice(1), ...args], {
			cwd,
			env: { ...process.env, ...env },
			 shell: false,
		});
		let stdout = "";
		let stderr = "";
		child.stdout?.setEncoding("utf8");
		child.stderr?.setEncoding("utf8");
		child.stdout?.on("data", (chunk) => { stdout += chunk; });
		child.stderr?.on("data", (chunk) => { stderr += chunk; });
		child.once("error", (error) => {
			if (settled) return;
			settled = true;
			if (error.code === "ENOENT") reject(new Error(`Mutation runner unavailable: ${command[0]}`));
			else reject(error);
		});
		child.once("close", (code) => {
			if (settled) return;
			settled = true;
			resolve({ code: code ?? 1, stdout, stderr });
		});
	});
}

async function readMutationReport(reportPath, stdout) {
	try {
		return JSON.parse(await readFile(reportPath, "utf8"));
	} catch (error) {
		if (error?.code !== "ENOENT") throw new Error(`Mutation report is not valid JSON: ${error.message}`);
		try {
			return JSON.parse(stdout.trim());
		} catch {
			throw new Error("Mutation runner did not produce a report; refusing to infer a score");
		}
	}
}

function readScore(report) {
	const score = report?.mutation_score ?? report?.mutationScore ?? report?.score;
	return typeof score === "number" && Number.isFinite(score) ? score : null;
}

function scoreRatio(score) {
	return score > 1 ? score / 100 : score;
}

function readOperatorChecks(report) {
	const source = report?.security_operator_checks ?? report?.operator_checks ?? report?.operatorChecks;
	const checks = new Map();
	if (Array.isArray(source)) {
		for (const check of source) {
			if (check && typeof check === "object" && (check.name ?? check.id)) {
				checks.set(normalizeId(check.name ?? check.id), {
					...check,
					status: check.status ?? check.result ?? check.passed,
				});
			}
		}
	} else if (source && typeof source === "object") {
		for (const [name, check] of Object.entries(source)) {
			const normalizedCheck = typeof check === "object" ? check : { status: check };
			checks.set(normalizeId(name), {
				...normalizedCheck,
				status: normalizedCheck.status ?? normalizedCheck.result ?? normalizedCheck.passed,
			});
		}
	}
	return checks;
}

function isPassingStatus(status) {
	return status === true || ["ok", "pass", "passed", "success", "satisfied"].includes(String(status).toLowerCase());
}

function normalizeId(value) {
	return String(value).trim().toLowerCase().replaceAll("_", "-").replace(/\s+/g, "-");
}

function compareStrings(left, right) {
	return left < right ? -1 : left > right ? 1 : 0;
}

async function main(argv) {
	const args = parseArgs(argv);
	if (args.help) {
		console.log("Usage: node scripts/assurance/mutation-gate.mjs --runner <command> [--root <dir>] [--seed <n>]");
		return;
	}
	const result = await runMutationGate(args);
	process.stdout.write(`${JSON.stringify(result, null, "\t")}\n`);
	if (!result.passed) process.exitCode = 1;
}

function parseArgs(argv) {
	const args = {};
	for (let index = 0; index < argv.length; index++) {
		const argument = argv[index];
		if (argument === "--help") args.help = true;
		else if (argument === "--root") args.rootDir = argv[++index];
		else if (argument === "--runner") args.runner = argv[++index];
		else if (argument === "--runner-arg") (args.runnerArgs ??= []).push(argv[++index]);
		else if (argument === "--report") args.reportPath = argv[++index];
		else if (argument === "--seed") args.seed = argv[++index];
		else throw new Error(`Unknown argument: ${argument}`);
	}
	return args;
}

if (process.argv[1] && path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1])) {
	main(process.argv.slice(2)).catch((error) => {
		console.error(`Mutation gate failed closed: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	});
}
