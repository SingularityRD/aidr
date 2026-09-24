import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_EXTENSIONS = new Set([".cjs", ".js", ".jsx", ".json", ".mjs", ".py", ".ts", ".tsx"]);
const TEST_DIRECTORY_NAMES = new Set(["__tests__", "__test__", "fixtures", "fixture", "test", "tests"]);
const SKIPPED_DIRECTORY_NAMES = new Set([".git", ".next", "coverage", "dist", "node_modules", "resources"]);
const TEST_FILE_PATTERN = /\.(?:e2e\.)?(?:spec|test)\.[^.]+$/i;

const DEFAULT_SOURCE_ROOTS = Object.freeze(["packages", "services/aig-bridge/app", "supabase/functions"]);

// These are deliberately explicit. A coverage exclusion is a release-risk
// exception, not an implementation detail that can disappear unnoticed.
export const CRITICAL_EXCLUSION_REGISTRY = Object.freeze({
	"packages/core/src/clients/control-plane.ts": {
		reason: "Control-plane integration needs dedicated contract and E2E evidence.",
	},
	"packages/core/src/evaluator.ts": {
		reason: "Evaluator decision paths need dedicated policy and mutation evidence.",
	},
	"packages/core/src/integrity/index.ts": {
		reason: "Integrity verification needs dedicated tamper and runtime evidence.",
	},
	"packages/core/src/integrity/runtime.ts": {
		reason: "Runtime integrity enforcement needs dedicated tamper and startup evidence.",
	},
	"packages/core/src/intel/semver.ts": {
		reason: "Version intelligence needs dedicated parser and compatibility evidence.",
	},
	"packages/core/src/managed.ts": {
		reason: "Managed-mode enforcement needs dedicated policy and integration evidence.",
	},
	"packages/core/src/policy.ts": {
		reason: "Policy decision paths need dedicated unit, property, and mutation evidence.",
	},
	"packages/core/src/session-start-scan.ts": {
		reason: "Session-start scanning needs dedicated hook and plugin-scan evidence.",
	},
	"packages/core/src/session-start.ts": {
		reason: "Session-start orchestration needs dedicated hook and integration evidence.",
	},
});

export async function buildLedger({
	rootDir = process.cwd(),
	sourceRoots = DEFAULT_SOURCE_ROOTS,
	coverageConfigPath = "vitest.config.ts",
	coverageExclusions,
	exclusionRegistry = CRITICAL_EXCLUSION_REGISTRY,
	metadata = {},
} = {}) {
	const absoluteRoot = path.resolve(rootDir);
	const normalizedRoots = [...sourceRoots].map(normalizeRelativePath).sort(compareStrings);
	const files = await collectProductionFiles(absoluteRoot, normalizedRoots);
	const testFiles = await collectTestFiles(absoluteRoot, normalizedRoots);
	const configuredExclusions = coverageExclusions
		? coverageExclusions.map(normalizeRelativePath).sort(compareStrings)
		: await readCoverageExclusions(absoluteRoot, coverageConfigPath);
	const registry = normalizeExclusionRegistry(exclusionRegistry);
	const failures = validateExclusions({ files, configuredExclusions, registry });
	if (failures.length > 0) throw new Error(failures.join("\n"));

	const fileEntries = [];
	for (const relativePath of files) {
		const bytes = await readFile(path.join(absoluteRoot, ...relativePath.split("/")));
		const generated = isGeneratedFile(relativePath, bytes);
		const exclusion = matchingCoverageExclusion(relativePath, configuredExclusions);
		const risk = riskForPath(relativePath, registry, generated);
		const tests = relatedTests(relativePath, testFiles);
		fileEntries.push({
			path: relativePath,
			package: packagePath(relativePath),
			classification: generated ? "generated" : "first-party",
			status: "active",
			sha256: createHash("sha256").update(bytes).digest("hex"),
			hash: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
			lines: countLines(bytes),
			line_count: countLines(bytes),
			risk,
			owner: ownerForPath(relativePath, metadata),
			requirements: requirementsForPath(relativePath, risk),
			tests,
			coverage: {
				status: exclusion ? "excluded" : "not-recorded",
				excluded: Boolean(exclusion),
				exclusion,
				lines: null,
				branches: null,
				functions: null,
				statements: null,
			},
		});
	}

	const packageTotals = new Map();
	for (const entry of fileEntries) {
		const current = packageTotals.get(entry.package) ?? { files: 0, lines: 0 };
		current.files += 1;
		current.lines += entry.lines;
		packageTotals.set(entry.package, current);
	}

	const criticalFiles = Object.keys(registry)
		.sort(compareStrings)
		.map((relativePath) => {
			const file = fileEntries.find((entry) => entry.path === relativePath);
			return {
				path: relativePath,
				lines: file.lines,
				reason: registry[relativePath].reason,
				coverageExcluded: Boolean(matchingCoverageExclusion(relativePath, configuredExclusions)),
			};
		});

	return {
		schema_version: 2,
		source_roots: normalizedRoots,
		coverage_exclusions: configuredExclusions,
		totals: {
			files: fileEntries.length,
			lines: fileEntries.reduce((total, entry) => total + entry.lines, 0),
		},
		packages: [...packageTotals.entries()]
			.sort(([left], [right]) => compareStrings(left, right))
			.map(([name, totals]) => ({ name, ...totals })),
		files: fileEntries,
		critical_files: criticalFiles,
	};
}

function renderLedger(ledger) {
	return `${JSON.stringify(ledger, null, "\t")}\n`;
}

async function collectProductionFiles(rootDir, sourceRoots) {
	const files = [];
	for (const sourceRoot of sourceRoots) {
		const absoluteSourceRoot = path.resolve(rootDir, ...sourceRoot.split("/"));
		if (!isWithin(absoluteSourceRoot, rootDir)) throw new Error(`Source root escapes repository root: ${sourceRoot}`);
		await walk(absoluteSourceRoot, sourceRoot, files, false);
	}
	return files.sort(compareStrings);
}

async function collectTestFiles(rootDir, sourceRoots) {
	const files = [];
	for (const sourceRoot of sourceRoots) {
		const absoluteSourceRoot = path.resolve(rootDir, ...sourceRoot.split("/"));
		if (!isWithin(absoluteSourceRoot, rootDir)) throw new Error(`Source root escapes repository root: ${sourceRoot}`);
		await walk(absoluteSourceRoot, sourceRoot, files, true);
	}
	return files.sort(compareStrings);
}

async function walk(absoluteDirectory, relativeDirectory, output, testsOnly) {
	let entries;
	try {
		entries = await readdir(absoluteDirectory, { withFileTypes: true });
	} catch (error) {
		if (error?.code === "ENOENT") return;
		throw error;
	}

	for (const entry of entries.sort((left, right) => compareStrings(left.name, right.name))) {
		if (entry.isSymbolicLink() || SKIPPED_DIRECTORY_NAMES.has(entry.name)) continue;
		const relativePath = normalizeRelativePath(`${relativeDirectory}/${entry.name}`);
		if (entry.isDirectory()) {
			await walk(path.join(absoluteDirectory, entry.name), relativePath, output, testsOnly);
			continue;
		}
		if (!entry.isFile() || !SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
		const isTest = TEST_FILE_PATTERN.test(entry.name) || relativePath.split("/").some((part) => TEST_DIRECTORY_NAMES.has(part));
		if (testsOnly ? isTest : !isTest && isProductionSourceFile(relativePath)) output.push(relativePath);
	}
}

function isProductionSourceFile(relativePath) {
	const parts = relativePath.split("/");
	const isPackageSource = parts[0] === "packages" && parts.includes("src");
	const isServiceSource = relativePath.startsWith("services/aig-bridge/app/");
	const isSupabaseSource = relativePath.startsWith("supabase/functions/");
	return isPackageSource || isServiceSource || isSupabaseSource;
}

function isGeneratedFile(relativePath, bytes) {
	const normalized = relativePath.toLowerCase();
	if (normalized.includes("/generated/") || /(?:^|[._-])generated(?:[._-]|$)/i.test(path.basename(relativePath))) return true;
	if (normalized.endsWith("/database.types.ts")) return true;
	const prefix = bytes.toString("utf8", 0, Math.min(bytes.length, 4096));
	return /(?:@generated|auto[- ]generated|generated schema types|do not edit(?: this file)?)/i.test(prefix);
}

function riskForPath(relativePath, registry, generated) {
	if (registry[relativePath]) return "critical";
	if (generated) return "low";
	if (/(auth|authoriz|contain|control-plane|credential|device|encrypt|enroll|integrity|managed|policy|redact|session-start|tenant|token|upload|validation|webhook)/i.test(relativePath)) return "high";
	if (relativePath.startsWith("services/") || relativePath.startsWith("supabase/")) return "medium";
	return "low";
}

function ownerForPath(relativePath, metadata) {
	if (metadata[relativePath]?.owner) return metadata[relativePath].owner;
	const parts = relativePath.split("/");
	if (parts[0] === "packages" && parts[1]) return `package:${parts[1]}`;
	if (parts[0] === "services" && parts[1]) return `service:${parts[1]}`;
	if (parts[0] === "supabase") return "supabase-functions";
	return "unassigned";
}

function requirementsForPath(relativePath, risk) {
	const requirements = ["REQ-SOURCE-TRACEABILITY"];
	if (risk === "critical" || risk === "high") requirements.push("REQ-SECURITY-DECISION-TRACEABILITY");
	if (relativePath.startsWith("services/") || relativePath.startsWith("supabase/")) requirements.push("REQ-EXTERNAL-CONTRACT-VALIDATION");
	return requirements;
}

function relatedTests(relativePath, testFiles) {
	const stem = path.basename(relativePath).replace(path.extname(relativePath), "");
	const packagePrefix = relativePath.startsWith("packages/") ? relativePath.split("/").slice(0, 2).join("/") : path.dirname(relativePath);
	return testFiles.filter((testPath) => {
		if (!testPath.startsWith(packagePrefix)) return false;
		const testName = path.basename(testPath).toLowerCase();
		return testName.includes(stem.toLowerCase()) || path.dirname(testPath) === path.dirname(relativePath);
	});
}

async function readCoverageExclusions(rootDir, coverageConfigPath) {
	if (coverageConfigPath === null) return [];
	const configPath = path.resolve(rootDir, coverageConfigPath);
	let config;
	try {
		config = await readFile(configPath, "utf8");
	} catch (error) {
		if (error?.code === "ENOENT") return [];
		throw error;
	}
	const coverageStart = config.indexOf("coverage");
	const excludeStart = config.indexOf("exclude", coverageStart);
	const arrayStart = config.indexOf("[", excludeStart);
	if (coverageStart < 0 || excludeStart < 0 || arrayStart < 0) return [];
	const arrayEnd = findClosingBracket(config, arrayStart);
	if (arrayEnd < 0) throw new Error(`Unable to parse coverage exclusions in ${coverageConfigPath}`);
	return [...config.slice(arrayStart + 1, arrayEnd).matchAll(/(['"])((?:\\.|(?!\1).)*)\1/g)]
		.map((match) => match[2].replaceAll(`\\${match[1]}`, match[1]).replaceAll("\\\\", "\\"))
		.map(normalizeRelativePath)
		.sort(compareStrings);
}

function findClosingBracket(text, start) {
	let depth = 0;
	let quote;
	for (let index = start; index < text.length; index++) {
		const current = text[index];
		if (quote) {
			if (current === "\\") index++;
			else if (current === quote) quote = undefined;
			continue;
		}
		if (current === "\"" || current === "'") {
			quote = current;
			continue;
		}
		if (current === "[") depth++;
		if (current === "]" && --depth === 0) return index;
	}
	return -1;
}

function normalizeExclusionRegistry(registry) {
	return Object.fromEntries(
		Object.entries(registry)
			.map(([relativePath, value]) => [normalizeRelativePath(relativePath), { reason: typeof value === "string" ? value : value?.reason }])
			.sort(([left], [right]) => compareStrings(left, right)),
	);
}

function validateExclusions({ files, configuredExclusions, registry }) {
	const fileSet = new Set(files);
	const failures = [];
	for (const pattern of configuredExclusions) {
		const matches = files.filter((file) => matchesPattern(file, pattern));
		for (const file of matches) {
			if (registry[file] === undefined) failures.push(`Unaccounted first-party coverage exclusion: ${file} (pattern: ${pattern})`);
		}
	}
	for (const [relativePath, entry] of Object.entries(registry)) {
		if (!entry.reason?.trim()) failures.push(`Critical source has no reason: ${relativePath}`);
		if (!fileSet.has(relativePath)) failures.push(`Critical source is not a production source file: ${relativePath}`);
	}
	return failures.sort(compareStrings);
}

function matchingCoverageExclusion(relativePath, exclusions) {
	return exclusions.find((pattern) => matchesPattern(relativePath, pattern)) ?? null;
}

function matchesPattern(relativePath, pattern) {
	const normalizedPattern = normalizeRelativePath(pattern);
	if (!normalizedPattern.includes("*")) return relativePath === normalizedPattern;
	const expression = normalizedPattern
		.replace(/[.+^${}()|[\]\\]/g, "\\$&")
		.replaceAll("**", "§§")
		.replaceAll("*", "[^/]*")
		.replaceAll("§§", ".*");
	return new RegExp(`^${expression}$`).test(relativePath);
}

function packagePath(relativePath) {
	const parts = relativePath.split("/");
	if (parts[0] === "packages") return parts.slice(0, 2).join("/");
	if (parts[0] === "services") return parts.slice(0, 2).join("/");
	return parts.slice(0, 2).join("/");
}

function countLines(bytes) {
	if (bytes.length === 0) return 0;
	let lines = 1;
	for (const byte of bytes) if (byte === 0x0a) lines++;
	return bytes[bytes.length - 1] === 0x0a ? lines - 1 : lines;
}

function normalizeRelativePath(value) {
	return String(value).replaceAll("\\", "/").replace(/^\.\//, "");
}

function isWithin(candidate, root) {
	const relative = path.relative(root, candidate);
	return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function compareStrings(left, right) {
	return left < right ? -1 : left > right ? 1 : 0;
}

async function main(argv) {
	const args = parseArgs(argv);
	if (args.help) {
		console.log("Usage: node scripts/assurance/source-ledger.mjs [--root <dir>] [--output <file>]");
		return;
	}
	const rootDir = path.resolve(args.root ?? process.cwd());
	const ledger = await buildLedger({ rootDir, coverageConfigPath: args.coverageConfig ?? "vitest.config.ts" });
	const rendered = renderLedger(ledger);
	if (args.output) {
		const outputPath = path.resolve(rootDir, args.output);
		await mkdir(path.dirname(outputPath), { recursive: true });
		await writeFile(outputPath, rendered, "utf8");
	} else process.stdout.write(rendered);
}

function parseArgs(argv) {
	const args = {};
	for (let index = 0; index < argv.length; index++) {
		const argument = argv[index];
		if (argument === "--help") args.help = true;
		else if (argument === "--root") args.root = argv[++index];
		else if (argument === "--output") args.output = argv[++index];
		else if (argument === "--coverage-config") args.coverageConfig = argv[++index];
		else throw new Error(`Unknown argument: ${argument}`);
	}
	return args;
}

if (process.argv[1] && path.resolve(fileURLToPath(import.meta.url)) === path.resolve(process.argv[1])) {
	main(process.argv.slice(2)).catch((error) => {
		console.error(`Source assurance ledger failed: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 1;
	});
}
