#!/usr/bin/env node
/**
 * T01 native support-matrix runner.
 *
 * Reads `deploy/native/support-matrix.json`, probes every *advertised* host on
 * this machine, and runs the declared native scenario manifest for any host that
 * is actually present. It then emits one machine-readable record per host.
 *
 * The rules that matter:
 *
 *   1. An advertised connector whose host binary is missing is `HOST_UNAVAILABLE`
 *      and a NO-GO blocker. It is never skipped, and it never counts as covered.
 *   2. A probe that only reports a version is `VERSION_PROBED`, never PASS. A
 *      hook verdict is not a host enforcement result.
 *   3. A row with no named acceptance evidence keeps `acceptance: "open"`, so the
 *      local record can never round up to a supported row.
 *   4. Nothing here writes a PASS for a row it did not actually exercise.
 *   5. A scenario manifest that still carries the committed template's
 *      `REPLACE_WITH_*` placeholders is refused with
 *      `SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE` before any host is
 *      launched: a template copy is not a host observation.
 *
 * Usage:
 *   node deploy/native/run-support-matrix.mjs [--output <path>] [--probe-only]
 *   node deploy/native/run-support-matrix.mjs --scenario-file <manifest> [--output <path>]
 *
 * `--scenario-file` runs an explicit manifest (for example one produced by a
 * real host run) for every row whose connector declares a host in that
 * manifest; the other rows keep using `deploy/native/scenarios/<connector>.json`.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { release as osRelease, version as osVersion } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import {
	SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE,
	carriesTemplatePlaceholders,
	validateScenarioManifest,
} from "../../scripts/verify-native-host-matrix-v6.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MATRIX_PATH = join(HERE, "support-matrix.json");
const SCENARIOS_DIR = join(HERE, "scenarios");
const MATRIX_VERIFIER = resolve(HERE, "..", "..", "scripts", "verify-native-host-matrix-v6.mjs");

/**
 * The support-matrix contract. `deploy/native/support-matrix.schema.json` is the
 * published, machine-readable form of exactly these values.
 *
 * The checks in `validateMatrix` below stay normative: the schema is never
 * loaded here, never decides a release, and is deliberately not a second
 * validator. `deploy/native/run-support-matrix.test.mjs` asserts that the
 * schema's `required`/`properties` sets agree with these constants.
 */
export const MATRIX_SCHEMA_VERSION = 1;
export const MATRIX_KIND = "aidr-native-support-matrix";
export const MATRIX_DECISION = "NO-GO";
export const MATRIX_REVIEWED_AT_PATTERN = "^\\d{4}-\\d{2}-\\d{2}$";
export const HOST_BINARY_ENV_PATTERN = "^[A-Z][A-Z0-9_]*$";
export const SUPPORTED_PLATFORMS = ["windows", "linux", "macos"];
export const SUPPORTED_ARCHITECTURES = ["x64", "arm64"];
export const SUPPORTED_CONTEXTS = ["user", "service"];
/** Root fields every support matrix must declare. */
export const MATRIX_REQUIRED_FIELDS = [
	"schemaVersion",
	"kind",
	"reviewedAt",
	"decision",
	"decisionMeaning",
	"soldConnectorScope",
	"soldPlatformScope",
	"soldArchitectureScope",
	"soldDeploymentProfiles",
	"interceptionPointVocabulary",
	"rows",
	"residual",
];
/** Fields every row must declare. */
export const ROW_REQUIRED_FIELDS = [
	"connector",
	"hostBinary",
	"hostBinaryEnvOverride",
	"interceptionPoint",
	"outputInterceptionPoint",
	"tamperResistance",
	"supportedPlatforms",
	"supportedArchitectures",
	"supportedContexts",
	"installPath",
	"uninstallPath",
	"supportOwnerRole",
	"knownBypasses",
	"unobservedActions",
	"acceptanceEvidence",
];
/** Row fields the validator requires to be arrays. */
export const ROW_ARRAY_FIELDS = ["knownBypasses", "unobservedActions", "acceptanceEvidence", "installPath", "uninstallPath"];
export const EVIDENCE_REQUIRED_FIELDS = ["path", "sha256"];
export const EVIDENCE_SHA256_PATTERN = "^[0-9a-f]{64}$";
/** Fields every residual entry must declare. */
export const RESIDUAL_REQUIRED_FIELDS = ["id", "description", "ownerRole", "requiredInput", "acceptanceCommand", "acceptanceEvidence"];
/** Residual fields the validator requires to be non-empty strings. */
export const RESIDUAL_STRING_FIELDS = ["id", "description", "ownerRole", "requiredInput", "acceptanceCommand"];

/** The host id each sold connector declares in a native scenario manifest. */
export const CONNECTOR_HOST_IDS = {
	"claude-code": "claude",
	cursor: "cursor",
	vscode: "vscode",
	openclaw: "openclaw",
	opencode: "opencode",
	codex: "codex",
};

/** Scenario-manifest outcomes a host row may carry. */
export const SCENARIO_MANIFEST_MISSING = "SCENARIO_MANIFEST_MISSING";
export const SCENARIO_MANIFEST_UNREADABLE = "SCENARIO_MANIFEST_UNREADABLE";
export const SCENARIOS_PASSED = "SCENARIOS_PASSED";
export const SCENARIOS_OPEN = "SCENARIOS_OPEN";
/** Refusals: a manifest that cannot be evidence, or cannot be read, is never launched. */
export const SCENARIO_REFUSAL_STATUSES = [SCENARIO_MANIFEST_UNREADABLE, SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE];
/** The template refusal code is defined by the native-host gate, which owns the vocabulary. */
export { SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE };

const PLATFORMS = new Set(SUPPORTED_PLATFORMS);
const ARCHITECTURES = new Set(SUPPORTED_ARCHITECTURES);
const CONTEXTS = new Set(SUPPORTED_CONTEXTS);
const SHA256 = new RegExp(EVIDENCE_SHA256_PATTERN, "u");
const REVIEWED_AT = new RegExp(MATRIX_REVIEWED_AT_PATTERN, "u");
const HOST_BINARY_ENV = new RegExp(HOST_BINARY_ENV_PATTERN, "u");

export function currentPlatform() {
	if (process.platform === "win32") return "windows";
	if (process.platform === "darwin") return "macos";
	if (process.platform === "linux") return "linux";
	return process.platform;
}

function digest(value) {
	return createHash("sha256").update(value).digest("hex");
}

function loadMatrix(path = MATRIX_PATH) {
	const raw = readFileSync(path, "utf8");
	const matrix = JSON.parse(raw);
	validateMatrix(matrix);
	return { matrix, sha256: digest(raw) };
}

/** Structural validation. A malformed matrix is a hard error, not a warning. */
export function validateMatrix(matrix) {
	const fail = (message) => {
		throw new Error(`support matrix: ${message}`);
	};
	if (!matrix || typeof matrix !== "object" || Array.isArray(matrix)) fail("must be an object");
	for (const field of MATRIX_REQUIRED_FIELDS) {
		if (!Object.hasOwn(matrix, field)) fail(`${field} is required`);
	}
	if (matrix.schemaVersion !== MATRIX_SCHEMA_VERSION) fail("unsupported schemaVersion");
	if (matrix.kind !== MATRIX_KIND) fail(`kind must be ${MATRIX_KIND}`);
	if (typeof matrix.reviewedAt !== "string" || !REVIEWED_AT.test(matrix.reviewedAt)) {
		fail("reviewedAt must be a YYYY-MM-DD date");
	}
	if (matrix.decision !== MATRIX_DECISION) {
		fail(`decision must stay ${MATRIX_DECISION} until every row carries named real-host acceptance`);
	}
	if (typeof matrix.decisionMeaning !== "string" || matrix.decisionMeaning.trim().length === 0) {
		fail("decisionMeaning is required");
	}
	for (const field of ["soldConnectorScope", "soldPlatformScope", "soldArchitectureScope", "soldDeploymentProfiles", "interceptionPointVocabulary"]) {
		if (!Array.isArray(matrix[field]) || matrix[field].length === 0) fail(`${field} must be a non-empty array`);
		for (const entry of matrix[field]) {
			if (typeof entry !== "string" || entry.trim().length === 0) fail(`${field} entries must be non-empty strings`);
		}
	}
	for (const platform of matrix.soldPlatformScope) {
		if (!PLATFORMS.has(platform)) fail(`unknown sold platform ${platform}`);
	}
	for (const architecture of matrix.soldArchitectureScope) {
		if (!ARCHITECTURES.has(architecture)) fail(`unknown sold architecture ${architecture}`);
	}
	if (!Array.isArray(matrix.rows) || matrix.rows.length === 0) fail("rows must be a non-empty array");
	const seenConnectors = new Set();
	for (const row of matrix.rows) {
		if (!row || typeof row !== "object" || Array.isArray(row)) fail("rows must be objects");
		for (const field of ROW_REQUIRED_FIELDS) {
			if (!Object.hasOwn(row, field)) fail(`row ${row.connector ?? "?"} is missing ${field}`);
		}
		if (typeof row.connector !== "string" || !row.connector) fail("row.connector is required");
		if (seenConnectors.has(row.connector)) fail(`duplicate connector ${row.connector}`);
		seenConnectors.add(row.connector);
		if (!matrix.soldConnectorScope.includes(row.connector)) {
			fail(`row ${row.connector} is outside soldConnectorScope`);
		}
		if (row.hostBinary !== null && (typeof row.hostBinary !== "string" || row.hostBinary.trim().length === 0)) {
			fail(`row ${row.connector} hostBinary must be a non-empty string or null`);
		}
		if (row.hostBinaryEnvOverride !== null && (typeof row.hostBinaryEnvOverride !== "string" || !HOST_BINARY_ENV.test(row.hostBinaryEnvOverride))) {
			fail(`row ${row.connector} hostBinaryEnvOverride must be an uppercase environment variable name or null`);
		}
		if (typeof row.tamperResistance !== "string" || row.tamperResistance.trim().length === 0) {
			fail(`row ${row.connector} must describe its tamperResistance`);
		}
		if (!matrix.interceptionPointVocabulary.includes(row.interceptionPoint)) {
			fail(`row ${row.connector} has an unknown interceptionPoint`);
		}
		if (row.outputInterceptionPoint !== null && !matrix.interceptionPointVocabulary.includes(row.outputInterceptionPoint)) {
			fail(`row ${row.connector} has an unknown outputInterceptionPoint`);
		}
		if (!Array.isArray(row.supportedPlatforms) || row.supportedPlatforms.length === 0) {
			fail(`row ${row.connector} must declare supportedPlatforms`);
		}
		for (const platform of row.supportedPlatforms) {
			if (!PLATFORMS.has(platform)) fail(`row ${row.connector} declares unknown platform ${platform}`);
		}
		if (!Array.isArray(row.supportedArchitectures) || row.supportedArchitectures.length === 0) {
			fail(`row ${row.connector} must declare supportedArchitectures`);
		}
		for (const architecture of row.supportedArchitectures) {
			if (!ARCHITECTURES.has(architecture)) fail(`row ${row.connector} declares unknown architecture ${architecture}`);
		}
		if (!Array.isArray(row.supportedContexts) || row.supportedContexts.length === 0) {
			fail(`row ${row.connector} must declare supportedContexts`);
		}
		for (const context of row.supportedContexts) {
			if (!CONTEXTS.has(context)) fail(`row ${row.connector} declares unknown context ${context}`);
		}
		if (typeof row.supportOwnerRole !== "string" || row.supportOwnerRole.trim().length < 3) {
			fail(`row ${row.connector} must name a supportOwnerRole`);
		}
		for (const field of ROW_ARRAY_FIELDS) {
			if (!Array.isArray(row[field])) fail(`row ${row.connector}.${field} must be an array`);
		}
		for (const evidence of row.acceptanceEvidence) {
			if (typeof evidence !== "object" || evidence === null) fail(`row ${row.connector} has a malformed evidence entry`);
			for (const field of EVIDENCE_REQUIRED_FIELDS) {
				if (!Object.hasOwn(evidence, field)) fail(`row ${row.connector} evidence is missing ${field}`);
			}
			if (typeof evidence.path !== "string" || !evidence.path) fail(`row ${row.connector} evidence needs a path`);
			if (typeof evidence.sha256 !== "string" || !SHA256.test(evidence.sha256)) {
				fail(`row ${row.connector} evidence needs a SHA-256`);
			}
			const evidencePath = resolve(evidence.path);
			if (!existsSync(evidencePath)) fail(`row ${row.connector} evidence path does not exist: ${evidence.path}`);
			if (digest(readFileSync(evidencePath)) !== evidence.sha256) {
				fail(`row ${row.connector} evidence digest does not match: ${evidence.path}`);
			}
		}
	}
	for (const connector of matrix.soldConnectorScope) {
		if (!seenConnectors.has(connector)) fail(`sold connector ${connector} has no support-matrix row`);
	}
	if (!Array.isArray(matrix.residual)) fail("residual must be an array");
	for (const item of matrix.residual) {
		if (!item || typeof item !== "object" || Array.isArray(item)) fail("residual entries must be objects");
		for (const field of RESIDUAL_REQUIRED_FIELDS) {
			if (!Object.hasOwn(item, field)) fail(`residual ${item.id ?? "?"} is missing ${field}`);
		}
		for (const field of RESIDUAL_STRING_FIELDS) {
			if (typeof item[field] !== "string" || item[field].trim().length === 0) {
				fail(`residual ${item.id} ${field} must be a non-empty string`);
			}
		}
		if (!Array.isArray(item.acceptanceEvidence)) fail(`residual ${item.id}.acceptanceEvidence must be an array`);
	}
	return matrix;
}

/** Locate the host binary the same way the native scenario runner does. */
function findBinary(row) {
	const explicit = row.hostBinaryEnvOverride ? process.env[row.hostBinaryEnvOverride] : undefined;
	if (explicit) {
		const file = resolve(explicit);
		return existsSync(file) ? file : null;
	}
	if (!row.hostBinary) return null;
	const suffixes = process.platform === "win32" ? [".exe", ".cmd", ".ps1", ""] : [""];
	for (const folder of (process.env.PATH ?? "").split(delimiter)) {
		for (const suffix of suffixes) {
			const candidate = join(folder.replace(/^"|"$/gu, ""), `${row.hostBinary}${suffix}`);
			if (existsSync(candidate)) return candidate;
		}
	}
	return null;
}

function scenarioPathFor(row) {
	return join(SCENARIOS_DIR, `${row.connector}.json`);
}

/** The host ids an explicit scenario manifest declares, or a hard error. */
function explicitScenarioHostIds(scenarioPath) {
	let spec;
	try {
		spec = JSON.parse(readFileSync(scenarioPath, "utf8"));
	} catch (error) {
		throw new Error(`native scenario manifest cannot be read: ${scenarioPath}: ${error instanceof Error ? error.message : String(error)}`);
	}
	return new Set(spec && typeof spec.hosts === "object" && !Array.isArray(spec.hosts) ? Object.keys(spec.hosts) : []);
}

/**
 * The manifest a row is exercised with. An explicit `--scenario-file` applies
 * to the rows whose connector declares a host in it; every other row keeps
 * using the committed per-connector path.
 */
function scenarioPathForRow(row, options = {}) {
	if (!options.scenarioHostIds?.has(CONNECTOR_HOST_IDS[row.connector])) return scenarioPathFor(row);
	return options.scenarioFile ?? scenarioPathFor(row);
}

/**
 * Refuse a manifest that is the committed template, or a copy of it whose
 * placeholders were never replaced, before any host is launched. Deleting
 * `template`/`kind` does not turn a placeholder into an observation, so both
 * shapes are refused with the same documented reason code.
 */
function refuseScenarioManifest(spec) {
	const validation = validateScenarioManifest(spec);
	if (validation.template !== true && !carriesTemplatePlaceholders(validation)) return null;
	return {
		status: SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE,
		reason: "the manifest still carries the committed template's REPLACE_WITH_* placeholders; only a real host run may replace them",
		validation: {
			template: validation.template,
			error_count: validation.error_count,
			placeholder_count: validation.placeholder_count,
			unreplaced_placeholder_count: validation.failures.filter((failure) => failure.code === "PLACEHOLDER_VALUE_UNREPLACED").length,
		},
	};
}

function runScenarioManifest(row, binary, outputDir, options = {}) {
	const scenarioPath = scenarioPathForRow(row, options);
	if (!existsSync(scenarioPath)) {
		return {
			status: SCENARIO_MANIFEST_MISSING,
			scenarioPath: null,
			reason: "no native scenario manifest is committed for this connector",
		};
	}
	let spec;
	try {
		spec = JSON.parse(readFileSync(scenarioPath, "utf8"));
	} catch (error) {
		return {
			status: SCENARIO_MANIFEST_UNREADABLE,
			scenarioPath,
			binary,
			reason: `scenario manifest is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	const refusal = refuseScenarioManifest(spec);
	if (refusal) return { ...refusal, scenarioPath, binary };
	mkdirSync(outputDir, { recursive: true });
	const output = join(outputDir, `${row.connector}-scenarios.json`);
	const result = spawnSync(
		process.execPath,
		[MATRIX_VERIFIER, "--scenario-file", scenarioPath, "--output", output],
		{ encoding: "utf8", timeout: 30 * 60 * 1000, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
	);
	return {
		status: result.status === 0 ? SCENARIOS_PASSED : SCENARIOS_OPEN,
		scenarioPath,
		outputPath: existsSync(output) ? output : null,
		exitCode: result.status,
		stdout: String(result.stdout ?? "").slice(-4000),
		stderr: String(result.stderr ?? "").slice(-4000),
		binary,
	};
}

export async function buildRecord(options = {}) {
	const { matrix, sha256 } = loadMatrix(options.matrixPath);
	const probeOnly = options.probeOnly === true;
	const platform = currentPlatform();
	const outputDir = options.outputDir ?? join(process.cwd(), ".release-evidence", "v8-native");
	const scenarioFile = options.scenarioFile ? resolve(options.scenarioFile) : null;
	if (scenarioFile && !existsSync(scenarioFile)) {
		throw new Error(`native scenario manifest does not exist: ${scenarioFile}`);
	}
	const scenarioHostIds = scenarioFile ? explicitScenarioHostIds(scenarioFile) : null;
	if (scenarioFile && !matrix.rows.some((row) => scenarioHostIds.has(CONNECTOR_HOST_IDS[row.connector]))) {
		throw new Error(`native scenario manifest declares no host advertised by this support matrix: ${scenarioFile}`);
	}
	const hosts = [];

	for (const row of matrix.rows) {
		const binary = findBinary(row);
		const host = {
			connector: row.connector,
			supportOwnerRole: row.supportOwnerRole,
			advertisedPlatforms: row.supportedPlatforms,
			advertisedArchitectures: row.supportedArchitectures,
			advertisedContexts: row.supportedContexts,
			interceptionPoint: row.interceptionPoint,
			outputInterceptionPoint: row.outputInterceptionPoint,
			tamperResistance: row.tamperResistance,
			knownBypasses: row.knownBypasses,
			unobservedActions: row.unobservedActions,
			acceptanceEvidence: row.acceptanceEvidence,
			platformSupportedHere: row.supportedPlatforms.includes(platform),
			architectureSupportedHere: row.supportedArchitectures.includes(process.arch),
			binary,
			binarySha256: binary ? digest(readFileSync(binary)) : null,
			version: null,
			status: "NOT_RUN",
			acceptance: row.acceptanceEvidence.length > 0 ? "named_evidence_present_review_required" : "open",
			reason: null,
			scenarios: null,
		};
		if (!binary) {
			host.status = "HOST_UNAVAILABLE";
			host.reason = "host binary is not installed on this machine";
		} else {
			const versionArgs = Array.isArray(row.versionArgs) ? row.versionArgs : ["--version"];
			// npm-installed CLIs on Windows resolve to a `.ps1` or `.cmd` shim, which
			// `spawnSync` cannot execute directly. Launch them through PowerShell or
			// cmd.exe the same way the native scenario runner does.
			const viaPowerShell = process.platform === "win32" && /\.ps1$/i.test(binary);
			const viaCmd = process.platform === "win32" && /\.cmd$/i.test(binary);
			const version = viaPowerShell
				? spawnSync(
						"powershell.exe",
						["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", binary, ...versionArgs],
						{ encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024, windowsHide: true },
					)
				: spawnSync(viaCmd ? "cmd.exe" : binary, viaCmd ? ["/d", "/s", "/c", binary, ...versionArgs] : versionArgs, {
						encoding: "utf8",
						timeout: 30_000,
						maxBuffer: 1024 * 1024,
						windowsHide: true,
					});
			host.version = String(version.stdout || version.stderr || "").trim().slice(0, 200) || null;
			host.status = version.status === 0 && host.version ? "VERSION_PROBED" : "VERSION_PROBE_FAILED";
			if (host.status === "VERSION_PROBE_FAILED") host.reason = "version probe did not succeed";
			if (!host.platformSupportedHere || !host.architectureSupportedHere) {
				host.status = "UNSUPPORTED_ON_THIS_MACHINE";
				host.reason = `advertised for ${row.supportedPlatforms.join("/")} ${row.supportedArchitectures.join("/")}`;
			} else if (!probeOnly) {
				host.scenarios = runScenarioManifest(row, binary, outputDir, { scenarioFile, scenarioHostIds });
				host.status =
					host.scenarios.status === SCENARIOS_PASSED ? "SCENARIOS_PASSED_REVIEW_OPEN" : "HOST_ACCEPTANCE_OPEN";
				host.reason = host.scenarios.reason ?? host.scenarios.status;
			}
		}
		hosts.push(host);
	}

	const blockers = [];
	for (const host of hosts) {
		if (host.acceptance !== "named_evidence_present_review_required") {
			blockers.push(`${host.connector}:MISSING_NAMED_ACCEPTANCE_EVIDENCE`);
		}
		if (host.status === "HOST_UNAVAILABLE" || host.status === "NOT_RUN" || host.status === "VERSION_PROBE_FAILED") {
			blockers.push(`${host.connector}:${host.status}`);
		}
		if (host.status === "UNSUPPORTED_ON_THIS_MACHINE") {
			blockers.push(`${host.connector}:NOT_EXERCISED_ON_${platform}_${process.arch}`);
		}
		if (host.scenarios && host.scenarios.status !== SCENARIOS_PASSED) {
			blockers.push(`${host.connector}:NATIVE_SCENARIOS_OPEN`);
			if (SCENARIO_REFUSAL_STATUSES.includes(host.scenarios.status)) {
				blockers.push(`${host.connector}:${host.scenarios.status}`);
			}
		}
		if (host.unobservedActions.length > 0) {
			blockers.push(`${host.connector}:UNOBSERVED_ACTIONS_REMAIN`);
		}
	}
	for (const item of matrix.residual ?? []) {
		if (!Array.isArray(item.acceptanceEvidence) || item.acceptanceEvidence.length === 0) {
			blockers.push(`${item.id}:OPEN`);
		}
	}

	return {
		schemaVersion: 1,
		kind: "aidr-native-support-matrix-record",
		decision: "NO-GO",
		recordedAtUtc: new Date().toISOString(),
		platform,
		osRelease: osRelease(),
		osVersion: osVersion(),
		architecture: process.arch,
		nodeVersion: process.version,
		matrixPath: MATRIX_PATH,
		matrixSha256: sha256,
		soldConnectorScope: matrix.soldConnectorScope,
		soldPlatformScope: matrix.soldPlatformScope,
		soldArchitectureScope: matrix.soldArchitectureScope,
		probeOnly,
		hosts,
		blockers,
		limitations: [
			"A version probe is not host enforcement evidence",
			"One machine cannot cover the sold OS, architecture or host-version matrix",
			"Named customer acceptance cannot be produced from this repository",
		],
	};
}

async function main(argv) {
	const { values } = parseArgs({
		args: argv,
		options: {
			output: { type: "string" },
			"matrix": { type: "string" },
			"scenario-file": { type: "string" },
			"probe-only": { type: "boolean" },
		},
		strict: true,
	});
	const record = await buildRecord({
		probeOnly: values["probe-only"] === true,
		matrixPath: values.matrix ? resolve(values.matrix) : undefined,
		scenarioFile: values["scenario-file"] ? resolve(values["scenario-file"]) : undefined,
	});
	if (values.output) {
		const output = resolve(values.output);
		writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`, { flag: "w" });
	}
	console.log(JSON.stringify(record, null, 2));
	if (record.decision !== "GO") process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try {
		await main(process.argv.slice(2));
	} catch (error) {
		console.error(`Native support matrix error: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}
