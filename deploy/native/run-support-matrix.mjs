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
 *
 * Usage:
 *   node deploy/native/run-support-matrix.mjs [--output <path>] [--probe-only]
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { release as osRelease, version as osVersion } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const MATRIX_PATH = join(HERE, "support-matrix.json");
const MATRIX_VERIFIER = resolve(HERE, "..", "..", "scripts", "verify-native-host-matrix-v6.mjs");

const PLATFORMS = new Set(["windows", "linux", "macos"]);
const ARCHITECTURES = new Set(["x64", "arm64"]);
const SHA256 = /^[0-9a-f]{64}$/;

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
	if (matrix.schemaVersion !== 1) fail("unsupported schemaVersion");
	if (!Array.isArray(matrix.rows) || matrix.rows.length === 0) fail("rows must be a non-empty array");
	const seenConnectors = new Set();
	for (const row of matrix.rows) {
		if (typeof row.connector !== "string" || !row.connector) fail("row.connector is required");
		if (seenConnectors.has(row.connector)) fail(`duplicate connector ${row.connector}`);
		seenConnectors.add(row.connector);
		if (!matrix.soldConnectorScope.includes(row.connector)) {
			fail(`row ${row.connector} is outside soldConnectorScope`);
		}
		if (row.hostBinary !== null && typeof row.hostBinary !== "string") {
			fail(`row ${row.connector} hostBinary must be a string or null`);
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
		if (typeof row.supportOwnerRole !== "string" || row.supportOwnerRole.trim().length < 3) {
			fail(`row ${row.connector} must name a supportOwnerRole`);
		}
		for (const field of ["knownBypasses", "unobservedActions", "acceptanceEvidence", "installPath", "uninstallPath"]) {
			if (!Array.isArray(row[field])) fail(`row ${row.connector}.${field} must be an array`);
		}
		for (const evidence of row.acceptanceEvidence) {
			if (typeof evidence !== "object" || evidence === null) fail(`row ${row.connector} has a malformed evidence entry`);
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
	return join(HERE, "scenarios", `${row.connector}.json`);
}

function runScenarioManifest(row, binary, outputDir) {
	const scenarioPath = scenarioPathFor(row);
	if (!existsSync(scenarioPath)) {
		return {
			status: "SCENARIO_MANIFEST_MISSING",
			scenarioPath: null,
			reason: "no native scenario manifest is committed for this connector",
		};
	}
	const output = join(outputDir, `${row.connector}-scenarios.json`);
	const result = spawnSync(
		process.execPath,
		[MATRIX_VERIFIER, "--scenario-file", scenarioPath, "--output", output],
		{ encoding: "utf8", timeout: 30 * 60 * 1000, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
	);
	return {
		status: result.status === 0 ? "SCENARIOS_PASSED" : "SCENARIOS_OPEN",
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
				host.scenarios = runScenarioManifest(row, binary, outputDir);
				host.status =
					host.scenarios.status === "SCENARIOS_PASSED" ? "SCENARIOS_PASSED_REVIEW_OPEN" : "HOST_ACCEPTANCE_OPEN";
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
		if (host.scenarios && host.scenarios.status !== "SCENARIOS_PASSED") {
			blockers.push(`${host.connector}:NATIVE_SCENARIOS_OPEN`);
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
			"probe-only": { type: "boolean" },
		},
		strict: true,
	});
	const record = await buildRecord({
		probeOnly: values["probe-only"] === true,
		matrixPath: values.matrix ? resolve(values.matrix) : undefined,
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
