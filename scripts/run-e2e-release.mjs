#!/usr/bin/env node

/**
 * Release E2E orchestrator.
 *
 * Vitest exits zero for a skipped suite. That is useful during development,
 * but unsafe for a release candidate. This runner executes the versioned
 * capability manifest, performs setup preflight, isolates every run in a new
 * HOME/tenant, writes redacted JSON/JUnit/log evidence, and fails closed unless
 * every advertised assertion was collected, executed and passed.
 */

import {
	existsSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
	mkdtempSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = resolve(root, "scripts", "e2e-release-manifest.json");
const evidenceDir = resolve(
	root,
	process.env.AIDR_E2E_EVIDENCE_DIR ?? ".e2e-artifacts/release",
);
const summaryPath = resolve(evidenceDir, "summary.json");
const runId = `${new Date().toISOString().replaceAll(/[^0-9A-Z]+/gi, "-")}-${process.pid}`;
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";

function readJson(filePath) {
	try {
		return JSON.parse(readFileSync(filePath, "utf8"));
	} catch (error) {
		throw new Error(`${filePath}: ${error instanceof Error ? error.message : String(error)}`);
	}
}

function writeJson(filePath, value) {
	writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function toPosixPath(value) {
	return value.replaceAll("\\", "/");
}

function relativePath(filePath) {
	return toPosixPath(relative(root, resolve(filePath)));
}

function reportFileName(filePath) {
	const normalized = toPosixPath(String(filePath));
	const normalizedRoot = toPosixPath(root).replace(/\/$/, "").toLowerCase();
	if (normalized.toLowerCase().startsWith(`${normalizedRoot}/`)) {
		return relativePath(filePath);
	}
	return normalized;
}

function escapeXml(value) {
	return String(value)
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&apos;");
}

function redactText(text, env = {}) {
	let output = String(text ?? "");
	const secretValues = Object.entries(env)
		.filter(
			([name, value]) =>
				/(KEY|TOKEN|SECRET|PASSWORD|PRIVATE|CREDENTIAL|AUTH)/i.test(name) &&
				typeof value === "string" &&
				value.length >= 6,
		)
		.map(([, value]) => value)
		.sort((a, b) => b.length - a.length);
	for (const value of secretValues) {
		output = output.split(value).join("[REDACTED]");
	}
	return output
		.replace(/(Authorization\s*[:=]\s*Bearer\s+)[^\s,}]+/gi, "$1[REDACTED]")
		.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, "$1[REDACTED]")
		.replace(/(api[_-]?key|token|secret|password)\s*[:=]\s*["']?[^\s,"'}]+/gi, "$1=[REDACTED]");
}

function writeLog(filePath, value, env) {
	writeFileSync(filePath, redactText(value, env), "utf8");
}

function fileSha256(filePath) {
	if (!existsSync(filePath)) return null;
	return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function redactValue(value, env) {
	if (typeof value === "string") return redactText(value, env);
	if (Array.isArray(value)) return value.map((item) => redactValue(item, env));
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value).map(([key, item]) => [key, redactValue(item, env)]),
		);
	}
	return value;
}

function validateManifest(manifest) {
	if (!manifest || typeof manifest !== "object") throw new Error("manifest must be an object");
	if (manifest.version !== 2) throw new Error(`unsupported manifest version: ${String(manifest.version)}`);
	if (!Array.isArray(manifest.suites) || manifest.suites.length === 0) {
		throw new Error("manifest.suites must contain at least one suite");
	}
	const ids = new Set();
	for (const suite of manifest.suites) {
		if (!suite || typeof suite !== "object") throw new Error("each suite must be an object");
		if (typeof suite.id !== "string" || !suite.id.trim()) throw new Error("each suite requires id");
		if (ids.has(suite.id)) throw new Error(`duplicate suite id: ${suite.id}`);
		ids.add(suite.id);
		if (!["vitest", "command", "external"].includes(suite.kind)) {
			throw new Error(`${suite.id}: kind must be vitest, command or external`);
		}
		for (const field of ["target", "testFile"]) {
			if (typeof suite[field] !== "string" || !suite[field].trim()) {
				throw new Error(`${suite.id}: ${field} is required`);
			}
		}
		if (!Number.isInteger(suite.expectedTests) || suite.expectedTests < 1) {
			throw new Error(`${suite.id}: expectedTests must be a positive integer`);
		}
		for (const field of ["requiredEnv", "requiredAnyEnv", "requiredCommands"]) {
			if (suite[field] !== undefined && (!Array.isArray(suite[field]) || suite[field].some((v) => typeof v !== "string"))) {
				throw new Error(`${suite.id}: ${field} must be a string array`);
			}
		}
		if (suite.kind === "command" && (!Array.isArray(suite.command) || suite.command.length === 0)) {
			throw new Error(`${suite.id}: command suites require a command array`);
		}
		if (suite.kind === "external" && typeof suite.externalEvidenceEnv !== "string") {
			throw new Error(`${suite.id}: external suites require externalEvidenceEnv`);
		}
		if (suite.env !== undefined && (!suite.env || typeof suite.env !== "object")) {
			throw new Error(`${suite.id}: env must be an object when provided`);
		}
	}
}

function commandAvailable(command, env) {
	const result = spawnSync(command, ["--version"], {
		cwd: root,
		encoding: "utf8",
		env,
		stdio: "ignore",
		windowsHide: true,
		shell: process.platform === "win32",
	});
	return !result.error && result.status === 0;
}

function preflight(suite, env) {
	const reasons = [];
	for (const name of suite.requiredEnv ?? []) {
		if (!String(env[name] ?? "").trim()) reasons.push(`missing required environment: ${name}`);
	}
	if (suite.requiredAnyEnv?.length > 0 && !suite.requiredAnyEnv.some((name) => String(env[name] ?? "").trim())) {
		reasons.push(`one of required environments is missing: ${suite.requiredAnyEnv.join(", ")}`);
	}
	for (const command of suite.requiredCommands ?? []) {
		if (!commandAvailable(command, env)) reasons.push(`required command is not runnable: ${command}`);
	}
	if (suite.kind === "external" && !String(env[suite.externalEvidenceEnv] ?? "").trim()) {
		reasons.push(`external evidence path is missing: ${suite.externalEvidenceEnv}`);
	}
	return reasons;
}

function assertionsFromReport(report) {
	if (!report || typeof report !== "object" || !Array.isArray(report.testResults)) return [];
	return report.testResults.flatMap((suite) =>
		Array.isArray(suite?.assertionResults) ? suite.assertionResults : [],
	);
}

function inspectReport(report, suite) {
	const assertions = assertionsFromReport(report);
	const counts = { collected: assertions.length, passed: 0, failed: 0, pending: 0, todo: 0 };
	const nonPassed = [];
	for (const assertion of assertions) {
		const status = assertion?.status;
		if (status === "passed") counts.passed += 1;
		else if (status === "skipped" || status === "pending") {
			counts.pending += 1;
			nonPassed.push(assertion);
		} else if (status === "todo") {
			counts.todo += 1;
			nonPassed.push(assertion);
		} else {
			counts.failed += 1;
			nonPassed.push(assertion);
		}
	}
	counts.executed = counts.passed + counts.failed;
	counts.nonPassed = nonPassed.length;

	const reasons = [];
	const reportedTotal = Number.isInteger(report?.numTotalTests) ? report.numTotalTests : undefined;
	if (reportedTotal === undefined) reasons.push("JSON report has no numTotalTests");
	else if (reportedTotal !== counts.collected) reasons.push(`reported total=${reportedTotal} but assertions collected=${counts.collected}`);
	if (counts.collected !== suite.expectedTests) reasons.push(`collected=${counts.collected}, expected=${suite.expectedTests}`);
	if (counts.executed !== counts.collected) reasons.push(`executed=${counts.executed}, collected=${counts.collected}`);
	if (counts.passed !== suite.expectedTests) reasons.push(`passed=${counts.passed}, expected=${suite.expectedTests}`);
	if (counts.pending > 0) reasons.push(`pending=${counts.pending}`);
	if (counts.todo > 0) reasons.push(`todo=${counts.todo}`);
	if (counts.failed > 0) reasons.push(`failed=${counts.failed}`);
	if (report?.success !== true) reasons.push("report success=false");

	const testFiles = [
		...new Set(
			(Array.isArray(report?.testResults) ? report.testResults : [])
				.map((result) => (typeof result?.name === "string" ? reportFileName(result.name) : ""))
				.filter(Boolean),
		),
	];
	const expectedFile = toPosixPath(suite.testFile);
	if (!testFiles.includes(expectedFile)) reasons.push(`expected test file not collected: ${expectedFile}`);
	const unexpectedFiles = testFiles.filter((file) => file !== expectedFile);
	if (unexpectedFiles.length > 0) reasons.push(`unexpected test files collected: ${unexpectedFiles.join(", ")}`);

	return {
		...counts,
		testFiles,
		unexpectedFiles,
		nonPassedTests: nonPassed.map((assertion) => ({
			fullName: assertion?.fullName,
			title: assertion?.title,
			status: assertion?.status,
			failureMessages: assertion?.failureMessages,
		})),
		reasons,
	};
}

function reportFromStatuses(suite, statuses, success, message) {
	const assertionResults = statuses.map((status, index) => ({
		ancestorTitles: [suite.id],
		fullName: `${suite.id} assertion ${index + 1}`,
		title: `assertion-${index + 1}`,
		status,
		failureMessages: status === "passed" ? [] : [message ?? "assertion failed"],
	}));
	const passed = statuses.filter((status) => status === "passed").length;
	const failed = statuses.filter((status) => status === "failed").length;
	const pending = statuses.filter((status) => status === "skipped" || status === "pending").length;
	const todo = statuses.filter((status) => status === "todo").length;
	return {
		numTotalTestSuites: 1,
		numPassedTestSuites: success ? 1 : 0,
		numFailedTestSuites: success ? 0 : 1,
		numTotalTests: statuses.length,
		numPassedTests: passed,
		numFailedTests: failed,
		numPendingTests: pending,
		numTodoTests: todo,
		success,
		testResults: [{ name: suite.testFile, assertionResults }],
	};
}

function writeJunit(filePath, suite, report) {
	const assertions = assertionsFromReport(report);
	const failures = assertions.filter((assertion) => assertion.status === "failed").length;
	const skipped = assertions.filter((assertion) => assertion.status === "skipped" || assertion.status === "pending").length;
	const cases = assertions
		.map((assertion) => {
			const name = escapeXml(assertion.fullName ?? assertion.title ?? "assertion");
			if (assertion.status === "skipped" || assertion.status === "pending") return `<testcase name="${name}"><skipped/></testcase>`;
			if (assertion.status !== "passed") return `<testcase name="${name}"><failure>${escapeXml((assertion.failureMessages ?? []).join("\n"))}</failure></testcase>`;
			return `<testcase name="${name}"/>`;
		})
		.join("");
	const xml = `<?xml version="1.0" encoding="UTF-8"?><testsuites><testsuite name="${escapeXml(suite.id)}" tests="${assertions.length}" failures="${failures}" errors="0" skipped="${skipped}">${cases}</testsuite></testsuites>\n`;
	writeFileSync(filePath, xml, "utf8");
}

function parseJUnit(filePath, suite) {
	if (!existsSync(filePath)) return undefined;
	const xml = readFileSync(filePath, "utf8");
	const matches = [...xml.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/gi)];
	if (matches.length === 0) return undefined;
	const statuses = matches.map((match) => {
		const body = match[2] ?? "";
		if (/<skipped\b/i.test(body)) return "skipped";
		if (/<failure\b|<error\b/i.test(body)) return "failed";
		return "passed";
	});
	const assertionResults = statuses.map((status, index) => ({
		fullName: `${suite.id} ${index + 1}`,
		title: `pytest-${index + 1}`,
		status,
		failureMessages: status === "passed" ? [] : ["JUnit reported a non-passing case"],
	}));
	return {
		...reportFromStatuses(suite, statuses, statuses.every((status) => status === "passed")),
		testResults: [{ name: suite.testFile, assertionResults }],
	};
}

function validateExternalEvidence(suite, env) {
	const configuredPath = String(env[suite.externalEvidenceEnv] ?? "").trim();
	const evidencePath = configuredPath ? resolve(root, configuredPath) : "";
	if (evidencePath && relative(root, evidencePath).startsWith("..")) {
		return { errors: ["external evidence path must remain inside the repository/evidence workspace"] };
	}
	if (!evidencePath || !existsSync(evidencePath)) {
		return { errors: [`external evidence file missing: ${evidencePath || suite.externalEvidenceEnv}`] };
	}
	let external;
	try {
		external = readJson(evidencePath);
	} catch (error) {
		return { errors: [`external evidence is invalid: ${error instanceof Error ? error.message : String(error)}`] };
	}
	const errors = [];
	if (external.schemaVersion !== "aidr-e2e-external-v1") errors.push("external evidence schemaVersion must be aidr-e2e-external-v1");
	if (external.suiteId !== suite.id) errors.push(`external suiteId mismatch: expected ${suite.id}`);
	if (external.status !== "passed") errors.push("external evidence status is not passed");
	if (external.redacted !== true) errors.push("external evidence must declare redacted=true");
	if (!String(external.generatedAt ?? "").trim()) errors.push("external generatedAt is missing");
	if (!String(external.rcDigest ?? "").trim()) errors.push("external rcDigest is missing");
	if (!String(external.attestation ?? "").trim()) errors.push("external attestation is missing");
	const assertions = Array.isArray(external.assertions) ? external.assertions : [];
	if (assertions.length !== suite.expectedTests) errors.push(`external assertions=${assertions.length}, expected=${suite.expectedTests}`);
	if (assertions.some((assertion) => assertion?.status !== "passed")) errors.push("external assertions contain non-passed status");
	const report = reportFromStatuses(suite, assertions.map(() => "passed"), errors.length === 0);
	return { report, errors, evidencePath: relativePath(evidencePath), externalMeta: { generatedAt: external.generatedAt, rcDigest: external.rcDigest } };
}

function replacePlaceholders(values, replacements) {
	return values.map((value) =>
		typeof value === "string"
			? value.replaceAll("{json}", replacements.json).replaceAll("{junit}", replacements.junit).replaceAll("{tenant}", replacements.tenant).replaceAll("{runId}", replacements.runId)
			: value,
	);
}

function spawnProcess(command, args, env) {
	return spawnSync(command, args, {
		cwd: root,
		encoding: "utf8",
		env,
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
		shell: process.platform === "win32",
	});
}

function writeHomeFiles(homeDir, files) {
	for (const [relativeFile, content] of Object.entries(files ?? {})) {
		const target = resolve(homeDir, relativeFile);
		if (!relative(homeDir, target) || relative(homeDir, target).startsWith("..")) {
			throw new Error(`homeFiles path escapes isolated HOME: ${relativeFile}`);
		}
		mkdirSync(dirname(target), { recursive: true });
		writeFileSync(target, content, "utf8");
	}
}

function runSuite(suite, evidence) {
	const reportPath = resolve(evidenceDir, `${suite.id}.json`);
	const junitPath = resolve(evidenceDir, `${suite.id}.xml`);
	const stdoutPath = resolve(evidenceDir, `${suite.id}.stdout.log`);
	const stderrPath = resolve(evidenceDir, `${suite.id}.stderr.log`);
	for (const filePath of [reportPath, junitPath, stdoutPath, stderrPath]) rmSync(filePath, { force: true });

	const homeDir = mkdtempSync(join(tmpdir(), `aidr-e2e-${suite.id}-`));
	const tenantId = `e2e-${runId}-${suite.id}`;
	const env = {
		...process.env,
		...(suite.env ?? {}),
		AIDR_E2E_RELEASE: "1",
		AIDR_E2E_RUN_ID: runId,
		AIDR_E2E_TENANT_ID: tenantId,
		AIDR_TENANT_ID: tenantId,
		AIG_TENANT_ID: tenantId,
		HOME: homeDir,
		USERPROFILE: homeDir,
		XDG_CONFIG_HOME: join(homeDir, ".config"),
	};
	writeLog(stdoutPath, "", env);
	writeLog(stderrPath, "", env);
	let reasons = preflight(suite, env);
	let report;
	let result = { status: null, signal: null, error: null, stdout: "", stderr: "" };
	let setupStatus = reasons.length === 0 ? "ready" : "blocked";

	try {
		writeHomeFiles(homeDir, suite.homeFiles);
		if (reasons.length === 0 && suite.kind === "external") {
			const external = validateExternalEvidence(suite, env);
			reasons = [...reasons, ...(external.errors ?? [])];
			report = external.report;
			if (external.evidencePath) env.AIDR_EXTERNAL_EVIDENCE = external.evidencePath;
		} else if (reasons.length === 0 && suite.kind === "vitest") {
			result = spawnProcess(pnpm, ["exec", "vitest", "run", "--config", suite.config ?? "vitest.e2e.config.ts", suite.target, "--reporter=json", "--reporter=junit", "--outputFile.json", reportPath, "--outputFile.junit", junitPath], env);
			writeLog(stdoutPath, result.stdout, env);
			writeLog(stderrPath, result.stderr, env);
			try {
				report = readJson(reportPath);
			} catch (error) {
				reasons.push(`JSON evidence missing or invalid: ${error instanceof Error ? error.message : String(error)}`);
			}
		} else if (reasons.length === 0 && suite.kind === "command") {
			const command = replacePlaceholders(suite.command, { json: reportPath, junit: junitPath, tenant: tenantId, runId });
			result = spawnProcess(command[0], command.slice(1), env);
			writeLog(stdoutPath, result.stdout, env);
			writeLog(stderrPath, result.stderr, env);
			report = parseJUnit(junitPath, suite);
			if (!report && result.status === 0) report = reportFromStatuses(suite, ["passed"], true, "command completed");
			if (!report && result.status !== 0) report = reportFromStatuses(suite, ["failed"], false, "command failed");
		}
	} catch (error) {
		reasons.push(`runner error: ${error instanceof Error ? error.message : String(error)}`);
	}

	if (!report && reasons.length > 0) report = reportFromStatuses(suite, [], false, reasons.join("; "));
	if (report) {
		report = redactValue(report, env);
		writeJson(reportPath, report);
		if (!existsSync(junitPath)) writeJunit(junitPath, suite, report);
	}
	if (result.error) reasons.push(`process error: ${result.error.message ?? String(result.error)}`);
	if (result.status !== null && result.status !== 0) reasons.push(`process exit=${result.status ?? "signal"}`);
	if (setupStatus === "blocked") reasons.push("setup preflight blocked execution");
	if (report) reasons.push(...inspectReport(report, suite).reasons);
	if (!existsSync(junitPath)) reasons.push("JUnit evidence missing or invalid");
	const inspected = report ? inspectReport(report, suite) : null;
	const entry = {
		id: suite.id,
		kind: suite.kind,
		target: suite.target,
		testFile: suite.testFile,
		capabilities: suite.capabilities ?? [],
		prerequisites: suite.prerequisites ?? [],
		expectedTests: suite.expectedTests,
		tenantId,
		setupStatus,
		exitCode: result.status,
		signal: result.signal ?? null,
		json: relativePath(reportPath),
		junit: relativePath(junitPath),
		stdout: relativePath(stdoutPath),
		stderr: relativePath(stderrPath),
		redactedLogs: true,
		artifactSha256: {
			json: fileSha256(reportPath),
			junit: fileSha256(junitPath),
			stdout: fileSha256(stdoutPath),
			stderr: fileSha256(stderrPath),
		},
		report: inspected,
		reasons: [...new Set(reasons)],
	};
	try {
		rmSync(homeDir, { recursive: true, force: true });
	} catch {
		entry.reasons.push("isolated HOME cleanup failed");
	}
	return entry;
}

mkdirSync(evidenceDir, { recursive: true });
let manifest;
try {
	manifest = readJson(manifestPath);
	validateManifest(manifest);
} catch (error) {
	console.error(`Release E2E manifest error: ${error instanceof Error ? error.message : String(error)}`);
	process.exitCode = 1;
	process.exit(process.exitCode);
}

const evidence = {
	schemaVersion: "aidr-e2e-release-v2",
	runId,
	manifest: relativePath(manifestPath),
	startedAt: new Date().toISOString(),
	status: "running",
	environment: {
		platform: process.platform,
		arch: process.arch,
		node: process.version,
		tenantIsolation: "fresh HOME and unique tenant per suite",
		secrets: "not recorded",
	},
	suites: [],
};
writeJson(summaryPath, evidence);

for (const suite of manifest.suites) {
	const entry = runSuite(suite, evidence);
	evidence.suites.push(entry);
	writeJson(summaryPath, evidence);
	console.log(`[e2e] ${suite.id}: ${entry.setupStatus}, ${entry.report?.passed ?? 0}/${entry.expectedTests} passed`);
}

const failures = evidence.suites.flatMap((suite) => suite.reasons.map((reason) => `${suite.id}: ${reason}`));
evidence.status = failures.length > 0 ? "failed" : "passed";
evidence.finishedAt = new Date().toISOString();
writeJson(summaryPath, evidence);

if (failures.length > 0) {
	console.error("\nRelease E2E gate failed closed:");
	for (const failure of failures) console.error(`- ${failure}`);
	console.error(`Evidence: ${evidenceDir}`);
	process.exitCode = 1;
} else {
	console.log(`Release E2E gate passed; evidence: ${evidenceDir}`);
}
