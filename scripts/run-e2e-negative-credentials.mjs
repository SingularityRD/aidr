#!/usr/bin/env node

/**
 * Negative control for release E2E credential gates.
 *
 * This command is expected to pass only when each real-host suite refuses to
 * execute with credentials deliberately removed. It must never be used as a
 * substitute for the positive release E2E run.
 */

import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const evidenceDir = resolve(root, ".e2e-artifacts", "negative-credentials");
const releaseEvidenceDir = resolve(root, ".e2e-artifacts", "negative-release-preflight");
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";

const cases = [
	{
		id: "claude-missing-api-key",
		target: "packages/claude-code",
		clear: ["ANTHROPIC_API_KEY"],
		env: {},
	},
	{
		id: "openclaw-missing-gateway-token",
		target: "packages/openclaw",
		clear: ["OPENCLAW_GATEWAY_TOKEN"],
		env: {},
	},
	{
		id: "opencode-missing-cli",
		target: "packages/opencode",
		clear: [],
		env: { OPENCODE_E2E_BIN: "C:\\__aidr_negative_missing__\\opencode.exe" },
	},
	{
		id: "cursor-missing-host-and-agent",
		target: "packages/extension",
		clear: ["AIDR_E2E_ENABLE_IDE_HOST", "AIDR_AGENT_PATH", "CURSOR_API_KEY"],
		env: { AIDR_E2E_HOST: "cursor" },
	},
	{
		id: "vscode-missing-host",
		target: "packages/extension",
		clear: ["AIDR_E2E_ENABLE_IDE_HOST"],
		env: { AIDR_E2E_HOST: "vscode" },
	},
];

function readJson(filePath) {
	try {
		return JSON.parse(readFileSync(filePath, "utf8"));
	} catch {
		return undefined;
	}
}

function hasJunitEvidence(filePath) {
	try {
		const xml = readFileSync(filePath, "utf8");
		return xml.includes("<testsuite") || xml.includes("<testsuites");
	} catch {
		return false;
	}
}

mkdirSync(evidenceDir, { recursive: true });
const failures = [];

for (const testCase of cases) {
	const reportPath = resolve(evidenceDir, `${testCase.id}.json`);
	const junitPath = resolve(evidenceDir, `${testCase.id}.xml`);
	rmSync(reportPath, { force: true });
	rmSync(junitPath, { force: true });

	// Reuse the immutable release artifacts.  Without the release flag each
	// Vitest invocation runs developer global setup, which concurrently rebuilds
	// and deletes the shared core/dist tree across the five negative cases.
	// That creates false module-resolution failures unrelated to credential
	// handling.  Missing artifacts are intentionally handled as a setup failure
	// by the release global setup.
	const env = { ...process.env, ...testCase.env, AIDR_E2E_NEGATIVE: "1", AIDR_E2E_RELEASE: "1" };
	for (const name of testCase.clear) delete env[name];
	const result = spawnSync(
		pnpm,
		[
			"exec",
			"vitest",
			"run",
			"--config",
			"vitest.e2e.config.ts",
			testCase.target,
			"--reporter=json",
			"--reporter=junit",
			"--outputFile.json",
			reportPath,
			"--outputFile.junit",
			junitPath,
		],
		{
			cwd: root,
			encoding: "utf8",
			env,
			stdio: "inherit",
			shell: process.platform === "win32",
		},
	);

	const report = readJson(reportPath);
	const assertions = Array.isArray(report?.testResults)
		? report.testResults.flatMap((suite) => suite.assertionResults ?? [])
		: [];
	const total = Number.isInteger(report?.numTotalTests) ? report.numTotalTests : 0;
	const pending = Number.isInteger(report?.numPendingTests) ? report.numPendingTests : 0;
	const passed = Number.isInteger(report?.numPassedTests) ? report.numPassedTests : 0;
	const failed = Number.isInteger(report?.numFailedTests) ? report.numFailedTests : 0;
	const todo = Number.isInteger(report?.numTodoTests) ? report.numTodoTests : 0;
	const nonSkipped = assertions.filter(
		(assertion) => assertion?.status !== "skipped" && assertion?.status !== "pending",
	);

	if (result.status !== 0) {
		failures.push(`${testCase.id}: process exit=${result.status ?? "signal"}`);
	}
	if (!report) {
		failures.push(`${testCase.id}: JSON evidence missing or invalid`);
		continue;
	}
	if (report.success !== true) failures.push(`${testCase.id}: Vitest success=false`);
	if (total < 1) failures.push(`${testCase.id}: no tests collected`);
	if (assertions.length !== total) {
		failures.push(`${testCase.id}: collected=${assertions.length}, reported total=${total}`);
	}
	if (pending !== total || passed !== 0 || failed !== 0 || todo !== 0 || nonSkipped.length > 0) {
		failures.push(
			`${testCase.id}: missing-credential control did not skip all tests (total=${total}, pending=${pending}, passed=${passed}, failed=${failed}, todo=${todo}, nonSkipped=${nonSkipped.length})`,
		);
	}
	if (!hasJunitEvidence(junitPath)) {
		failures.push(`${testCase.id}: JUnit evidence missing or invalid`);
	}
}

// The release orchestrator itself must reject an environment with every
// external credential/evidence pointer removed. A green Vitest process is not
// enough: this control proves the promotion command exits non-zero and writes
// a failed, machine-readable summary in an isolated evidence directory.
const releaseEnv = { ...process.env, AIDR_E2E_NEGATIVE: "1", AIDR_E2E_EVIDENCE_DIR: releaseEvidenceDir };
for (const name of [
	"ANTHROPIC_API_KEY",
	"OPENCLAW_GATEWAY_TOKEN",
	"OPENCLAW_E2E_HOST",
	"OPENCODE_API_KEY",
	"OPENAI_API_KEY",
	"AIDR_E2E_ENABLE_IDE_HOST",
	"AIDR_CURSOR_PATH",
	"AIDR_AGENT_PATH",
	"AIDR_VSCODE_PATH",
	"AIDR_AIG_E2E_EVIDENCE",
	"AIDR_SUPABASE_E2E_EVIDENCE",
	"DASHBOARD_SMOKE_BASE_URL",
	"AIDR_DASHBOARD_BROWSER_EVIDENCE",
]) delete releaseEnv[name];
const releaseResult = spawnSync(process.execPath, ["scripts/run-e2e-release.mjs"], {
	cwd: root,
	encoding: "utf8",
	env: releaseEnv,
	stdio: "inherit",
	windowsHide: true,
});
const releaseSummary = readJson(resolve(releaseEvidenceDir, "summary.json"));
if (releaseResult.status === 0) {
	failures.push("release-preflight: promotion command unexpectedly exited zero with credentials removed");
}
if (releaseSummary?.status !== "failed") {
	failures.push(`release-preflight: expected failed summary, got ${String(releaseSummary?.status ?? "missing")}`);
}

if (failures.length > 0) {
	console.error("\nNegative credential E2E control failed:");
	for (const failure of failures) console.error(`- ${failure}`);
	console.error(`Evidence: ${evidenceDir}`);
	process.exitCode = 1;
} else {
	console.log(`Negative credential E2E control passed; evidence: ${evidenceDir}`);
}
