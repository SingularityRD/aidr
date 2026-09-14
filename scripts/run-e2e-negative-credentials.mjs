#!/usr/bin/env node

/**
 * Negative control for release E2E credential gates.
 *
 * This command is expected to pass only when each real-host suite refuses to
 * execute with credentials deliberately removed, and when the release
 * promotion command itself refuses to promote an environment with every
 * external credential/evidence pointer removed. It must never be used as a
 * substitute for the positive release E2E run.
 *
 * ## Why this runner classifies instead of just failing
 *
 * A Vitest report alone cannot tell a refusal from an unusable environment. When
 * a suite refuses at collection time (for example a configured CLI override that
 * cannot be spawned) Vitest reports `numTotalTests: 0`, `success: false` and
 * exits 1 - and the release global setup failing on missing build artifacts
 * produces the same shape. Treating those as one thing conflates a product
 * defect with an unsupported/unavailable environment, so every scenario is
 * classified into a fixed vocabulary and the environment facts are recorded
 * next to the verdict.
 *
 * ## Outcome vocabulary (one per scenario, recorded in summary.json)
 *
 *   PASS              the negative case was correctly refused: no assertion
 *                     executed, and the host/inputs the suite needs are
 *                     present, so the refusal is attributable to the input the
 *                     runner deliberately removed.
 *   FAIL              the case was wrongly accepted: at least one assertion
 *                     executed under the negative case. A real defect.
 *   HOST_UNAVAILABLE  the host binary / extension host is not installed on this
 *                     machine. An environment blocker, never a product defect.
 *   BLOCKED_EXTERNAL  a credential, gateway or customer input the scenario
 *                     needs is missing.
 *   UNSUPPORTED       the scenario is not advertised for this platform/arch.
 *   SETUP_FAILURE     the control could not be exercised (missing build
 *                     artifacts, unreadable evidence, no refusal evidence).
 *                     Never green: an unusable control must not report PASS.
 *
 * ## Exit codes
 *
 *   0  every scenario is PASS, or the only non-PASS scenarios are
 *      HOST_UNAVAILABLE / BLOCKED_EXTERNAL / UNSUPPORTED. The run is then
 *      reported as an explicit NO-GO/blocked environment (decision=NO-GO,
 *      status=blocked) that names the missing hosts and inputs. It is not a
 *      product failure, and the release gate (`pnpm test:e2e`) remains the
 *      fail-closed NO-GO for that environment.
 *   1  at least one FAIL (a negative case was accepted) or SETUP_FAILURE. A
 *      crash before the summary is written exits 1 as well and leaves no
 *      summary.json, so a stale result can never be mistaken for this run.
 *
 * The wrong-accept guard runs before any host/credential availability
 * downgrade, so a genuine wrong-accept can never be reported as a skip, a
 * blocker or a PASS.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const evidenceDir = resolve(root, ".e2e-artifacts", "negative-credentials");
const releaseEvidenceDir = resolve(root, ".e2e-artifacts", "negative-release-preflight");
const summaryPath = resolve(evidenceDir, "summary.json");
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const startedAt = new Date().toISOString();
const runId = `${startedAt.replaceAll(/[^0-9A-Z]+/gi, "-")}-${process.pid}`;

// ---------------------------------------------------------------------------
// Outcome vocabulary
// ---------------------------------------------------------------------------

const PASS = "PASS";
const FAIL = "FAIL";
const HOST_UNAVAILABLE = "HOST_UNAVAILABLE";
const BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL";
const UNSUPPORTED = "UNSUPPORTED";
const SETUP_FAILURE = "SETUP_FAILURE";
const STATUS_VOCABULARY = [PASS, FAIL, HOST_UNAVAILABLE, BLOCKED_EXTERNAL, UNSUPPORTED, SETUP_FAILURE];
const BLOCKED_STATUSES = new Set([HOST_UNAVAILABLE, BLOCKED_EXTERNAL, UNSUPPORTED]);

const DECISION_PASS = "PASS";
const DECISION_NO_GO = "NO-GO";
const DECISION_FAIL = "FAIL";
const DECISION_INVALID = "INVALID";
const EXIT_CODE = {
	[DECISION_PASS]: 0,
	[DECISION_NO_GO]: 0,
	[DECISION_FAIL]: 1,
	[DECISION_INVALID]: 1,
};

/**
 * Artifacts the release Vitest global setup refuses to execute without. A
 * missing artifact means the control cannot distinguish "the suite refused"
 * from "the workspace is broken", so it is never counted as a refusal.
 */
const REQUIRED_ARTIFACTS = [
	"packages/core/dist/index.js",
	"packages/claude-code/dist/pre-tool-use.cjs",
	"packages/claude-code/dist/health.cjs",
	"packages/openclaw/dist/index.cjs",
	"packages/opencode/dist/index.js",
	"packages/extension/dist/cursor_extension.js",
];

const PLATFORM_HOST_SUPPORT = {
	claude: ["win32", "darwin", "linux"],
	opencode: ["win32", "darwin", "linux"],
	openclaw: ["win32", "darwin", "linux"],
	cursor: ["win32", "darwin", "linux"],
	agent: ["win32", "darwin", "linux"],
	vscode: ["win32", "darwin", "linux"],
};

// ---------------------------------------------------------------------------
// Host availability probes
// ---------------------------------------------------------------------------

function hasEnv(name) {
	return Boolean(String(process.env[name] ?? "").trim());
}

function whichCommand(command) {
	const finder = process.platform === "win32" ? "where.exe" : "which";
	const result = spawnSync(finder, [command], {
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
		timeout: 15_000,
	});
	if (result.error || result.status !== 0) return [];
	return String(result.stdout ?? "")
		.split(/\r?\n/)
		.map((value) => value.trim())
		.filter(Boolean);
}

function vsCodeInstallCandidates() {
	if (process.platform === "win32") {
		const candidates = [];
		if (process.env.LOCALAPPDATA) {
			candidates.push(
				resolve(process.env.LOCALAPPDATA, "Programs", "Microsoft VS Code", "Code.exe"),
				resolve(
					process.env.LOCALAPPDATA,
					"Programs",
					"Microsoft VS Code Insiders",
					"Code - Insiders.exe",
				),
			);
		}
		if (process.env.ProgramFiles) {
			candidates.push(resolve(process.env.ProgramFiles, "Microsoft VS Code", "Code.exe"));
		}
		if (process.env["ProgramFiles(x86)"]) {
			candidates.push(resolve(process.env["ProgramFiles(x86)"], "Microsoft VS Code", "Code.exe"));
		}
		return candidates;
	}
	if (process.platform === "darwin") {
		return [
			"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
			"/Applications/Visual Studio Code - Insiders.app/Contents/MacOS/Electron",
		];
	}
	return ["/usr/bin/code", "/usr/local/bin/code", "/snap/bin/code"];
}

function cursorInstallCandidates() {
	if (process.platform === "win32") {
		const candidates = [];
		if (process.env.LOCALAPPDATA) {
			candidates.push(resolve(process.env.LOCALAPPDATA, "Programs", "Cursor", "Cursor.exe"));
		}
		if (process.env.ProgramFiles) {
			candidates.push(resolve(process.env.ProgramFiles, "Cursor", "Cursor.exe"));
		}
		return candidates;
	}
	if (process.platform === "darwin") {
		return ["/Applications/Cursor.app/Contents/MacOS/Cursor"];
	}
	return ["/usr/bin/cursor", "/usr/local/bin/cursor"];
}

function probeExecutableHost({ id, label, kind, envOverrides = [], commands = [], candidates = [] }) {
	const probed = [];
	const overrides = [];
	for (const name of envOverrides) {
		const value = String(process.env[name] ?? "").trim();
		probed.push(`${name}=${value ? "set" : "unset"}`);
		if (value) overrides.push({ name, value });
	}
	for (const override of overrides) {
		probed.push(`${override.name} -> ${override.value}`);
		if (existsSync(override.value)) {
			return {
				id,
				label,
				kind,
				available: true,
				resolvedPath: override.value,
				probed,
				detail: `resolved from ${override.name}`,
			};
		}
	}
	for (const candidate of candidates) {
		probed.push(`candidate ${candidate}`);
		if (existsSync(candidate)) {
			return {
				id,
				label,
				kind,
				available: true,
				resolvedPath: candidate,
				probed,
				detail: "found in a default install location",
			};
		}
	}
	for (const command of commands) {
		const hits = whichCommand(command);
		probed.push(hits.length > 0 ? `PATH ${command} -> ${hits.join(", ")}` : `PATH ${command} (not found)`);
		if (hits.length > 0) {
			return {
				id,
				label,
				kind,
				available: true,
				resolvedPath: hits[0],
				probed,
				detail: "found on PATH",
			};
		}
	}
	const searched = [...envOverrides, ...commands, ...candidates];
	return {
		id,
		label,
		kind,
		available: false,
		resolvedPath: null,
		probed,
		detail: `not installed on this machine (searched: ${searched.join(", ")})`,
	};
}

function readOpenClawConfig() {
	const configPath = resolve(homedir(), ".openclaw", "openclaw.json");
	try {
		return { configPath, config: JSON.parse(readFileSync(configPath, "utf8")) };
	} catch {
		return { configPath, config: undefined };
	}
}

function openClawFacts() {
	const { configPath, config } = readOpenClawConfig();
	const envToken = String(process.env.OPENCLAW_GATEWAY_TOKEN ?? "").trim();
	const fileToken = String(config?.gateway?.auth?.token ?? "").trim();
	const chatEnabled = config?.gateway?.http?.endpoints?.chatCompletions?.enabled === true;
	const gatewayHost = String(process.env.OPENCLAW_E2E_HOST ?? "").trim() || "http://localhost:18789";
	return {
		configPath,
		configPresent: Boolean(config),
		envToken,
		fileToken,
		chatEnabled,
		gatewayHost,
		available: Boolean(envToken || fileToken) && chatEnabled,
	};
}

function probeOpenClawGateway() {
	const facts = openClawFacts();
	const missing = [];
	if (!facts.envToken && !facts.fileToken) {
		missing.push("gateway auth token (OPENCLAW_GATEWAY_TOKEN or gateway.auth.token in the config)");
	}
	if (!facts.chatEnabled) {
		missing.push("gateway.http.endpoints.chatCompletions.enabled=true in the OpenClaw config");
	}
	return {
		id: "openclaw",
		label: "OpenClaw gateway",
		kind: "service",
		available: facts.available,
		resolvedPath: null,
		probed: [
			`OPENCLAW_GATEWAY_TOKEN=${facts.envToken ? "set" : "unset"}`,
			`OPENCLAW_E2E_HOST=${String(process.env.OPENCLAW_E2E_HOST ?? "").trim() ? "set" : `unset (default ${facts.gatewayHost})`}`,
			`${facts.configPath}=${facts.configPresent ? "present" : "absent"}`,
			`gateway.auth.token in config=${facts.fileToken ? "set" : "unset"}`,
			`gateway.http.endpoints.chatCompletions.enabled=${String(facts.chatEnabled)}`,
		],
		detail: facts.available
			? `gateway auth token and chatCompletions endpoint are configured for ${facts.gatewayHost}`
			: `gateway is not ready on this machine: missing ${missing.join("; ")} (host ${facts.gatewayHost})`,
	};
}

const HOST_PROBES = {
	claude: () =>
		probeExecutableHost({
			id: "claude",
			label: "Claude Code CLI (`claude`)",
			kind: "cli",
			commands: ["claude"],
		}),
	opencode: () =>
		probeExecutableHost({
			id: "opencode",
			label: "OpenCode CLI (`opencode`)",
			kind: "cli",
			commands: ["opencode"],
		}),
	openclaw: () => probeOpenClawGateway(),
	cursor: () =>
		probeExecutableHost({
			id: "cursor",
			label: "Cursor extension host (Cursor executable)",
			kind: "ide-host",
			envOverrides: ["AIDR_CURSOR_PATH"],
			commands: ["cursor"],
			candidates: cursorInstallCandidates(),
		}),
	agent: () =>
		probeExecutableHost({
			id: "agent",
			label: "Cursor headless agent CLI (`agent`)",
			kind: "cli",
			envOverrides: ["AIDR_AGENT_PATH"],
			commands: ["agent"],
		}),
	vscode: () =>
		probeExecutableHost({
			id: "vscode",
			label: "VS Code extension host (VS Code executable)",
			kind: "ide-host",
			envOverrides: ["AIDR_VSCODE_PATH", "VSCODE_EXECUTABLE_PATH"],
			commands: ["code", "code-insiders"],
			candidates: vsCodeInstallCandidates(),
		}),
};

function probeHosts(ids) {
	const records = new Map();
	for (const id of ids) {
		const probe = HOST_PROBES[id];
		records.set(id, probe ? probe() : { id, label: id, kind: "unknown", available: false, detail: "unknown host id" });
	}
	return records;
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

const cases = [
	{
		id: "claude-missing-api-key",
		target: "packages/claude-code",
		clear: ["ANTHROPIC_API_KEY"],
		env: {},
		hosts: ["claude"],
		inputs: [
			{
				id: "ANTHROPIC_API_KEY",
				description: "Anthropic credential for the Claude CLI",
				present: () => hasEnv("ANTHROPIC_API_KEY"),
			},
		],
		refusalSignatures: [/Claude Code E2E skipped[^\n]*/i, /missing ANTHROPIC_API_KEY/i],
	},
	{
		id: "openclaw-missing-gateway-token",
		target: "packages/openclaw",
		clear: ["OPENCLAW_GATEWAY_TOKEN"],
		env: {},
		hosts: ["openclaw"],
		inputs: [],
		refusalSignatures: [/OpenClaw E2E skipped[^\n]*/i, /no gateway token/i],
	},
	{
		id: "opencode-missing-cli",
		target: "packages/opencode",
		clear: [],
		env: { OPENCODE_E2E_BIN: "C:\\__aidr_negative_missing__\\opencode.exe" },
		hosts: ["opencode"],
		inputs: [],
		refusalSignatures: [/OpenCode E2E prerequisite failed[^\n]*/i],
	},
	{
		id: "cursor-missing-host-and-agent",
		target: "packages/extension",
		clear: ["AIDR_E2E_ENABLE_IDE_HOST", "AIDR_AGENT_PATH", "CURSOR_API_KEY"],
		env: { AIDR_E2E_HOST: "cursor" },
		hosts: ["cursor", "agent"],
		inputs: [
			{
				id: "CURSOR_API_KEY",
				description: "Cursor headless agent auth (`agent login` or CURSOR_API_KEY)",
				present: () => hasEnv("CURSOR_API_KEY"),
			},
		],
		refusalSignatures: [
			/Cursor E2E skipped[^\n]*/i,
			/agent CLI not found[^\n]*/i,
			/configured agent command is not runnable[^\n]*/i,
			/Set AIDR_E2E_ENABLE_IDE_HOST=1[^\n]*/i,
		],
	},
	{
		id: "vscode-missing-host",
		target: "packages/extension",
		clear: ["AIDR_E2E_ENABLE_IDE_HOST"],
		env: { AIDR_E2E_HOST: "vscode" },
		hosts: ["vscode"],
		inputs: [],
		refusalSignatures: [/VS Code E2E skipped[^\n]*/i, /Set AIDR_E2E_ENABLE_IDE_HOST=1[^\n]*/i],
	},
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readJson(filePath) {
	try {
		return JSON.parse(readFileSync(filePath, "utf8"));
	} catch {
		return undefined;
	}
}

function writeJson(filePath, value) {
	writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function relativePath(filePath) {
	return resolve(filePath).slice(root.length + 1).replaceAll("\\", "/");
}

function hasJunitEvidence(filePath) {
	return inspectJunit(filePath).present;
}

/**
 * Read the JUnit evidence independently of the JSON reporter. The two are
 * cross-checked so that a JSON report which under-reports the collected cases
 * (the failure mode this control exists to catch) cannot hide an executed
 * assertion.
 *
 * Vitest's JUnit reporter emits a synthetic testcase named after the test FILE
 * when the file itself failed to collect (a suite-level prerequisite error).
 * That is a refusal, not an executed assertion, so it is counted separately.
 */
function inspectJunit(filePath) {
	try {
		const xml = readFileSync(filePath, "utf8");
		const matches = [...xml.matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/gi)];
		const cases = matches.map((match) => {
			const attributes = match[1] ?? "";
			const name = /\bname="([^"]*)"/i.exec(attributes)?.[1] ?? "";
			const classname = /\bclassname="([^"]*)"/i.exec(attributes)?.[1] ?? "";
			const body = match[2] ?? "";
			const skipped = /<skipped\b/i.test(body);
			const failure = /<failure\b|<error\b/i.test(body);
			return {
				name,
				skipped,
				failure,
				suiteLevel: failure && name !== "" && name === classname,
				body,
			};
		});
		return {
			present: /<testsuite\b/i.test(xml),
			cases: cases.length,
			skipped: cases.filter((testCase) => testCase.skipped).length,
			failed: cases.filter((testCase) => testCase.failure).length,
			executed: cases.filter((testCase) => !testCase.skipped && !testCase.suiteLevel).length,
			suiteLevelFailures: cases.filter((testCase) => testCase.suiteLevel).length,
			messages: cases
				.filter((testCase) => testCase.failure)
				.map((testCase) => `${testCase.name}: ${testCase.body}`.slice(0, 400)),
		};
	} catch {
		return {
			present: false,
			cases: 0,
			skipped: 0,
			failed: 0,
			executed: 0,
			suiteLevelFailures: 0,
			messages: [],
		};
	}
}

function missingArtifacts() {
	return REQUIRED_ARTIFACTS.filter((relativeFile) => !existsSync(resolve(root, relativeFile)));
}

function scenarioRecord(testCase, hostRecords) {
	const hosts = testCase.hosts.map((id) => hostRecords.get(id)).filter(Boolean);
	const inputs = testCase.inputs.map((input) => ({
		id: input.id,
		description: input.description,
		present: input.present(),
	}));
	const removedInputs = [...testCase.clear, ...Object.keys(testCase.env)];
	return { hosts, inputs, removedInputs };
}

function describeMissing(hosts, inputs) {
	const parts = [];
	for (const host of hosts) parts.push(`${host.label}: ${host.detail}`);
	for (const input of inputs) parts.push(`${input.id} (${input.description}): not provided`);
	return parts;
}

/**
 * Classify one scenario run. The wrong-accept guard is the first thing that can
 * return FAIL and it cannot be bypassed by any availability fact.
 */
function classifyScenario(testCase, run) {
	const report = readJson(run.reportPath);
	const assertions = Array.isArray(report?.testResults)
		? report.testResults.flatMap((suite) =>
				Array.isArray(suite?.assertionResults) ? suite.assertionResults : [],
			)
		: [];
	const statuses = assertions.map((assertion) => String(assertion?.status ?? "unknown"));
	const counts = {
		collected: assertions.length,
		passed: statuses.filter((status) => status === "passed").length,
		failed: statuses.filter((status) => status === "failed").length,
		pending: statuses.filter((status) => status === "skipped" || status === "pending").length,
		todo: statuses.filter((status) => status === "todo").length,
	};
	counts.executed = counts.passed + counts.failed;
	counts.refused = counts.executed === 0 && counts.todo === 0;
	const reportedTotal = Number.isInteger(report?.numTotalTests) ? report.numTotalTests : undefined;

	const vitest = {
		exitCode: run.result.status,
		signal: run.result.signal ?? null,
		processError: run.result.error ? String(run.result.error.message ?? run.result.error) : null,
		success: report?.success ?? null,
		reportedTotal: reportedTotal ?? null,
		...counts,
	};
	const evidence = {
		json: relativePath(run.reportPath),
		junit: relativePath(run.junitPath),
		stdout: relativePath(run.stdoutPath),
		stderr: relativePath(run.stderrPath),
	};

	// --- integrity: an unusable control must never report PASS -------------
	if (run.skippedReason) {
		return { status: SETUP_FAILURE, reason: run.skippedReason, vitest, evidence };
	}
	if (!report) {
		return {
			status: SETUP_FAILURE,
			reason: "JSON evidence missing or invalid; the control cannot tell a refusal from a broken run",
			vitest,
			evidence,
		};
	}
	if (reportedTotal !== counts.collected) {
		return {
			status: SETUP_FAILURE,
			reason: `evidence integrity: reported total=${String(reportedTotal)} but assertions collected=${counts.collected}`,
			vitest,
			evidence,
		};
	}
	if (!hasJunitEvidence(run.junitPath)) {
		return {
			status: SETUP_FAILURE,
			reason: "JUnit evidence missing or invalid",
			vitest,
			evidence,
		};
	}

	// --- anti-weakening guard: a negative case that ran was wrongly accepted
	//
	// This runs before any host/credential availability fact is consulted, and it
	// uses both the JSON report and the JUnit report, so a negative case that was
	// allowed to execute can never be downgraded to a skip, a blocker or a PASS.
	// `junit.executed` catches a JSON report that lost the assertions while JUnit
	// still recorded them as executed assertions.
	const junit = inspectJunit(run.junitPath);
	const jsonSuiteFailures = (Array.isArray(report.testResults) ? report.testResults : []).filter(
		(suite) =>
			(Array.isArray(suite?.assertionResults) ? suite.assertionResults : []).length === 0 &&
			String(suite?.message ?? "").trim() !== "",
	).length;
	const executedAssertions = assertions.filter(
		(assertion) => assertion?.status !== "skipped" && assertion?.status !== "pending",
	);
	if (
		executedAssertions.length > 0 ||
		counts.executed > 0 ||
		counts.passed > 0 ||
		counts.failed > 0 ||
		counts.todo > 0 ||
		junit.executed > 0
	) {
		const titles = executedAssertions
			.slice(0, 5)
			.map((assertion) => `${String(assertion?.title ?? "assertion")} (${String(assertion?.status)})`);
		const junitNote =
			junit.executed > 0
				? `; JUnit recorded ${junit.executed} executed testcase(s) of ${junit.cases}`
				: "";
		return {
			status: FAIL,
			reason:
				`wrong accept: ${counts.executed} assertion(s) executed and ${counts.passed} passed ` +
				`under the negative case (collected=${counts.collected}, pending=${counts.pending}${junitNote})` +
				(titles.length > 0 ? `: ${titles.join("; ")}` : "") +
				" - the suite did not refuse to run without its credential/host",
			vitest: { ...vitest, junit },
			evidence,
		};
	}
	if (
		junit.cases - junit.suiteLevelFailures !== counts.collected ||
		junit.suiteLevelFailures !== jsonSuiteFailures
	) {
		return {
			status: SETUP_FAILURE,
			reason:
				`evidence integrity: JSON report collected=${counts.collected} with ${jsonSuiteFailures} suite-level error(s) ` +
				`but JUnit recorded ${junit.cases} testcase(s) of which ${junit.suiteLevelFailures} are suite-level errors`,
			vitest: { ...vitest, junit },
			evidence,
		};
	}

	// --- positive evidence that the refusal came from the missing input ----
	//
	// Two refusal shapes are legitimate, and both must be proven, never assumed:
	//
	//   skipped  Vitest collected the suite and reported every assertion as
	//            skipped (`numPendingTests === numTotalTests`). The report itself
	//            is the evidence: a crashed or unloaded suite cannot produce it.
	//   aborted  The suite refused at import time (for example a configured CLI
	//            override that does not exist), so Vitest reports zero tests and
	//            a non-zero exit. This shape is only accepted when the captured
	//            output names the declared prerequisite failure, because an
	//            unrelated crash looks identical.
	const haystack = [
		run.stdout,
		run.stderr,
		...assertions.flatMap((assertion) =>
			Array.isArray(assertion?.failureMessages) ? assertion.failureMessages : [],
		),
		// Suite-level collection errors carry the prerequisite failure text that the
		// `aborted` refusal shape is proven with; they only appear in the reports.
		...(Array.isArray(report.testResults) ? report.testResults : []).map((suite) =>
			String(suite?.message ?? ""),
		),
		...junit.messages,
	].join("\n");
	const collectedAll = reportedTotal === counts.collected;
	const skippedSuite =
		report.success === true &&
		collectedAll &&
		counts.collected > 0 &&
		counts.pending === counts.collected &&
		counts.executed === 0 &&
		counts.todo === 0;

	// A setup/infrastructure failure is never a refusal, whatever the suite says.
	if (/\[global-setup\]/.test(haystack)) {
		return {
			status: SETUP_FAILURE,
			reason:
				"the Vitest global setup failed (missing or stale build artifacts), so no scenario can be classified",
			vitest,
			evidence,
		};
	}

	let refusalEvidence;
	if (skippedSuite) {
		refusalEvidence = `Vitest collected ${counts.collected} assertion(s) and reported all of them skipped (success=true, exit=${String(run.result.status)})`;
	} else {
		const refusalMatch = testCase.refusalSignatures
			.map((pattern) => pattern.exec(haystack))
			.find((match) => match !== null);
		if (!refusalMatch || run.result.status === 0) {
			return {
				status: SETUP_FAILURE,
				reason:
					"no refusal evidence: no assertion executed, but the suite never declared that it refused " +
					"because of the removed credential/host (expected one of " +
					testCase.refusalSignatures.map((pattern) => pattern.source).join(" | ") +
					`; exit=${String(run.result.status)})`,
				vitest,
				evidence,
			};
		}
		refusalEvidence = `the suite refused at collection time (exit=${String(run.result.status)}): ${refusalMatch[0].trim()}`;
	}

	// --- the suite refused: decide whether this machine could ever be decisive
	const { hosts, inputs } = run.scenario;
	const missingHosts = hosts.filter((host) => !host.available && host.kind !== "service");
	const missingServices = hosts.filter((host) => !host.available && host.kind === "service");
	const missingInputs = inputs.filter((input) => !input.present);
	const unsupported = hosts.filter(
		(host) => !(PLATFORM_HOST_SUPPORT[host.id] ?? []).includes(process.platform) && host.available,
	);
	const refusal = `the suite refused to execute (0 executed assertions, ${counts.collected} collected); refusal evidence: ${refusalEvidence}`;

	if (unsupported.length > 0) {
		return {
			status: UNSUPPORTED,
			reason: `${refusal}; not advertised for ${process.platform}: ${unsupported.map((host) => host.label).join(", ")}`,
			vitest,
			evidence,
		};
	}
	if (missingHosts.length > 0) {
		return {
			status: HOST_UNAVAILABLE,
			reason: `${refusal}; this machine cannot be decisive because the host is not installed - ${describeMissing(missingHosts, []).join("; ")}`,
			vitest,
			evidence,
		};
	}
	if (missingServices.length > 0 || missingInputs.length > 0) {
		return {
			status: BLOCKED_EXTERNAL,
			reason: `${refusal}; this machine cannot be decisive because an external input is missing - ${describeMissing(missingServices, missingInputs).join("; ")}`,
			vitest,
			evidence,
		};
	}
	return {
		status: PASS,
		reason: `${refusal}; host(s) ${hosts.map((host) => host.label).join(", ")} are present, so the refusal is attributable to the deliberately removed input(s): ${run.scenario.removedInputs.join(", ")}`,
		vitest,
		evidence,
	};
}

function runScenario(testCase, hostRecords, artifactsMissing) {
	const reportPath = resolve(evidenceDir, `${testCase.id}.json`);
	const junitPath = resolve(evidenceDir, `${testCase.id}.xml`);
	const stdoutPath = resolve(evidenceDir, `${testCase.id}.stdout.log`);
	const stderrPath = resolve(evidenceDir, `${testCase.id}.stderr.log`);
	for (const filePath of [reportPath, junitPath, stdoutPath, stderrPath]) rmSync(filePath, { force: true });

	const scenario = scenarioRecord(testCase, hostRecords);
	const record = {
		id: testCase.id,
		target: testCase.target,
		removedInputs: scenario.removedInputs,
		hosts: scenario.hosts,
		inputs: scenario.inputs,
	};

	if (artifactsMissing.length > 0) {
		record.status = SETUP_FAILURE;
		record.reason = `required build artifacts are missing, so no scenario can be classified: ${artifactsMissing.join(", ")} (run the build first)`;
		record.vitest = null;
		return record;
	}

	// Each scenario runs the release-mode E2E configuration (AIDR_E2E_RELEASE=1)
	// against the immutable build prepared by the release pipeline. Without the
	// release flag every Vitest invocation runs developer global setup, which
	// rebuilds and deletes the shared core/dist tree across the five negative
	// cases. Missing artifacts are a setup failure, never a refusal.
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
			stdio: ["ignore", "pipe", "pipe"],
			shell: process.platform === "win32",
			windowsHide: true,
			maxBuffer: 32 * 1024 * 1024,
		},
	);

	const stdout = String(result.stdout ?? "");
	const stderr = String(result.stderr ?? "");
	writeFileSync(stdoutPath, stdout, "utf8");
	writeFileSync(stderrPath, stderr, "utf8");
	process.stdout.write(`\n--- ${testCase.id} stdout ---\n${stdout}`);
	if (stderr.trim()) process.stderr.write(`--- ${testCase.id} stderr ---\n${stderr}`);

	const classification = classifyScenario(testCase, {
		result,
		reportPath,
		junitPath,
		stdoutPath,
		stderrPath,
		stdout,
		stderr,
		scenario,
	});
	return { ...record, ...classification, hosts: scenario.hosts, inputs: scenario.inputs };
}

// ---------------------------------------------------------------------------
// Release preflight scenario
// ---------------------------------------------------------------------------

/**
 * The release orchestrator itself must reject an environment with every
 * external credential/evidence pointer removed. A green Vitest process is not
 * enough: this control proves the promotion command exits non-zero and writes a
 * failed, machine-readable summary in an isolated evidence directory.
 */
function runReleasePreflight() {
	const summaryFile = resolve(releaseEvidenceDir, "summary.json");
	const stdoutPath = resolve(evidenceDir, "release-preflight.stdout.log");
	const stderrPath = resolve(evidenceDir, "release-preflight.stderr.log");
	// Never read a stale summary written by an earlier run: a deleted or absent
	// file is a setup failure, a leftover "failed" file would be a false PASS.
	rmSync(summaryFile, { force: true });

	const env = { ...process.env, AIDR_E2E_NEGATIVE: "1", AIDR_E2E_EVIDENCE_DIR: releaseEvidenceDir };
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
	]) {
		delete env[name];
	}
	const result = spawnSync(process.execPath, ["scripts/run-e2e-release.mjs"], {
		cwd: root,
		encoding: "utf8",
		env,
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
		maxBuffer: 32 * 1024 * 1024,
	});
	const stdout = String(result.stdout ?? "");
	const stderr = String(result.stderr ?? "");
	writeFileSync(stdoutPath, stdout, "utf8");
	writeFileSync(stderrPath, stderr, "utf8");
	process.stdout.write(`\n--- release-preflight stdout ---\n${stdout}`);
	if (stderr.trim()) process.stderr.write(`--- release-preflight stderr ---\n${stderr}`);

	const releaseSummary = readJson(summaryFile);
	const blockedSuites = Array.isArray(releaseSummary?.suites)
		? releaseSummary.suites.filter((suite) => suite?.setupStatus === "blocked")
		: [];
	const record = {
		id: "release-preflight-all-external-inputs-removed",
		target: "scripts/run-e2e-release.mjs",
		removedInputs: [
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
		],
		hosts: [],
		inputs: [],
		evidence: {
			summary: relativePath(summaryFile),
			stdout: relativePath(stdoutPath),
			stderr: relativePath(stderrPath),
		},
		releasePreflight: {
			exitCode: result.status,
			summaryStatus: releaseSummary?.status ?? null,
			blockedSuites: blockedSuites.map((suite) => suite.id),
		},
	};

	if (result.status === 0) {
		record.status = FAIL;
		record.reason =
			"the promotion command unexpectedly exited zero with every external credential/evidence pointer removed";
		return record;
	}
	if (!releaseSummary) {
		record.status = SETUP_FAILURE;
		record.reason = `the promotion command exited ${String(result.status)} but wrote no readable summary.json (exit != 0 is not proof the credential gate refused)`;
		return record;
	}
	if (releaseSummary.status !== "failed") {
		record.status = releaseSummary.status === "passed" ? FAIL : SETUP_FAILURE;
		record.reason = `the promotion command exited ${String(result.status)} but its summary status is ${String(releaseSummary.status ?? "missing")}, not "failed"`;
		return record;
	}
	if (blockedSuites.length === 0) {
		record.status = SETUP_FAILURE;
		record.reason =
			"the promotion command failed but no suite reported a blocked setup preflight, so the refusal is not attributable to the removed inputs";
		return record;
	}
	record.status = PASS;
	record.reason =
		`the promotion command refused the credential-less environment (exit=${String(result.status)}, summary status=failed, ` +
		`blocked suites=${blockedSuites.length}: ${blockedSuites.map((suite) => suite.id).join(", ")})`;
	return record;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

mkdirSync(evidenceDir, { recursive: true });
// A result file from an earlier run must never be mistaken for this one: if the
// control crashes before it writes its verdict, the absence of summary.json is
// the honest record.
rmSync(summaryPath, { force: true });

const hostIds = [...new Set(cases.flatMap((testCase) => testCase.hosts))];
const hostRecords = probeHosts(hostIds);
const artifactsMissing = missingArtifacts();

const scenarios = cases.map((testCase) => runScenario(testCase, hostRecords, artifactsMissing));
scenarios.push(runReleasePreflight());

const statusCounts = Object.fromEntries(STATUS_VOCABULARY.map((status) => [status, 0]));
for (const scenario of scenarios) statusCounts[scenario.status] = (statusCounts[scenario.status] ?? 0) + 1;

const productFailures = scenarios.filter((scenario) => scenario.status === FAIL);
const setupFailures = scenarios.filter((scenario) => scenario.status === SETUP_FAILURE);
const blockers = scenarios.filter((scenario) => BLOCKED_STATUSES.has(scenario.status));

let decision = DECISION_PASS;
if (productFailures.length > 0) decision = DECISION_FAIL;
else if (setupFailures.length > 0) decision = DECISION_INVALID;
else if (blockers.length > 0) decision = DECISION_NO_GO;

const status = { [DECISION_PASS]: "passed", [DECISION_NO_GO]: "blocked", [DECISION_FAIL]: "failed", [DECISION_INVALID]: "invalid" }[decision];
const exitCode = EXIT_CODE[decision];
const finishedAt = new Date().toISOString();

const missingHosts = [...hostRecords.values()]
	.filter((host) => !host.available && host.kind !== "service")
	.map((host) => ({ id: host.id, label: host.label, detail: host.detail }));
const missingExternalInputs = [
	...hostRecords
		.values()
		.filter((host) => !host.available && host.kind === "service")
		.map((host) => ({ id: host.id, description: host.label, detail: host.detail })),
	...scenarios.flatMap((scenario) =>
		(scenario.inputs ?? [])
			.filter((input) => !input.present)
			.map((input) => ({ id: input.id, description: input.description, detail: "not provided" })),
	),
].filter(
	(item, index, all) => all.findIndex((candidate) => candidate.id === item.id) === index,
);

const summary = {
	schemaVersion: "aidr-e2e-negative-credentials-v1",
	kind: "aidr-e2e-negative-credentials-control",
	command: "pnpm test:e2e:negative",
	runId,
	startedAt,
	finishedAt,
	decision,
	status,
	exitCode,
	productFailure: productFailures.length > 0,
	vocabulary: STATUS_VOCABULARY,
	statusCounts,
	requiresProductFix: productFailures.map((scenario) => `${scenario.id}: ${scenario.reason}`),
	blockers: blockers.map((scenario) => `${scenario.id} [${scenario.status}]: ${scenario.reason}`),
	setupFailures: setupFailures.map((scenario) => `${scenario.id}: ${scenario.reason}`),
	missingHosts,
	missingExternalInputs,
	environment: {
		platform: process.platform,
		arch: process.arch,
		node: process.version,
		releaseMode: "AIDR_E2E_RELEASE=1 against the immutable release build",
		artifactsMissing,
	},
	hostAvailability: [...hostRecords.values()],
	scenarios,
	evidence: { directory: relativePath(evidenceDir), summary: relativePath(summaryPath) },
	// Serialization boundary for the release evidence index
	// (scripts/generate-v8-evidence-index.mjs), which reads exit_code,
	// started_at_utc, ended_at_utc and duration_ms from a result file.
	exit_code: exitCode,
	started_at_utc: startedAt,
	ended_at_utc: finishedAt,
	duration_ms: Math.max(0, Date.parse(finishedAt) - Date.parse(startedAt)),
};

writeJson(summaryPath, summary);

console.log("\nNegative credential E2E control - scenario outcomes:");
for (const scenario of scenarios) {
	console.log(`- ${scenario.id}: ${scenario.status}`);
	console.log(`    ${scenario.reason}`);
}

if (decision === DECISION_FAIL) {
	console.error("\nNegative credential E2E control failed:");
	for (const failure of productFailures) console.error(`- ${failure.id}: ${failure.reason}`);
	console.error(`Evidence: ${evidenceDir}`);
} else if (decision === DECISION_INVALID) {
	console.error("\nNegative credential E2E control could not be exercised (no product verdict):");
	for (const failure of setupFailures) console.error(`- ${failure.id}: ${failure.reason}`);
	console.error(`Evidence: ${evidenceDir}`);
} else if (decision === DECISION_NO_GO) {
	console.error("\nNegative credential E2E control: NO-GO (blocked environment) - not a product failure.");
	console.error(
		`No negative case was wrongly accepted (FAIL=0); ${blockers.length} scenario(s) could not be exercised on this machine.`,
	);
	console.error("\nHosts not installed:");
	for (const host of missingHosts) console.error(`- ${host.label}: ${host.detail}`);
	console.error("\nExternal inputs missing:");
	for (const input of missingExternalInputs) console.error(`- ${input.id}: ${input.detail}`);
	console.error(
		`\nBlocked scenarios: ${blockers.map((scenario) => `${scenario.id} [${scenario.status}]`).join(", ")}`,
	);
	console.error(`Evidence: ${evidenceDir}`);
} else {
	console.log(`Negative credential E2E control passed; evidence: ${evidenceDir}`);
}

console.log(
	`[e2e-negative] decision=${decision} status=${status} exit_code=${exitCode} product_failures=${productFailures.length} blocked=${blockers.length} setup_failures=${setupFailures.length} passed=${statusCounts[PASS] ?? 0}`,
);

process.exitCode = exitCode;
