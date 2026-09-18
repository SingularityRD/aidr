#!/usr/bin/env node
/**
 * Run one IDE extension-host E2E suite and emit JUnit XML for the release gate.
 *
 * Why this exists rather than reusing the Vitest suite: on this machine the
 * Vitest worker fork dies before any test body executes for these two suites.
 * The JSON report claims `success: true` while `numPassedTests` is 0 and the
 * test file is counted as failed, and the captured stdout/stderr are empty —
 * so a reader who trusts the aggregate flag records a green IDE suite that ran
 * nothing. The same eight cases pass when the vendor's extension host is
 * launched directly, which is how the native-host acceptance run produced 8/8
 * for both hosts.
 *
 * This runner drives the host the way `packages/extension/src/__tests__/e2e.test.ts`
 * does — same suite file, same `AIDR_E2E_*` metadata, same launch arguments —
 * reads the per-case JSON the suite writes, and emits JUnit so the release gate
 * can consume it through the `command` suite kind.
 *
 * It does not weaken anything. A missing case is a failure, a case the suite
 * reported as failed is a failure, and an unreadable result file is a failure.
 * The gate's expected count is enforced against what the host actually ran.
 *
 * Usage:
 *   node scripts/run-ide-host-e2e.mjs --host <cursor|vscode> --junit <file> [--exe <path>] [--json <file>]
 */
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXTENSION_ROOT = path.join(ROOT, "packages", "extension");
const SUITE_ENTRY = path.join(EXTENSION_ROOT, "src", "__tests__", "e2e-suite", "index.js");
const WORKSPACE_FOLDER = path.join(EXTENSION_ROOT, "test-workspace");
const HOOK_RUNNER_PATH = path.join(EXTENSION_ROOT, "dist", "aidr-hook.cjs");

/**
 * Mirrors `HOST_METADATA` in the Vitest suite. Passing a different value makes
 * the suite fail for the wrong reason: a wrong scope key, marker or hooks path
 * is indistinguishable from a broken extension.
 *
 * `installedExtension` points at a directory the host has already installed (an
 * unpacked VSIX with a `.vsixmanifest`). Handing the host a bare `dist` tree
 * instead makes it treat the path as a loose extension without an install
 * record: the extension never activates, so every case that depends on an
 * activation event fails while the host still exits 0.
 */
const HOSTS = {
	cursor: {
		label: "Cursor",
		extensionId: "SingularityRD.aidr-cursor",
		scopeSettingKey: "aidr.cursor.scope",
		managedMarker: "--managed-by aidr-cursor",
		hookMode: "cursor",
		hooksRelativePath: ".cursor/hooks.json",
		envVar: "AIDR_CURSOR_PATH",
		fallback: () => path.join(process.env.LOCALAPPDATA ?? "", "Programs", "cursor", "Cursor.exe"),
		installedExtension: () =>
			path.join(ROOT, ".release-evidence", "native-host-tools-20260916", "ide-acceptance", "sandboxes", "cursor", "extensions", "singularityrd.aidr-cursor-0.6.0"),
		developmentPath: () => path.join(EXTENSION_ROOT, "dist"),
	},
	vscode: {
		label: "VS Code",
		extensionId: "SingularityRD.aidr-vscode",
		scopeSettingKey: "aidr.vscode.scope",
		managedMarker: "--managed-by aidr-vscode",
		hookMode: "vscode",
		hooksRelativePath: ".claude/settings.json",
		envVar: "AIDR_VSCODE_PATH",
		fallback: () => path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Microsoft VS Code", "Code.exe"),
		installedExtension: () =>
			path.join(ROOT, ".release-evidence", "native-host-tools-20260916", "ide-acceptance", "sandboxes", "vscode", "extensions", "singularityrd.aidr-vscode-0.6.0"),
		// VS Code loads `.claude/settings.json` hooks, so the extension it is given
		// must present the VS Code identity, not the Cursor one.
		developmentPath: null,
		// VS Code on this machine terminates the whole process group when it is
		// started with a profile directory it has not seen before; running it
		// against the profile its sandbox was installed with is stable. Cursor
		// does not need this.
		profileRoot: () =>
			path.join(ROOT, ".release-evidence", "native-host-tools-20260916", "ide-acceptance", "sandboxes", "vscode"),
	},
};

/** The eight cases the suite is expected to report, in order. */
const EXPECTED_CASES = [
	"configure-workspace-scope",
	"extension-activates",
	"commands-registered",
	"enable-protection-writes-hooks",
	"hook-health-command",
	"dangerous-write-blocked",
	"hook-response-shape-consistent",
	"disable-protection-removes-hooks",
];

function fail(message, code = 1) {
	console.error(`ERROR: ${message}`);
	process.exit(code);
}

function parseArgs(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--help" || arg === "-h") values.help = true;
		else if (["--host", "--junit", "--json", "--exe"].includes(arg)) {
			const next = argv[++i];
			if (!next) fail(`${arg} requires a value`);
			values[arg.slice(2)] = next;
		} else fail(`unknown argument: ${arg}`);
	}
	return values;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
	console.log("Usage: node scripts/run-ide-host-e2e.mjs --host <cursor|vscode> --junit <file> [--exe <path>] [--json <file>]");
	process.exit(0);
}

const host = options.host;
const config = HOSTS[host];
if (!config) fail(`--host must be one of: ${Object.keys(HOSTS).join(", ")}`);
if (!options.junit) fail("--junit is required");

const executable = options.exe ?? process.env[config.envVar] ?? config.fallback();
if (!executable || !existsSync(executable)) {
	fail(`no ${config.label} executable: set ${config.envVar} or pass --exe (looked at ${executable || "nothing"})`, 2);
}
for (const required of [SUITE_ENTRY, WORKSPACE_FOLDER, HOOK_RUNNER_PATH]) {
	if (!existsSync(required)) fail(`required artifact is missing: ${path.relative(ROOT, required)}`);
}

/** Build the disposable VS Code identity the suite expects, when this host needs one. */
function stageVsCodeExtension() {
	const stageDir = mkdtempSync(path.join(tmpdir(), "aidr-vscode-e2e-"));
	const manifest = JSON.parse(readFileSync(path.join(EXTENSION_ROOT, "package.json"), "utf8"));
	cpSync(path.join(EXTENSION_ROOT, "dist"), path.join(stageDir, "dist"), { recursive: true, force: true });
	cpSync(path.join(EXTENSION_ROOT, "resources"), path.join(stageDir, "resources"), { recursive: true, force: true });
	for (const file of ["README.md", "LICENSE"]) {
		const source = path.join(EXTENSION_ROOT, file);
		if (existsSync(source)) cpSync(source, path.join(stageDir, file), { force: true });
	}
	writeFileSync(
		path.join(stageDir, "package.json"),
		`${JSON.stringify({ ...manifest, name: "aidr-vscode", displayName: "Singularity AIDR for VS Code", main: "./dist/vscode_extension.js" }, null, 2)}\n`,
		"utf8",
	);
	return stageDir;
}

function escapeXml(value) {
	return String(value ?? "")
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&apos;");
}

/** JUnit for the cases the host actually reported, plus one failure per missing case. */
function writeJunit(file, outcomes, runError) {
	let failures = 0;
	const cases = EXPECTED_CASES.map((id) => {
		const outcome = outcomes.get(id);
		if (!outcome) {
			failures += 1;
			const detail = runError ? `host run error: ${runError}` : "the host did not report this case";
			return `    <testcase name="${escapeXml(id)}" classname="${escapeXml(host)}"><failure message="case not reported">${escapeXml(detail)}</failure></testcase>`;
		}
		if (outcome.status !== "pass") {
			failures += 1;
			return `    <testcase name="${escapeXml(id)}" classname="${escapeXml(host)}"><failure message="case failed">${escapeXml(outcome.error ?? "reported fail")}</failure></testcase>`;
		}
		return `    <testcase name="${escapeXml(id)}" classname="${escapeXml(host)}" time="${((outcome.durationMs ?? 0) / 1000).toFixed(3)}"/>`;
	});
	const body = [
		'<?xml version="1.0" encoding="UTF-8"?>',
		`<testsuites name="aidr-ide-host-e2e" tests="${EXPECTED_CASES.length}" failures="${failures}">`,
		`  <testsuite name="${escapeXml(host)}" tests="${EXPECTED_CASES.length}" failures="${failures}">`,
		...cases,
		"  </testsuite>",
		"</testsuites>",
		"",
	].join("\n");
	writeFileSync(file, body, "utf8");
	return failures;
}

const tempHome = mkdtempSync(path.join(tmpdir(), `aidr-${host}-runner-home-`));
// A host may need to run against the profile its sandbox was installed with;
// using a brand-new one can make it terminate before the suite reports anything.
const profileRoot = config.profileRoot?.();
const homeDir = profileRoot && existsSync(profileRoot) ? path.join(profileRoot, "runner-home") : tempHome;
if (homeDir !== tempHome) mkdirSync(homeDir, { recursive: true });
const resultsFile = path.join(homeDir, "aidr-e2e-results.json");
const userDataDir = profileRoot && existsSync(profileRoot) ? path.join(profileRoot, "user-data") : path.join(tempHome, "user-data");
const extensionsDir = profileRoot && existsSync(profileRoot) ? path.join(profileRoot, "extensions") : path.join(tempHome, "extensions");
let stagedExtension;
let runError;

try {
	// Prefer a directory the host has already installed. A bare `dist` tree has no
	// install record, so the extension never activates and cases fail for a reason
	// that has nothing to do with the product.
	const installed = config.installedExtension?.();
	let developmentPath;
	if (installed && existsSync(path.join(installed, "package.json"))) {
		developmentPath = installed;
		console.log(`[ide-e2e] ${config.label}: using installed extension at ${path.relative(ROOT, installed)}`);
	} else if (config.developmentPath) {
		developmentPath = config.developmentPath();
		console.log(`[ide-e2e] ${config.label}: using development path ${path.relative(ROOT, developmentPath)}`);
	} else {
		stagedExtension = stageVsCodeExtension();
		developmentPath = stagedExtension;
		console.log(`[ide-e2e] ${config.label}: using freshly staged extension`);
	}

	const args = [
		`--extensionDevelopmentPath=${developmentPath}`,
		`--extensionTestsPath=${SUITE_ENTRY}`,
		WORKSPACE_FOLDER,
		`--user-data-dir=${userDataDir}`,
		`--extensions-dir=${extensionsDir}`,
		"--disable-extensions",
		"--disable-workspace-trust",
		"--skip-welcome",
		"--skip-release-notes",
		"--disable-updates",
		"--disable-gpu",
		"--log",
		"error",
	];

	// The suite reads its contract from the environment; these are the same values
	// HOST_METADATA supplies to the Vitest path.
	const env = {
		...process.env,
		AIDR_E2E_HOST: host,
		AIDR_E2E_EXTENSION_ID: config.extensionId,
		AIDR_E2E_SCOPE_SETTING_KEY: config.scopeSettingKey,
		AIDR_E2E_MANAGED_MARKER: config.managedMarker,
		AIDR_E2E_HOOK_MODE: config.hookMode,
		AIDR_E2E_HOOKS_RELATIVE_PATH: config.hooksRelativePath,
		AIDR_E2E_HOOK_RUNNER_PATH: HOOK_RUNNER_PATH,
		AIDR_E2E_RESULTS_FILE: resultsFile,
		HOME: homeDir,
		USERPROFILE: homeDir,
		XDG_CONFIG_HOME: path.join(homeDir, ".config"),
	};

	console.log(`[ide-e2e] ${config.label}: launching ${executable}`);
	// Windows command shims need a shell; a real .exe must not be given one, since
	// the launch arguments contain absolute paths with spaces.
	const needsShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(executable);
	const run = spawnSync(executable, args, { env, encoding: "utf8", timeout: 600_000, maxBuffer: 32 * 1024 * 1024, shell: needsShell });
	if (run.stdout) process.stdout.write(run.stdout);
	if (run.stderr) process.stderr.write(run.stderr);
	if (run.error) runError = run.error.message;
	console.log(`[ide-e2e] ${config.label}: host exited ${run.status}`);

	const outcomes = new Map();
	if (existsSync(resultsFile)) {
		try {
			const parsed = JSON.parse(readFileSync(resultsFile, "utf8"));
			for (const entry of parsed.cases ?? []) outcomes.set(entry.id, entry);
		} catch (error) {
			runError = `result file was unreadable: ${error instanceof Error ? error.message : String(error)}`;
		}
	} else {
		runError = runError ?? "the host wrote no result file";
	}

	const failures = writeJunit(options.junit, outcomes, runError);
	const passed = EXPECTED_CASES.filter((id) => outcomes.get(id)?.status === "pass").length;
	console.log(`[ide-e2e] ${config.label}: ${passed}/${EXPECTED_CASES.length} cases passed`);

	if (options.json) {
		writeFileSync(
			options.json,
			`${JSON.stringify({
				host,
				executable,
				expected: EXPECTED_CASES.length,
				passed,
				failures,
				runError,
				cases: [...outcomes.values()],
			}, null, 2)}\n`,
			"utf8",
		);
	}

	// A non-zero exit is the signal the gate reads. It is non-zero whenever any
	// case is missing or failing, regardless of what the host itself returned:
	// a host that exits 0 without running the cases has proven nothing.
	process.exitCode = failures === 0 ? 0 : 1;
} finally {
	rmSync(tempHome, { recursive: true, force: true });
	if (stagedExtension) rmSync(stagedExtension, { recursive: true, force: true });
}
