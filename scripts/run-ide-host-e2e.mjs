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
 *   AIDR_E2E_VSIX_PATH=<candidate.vsix> AIDR_E2E_VSIX_SHA256=<sha256> \
 *     node scripts/run-ide-host-e2e.mjs --host <cursor|vscode> --junit <file> [--exe <path>] [--json <file>] [--workspace <fresh-temp-dir>]
 */
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXTENSION_ROOT = path.join(ROOT, "packages", "extension");
const SUITE_ENTRY = path.join(EXTENSION_ROOT, "src", "__tests__", "e2e-suite", "index.js");
const DEFAULT_WORKSPACE_FOLDER = path.join(EXTENSION_ROOT, "test-workspace");

/**
 * Mirrors `HOST_METADATA` in the Vitest suite. Passing a different value makes
 * the suite fail for the wrong reason: a wrong scope key, marker or hooks path
 * is indistinguishable from a broken extension.
 *
 * Each run installs the inventory-bound VSIX into a new profile. Reusing a
 * developer checkout or a preinstalled extension could let stale bytes pass
 * acceptance while the release candidate itself was never exercised.
 */
const HOSTS = {
	cursor: {
		label: "Cursor",
		extensionId: "SingularityRD.aidr-cursor",
		packageName: "aidr-cursor",
		main: "./dist/cursor_extension.js",
		scopeSettingKey: "aidr.cursor.scope",
		managedMarker: "--managed-by aidr-cursor",
		hookMode: "cursor",
		hooksRelativePath: ".cursor/hooks.json",
		envVar: "AIDR_CURSOR_PATH",
		fallback: () => path.join(process.env.LOCALAPPDATA ?? "", "Programs", "cursor", "Cursor.exe"),
	},
	vscode: {
		label: "VS Code",
		extensionId: "SingularityRD.aidr-vscode",
		packageName: "aidr-vscode",
		main: "./dist/vscode_extension.js",
		scopeSettingKey: "aidr.vscode.scope",
		managedMarker: "--managed-by aidr-vscode",
		hookMode: "vscode",
		hooksRelativePath: ".claude/settings.json",
		envVar: "AIDR_VSCODE_PATH",
		fallback: () => path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Microsoft VS Code", "Code.exe"),
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
		else if (["--host", "--junit", "--json", "--exe", "--workspace"].includes(arg)) {
			const next = argv[++i];
			if (!next) fail(`${arg} requires a value`);
			values[arg.slice(2)] = next;
		} else fail(`unknown argument: ${arg}`);
	}
	return values;
}

const options = parseArgs(process.argv.slice(2));
if (options.help) {
	console.log("Usage: AIDR_E2E_VSIX_PATH=<candidate.vsix> AIDR_E2E_VSIX_SHA256=<sha256> node scripts/run-ide-host-e2e.mjs --host <cursor|vscode> --junit <file> [--exe <path>] [--json <file>] [--workspace <fresh-temp-dir>]");
	process.exit(0);
}

const host = options.host;
const config = HOSTS[host];
if (!config) fail(`--host must be one of: ${Object.keys(HOSTS).join(", ")}`);
if (!options.junit) fail("--junit is required");

const WORKSPACE_FOLDER = options.workspace ?? DEFAULT_WORKSPACE_FOLDER;
if (options.workspace) {
	// The suite removes hook/config directories. An explicit fixture therefore
	// must be a fresh directory directly under the OS temp root, never a profile,
	// repository, symlink or Windows junction containing an operator's settings.
	let safe = false;
	try {
		const info = lstatSync(WORKSPACE_FOLDER);
		const tempRoot = realpathSync(tmpdir());
		safe = path.isAbsolute(WORKSPACE_FOLDER) && info.isDirectory() && !info.isSymbolicLink()
			&& realpathSync(path.dirname(WORKSPACE_FOLDER)) === tempRoot
			&& path.dirname(realpathSync(WORKSPACE_FOLDER)) === tempRoot
			&& path.basename(WORKSPACE_FOLDER).startsWith("aidr-ide-workspace-")
			&& readdirSync(WORKSPACE_FOLDER).length === 0;
	} catch { /* An absent/unreadable fixture is unsafe. */ }
	if (!safe) fail("--workspace must be an empty controlled temporary directory (aidr-ide-workspace-*), without symlinks or junctions");
}

const hostCandidatePrefix = `AIDR_E2E_${host.toUpperCase()}_VSIX`;
const candidateInput = process.env[`${hostCandidatePrefix}_PATH`] ?? process.env.AIDR_E2E_VSIX_PATH;
const expectedCandidateSha256 = (
	process.env[`${hostCandidatePrefix}_SHA256`] ?? process.env.AIDR_E2E_VSIX_SHA256
)?.toLowerCase();
if (!candidateInput) fail(`${hostCandidatePrefix}_PATH or AIDR_E2E_VSIX_PATH is required`);
if (!/^[0-9a-f]{64}$/.test(expectedCandidateSha256 ?? "")) {
	fail(`${hostCandidatePrefix}_SHA256 or AIDR_E2E_VSIX_SHA256 must be 64 hexadecimal characters`);
}
const candidatePath = path.resolve(candidateInput);
if (!existsSync(candidatePath) || !statSync(candidatePath).isFile()) {
	fail(`candidate VSIX is missing: ${candidatePath}`);
}
const candidateSha256 = sha256File(candidatePath);
if (candidateSha256 !== expectedCandidateSha256) {
	fail(`candidate VSIX SHA-256 mismatch: expected ${expectedCandidateSha256}, got ${candidateSha256}`);
}

let agentConfigBytes;
let agentConfigSha256;
const agentConfigPath = process.env.AIDR_E2E_AGENT_CONFIG_PATH;
if (agentConfigPath || process.env.AIDR_E2E_AGENT_CONFIG_SHA256) {
	try {
		if (!agentConfigPath || !path.isAbsolute(agentConfigPath)) throw new Error("absolute config path required");
		agentConfigBytes = readFileSync(agentConfigPath);
		agentConfigSha256 = createHash("sha256").update(agentConfigBytes).digest("hex");
		if (agentConfigSha256 !== process.env.AIDR_E2E_AGENT_CONFIG_SHA256?.toLowerCase()) throw new Error("SHA-256 mismatch");
		const config = JSON.parse(agentConfigBytes);
		const integrity = config.integrity;
		if (integrity?.enabled !== true || integrity?.verify_on_start !== true || !Array.isArray(integrity.public_keys_pem) || integrity.public_keys_pem.length === 0) {
			throw new Error("enabled startup integrity verification and independent public keys required");
		}
		for (const key of integrity.public_keys_pem) {
			if (typeof key !== "string" || createPublicKey(key).asymmetricKeyType !== "ed25519") throw new Error("Ed25519 artifact public key required");
		}
	} catch (error) { fail(`invalid inventory-bound agent fixture config: ${error.message}`); }
}

const executable = options.exe ?? process.env[config.envVar] ?? config.fallback();
if (!executable || !existsSync(executable)) {
	fail(`no ${config.label} executable: set ${config.envVar} or pass --exe (looked at ${executable || "nothing"})`, 2);
}
for (const required of [SUITE_ENTRY, WORKSPACE_FOLDER]) {
	if (!existsSync(required)) fail(`required artifact is missing: ${path.relative(ROOT, required)}`);
}

function sha256File(file) {
	return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function listFiles(root) {
	const files = [];
	const stack = [root];
	while (stack.length > 0) {
		const current = stack.pop();
		for (const entry of readdirSync(current, { withFileTypes: true })) {
			const full = path.join(current, entry.name);
			if (entry.isDirectory()) stack.push(full);
			else if (entry.isFile()) files.push(path.relative(root, full).replace(/\\/g, "/"));
		}
	}
	return files.sort();
}

function verifyInstalledCandidate(extensionDir) {
	const packageJson = JSON.parse(readFileSync(path.join(extensionDir, "package.json"), "utf8"));
	if (packageJson.publisher !== "SingularityRD" || packageJson.name !== config.packageName || packageJson.main !== config.main) {
		throw new Error(`installed extension identity does not match ${config.extensionId}`);
	}

	const distDir = path.join(extensionDir, "dist");
	const manifestPath = path.join(distDir, "aidr-artifact.manifest.json");
	const signaturePath = path.join(distDir, "aidr-artifact.manifest.sig");
	if (!existsSync(manifestPath) || !existsSync(signaturePath)) {
		throw new Error("installed candidate is missing its signed artifact manifest");
	}
	const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
	if (manifest.schema_version !== 1 || manifest.artifact_id !== "extension/dist" || !Array.isArray(manifest.files) || manifest.files.length === 0) {
		throw new Error("installed candidate artifact manifest is invalid");
	}

	const expectedFiles = new Set();
	for (const entry of manifest.files) {
		const relative = entry?.path;
		if (
			typeof relative !== "string" ||
			relative.length === 0 ||
			relative.includes("\\") ||
			relative.includes("\0") ||
			/^[A-Za-z]:/.test(relative) ||
			path.posix.isAbsolute(relative) ||
			path.posix.normalize(relative) !== relative ||
			relative === ".." ||
			relative.startsWith("../")
		) {
			throw new Error(`installed candidate artifact manifest has unsafe path: ${relative}`);
		}
		if (!/^[0-9a-f]{64}$/.test(entry.sha256 ?? "") || expectedFiles.has(relative)) {
			throw new Error(`installed candidate artifact manifest has invalid entry: ${relative}`);
		}
		expectedFiles.add(relative);
		const artifactFile = path.join(distDir, ...relative.split("/"));
		if (!existsSync(artifactFile) || !statSync(artifactFile).isFile()) {
			throw new Error(`installed candidate artifact is missing: ${relative}`);
		}
		const actual = sha256File(artifactFile);
		if (actual !== entry.sha256) throw new Error(`installed candidate artifact digest mismatch: ${relative}`);
	}
	for (const required of [
		"aidr-hook.cjs",
		"cursor_extension.js",
		"vscode_extension.js",
		"aidr-sbom.cdx.json",
		"aidr-sbom.cdx.json.sha256",
	]) {
		if (!expectedFiles.has(required)) throw new Error(`installed candidate artifact manifest is missing: ${required}`);
	}

	const actualFiles = listFiles(distDir).filter(
		(relative) => relative !== "aidr-artifact.manifest.json" && relative !== "aidr-artifact.manifest.sig",
	);
	if (actualFiles.length !== expectedFiles.size || actualFiles.some((relative) => !expectedFiles.has(relative))) {
		throw new Error("installed candidate dist does not match its artifact manifest file set");
	}
	return createHash("sha256").update(readFileSync(manifestPath)).digest("hex");
}

function spawnHost(executablePath, args, env) {
	const needsShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(executablePath);
	return spawnSync(executablePath, args, {
		env,
		encoding: "utf8",
		timeout: 600_000,
		maxBuffer: 32 * 1024 * 1024,
		shell: needsShell,
	});
}

function installCandidate(executablePath, userDataDir, extensionsDir, env) {
	const installArgs = [
			"--install-extension",
			candidatePath,
			`--user-data-dir=${userDataDir}`,
			`--extensions-dir=${extensionsDir}`,
			"--force",
		];
	let installEnv = env;
	if (process.platform === "win32" && /\.exe$/i.test(executablePath)) {
		// The vendor's .cmd launcher runs cli.js in Electron's Node mode. The
		// GUI executable alone ignores CLI installation and opens a window.
		const cliEntry = path.join(path.dirname(executablePath), "resources", "app", "out", "cli.js");
		if (!existsSync(cliEntry)) throw new Error("installed vendor CLI entry is missing");
		installArgs.unshift(cliEntry);
		installEnv = { ...env, ELECTRON_RUN_AS_NODE: "1", VSCODE_DEV: "" };
	}
	const install = spawnHost(executablePath, installArgs, installEnv);
	if (install.stdout) process.stdout.write(install.stdout);
	if (install.stderr) process.stderr.write(install.stderr);
	if (install.error || install.status !== 0) {
		throw new Error(`candidate VSIX installation failed: ${install.error?.message ?? `host exited ${install.status}`}`);
	}

	const installed = readdirSync(extensionsDir, { withFileTypes: true })
		.filter((entry) => entry.isDirectory())
		.map((entry) => path.join(extensionsDir, entry.name))
		.filter((directory) => {
			try {
				const manifest = JSON.parse(readFileSync(path.join(directory, "package.json"), "utf8"));
				return manifest.publisher === "SingularityRD" && manifest.name === config.packageName;
			} catch {
				return false;
			}
		});
	if (installed.length !== 1) {
		throw new Error(`fresh sandbox contains ${installed.length} matching installed extensions; expected exactly one`);
	}
	return installed[0];
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
	const errors = runError ? 1 : 0;
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
		`<testsuites name="aidr-ide-host-e2e" tests="${EXPECTED_CASES.length}" failures="${failures}" errors="${errors}" skipped="0">`,
		`  <testsuite name="${escapeXml(host)}" tests="${EXPECTED_CASES.length}" failures="${failures}" errors="${errors}" skipped="0">`,
		...cases,
		...(runError ? [`    <system-err>${escapeXml(runError)}</system-err>`] : []),
		"  </testsuite>",
		"</testsuites>",
		"",
	].join("\n");
	writeFileSync(file, body, "utf8");
	return failures;
}

const tempHome = mkdtempSync(path.join(tmpdir(), `aidr-${host}-runner-home-`));
const homeDir = tempHome;
const resultsFile = path.join(homeDir, "aidr-e2e-results.json");
const userDataDir = path.join(tempHome, "user-data");
const extensionsDir = path.join(tempHome, "extensions");
let runError;
let fatalError;

try {
	if (agentConfigBytes) {
		mkdirSync(path.join(homeDir, ".singularity-aidr"), { recursive: true });
		writeFileSync(path.join(homeDir, ".singularity-aidr", "config.json"), agentConfigBytes, { mode: 0o600 });
	}
	const sandboxEnv = {
		...process.env,
		HOME: homeDir,
		USERPROFILE: homeDir,
		XDG_CONFIG_HOME: path.join(homeDir, ".config"),
	};
	// Parent IDE/terminal state must not redirect CLI requests to its existing
	// instance or make the actual extension-test launch run in Node/dev mode.
	const inheritedIdeEnvKeys = new Set(["VSCODE_IPC_HOOK_CLI", "VSCODE_PID", "ELECTRON_RUN_AS_NODE", "VSCODE_DEV", "VSCODE_CWD"]);
	for (const key of Object.keys(sandboxEnv)) if (inheritedIdeEnvKeys.has(key.toUpperCase())) delete sandboxEnv[key];
	const developmentPath = installCandidate(executable, userDataDir, extensionsDir, sandboxEnv);
	const artifactManifestSha256 = verifyInstalledCandidate(developmentPath);
	const hookRunnerPath = path.join(developmentPath, "dist", "aidr-hook.cjs");
	console.log(`[ide-e2e] ${config.label}: installed candidate VSIX SHA-256 ${candidateSha256}`);
	console.log(`[ide-e2e] ${config.label}: verified artifact manifest SHA-256 ${artifactManifestSha256}`);

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
		...sandboxEnv,
		AIDR_E2E_HOST: host,
		AIDR_E2E_EXTENSION_ID: config.extensionId,
		AIDR_E2E_SCOPE_SETTING_KEY: config.scopeSettingKey,
		AIDR_E2E_MANAGED_MARKER: config.managedMarker,
		AIDR_E2E_HOOK_MODE: config.hookMode,
		AIDR_E2E_HOOKS_RELATIVE_PATH: config.hooksRelativePath,
		AIDR_E2E_HOOK_RUNNER_PATH: hookRunnerPath,
		AIDR_E2E_RESULTS_FILE: resultsFile,
	};

	console.log(`[ide-e2e] ${config.label}: launching ${executable}`);
	const run = spawnHost(executable, args, env);
	if (run.stdout) process.stdout.write(run.stdout);
	if (run.stderr) process.stderr.write(run.stderr);
	if (run.error || run.status !== 0) runError = run.error?.message ?? `host exited ${run.status}${run.signal ? ` (${run.signal})` : ""}`;
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
				workspace: WORKSPACE_FOLDER,
				candidateVsix: candidatePath,
				candidateSha256,
				artifactManifestSha256,
				agentConfigSha256: agentConfigSha256 ?? null,
				expected: EXPECTED_CASES.length,
				passed,
				failures,
				errors: runError ? 1 : 0,
				hostExitCode: run.status,
				hostSignal: run.signal,
				runError,
				cases: [...outcomes.values()],
			}, null, 2)}\n`,
			"utf8",
		);
	}

	// A non-zero exit is the signal the gate reads. It is non-zero whenever any
	// case is missing or failing, or the native host failed. A host that exits 0
	// without running the cases has proven nothing either.
	process.exitCode = failures === 0 && !runError ? 0 : 1;
} catch (error) {
	fatalError = error instanceof Error ? error.message : String(error);
} finally {
	rmSync(tempHome, { recursive: true, force: true });
}
if (fatalError) fail(fatalError);
