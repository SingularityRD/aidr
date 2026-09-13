#!/usr/bin/env node
/**
 * Native-host acceptance recorder. A hook subprocess verdict is not a host
 * enforcement result: every attack case needs an observed tool attempt, an
 * observed connector invocation, and an independent side-effect marker.
 *
 * Without a scenario file this command inventories installed hosts only. It
 * never converts a missing runtime, model credential, or skipped suite to PASS.
 */
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { release as osRelease, tmpdir, version as osVersion } from "node:os";
import { delimiter, dirname, join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const HOSTS = [
	{ id: "claude", command: "claude", ga: true },
	{ id: "cursor", command: "cursor", env: "AIDR_CURSOR_PATH", ga: true },
	{ id: "vscode", command: "code", env: "AIDR_VSCODE_PATH", ga: true },
	{ id: "opencode", command: "opencode", env: "OPENCODE_E2E_BIN", ga: true },
	{ id: "openclaw", command: "openclaw", ga: true },
	{ id: "codex", command: "codex", ga: false },
	{ id: "sdk", command: null, ga: false },
];
const CASES = ["denied_side_effect", "benign_allow", "disabled_hook", "crash", "timeout", "offline", "restart"];
const PROTECTED = new Set(["denied_side_effect", "offline", "restart"]);
const FAULTS = new Set(["disabled_hook", "crash", "timeout"]);
const CONDITIONS = new Set(["disabled_hook", "crash", "timeout", "offline", "restart"]);
const SHA256 = /^[a-f0-9]{64}$/u;

function digest(data) { return createHash("sha256").update(data).digest("hex"); }
function bounded(value, limit = 200) { return String(value ?? "").trim().slice(0, limit); }
function interpolate(value, vars) {
	return value.replaceAll(/\{(host_binary|workspace|home|sentinel|receipt|case_nonce)\}/g, (whole, key) => vars[key] ?? whole);
}
function withinWorkspace(path, workspace) {
	const resolved = resolve(path);
	if (!resolved.startsWith(`${workspace}${sep}`)) throw new Error("Scenario path escapes disposable workspace");
	return resolved;
}
function runBinary(binary, args, options = {}) {
	const defaults = { encoding: "utf8", timeout: options.timeout ?? 10_000, maxBuffer: 2_000_000, windowsHide: true,
		cwd: options.cwd, env: options.env, input: options.input, stdio: ["pipe", "pipe", "pipe"] };
	if (process.platform === "win32" && /\.ps1$/i.test(binary)) {
		return spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", binary, ...args], defaults);
	}
	if (process.platform === "win32" && /\.cmd$/i.test(binary)) {
		// cmd shims require a shell on Windows. All arguments are validated below.
		if (args.some((arg) => /[\r\n&|<>^%!"]/u.test(arg))) throw new Error("Unsafe argument for Windows command shim");
		return spawnSync(binary, args, { ...defaults, shell: true });
	}
	return spawnSync(binary, args, defaults);
}
function pathCandidates(command) {
	const suffixes = process.platform === "win32" ? [".exe", ".ps1", ".cmd", ""] : [""];
	return (process.env.PATH ?? "").split(delimiter).flatMap((folder) =>
		suffixes.map((suffix) => join(folder.replace(/^"|"$/gu, ""), `${command}${suffix}`)).filter((candidate) => existsSync(candidate)));
}
function binaryFor(host, config) {
	const explicit = config?.binary || (host.env ? process.env[host.env] : undefined);
	if (explicit) {
		const file = resolve(explicit);
		return existsSync(file) ? file : null;
	}
	return pathCandidates(host.command).find((path) => existsSync(path)) ?? null;
}
function probe(host, config) {
	if (host.id === "sdk") return { id: host.id, ga: false, status: "REQUIRES_EMBEDDED_APPLICATION_ACCEPTANCE", binary: null, version: null, cases: [] };
	const binary = binaryFor(host, config);
	if (!binary) return { id: host.id, ga: host.ga, status: "HOST_UNAVAILABLE", binary: null, version: null, cases: [] };
	const versionArgs = config?.version_args ?? ["--version"];
	if (!Array.isArray(versionArgs) || !versionArgs.every((arg) => typeof arg === "string" && arg.length < 100)) throw new Error(`${host.id}: invalid version_args`);
	const result = runBinary(binary, versionArgs, { timeout: 30_000 });
	const version = bounded(result.stdout || result.stderr);
	return { id: host.id, ga: host.ga, status: result.status === 0 && !result.error && version ? "VERSION_PROBED" : "VERSION_PROBE_FAILED",
		binary, launcher_sha256: digest(readFileSync(binary)), version: version || null, cases: [] };
}
function observation(spec, result, vars) {
	if (!spec || typeof spec !== "object" || !["stdout", "stderr", "file"].includes(spec.source) ||
		typeof spec.contains !== "string" || !spec.contains || spec.contains.length > 200) throw new Error("Invalid attempt/hook observation");
	let content;
	if (spec.source === "file") {
		if (typeof spec.path !== "string") throw new Error("File observation requires path");
		const path = withinWorkspace(interpolate(spec.path, vars), vars.workspace);
		content = existsSync(path) ? readFileSync(path, "utf8") : "";
	} else content = result[spec.source] ?? "";
	return { seen: content.includes(interpolate(spec.contains, vars)), sha256: digest(content) };
}
function runCase(host, spec, index) {
	if (!CASES.includes(spec.id)) throw new Error(`${host.id}: unsupported case ${spec.id}`);
	if (spec.attack_id !== undefined && (typeof spec.attack_id !== "string" || !/^[a-z0-9][a-z0-9_.-]{0,100}$/u.test(spec.attack_id))) {
		throw new Error(`${host.id}/${spec.id}: invalid attack_id`);
	}
	if (!Array.isArray(spec.argv) || spec.argv[0] !== "{host_binary}" || !spec.argv.every((arg) => typeof arg === "string" && arg.length < 20_000)) {
		throw new Error(`${host.id}/${spec.id}: argv must start with {host_binary}`);
	}
	if (typeof spec.attempt !== "object" || typeof spec.hook !== "object") throw new Error(`${host.id}/${spec.id}: attempt and hook observations are mandatory`);
	if (spec.timeout_ms !== undefined && (!Number.isInteger(spec.timeout_ms) || spec.timeout_ms < 1000 || spec.timeout_ms > 180_000)) throw new Error("Invalid timeout_ms");
	const workspace = mkdtempSync(join(tmpdir(), `aidr-native-${host.id}-${index}-`));
	const vars = { host_binary: host.binary, workspace, home: join(workspace, "home"), sentinel: join(workspace, "side-effect.marker"), receipt: join(workspace, "hook.receipt"), case_nonce: randomUUID() };
	try {
		mkdirSync(vars.home, { recursive: true });
		const evidencePaths = new Set([vars.sentinel, vars.receipt]);
		for (const observed of [spec.attempt, spec.hook, spec.condition, spec.boundary].filter(Boolean)) if (observed.source === "file") {
			if (typeof observed.path !== "string") throw new Error("File observation requires path");
			evidencePaths.add(withinWorkspace(interpolate(observed.path, vars), workspace));
		}
		if (spec.files !== undefined) {
			if (!Array.isArray(spec.files) || spec.files.length > 20) throw new Error("Invalid scenario files");
			for (const file of spec.files) {
				if (typeof file?.path !== "string" || typeof file.content !== "string" || file.content.length > 20_000) throw new Error("Invalid scenario file");
				const path = withinWorkspace(interpolate(file.path, vars), workspace);
				if (evidencePaths.has(path)) throw new Error("Fixture cannot pre-create side-effect or observation evidence");
				mkdirSync(dirname(path), { recursive: true });
				writeFileSync(path, interpolate(file.content, vars), { flag: "wx" });
			}
		}
		const args = spec.argv.slice(1).map((arg) => interpolate(arg, vars));
		const home = spec.inherit_host_profile === true ? process.env.USERPROFILE || process.env.HOME : vars.home;
		const env = { ...process.env, HOME: home, USERPROFILE: home, AIDR_NATIVE_TEST_WORKSPACE: workspace,
			AIDR_NATIVE_TEST_SENTINEL: vars.sentinel, AIDR_NATIVE_TEST_RECEIPT: vars.receipt,
			AIDR_NATIVE_TEST_CASE_NONCE: vars.case_nonce };
		if (spec.env !== undefined) {
			if (!spec.env || typeof spec.env !== "object" || Array.isArray(spec.env)) throw new Error("Invalid scenario env");
			for (const [key, value] of Object.entries(spec.env)) {
				if (!/^[A-Z][A-Z0-9_]*$/u.test(key) || /^(HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PATH|NODE_OPTIONS)$/u.test(key) || key.startsWith("AIDR_NATIVE_TEST_") ||
					typeof value !== "string" || value.length > 2000) throw new Error("Invalid scenario environment override");
				env[key] = interpolate(value, vars);
			}
		}
		const started = performance.now();
		const result = runBinary(host.binary, args, { timeout: spec.timeout_ms ?? 90_000, cwd: workspace, env });
		const attempt = observation(spec.attempt, result, vars);
		const hook = observation(spec.hook, result, vars);
		const condition = spec.condition ? observation(spec.condition, result, vars) : null;
		const boundary = spec.boundary ? observation(spec.boundary, result, vars) : null;
		const sideEffect = existsSync(vars.sentinel);
		const timedOut = result.error?.code === "ETIMEDOUT";
		const requiredSideEffect = spec.id === "benign_allow";
		const diagnostic = FAULTS.has(spec.id);
		const leaked = sideEffect && (diagnostic || PROTECTED.has(spec.id));
		let status;
		if (diagnostic && sideEffect) status = "FAIL_OPEN_OBSERVED";
		else if (PROTECTED.has(spec.id) && sideEffect) status = "DENIED_SIDE_EFFECT_OCCURRED";
		else if (!attempt.seen) status = "ATTEMPT_UNPROVEN";
		else if (CONDITIONS.has(spec.id) && !condition?.seen) status = "CONDITION_UNPROVEN";
		else if (diagnostic) status = boundary?.seen ? "BOUNDARY_CLAIM_RECORDED" : "ENFORCEMENT_UNPROVEN";
		else if (!hook.seen) status = "HOOK_UNPROVEN";
		else if (sideEffect !== requiredSideEffect) status = requiredSideEffect ? "BENIGN_SIDE_EFFECT_MISSING" : "DENIED_SIDE_EFFECT_OCCURRED";
		else status = "PASS";
		if (timedOut && !leaked) status = "HOST_TIMED_OUT";
		if (result.error && !timedOut && !leaked) status = "HOST_LAUNCH_FAILED";
		if (spec.expected_exit_code !== undefined && result.status !== spec.expected_exit_code && !leaked) status = "EXIT_MISMATCH";
		const observedSpecs = [spec.attempt, spec.hook, ...(CONDITIONS.has(spec.id) ? [spec.condition] : []), ...(diagnostic ? [spec.boundary] : [])];
		const tracePaths = observedSpecs.map((item) => item?.source === "file" && typeof item.path === "string" ? withinWorkspace(interpolate(item.path, vars), workspace) : null);
		const correlatedFiles = observedSpecs.every((item) => item?.source === "file" && item.contains?.includes("{case_nonce}")) &&
			tracePaths.every(Boolean) && new Set(tracePaths).size === tracePaths.length;
		return { id: spec.id, attack_id: spec.attack_id ?? null, status, exit_code: result.status, timed_out: timedOut, duration_ms: Math.round(performance.now() - started),
			attempt_observed: attempt.seen, hook_observed: hook.seen, condition_observed: condition?.seen ?? null,
			independent_boundary_observed: boundary?.seen ?? null, side_effect_observed: sideEffect,
			correlated_file_observations: correlatedFiles,
			attempt_source: spec.attempt.source, hook_source: spec.hook.source,
			stdout_sha256: digest(result.stdout ?? ""), stderr_sha256: digest(result.stderr ?? ""),
			attempt_sha256: attempt.sha256, hook_sha256: hook.sha256,
			condition_sha256: condition?.sha256 ?? null, independent_boundary_sha256: boundary?.sha256 ?? null };
	} finally { rmSync(workspace, { recursive: true, force: true }); }
}
function acceptanceBlockers(host, config) {
	const record = config?.acceptance;
	if (!record || typeof record !== "object" || Array.isArray(record)) return ["MISSING_NAMED_ACCEPTANCE_RECORD"];
	const blockers = [];
	for (const [field, actual] of Object.entries({ os_platform: process.platform, os_release: osRelease(), architecture: process.arch,
		host_version: host.version, launcher_sha256: host.launcher_sha256 })) {
		if (record[field] !== actual) blockers.push(`UNPINNED_OR_MISMATCHED_${field.toUpperCase()}`);
	}
	for (const field of ["candidate_sha256", "policy_sha256", "install_evidence_sha256", "uninstall_evidence_sha256"]) {
		if (typeof record[field] !== "string" || !SHA256.test(record[field])) blockers.push(`MISSING_${field.toUpperCase()}`);
	}
	for (const field of ["qa_owner", "endpoint_owner", "support_owner"]) {
		if (typeof record[field] !== "string" || record[field].trim().length < 3) blockers.push(`MISSING_${field.toUpperCase()}`);
	}
	if (!Array.isArray(record.unobserved_actions) || !record.unobserved_actions.every((entry) => typeof entry === "string" && entry.trim())) {
		blockers.push("MISSING_UNOBSERVED_ACTIONS_INVENTORY");
	} else if (record.unobserved_actions.length > 0) blockers.push("UNOBSERVED_ACTIONS_REMAIN");
	if (!Array.isArray(record.required_attack_ids) || record.required_attack_ids.length === 0 ||
		!record.required_attack_ids.every((id) => typeof id === "string" && /^[a-z0-9][a-z0-9_.-]{0,100}$/u.test(id)) ||
		new Set(record.required_attack_ids).size !== record.required_attack_ids.length) {
		blockers.push("MISSING_REQUIRED_ATTACK_IDS");
	} else for (const attackId of record.required_attack_ids) {
		if (!host.cases.some((entry) => entry.id === "denied_side_effect" && entry.attack_id === attackId && entry.status === "PASS")) {
			blockers.push(`DENIED_ATTACK_UNPROVEN:${attackId}`);
		}
		if (!host.cases.some((entry) => entry.id === "benign_allow" && entry.attack_id === attackId && entry.status === "PASS")) {
			blockers.push(`BENIGN_TWIN_UNPROVEN:${attackId}`);
		}
	}
	return blockers;
}
function parseCli(argv) {
	const { values } = parseArgs({ args: argv, options: {
		"scenario-file": { type: "string" }, output: { type: "string" }, "probe-only": { type: "boolean" },
	}, strict: true });
	return values;
}
function main(argv) {
	const options = parseCli(argv);
	const scenarioPath = options["scenario-file"] ? resolve(options["scenario-file"]) : null;
	const spec = scenarioPath ? JSON.parse(readFileSync(scenarioPath, "utf8")) : { schema_version: 1, hosts: {} };
	if (spec.schema_version !== 1 || !spec.hosts || typeof spec.hosts !== "object" || Array.isArray(spec.hosts)) throw new Error("Invalid native scenario manifest");
	for (const id of Object.keys(spec.hosts)) if (!HOSTS.some((host) => host.id === id)) throw new Error(`Unknown host: ${id}`);
	const hosts = HOSTS.map((definition) => {
		const host = probe(definition, spec.hosts[definition.id]);
		if (host.status === "VERSION_PROBED" && !options["probe-only"]) {
			const cases = spec.hosts[host.id]?.cases ?? [];
			if (!Array.isArray(cases) || new Set(cases.map((entry) => `${entry?.id}:${entry?.attack_id ?? ""}`)).size !== cases.length) throw new Error(`${host.id}: duplicate or invalid cases`);
			host.cases = cases.map((entry, index) => runCase(host, entry, index));
			host.acceptance_blockers = acceptanceBlockers(host, spec.hosts[host.id]);
			for (const entry of host.cases) if (!entry.correlated_file_observations) host.acceptance_blockers.push(`${entry.id}:CORRELATED_FILE_TRACES_MISSING`);
			host.status = CASES.every((id) => host.cases.some((entry) => entry.id === id)) &&
				host.cases.every((entry) => ["PASS", "BOUNDARY_CLAIM_RECORDED"].includes(entry.status)) &&
				host.acceptance_blockers.length === 0 ? "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN" : "HOST_ACCEPTANCE_OPEN";
		}
		return host;
	});
	const report = { schema_version: 1, kind: "aidr_native_host_matrix_v6", measured_at: new Date().toISOString(),
		platform: process.platform, os_release: osRelease(), os_version: osVersion(), architecture: process.arch, node_version: process.version,
		scenario_manifest_sha256: scenarioPath ? digest(readFileSync(scenarioPath)) : null,
		gate: "NO_GO",
		local_scenario_coverage: hosts.filter((host) => host.ga).every((host) => host.status === "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN") ? "COMPLETE_REVIEW_OPEN" : "INCOMPLETE",
		hosts,
		limitations: ["A version probe does not prove hook registration, tool interception, or prevented side effects",
			"SDK acceptance requires a named embedding application and cannot be inferred from an in-process unit test",
			"File observations and manifest owner names are operator supplied; independent collection and named acceptance require external review",
			"One local OS run is not a supported host and operating-system version matrix"] };
	if (options.output) {
		const output = resolve(options.output);
		if (scenarioPath && output === scenarioPath) throw new Error("Refusing to overwrite scenario manifest");
		writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
	}
	console.log(JSON.stringify(report, null, 2));
	if (!options["probe-only"] && report.gate !== "GO") process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try { main(process.argv.slice(2)); }
	catch (error) { console.error(`Native host matrix error: ${error.message}`); process.exitCode = 2; }
}

export { main };
