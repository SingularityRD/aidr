#!/usr/bin/env node
/**
 * Native-host acceptance recorder. A hook subprocess verdict is not a host
 * enforcement result: every attack case needs an observed tool attempt, an
 * observed connector invocation, and an independent side-effect marker.
 *
 * Status vocabulary, most specific first:
 *
 *   SCENARIO_MANIFEST_MISSING             no scenario manifest was supplied and
 *                                        the committed default is absent, so the
 *                                        per-host matrix could not be exercised
 *   HOST_UNAVAILABLE                      a manifest is available but no
 *                                        advertised host binary exists here
 *   VERSION_PROBED                        inventory only (--probe-only): versions
 *                                        were read, nothing was exercised
 *   HOST_ACCEPTANCE_OPEN                  scenarios ran or failed and/or the named
 *                                        acceptance record is incomplete
 *   LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN  every GA host passed every local case and
 *                                        still needs named external review
 *   NO_GO                                 the gate decision; it is never GO while a
 *                                        named accepted-host record is missing
 *
 * `--validate-only` validates a scenario manifest structure, reports every
 * violation with a stable machine-readable code, and exits 0 for a structurally
 * valid template. Structure validation is not host acceptance and never prints
 * PASS; a template is never acceptance evidence.
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

const HERE = dirname(fileURLToPath(import.meta.url));
/** The manifest this gate expects when no --scenario-file is supplied. */
const DEFAULT_SCENARIO_PATH = resolve(HERE, "..", "deploy", "native", "scenarios", "native-host-scenarios.json");

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

/** Every status a report or a host record may carry. */
const GATE_STATUSES = ["SCENARIO_MANIFEST_MISSING", "HOST_UNAVAILABLE", "VERSION_PROBED", "HOST_ACCEPTANCE_OPEN",
	"LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN", "NO_GO"];
const GATE_REASONS = {
	SCENARIO_MANIFEST_MISSING: "No scenario manifest was supplied and the committed default is absent; the per-host matrix could not be exercised.",
	HOST_UNAVAILABLE: "No advertised host binary is installed on this machine, so no host enforcement was observed.",
	VERSION_PROBED: "Inventory only: a version probe does not prove hook registration, tool interception, or a prevented side effect.",
	HOST_ACCEPTANCE_OPEN: "Host scenarios or the named acceptance record are still incomplete.",
	LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN: "Local scenarios completed; independent trace collection and named acceptance still require external review.",
};

/**
 * A blocker code for a manifest that is not acceptance evidence: either it
 * declares itself the committed template, or it still carries that template's
 * `REPLACE_WITH_*` placeholders after the markers were deleted. Both shapes are
 * the same defect and are refused with this one code.
 */
export const SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE = "SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE";

/**
 * True when a validated manifest still carries `REPLACE_WITH_*` values. Inside a
 * template those findings have `placeholder` severity and outside one they are
 * `error`s, so the count alone cannot answer this: the code can.
 */
export function carriesTemplatePlaceholders(validation) {
	return (validation?.failures ?? []).some((failure) => failure.code === "PLACEHOLDER_VALUE_UNREPLACED");
}

/** A value that must come from a real host run. Never a real digest, version or name. */
const PLACEHOLDER = /REPLACE_WITH_[A-Z0-9_]+/u;
const OBSERVATION_SOURCES = ["stdout", "stderr", "file"];
const ACCEPTANCE_PINNED_FIELDS = ["os_platform", "os_release", "architecture", "host_version"];
const ACCEPTANCE_SHA256_FIELDS = ["launcher_sha256", "candidate_sha256", "policy_sha256", "install_evidence_sha256", "uninstall_evidence_sha256"];
const ACCEPTANCE_OWNER_FIELDS = ["qa_owner", "endpoint_owner", "support_owner"];
const ACCEPTANCE_ARRAY_FIELDS = ["unobserved_actions", "required_attack_ids"];
const ATTACK_ID = /^[a-z0-9][a-z0-9_.-]{0,100}$/u;
const ENV_KEY = /^[A-Z][A-Z0-9_]*$/u;
const RESERVED_ENV_KEYS = /^(HOME|USERPROFILE|APPDATA|LOCALAPPDATA|PATH|NODE_OPTIONS)$/u;

function digest(data) { return createHash("sha256").update(data).digest("hex"); }
function bounded(value, limit = 200) { return String(value ?? "").trim().slice(0, limit); }
function isPlaceholder(value) { return typeof value === "string" && PLACEHOLDER.test(value); }
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
	const launcher_sha256 = digest(readFileSync(binary));
	if (!Array.isArray(versionArgs) || !versionArgs.every((arg) => typeof arg === "string" && arg.length < 100)) {
		return { id: host.id, ga: host.ga, status: "VERSION_PROBE_FAILED", binary, launcher_sha256, version: null, cases: [],
			probe_error: "invalid version_args" };
	}
	let result;
	try {
		result = runBinary(binary, versionArgs, { timeout: 30_000 });
	} catch (error) {
		return { id: host.id, ga: host.ga, status: "VERSION_PROBE_FAILED", binary, launcher_sha256, version: null, cases: [],
			probe_error: error instanceof Error ? error.message : String(error) };
	}
	const version = bounded(result.stdout || result.stderr);
	return { id: host.id, ga: host.ga, status: result.status === 0 && !result.error && version ? "VERSION_PROBED" : "VERSION_PROBE_FAILED",
		binary, launcher_sha256, version: version || null, cases: [], ...(result.error ? { probe_error: String(result.error.message ?? result.error) } : {}) };
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
	if (spec.attack_id !== undefined && (typeof spec.attack_id !== "string" || !ATTACK_ID.test(spec.attack_id))) {
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
				if (!ENV_KEY.test(key) || RESERVED_ENV_KEYS.test(key) || key.startsWith("AIDR_NATIVE_TEST_") ||
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
		!record.required_attack_ids.every((id) => typeof id === "string" && ATTACK_ID.test(id)) ||
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

/**
 * Structural validation of a scenario manifest. It never throws, so a caller
 * can list every violation at once, and every finding carries a stable
 * machine-readable `code`.
 *
 * A value that must come from a real host run is written as the literal
 * `REPLACE_WITH_*` placeholder. Inside a manifest that declares itself a
 * template those values are reported with severity `placeholder` (a template is
 * expected to be unfilled). Anywhere else the same value is an `error`, because
 * an accepted manifest may not ship an invented or unfilled value.
 */
export function validateScenarioManifest(spec) {
	const failures = [];
	const template = spec?.template === true || spec?.kind === "aidr-native-host-scenario-template";
	const push = (code, extra = {}) => {
		failures.push({ code, severity: extra.placeholder === true && template ? "placeholder" : "error",
			host: extra.host ?? null, case_id: extra.case_id ?? null, case_index: extra.case_index ?? null,
			field: extra.field ?? null, path: extra.path ?? null, detail: extra.detail ?? null });
	};
	const checkText = (value, code, extra) => {
		if (isPlaceholder(value)) { push("PLACEHOLDER_VALUE_UNREPLACED", { ...extra, placeholder: true, detail: value }); return true; }
		if (typeof value !== "string" || value.trim().length === 0) { push(code, extra); return true; }
		return false;
	};
	const checkObservation = (value, prefix, extra) => {
		if (!value || typeof value !== "object" || Array.isArray(value)) { push(`${prefix}_NOT_OBJECT`, extra); return; }
		if (typeof value.source !== "string" || !OBSERVATION_SOURCES.includes(value.source)) { push(`${prefix}_SOURCE_INVALID`, { ...extra, detail: String(value.source) }); return; }
		if (isPlaceholder(value.contains)) push("PLACEHOLDER_VALUE_UNREPLACED", { ...extra, field: `${extra.field}.contains`, placeholder: true, detail: value.contains });
		else if (typeof value.contains !== "string" || value.contains.length === 0 || value.contains.length > 200) push(`${prefix}_CONTAINS_INVALID`, { ...extra, field: `${extra.field}.contains` });
		if (value.source === "file") checkText(value.path, `${prefix}_PATH_MISSING`, { ...extra, field: `${extra.field}.path` });
	};
	const checkAcceptance = (host, acceptance) => {
		if (acceptance === undefined || acceptance === null) { push("ACCEPTANCE_BLOCK_MISSING", { host, field: "acceptance" }); return; }
		if (typeof acceptance !== "object" || Array.isArray(acceptance)) { push("ACCEPTANCE_BLOCK_NOT_OBJECT", { host, field: "acceptance" }); return; }
		for (const field of [...ACCEPTANCE_PINNED_FIELDS, ...ACCEPTANCE_SHA256_FIELDS, ...ACCEPTANCE_OWNER_FIELDS]) {
			const path = `hosts.${host}.acceptance.${field}`;
			if (!Object.hasOwn(acceptance, field)) { push("ACCEPTANCE_FIELD_MISSING", { host, field, path }); continue; }
			const value = acceptance[field];
			if (isPlaceholder(value)) { push("PLACEHOLDER_VALUE_UNREPLACED", { host, field, path, placeholder: true, detail: value }); continue; }
			if (typeof value !== "string" || value.trim().length === 0) { push("ACCEPTANCE_FIELD_INVALID", { host, field, path, detail: String(value) }); continue; }
			if (ACCEPTANCE_SHA256_FIELDS.includes(field) && !SHA256.test(value)) { push("ACCEPTANCE_SHA256_INVALID", { host, field, path, detail: value }); continue; }
			if (ACCEPTANCE_OWNER_FIELDS.includes(field) && value.trim().length < 3) push("ACCEPTANCE_OWNER_INVALID", { host, field, path, detail: value });
		}
		for (const field of ACCEPTANCE_ARRAY_FIELDS) {
			const path = `hosts.${host}.acceptance.${field}`;
			if (!Object.hasOwn(acceptance, field)) { push("ACCEPTANCE_FIELD_MISSING", { host, field, path }); continue; }
			const value = acceptance[field];
			// An empty `unobserved_actions` list is the goal state; an empty
			// `required_attack_ids` list proves nothing was ever attacked.
			if (!Array.isArray(value) || (field === "required_attack_ids" && value.length === 0)) {
				push("ACCEPTANCE_ARRAY_INVALID", { host, field, path, detail: String(value) });
				continue;
			}
			const seenEntries = new Set();
			value.forEach((entry, index) => {
				const entryPath = `${path}[${index}]`;
				if (isPlaceholder(entry)) { push("PLACEHOLDER_VALUE_UNREPLACED", { host, field, path: entryPath, placeholder: true, detail: entry }); return; }
				if (typeof entry !== "string" || entry.trim().length === 0) { push("ACCEPTANCE_ARRAY_INVALID", { host, field, path: entryPath, detail: String(entry) }); return; }
				if (field === "required_attack_ids" && !ATTACK_ID.test(entry)) { push("ACCEPTANCE_ATTACK_ID_INVALID", { host, field, path: entryPath, detail: entry }); return; }
				if (seenEntries.has(entry)) push("ACCEPTANCE_ARRAY_DUPLICATE", { host, field, path: entryPath, detail: entry });
				seenEntries.add(entry);
			});
		}
	};
	const checkCases = (host, cases) => {
		if (cases === undefined || cases === null) { push("HOST_CASES_MISSING", { host, field: "cases", path: `hosts.${host}.cases` }); return; }
		if (!Array.isArray(cases)) { push("HOST_CASES_NOT_ARRAY", { host, field: "cases", path: `hosts.${host}.cases` }); return; }
		if (cases.length === 0) push("HOST_CASES_MISSING", { host, field: "cases", path: `hosts.${host}.cases` });
		const seenPairs = new Set();
		cases.forEach((entry, index) => {
			const path = `hosts.${host}.cases[${index}]`;
			if (!entry || typeof entry !== "object" || Array.isArray(entry)) { push("CASE_NOT_OBJECT", { host, case_index: index, path }); return; }
			const caseId = typeof entry.id === "string" ? entry.id : null;
			const scope = { host, case_id: caseId, case_index: index };
			if (caseId === null) push("CASE_ID_MISSING", { ...scope, field: "id", path: `${path}.id` });
			else if (!CASES.includes(caseId)) push("UNKNOWN_CASE_ID", { ...scope, field: "id", path: `${path}.id`, detail: caseId });
			if (entry.attack_id !== undefined) {
				if (isPlaceholder(entry.attack_id)) {
					push("PLACEHOLDER_VALUE_UNREPLACED", { ...scope, field: "attack_id", path: `${path}.attack_id`, placeholder: true, detail: entry.attack_id });
				} else if (typeof entry.attack_id !== "string" || !ATTACK_ID.test(entry.attack_id)) {
					push("CASE_ATTACK_ID_INVALID", { ...scope, field: "attack_id", path: `${path}.attack_id`, detail: String(entry.attack_id) });
				}
			}
			const pair = `${caseId ?? ""}:${entry.attack_id ?? ""}`;
			if (caseId !== null && seenPairs.has(pair)) push("DUPLICATE_CASE_ID_ATTACK_PAIR", { ...scope, field: "attack_id", path: `${path}.attack_id`, detail: pair });
			seenPairs.add(pair);
			if (!Array.isArray(entry.argv)) push("CASE_ARGV_INVALID", { ...scope, field: "argv", path: `${path}.argv` });
			else if (entry.argv[0] !== "{host_binary}") push("CASE_ARGV_MUST_START_WITH_HOST_BINARY", { ...scope, field: "argv", path: `${path}.argv`, detail: String(entry.argv[0] ?? null) });
			else entry.argv.forEach((arg, argIndex) => {
				const argPath = `${path}.argv[${argIndex}]`;
				if (isPlaceholder(arg)) { push("PLACEHOLDER_VALUE_UNREPLACED", { ...scope, field: `argv[${argIndex}]`, path: argPath, placeholder: true, detail: arg }); return; }
				if (typeof arg !== "string" || arg.length === 0 || arg.length >= 20_000) push("CASE_ARGV_ENTRY_INVALID", { ...scope, field: `argv[${argIndex}]`, path: argPath, detail: String(arg) });
			});
			if (entry.attempt === undefined || entry.attempt === null) push("ATTEMPT_OBSERVATION_MISSING", { ...scope, field: "attempt", path: `${path}.attempt` });
			else checkObservation(entry.attempt, "ATTEMPT_OBSERVATION", { ...scope, field: "attempt", path: `${path}.attempt` });
			if (entry.hook === undefined || entry.hook === null) push("HOOK_OBSERVATION_MISSING", { ...scope, field: "hook", path: `${path}.hook` });
			else checkObservation(entry.hook, "HOOK_OBSERVATION", { ...scope, field: "hook", path: `${path}.hook` });
			for (const [field, prefix] of [["condition", "CONDITION_OBSERVATION"], ["boundary", "BOUNDARY_OBSERVATION"]]) {
				if (entry[field] === undefined || entry[field] === null) continue;
				checkObservation(entry[field], prefix, { ...scope, field, path: `${path}.${field}` });
			}
			for (const [field, code] of [["timeout_ms", "CASE_TIMEOUT_MS_INVALID"], ["expected_exit_code", "CASE_EXPECTED_EXIT_CODE_INVALID"]]) {
				if (entry[field] === undefined) continue;
				if (isPlaceholder(entry[field])) { push("PLACEHOLDER_VALUE_UNREPLACED", { ...scope, field, path: `${path}.${field}`, placeholder: true, detail: entry[field] }); continue; }
				const bounds = field === "timeout_ms" ? entry[field] >= 1000 && entry[field] <= 180_000 : true;
				if (!Number.isInteger(entry[field]) || !bounds) push(code, { ...scope, field, path: `${path}.${field}`, detail: String(entry[field]) });
			}
			if (entry.files !== undefined) {
				if (!Array.isArray(entry.files) || entry.files.length > 20) { push("CASE_FILES_INVALID", { ...scope, field: "files", path: `${path}.files` }); }
				else entry.files.forEach((file, fileIndex) => {
					const filePath = `${path}.files[${fileIndex}]`;
					if (!file || typeof file !== "object" || Array.isArray(file)) { push("CASE_FILE_INVALID", { ...scope, field: `files[${fileIndex}]`, path: filePath }); return; }
					checkText(file.path, "CASE_FILE_PATH_INVALID", { ...scope, field: `files[${fileIndex}].path`, path: `${filePath}.path` });
					if (isPlaceholder(file.content)) push("PLACEHOLDER_VALUE_UNREPLACED", { ...scope, field: `files[${fileIndex}].content`, path: `${filePath}.content`, placeholder: true, detail: file.content });
					else if (typeof file.content !== "string" || file.content.length > 20_000) push("CASE_FILE_CONTENT_INVALID", { ...scope, field: `files[${fileIndex}].content`, path: `${filePath}.content` });
				});
			}
			if (entry.env !== undefined) {
				if (!entry.env || typeof entry.env !== "object" || Array.isArray(entry.env)) { push("CASE_ENV_INVALID", { ...scope, field: "env", path: `${path}.env` }); }
				else for (const [key, value] of Object.entries(entry.env)) {
					const envPath = `${path}.env.${key}`;
					if (!ENV_KEY.test(key) || RESERVED_ENV_KEYS.test(key) || key.startsWith("AIDR_NATIVE_TEST_")) { push("CASE_ENV_KEY_INVALID", { ...scope, field: `env.${key}`, path: envPath, detail: key }); continue; }
					if (isPlaceholder(value)) push("PLACEHOLDER_VALUE_UNREPLACED", { ...scope, field: `env.${key}`, path: envPath, placeholder: true, detail: value });
					else if (typeof value !== "string" || value.length > 2000) push("CASE_ENV_VALUE_INVALID", { ...scope, field: `env.${key}`, path: envPath });
				}
			}
		});
	};

	if (!spec || typeof spec !== "object" || Array.isArray(spec)) push("MANIFEST_NOT_OBJECT", { field: "manifest" });
	else {
		if (spec.schema_version !== 1) push("SCHEMA_VERSION_UNSUPPORTED", { field: "schema_version", detail: String(spec.schema_version) });
		if (spec.hosts === undefined || spec.hosts === null) push("HOSTS_MISSING", { field: "hosts" });
		else if (typeof spec.hosts !== "object" || Array.isArray(spec.hosts)) push("HOSTS_NOT_OBJECT", { field: "hosts" });
		else if (Object.keys(spec.hosts).length === 0) push("HOSTS_EMPTY", { field: "hosts" });
		else for (const [host, config] of Object.entries(spec.hosts)) {
			if (!HOSTS.some((definition) => definition.id === host)) { push("UNKNOWN_HOST", { host, field: "hosts", path: `hosts.${host}` }); continue; }
			if (!config || typeof config !== "object" || Array.isArray(config)) { push("HOST_CONFIG_NOT_OBJECT", { host, field: "hosts", path: `hosts.${host}` }); continue; }
			if (host !== "sdk") checkText(config.binary, "HOST_BINARY_MISSING", { host, field: "binary", path: `hosts.${host}.binary` });
			if (config.version_args !== undefined) {
				if (!Array.isArray(config.version_args) || config.version_args.length === 0) {
					push("HOST_VERSION_ARGS_INVALID", { host, field: "version_args", path: `hosts.${host}.version_args` });
				} else config.version_args.forEach((arg, index) => {
					checkText(arg, "HOST_VERSION_ARGS_INVALID", { host, field: `version_args[${index}]`, path: `hosts.${host}.version_args[${index}]` });
				});
			}
			checkAcceptance(host, config.acceptance);
			checkCases(host, config.cases);
		}
	}

	const errors = failures.filter((failure) => failure.severity === "error");
	const placeholders = failures.filter((failure) => failure.severity === "placeholder");
	return { ok: errors.length === 0, template, status: errors.length === 0 ? "STRUCTURE_OK" : "STRUCTURE_INVALID",
		failures, errors, placeholders, error_count: errors.length, placeholder_count: placeholders.length };
}

function unreadableManifestReport(path, error, raw = null) {
	const detail = error instanceof Error ? error.message : String(error);
	const failure = { code: "SCENARIO_MANIFEST_UNREADABLE", severity: "error", host: null, case_id: null, case_index: null,
		field: "scenario_file", path, detail };
	return { schema_version: 1, kind: "aidr_native_host_scenario_validation", validated_at: new Date().toISOString(),
		path, sha256: raw === null ? null : digest(raw), status: "SCENARIO_MANIFEST_UNREADABLE", ok: false, template: null,
		error_count: 1, placeholder_count: 0, failures: [failure],
		limitations: ["The scenario manifest could not be parsed, so no host behaviour was validated or exercised",
			"A template is never acceptance evidence; every REPLACE_WITH_* value must be replaced from a real host run"] };
}

/** Validate a scenario file on disk and wrap the findings in a report. */
export function validateScenarioFile(scenarioPath) {
	let raw;
	try {
		raw = readFileSync(scenarioPath, "utf8");
	} catch (error) {
		return unreadableManifestReport(scenarioPath, error);
	}
	let spec;
	try {
		spec = JSON.parse(raw);
	} catch (error) {
		return unreadableManifestReport(scenarioPath, error, raw);
	}
	const validation = validateScenarioManifest(spec);
	return { schema_version: 1, kind: "aidr_native_host_scenario_validation", validated_at: new Date().toISOString(),
		path: scenarioPath, sha256: digest(raw), status: validation.status, ok: validation.ok, template: validation.template,
		error_count: validation.error_count, placeholder_count: validation.placeholder_count, failures: validation.failures,
		limitations: ["Structure validation is not host acceptance: no host was launched and no side effect was observed",
			"A template is never acceptance evidence; every REPLACE_WITH_* value must be replaced from a real host run",
			"Replacing every placeholder does not prove enforcement either: the traces still need independent collection and named review"] };
}

function missingManifestFailure(path, explicit) {
	return { code: "SCENARIO_MANIFEST_MISSING", severity: "error", host: null, case_id: null, case_index: null, field: "scenario_file",
		path, detail: explicit ? "the requested scenario file does not exist" : "the committed default scenario manifest does not exist" };
}

function manifestReport(path, requested) {
	return { schema_version: 1, kind: "aidr_native_host_scenario_validation", validated_at: new Date().toISOString(),
		path, sha256: null, status: "SCENARIO_MANIFEST_MISSING", ok: false, template: null, error_count: 1, placeholder_count: 0,
		failures: [missingManifestFailure(path, requested)],
		limitations: ["No scenario manifest exists at this path, so no host behaviour could be validated or exercised",
			"deploy/native/scenarios/TEMPLATE.json is a schema template; copying it into place is not acceptance evidence"] };
}

function gateStatus(manifestPresent, probeOnly, hosts) {
	if (!manifestPresent) return "SCENARIO_MANIFEST_MISSING";
	if (probeOnly) return "VERSION_PROBED";
	if (hosts.filter((host) => host.ga).every((host) => host.status === "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN")) return "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN";
	if (hosts.some((host) => host.status === "HOST_ACCEPTANCE_OPEN" || host.status === "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN" || host.status === "VERSION_PROBE_FAILED")) return "HOST_ACCEPTANCE_OPEN";
	return "HOST_UNAVAILABLE";
}

function gateBlockers(manifestPresent, manifestPath, hosts, validation, manifestFailure = null) {
	const blockers = [];
	if (!manifestPresent) blockers.push(`SCENARIO_MANIFEST_MISSING:${manifestPath}`);
	if (manifestFailure) blockers.push(`${manifestFailure.code}:${manifestPath}`);
	// A template is never acceptance evidence, and deleting its `template`/`kind`
	// markers does not replace a single placeholder: both shapes are refused with
	// the same code, so a copied template cannot look like an ordinary open run.
	if (validation?.template === true || carriesTemplatePlaceholders(validation)) {
		blockers.push(SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE);
	}
	for (const failure of validation?.errors ?? []) blockers.push(`SCENARIO_MANIFEST_INVALID:${failure.code}${failure.field ? `:${failure.field}` : ""}`);
	for (const host of hosts) {
		if (host.status === "HOST_UNAVAILABLE") blockers.push(`${host.id}:HOST_UNAVAILABLE`);
		if (host.status === "HOST_ACCEPTANCE_OPEN") blockers.push(`${host.id}:HOST_ACCEPTANCE_OPEN`);
		if (host.status === "VERSION_PROBE_FAILED") blockers.push(`${host.id}:VERSION_PROBE_FAILED`);
		for (const entry of host.acceptance_blockers ?? []) blockers.push(`${host.id}:${entry}`);
	}
	return [...new Set(blockers)];
}

function printGateSummary(report) {
	console.log("Native host matrix v6 gate");
	console.log(`status   ${report.status}`);
	console.log(`gate     ${report.gate}`);
	console.log(`vocab    ${report.status_vocabulary.join(" ")}`);
	console.log(`manifest ${report.scenario_manifest_present ? report.scenario_manifest_path : `${report.scenario_manifest_expected_path} (absent)`}`);
	console.log(`coverage ${report.local_scenario_coverage}`);
	for (const host of report.hosts) console.log(`  ${host.id.padEnd(9)} ${host.status}${host.version ? ` version=${host.version}` : ""}`);
	console.log(`blockers ${report.blockers.length}`);
	for (const blocker of report.blockers) console.log(`  ${blocker}`);
	console.log(`reason   ${report.gate_reason}`);
	console.log(`note     Only a real host run plus independently collected traces and named external acceptance can raise this gate to GO.`);
}

function printValidationSummary(report) {
	console.log("Native host scenario manifest validation");
	console.log(`file         ${report.path}`);
	console.log(`sha256       ${report.sha256 ?? "unavailable"}`);
	console.log(`kind         ${report.template ? "template (never acceptance evidence)" : "acceptance manifest"}`);
	console.log(`validity     ${report.status}`);
	console.log(`errors       ${report.error_count}`);
	console.log(`placeholders ${report.placeholder_count}`);
	for (const failure of report.failures) {
		console.log(`  ${failure.severity.padEnd(11)} ${failure.code}${failure.path ? ` ${failure.path}` : ""}${failure.detail ? ` = ${JSON.stringify(failure.detail)}` : ""}`);
	}
	console.log("note         Structure validation is not host acceptance: no host was launched and no side effect was observed.");
}

function writeReport(outputPath, report, manifestPath) {
	const output = resolve(outputPath);
	if (manifestPath && output === manifestPath) throw new Error("Refusing to overwrite scenario manifest");
	mkdirSync(dirname(output), { recursive: true });
	writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx" });
}

function parseCli(argv) {
	const { values } = parseArgs({ args: argv, options: {
		"scenario-file": { type: "string" }, output: { type: "string" }, "probe-only": { type: "boolean" },
		"validate-only": { type: "boolean" },
	}, strict: true });
	return values;
}
function main(argv) {
	const options = parseCli(argv);
	const requested = options["scenario-file"] ? resolve(options["scenario-file"]) : null;
	const manifestPath = requested ?? DEFAULT_SCENARIO_PATH;
	const manifestPresent = existsSync(manifestPath);

	if (options["validate-only"] === true) {
		const report = manifestPresent ? validateScenarioFile(manifestPath) : manifestReport(manifestPath, requested !== null);
		if (options.output) writeReport(options.output, report, manifestPath);
		printValidationSummary(report);
		console.log(JSON.stringify(report, null, 2));
		if (!report.ok) process.exitCode = 1;
		return;
	}

	let rawManifest = null;
	let spec = { schema_version: 1, hosts: {} };
	let manifestFailure = null;
	if (manifestPresent) {
		try {
			rawManifest = readFileSync(manifestPath, "utf8");
			spec = JSON.parse(rawManifest);
		} catch (error) {
			manifestFailure = { code: "SCENARIO_MANIFEST_UNREADABLE", detail: error instanceof Error ? error.message : String(error) };
		}
	}
	const validation = manifestPresent && !manifestFailure ? validateScenarioManifest(spec) : null;
	const manifestRefused = validation?.template === true || carriesTemplatePlaceholders(validation);
	const scenarioHosts = spec && typeof spec === "object" && !Array.isArray(spec) && spec.hosts &&
		typeof spec.hosts === "object" && !Array.isArray(spec.hosts) ? spec.hosts : {};
	const hosts = HOSTS.map((definition) => {
		const host = probe(definition, scenarioHosts[definition.id]);
		// Without a manifest there is nothing to exercise: probing is all this
		// machine can honestly report, so the host record stays VERSION_PROBED.
		if (host.status === "VERSION_PROBED" && manifestPresent && !options["probe-only"]) {
			if (manifestFailure) {
				host.cases = [];
				host.acceptance_blockers = [manifestFailure.code];
				host.status = "HOST_ACCEPTANCE_OPEN";
			} else if (manifestRefused) {
				host.cases = [];
				host.acceptance_blockers = [SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE];
				host.status = "HOST_ACCEPTANCE_OPEN";
			} else {
				const cases = scenarioHosts[host.id]?.cases ?? [];
				if (!Array.isArray(cases) || new Set(cases.map((entry) => `${entry?.id}:${entry?.attack_id ?? ""}`)).size !== cases.length) throw new Error(`${host.id}: duplicate or invalid cases`);
				host.cases = cases.map((entry, index) => runCase(host, entry, index));
				host.acceptance_blockers = acceptanceBlockers(host, scenarioHosts[host.id]);
				for (const entry of host.cases) if (!entry.correlated_file_observations) host.acceptance_blockers.push(`${entry.id}:CORRELATED_FILE_TRACES_MISSING`);
				host.status = CASES.every((id) => host.cases.some((entry) => entry.id === id)) &&
					host.cases.every((entry) => ["PASS", "BOUNDARY_CLAIM_RECORDED"].includes(entry.status)) &&
					host.acceptance_blockers.length === 0 ? "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN" : "HOST_ACCEPTANCE_OPEN";
			}
		}
		return host;
	});
	const status = gateStatus(manifestPresent, options["probe-only"] === true, hosts);
	const manifestValidation = validation ? { status: validation.status, ok: validation.ok, template: validation.template,
		error_count: validation.error_count, placeholder_count: validation.placeholder_count, failures: validation.failures } :
		manifestFailure ? { status: manifestFailure.code, ok: false, template: null, error_count: 1, placeholder_count: 0,
			failures: [{ code: manifestFailure.code, severity: "error", host: null, case_id: null, case_index: null,
				field: "scenario_file", path: manifestPath, detail: manifestFailure.detail }] } : null;
	const report = { schema_version: 1, kind: "aidr_native_host_matrix_v6", measured_at: new Date().toISOString(),
		platform: process.platform, os_release: osRelease(), os_version: osVersion(), architecture: process.arch, node_version: process.version,
		scenario_manifest_path: manifestPresent ? manifestPath : null,
		scenario_manifest_expected_path: manifestPath,
		scenario_manifest_present: manifestPresent,
		scenario_manifest_sha256: manifestPresent && rawManifest !== null ? digest(rawManifest) : null,
		status_vocabulary: GATE_STATUSES,
		status,
		gate: "NO_GO",
		gate_reason: GATE_REASONS[status],
		manifest_validation: manifestValidation,
		local_scenario_coverage: hosts.filter((host) => host.ga).every((host) => host.status === "LOCAL_SCENARIOS_COMPLETE_REVIEW_OPEN") ? "COMPLETE_REVIEW_OPEN" : "INCOMPLETE",
		blockers: gateBlockers(manifestPresent, manifestPath, hosts, validation, manifestFailure),
		hosts,
		limitations: ["A version probe does not prove hook registration, tool interception, or prevented side effects",
			"SDK acceptance requires a named embedding application and cannot be inferred from an in-process unit test",
			"File observations and manifest owner names are operator supplied; independent collection and named acceptance require external review",
			"One local OS run is not a supported host and operating-system version matrix",
			"SCENARIO_MANIFEST_MISSING is a repository state, not a host result: deploy/native/scenarios/TEMPLATE.json is a schema template and a template is never acceptance evidence"] };
	if (options.output) writeReport(options.output, report, manifestPresent ? manifestPath : null);
	printGateSummary(report);
	console.log(JSON.stringify(report, null, 2));
	if (!options["probe-only"] && report.gate !== "GO") process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	try { main(process.argv.slice(2)); }
	catch (error) { console.error(`Native host matrix error: ${error.message}`); process.exitCode = 2; }
}

export { CASES, DEFAULT_SCENARIO_PATH, GATE_STATUSES, main };
