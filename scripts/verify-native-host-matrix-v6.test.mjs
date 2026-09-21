import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
	GATE_STATUSES,
	SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE,
	validateScenarioManifest,
	binaryFor,
	pathCandidates,
	runBinary,
} from "./verify-native-host-matrix-v6.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, "verify-native-host-matrix-v6.mjs");
const templatePath = resolve(here, "..", "deploy", "native", "scenarios", "TEMPLATE.json");
const code = `const fs=require('node:fs'); console.log('HOST_ATTEMPT'); if(!process.argv.some(arg=>arg.includes('disabled'))) fs.writeFileSync(process.env.AIDR_NATIVE_TEST_RECEIPT,'AIDR_HOOK_INVOKED'); if(process.argv.some(arg=>arg.includes('write'))) fs.writeFileSync(process.env.AIDR_NATIVE_TEST_SENTINEL,'side effect');`;
const observation = (source, contains, path) => ({ source, contains, ...(path ? { path } : {}) });
const fixtureCase = (id, action) => ({ id, argv: ["{host_binary}", "-e", code, action],
	active: true, attempt: observation("stdout", "HOST_ATTEMPT"), hook: observation("file", "AIDR_HOOK_INVOKED", "{receipt}") });

function withFixture(fn) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-native-matrix-test-"));
	try { return fn(dir); }
	finally { rmSync(dir, { recursive: true, force: true }); }
}
function invoke(dir, manifest, extra = []) {
	const path = join(dir, "scenarios.json");
	const output = join(dir, "report.json");
	writeFileSync(path, JSON.stringify(manifest));
	const result = spawnSync(process.execPath, [script, "--scenario-file", path, "--output", output, ...extra], {
		encoding: "utf8", timeout: 120_000,
		env: { ...process.env, PATH: dirname(process.execPath) },
	});
	assert.ok(existsSync(output), `matrix report missing: ${result.error?.message ?? "unknown"}; ${result.stderr}`);
	return { result, report: JSON.parse(readFileSync(output, "utf8")) };
}

test("Windows resolver preserves Unicode paths and prefers real editor executables over PATH shims", () => {
	const unicodeRoot = "C:\\unicode-test\\测试用户\\AppData\\Local";
	const realCode = `${unicodeRoot}\\Programs\\Microsoft VS Code\\Code.exe`;
	const shim = `${unicodeRoot}\\bin\\code.cmd`;
	const present = new Set([realCode, shim]);
	const env = { LOCALAPPDATA: unicodeRoot, PATH: `${unicodeRoot}\\bin`, ProgramFiles: "C:\\Program Files" };
	assert.equal(binaryFor({ id: "vscode", command: "code", env: "AIDR_VSCODE_PATH" }, undefined, {
		platform: "win32", env, exists: (candidate) => present.has(candidate),
	}), realCode);
	assert.deepEqual(pathCandidates("code", { platform: "win32", pathValue: env.PATH, exists: (candidate) => present.has(candidate) }), [shim]);
});

test("Windows command shims reject metacharacters in binary paths and arguments", () => {
	assert.throws(() => runBinary("C:\\Program Files\\bad&host.cmd", [], { platform: "win32", env: { ComSpec: "C:\\Windows\\System32\\cmd.exe" } }), /Unsafe argument/u);
	assert.throws(() => runBinary("C:\\Program Files\\host.cmd", ["safe", "bad|argument"], { platform: "win32", env: { ComSpec: "C:\\Windows\\System32\\cmd.exe" } }), /Unsafe argument/u);
	assert.throws(() => runBinary("C:\\Program Files\\host.cmd", [], { platform: "win32", env: { ComSpec: "C:\\Windows\\System32\\cmd.exe&bad" } }), /Unsafe ComSpec/u);
	assert.throws(() => runBinary("C:\\Program Files\\host.cmd", [42], { platform: "win32", env: { ComSpec: "C:\\Windows\\System32\\cmd.exe" } }), /Unsafe argument/u);
});

test("Windows explicit binary paths resolve with Windows semantics", () => {
	const explicit = "C:\\unicode-test\\测试用户\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe";
	assert.equal(binaryFor({ id: "vscode", command: "code", env: "AIDR_VSCODE_PATH" }, { binary: explicit }, {
		platform: "win32", env: {}, exists: (candidate) => candidate === explicit,
	}), explicit);
});

test("inventory-only execution does not invent native acceptance", () => withFixture((dir) => {
	const manifest = { schema_version: 1, hosts: { codex: { binary: process.execPath } } };
	const { result, report } = invoke(dir, manifest, ["--probe-only"]);
	assert.equal(result.status, 0);
	assert.equal(report.gate, "NO_GO");
	assert.equal(report.hosts.find((host) => host.id === "codex").status, "VERSION_PROBED");
	assert.equal(report.hosts.find((host) => host.id === "sdk").status, "REQUIRES_EMBEDDED_APPLICATION_ACCEPTANCE");
	assert.equal(report.hosts.find((host) => host.id === "claude").status, "HOST_UNAVAILABLE");
}));

test("independent side-effect, attempt and hook observations are kept separate", () => withFixture((dir) => {
	const manifest = { schema_version: 1, hosts: { codex: { binary: process.execPath, cases: [
		fixtureCase("denied_side_effect", "block"),
		fixtureCase("benign_allow", "write"),
		fixtureCase("disabled_hook", "disabled-write"),
	], acceptance: { required_attack_ids: ["credential_read"] } } } };
	const { result, report } = invoke(dir, manifest);
	assert.equal(result.status, 1);
	assert.equal(report.gate, "NO_GO");
	const cases = report.hosts.find((host) => host.id === "codex").cases;
	assert.deepEqual(cases.map((entry) => entry.status), ["PASS", "PASS", "FAIL_OPEN_OBSERVED"]);
	assert.deepEqual(cases.map((entry) => entry.side_effect_observed), [false, true, true]);
	assert.equal(cases[0].attempt_observed, true);
	assert.equal(cases[0].hook_observed, true);
	assert.equal(cases[0].correlated_file_observations, false);
	assert.ok(report.hosts.find((host) => host.id === "codex").acceptance_blockers.includes("DENIED_ATTACK_UNPROVEN:credential_read"));
	assert.ok(report.hosts.find((host) => host.id === "codex").acceptance_blockers.includes("BENIGN_TWIN_UNPROVEN:credential_read"));
}));

test("a silent blocked marker without an actual tool attempt never passes", () => withFixture((dir) => {
	const manifest = { schema_version: 1, hosts: { codex: { binary: process.execPath, cases: [{
		id: "denied_side_effect", argv: ["{host_binary}", "-e", "process.stdout.write('model refused')"],
		attempt: observation("stdout", "HOST_ATTEMPT"), hook: observation("file", "AIDR_HOOK_INVOKED", "{receipt}"),
	}] } } };
	const { result, report } = invoke(dir, manifest);
	assert.equal(result.status, 1);
	assert.equal(report.hosts.find((host) => host.id === "codex").cases[0].status, "ATTEMPT_UNPROVEN");
}));

test("fixture files cannot forge a hook receipt or side-effect marker", () => withFixture((dir) => {
	const path = join(dir, "forged.json");
	writeFileSync(path, JSON.stringify({ schema_version: 1, hosts: { codex: { binary: process.execPath, cases: [{
		...fixtureCase("denied_side_effect", "block"), files: [{ path: "{receipt}", content: "AIDR_HOOK_INVOKED" }],
	}] } } }));
	const result = spawnSync(process.execPath, [script, "--scenario-file", path], {
		encoding: "utf8", timeout: 60_000, env: { ...process.env, PATH: dirname(process.execPath) },
	});
	assert.equal(result.status, 2);
	assert.match(result.stderr, /cannot pre-create side-effect or observation evidence/u);
}));

test("offline and restart cases require observed fault conditions", () => withFixture((dir) => {
	const manifest = { schema_version: 1, hosts: { codex: { binary: process.execPath, cases: [
		fixtureCase("offline", "block"), fixtureCase("restart", "block"),
	] } } };
	const { result, report } = invoke(dir, manifest);
	assert.equal(result.status, 1);
	assert.deepEqual(report.hosts.find((host) => host.id === "codex").cases.map((entry) => entry.status),
		["CONDITION_UNPROVEN", "CONDITION_UNPROVEN"]);
}));

test("a fault-mode boundary claim is recorded but cannot grant release GO", () => withFixture((dir) => {
	const fakeHost = `const fs=require('node:fs'); const p=require('node:path'); const n=process.env.AIDR_NATIVE_TEST_CASE_NONCE; const w=process.env.AIDR_NATIVE_TEST_WORKSPACE; fs.writeFileSync(p.join(w,'attempt.log'),'attempt:'+n); fs.writeFileSync(p.join(w,'condition.log'),'disabled:'+n); fs.writeFileSync(p.join(w,'boundary.log'),'blocked:'+n);`;
	const manifest = { schema_version: 1, hosts: { codex: { binary: process.execPath, cases: [{
		id: "disabled_hook", argv: ["{host_binary}", "-e", fakeHost],
		attempt: observation("file", "attempt:{case_nonce}", "{workspace}/attempt.log"),
		hook: observation("file", "hook:{case_nonce}", "{receipt}"),
		condition: observation("file", "disabled:{case_nonce}", "{workspace}/condition.log"),
		boundary: observation("file", "blocked:{case_nonce}", "{workspace}/boundary.log"),
	}] } } };
	const { result, report } = invoke(dir, manifest);
	assert.equal(result.status, 1);
	const entry = report.hosts.find((host) => host.id === "codex").cases[0];
	assert.equal(entry.status, "BOUNDARY_CLAIM_RECORDED", JSON.stringify(entry));
	assert.equal(entry.correlated_file_observations, true);
	assert.equal(entry.hook_observed, false);
	assert.equal(entry.side_effect_observed, false);
	assert.equal(report.gate, "NO_GO");
}));

test("a harness timeout never passes even when benign side effect was written", () => withFixture((dir) => {
	const fakeHost = `const fs=require('node:fs'); fs.writeFileSync(process.env.AIDR_NATIVE_TEST_SENTINEL,'written'); console.log('HOST_ATTEMPT'); fs.writeFileSync(process.env.AIDR_NATIVE_TEST_RECEIPT,'AIDR_HOOK_INVOKED'); setTimeout(()=>{},10000);`;
	const manifest = { schema_version: 1, hosts: { codex: { binary: process.execPath, cases: [{
		id: "benign_allow", argv: ["{host_binary}", "-e", fakeHost], timeout_ms: 3000,
		attempt: observation("stdout", "HOST_ATTEMPT"), hook: observation("file", "AIDR_HOOK_INVOKED", "{receipt}"),
	}] } } };
	const { result, report } = invoke(dir, manifest);
	assert.equal(result.status, 1);
	const entry = report.hosts.find((host) => host.id === "codex").cases[0];
	assert.equal(entry.status, "HOST_TIMED_OUT");
	assert.equal(entry.side_effect_observed, true);
}));

const observedCase = (id, attackId) => ({ id, ...(attackId ? { attack_id: attackId } : {}),
	argv: ["{host_binary}", "--non-interactive", "prompt"],
	attempt: { source: "file", path: "{workspace}/attempt.log", contains: "ATTEMPT:{case_nonce}" },
	hook: { source: "file", path: "{receipt}", contains: "HOOK:{case_nonce}" } });
const observedAcceptance = () => ({ os_platform: "win32", os_release: "10.0.19045", architecture: "x64",
	host_version: "codex-cli 0.141.0", launcher_sha256: "a".repeat(64), candidate_sha256: "b".repeat(64),
	policy_sha256: "c".repeat(64), install_evidence_sha256: "d".repeat(64), uninstall_evidence_sha256: "e".repeat(64),
	qa_owner: "QA Lead", endpoint_owner: "Endpoint Lead", support_owner: "Support Lead",
	unobserved_actions: [], required_attack_ids: ["credential_read"] });
const observedManifest = () => ({ schema_version: 1, hosts: { codex: { binary: process.execPath,
	version_args: ["--version"], acceptance: observedAcceptance(),
	cases: [observedCase("denied_side_effect", "credential_read"), observedCase("benign_allow", "credential_read")] } } });
const failureCodes = (validation) => validation.failures.map((entry) => entry.code);
function runCli(dir, args) {
	return spawnSync(process.execPath, [script, ...args], {
		encoding: "utf8", timeout: 120_000, cwd: dir, env: { ...process.env, PATH: dirname(process.execPath) },
	});
}

test("a fully filled manifest is structurally valid", () => {
	const validation = validateScenarioManifest(observedManifest());
	assert.equal(validation.ok, true, JSON.stringify(validation.failures));
	assert.equal(validation.error_count, 0);
	assert.equal(validation.placeholder_count, 0);
	assert.equal(validation.template, false);
});

test("the committed template is structurally valid and honestly unfilled", () => {
	const spec = JSON.parse(readFileSync(templatePath, "utf8"));
	const validation = validateScenarioManifest(spec);
	assert.equal(validation.ok, true, JSON.stringify(validation.errors));
	assert.equal(validation.template, true);
	assert.equal(validation.error_count, 0);
	assert.ok(validation.placeholder_count > 0);
	for (const field of ["launcher_sha256", "candidate_sha256", "policy_sha256", "install_evidence_sha256", "uninstall_evidence_sha256"]) {
		assert.ok(validation.placeholders.some((entry) => entry.field === field), `${field} must stay a placeholder`);
	}
	for (const host of Object.values(spec.hosts)) {
		assert.deepEqual([...new Set(host.cases.map((entry) => entry.id))].sort(),
			["benign_allow", "crash", "denied_side_effect", "disabled_hook", "offline", "restart", "timeout"],
			"the template documents every native case");
	}
});

test("an unreplaced template value fails validation outside a template", () => {
	const spec = observedManifest();
	spec.hosts.codex.acceptance.host_version = "REPLACE_WITH_PROBED_HOST_VERSION";
	const validation = validateScenarioManifest(spec);
	assert.equal(validation.ok, false);
	assert.ok(failureCodes(validation).includes("PLACEHOLDER_VALUE_UNREPLACED"));
	const entry = validation.errors.find((item) => item.code === "PLACEHOLDER_VALUE_UNREPLACED");
	assert.equal(entry.field, "host_version");
	assert.equal(entry.path, "hosts.codex.acceptance.host_version");
	assert.equal(entry.severity, "error");
});

test("argv that does not start with the probed host binary fails validation", () => {
	const spec = observedManifest();
	spec.hosts.codex.cases[0].argv = ["codex", "--non-interactive", "prompt"];
	const validation = validateScenarioManifest(spec);
	assert.equal(validation.ok, false);
	assert.ok(failureCodes(validation).includes("CASE_ARGV_MUST_START_WITH_HOST_BINARY"));
	assert.equal(validation.errors.find((item) => item.code === "CASE_ARGV_MUST_START_WITH_HOST_BINARY").path, "hosts.codex.cases[0].argv");
});

test("a duplicate id:attack_id pair fails validation", () => {
	const spec = observedManifest();
	spec.hosts.codex.cases.push(observedCase("denied_side_effect", "credential_read"));
	const validation = validateScenarioManifest(spec);
	assert.equal(validation.ok, false);
	assert.ok(failureCodes(validation).includes("DUPLICATE_CASE_ID_ATTACK_PAIR"));
	assert.equal(validation.errors.find((item) => item.code === "DUPLICATE_CASE_ID_ATTACK_PAIR").detail, "denied_side_effect:credential_read");
});

test("an unknown case id fails validation", () => {
	const spec = observedManifest();
	spec.hosts.codex.cases[1].id = "denied_side_effect_not_really";
	const validation = validateScenarioManifest(spec);
	assert.equal(validation.ok, false);
	assert.ok(failureCodes(validation).includes("UNKNOWN_CASE_ID"));
});

test("a missing attempt or hook observation fails validation", () => {
	const withoutAttempt = observedManifest();
	delete withoutAttempt.hosts.codex.cases[0].attempt;
	const attemptValidation = validateScenarioManifest(withoutAttempt);
	assert.equal(attemptValidation.ok, false);
	assert.ok(failureCodes(attemptValidation).includes("ATTEMPT_OBSERVATION_MISSING"));
	const withoutHook = observedManifest();
	delete withoutHook.hosts.codex.cases[0].hook;
	const hookValidation = validateScenarioManifest(withoutHook);
	assert.equal(hookValidation.ok, false);
	assert.ok(failureCodes(hookValidation).includes("HOOK_OBSERVATION_MISSING"));
});

test("an acceptance block missing a required field fails validation", () => {
	const spec = observedManifest();
	delete spec.hosts.codex.acceptance.candidate_sha256;
	const validation = validateScenarioManifest(spec);
	assert.equal(validation.ok, false);
	const entry = validation.errors.find((item) => item.code === "ACCEPTANCE_FIELD_MISSING");
	assert.ok(entry, JSON.stringify(validation.failures));
	assert.equal(entry.field, "candidate_sha256");
	assert.equal(entry.path, "hosts.codex.acceptance.candidate_sha256");
});

test("--validate-only accepts the template structurally and never claims host acceptance", () => withFixture((dir) => {
	const result = runCli(dir, ["--scenario-file", templatePath, "--validate-only"]);
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /validity\s+STRUCTURE_OK/u);
	assert.match(result.stdout, /"status": "STRUCTURE_OK"/u);
	assert.match(result.stdout, /PLACEHOLDER_VALUE_UNREPLACED hosts\.codex\.binary/u);
	assert.doesNotMatch(result.stdout, /\bPASS\b/u);
}));

test("--validate-only fails an accepted manifest that still holds a placeholder", () => withFixture((dir) => {
	const path = join(dir, "unfilled.json");
	const spec = observedManifest();
	spec.hosts.codex.cases[0].argv[2] = "REPLACE_WITH_DENIED_ACTION_PROMPT";
	writeFileSync(path, JSON.stringify(spec));
	const result = runCli(dir, ["--scenario-file", path, "--validate-only"]);
	assert.equal(result.status, 1);
	assert.match(result.stdout, /validity\s+STRUCTURE_INVALID/u);
	assert.match(result.stdout, /PLACEHOLDER_VALUE_UNREPLACED/u);
}));

test("normal execution refuses a template before launching its host", () => withFixture((dir) => {
	const path = join(dir, "template.json");
	const output = join(dir, "nested", "gate.json");
	const spec = JSON.parse(readFileSync(templatePath, "utf8"));
	spec.hosts.codex.binary = process.execPath;
	spec.hosts.codex.version_args = ["--version"];
	writeFileSync(path, JSON.stringify(spec));
	const cliResult = runCli(dir, ["--scenario-file", path, "--output", output]);
	assert.equal(cliResult.status, 1, cliResult.stderr);
	assert.ok(existsSync(output));
	const record = JSON.parse(readFileSync(output, "utf8"));
	const host = record.hosts.find((entry) => entry.id === "codex");
	assert.equal(host.status, "HOST_ACCEPTANCE_OPEN");
	assert.deepEqual(host.cases, []);
	assert.ok(record.blockers.includes(SCENARIO_TEMPLATE_IS_NOT_ACCEPTANCE_EVIDENCE), record.blockers.join("; "));
	assert.equal(record.gate, "NO_GO");
}));

test("a malformed scenario manifest writes a machine-readable blocker", () => withFixture((dir) => {
	const path = join(dir, "malformed.json");
	const output = join(dir, "nested", "gate.json");
	writeFileSync(path, "{not-json");
	const result = runCli(dir, ["--scenario-file", path, "--output", output]);
	assert.equal(result.status, 1, result.stderr);
	assert.ok(existsSync(output));
	const report = JSON.parse(readFileSync(output, "utf8"));
	assert.equal(report.manifest_validation.status, "SCENARIO_MANIFEST_UNREADABLE");
	assert.equal(report.manifest_validation.ok, false);
	assert.ok(report.blockers.includes(`SCENARIO_MANIFEST_UNREADABLE:${resolve(path)}`), report.blockers.join("; "));
	assert.equal(report.gate, "NO_GO");
}));

test("--validate-only reports malformed JSON without throwing", () => withFixture((dir) => {
	const path = join(dir, "malformed.json");
	const output = join(dir, "nested", "validation.json");
	writeFileSync(path, "{not-json");
	const result = runCli(dir, ["--scenario-file", path, "--validate-only", "--output", output]);
	assert.equal(result.status, 1, result.stderr);
	const report = JSON.parse(readFileSync(output, "utf8"));
	assert.equal(report.status, "SCENARIO_MANIFEST_UNREADABLE");
	assert.equal(report.ok, false);
	assert.equal(report.failures[0].code, "SCENARIO_MANIFEST_UNREADABLE");
}));

test("invalid probe arguments remain a machine-readable open blocker", () => withFixture((dir) => {
	const manifest = { schema_version: 1, hosts: { codex: { binary: process.execPath, version_args: "--version" } } };
	const { result, report } = invoke(dir, manifest);
	assert.equal(result.status, 1, result.stderr);
	assert.equal(report.status, "HOST_ACCEPTANCE_OPEN");
	assert.equal(report.hosts.find((host) => host.id === "codex").status, "VERSION_PROBE_FAILED");
	assert.ok(report.blockers.some((blocker) => blocker.startsWith("SCENARIO_MANIFEST_INVALID:HOST_VERSION_ARGS_INVALID")), report.blockers.join("; "));
	assert.equal(report.gate, "NO_GO");
}));

test("a missing scenario manifest reports SCENARIO_MANIFEST_MISSING and fails closed", () => withFixture((dir) => {
	const output = join(dir, "gate.json");
	const result = runCli(dir, ["--scenario-file", join(dir, "not-committed.json"), "--output", output]);
	assert.equal(result.status, 1);
	assert.match(result.stdout, /^status\s+SCENARIO_MANIFEST_MISSING$/mu);
	assert.ok(existsSync(output), "the gate must still write its report");
	const report = JSON.parse(readFileSync(output, "utf8"));
	assert.equal(report.status, "SCENARIO_MANIFEST_MISSING");
	assert.equal(report.gate, "NO_GO");
	assert.equal(report.scenario_manifest_present, false);
	assert.deepEqual(report.status_vocabulary, GATE_STATUSES);
	assert.ok(report.blockers.some((blocker) => blocker.startsWith("SCENARIO_MANIFEST_MISSING:")));
}));

test("the gate without a scenario file stays inside the status vocabulary and never exits 0", () => withFixture((dir) => {
	// The repository deliberately commits no default manifest: only a real host run
	// may produce one, so this is where that expectation is asserted.
	const defaultManifest = resolve(here, "..", "deploy", "native", "scenarios", "native-host-scenarios.json");
	assert.equal(existsSync(defaultManifest), false, "a default manifest must not be invented in the repository");
	const result = runCli(dir, []);
	assert.equal(result.status, 1);
	const report = JSON.parse(result.stdout.slice(result.stdout.indexOf("{")));
	assert.equal(report.gate, "NO_GO");
	assert.ok(GATE_STATUSES.includes(report.status), report.status);
	assert.equal(report.status, "SCENARIO_MANIFEST_MISSING");
	assert.doesNotMatch(result.stdout.split("\n{")[0], /\bPASS\b/u);
}));
