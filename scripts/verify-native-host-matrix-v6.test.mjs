import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = join(dirname(fileURLToPath(import.meta.url)), "verify-native-host-matrix-v6.mjs");
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
