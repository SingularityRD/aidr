#!/usr/bin/env node
/**
 * Regressions for the direct IDE extension-host runner.
 *
 * The properties that matter are the ones that made this runner necessary:
 * it must not report success when the host ran nothing, it must not silently
 * accept a partial case set, and it must refuse to run without a real host
 * binary rather than producing an empty green report. These are the exact
 * failures the Vitest path exhibited — `success: true` with zero tests — so a
 * regression here would reintroduce an invisible gap in release evidence.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "run-ide-host-e2e.mjs");

function run(args, env = {}) {
	try {
		const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
			cwd: ROOT,
			encoding: "utf8",
			env: { ...process.env, ...env },
			stdio: ["ignore", "pipe", "pipe"],
		});
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

function candidateEnv(dir, contents = "candidate-vsix\n") {
	const candidate = join(dir, "aidr-cursor.vsix");
	writeFileSync(candidate, contents);
	return {
		AIDR_E2E_VSIX_PATH: candidate,
		AIDR_E2E_VSIX_SHA256: createHash("sha256").update(contents).digest("hex"),
	};
}

function cursorCandidateEnv(dir) {
	const generic = candidateEnv(dir);
	return {
		AIDR_E2E_CURSOR_VSIX_PATH: generic.AIDR_E2E_VSIX_PATH,
		AIDR_E2E_CURSOR_VSIX_SHA256: generic.AIDR_E2E_VSIX_SHA256,
	};
}

function writeStubHost(dir, runSource) {
	const stub = join(dir, "stub-host.cjs");
	writeFileSync(
		stub,
		`${String.raw`
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
if (process.env.AIDR_TEST_HOST_LOG) fs.appendFileSync(process.env.AIDR_TEST_HOST_LOG, JSON.stringify(args) + "\n");
if (process.env.AIDR_TEST_SANDBOX_ENV_LOG) fs.appendFileSync(process.env.AIDR_TEST_SANDBOX_ENV_LOG, JSON.stringify({install:args.includes("--install-extension"),vars:Object.fromEntries(["VSCODE_IPC_HOOK_CLI","VSCODE_PID","ELECTRON_RUN_AS_NODE","VSCODE_DEV","VSCODE_CWD"].map(key=>[key,process.env[key]??null])),aliases:Object.keys(process.env).filter(key=>["VSCODE_IPC_HOOK_CLI","VSCODE_PID","ELECTRON_RUN_AS_NODE","VSCODE_DEV","VSCODE_CWD"].includes(key.toUpperCase()))}) + "\n");
const installIndex = args.indexOf("--install-extension");
if (installIndex !== -1) {
  const expectedVsix = process.env.AIDR_E2E_CURSOR_VSIX_PATH || process.env.AIDR_E2E_VSIX_PATH;
  if (args[installIndex + 1] !== expectedVsix) process.exit(41);
  const extensionsDir = args.find((arg) => arg.startsWith("--extensions-dir=")).slice("--extensions-dir=".length);
  const installed = path.join(extensionsDir, "singularityrd.aidr-cursor-0.6.0");
  const dist = path.join(installed, "dist");
  fs.mkdirSync(dist, { recursive: true });
  fs.writeFileSync(path.join(installed, "package.json"), JSON.stringify({ publisher: "SingularityRD", name: "aidr-cursor", main: "./dist/cursor_extension.js" }));
  const payloads = {
    "aidr-hook.cjs": "hook\n",
    "aidr-hook.bundle.cjs": "hook bundle\n",
    "cursor_extension.js": "cursor\n",
    "vscode_extension.js": "vscode\n",
    "aidr-sbom.cdx.json": "{}\n",
    "aidr-sbom.cdx.json.sha256": "checksum\n"
  };
  const files = Object.entries(payloads).map(([name, contents]) => {
    fs.writeFileSync(path.join(dist, name), contents);
    return { path: name, sha256: crypto.createHash("sha256").update(contents).digest("hex") };
  });
  fs.writeFileSync(path.join(dist, "aidr-artifact.manifest.json"), JSON.stringify({ schema_version: 1, artifact_id: "extension/dist", files }));
  fs.writeFileSync(path.join(dist, "aidr-artifact.manifest.sig"), "signature\n");
  if (process.env.AIDR_TEST_TAMPER_INSTALLED === "1") fs.writeFileSync(path.join(dist, "cursor_extension.js"), "tampered\n");
  process.exit(0);
}
`}${runSource}\n`,
	);
	const wrapperDir = join(dir, "bin");
	mkdirSync(wrapperDir, { recursive: true });
	const wrapper = join(wrapperDir, process.platform === "win32" ? "stub-host.cmd" : "stub-host");
	if (process.platform === "win32") {
		writeFileSync(wrapper, `@echo off\r\n"${process.execPath}" "${stub}" %*\r\n`);
	} else {
		writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${stub}" "$@"\n`, { mode: 0o755 });
	}
	return wrapper;
}

describe("direct IDE host runner", () => {
	it("documents its arguments", () => {
		const result = run(["--help"]);
		assert.equal(result.status, 0);
		assert.match(result.output, /--host/);
		assert.match(result.output, /--junit/);
	});

	it("rejects an unknown host instead of defaulting to one", () => {
		const result = run(["--host", "not-a-host", "--junit", join(tmpdir(), "x.xml")]);
		assert.equal(result.status, 1);
		assert.match(result.output, /--host must be one of/);
	});

	it("rejects an unknown argument", () => {
		const result = run(["--host", "cursor", "--junit", join(tmpdir(), "x.xml"), "--force"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /unknown argument/);
	});

	it("requires --junit so a run cannot be unrecorded", () => {
		const result = run(["--host", "cursor"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /--junit is required/);
	});

	it("requires an inventory-bound candidate VSIX", () => {
		const result = run(["--host", "cursor", "--junit", join(tmpdir(), "x.xml")], {
			AIDR_E2E_VSIX_PATH: "",
			AIDR_E2E_VSIX_SHA256: "",
		});
		assert.equal(result.status, 1);
		assert.match(result.output, /AIDR_E2E_CURSOR_VSIX_PATH or AIDR_E2E_VSIX_PATH is required/);
	});

	it("rejects a candidate whose archive digest does not match", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const env = candidateEnv(dir);
			env.AIDR_E2E_VSIX_SHA256 = "0".repeat(64);
			const result = run(["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", join(dir, "unused")], env);
			assert.equal(result.status, 1);
			assert.match(result.output, /candidate VSIX SHA-256 mismatch/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("rejects installed bytes that do not match the candidate artifact manifest", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const wrapper = writeStubHost(dir, "process.exit(0);");
			const result = run(
				["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", wrapper],
				{ ...candidateEnv(dir), AIDR_TEST_TAMPER_INSTALLED: "1" },
			);
			assert.equal(result.status, 1);
			assert.match(result.output, /installed candidate artifact digest mismatch: cursor_extension\.js/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("uses the host-specific candidate binding during the combined release run", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const result = run(
				["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", join(dir, "absent-Cursor.exe")],
				cursorCandidateEnv(dir),
			);
			assert.equal(result.status, 2);
			assert.match(result.output, /no Cursor executable/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("refuses a missing host binary as blocked rather than reporting a pass", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const junit = join(dir, "out.xml");
			const result = run(
				["--host", "cursor", "--junit", junit, "--exe", join(dir, "absent-Cursor.exe")],
				candidateEnv(dir),
			);
			assert.equal(result.status, 2, "a missing host must exit with the blocked code");
			assert.match(result.output, /no Cursor executable/);
			// No JUnit must be produced: an empty report is exactly the failure mode
			// this runner exists to prevent.
			assert.equal(existsSync(junit), false);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("reports zero cases as failure when the host writes no result file", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const wrapper = writeStubHost(dir, "process.exit(0);");
			const hostLog = join(dir, "host-calls.jsonl");
			const env = { ...cursorCandidateEnv(dir), AIDR_TEST_HOST_LOG: hostLog };
			const junit = join(dir, "out.xml");
			const result = run(["--host", "cursor", "--junit", junit, "--exe", wrapper], env);

			assert.equal(result.status, 1, "a host that ran nothing must not exit zero");
			assert.match(result.output, /0\/8 cases passed/);
			const calls = readFileSync(hostLog, "utf8").trim().split("\n").map((line) => JSON.parse(line));
			assert.equal(calls.length, 2, "the fresh candidate must be installed before the host test launch");
			const installIndex = calls[0].indexOf("--install-extension");
			assert.equal(calls[0][installIndex + 1], env.AIDR_E2E_CURSOR_VSIX_PATH);
			assert.ok(calls[1].some((arg) => arg.startsWith("--extensionDevelopmentPath=")));
			assert.ok(calls[1].includes(join(ROOT, "packages/extension/test-workspace")), "the default fixture remains unchanged");
			assert.ok(calls.every((args) => args.every((arg) => !arg.includes("native-host-tools-20260916"))));
			assert.ok(existsSync(junit), "a JUnit report must still be written so the gate sees the failure");
			const xml = readFileSync(junit, "utf8");
			assert.match(xml, /tests="8"/);
			assert.match(xml, /failures="8"/);
			// Every expected case must be named, so a reader can see which ones are
			// missing rather than only that the count was wrong.
			for (const id of ["configure-workspace-scope", "dangerous-write-blocked", "disable-protection-removes-hooks"]) {
				assert.match(xml, new RegExp(id));
			}
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("passes a fresh controlled workspace to the actual host launch", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		const workspace = mkdtempSync(join(tmpdir(), "aidr-ide-workspace-"));
		try {
			const wrapper = writeStubHost(dir, "process.exit(0);");
			const hostLog = join(dir, "host-calls.jsonl");
			const result = run(["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", wrapper, "--workspace", workspace], {
				...candidateEnv(dir), AIDR_TEST_HOST_LOG: hostLog,
			});
			assert.equal(result.status, 1, "zero reported cases must still fail");
			assert.match(result.output, /0\/8 cases passed/);
			const calls = readFileSync(hostLog, "utf8").trim().split("\n").map((line) => JSON.parse(line));
			assert.ok(calls[1].includes(workspace));
			assert.equal(calls[1].includes(join(ROOT, "packages/extension/test-workspace")), false);
		} finally { rmSync(dir, { recursive: true, force: true }); rmSync(workspace, { recursive: true, force: true }); }
	});

	it("refuses existing profile content, outside workspaces and junction fixtures before host launch", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		const workspace = mkdtempSync(join(tmpdir(), "aidr-ide-workspace-"));
		const link = join(tmpdir(), `aidr-ide-workspace-link-${basename(workspace)}`);
		try {
			const wrapper = writeStubHost(dir, "process.exit(0);");
			const hostLog = join(dir, "host-calls.jsonl");
			const env = { ...candidateEnv(dir), AIDR_TEST_HOST_LOG: hostLog };
			const args = ["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", wrapper, "--workspace"];
			writeFileSync(join(workspace, "settings.json"), "existing profile\n");
			const nonempty = run([...args, workspace], env);
			assert.equal(nonempty.status, 1); assert.match(nonempty.output, /workspace must be an empty controlled temporary directory/);
			assert.equal(readFileSync(join(workspace, "settings.json"), "utf8"), "existing profile\n");
			for (const outside of [ROOT, "packages/extension/test-workspace"]) {
				const result = run([...args, outside], env);
				assert.equal(result.status, 1); assert.match(result.output, /workspace must be an empty controlled temporary directory/);
			}
			unlinkSync(join(workspace, "settings.json"));
			symlinkSync(workspace, link, process.platform === "win32" ? "junction" : "dir");
			const linked = run([...args, link], env);
			assert.equal(linked.status, 1); assert.match(linked.output, /workspace must be an empty controlled temporary directory/);
			assert.equal(existsSync(hostLog), false, "invalid fixtures must never reach the host");
		} finally { if (existsSync(link)) unlinkSync(link); rmSync(dir, { recursive: true, force: true }); rmSync(workspace, { recursive: true, force: true }); }
	});

	it("copies the independently pinned artifact-key config only into the fresh host HOME", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const { publicKey } = generateKeyPairSync("ed25519");
			const config = JSON.stringify({ integrity: { enabled: true, verify_on_start: true, public_keys_pem: [publicKey.export({ type: "spki", format: "pem" }).toString()] } });
			const configPath = join(dir, "agent-config.json");
			writeFileSync(configPath, config);
			const wrapper = writeStubHost(dir, "if(fs.readFileSync(path.join(process.env.HOME,'.singularity-aidr/config.json'),'utf8')!==process.env.AIDR_TEST_CONFIG_BYTES)process.exit(51);process.exit(0);");
			const result = run(["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", wrapper], {
				...candidateEnv(dir), AIDR_E2E_AGENT_CONFIG_PATH: configPath,
				AIDR_E2E_AGENT_CONFIG_SHA256: createHash("sha256").update(config).digest("hex"), AIDR_TEST_CONFIG_BYTES: config,
			});
			assert.equal(result.status, 1, "zero reported cases must still fail");
			assert.match(result.output, /host exited 0/); assert.match(result.output, /0\/8 cases passed/);
			assert.equal(readFileSync(configPath, "utf8"), config, "the source fixture must remain unchanged");
		} finally { rmSync(dir, { recursive: true, force: true }); }
	});

	it("rejects config tampering and missing startup artifact keys before invoking the vendor", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const hostLog = join(dir, "host-calls.jsonl");
			const wrapper = writeStubHost(dir, "process.exit(0);");
			const configPath = join(dir, "agent-config.json");
			for (const config of [{ integrity: { enabled: false, verify_on_start: true, public_keys_pem: [] } }, { integrity: { enabled: true, verify_on_start: true, public_keys_pem: [] } }]) {
				const bytes = JSON.stringify(config); writeFileSync(configPath, bytes);
				for (const digest of ["0".repeat(64), createHash("sha256").update(bytes).digest("hex")]) {
					const result = run(["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", wrapper], {
						...candidateEnv(dir), AIDR_E2E_AGENT_CONFIG_PATH: configPath, AIDR_E2E_AGENT_CONFIG_SHA256: digest, AIDR_TEST_HOST_LOG: hostLog,
					});
					assert.equal(result.status, 1); assert.match(result.output, /invalid inventory-bound agent fixture config/);
				}
			}
			assert.equal(existsSync(hostLog), false, "invalid fixture configs must never reach the vendor");
		} finally { rmSync(dir, { recursive: true, force: true }); }
	});

	it("reports a partially reported case set as failure", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const wrapper = writeStubHost(
				dir,
				[
					"fs.writeFileSync(process.env.AIDR_E2E_RESULTS_FILE, JSON.stringify({host:'cursor',cases:[",
					"  {id:'configure-workspace-scope',status:'pass',durationMs:1},",
					"  {id:'extension-activates',status:'fail',error:'boom'}",
					"]}));",
					"process.exit(0);",
				].join("\n"),
			);

			const junit = join(dir, "out.xml");
			const result = run(["--host", "cursor", "--junit", junit, "--exe", wrapper], candidateEnv(dir));

			assert.equal(result.status, 1, result.output);
			assert.match(result.output, /1\/8 cases passed/);
			const xml = readFileSync(junit, "utf8");
			assert.match(xml, /failures="7"/);
			assert.match(xml, /case failed/);
			assert.match(xml, /case not reported/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	for (const hostExit of [0, 23]) {
		it(`preserves all eight results and ${hostExit === 0 ? "accepts a clean" : "rejects a failed"} host exit`, () => {
			const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
			try {
				const ids = ["configure-workspace-scope", "extension-activates", "commands-registered", "enable-protection-writes-hooks", "hook-health-command", "dangerous-write-blocked", "hook-response-shape-consistent", "disable-protection-removes-hooks"];
				const wrapper = writeStubHost(dir, `fs.writeFileSync(process.env.AIDR_E2E_RESULTS_FILE, JSON.stringify({host:'cursor',cases:${JSON.stringify(ids)}.map(id=>({id,status:'pass',durationMs:1}))}));process.exit(${hostExit});`);
				const junit = join(dir, "out.xml");
				const json = join(dir, "out.json");
				const result = run(["--host", "cursor", "--junit", junit, "--json", json, "--exe", wrapper], candidateEnv(dir));
				assert.equal(result.status, hostExit === 0 ? 0 : 1, result.output);
				assert.match(result.output, /8\/8 cases passed/);
				const xml = readFileSync(junit, "utf8");
				assert.equal((xml.match(/<testcase\b/g) ?? []).length, 8);
				assert.match(xml, /tests="8" failures="0"/);
				assert.match(xml, new RegExp(`errors="${hostExit === 0 ? 0 : 1}" skipped="0"`));
				const report = JSON.parse(readFileSync(json, "utf8"));
				assert.equal(report.passed, 8);
				assert.equal(report.failures, 0);
				assert.equal(report.cases.length, 8);
				if (hostExit === 0) assert.equal(report.runError, undefined);
				else { assert.match(report.runError, /host exited 23/); assert.match(xml, /host exited 23/); }
			} finally { rmSync(dir, { recursive: true, force: true }); }
		});
	}

	it("installs through the native Windows Electron CLI entry before launching the extension host", { skip: process.platform !== "win32" }, () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			writeStubHost(dir, "process.exit(0);");
			const nativeDir = join(dir, "native");
			const cli = join(nativeDir, "resources/app/out/cli.js");
			mkdirSync(dirname(cli), { recursive: true });
			const executable = join(nativeDir, "Cursor.exe");
			copyFileSync(process.execPath, executable);
			const envLog = join(dir, "native-cli-env.json");
			const hostLog = join(dir, "host-calls.jsonl");
			writeFileSync(cli, `require('node:fs').writeFileSync(process.env.AIDR_TEST_NATIVE_CLI_ENV,JSON.stringify({runAsNode:process.env.ELECTRON_RUN_AS_NODE,dev:process.env.VSCODE_DEV}));\n${readFileSync(join(dir, "stub-host.cjs"), "utf8")}`);
			const result = run(["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", executable], {
				...candidateEnv(dir), AIDR_TEST_NATIVE_CLI_ENV: envLog, AIDR_TEST_HOST_LOG: hostLog,
			});
			assert.match(result.output, /installed candidate VSIX SHA-256/);
			assert.deepEqual(JSON.parse(readFileSync(envLog, "utf8")), { runAsNode: "1", dev: "" });
			const calls = readFileSync(hostLog, "utf8").trim().split("\n").map(line => JSON.parse(line));
			assert.equal(calls.length, 1);
			assert.equal(calls[0][0], "--install-extension");
			assert.equal(result.status, 1, "the fixture intentionally reports no extension-host cases");
			assert.match(result.output, /0\/8 cases passed/);
		} finally { rmSync(dir, { recursive: true, force: true }); }
	});

	it("removes inherited IDE IPC, PID, Node/dev mode and cwd from installation and extension-host launch", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const wrapper = writeStubHost(dir, "process.exit(0);");
			const log = join(dir, "sandbox-env.jsonl");
			const keys = ["VSCODE_IPC_HOOK_CLI", "VSCODE_PID", "ELECTRON_RUN_AS_NODE", "VSCODE_DEV", "VSCODE_CWD"];
			const result = run(["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", wrapper], {
				...candidateEnv(dir), ...Object.fromEntries(keys.map(key => [key, key === "ELECTRON_RUN_AS_NODE" ? "1" : "existing-user-instance"])), AIDR_TEST_SANDBOX_ENV_LOG: log,
			});
			assert.equal(result.status, 1, "zero reported cases must still fail");
			const calls = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line));
			assert.deepEqual(calls.map(call => call.install), [true, false]);
			for (const call of calls) assert.deepEqual(call.vars, Object.fromEntries(keys.map(key => [key, null])));
		} finally { rmSync(dir, { recursive: true, force: true }); }
	});

	it("removes lowercase and mixed-case inherited IDE environment aliases from both real child launches", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const wrapper = writeStubHost(dir, "process.exit(0);");
			const log = join(dir, "sandbox-env.jsonl");
			const aliases = ["electron_run_as_node", "vScOdE_IpC_hOoK_cLi", "vScOdE_PiD", "vscode_dev", "VsCoDe_CwD"];
			const result = run(["--host", "cursor", "--junit", join(dir, "out.xml"), "--exe", wrapper], {
				...candidateEnv(dir), ...Object.fromEntries(aliases.map(key => [key, "existing-user-instance"])), AIDR_TEST_SANDBOX_ENV_LOG: log,
			});
			assert.equal(result.status, 1, "zero reported cases must still fail");
			const calls = readFileSync(log, "utf8").trim().split("\n").map(line => JSON.parse(line));
			assert.deepEqual(calls.map(call => call.install), [true, false]);
			for (const call of calls) assert.deepEqual(call.aliases, [], "no case alias may target an existing user instance or enable Node/dev mode");
		} finally { rmSync(dir, { recursive: true, force: true }); }
	});
});
