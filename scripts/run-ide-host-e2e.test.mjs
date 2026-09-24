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
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
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
});
