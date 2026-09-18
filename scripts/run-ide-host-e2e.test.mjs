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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "run-ide-host-e2e.mjs");

function run(args) {
	try {
		const stdout = execFileSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
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

	it("refuses a missing host binary as blocked rather than reporting a pass", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const junit = join(dir, "out.xml");
			const result = run(["--host", "cursor", "--junit", junit, "--exe", join(dir, "absent-Cursor.exe")]);
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
		// A stand-in "host" that exits 0 without doing anything. The runner must
		// treat that as eight missing cases, not as success. The stub is reached
		// through a wrapper because Node rejects the host's own CLI flags.
		const dir = mkdtempSync(join(tmpdir(), "aidr-ide-runner-test-"));
		try {
			const stub = join(dir, "silent-host.cjs");
			writeFileSync(stub, "process.exit(0);\n");
			const wrapperDir = join(dir, "bin");
			mkdirSync(wrapperDir, { recursive: true });
			const wrapper = join(wrapperDir, process.platform === "win32" ? "silent-host.cmd" : "silent-host");
			if (process.platform === "win32") {
				writeFileSync(wrapper, `@echo off\r\n"${process.execPath}" "${stub}"\r\n`);
			} else {
				writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${stub}"\n`, { mode: 0o755 });
			}

			const junit = join(dir, "out.xml");
			const result = run(["--host", "cursor", "--junit", junit, "--exe", wrapper]);

			assert.equal(result.status, 1, "a host that ran nothing must not exit zero");
			assert.match(result.output, /0\/8 cases passed/);
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
			// Node rejects the host's `--extensionDevelopmentPath` flags outright, so
			// this stub is invoked through a wrapper that swallows them. The stub then
			// writes only the cases it was handed, which is what a host that dies
			// midway does.
			const stub = join(dir, "partial-host.cjs");
			writeFileSync(
				stub,
				[
					"const fs=require('node:fs');",
					"fs.writeFileSync(process.env.AIDR_E2E_RESULTS_FILE, JSON.stringify({host:'cursor',cases:[",
					"  {id:'configure-workspace-scope',status:'pass',durationMs:1},",
					"  {id:'extension-activates',status:'fail',error:'boom'}",
					"]}));",
					"process.exit(0);",
				].join("\n"),
			);
			const wrapperDir = join(dir, "bin");
			mkdirSync(wrapperDir, { recursive: true });
			const wrapper = join(wrapperDir, process.platform === "win32" ? "stub-host.cmd" : "stub-host");
			if (process.platform === "win32") {
				writeFileSync(wrapper, `@echo off\r\n"${process.execPath}" "${stub}"\r\n`);
			} else {
				writeFileSync(wrapper, `#!/bin/sh\nexec "${process.execPath}" "${stub}"\n`, { mode: 0o755 });
			}

			const junit = join(dir, "out.xml");
			const result = run(["--host", "cursor", "--junit", junit, "--exe", wrapper]);

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
