#!/usr/bin/env node
/**
 * Argument-contract regressions for verify-openclaw-release-host.mjs.
 *
 * The gate used to hard-code a 120 s CLI budget and a 10 s per-poll health
 * budget. On the machine it was developed on, OpenClaw's CLI needs ~100 s
 * before its first-run state migration and ~200 s afterwards, so a working host
 * was reported as ETIMEDOUT. These tests pin the operator-visible contract: the
 * default stays strict, an explicit value is honoured, and nonsense is refused
 * rather than silently clamped.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const SCRIPT = join(resolve(dirname(fileURLToPath(import.meta.url))), "verify-openclaw-release-host.mjs");

/** Runs the gate and returns its exit status plus combined output. */
function run(args) {
	try {
		const stdout = execFileSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

describe("OpenClaw release host gate argument contract", () => {
	it("documents --timeout-ms in its own help output", () => {
		const result = run(["--help"]);
		assert.equal(result.status, 0);
		assert.match(result.output, /--timeout-ms/);
	});

	it("still requires --package and --openclaw-root", () => {
		const missingPackage = run(["--openclaw-root", process.cwd()]);
		assert.equal(missingPackage.status, 1);
		assert.match(missingPackage.output, /missing --package/);

		const missingRoot = run(["--package", "plugin.tgz"]);
		assert.equal(missingRoot.status, 1);
		assert.match(missingRoot.output, /missing --openclaw-root/);
	});

	it("rejects an unknown argument instead of ignoring it", () => {
		const result = run(["--package", "plugin.tgz", "--openclaw-root", process.cwd(), "--timeout", "900000"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /unknown argument/);
	});

	it("refuses a timeout outside the supported range", () => {
		for (const value of ["0", "9999", "3600001", "-1", "not-a-number"]) {
			const result = run(["--package", "plugin.tgz", "--openclaw-root", process.cwd(), "--timeout-ms", value]);
			assert.equal(result.status, 1, `--timeout-ms ${value} must be refused`);
			// The value must be rejected on its own merits, not by a later missing-file failure.
			assert.match(result.output, /--timeout-ms must be an integer between 10000 and 3600000/, `--timeout-ms ${value}`);
		}
	});

	it("accepts an in-range timeout and proceeds to real path validation", () => {
		const result = run(["--package", "plugin.tgz", "--openclaw-root", process.cwd(), "--timeout-ms", "900000"]);
		assert.equal(result.status, 1);
		// Past argument parsing: it must now fail because the plugin tarball does not exist.
		assert.match(result.output, /plugin tarball not found/);
		assert.doesNotMatch(result.output, /--timeout-ms must be/);
	});
});
