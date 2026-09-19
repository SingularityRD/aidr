#!/usr/bin/env node
/**
 * Regressions for the gate-artifact snapshot helper.
 *
 * The behaviour that matters: a capture must reproduce the source bytes exactly
 * and refuse, without writing anything, whenever the source cannot be trusted as
 * this gate's own output - missing, empty, a directory, or the destination
 * itself. A helper that silently captured an empty file would let a gate bind to
 * nothing and still look proven, which is the defect this script exists to close.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, it } from "node:test";
import { CaptureError, captureArtifact, parseArgs } from "./capture-gate-artifact.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "capture-gate-artifact.mjs");

let workDir;

before(() => {
	workDir = mkdtempSync(join(tmpdir(), "aidr-capture-gate-artifact-"));
});

after(() => {
	rmSync(workDir, { recursive: true, force: true });
});

/** Runs the CLI and captures its status instead of throwing on a non-zero exit. */
function runCli(args) {
	try {
		const output = execFileSync(process.execPath, [SCRIPT, ...args], { cwd: workDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
		return { status: 0, output };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

function writeSource(name, contents) {
	const path = join(workDir, name);
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, contents);
	return path;
}

describe("gate artifact capture", () => {
	it("reproduces the source bytes and reports their digest", () => {
		const source = writeSource("reports/test-results.json", '{"numTotalTests":3,"numPassedTests":3}\n');
		const destination = join(workDir, "snapshots", "11-test-ci-final.test-results.json");

		const captured = captureArtifact({ source, destination, root: workDir, expectJson: true });

		assert.deepEqual(readFileSync(destination), readFileSync(source), "the snapshot is not byte-identical to the source");
		assert.equal(captured.byte_length, readFileSync(source).length);
		assert.equal(captured.sha256, createHash("sha256").update(readFileSync(source)).digest("hex"));
	});

	it("creates the destination directory tree", () => {
		const source = writeSource("reports/nested.json", "{}\n");
		const destination = join(workDir, "deep", "a", "b", "nested.json");
		assert.equal(existsSync(dirname(destination)), false, "the fixture already contained the destination directory");

		captureArtifact({ source, destination, root: workDir });

		assert.ok(existsSync(destination));
	});

	it("refuses a missing source and writes nothing", () => {
		const destination = join(workDir, "snapshots", "absent-source.json");
		assert.throws(
			() => captureArtifact({ source: join(workDir, "reports", "does-not-exist.json"), destination, root: workDir }),
			(error) => error instanceof CaptureError && /is missing/.test(error.message),
		);
		assert.equal(existsSync(destination), false, "a refused capture left a destination behind");
	});

	it("refuses an empty source", () => {
		// An empty report would still hash, so the gate would bind to nothing.
		const source = writeSource("reports/empty.json", "");
		const destination = join(workDir, "snapshots", "empty.json");
		assert.throws(
			() => captureArtifact({ source, destination, root: workDir }),
			(error) => error instanceof CaptureError && /is empty/.test(error.message),
		);
		assert.equal(existsSync(destination), false);
	});

	it("refuses a source that is not a regular file", () => {
		const directorySource = join(workDir, "reports");
		const destination = join(workDir, "snapshots", "directory.json");
		assert.throws(
			() => captureArtifact({ source: directorySource, destination, root: workDir }),
			(error) => error instanceof CaptureError && /not a regular file/.test(error.message),
		);
		assert.equal(existsSync(destination), false);
	});

	it("refuses to copy a path onto itself", () => {
		const source = writeSource("reports/self.json", "{}\n");
		assert.throws(
			() => captureArtifact({ source, destination: source, root: workDir }),
			(error) => error instanceof CaptureError && /same path/.test(error.message),
		);
	});

	it("rejects a source that is not parseable JSON when the gate expects JSON", () => {
		const truncated = writeSource("reports/truncated.json", '{"numTotalTests":4258,"numPassed');
		const destination = join(workDir, "snapshots", "truncated.json");
		assert.throws(
			() => captureArtifact({ source: truncated, destination, root: workDir, expectJson: true }),
			(error) => error instanceof CaptureError && /not parseable JSON/.test(error.message),
		);
		assert.equal(existsSync(destination), false, "a refused capture left a destination behind");
	});

	it("accepts the same truncated bytes when JSON is not required", () => {
		// The JSON check is opt-in, so the helper stays usable for artifacts that
		// are not JSON; without it the bytes are captured unchanged.
		const source = writeSource("reports/plain.txt", "not json at all\n");
		const destination = join(workDir, "snapshots", "plain.txt");
		captureArtifact({ source, destination, root: workDir });
		assert.equal(readFileSync(destination, "utf8"), "not json at all\n");
	});
});

describe("gate artifact capture CLI", () => {
	it("captures successfully and prints the destination", () => {
		const source = writeSource("cli/source.json", '{"numTotalTests":1}\n');
		const destination = join(workDir, "cli", "snapshot.json");
		const result = runCli([source, destination, "--expect-json"]);
		assert.equal(result.status, 0, result.output);
		assert.match(result.output, /capture-gate-artifact/);
		assert.ok(existsSync(destination));
	});

	it("exits non-zero on a missing source", () => {
		const result = runCli([join(workDir, "cli", "missing.json"), join(workDir, "cli", "never.json")]);
		assert.equal(result.status, 1, result.output);
		assert.match(result.output, /is missing/);
		assert.equal(existsSync(join(workDir, "cli", "never.json")), false);
	});

	it("rejects an unknown flag instead of ignoring it", () => {
		assert.throws(() => parseArgs(["--nope"]), (error) => error instanceof CaptureError && /unknown argument/.test(error.message));
		const result = runCli(["--nope"]);
		assert.equal(result.status, 2, result.output);
	});

	it("documents itself", () => {
		const result = runCli(["--help"]);
		assert.equal(result.status, 0, result.output);
		assert.match(result.output, /Usage: node scripts\/capture-gate-artifact\.mjs/);
	});
});
