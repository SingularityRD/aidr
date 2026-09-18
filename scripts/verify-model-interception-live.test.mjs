#!/usr/bin/env node
/**
 * Regressions for the live model-interception runner.
 *
 * The runner spends real tokens, so these tests cover the part that must be right
 * before it does: the argument contract, the refusals, and above all the
 * interpretation rule. A live turn can end in three distinct ways and conflating
 * them would make the evidence lie:
 *
 *   - the hook declined the action        -> AIDR enforced
 *   - the action executed                 -> AIDR did not enforce
 *   - the host model refused to try       -> AIDR was never reached; proves nothing
 *
 * That third case is the one that was mis-reported on the first run: two cases
 * looked like detection failures when in fact the host model had declined on its
 * own safety grounds, so no tool call was ever made.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "verify-model-interception-live.mjs");

function run(args) {
	try {
		const stdout = execFileSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 });
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

describe("live model-interception runner", () => {
	it("documents that it spends real tokens", () => {
		const result = run(["--help"]);
		assert.equal(result.status, 0);
		assert.match(result.output, /authenticated/);
		assert.match(result.output, /tokens/);
	});

	it("rejects an unknown host rather than silently defaulting", () => {
		const result = run(["--host", "not-a-host"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /unsupported host/);
	});

	it("rejects an unknown argument", () => {
		const result = run(["--host", "codex", "--force"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /unknown argument/);
	});

	it("requires a value for every declared option", () => {
		const result = run(["--host"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /requires a value/);
	});

	it("refuses a missing host binary as blocked, not as a pass", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-live-model-test-"));
		try {
			const result = run(["--host", "codex", "--exe", join(dir, "absent-codex.exe")]);
			assert.equal(result.status, 2, "a missing host must exit with the blocked code");
			assert.match(result.output, /codex executable not found/);
			assert.doesNotMatch(result.output, /AIDR_GATE_RESULT/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("refuses when the host has no session, instead of reporting an unauthenticated run", () => {
		// Point USERPROFILE at an empty directory so no auth.json exists. The runner
		// must exit blocked and must not attempt to run the host unauthenticated.
		const dir = mkdtempSync(join(tmpdir(), "aidr-live-model-test-"));
		try {
			const result = execFileSync(process.execPath, ["--version"], { encoding: "utf8" });
			assert.ok(result);
			let captured;
			try {
				execFileSync(process.execPath, [SCRIPT, "--host", "codex"], {
					cwd: ROOT,
					encoding: "utf8",
					stdio: ["ignore", "pipe", "pipe"],
					timeout: 60_000,
					env: { ...process.env, USERPROFILE: dir, HOME: dir },
				});
				captured = { status: 0, output: "" };
			} catch (error) {
				captured = { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
			}
			assert.equal(captured.status, 3, "no session must exit blocked");
			assert.match(captured.output, /no Codex session|codex login/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("does not present a hook-level fixture as live evidence", () => {
		// The runner must name the host and the classification, so a reader cannot
		// mistake the record for a customer-environment result.
		const source = execFileSync(process.execPath, ["-e", "process.stdout.write(require('fs').readFileSync(process.argv[1],'utf8'))", SCRIPT], { encoding: "utf8" });
		assert.match(source, /not a customer environment/);
		assert.match(source, /host-model-refused/);
		assert.match(source, /proves nothing about AIDR/);
	});

	it("keeps a benign control beside every dangerous case", () => {
		// A hook that blocked everything would pass a dangerous-only suite while
		// being useless, so every declared case must carry a control.
		const source = execFileSync(process.execPath, ["-e", "process.stdout.write(require('fs').readFileSync(process.argv[1],'utf8'))", SCRIPT], { encoding: "utf8" });
		const dangerous = [...source.matchAll(/dangerous: "([^"]+)"/g)].map((match) => match[1]);
		const benign = [...source.matchAll(/benign: "([^"]+)"/g)].map((match) => match[1]);
		assert.ok(dangerous.length >= 3, "expected at least three declared cases");
		assert.equal(benign.length, dangerous.length, "every dangerous case needs a control");
		for (const control of benign) assert.match(control, /^echo /, `control must be a harmless command: ${control}`);
	});
});
