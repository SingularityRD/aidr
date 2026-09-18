#!/usr/bin/env node
/**
 * Argument-contract regressions for the live url-check rehearsal.
 *
 * The rehearsal itself needs a running installation, so these tests pin the part
 * that is checkable without one: the script must refuse to run without a real
 * installation, must say so with the blocked exit code rather than a crash, and
 * must not report a pass for an installation it never reached. The provenance
 * rule matters more than the argument parsing: a rehearsal that silently ran
 * against nothing would be indistinguishable from one that passed.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "verify-url-check-live.mjs");

function run(args, options = {}) {
	try {
		const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
			cwd: ROOT,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			...options,
		});
		return { status: 0, output: stdout };
	} catch (error) {
		return { status: error.status ?? 1, output: `${error.stdout ?? ""}${error.stderr ?? ""}` };
	}
}

describe("live url-check rehearsal", () => {
	it("documents its arguments", () => {
		const result = run(["--help"]);
		assert.equal(result.status, 0);
		assert.match(result.output, /--deployment/);
		assert.match(result.output, /--evidence-dir/);
	});

	it("rejects an unknown argument instead of ignoring it", () => {
		const result = run(["--deployment", ".aidr-deploy", "--force"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /unknown argument/);
	});

	it("requires a value for every declared option", () => {
		const result = run(["--deployment"]);
		assert.equal(result.status, 1);
		assert.match(result.output, /requires a value/);
	});

	it("reports a missing installation as blocked, not as a pass", () => {
		const result = run(["--deployment", ".release-evidence/absent-installation-for-test"]);
		// Exit 3 is the blocked code the onboarding verifier also uses for
		// "operator input required"; it must not be 0.
		assert.equal(result.status, 3);
		assert.match(result.output, /no installation at/);
		assert.doesNotMatch(result.output, /AIDR_GATE_RESULT/);
	});

	it("refuses an installation directory that has no deployment manifest", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-urlcheck-test-"));
		try {
			// A directory that exists but is not an installation must be refused the
			// same way, rather than producing a confusing downstream failure.
			const result = run(["--deployment", dir]);
			assert.equal(result.status, 3);
			assert.match(result.output, /deployment\.json is missing/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	it("refuses an installation whose env has no service role key", () => {
		const dir = mkdtempSync(join(tmpdir(), "aidr-urlcheck-test-"));
		try {
			writeFileSync(join(dir, "deployment.json"), JSON.stringify({ mode: "self-hosted", supabase_url: "http://127.0.0.1:8000" }));
			writeFileSync(join(dir, ".env"), "ANON_KEY=something\n");
			const result = run(["--deployment", dir]);
			assert.equal(result.status, 1);
			assert.match(result.output, /no SERVICE_ROLE_KEY/);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});
