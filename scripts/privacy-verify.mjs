#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const vitest = resolve(root, "node_modules/vitest/vitest.mjs");
const { values } = parseArgs({
	options: {
		output: { type: "string", default: ".release-evidence/privacy-canary-v6.json" },
	},
});
const sourcePaths = [
	"scripts/privacy-canary.config.mjs",
	"scripts/privacy-canary.test.mjs",
	"scripts/privacy-verify.mjs",
	"packages/core/src/clients/control-plane.ts",
	"packages/core/src/managed.ts",
	"packages/core/src/telemetry-redaction.ts",
	"packages/dashboard/src/sentry.ts",
	"supabase/functions/ingest/events.ts",
	"supabase/functions/discovery/logic.ts",
	"scripts/support-bundle.mjs",
	"scripts/verify-support-bundle.mjs",
];
const started = new Date();

function sourceHashes() {
	return Object.fromEntries(sourcePaths.map((path) => [
		path,
		createHash("sha256").update(readFileSync(resolve(root, path))).digest("hex"),
	]));
}

const testedSourceHashes = sourceHashes();

function run(command, args, timeout, cwd = root) {
	const result = spawnSync(command, args, {
		cwd,
		stdio: "inherit",
		timeout,
		windowsHide: true,
	});
	return {
		passed: result.status === 0 && !result.error,
		exit_code: result.status,
		error_code: result.error?.code ?? null,
	};
}

const tests = run(process.execPath, [vitest, "run", "--config", "scripts/privacy-canary.config.mjs"], 300_000);
const supportCwd = mkdtempSync(resolve(tmpdir(), "aidr-privacy-support-"));
let supportBundle;
try {
	mkdirSync(resolve(supportCwd, ".release-evidence"));
	supportBundle = run(process.execPath, [resolve(root, "scripts/verify-support-bundle.mjs"), "--self-test"], 180_000, supportCwd);
} finally {
	rmSync(supportCwd, { recursive: true, force: true });
}
const finalSourceHashes = sourceHashes();
const sourceStable = sourcePaths.every((path) => testedSourceHashes[path] === finalSourceHashes[path]);
const result = {
	schema_version: 1,
	gate: "privacy-local-canary-v6",
	status: tests.passed && supportBundle.passed && sourceStable ? "LOCAL_PASS" : "LOCAL_FAIL",
	started_at: started.toISOString(),
	finished_at: new Date().toISOString(),
	checks: {
		boundary_canaries: tests,
		support_bundle_self_test: supportBundle,
		source_stable_during_checks: sourceStable,
	},
	coverage: [
		"managed client wire and durable queue credential scrub",
		"default hash/full remote event prompt minimization",
		"direct ingest payload minimization before persistence",
		"runtime and browser diagnostic credential and structured prompt scrub; OTLP endpoint sanitation",
		"discovery target pseudonym-only contract (addresses stay on device)",
		"support bundle allowlist and canary self-test",
	],
	source_sha256: testedSourceHashes,
	field_acceptance: "OPEN",
	legal_approval: "OPEN",
};
const output = resolve(root, values.output);
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`, { encoding: "utf8", flag: "w", mode: 0o600 });
process.stdout.write(`Privacy evidence: ${output} (${result.status})\n`);
if (result.status !== "LOCAL_PASS") process.exitCode = 1;
