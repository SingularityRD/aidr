import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const runnerPath = fileURLToPath(new URL("./run-e2e-release.mjs", import.meta.url));
const candidateDigest = "a".repeat(64);

function externalSuite(id, evidenceEnv) {
	return {
		id,
		kind: "external",
		target: `test-${id}`,
		testFile: `test-${id}`,
		expectedTests: 1,
		externalEvidenceEnv: evidenceEnv,
		requiredEnv: [evidenceEnv],
	};
}

function fixture(suites) {
	const root = mkdtempSync(join(tmpdir(), "aidr-e2e-runner-test-"));
	mkdirSync(join(root, "scripts"));
	copyFileSync(runnerPath, join(root, "scripts", "run-e2e-release.mjs"));
	writeFileSync(join(root, "scripts", "e2e-release-manifest.json"), JSON.stringify({ version: 2, suites }));
	return root;
}

function writeReceipt(root, id, overrides = {}) {
	const path = join(root, `${id}-receipt.json`);
	writeFileSync(path, JSON.stringify({
		schemaVersion: "aidr-e2e-external-v1",
		suiteId: id,
		status: "passed",
		redacted: true,
		generatedAt: new Date().toISOString(),
		rcDigest: candidateDigest,
		attestation: "fixture attestation",
		assertions: [{ status: "passed" }],
		...overrides,
	}));
	return path;
}

function run(root, overrides = {}) {
	const env = {
		...process.env,
		AIDR_E2E_EVIDENCE_DIR: join(root, "artifacts"),
		AIDR_E2E_RC_DIGEST: candidateDigest,
		...overrides,
	};
	for (const [key, value] of Object.entries(env)) if (value === undefined) delete env[key];
	const result = spawnSync(process.execPath, [join(root, "scripts", "run-e2e-release.mjs")], {
		cwd: root,
		encoding: "utf8",
		env,
		timeout: 15_000,
	});
	const summary = JSON.parse(readFileSync(join(root, "artifacts", "summary.json"), "utf8"));
	return { result, summary };
}

test("external gates pass only with fresh receipts for the same candidate", () => {
	const root = fixture([externalSuite("first", "E2E_FIRST"), externalSuite("second", "E2E_SECOND")]);
	try {
		const first = writeReceipt(root, "first");
		const second = writeReceipt(root, "second", { rcDigest: `sha256:${candidateDigest.toUpperCase()}` });
		const { result, summary } = run(root, { E2E_FIRST: first, E2E_SECOND: second });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(summary.status, "passed");
		assert.equal(summary.environment.candidateDigest, candidateDigest);
		assert.deepEqual(summary.suites.map((suite) => suite.externalEvidence.rcDigest), [candidateDigest, candidateDigest]);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("external gates reject stale and mismatched candidate receipts", () => {
	const root = fixture([externalSuite("external", "E2E_RECEIPT")]);
	try {
		const receipt = writeReceipt(root, "external", {
			generatedAt: new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(),
			rcDigest: "b".repeat(64),
		});
		const { result, summary } = run(root, { E2E_RECEIPT: receipt });
		assert.equal(result.status, 1);
		assert.equal(summary.status, "failed");
		assert.match(summary.suites[0].reasons.join("\n"), /stale/);
		assert.match(summary.suites[0].reasons.join("\n"), /does not match/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("external gates reject missing candidate and future timestamps", () => {
	const root = fixture([externalSuite("external", "E2E_RECEIPT")]);
	try {
		const receipt = writeReceipt(root, "external", {
			generatedAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
		});
		const missing = run(root, { E2E_RECEIPT: receipt, AIDR_E2E_RC_DIGEST: undefined });
		assert.equal(missing.result.status, 1);
		assert.match(missing.summary.suites[0].reasons.join("\n"), /AIDR_E2E_RC_DIGEST/);
		const future = run(root, { E2E_RECEIPT: receipt });
		assert.equal(future.result.status, 1);
		assert.match(future.summary.suites[0].reasons.join("\n"), /future/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("command suites fail closed at their configured timeout", () => {
	const root = fixture([{
		id: "hung-command",
		kind: "command",
		target: "hold.mjs",
		testFile: "hold.mjs",
		expectedTests: 1,
		timeoutMs: 100,
		command: ["node", "hold.mjs"],
	}]);
	try {
		writeFileSync(join(root, "hold.mjs"), "setTimeout(() => {}, 10000);\n");
		const { result, summary } = run(root);
		assert.equal(result.status, 1);
		assert.equal(summary.suites[0].timeoutMs, 100);
		assert.match(summary.suites[0].reasons.join("\n"), /process error|process exit/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("command suites reject JUnit suite errors even when a testcase says passed", () => {
	const root = fixture([{
		id: "junit-error",
		kind: "command",
		target: "write-junit.mjs",
		testFile: "write-junit.mjs",
		expectedTests: 1,
		command: ["node", "write-junit.mjs", "{junit}"],
	}]);
	try {
		writeFileSync(join(root, "write-junit.mjs"), `import { writeFileSync } from "node:fs";
writeFileSync(process.argv[2], '<testsuites><testsuite tests="1" errors="1" failures="0" skipped="0"><testcase name="passed"/></testsuite></testsuites>');
`);
		const { result, summary } = run(root);
		assert.equal(result.status, 1);
		assert.match(summary.suites[0].reasons.join("\n"), /report success=false/);
		writeFileSync(join(root, "write-junit.mjs"), `import { writeFileSync } from "node:fs";
writeFileSync(process.argv[2], '<testsuites><testsuite tests="1" errors="0" failures="0" skipped="0"><testcase name="passed"/></testsuite></testsuites>');
`);
		const valid = run(root);
		assert.equal(valid.result.status, 0, valid.result.stderr);
		assert.equal(valid.summary.status, "passed");
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
