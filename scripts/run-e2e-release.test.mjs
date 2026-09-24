import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const runnerPath = fileURLToPath(new URL("./run-e2e-release.mjs", import.meta.url));
const candidateDigest = "a".repeat(64);
const fixtureSigningKey = generateKeyPairSync("ed25519");

function externalSuite(id, evidenceEnv) {
	const signatureEnv = `${id.toUpperCase().replaceAll(/[^A-Z0-9]/g, "_")}_RECEIPT_SIGNATURE`;
	return {
		id,
		kind: "external",
		target: `test-${id}`,
		testFile: `test-${id}`,
		expectedTests: 1,
		externalEvidenceEnv: evidenceEnv,
		externalEvidenceSignatureEnv: signatureEnv,
		externalEvidencePublicKeyEnv: "E2E_RECEIPT_PUBLIC_KEY",
		requiredEnv: [evidenceEnv, signatureEnv, "E2E_RECEIPT_PUBLIC_KEY"],
	};
}

function fixture(suites) {
	const root = mkdtempSync(join(tmpdir(), "aidr-e2e-runner-test-"));
	mkdirSync(join(root, "scripts"));
	copyFileSync(runnerPath, join(root, "scripts", "run-e2e-release.mjs"));
	writeFileSync(join(root, "scripts", "e2e-release-manifest.json"), JSON.stringify({ version: 2, suites }));
	writeFileSync(join(root, "external-public.pem"), fixtureSigningKey.publicKey.export({ type: "spki", format: "pem" }));
	return root;
}

function writeReceipt(root, id, overrides = {}) {
	const path = join(root, `${id}-receipt.json`);
	const bytes = Buffer.from(JSON.stringify({
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
	writeFileSync(path, bytes);
	writeFileSync(`${path}.sig`, `${sign(null, bytes, fixtureSigningKey.privateKey).toString("base64")}\n`);
	return path;
}

function run(root, overrides = {}) {
	const env = {
		...process.env,
		AIDR_E2E_EVIDENCE_DIR: join(root, "artifacts"),
		AIDR_E2E_RC_DIGEST: candidateDigest,
		AIDR_E2E_CANDIDATE_BOUND_AT: new Date(Date.now() - 60_000).toISOString(),
		...overrides,
	};
	const manifest = JSON.parse(readFileSync(join(root, "scripts", "e2e-release-manifest.json"), "utf8"));
	for (const suite of manifest.suites) {
		if (suite.kind !== "external") continue;
		const evidencePath = env[suite.externalEvidenceEnv];
		if (evidencePath && env[suite.externalEvidenceSignatureEnv] === undefined) {
			env[suite.externalEvidenceSignatureEnv] = `${evidencePath}.sig`;
		}
		if (env[suite.externalEvidencePublicKeyEnv] === undefined) {
			env[suite.externalEvidencePublicKeyEnv] = join(root, "external-public.pem");
		}
	}
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
		assert.deepEqual(summary.suites.map((suite) => suite.externalEvidence.signatureVerified), [true, true]);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("external gates reject missing or tampered detached signatures", () => {
	for (const tamper of ["missing", "modified"]) {
		const root = fixture([externalSuite("external", "E2E_RECEIPT")]);
		try {
			const receipt = writeReceipt(root, "external");
			if (tamper === "missing") rmSync(`${receipt}.sig`);
			else writeFileSync(receipt, `${readFileSync(receipt, "utf8")} `);
			const { result, summary } = run(root, { E2E_RECEIPT: receipt });
			assert.equal(result.status, 1);
			assert.equal(summary.status, "failed");
			assert.match(summary.suites[0].reasons.join("\n"), /signature verification failed|signature is invalid/);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	}
});

test("external suite manifests cannot omit signature or signer key requirements", () => {
	const root = fixture([externalSuite("external", "E2E_RECEIPT")]);
	try {
		const manifestPath = join(root, "scripts", "e2e-release-manifest.json");
		const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
		delete manifest.suites[0].externalEvidenceSignatureEnv;
		delete manifest.suites[0].externalEvidencePublicKeyEnv;
		writeFileSync(manifestPath, JSON.stringify(manifest));
		const result = spawnSync(process.execPath, [join(root, "scripts", "run-e2e-release.mjs")], {
			cwd: root,
			encoding: "utf8",
			env: { ...process.env, AIDR_E2E_EVIDENCE_DIR: join(root, "artifacts") },
		});
		assert.equal(result.status, 1);
		assert.match(result.stderr, /external evidence requires externalEvidenceSignatureEnv in requiredEnv/);
		assert.equal(existsSync(join(root, "artifacts", "summary.json")), false);
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

test("external gates reject receipts created before the candidate digest was bound", () => {
	const root = fixture([{
		...externalSuite("external", "E2E_RECEIPT"),
		env: { AIDR_E2E_CANDIDATE_BOUND_AT: new Date(Date.now() - 120_000).toISOString() },
	}]);
	try {
		const receipt = writeReceipt(root, "external", {
			generatedAt: new Date(Date.now() - 60_000).toISOString(),
		});
		const boundAt = new Date().toISOString();
		const beforeBinding = run(root, { E2E_RECEIPT: receipt, AIDR_E2E_CANDIDATE_BOUND_AT: boundAt });
		assert.equal(beforeBinding.result.status, 1);
		assert.match(beforeBinding.summary.suites[0].reasons.join("\n"), /predates the bound release candidate digest/);
		const missingBinding = run(root, { E2E_RECEIPT: receipt, AIDR_E2E_CANDIDATE_BOUND_AT: undefined });
		assert.equal(missingBinding.result.status, 1);
		assert.match(missingBinding.summary.suites[0].reasons.join("\n"), /AIDR_E2E_CANDIDATE_BOUND_AT/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("signed host evidence gates a candidate-bound suite before execution", () => {
	const root = fixture([{
		id: "openclaw",
		kind: "command",
		target: "remote OpenClaw host",
		testFile: "openclaw-host.mjs",
		expectedTests: 1,
		command: ["node", "openclaw-host.mjs", "{junit}"],
		externalEvidenceEnv: "OPENCLAW_RECEIPT",
		externalEvidenceSignatureEnv: "OPENCLAW_RECEIPT_SIGNATURE",
		externalEvidencePublicKeyEnv: "OPENCLAW_RECEIPT_PUBLIC_KEY",
		externalEvidenceReleaseVersionEnv: "AIDR_RELEASE_VERSION",
		externalEvidenceHostEnv: "OPENCLAW_E2E_HOST",
		externalEvidenceExpectedTests: 1,
		requiredEnv: ["OPENCLAW_RECEIPT", "OPENCLAW_RECEIPT_SIGNATURE", "OPENCLAW_RECEIPT_PUBLIC_KEY", "AIDR_RELEASE_VERSION", "OPENCLAW_E2E_HOST"],
	}]);
	try {
		const marker = join(root, "openclaw-executed");
		writeFileSync(join(root, "openclaw-host.mjs"), `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(marker)}, "executed");
writeFileSync(process.argv[2], '<testsuites><testsuite tests="1" errors="0" failures="0" skipped="0"><testcase name="candidate host"/></testsuite></testsuites>');
`);
		const receipt = writeReceipt(root, "openclaw", { releaseVersion: "1.2.3", host: "https://openclaw.example" });
		const signaturePath = join(root, "openclaw-receipt.sig");
		const publicKeyPath = join(root, "openclaw-public.pem");
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }));
		const signReceipt = () => writeFileSync(signaturePath, `${sign(null, readFileSync(receipt), privateKey).toString("base64")}\n`);
		signReceipt();
		const environment = {
			OPENCLAW_RECEIPT: receipt,
			OPENCLAW_RECEIPT_SIGNATURE: signaturePath,
			OPENCLAW_RECEIPT_PUBLIC_KEY: publicKeyPath,
			AIDR_RELEASE_VERSION: "1.2.3",
			OPENCLAW_E2E_HOST: "https://openclaw.example",
		};
		const valid = run(root, environment);
		assert.equal(valid.result.status, 0, valid.result.stderr);
		assert.equal(valid.summary.suites[0].externalEvidence.signatureVerified, true);
		assert.equal(existsSync(marker), true);

		rmSync(marker, { force: true });
		writeReceipt(root, "openclaw", { releaseVersion: "9.9.9", host: "https://openclaw.example" });
		signReceipt();
		const wrongVersion = run(root, environment);
		assert.equal(wrongVersion.result.status, 1);
		assert.match(wrongVersion.summary.suites[0].reasons.join("\n"), /releaseVersion does not match/);
		assert.equal(existsSync(marker), false);

		writeReceipt(root, "openclaw", { releaseVersion: "1.2.3", host: "https://openclaw.example" });
		signReceipt();
		writeFileSync(receipt, `${readFileSync(receipt, "utf8")}\n`);
		const tampered = run(root, environment);
		assert.equal(tampered.result.status, 1);
		assert.match(tampered.summary.suites[0].reasons.join("\n"), /signature is invalid/);
		assert.equal(existsSync(marker), false);
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

test("help and invalid arguments never run the release gate or write evidence", () => {
	const root = fixture([externalSuite("external", "E2E_RECEIPT")]);
	try {
		const runner = join(root, "scripts", "run-e2e-release.mjs");
		for (const [args, status] of [[["--help"], 0], [["-h"], 0], [["--help", "--unknown"], 2], [["--unknown"], 2]]) {
			const result = spawnSync(process.execPath, [runner, ...args], {
				cwd: root,
				encoding: "utf8",
				env: { ...process.env, AIDR_E2E_EVIDENCE_DIR: join(root, "artifacts") },
			});
			assert.equal(result.status, status, result.stderr);
			assert.equal(existsSync(join(root, "artifacts")), false);
		}
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("suite logs redact DSNs and credential-bearing URLs", () => {
	const root = fixture([{
		id: "redaction",
		kind: "command",
		target: "redact.mjs",
		testFile: "redact.mjs",
		expectedTests: 1,
		command: ["node", "redact.mjs", "{junit}"],
	}]);
	try {
		writeFileSync(join(root, "redact.mjs"), `import { writeFileSync } from "node:fs";
console.log(process.env.AIG_BRIDGE_TEST_POSTGRES_DSN);
console.error("postgresql://other:independent-password@localhost/private");
writeFileSync(process.argv[2], '<testsuites><testsuite tests="1" errors="0" failures="0" skipped="0"><testcase name="' + process.env.AIG_BRIDGE_TEST_POSTGRES_DSN + '"/><system-out>postgresql://other:xml-password@localhost/private</system-out></testsuite></testsuites>');
`);
		const { result, summary } = run(root, { AIG_BRIDGE_TEST_POSTGRES_DSN: "postgresql://reader:dsn-password@localhost/test" });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(summary.status, "passed");
		const stdout = readFileSync(join(root, "artifacts", "redaction.stdout.log"), "utf8");
		const stderr = readFileSync(join(root, "artifacts", "redaction.stderr.log"), "utf8");
		const junit = readFileSync(join(root, "artifacts", "redaction.xml"), "utf8");
		assert.doesNotMatch(stdout + stderr + junit, /dsn-password|independent-password|xml-password|reader:dsn-password/);
		assert.match(stdout, /\[REDACTED\]/);
		assert.match(stderr, /\[REDACTED\]/);
		assert.match(junit, /\[REDACTED\]/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("local suites block execution without a bound candidate", () => {
	const root = fixture([{
		id: "local",
		kind: "command",
		target: "local.mjs",
		testFile: "local.mjs",
		expectedTests: 1,
		command: ["node", "local.mjs", "{junit}"],
	}]);
	try {
		const marker = join(root, "local-executed");
		writeFileSync(join(root, "local.mjs"), `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(marker)}, "executed");
writeFileSync(process.argv[2], '<testsuites><testsuite tests="1" errors="0" failures="0" skipped="0"><testcase name="local"/></testsuite></testsuites>');
`);
		for (const environment of [
			{ AIDR_E2E_RC_DIGEST: undefined },
			{ AIDR_E2E_CANDIDATE_BOUND_AT: undefined },
			{ AIDR_E2E_CANDIDATE_BOUND_AT: new Date(Date.now() + 60_000).toISOString() },
		]) {
			const { result, summary } = run(root, environment);
			assert.equal(result.status, 1);
			assert.equal(summary.status, "failed");
			assert.equal(summary.suites[0].setupStatus, "blocked");
			assert.equal(existsSync(marker), false);
		}
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("runner setup errors are blocked and summary reasons are redacted", () => {
	const root = fixture([{
		...externalSuite("setup", "E2E_SECRET_TOKEN"),
		homeFiles: { "../escape": "forbidden" },
	}, externalSuite("missing", "E2E_SECRET_TOKEN")]);
	try {
		const { result, summary } = run(root, { E2E_SECRET_TOKEN: "private-receipt-path" });
		assert.equal(result.status, 1);
		assert.equal(summary.suites[0].setupStatus, "blocked");
		assert.match(summary.suites[0].reasons.join("\n"), /runner error: homeFiles path escapes/);
		assert.match(summary.suites[1].reasons.join("\n"), /\[REDACTED\]/);
		assert.doesNotMatch(JSON.stringify(summary) + result.stderr, /private-receipt-path/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("Windows prerequisite .cmd shims are checked without shell-argument deprecations", { skip: process.platform !== "win32" }, () => {
	const root = fixture([{
		id: "cmd-preflight",
		kind: "command",
		target: "preflight.mjs",
		testFile: "preflight.mjs",
		expectedTests: 1,
		requiredCommands: ["probe-cli"],
		command: ["node", "preflight.mjs", "{junit}"],
	}]);
	try {
		writeFileSync(join(root, "probe-cli.cmd"), "@echo off\r\nif \"%1\"==\"--version\" exit /b 0\r\nexit /b 1\r\n");
		writeFileSync(join(root, "preflight.mjs"), `import { writeFileSync } from "node:fs";
writeFileSync(process.argv[2], '<testsuites><testsuite tests="1" errors="0" failures="0" skipped="0"><testcase name="preflight"/></testsuite></testsuites>');
`);
		const { result, summary } = run(root, { PATH: `${root};${process.env.PATH}`, NODE_OPTIONS: "--trace-deprecation" });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(summary.status, "passed");
		assert.doesNotMatch(result.stderr, /DEP0190/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("external evidence symlinks cannot escape the evidence workspace", (context) => {
	const root = fixture([externalSuite("external", "E2E_RECEIPT")]);
	const outside = mkdtempSync(join(tmpdir(), "aidr-e2e-outside-"));
	try {
		const receipt = writeReceipt(outside, "external");
		const link = join(root, "linked-receipt.json");
		try {
			symlinkSync(receipt, link, "file");
		} catch (error) {
			if (error?.code === "EPERM") return context.skip("file symlink permission unavailable");
			throw error;
		}
		const { result, summary } = run(root, { E2E_RECEIPT: link });
		assert.equal(result.status, 1);
		assert.equal(summary.suites[0].setupStatus, "blocked");
		assert.match(summary.suites[0].reasons.join("\n"), /inside the repository\/evidence workspace/);
	} finally {
		rmSync(root, { recursive: true, force: true });
		rmSync(outside, { recursive: true, force: true });
	}
});

test("Windows evidence paths on another drive are rejected before opening", { skip: process.platform !== "win32" }, () => {
	const root = fixture([externalSuite("external", "E2E_RECEIPT")]);
	try {
		const otherDrive = root[0].toUpperCase() === "C" ? "D" : "C";
		const { result, summary } = run(root, { E2E_RECEIPT: `${otherDrive}:\\external-receipt.json` });
		assert.equal(result.status, 1);
		assert.match(summary.suites[0].reasons.join("\n"), /inside the repository\/evidence workspace/);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
