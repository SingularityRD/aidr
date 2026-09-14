/**
 * Unit coverage for the install gate's exported verification logic.
 *
 * The fixtures are minimal fabricated packages, so the suite never depends on
 * `pnpm build:release` having run, on the repository's `dist/` output, or on
 * the network.
 */

import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
	FAIL,
	PASS,
	RELEASE_PACKAGES,
	SKIPPED_WITH_REASON,
	classifyRunFailure,
	collectDeclaredArtifacts,
	createTempWorkspace,
	findForbiddenEntries,
	listPackageEntries,
	removePath,
	sanitizedEnvironment,
	verifyExtractedPackage,
	verifyPackageInstall,
} from "./verify-package-install.mjs";

function fixtureRoot(label) {
	const root = path.join(tmpdir(), `aidr-install-test-${label}-${process.pid.toString(36)}-${Date.now().toString(36)}`);
	mkdirSync(path.join(root, "dist"), { recursive: true });
	return root;
}

function writePackage(root, options = {}) {
	const {
		name = "@example/fixture",
		version = "1.0.0",
		license = "Proprietary",
		bin = { fixture: "dist/cli.cjs" },
		exports = { ".": { types: "./dist/index.d.ts", import: "./dist/index.js" } },
		files = ["dist/**"],
		main,
		createBin = true,
		createExports = true,
		createFiles = true,
	} = options;
	const manifest = { name, version, license, type: "module", bin, exports, files };
	if (main !== undefined) manifest.main = main;
	writeFileSync(path.join(root, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
	if (createBin) writeFileSync(path.join(root, "dist", "cli.cjs"), "#!/usr/bin/env node\nconsole.log('fixture');\n", "utf8");
	if (createExports) {
		writeFileSync(path.join(root, "dist", "index.js"), "export const answer = 42;\n", "utf8");
		writeFileSync(path.join(root, "dist", "index.d.ts"), "export declare const answer: number;\n", "utf8");
	}
	if (createFiles) writeFileSync(path.join(root, "dist", "asset.json"), '{"ok":true}\n', "utf8");
	return manifest;
}

async function runFixture(label, options = {}, verification = {}) {
	const root = fixtureRoot(label);
	try {
		writePackage(root, options);
		if (typeof options.prepare === "function") options.prepare(root);
		return await verifyExtractedPackage({
			packageDir: root,
			runs: verification.runs ?? [],
			runner: verification.runner,
			strictFiles: verification.strictFiles,
			platformAssets: verification.platformAssets,
		});
	} finally {
		removePath(root);
	}
}

const passingRunner = () => ({ status: PASS });

test("a minimal package with a declared bin and exports passes", async () => {
	const result = await runFixture("pass", {}, { runs: [{ id: "fixture import", kind: "import" }], runner: passingRunner });
	assert.equal(result.status, PASS);
	assert.deepEqual(result.failures, []);
	assert.equal(result.artifacts.declared, 4); // bin.fixture, exports["."], files "dist/**", types target is inside exports
	assert.equal(result.artifacts.verified, 4);
	assert.equal(result.runResults.length, 1);
	assert.equal(result.runResults[0].status, PASS);
});

test("a missing bin target fails", async () => {
	const result = await runFixture("missing-bin", { createBin: false });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["MISSING_BIN_TARGET"],
	);
	assert.match(result.failures[0].detail, /dist\/cli\.cjs/);
});

test("a missing exports target fails", async () => {
	const result = await runFixture("missing-exports", { createExports: false });
	assert.equal(result.status, FAIL);
	const codes = result.failures.map((failure) => failure.code);
	assert.ok(codes.includes("MISSING_EXPORTS_TARGET"), `expected MISSING_EXPORTS_TARGET in ${codes.join(", ")}`);
});

test("a missing files entry fails", async () => {
	const result = await runFixture("missing-files", { files: ["dist/**", "missing/**"] });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["MISSING_FILES_ENTRY"],
	);
});

test("a package containing a *.map file fails", async () => {
	const result = await runFixture("sourcemap", {
		prepare: (root) => writeFileSync(path.join(root, "dist", "index.js.map"), "{}\n", "utf8"),
	});
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["SOURCE_MAP_PRESENT"],
	);
});

test("a package containing a test/ directory fails", async () => {
	const result = await runFixture("test-dir", {
		prepare: (root) => {
			mkdirSync(path.join(root, "test"), { recursive: true });
			writeFileSync(path.join(root, "test", "index.test.js"), "// test\n", "utf8");
		},
	});
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["TEST_DIRECTORY_PRESENT"],
	);
});

test("a package containing a node_modules/ directory fails", async () => {
	const result = await runFixture("node-modules", {
		prepare: (root) => {
			mkdirSync(path.join(root, "node_modules", "left-pad"), { recursive: true });
			writeFileSync(path.join(root, "node_modules", "left-pad", "index.js"), "module.exports = 1;\n", "utf8");
		},
	});
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["NODE_MODULES_PRESENT"],
	);
});

test("a package containing a .env file fails", async () => {
	const result = await runFixture("env-file", {
		prepare: (root) => writeFileSync(path.join(root, ".env.local"), "SECRET=1\n", "utf8"),
	});
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["ENV_FILE_PRESENT"],
	);
});

test("a package with an empty license fails", async () => {
	const result = await runFixture("empty-license", { license: "" });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["EMPTY_LICENSE_FIELD"],
	);
});

test("a package with an empty version fails", async () => {
	const result = await runFixture("empty-version", { version: "" });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["EMPTY_VERSION_FIELD"],
	);
});

test("an UNSUPPORTED reason is propagated instead of becoming a pass", async () => {
	const reason = "UNSUPPORTED host: the vscode extension host does not exist in a Node-only consumer process";
	const result = await runFixture(
		"unsupported",
		{},
		{ runs: [{ id: "extension host entry", kind: "import", host: "vscode" }], runner: () => ({ status: SKIPPED_WITH_REASON, reason }) },
	);
	assert.notEqual(result.status, PASS);
	assert.equal(result.status, SKIPPED_WITH_REASON);
	assert.equal(result.skips.length, 1);
	assert.equal(result.skips[0].id, "extension host entry");
	assert.equal(result.skips[0].scope, "run");
	assert.equal(result.skips[0].reason, reason);
	assert.equal(result.runResults[0].status, SKIPPED_WITH_REASON);
	assert.deepEqual(result.failures, []);
});

test("a declared documentation files entry is reported as a skip, not a failure", async () => {	const result = await runFixture("doc-entry", { files: ["dist/**", "LICENSE", "README.md"] });
	assert.equal(result.status, PASS);
	assert.deepEqual(result.failures, []);
	assert.equal(result.skips.length, 2);
	assert.ok(result.skips.every((skip) => skip.scope === "artefact"));
	assert.match(result.skips[0].reason, /matches no file in the tarball/);
});

test("--strict-files turns a declared documentation files entry into a failure", async () => {
	const result = await runFixture("strict-doc-entry", { files: ["dist/**", "LICENSE"] }, { strictFiles: true });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["MISSING_FILES_ENTRY"],
	);
});

test("a run that fails produces a machine-readable failure", async () => {
	const result = await runFixture("run-failure", {}, { runs: [{ id: "fixture bin --help", kind: "bin" }], runner: () => ({ status: FAIL, detail: "exited 1: boom" }) });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["RUN_FAILED"],
	);
	assert.match(result.failures[0].detail, /boom/);
});

test("a module-resolution failure is classified as an environmental skip", () => {
	const classified = classifyRunFailure({ status: 1, stderr: "Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'pino' imported from /tmp/x.js", stdout: "" });
	assert.equal(classified.status, SKIPPED_WITH_REASON);
	assert.match(classified.reason, /UNSUPPORTED dependency/);
	assert.match(classified.reason, /pino/);
});

test("a native payload failure is classified as an environmental skip", () => {
	const classified = classifyRunFailure({ status: 1, stderr: "Error: \\\\?\\C:\\x\\koffi.node is not a valid Win32 application.", stdout: "" });
	assert.equal(classified.status, SKIPPED_WITH_REASON);
	assert.match(classified.reason, /UNSUPPORTED host/);
});

test("an ordinary crash is classified as a failure", () => {
	const classified = classifyRunFailure({ status: 1, stderr: "TypeError: undefined is not a function", stdout: "" });
	assert.equal(classified.status, FAIL);
});

test("the sanitised environment has an empty PATH and a private home", () => {
	const home = path.join(tmpdir(), "aidr-install-test-home");
	const emptyPath = path.join(tmpdir(), "aidr-install-test-empty-path");
	mkdirSync(emptyPath, { recursive: true });
	try {
		const environment = sanitizedEnvironment({ home, emptyPathDir: emptyPath });
		assert.equal(environment.PATH, emptyPath);
		assert.equal(environment.HOME, home);
		assert.equal(environment.USERPROFILE, home);
		assert.equal(environment.AIDR_THREATS_DIR, undefined);
		assert.equal(environment.NODE_PATH, undefined);
		assert.equal(environment.npm_config_user_agent, undefined);
		assert.equal(environment.CI, "1");
	} finally {
		removePath(emptyPath);
	}
});

test("the declared artefact collector flattens bins, exports and files", () => {
	const artifacts = collectDeclaredArtifacts({
		bin: { aidr: "./dist/index.js", "aidr-setup": "./dist/index.js" },
		main: "./dist/index.cjs",
		files: ["dist/**", "resources/**"],
		exports: { ".": { import: "./dist/index.mjs", require: { default: "./dist/index.cjs" } }, "./sub": "./dist/sub.js" },
	});
	const targets = artifacts.map((artifact) => `${artifact.kind}:${artifact.target}`);
	assert.deepEqual(targets, [
		"bin:./dist/index.js",
		"bin:./dist/index.js",
		"main:./dist/index.cjs",
		"exports:./dist/index.mjs",
		"exports:./dist/index.cjs",
		"exports:./dist/sub.js",
		"files:dist/**",
		"files:resources/**",
	]);
});

test("cleanup removes every temporary directory it created", () => {
	const workspace = createTempWorkspace("aidr-install-test-cleanup-");
	const nested = workspace.directory("nested");
	mkdirSync(path.join(nested, "deep", "deeper"), { recursive: true });
	writeFileSync(path.join(nested, "deep", "deeper", "file.txt"), "x\n", "utf8");
	const root = workspace.root;
	assert.ok(existsSync(root));
	workspace.dispose();
	assert.equal(existsSync(root), false);
	assert.equal(existsSync(nested), false);
});

test("removePath reports success and leaves nothing behind", () => {
	const workspace = createTempWorkspace("aidr-install-test-remove-");
	const target = workspace.directory("target");
	writeFileSync(path.join(target, "file.txt"), "x\n", "utf8");
	assert.equal(removePath(target), true);
	assert.equal(existsSync(target), false);
	workspace.dispose();
});

test("the repository's own packed layout is described by the same rules", () => {
	// `listPackageEntries` and `findForbiddenEntries` are the only readers of an
	// extracted package; both must agree with the shared sourcemap rules.
	const root = fixtureRoot("entries");
	try {
		writePackage(root);
		const entries = listPackageEntries(root);
		assert.ok(entries.includes("dist/index.js"));
		assert.ok(entries.includes("package.json"));
		assert.deepEqual(findForbiddenEntries(root), []);
		writeFileSync(path.join(root, "dist", "index.js.map"), "{}\n", "utf8");
		assert.deepEqual(
			findForbiddenEntries(root).map((violation) => violation.code),
			["SOURCE_MAP_PRESENT"],
		);
	} finally {
		removePath(root);
	}
});

test("a package whose manifest cannot be read fails instead of passing", async () => {
	const root = fixtureRoot("no-manifest");
	try {
		const result = await verifyExtractedPackage({ packageDir: root, runs: [], runner: passingRunner });
		assert.equal(result.status, FAIL);
		assert.deepEqual(
			result.failures.map((failure) => failure.code),
			["MISSING_PACKAGE_JSON"],
		);
	} finally {
		removePath(root);
	}
});

test("a declared path that escapes the package fails", async () => {
	const result = await runFixture("escape", { bin: { fixture: "../outside.cjs" } });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["DECLARED_PATH_ESCAPES_PACKAGE"],
	);
});

test("a missing platform-specific native payload fails", async () => {
	const result = await runFixture("platform-asset", {}, { platformAssets: { [process.platform]: ["dist/vendor/native.node"] } });
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["MISSING_PLATFORM_ASSET"],
	);
	assert.match(result.failures[0].detail, /dist\/vendor\/native\.node/);
});

test("a present platform-specific native payload is verified by path", async () => {
	const result = await runFixture(
		"platform-asset-present",
		{ prepare: (root) => writeFileSync(path.join(root, "dist", "native.node"), "binary\n", "utf8") },
		{ platformAssets: { [process.platform]: ["dist/native.node"] } },
	);
	assert.equal(result.status, PASS);
	assert.deepEqual(result.failures, []);
	assert.equal(result.artifacts.verified, 5);
});

test("another platform's native payload is reported as an unsupported host, not a failure", async () => {
	const foreign = process.platform === "win32" ? "linux" : "win32";
	const result = await runFixture("foreign-platform", {}, { platformAssets: { [foreign]: ["dist/vendor/koffi/build/koffi/win32_x64/koffi.node"] } });
	assert.equal(result.status, PASS);
	assert.deepEqual(result.failures, []);
	assert.equal(result.skips.length, 1);
	assert.equal(result.skips[0].scope, "artefact");
	assert.match(result.skips[0].reason, /UNSUPPORTED host/);
	assert.match(result.skips[0].reason, new RegExp(process.platform));
});

test("the gate exports its per-package verification entry points for the ten release packages", () => {
	assert.equal(typeof verifyPackageInstall, "function");
	assert.equal(typeof verifyExtractedPackage, "function");
	assert.deepEqual(
		RELEASE_PACKAGES.map((spec) => spec.key),
		[
			"packages/core",
			"packages/claude-code",
			"packages/extension",
			"packages/openclaw",
			"packages/opencode",
			"packages/cli",
			"packages/sdk",
			"packages/dashboard",
			"packages/codex",
			"packages/mcp-gateway",
		],
	);
	for (const spec of RELEASE_PACKAGES) {
		assert.ok(Array.isArray(spec.runs) && spec.runs.length > 0, `${spec.key} must declare at least one exercised entry point`);
	}
});

test("the packaged manifest is the one that is verified", async () => {
	const root = fixtureRoot("manifest");
	try {
		writePackage(root);
		const before = readFileSync(path.join(root, "package.json"), "utf8");
		const result = await verifyExtractedPackage({ packageDir: root, runs: [], runner: passingRunner });
		assert.equal(result.status, PASS);
		assert.equal(result.packageName, "@example/fixture");
		assert.equal(readFileSync(path.join(root, "package.json"), "utf8"), before);
	} finally {
		removePath(root);
	}
});
