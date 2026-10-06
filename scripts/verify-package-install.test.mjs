/**
 * Unit coverage for the install gate's exported verification logic.
 *
 * Fixtures are fabricated packages or isolated source bundles; the suite never depends on
 * `pnpm build:release` having run, on the repository's `dist/` output, or on
 * the network.
 */

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { existsSync, linkSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { duplicateBins, verifyWorkspaceBins } from "./check-publishable-bins.mjs";
import {
	FAIL,
	PASS,
	RELEASE_PACKAGES,
	SKIPPED_WITH_REASON,
	applicableLifecycleDependencies,
	applyInstallOutcome,
	applyLifecycleInstallOutcome,
	classifyRunFailure,
	collectDeclaredArtifacts,
	createTempWorkspace,
	defaultRunner,
	findForbiddenEntries,
	gateExitCode,
	listPackageEntries,
	packageManagerEnvironment,
	packageInstallArguments,
	parseArguments,
	installedBinShimPath,
	lifecycleDependencySkips,
	provisionNodeRuntime,
	provisionArtifactTrust,
	redactUrlCredentials,
	releaseTarballPath,
	removePath,
	resolvePosixPnpmExecutable,
	resolveWindowsPnpmExecutable,
	runInstalledBin,
	runPnpm,
	sanitizedEnvironment,
	verifyExtractedPackage,
	verifyPackageInstall,
} from "./verify-package-install.mjs";
import { hasForbiddenArchiveEntry, isConsumerArchive } from "./lib/package-artifact-rules.mjs";
import { buildGatewayPackageFixture } from "../packages/mcp-gateway/scripts/library-fixture.mjs";

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

test("--tarball-dir selects immutable release inputs", () => {
	const options = parseArguments(["--tarball-dir", "release-output", "packages/core"]);
	assert.equal(options.tarballDir, path.resolve("release-output"));
	assert.deepEqual(options.requested, ["packages/core"]);
	assert.deepEqual(options.unknown, []);
});

test("release tarball lookup requires the exact package name and version", () => {
	const root = fixtureRoot("exact-tarball");
	try {
		const spec = RELEASE_PACKAGES.find((entry) => entry.key === "packages/core");
		const pkg = JSON.parse(readFileSync(path.resolve(spec.key, "package.json"), "utf8"));
		const expected = path.join(root, `${pkg.name.replace(/^@/, "").replace("/", "-")}-${pkg.version}.tgz`);
		writeFileSync(expected, "exact candidate bytes");
		assert.equal(releaseTarballPath({ spec, tarballDir: root }), expected);
	} finally {
		removePath(root);
	}
});

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

test("packaged JavaScript rejects sourceMappingURL and sourceURL directives", async () => {
	const result = await runFixture("source-directives", {
		prepare: (root) => writeFileSync(path.join(root, "dist", "index.js"), "//# sourceMappingURL=index.js.map\n//# sourceURL=fixture.js\n", "utf8"),
	});
	assert.equal(result.status, FAIL);
	assert.deepEqual(
		result.failures.map((failure) => failure.code),
		["SOURCE_MAPPING_URL_PRESENT", "SOURCE_URL_PRESENT"],
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

test("a failed consumer install is fail-closed", () => {
	const result = { status: PASS, failures: [] };
	applyInstallOutcome(result, { ok: false, error: "registry unavailable" });
	assert.equal(result.status, FAIL);
	assert.deepEqual(result.failures, [{ code: "INSTALL_FAILED", detail: "registry unavailable" }]);
});

test("a failed lifecycle-enabled install is fail-closed", () => {
	const result = { status: PASS, failures: [] };
	applyLifecycleInstallOutcome(result, { ok: false, error: "koffi install failed" });
	assert.equal(result.status, FAIL);
	assert.deepEqual(result.failures, [{ code: "LIFECYCLE_INSTALL_FAILED", detail: "koffi install failed" }]);
});

test("the gate succeeds only when every package passes", () => {
	assert.equal(gateExitCode([{ status: PASS }, { status: PASS }]), 0);
	assert.equal(gateExitCode([{ status: PASS }, { status: SKIPPED_WITH_REASON }]), 1);
	assert.equal(gateExitCode([{ status: PASS }, { status: FAIL }]), 1);
	assert.equal(gateExitCode([]), 1);
});

test("the sanitised environment has an empty PATH and a private home", () => {
	const home = path.join(tmpdir(), "aidr-install-test-home");
	const emptyPath = path.join(tmpdir(), "aidr-install-test-empty-path");
	const previousSecret = process.env.AWS_SECRET_ACCESS_KEY;
	const previousToken = process.env.GITHUB_TOKEN;
	process.env.AWS_SECRET_ACCESS_KEY = "must-not-leak";
	process.env.GITHUB_TOKEN = "must-not-leak";
	mkdirSync(emptyPath, { recursive: true });
	try {
		const environment = sanitizedEnvironment({ home, emptyPathDir: emptyPath });
		assert.equal(environment.PATH, emptyPath);
		assert.equal(environment.HOME, home);
		assert.equal(environment.USERPROFILE, home);
		assert.equal(environment.AIDR_THREATS_DIR, undefined);
		assert.equal(environment.NODE_PATH, undefined);
		assert.equal(environment.npm_config_user_agent, undefined);
		assert.equal(environment.AWS_SECRET_ACCESS_KEY, undefined);
		assert.equal(environment.GITHUB_TOKEN, undefined);
		assert.equal(environment.CI, "1");
	} finally {
		if (previousSecret === undefined) delete process.env.AWS_SECRET_ACCESS_KEY;
		else process.env.AWS_SECRET_ACCESS_KEY = previousSecret;
		if (previousToken === undefined) delete process.env.GITHUB_TOKEN;
		else process.env.GITHUB_TOKEN = previousToken;
		removePath(emptyPath);
	}
});

test("credential-bearing proxy URLs are rejected without echoing credentials", () => {
	const options = {
		home: path.join(tmpdir(), "aidr-install-test-proxy-home"),
		emptyPathDir: path.join(tmpdir(), "aidr-install-test-proxy-path"),
		source: { HTTPS_PROXY: "http://alice:super-secret@proxy.example:8080" },
	};
	assert.throws(
		() => packageManagerEnvironment(options),
		(error) => {
			assert.match(error.message, /Credential-bearing HTTPS_PROXY is not allowed/);
			assert.doesNotMatch(error.message, /alice|super-secret/);
			return true;
		},
	);
});

test("credential-bearing proxy URLs are redacted from package-manager logs", () => {
	const output = redactUrlCredentials(
		"fetch https://build-user:token-123@registry.example/pkg via socks5://proxy-user:proxy-pass@proxy.example:1080",
	);
	assert.equal(output, "fetch https://<redacted>@registry.example/pkg via socks5://<redacted>@proxy.example:1080");
	assert.doesNotMatch(output, /build-user|token-123|proxy-user|proxy-pass/);
});

test("an absolute executable POSIX pnpm shim runs directly without a shell", () => {
	const shim = path.resolve(path.parse(process.cwd()).root, "opt", "pnpm", "pnpm");
	const executable = resolvePosixPnpmExecutable(shim, {
		realpath: () => shim,
		stat: () => ({ isFile: () => true, mode: 0o100755 }),
	});
	assert.deepEqual(executable, { file: shim, viaNode: false, commandDirectory: path.dirname(shim) });
	assert.equal(
		resolvePosixPnpmExecutable("relative/pnpm", {
			realpath: () => "relative/pnpm",
			stat: () => ({ isFile: () => true, mode: 0o100755 }),
		}),
		null,
	);
});

test("Windows pnpm native and cmd shims resolve without executing cmd.exe", () => {
	const metadata = { isFile: () => true, size: 1024 };
	const options = {
		pathApi: path.win32,
		realpath: (value) => path.win32.normalize(value),
		stat: () => metadata,
		readFile: () => String.raw`@echo off
"%~dp0\node.exe" "%~dp0\node_modules\pnpm\bin\pnpm.cjs" %*`,
	};
	assert.deepEqual(resolveWindowsPnpmExecutable("C:\\pnpm home\\pnpm.exe", options), {
		file: "C:\\pnpm home\\pnpm.exe",
		viaNode: false,
		commandDirectory: "C:\\pnpm home",
	});
	assert.deepEqual(resolveWindowsPnpmExecutable("C:\\pnpm home\\pnpm.cmd", options), {
		file: "C:\\pnpm home\\node_modules\\pnpm\\bin\\pnpm.cjs",
		viaNode: true,
		commandDirectory: "C:\\pnpm home",
	});
	assert.equal(resolveWindowsPnpmExecutable("relative\\pnpm.cmd", options), null);
	assert.equal(resolveWindowsPnpmExecutable("C:\\pnpm home\\pnpm.cmd", { ...options, readFile: () => "@echo off & calc.exe" }), null);
});

test("pnpm lifecycle children resolve the trusted package manager from the sanitised PATH", () => {
	const workspace = createTempWorkspace("aidr-install-test-pnpm-lifecycle-");
	try {
		const packageManager = JSON.parse(readFileSync(path.join(import.meta.dirname, "..", "package.json"), "utf8")).packageManager;
		const pinnedVersion = packageManager.replace(/^pnpm@/u, "");
		const packageRoot = workspace.directory("package");
		const home = workspace.directory("home");
		const runtimeRoot = workspace.directory("runtime");
		provisionNodeRuntime(runtimeRoot);
		writeFileSync(
			path.join(packageRoot, "package.json"),
			`${JSON.stringify({ name: "pnpm-lifecycle-fixture", private: true, packageManager, scripts: { verify: `node -e "if (process.env.COREPACK_ENABLE_NETWORK !== '0') process.exit(1)" && pnpm --version` } }, null, 2)}\n`,
			"utf8",
		);
		const environment = packageManagerEnvironment({ home, emptyPathDir: runtimeRoot, source: {} });
		const result = runPnpm(["run", "verify"], { cwd: packageRoot, env: environment, timeout: 30_000 });
		assert.equal(result.status, 0, [result.stdout, result.stderr].filter(Boolean).join("\n"));
		assert.equal(result.stdout.trim().split(/\r?\n/u).at(-1), pinnedVersion);
	} finally {
		workspace.dispose();
	}
});

test("consumer install arguments distinguish safe inspection from lifecycle acceptance", () => {
	assert.ok(packageInstallArguments().includes("--ignore-scripts"));
	assert.ok(!packageInstallArguments({ runLifecycleScripts: true }).includes("--ignore-scripts"));
});

test("installed bin shim paths are bounded and platform-specific", () => {
	const root = path.resolve("consumer");
	assert.equal(installedBinShimPath(root, "aidr", "win32"), path.join(root, "node_modules", ".bin", "aidr.cmd"));
	assert.equal(installedBinShimPath(root, "aidr", "linux"), path.join(root, "node_modules", ".bin", "aidr"));
	assert.equal(installedBinShimPath(root, "../escape", "linux"), null);
});

test("Windows installed bin shims execute through a trusted ComSpec without a command string", { skip: process.platform !== "win32" }, () => {
	const workspace = createTempWorkspace("aidr-install-test-bin-shim-");
	try {
		const shimRoot = workspace.directory("shim path");
		const runtimeRoot = workspace.directory("runtime path");
		provisionNodeRuntime(runtimeRoot);
		const shim = path.join(shimRoot, "fixture.cmd");
		writeFileSync(path.join(shimRoot, "fixture.cjs"), 'if (process.argv[2] !== "--help") process.exit(3);\nconsole.log("fixture-ok");\n', "utf8");
		writeFileSync(shim, '@echo off\r\nnode "%~dp0fixture.cjs" %*\r\n', "utf8");
		const environment = sanitizedEnvironment({ home: workspace.root, emptyPathDir: runtimeRoot });
		const result = runInstalledBin(shim, ["--help"], { cwd: workspace.root, env: environment, timeout: 30_000 });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(result.stdout.trim(), "fixture-ok");
	} finally {
		workspace.dispose();
	}
});

test("the clean consumer PATH contains only a runnable Node runtime", () => {
	const workspace = createTempWorkspace("aidr-install-test-node-path-");
	try {
		const emptyPath = workspace.directory("path");
		const runtime = provisionNodeRuntime(emptyPath);
		assert.equal(existsSync(runtime), true);
		assert.equal(path.dirname(runtime), emptyPath);
	} finally {
		workspace.dispose();
	}
});

test("both npm tarballs and product tar.gz archives use the same hygiene policy", () => {
	assert.equal(isConsumerArchive("package.tgz"), true);
	assert.equal(isConsumerArchive("plugin.tar.gz"), true);
	assert.equal(isConsumerArchive("notes.zip"), false);
	assert.equal(hasForbiddenArchiveEntry("package/dist/index.js\npackage/dist/index.js.map\n"), true);
	assert.equal(hasForbiddenArchiveEntry("packages/claude-code/dist/pre-tool-use.cjs\n"), false);
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

test("publishable packages cannot claim duplicate bin names", () => {
	assert.deepEqual(
		duplicateBins([
			{ name: "@example/cli", package: { bin: { aidr: "dist/cli.js" } } },
			{ name: "@example/sdk", package: { bin: { aidr: "dist/sdk.js" } } },
		]),
		[{ name: "aidr", packages: ["@example/cli", "@example/sdk"] }],
	);
	assert.deepEqual(duplicateBins([{ name: "@example/cli", package: { bin: { aidr: "dist/cli.js" } } }]), []);
});

test("the workspace's published bin names are unique", () => {
	assert.equal(verifyWorkspaceBins(), true);
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

test("Koffi lifecycle probing is limited to Windows AMSI hosts and skipped honestly elsewhere", () => {
	const dependencies = [{ name: "koffi", platforms: ["win32"] }];
	assert.deepEqual(applicableLifecycleDependencies(dependencies, "win32").map((item) => item.name), ["koffi"]);
	assert.deepEqual(applicableLifecycleDependencies(dependencies, "linux"), []);
	const skips = lifecycleDependencySkips(dependencies, "linux");
	assert.equal(skips.length, 1);
	assert.equal(skips[0].scope, "dependency");
	assert.match(skips[0].reason, /UNSUPPORTED host.*win32.*linux/);
});

test("a signed clean install provisions an independent artifact public key", () => {
	const workspace = createTempWorkspace("aidr-install-test-artifact-trust-");
	try {
		const packageDir = workspace.directory("package");
		const home = workspace.directory("home");
		mkdirSync(path.join(packageDir, "dist"), { recursive: true });
		writeFileSync(path.join(packageDir, "dist", "aidr-artifact.manifest.sig"), "signature\n");
		const { publicKey } = generateKeyPairSync("ed25519");
		const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
		assert.deepEqual(provisionArtifactTrust({ packageDir, home, options: { artifactPublicKeyPem: pem } }), { signed: true });
		const config = JSON.parse(readFileSync(path.join(home, ".singularity-aidr", "config.json"), "utf8"));
		assert.equal(config.integrity.enabled, true);
		assert.equal(config.integrity.verify_on_start, true);
		assert.deepEqual(config.integrity.public_keys_pem, [pem]);
	} finally {
		workspace.dispose();
	}
});

test("the signed OpenClaw clean-install run exercises register() and before_tool_call", async () => {
	const workspace = createTempWorkspace("aidr-install-test-openclaw-hook-");
	try {
		const packageRoot = workspace.directory("package");
		const runtimeRoot = workspace.directory("runtime");
		const home = workspace.directory("home");
		mkdirSync(path.join(packageRoot, "dist"), { recursive: true });
		const pkg = writePackage(packageRoot, {
			name: "@example/openclaw",
			main: "dist/plugin.cjs",
			bin: {},
			exports: {},
			createBin: false,
			createExports: false,
		});
		writeFileSync(
			path.join(packageRoot, "dist", "plugin.cjs"),
			'module.exports = { register(api) { api.on("before_tool_call", async () => ({ block: true, blockReason: "fail closed" })); } };\n',
		);
		provisionNodeRuntime(runtimeRoot);
		const result = await defaultRunner(
			{ id: "plugin", kind: "import", entry: { main: true }, format: "cjs", pluginDefault: true },
			{
				pkg,
				packageRoot,
				consumerRoot: packageRoot,
				installed: false,
				exercisePlugin: true,
				environment: sanitizedEnvironment({ home, emptyPathDir: runtimeRoot }),
			},
		);
		assert.equal(result.status, PASS, result.detail);
	} finally {
		workspace.dispose();
	}
});

test("gateway clean-install gate verifies the real installed factory and both integrity denials", async (t) => {
	const workspace = createTempWorkspace("aidr-install-test-gateway-import-");
	try {
		const fixture = await buildGatewayPackageFixture(workspace.root);
		const runtimeRoot = workspace.directory("runtime");
		provisionNodeRuntime(runtimeRoot);
		const pkg = JSON.parse(readFileSync(path.join(fixture.installed, "package.json"), "utf8"));
		const run = RELEASE_PACKAGES.find((spec) => spec.key === "packages/mcp-gateway").runs.find((item) => item.kind === "gateway-signed-import");
		const context = {
			pkg, packageRoot: fixture.installed, consumerRoot: workspace.root, home: fixture.home,
			installed: true, environment: sanitizedEnvironment({ home: fixture.home, emptyPathDir: runtimeRoot }),
		};
		const configPath = path.join(fixture.home, ".singularity-aidr", "config.json");
		const manifestPath = path.join(fixture.dist, "aidr-artifact.manifest.json");
		const signaturePath = path.join(fixture.dist, "aidr-artifact.manifest.sig");
		const libraryPath = path.join(fixture.dist, "aidr-mcp-library.mjs");
		const originalManifest = readFileSync(manifestPath);
		const publisherSignature = readFileSync(signaturePath);
		const originalLibrary = readFileSync(libraryPath);
		const sharedLibrary = path.join(workspace.root, "package-store-library.mjs");
		linkSync(libraryPath, sharedLibrary);
		const publicKeyPem = JSON.parse(readFileSync(configPath, "utf8")).integrity.public_keys_pem[0];
		await t.test("an existing signature is never replaced without independent trust", async () => {
			const result = await defaultRunner(run, context);
			assert.equal(result.status, FAIL);
			assert.match(result.detail, /independently provisioned artifact trust key/);
			assert.deepEqual(readFileSync(signaturePath), publisherSignature);
		});
		await t.test("independently trusted signed package loads and wrong trust or library tamper deny", async () => {
			context.artifactTrust = provisionArtifactTrust({ packageDir: fixture.installed, home: fixture.home, options: { artifactPublicKeyPem: publicKeyPem } });
			const trustedConfig = readFileSync(configPath);
			const result = await defaultRunner(run, context);
			assert.equal(result.status, PASS, result.detail ?? result.reason);
			assert.deepEqual(readFileSync(signaturePath), publisherSignature);
			assert.deepEqual(readFileSync(configPath), trustedConfig);
			assert.deepEqual(readFileSync(libraryPath), originalLibrary);
			assert.deepEqual(readFileSync(sharedLibrary), originalLibrary, "tampering must not change a package-manager hard link");
			assert.notEqual(statSync(libraryPath, { bigint: true }).ino, statSync(sharedLibrary, { bigint: true }).ino, "tampering must detach the installed file from its package-manager hard link");
		});
		await t.test("wrong independently provisioned key fails without resigning", async () => {
			const { publicKey } = generateKeyPairSync("ed25519");
			context.artifactTrust = provisionArtifactTrust({ packageDir: fixture.installed, home: fixture.home, options: { artifactPublicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() } });
			const result = await defaultRunner(run, context);
			assert.equal(result.status, FAIL);
			assert.match(result.detail, /import of @singularityrd\/aidr-mcp-gateway/);
			assert.deepEqual(readFileSync(signaturePath), publisherSignature);
		});
		await t.test("a signed candidate losing its installed signature is never resigned", async () => {
			rmSync(signaturePath);
			const configBefore = readFileSync(configPath);
			const result = await defaultRunner(run, context);
			assert.equal(result.status, FAIL);
			assert.match(result.detail, /installed signature is missing/);
			assert.equal(existsSync(signaturePath), false);
			assert.deepEqual(readFileSync(configPath), configBefore);
		});
		await t.test("an unsigned disposable installation uses only an in-memory signing key", async () => {
			context.artifactTrust = { signed: false };
			const result = await defaultRunner(run, context);
			assert.equal(result.status, PASS, result.detail ?? result.reason);
			const key = JSON.parse(readFileSync(configPath, "utf8")).integrity.public_keys_pem[0];
			assert.equal(verify(null, originalManifest, key, Buffer.from(readFileSync(signaturePath, "utf8").trim(), "base64")), true);
			assert.deepEqual(readFileSync(manifestPath), originalManifest);
			assert.deepEqual(readFileSync(libraryPath), originalLibrary);
			assert.equal(listPackageEntries(workspace.root).some((file) => /private.*key|\.key$/iu.test(file)), false);
		});
		await t.test("an uninstalled package cannot be signed by this runner", async () => {
			rmSync(signaturePath);
			const result = await defaultRunner(run, { ...context, installed: false });
			assert.equal(result.status, FAIL);
			assert.match(result.detail, /disposable installed package/);
			assert.equal(existsSync(signaturePath), false);
		});
		await t.test("an escaping library export cannot mutate files outside the package", async () => {
			const escapingPkg = { ...pkg, exports: { ".": path.relative(fixture.installed, sharedLibrary) } };
			const result = await defaultRunner(run, { ...context, pkg: escapingPkg });
			assert.equal(result.status, FAIL);
			assert.match(result.detail, /integrity target escapes/);
			assert.equal(existsSync(signaturePath), false);
			assert.deepEqual(readFileSync(sharedLibrary), originalLibrary);
		});
		await t.test("a path outside the disposable consumer cannot be signed", async () => {
			const result = await defaultRunner(run, { ...context, consumerRoot: workspace.directory("other-consumer") });
			assert.equal(result.status, FAIL);
			assert.equal(existsSync(signaturePath), false);
		});
		await t.test("an import bypassing integrity cannot satisfy the negative probe", async () => {
			const bypass = Buffer.from("export function createMcpGateway() {}\n");
			writeFileSync(libraryPath, bypass);
			const manifest = JSON.parse(originalManifest);
			manifest.files.find((file) => file.path === "aidr-mcp-library.mjs").sha256 = createHash("sha256").update(bypass).digest("hex");
			writeFileSync(manifestPath, JSON.stringify(manifest));
			const result = await defaultRunner(run, context);
			assert.equal(result.status, FAIL);
			assert.match(result.detail, /trust-key tamper/);
			assert.deepEqual(readFileSync(libraryPath), bypass);
		});
	} finally {
		workspace.dispose();
	}
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
	assert.deepEqual(
		RELEASE_PACKAGES.filter((spec) => spec.lifecycleDependencies?.length).map((spec) => spec.key),
		["packages/core", "packages/claude-code", "packages/openclaw", "packages/codex"],
	);
	const extension = RELEASE_PACKAGES.find((spec) => spec.key === "packages/extension");
	assert.ok(extension.runs.every((run) => run.host !== "vscode"), "the Node-only package gate must not claim to execute the VS Code host");
	const codex = RELEASE_PACKAGES.find((spec) => spec.key === "packages/codex");
	assert.ok(
		codex.runs.some((run) => run.kind === "codex-signed-bin" && run.bin === "aidr-codex-hook"),
		"the clean-consumer gate must execute the installed commercial Codex hook",
	);
	const gateway = RELEASE_PACKAGES.find((spec) => spec.key === "packages/mcp-gateway");
	assert.ok(
		gateway.runs.some((run) => run.kind === "gateway-signed-import" && run.entry?.exports === "." && run.expected?.createMcpGateway === "function"),
		"the clean-consumer gate must import the verified public MCP factory and exercise its integrity boundary",
	);
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
