#!/usr/bin/env node
/**
 * Install every release package into an empty temporary directory and use it
 * with nothing on `PATH`.
 *
 * `check-package-contracts.mjs` proves that declared paths exist inside the
 * repository. `check-package-consumers.mjs` loads the declared entry points from
 * the repository's `dist/`. Neither answers the question the v8 completion
 * contract asks: can a *consumer* install this package into an empty directory,
 * with no repository on disk and an empty `PATH`, and still find every declared
 * `bin`, export subpath, asset, native payload, version and license?
 *
 * This gate answers it per release package:
 *
 *   1. `pnpm pack` the package into a fresh temporary directory outside the
 *      repository (Corepack's JS entry is invoked through the absolute Node
 *      executable, so no shell quoting is involved on Windows).
 *   2. Unpack the tarball into a second fresh temporary directory.
 *   3. Install the tarball into a third fresh temporary directory with the
 *      package manager, offline (dependency tarballs come from the local pnpm
 *      store, and workspace-internal packages are installed from their own
 *      packed tarballs through a consumer-local `pnpm-workspace.yaml`
 *      `overrides:` block, because pnpm 10 no longer reads `pnpm.overrides`
 *      from `package.json`). A fresh offline resolution can still fail when it
 *      picks a transitive version the local store does not hold; the entry
 *      points are then exercised straight from the unpacked tarball and the
 *      affected run is reported as `SKIPPED_WITH_REASON` with pnpm's reason.
 *   4. Run the declared entry points and `bin`s from the consumer directory
 *      with a sanitised environment: `PATH` pointing at a single empty
 *      directory, `HOME`/`USERPROFILE`/`TEMP` redirected into a private temp
 *      home, `NODE_OPTIONS`/`NODE_PATH`/`AIDR_*`/`npm_*` removed, and the
 *      absolute Node executable as the interpreter.
 *   5. Assert that every declared `bin`, `exports` subpath target and
 *      `files`/asset entry exists inside the unpacked package, that `version`
 *      and `license` are present and non-empty, and that no source, test,
 *      `.env`, `node_modules` or `.map` content shipped with the package.
 *
 * Usage:
 *   node scripts/verify-package-install.mjs [--keep] [--strict-files] [--no-install] [packageDir ...]
 *
 * Flags:
 *   --keep          keep the temporary directories (their paths are printed)
 *   --strict-files  treat a declared `files` documentation entry (README,
 *                   LICENSE, CHANGELOG, NOTICE) that matches nothing in the
 *                   tarball as a failure instead of an explicit skip
 *   --no-install    skip the offline package-manager install step
 *
 * A host that cannot run a package for an environmental reason (no offline copy
 * of its dependency tree, a native payload built for another architecture, an
 * editor host that does not exist in a Node-only process) is reported as
 * `SKIPPED_WITH_REASON` together with the reason, never as `PASS` and never as
 * a silent omission. Exit status is non-zero only when a package fails.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { IGNORE_DIRS, isSourceMapFile } from "./lib/package-artifact-rules.mjs";

const modulePath = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(modulePath), "..");

export const PASS = "PASS";
export const FAIL = "FAIL";
export const SKIPPED_WITH_REASON = "SKIPPED_WITH_REASON";

const RUN_TIMEOUT_MS = 30_000;
const PACK_TIMEOUT_MS = 300_000;
const INSTALL_TIMEOUT_MS = 600_000;
/** Failures printed per package before the report is truncated. */
const MAX_REPORTED_FAILURES = 8;

/**
 * Directory names that prove source, test, dependency or VCS content was
 * shipped by accident. The shared `IGNORE_DIRS` rules are folded in below so
 * this gate and `check-no-sourcemaps.mjs` cannot drift apart.
 */
const FORBIDDEN_DIRECTORY_RULES = new Map([
	["src", "SOURCE_DIRECTORY_PRESENT"],
	["test", "TEST_DIRECTORY_PRESENT"],
	["tests", "TEST_DIRECTORY_PRESENT"],
	["__tests__", "TEST_DIRECTORY_PRESENT"],
	["__snapshots__", "TEST_DIRECTORY_PRESENT"],
	["coverage", "COVERAGE_DIRECTORY_PRESENT"],
]);
for (const name of IGNORE_DIRS) {
	if (FORBIDDEN_DIRECTORY_RULES.has(name)) continue;
	FORBIDDEN_DIRECTORY_RULES.set(name, name === "node_modules" ? "NODE_MODULES_PRESENT" : name === ".git" ? "VCS_DIRECTORY_PRESENT" : "IGNORED_DIRECTORY_PRESENT");
}

/**
 * npm always auto-includes `README`, `LICENSE`/`LICENCE`, `CHANGELOG` and
 * `NOTICE` when the package root has one, and never fails an install when a
 * declared documentation entry is absent. Those entries are therefore reported
 * explicitly instead of failing the gate — unless `--strict-files` is set.
 */
const DOCUMENTATION_ENTRY_RE = /^(?:readme|licen[cs]e|licence|changelog|notice|third[_-]party[_-]notices)(?:\.(?:md|markdown|txt|rst))?$/i;

const SOURCE_FILE_RE = /\.(?:ts|tsx|mts|cts)$/i;
const DECLARATION_FILE_RE = /\.d\.(?:ts|mts|cts)$/i;
const ENV_FILE_RE = /^\.env(?:\.|$)/i;

/**
 * The ten release packages, in the order the release build produces them.
 *
 * `runs` names the entry points this gate exercises. Everything declared in
 * `bin`, `exports` or `files` that is *not* covered here is still verified: a
 * declared `bin` without a run gets a syntax check, and a declared `exports`
 * subpath without a run gets an import smoke test.
 */
export const RELEASE_PACKAGES = [
	{
		key: "packages/core",
		display: "@singularityrd/aidr-core",
		runs: [
			{ id: "core ESM import", kind: "import", entry: { exports: "." }, format: "esm", expected: { evaluateToolCall: "function" } },
		],
	},
	{
		key: "packages/claude-code",
		display: "@singularityrd/aidr-claude-code",
		// The AMSI bridge is a platform-specific native payload vendored into
		// `dist/vendor/koffi`; `dist/**` covers it, but the release contract
		// names it explicitly, so it is verified by path.
		platformAssets: {
			win32: [
				"dist/vendor/koffi/index.js",
				"dist/vendor/koffi/package.json",
				"dist/vendor/koffi/LICENSE.txt",
				"dist/vendor/koffi/build/koffi/win32_x64/koffi.node",
				"dist/vendor/koffi/build/koffi/win32_arm64/koffi.node",
				"dist/vendor/koffi/build/koffi/win32_ia32/koffi.node",
			],
		},
		runs: [
			{ id: "aidr-claude-code health --json", kind: "bin", bin: "aidr-claude-code", args: ["--json"], expect: "claude-health-json" },
		],
	},
	{
		key: "packages/extension",
		display: "aidr-cursor",
		runs: [
			{ id: "hook runner syntax", kind: "syntax", entry: { files: "dist/aidr-hook.cjs" } },
			{ id: "extension entry syntax", kind: "syntax", entry: { main: true } },
			{ id: "extension host entry", kind: "import", entry: { main: true }, format: "esm", host: "vscode" },
		],
	},
	{
		key: "packages/openclaw",
		display: "@singularityrd/aidr-openclaw",
		runs: [
			{ id: "plugin CJS require", kind: "import", entry: { main: true }, format: "cjs", pluginDefault: true },
			{ id: "openclaw.plugin.json", kind: "json", entry: { files: "openclaw.plugin.json" } },
		],
	},
	{
		key: "packages/opencode",
		display: "@singularityrd/aidr-opencode",
		runs: [
			{ id: "opencode ESM import", kind: "import", entry: { exports: "." }, format: "esm", expected: { AidrPlugin: "function" } },
		],
	},
	{
		key: "packages/cli",
		display: "@singularityrd/aidr-cli",
		runs: [
			{ id: "aidr --help", kind: "bin", bin: "aidr", args: ["--help"], expect: "aidr-usage" },
			{ id: "aidr-setup --help", kind: "bin", bin: "aidr-setup", args: ["--help"], expect: "aidr-usage" },
		],
	},
	{
		key: "packages/sdk",
		display: "@singularityrd/aidr-sdk",
		runs: [
			{ id: "sdk CJS require", kind: "import", entry: { exports: "." }, format: "cjs", expected: { AIDRClient: "function" } },
			{ id: "sdk ESM import", kind: "import", entry: { exports: "." }, format: "esm", expected: { AIDRClient: "function" } },
			{ id: "sdk aidr-sdk --help", kind: "bin", bin: "aidr-sdk", args: ["--help"], expect: "aidr-sdk-usage" },
		],
	},
	{
		key: "packages/dashboard",
		display: "@singularityrd/aidr-dashboard",
		runs: [
			{ id: "dashboard static build", kind: "static-html", entry: { files: "dist/index.html" }, expect: "dashboard-html" },
		],
	},
	{
		key: "packages/codex",
		display: "@singularityrd/aidr-codex",
		runs: [
			{ id: "codex ESM import", kind: "import", entry: { exports: "." }, format: "esm", expected: { enforceCodexPreToolUse: "function" } },
		],
	},
	{
		key: "packages/mcp-gateway",
		display: "@singularityrd/aidr-mcp-gateway",
		runs: [
			{ id: "gateway bounded usage", kind: "bin", bin: "aidr-mcp-gateway", args: [], expect: "gateway-usage" },
		],
	},
];

const invokedDirectly = process.argv[1] !== undefined && samePath(process.argv[1], modulePath);

if (invokedDirectly) {
	const options = parseArguments(process.argv.slice(2));
	const exitCode = await main(options);
	process.exit(exitCode);
}

/* -------------------------------------------------------------------------- */
/* options                                                                    */
/* -------------------------------------------------------------------------- */

export function parseArguments(argv) {
	const options = { keep: false, strictFiles: false, install: true, requested: [], unknown: [] };
	for (const value of argv) {
		if (value === "--keep") options.keep = true;
		else if (value === "--strict-files") options.strictFiles = true;
		else if (value === "--no-install") options.install = false;
		else if (value.startsWith("-")) options.unknown.push(value);
		else options.requested.push(normalizePackageArg(value));
	}
	return options;
}

export function normalizePackageArg(value) {
	const absolute = path.resolve(repoRoot, value);
	const relative = path.relative(repoRoot, absolute).replaceAll("\\", "/");
	return relative.replace(/\/$/, "");
}

async function main(options) {
	if (options.unknown.length > 0) {
		console.error(`Unknown option(s): ${options.unknown.join(", ")}`);
		return 2;
	}

	const failures = [];
	if (options.requested.length > 0) {
		for (const requested of options.requested) {
			if (!RELEASE_PACKAGES.some((spec) => spec.key === requested)) failures.push(`Unknown package directory: ${requested}`);
		}
	}
	if (failures.length > 0) {
		console.error("ERROR: release package install verification could not start:");
		for (const failure of failures) console.error(`  - ${failure}`);
		return 2;
	}

	const selected = RELEASE_PACKAGES.filter((spec) => options.requested.length === 0 || options.requested.includes(spec.key));
	const workspace = createTempWorkspace("aidr-package-install-");
	const results = [];
	let interrupted = false;
	const onSignal = () => {
		interrupted = true;
		workspace.dispose();
		process.exit(130);
	};
	process.on("SIGINT", onSignal);
	process.on("SIGTERM", onSignal);
	process.on("SIGHUP", onSignal);

	try {
		// Phase 1: pack every selected package once, plus the workspace-internal
		// packages they depend on. The tarballs double as the offline source for
		// those dependencies, because pnpm rewrites `workspace:*` ranges to the
		// published version and those versions are not in any registry this host
		// can reach.
		const packed = new Map();
		const packErrors = new Map();
		if (options.install) {
			const needed = workspaceDependencyClosure(selected);
			const toPack = RELEASE_PACKAGES.filter((spec) => selected.includes(spec) || needed.has(packageNameOf(spec)));
			for (const spec of toPack) {
				try {
					packed.set(packageNameOf(spec), packReleasePackage({ spec, packRoot: workspace.directory(`pack-${packageSlug(spec.key)}`) }));
				} catch (error) {
					packErrors.set(spec.key, formatError(error));
				}
			}
		}

		// Phase 2: extract, install and exercise every package.
		for (const spec of selected) {
			try {
				results.push(
					await verifyPackageInstall({
						spec,
						workspace,
						options,
						availableTarballs: packed,
						workspaceOverrides: scopeTarballsTo(spec, packed),
						prepackedError: packErrors.get(spec.key),
					}),
				);
			} catch (error) {
				results.push({
					key: spec.key,
					name: spec.display,
					status: FAIL,
					failures: [{ code: "VERIFICATION_CRASHED", detail: formatError(error) }],
					skips: [],
					artifacts: { declared: 0, verified: 0 },
					runResults: [],
				});
			}
		}
	} finally {
		process.off("SIGINT", onSignal);
		process.off("SIGTERM", onSignal);
		process.off("SIGHUP", onSignal);
		if (!options.keep && !interrupted) workspace.dispose();
	}

	reportResults(results, { keep: options.keep, tempRoot: workspace.root });
	const failed = results.filter((result) => result.status === FAIL);
	return failed.length > 0 ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* temporary directories                                                      */
/* -------------------------------------------------------------------------- */

export function createTempWorkspace(prefix) {
	const base = path.join(tmpdir(), `${prefix}${randomSuffix()}`);
	mkdirSync(base, { recursive: true });
	const created = [base];
	const workspace = {
		root: base,
		directory(name) {
			const target = path.join(base, name);
			mkdirSync(target, { recursive: true });
			created.push(target);
			return target;
		},
		dispose() {
			for (const target of [...created].reverse()) removePath(target);
			removePath(base);
		},
	};
	return workspace;
}

export function removePath(target) {
	for (let attempt = 0; attempt < 6; attempt++) {
		try {
			rmSync(target, { recursive: true, force: true, maxRetries: 2, retryDelay: 50 });
		} catch {
			// Windows can keep a directory locked briefly after a child exits.
		}
		if (!existsSync(target)) return true;
		sleepSync(100 * (attempt + 1));
	}
	return !existsSync(target);
}

function randomSuffix() {
	return `${process.pid.toString(36)}${Date.now().toString(36)}${Math.floor(Math.random() * 0x100000).toString(36)}`;
}

function packageSlug(key) {
	return key.replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function sleepSync(milliseconds) {
	const shared = new SharedArrayBuffer(4);
	Atomics.wait(new Int32Array(shared), 0, 0, milliseconds);
}

/* -------------------------------------------------------------------------- */
/* process environment and spawning                                           */
/* -------------------------------------------------------------------------- */

/**
 * Build the sanitised environment a clean consumer machine looks like: empty
 * `PATH`, private home, no inherited Node or repository knobs.
 */
export function sanitizedEnvironment({ home, emptyPathDir, extra = {} }) {
	const environment = {};
	for (const [key, value] of Object.entries(process.env)) {
		if (value === undefined) continue;
		const upper = key.toUpperCase();
		if (upper === "PATH" || upper === "NODE_OPTIONS" || upper === "NODE_PATH") continue;
		if (upper.startsWith("AIDR_") || upper.startsWith("NPM_CONFIG_") || upper.startsWith("NPM_LIFECYCLE_")) continue;
		environment[key] = value;
	}
	environment.PATH = emptyPathDir;
	environment.HOME = home;
	environment.USERPROFILE = home;
	environment.TMPDIR = home;
	environment.TEMP = home;
	environment.TMP = home;
	environment.NODE_ENV = "test";
	environment.CI = "1";
	return { ...environment, ...extra };
}

function runNode(args, { cwd, env, timeout = RUN_TIMEOUT_MS, input = "" }) {
	return spawnSync(process.execPath, args, {
		cwd,
		env,
		encoding: "utf8",
		input,
		timeout,
		maxBuffer: 16 * 1024 * 1024,
		windowsHide: true,
	});
}

function corepackPnpm() {
	const candidate = path.join(path.dirname(process.execPath), "node_modules", "corepack", "dist", "pnpm.js");
	return existsSync(candidate) ? candidate : null;
}

/**
 * Path to the workspace's own package manager, or null to fall back to PATH.
 *
 * `packageManager` in the root manifest pins the version this repository is
 * built and tested with. Corepack, when present, resolves that pin and may pick
 * a different major than the one the operator has on PATH - and each major keeps
 * its own content-addressable store and metadata cache. Running this gate under
 * the wrong major makes every offline install fail with
 * ERR_PNPM_NO_OFFLINE_TARBALL for packages that are already in the operator's
 * store, which reads as a missing-dependency defect rather than a version
 * mismatch. Prefer the pinned version when it is installed.
 */
function pinnedPnpm() {
	let pinned;
	try {
		const manifest = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf8"));
		pinned = /\d+\.\d+\.\d+/.exec(String(manifest.packageManager ?? ""))?.[0];
	} catch {
		return null;
	}
	if (!pinned) return null;
	// Corepack keeps each resolved version under its own cache directory, keyed
	// by the exact version string. That copy is the reliable one: the shim on
	// PATH resolves through corepack, and a bare `pnpm` on PATH can be a
	// different major whose store and metadata cache do not contain what this
	// repository installed.
	const corepackCache = path.join(process.env.LOCALAPPDATA ?? "", "node", "corepack", "v1", "pnpm", pinned, "bin", "pnpm.cjs");
	const candidates = [
		corepackCache,
		path.join(path.dirname(process.execPath), "node_modules", "pnpm", "bin", "pnpm.cjs"),
		path.join(process.env.APPDATA ?? "", "npm", "node_modules", "pnpm", "bin", "pnpm.cjs"),
		path.join(process.env.LOCALAPPDATA ?? "", "pnpm", "pnpm.cjs"),
	];
	for (const candidate of candidates) {
		if (!existsSync(candidate)) continue;
		// Only accept a candidate whose reported version matches the pin.
		const probe = spawnSync(process.execPath, [candidate, "--version"], { encoding: "utf8", timeout: 30_000, windowsHide: true });
		if (probe.status === 0 && String(probe.stdout ?? "").trim() === pinned) return candidate;
	}
	return null;
}

/** Invoke the workspace package manager without depending on shell quoting. */
function runPnpm(args, { cwd, env, timeout }) {
	const pinned = pinnedPnpm();
	if (pinned) return spawnSync(process.execPath, [pinned, ...args], spawnOptions({ cwd, env, timeout }));
	const corepack = corepackPnpm();
	if (corepack) return spawnSync(process.execPath, [corepack, ...args], spawnOptions({ cwd, env, timeout }));
	if (process.platform === "win32") {
		return spawnSync("pnpm.cmd", args, { ...spawnOptions({ cwd, env, timeout }), shell: true });
	}
	return spawnSync("pnpm", args, spawnOptions({ cwd, env, timeout }));
}

function spawnOptions({ cwd, env, timeout }) {
	return {
		cwd,
		env,
		encoding: "utf8",
		timeout,
		maxBuffer: 16 * 1024 * 1024,
		windowsHide: true,
	};
}

function runTar(args, { cwd, env }) {
	return spawnSync("tar", args, spawnOptions({ cwd, env, timeout: RUN_TIMEOUT_MS }));
}

/* -------------------------------------------------------------------------- */
/* declarations                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Flatten every artifact a package declares: `bin` names, `main`/`module`/
 * `types`, `exports` subpath targets and `files` entries.
 */
export function collectDeclaredArtifacts(pkg) {
	const artifacts = [];
	for (const [name, target] of Object.entries(pkg.bin ?? {})) {
		if (typeof target === "string") artifacts.push({ kind: "bin", field: `bin.${name}`, name, target });
	}
	for (const field of ["main", "module", "types", "typings"]) {
		if (typeof pkg[field] === "string") artifacts.push({ kind: field, field, name: field, target: pkg[field] });
	}
	collectExportTargets(pkg.exports, ".", artifacts);
	for (const entry of pkg.files ?? []) {
		if (typeof entry === "string") artifacts.push({ kind: "files", field: "files", name: entry, target: entry });
	}
	return artifacts;
}

function collectExportTargets(value, subpath, artifacts) {
	if (typeof value === "string") {
		artifacts.push({ kind: "exports", field: `exports["${subpath}"]`, name: subpath, target: value });
		return;
	}
	if (Array.isArray(value)) {
		for (const child of value) collectExportTargets(child, subpath, artifacts);
		return;
	}
	if (!value || typeof value !== "object") return;
	for (const [key, child] of Object.entries(value)) {
		if (key.startsWith(".")) collectExportTargets(child, key, artifacts);
		else collectExportTargets(child, subpath, artifacts);
	}
}

/**
 * Verify one extracted package: declarations, version/license, forbidden
 * content, then the declared runs through the injected `runner`.
 */
export async function verifyExtractedPackage({ packageDir, runs = [], runner, strictFiles = false, platformAssets = {}, context = {} }) {
	const failures = [];
	const skips = [];
	const runResults = [];

	const manifestPath = path.join(packageDir, "package.json");
	if (!isFile(manifestPath)) return unreadable("MISSING_PACKAGE_JSON", manifestPath);
	let pkg;
	try {
		pkg = JSON.parse(readFileSync(manifestPath, "utf8"));
	} catch (error) {
		return unreadable("INVALID_PACKAGE_JSON", formatError(error));
	}

	if (typeof pkg.version !== "string" || pkg.version.trim() === "") failures.push({ code: "EMPTY_VERSION_FIELD", detail: "package.json#version is missing or empty" });
	if (typeof pkg.license !== "string" || pkg.license.trim() === "") failures.push({ code: "EMPTY_LICENSE_FIELD", detail: "package.json#license is missing or empty" });

	const declared = collectDeclaredArtifacts(pkg);
	const files = listPackageEntries(packageDir);
	let verified = 0;
	let artefactSkips = 0;
	for (const artifact of declared) {
		const problem = checkDeclaredArtifact(artifact, packageDir, files);
		if (!problem) {
			verified += 1;
			continue;
		}
		if (problem.code === "MISSING_FILES_ENTRY" && !strictFiles && DOCUMENTATION_ENTRY_RE.test(artifact.target)) {
			artefactSkips += 1;
			skips.push({
				id: artifact.field,
				scope: "artefact",
				reason: `declared files entry "${artifact.target}" matches no file in the tarball (npm conventional documentation entry); pass --strict-files to fail on it`,
			});
			continue;
		}
		failures.push({ code: problem.code, detail: problem.detail });
	}

	// Platform-specific native payloads, verified by path rather than by glob.
	let platformDeclared = 0;
	for (const [platform, paths] of Object.entries(platformAssets ?? {})) {
		if (platform !== process.platform) {
			skips.push({
				id: `platform assets (${platform})`,
				scope: "artefact",
				reason: `UNSUPPORTED host: ${paths.length} ${platform} native payload file(s) are only produced on ${platform}; this host is ${process.platform}`,
			});
			continue;
		}
		platformDeclared += paths.length;
		for (const relative of paths) {
			if (isFile(path.join(packageDir, relative))) {
				verified += 1;
			} else {
				failures.push({ code: "MISSING_PLATFORM_ASSET", detail: `${relative} is a declared ${platform} payload that is not shipped` });
			}
		}
	}

	failures.push(...findForbiddenEntries(packageDir));

	for (const run of runs) {
		const outcome = await executeRun(run, runner, { ...context, packageDir, pkg });
		const entry = { id: run.id, status: outcome?.status ?? FAIL, reason: outcome?.reason, detail: outcome?.detail };
		if (entry.status === SKIPPED_WITH_REASON) {
			skips.push({ id: run.id, scope: "run", reason: entry.reason ?? "no reason reported" });
		} else if (entry.status !== PASS) {
			failures.push({ code: run.code ?? "RUN_FAILED", detail: `${run.id}: ${entry.detail ?? entry.reason ?? "failed"}` });
		}
		runResults.push(entry);
	}

	return finish(failures);

	/** A package whose manifest cannot be read cannot be verified at all. */
	function unreadable(code, detail) {
		return {
			name: path.basename(packageDir),
			packageName: path.basename(packageDir),
			status: FAIL,
			failures: [{ code, detail }],
			skips: [],
			artifacts: { declared: 0, verified: 0 },
			runResults: [],
		};
	}

	function finish(collected) {
		const runSkipped = runResults.some((entry) => entry.status === SKIPPED_WITH_REASON);
		return {
			name: pkg?.name ?? path.basename(packageDir),
			packageName: pkg?.name ?? path.basename(packageDir),
			status: collected.length > 0 ? FAIL : runSkipped ? SKIPPED_WITH_REASON : PASS,
			failures: collected,
			skips,
			artifacts: { declared: declared.length + platformDeclared - artefactSkips, verified },
			runResults,
		};
	}
}

async function executeRun(run, runner, context) {
	if (typeof runner !== "function") {
		return { status: SKIPPED_WITH_REASON, reason: "no runner was supplied for this run" };
	}
	try {
		return (await runner(run, context)) ?? { status: FAIL, detail: "runner returned no outcome" };
	} catch (error) {
		return { status: FAIL, detail: formatError(error) };
	}
}

function checkDeclaredArtifact(artifact, packageDir, files) {
	const raw = artifact.target.replace(/^\.\//, "");
	if (path.isAbsolute(raw)) return { code: "DECLARED_PATH_ESCAPES_PACKAGE", detail: `${artifact.field} → ${artifact.target} is absolute` };
	const resolved = path.resolve(packageDir, raw);
	if (!isWithin(resolved, packageDir)) return { code: "DECLARED_PATH_ESCAPES_PACKAGE", detail: `${artifact.field} → ${artifact.target} escapes the package` };
	if (artifact.kind === "files") {
		if (hasGlob(raw)) {
			const matcher = globToRegExp(raw);
			if (!files.some((file) => matcher.test(file))) return { code: "MISSING_FILES_ENTRY", detail: `files entry "${artifact.target}" matches nothing in the tarball` };
			return null;
		}
		if (!existsSync(resolved)) return { code: "MISSING_FILES_ENTRY", detail: `files entry "${artifact.target}" is not shipped` };
		return null;
	}
	if (!existsSync(resolved) || isDirectory(resolved)) {
		return { code: `MISSING_${artifact.kind.toUpperCase()}_TARGET`, detail: `${artifact.field} → ${artifact.target} is not a file in the tarball` };
	}
	return null;
}

/** Every relative file and directory path inside the package, `/`-separated. */
export function listPackageEntries(root) {
	const entries = [];
	const walk = (dir, prefix) => {
		let children;
		try {
			children = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const child of children) {
			const relative = prefix ? `${prefix}/${child.name}` : child.name;
			entries.push(relative);
			if (child.isDirectory()) walk(path.join(dir, child.name), relative);
		}
	};
	walk(root, "");
	return entries;
}

/**
 * Content that must never ship: source maps, TypeScript sources, test trees,
 * environment files, installed dependencies and VCS metadata.
 */
export function findForbiddenEntries(root) {
	const violations = [];
	const walk = (dir, prefix) => {
		let children;
		try {
			children = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const child of children) {
			const relative = prefix ? `${prefix}/${child.name}` : child.name;
			if (child.isDirectory()) {
				const rule = FORBIDDEN_DIRECTORY_RULES.get(child.name);
				if (rule) {
					violations.push({ code: rule, detail: `${relative}/ must not be present in the package` });
					continue;
				}
				walk(path.join(dir, child.name), relative);
				continue;
			}
			if (!child.isFile()) continue;
			if (isSourceMapFile(child.name)) {
				violations.push({ code: "SOURCE_MAP_PRESENT", detail: `${relative} must not be present (build a release artifact with "pnpm build:release")` });
				continue;
			}
			if (ENV_FILE_RE.test(child.name)) {
				violations.push({ code: "ENV_FILE_PRESENT", detail: `${relative} must not be present` });
				continue;
			}
			if (SOURCE_FILE_RE.test(child.name) && !DECLARATION_FILE_RE.test(child.name)) {
				violations.push({ code: "SOURCE_FILE_PRESENT", detail: `${relative} must not be present` });
			}
		}
	};
	walk(root, "");
	return violations;
}

/* -------------------------------------------------------------------------- */
/* packing and installing                                                     */
/* -------------------------------------------------------------------------- */

/** `pnpm pack` into a fresh directory, returning the produced tarball. */
export function packReleasePackage({ spec, packRoot }) {
	const packageDir = path.join(repoRoot, spec.key);
	if (!isDirectory(packageDir)) throw new Error(`missing package directory ${spec.key}`);
	const result = runPnpm(["pack", "--pack-destination", packRoot], { cwd: packageDir, env: process.env, timeout: PACK_TIMEOUT_MS });
	if (result.error) throw new Error(`${spec.key}: pnpm pack could not start: ${formatError(result.error)}`);
	if (result.status !== 0) {
		// pnpm writes its wrapped error to stdout when a lifecycle script fails.
		const details = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
		throw new Error(`${spec.key}: pnpm pack exited ${String(result.status)}${details ? `: ${tail(details, 12)}` : ""}`);
	}
	const tarballs = readdirSync(packRoot).filter((name) => name.endsWith(".tgz"));
	if (tarballs.length !== 1) throw new Error(`${spec.key}: expected exactly one tarball, found ${tarballs.length}`);
	return path.join(packRoot, tarballs[0]);
}

function unpackTarball({ tarball, extractRoot, spec }) {
	const result = runTar(["-xzf", tarball, "-C", extractRoot], { cwd: extractRoot, env: process.env });
	if (result.error) throw new Error(`${spec.key}: tar could not start: ${formatError(result.error)}`);
	if (result.status !== 0) throw new Error(`${spec.key}: tar exited ${String(result.status)}: ${tail([result.stderr, result.stdout].filter(Boolean).join("\n"), 6)}`);
	const unpacked = path.join(extractRoot, "package");
	if (!isDirectory(unpacked)) throw new Error(`${spec.key}: the tarball does not contain a top-level package/ directory`);
	return unpacked;
}

/**
 * Install the tarball into an empty consumer project from the local pnpm store.
 * Returns `{ ok, root, error }`; `ok: false` reasons are environmental (no warm
 * offline store, no published workspace dependency) and are reported, not
 * treated as package defects.
 *
 * pnpm 10 no longer reads `pnpm.overrides` from `package.json`, and the packed
 * tarballs reference each other by their published version while those versions
 * are not in any registry this host can reach. The overrides therefore go into
 * the consumer's own `pnpm-workspace.yaml`, and every workspace tarball is also
 * declared as a direct `file:` dependency so pnpm can satisfy the transitive
 * `workspace:` ranges locally.
 */
export function installConsumerPackage({ spec, tarball, consumerRoot, workspaceTarballs, options = {} }) {
	const dependencies = { [packageNameOf(spec)]: fileSpecifier(consumerRoot, tarball) };
	const overrides = {};
	for (const [name, workspaceTarball] of workspaceTarballs ?? []) {
		overrides[name] = fileSpecifier(consumerRoot, workspaceTarball);
		dependencies[name] = fileSpecifier(consumerRoot, workspaceTarball);
	}
	const manifest = { name: "aidr-consumer-verification", version: "0.0.0", private: true, dependencies };
	writeFileSync(path.join(consumerRoot, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
	writeFileSync(
		path.join(consumerRoot, "pnpm-workspace.yaml"),
		`packages:\n  - "."\n${Object.keys(overrides).length > 0 ? `overrides:\n${Object.entries(overrides).map(([name, target]) => `  ${JSON.stringify(name)}: ${JSON.stringify(target)}`).join("\n")}\n` : ""}`,
		"utf8",
	);
	const result = runPnpm(["install", "--offline", "--ignore-scripts", "--reporter=append-only"], {
		cwd: consumerRoot,
		env: options.environment ?? process.env,
		timeout: INSTALL_TIMEOUT_MS,
	});
	const installedRoot = path.join(consumerRoot, "node_modules", packageNameOf(spec));
	if (result.error || result.status !== 0 || !existsSync(installedRoot)) {
		const details = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
		return {
			ok: false,
			error: `${spec.key}: offline pnpm install did not produce node_modules (${result.error ? formatError(result.error) : `exit ${String(result.status)}`})${details ? `: ${tail(details, 8)}` : ""}`,
		};
	}
	return { ok: true, root: safeRealpath(installedRoot), consumerRoot };
}

/* -------------------------------------------------------------------------- */
/* one package, end to end                                                    */
/* -------------------------------------------------------------------------- */

export async function verifyPackageInstall({ spec, workspace, options, availableTarballs = new Map(), workspaceOverrides = new Map(), prepackedError }) {
	const extractRoot = workspace.directory(`extract-${packageSlug(spec.key)}`);
	const consumerRoot = workspace.directory(`consumer-${packageSlug(spec.key)}`);
	const home = workspace.directory(`home-${packageSlug(spec.key)}`);
	const emptyPathDir = workspace.directory(`empty-path-${packageSlug(spec.key)}`);

	if (prepackedError) {
		return {
			key: spec.key,
			name: spec.display,
			status: FAIL,
			failures: [{ code: "PACK_FAILED", detail: prepackedError }],
			skips: [],
			artifacts: { declared: 0, verified: 0 },
			runResults: [],
		};
	}

	let tarball = availableTarballs.get(packageNameOf(spec));
	if (!tarball) {
		try {
			tarball = packReleasePackage({ spec, packRoot: workspace.directory(`pack-${packageSlug(spec.key)}`) });
		} catch (error) {
			return {
				key: spec.key,
				name: spec.display,
				status: FAIL,
				failures: [{ code: "PACK_FAILED", detail: formatError(error) }],
				skips: [],
				artifacts: { declared: 0, verified: 0 },
				runResults: [],
			};
		}
	}

	let packageDir;
	try {
		packageDir = unpackTarball({ tarball, extractRoot, spec });
	} catch (error) {
		return {
			key: spec.key,
			name: spec.display,
			status: FAIL,
			failures: [{ code: "EXTRACT_FAILED", detail: formatError(error) }],
			skips: [],
			artifacts: { declared: 0, verified: 0 },
			runResults: [],
		};
	}

	const environment = sanitizedEnvironment({ home, emptyPathDir });
	const install = options.install
		? installConsumerPackage({ spec, tarball, consumerRoot, workspaceTarballs: workspaceOverrides, options: { environment } })
		: { ok: false, error: `${spec.key}: the install step was disabled with --no-install` };
	if (!install.ok) removePath(path.join(consumerRoot, "node_modules"));

	const context = {
		environment,
		consumerRoot: install.ok ? consumerRoot : extractRoot,
		packageRoot: install.ok ? install.root : packageDir,
		installed: install.ok,
		installError: install.ok ? undefined : install.error,
		spec,
	};
	const result = await verifyExtractedPackage({
		packageDir,
		runs: buildRuns(spec),
		runner: defaultRunner,
		strictFiles: options.strictFiles,
		platformAssets: spec.platformAssets,
		context,
	});
	if (!install.ok) {
		result.skips.unshift({ id: "package install", scope: "artefact", reason: `offline install unavailable: ${install.error}` });
	}
	result.key = spec.key;
	result.display = spec.display;
	result.name = spec.display;
	return result;
}

/** The declared runs, plus a generic check for every declared artifact. */
export function buildRuns(spec) {
	const runs = [...(spec.runs ?? [])];
	const coveredBins = new Set(runs.filter((run) => run.kind === "bin").map((run) => run.bin));
	const coveredExports = new Set(runs.filter((run) => run.kind === "import" && run.entry?.exports).map((run) => run.entry.exports));
	const packageDir = path.join(repoRoot, spec.key);
	if (!isDirectory(packageDir)) return runs;
	const pkg = manifestOf(spec);
	for (const name of Object.keys(pkg.bin ?? {})) {
		if (!coveredBins.has(name)) runs.push({ id: `${name} syntax`, kind: "syntax", entry: { bin: name } });
	}
	if (typeof pkg.exports === "object" && pkg.exports !== null) {
		for (const subpath of Object.keys(pkg.exports).filter((key) => key.startsWith("."))) {
			if (!coveredExports.has(subpath) && subpath !== ".") {
				runs.push({ id: `exports ${subpath} import`, kind: "import", entry: { exports: subpath }, format: "esm", expected: {} });
			}
		}
	}
	return runs;
}

/* -------------------------------------------------------------------------- */
/* the default runner                                                         */
/* -------------------------------------------------------------------------- */

export async function defaultRunner(run, context) {
	if (run.host) {
		return {
			status: SKIPPED_WITH_REASON,
			reason: `UNSUPPORTED host: the ${run.host} extension host does not exist in a Node-only consumer process; the packaged entry point is verified by syntax check and presence instead of by loading it`,
		};
	}
	switch (run.kind) {
		case "syntax":
			return runSyntax(run, context);
		case "import":
			return runImport(run, context);
		case "bin":
			return runBin(run, context);
		case "json":
			return runJson(run, context);
		case "static-html":
			return runStaticHtml(run, context);
		default:
			return { status: FAIL, detail: `unknown run kind ${String(run.kind)}` };
	}
}

function resolveEntry(run, context) {
	const pkg = context.pkg;
	if (run.entry?.main) {
		const target = pkg.main;
		if (typeof target !== "string") return { error: "package.json#main is not declared" };
		return { file: path.join(context.packageRoot, target.replace(/^\.\//, "")), specifier: context.installed ? pkg.name : null, target };
	}
	if (run.entry?.bin ?? run.bin) {
		const binName = run.entry?.bin ?? run.bin;
		const target = pkg.bin?.[binName];
		if (typeof target !== "string") return { error: `bin.${binName} is not declared` };
		return { file: path.join(context.packageRoot, target.replace(/^\.\//, "")), target, bin: binName };
	}
	if (run.entry?.files) {
		return { file: path.join(context.packageRoot, run.entry.files.replace(/^\.\//, "")), target: run.entry.files };
	}
	if (run.entry?.exports) {
		const target = findExportTarget(pkg.exports, run.entry.exports);
		if (!target) return { error: `exports["${run.entry.exports}"] has no file target` };
		return { file: path.join(context.packageRoot, target.replace(/^\.\//, "")), specifier: context.installed ? exportSpecifier(pkg.name, run.entry.exports) : null, target };
	}
	return { error: "run does not declare an entry point" };
}

function findExportTarget(exportsField, subpath) {
	if (typeof exportsField === "string") return subpath === "." ? exportsField : null;
	if (!exportsField || typeof exportsField !== "object") return null;
	const node = exportsField[subpath];
	if (node === undefined) return null;
	return firstStringTarget(node);
}

function firstStringTarget(value) {
	if (typeof value === "string") return value;
	if (Array.isArray(value)) {
		for (const child of value) {
			const found = firstStringTarget(child);
			if (found) return found;
		}
		return null;
	}
	if (!value || typeof value !== "object") return null;
	// Prefer the runtime condition over the type declarations.
	for (const key of ["import", "require", "default", "node"]) {
		if (key in value) {
			const found = firstStringTarget(value[key]);
			if (found) return found;
		}
	}
	for (const child of Object.values(value)) {
		const found = firstStringTarget(child);
		if (found) return found;
	}
	return null;
}

function exportSpecifier(name, subpath) {
	return subpath === "." ? name : `${name}/${subpath.replace(/^\.\//, "")}`;
}

function runSyntax(run, context) {
	const entry = resolveEntry(run, context);
	if (entry.error) return { status: FAIL, detail: entry.error };
	if (!isFile(entry.file)) return { status: FAIL, detail: `declared target ${entry.target} is missing` };
	const result = runNode(["--check", entry.file], { cwd: context.consumerRoot, env: context.environment });
	return interpret(result, `syntax check of ${entry.target}`);
}

function runJson(run, context) {
	const entry = resolveEntry(run, context);
	if (entry.error) return { status: FAIL, detail: entry.error };
	if (!isFile(entry.file)) return { status: FAIL, detail: `declared target ${entry.target} is missing` };
	try {
		const parsed = JSON.parse(readFileSync(entry.file, "utf8"));
		if (!parsed || typeof parsed !== "object") return { status: FAIL, detail: `${entry.target} is not a JSON object` };
		return { status: PASS, detail: `${entry.target} parses as JSON` };
	} catch (error) {
		return { status: FAIL, detail: `${entry.target} is not valid JSON: ${formatError(error)}` };
	}
}

function runImport(run, context) {
	const entry = resolveEntry(run, context);
	if (entry.error) return { status: FAIL, detail: entry.error };
	if (!isFile(entry.file)) return { status: FAIL, detail: `declared target ${entry.target} is missing` };
	const specifier = entry.specifier ?? (run.format === "cjs" ? entry.file : pathToFileURL(entry.file).href);
	const expected = run.expected ?? {};
	const checks = Object.entries(expected)
		.map(([name, kind]) => `if (typeof mod[${JSON.stringify(name)}] !== ${JSON.stringify(kind)}) problems.push(${JSON.stringify(name)} + " must be a " + ${JSON.stringify(kind)} + " (found " + typeof mod[${JSON.stringify(name)}] + ")");`)
		.join("\n");
	const pluginCheck = run.pluginDefault
		? 'const plugin = mod && mod.default ? mod.default : mod;\nif (typeof plugin?.register !== "function") problems.push("default plugin export must expose register()");'
		: "";
	const source =
		run.format === "cjs"
			? `const mod = require(${JSON.stringify(specifier)});\nconst problems = [];\n${pluginCheck}\n${checks}\nif (mod === undefined) problems.push("module did not load");\nif (problems.length) { console.error(problems.join("; ")); process.exit(3); }`
			: `const mod = await import(${JSON.stringify(specifier)});\nconst problems = [];\n${pluginCheck}\n${checks}\nif (Object.keys(mod).length === 0) problems.push("module namespace is empty");\nif (problems.length) { console.error(problems.join("; ")); process.exit(3); }`;
	const args = run.format === "cjs" ? ["-e", source] : ["--input-type=module", "-e", source];
	const result = runNode(args, { cwd: context.consumerRoot, env: context.environment });
	return interpret(result, `${run.format} import of ${specifier}`, { assertionExitCode: 3 });
}

function runBin(run, context) {
	const entry = resolveEntry(run, context);
	if (entry.error) return { status: FAIL, detail: entry.error };
	if (!isFile(entry.file)) return { status: FAIL, detail: `declared bin target ${entry.target} is missing` };
	const result = runNode([entry.file, ...(run.args ?? [])], { cwd: context.consumerRoot, env: context.environment });
	const outcome = interpret(result, `${run.id}`, { acceptedStatuses: run.expect === "gateway-usage" ? [0, 2] : [0] });
	if (outcome.status !== PASS) return outcome;
	return applyExpectation(run.expect, result, run.id);
}

function applyExpectation(expect, result, label) {
	switch (expect) {
		case "claude-health-json": {
			let payload;
			try {
				payload = JSON.parse(result.stdout);
			} catch (error) {
				return { status: FAIL, detail: `${label} did not print JSON: ${formatError(error)}` };
			}
			if (payload?.status !== "healthy") return { status: FAIL, detail: `${label} reported status ${JSON.stringify(payload?.status)} (expected healthy)` };
			if (typeof payload?.checks !== "object" || payload.checks === null) return { status: FAIL, detail: `${label} is missing checks` };
			const threatCheck = payload.checkDetails?.find?.((check) => check?.name === "threat_rules");
			if (threatCheck?.status !== "healthy" || Number(threatCheck?.details?.rulesCount ?? 0) <= 0) {
				return { status: FAIL, detail: `${label} packaged threat rules are missing or empty` };
			}
			if (!String(threatCheck?.details?.threatsDir ?? "").includes("resources")) {
				return { status: FAIL, detail: `${label} did not resolve threat rules from the packaged resources` };
			}
			return { status: PASS };
		}
		case "aidr-usage":
			if (!/Usage:\s+aidr\b/i.test(result.stdout ?? "")) return { status: FAIL, detail: `${label} output does not contain the aidr usage header` };
			return { status: PASS };
		case "aidr-sdk-usage":
			if (!/Usage:\s+aidr-sdk\b/i.test(result.stdout ?? "")) return { status: FAIL, detail: `${label} output does not contain the aidr-sdk usage header` };
			return { status: PASS };
		case "gateway-usage":
			if (result.status !== 2 || !/usage: aidr-mcp-gateway <config\.json>/.test(result.stderr ?? "")) {
				return { status: FAIL, detail: `${label} did not report bounded configuration usage` };
			}
			return { status: PASS };
		case undefined:
			return { status: PASS };
		default:
			return { status: FAIL, detail: `unknown expectation ${String(expect)}` };
	}
}

function runStaticHtml(run, context) {
	const entry = resolveEntry(run, context);
	if (entry.error) return { status: FAIL, detail: entry.error };
	if (!isFile(entry.file)) return { status: FAIL, detail: `declared target ${entry.target} is missing` };
	const html = readFileSync(entry.file, "utf8");
	if (!/<div[^>]+id=["']root["']/i.test(html)) return { status: FAIL, detail: `${entry.target} is missing the root mount element` };
	const references = [...html.matchAll(/(?:src|href)=["']([^"']+)["']/gi)].map((match) => match[1]).filter((value) => !/^(?:[a-z]+:|#|\/\/)/i.test(value));
	const assetReferences = references.filter((value) => value.includes("assets/"));
	if (assetReferences.length === 0) return { status: FAIL, detail: `${entry.target} does not reference a built asset` };
	const root = path.dirname(entry.file);
	for (const reference of references) {
		const resolved = path.resolve(root, reference.replace(/^\/+/, ""));
		if (!existsSync(resolved)) return { status: FAIL, detail: `${entry.target} references ${reference}, which is not shipped` };
	}
	return { status: PASS, detail: `${references.length} referenced asset(s) present` };
}

function interpret(result, label, { acceptedStatuses = [0], assertionExitCode } = {}) {
	if (result.error) {
		const classified = classifyRunFailure({ error: result.error, stderr: "", stdout: "" });
		return { status: classified.status, reason: `${label}: ${classified.reason}` };
	}
	if (assertionExitCode !== undefined && result.status === assertionExitCode) {
		return { status: FAIL, detail: `${label}: ${tail(result.stderr, 4) || "assertion failed"}` };
	}
	if (!acceptedStatuses.includes(result.status)) {
		const classified = classifyRunFailure(result);
		if (classified.status === SKIPPED_WITH_REASON) return { status: SKIPPED_WITH_REASON, reason: `${label}: ${classified.reason}` };
		const details = tail([result.stderr, result.stdout].filter(Boolean).join("\n").trim(), 6);
		return { status: FAIL, detail: `${label} exited ${String(result.status)}${details ? `: ${details}` : ""}` };
	}
	return { status: PASS };
}

/**
 * Turn a failing child process into either an environmental skip or a defect.
 * Only module-resolution and native-platform failures are environmental: they
 * describe the host, not the package.
 */
export function classifyRunFailure(result) {
	const output = `${result.stderr ?? ""}\n${result.stdout ?? ""}\n${result.error ? formatError(result.error) : ""}`;
	const missing = [...output.matchAll(/Cannot find (?:module|package) '([^']+)'/g)].map((match) => match[1]);
	if (missing.length > 0 || /ERR_MODULE_NOT_FOUND/.test(output)) {
		const names = [...new Set(missing)].slice(0, 4).join(", ");
		return {
			status: SKIPPED_WITH_REASON,
			reason: `UNSUPPORTED dependency: the entry point needs ${names || "an external module"} which is not shipped in the tarball and could not be installed offline`,
		};
	}
	if (/ERR_DLOPEN_FAILED|not a valid Win32 application|invalid ELF header|cannot open shared object|incompatible architecture|dlopen/.test(output)) {
		return {
			status: SKIPPED_WITH_REASON,
			reason: `UNSUPPORTED host: a native payload could not be loaded on ${process.platform}/${process.arch} (${tail(output.trim(), 2)})`,
		};
	}
	if (/ETIMEDOUT|timed? ?out/i.test(output)) {
		return { status: FAIL, reason: "the entry point timed out" };
	}
	return { status: FAIL, reason: tail(output.trim(), 3) || "the entry point failed" };
}

/* -------------------------------------------------------------------------- */
/* reporting                                                                  */
/* -------------------------------------------------------------------------- */

function reportResults(results, { keep, tempRoot }) {
	const skipped = [];
	for (const result of results) {
		const artifacts = `artefacts ${result.artifacts?.verified ?? 0}/${result.artifacts?.declared ?? 0}`;
		const runs = `${result.runResults?.filter((run) => run.status === PASS).length ?? 0}/${result.runResults?.length ?? 0} runs`;
		if (result.status === PASS) {
			console.log(`${PASS} ${result.key} (${result.name}) — ${artifacts}, ${runs}`);
		} else if (result.status === SKIPPED_WITH_REASON) {
			console.log(`${SKIPPED_WITH_REASON} ${result.key} (${result.name}) — ${artifacts}, ${runs}`);
			for (const skip of result.skips ?? []) console.log(`  ${SKIPPED_WITH_REASON} [${skip.scope}]: ${skip.reason}`);
		} else {
			console.log(`${FAIL} ${result.key} (${result.name}) — ${artifacts}, ${runs}`);
			for (const failure of (result.failures ?? []).slice(0, MAX_REPORTED_FAILURES)) console.log(`  ${failure.code}: ${failure.detail}`);
			if ((result.failures?.length ?? 0) > MAX_REPORTED_FAILURES) {
				console.log(`  … ${result.failures.length - MAX_REPORTED_FAILURES} further failure(s) suppressed here; the complete list is returned by verifyPackageInstall()`);
			}
		}
		for (const skip of result.skips ?? []) skipped.push(`${result.key} → ${skip.id}: ${skip.reason}`);
	}

	console.log("");
	if (skipped.length > 0) {
		console.log(`SKIPPED_WITH_REASON (${skipped.length}) — reported, never counted as a pass:`);
		for (const entry of skipped) console.log(`  - ${entry}`);
		console.log("");
	}

	const failures = results.filter((result) => result.status === FAIL);
	if (failures.length > 0) {
		console.error("ERROR: release packages are not installable and usable from a clean consumer directory:");
		for (const result of failures) {
			const counts = new Map();
			for (const failure of result.failures ?? []) counts.set(failure.code, (counts.get(failure.code) ?? 0) + 1);
			console.error(`  - ${result.key}: ${[...counts].map(([code, count]) => `${code}×${count}`).join(", ")}`);
			for (const failure of (result.failures ?? []).slice(0, 3)) console.error(`      ${failure.detail}`);
		}
		console.error("");
		console.error('Run "pnpm build:release" first when the failure mentions source maps or missing release artifacts.');
	} else {
		const passed = results.filter((result) => result.status === PASS).length;
		const unresolved = results.filter((result) => result.status === SKIPPED_WITH_REASON).length;
		console.log(`Package install verification: ${passed}/${results.length} PASS, ${unresolved} SKIPPED_WITH_REASON, 0 FAIL, ${skipped.length} reported skip(s).`);
	}
	if (keep) console.log(`Temporary directories kept at ${tempRoot}`);
}

/** `file:` specifier that survives Windows drive letters and spaces. */
function fileSpecifier(from, target) {
	return `file:${path.relative(from, target).replaceAll("\\", "/")}`;
}

/* -------------------------------------------------------------------------- */
/* helpers                                                                    */
/* -------------------------------------------------------------------------- */

function packageNameOf(spec) {
	try {
		return JSON.parse(readFileSync(path.join(repoRoot, spec.key, "package.json"), "utf8")).name;
	} catch {
		return spec.display;
	}
}

function manifestOf(spec) {
	try {
		return JSON.parse(readFileSync(path.join(repoRoot, spec.key, "package.json"), "utf8"));
	} catch {
		return {};
	}
}

/** Runtime dependency names a package declares, workspace-internal or not. */
export function declaredDependencyNames(pkg) {
	const names = new Set();
	for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
		for (const name of Object.keys(pkg?.[field] ?? {})) names.add(name);
	}
	return names;
}

/** Release package names the given packages depend on, transitively. */
export function workspaceDependencyClosure(specs) {
	const byName = new Map(RELEASE_PACKAGES.map((spec) => [packageNameOf(spec), spec]));
	const needed = new Set();
	const queue = [...specs];
	const visited = new Set();
	while (queue.length > 0) {
		const spec = queue.shift();
		if (visited.has(spec.key)) continue;
		visited.add(spec.key);
		for (const name of declaredDependencyNames(manifestOf(spec))) {
			const dependency = byName.get(name);
			if (!dependency || needed.has(name)) continue;
			needed.add(name);
			queue.push(dependency);
		}
	}
	return needed;
}

/**
 * Restrict the packed workspace tarballs to the closure of a single package.
 * Installing every sibling tarball would widen the consumer project to the
 * whole workspace and make one unrelated unresolvable dependency fail a package
 * that has nothing to do with it.
 */
export function scopeTarballsTo(spec, packed) {
	const byName = new Map(RELEASE_PACKAGES.map((candidate) => [packageNameOf(candidate), candidate]));
	const scoped = new Map();
	const queue = [spec];
	const visited = new Set();
	while (queue.length > 0) {
		const current = queue.shift();
		if (visited.has(current.key)) continue;
		visited.add(current.key);
		for (const name of declaredDependencyNames(manifestOf(current))) {
			const tarball = packed.get(name);
			const dependency = byName.get(name);
			if (!tarball || !dependency || scoped.has(name)) continue;
			scoped.set(name, tarball);
			queue.push(dependency);
		}
	}
	return scoped;
}

function globToRegExp(pattern) {
	let source = "^";
	for (let index = 0; index < pattern.length; index++) {
		const char = pattern[index];
		if (char === "*") {
			if (pattern[index + 1] === "*") {
				index += 1;
				if (pattern[index + 1] === "/") {
					index += 1;
					source += "(?:.*/)?";
				} else {
					source += ".*";
				}
			} else {
				source += "[^/]*";
			}
		} else if (char === "?") {
			source += "[^/]";
		} else {
			source += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
		}
	}
	return new RegExp(`${source}$`);
}

function hasGlob(value) {
	return value.includes("*") || value.includes("?");
}

function safeRealpath(target) {
	try {
		return realpathSync(target);
	} catch {
		return target;
	}
}

function isFile(target) {
	try {
		return statSync(target).isFile();
	} catch {
		return false;
	}
}

function isDirectory(target) {
	try {
		return statSync(target).isDirectory();
	} catch {
		return false;
	}
}

function isWithin(candidate, root) {
	const relative = path.relative(root, candidate);
	return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function samePath(left, right) {
	const normalize = (value) => path.resolve(value).replace(/[\\/]+$/, "");
	return process.platform === "win32" ? normalize(left).toLowerCase() === normalize(right).toLowerCase() : normalize(left) === normalize(right);
}

function tail(value, lines) {
	const all = String(value ?? "").split(/\r?\n/).filter((line) => line.trim() !== "");
	return all.slice(-lines).join(" | ");
}

function formatError(error) {
	return error instanceof Error ? error.message : String(error);
}
