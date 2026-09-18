import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { assertNoReleaseSourceMaps, runWorkspaceBuild, sourceMapsInPackageDist } from "./build-workspace.mjs";
import { ensureCoreBuild } from "./ensure-core-build.mjs";

function fixture() {
	const root = mkdtempSync(join(tmpdir(), "aidr-build-workspace-"));
	const core = join(root, "packages", "core");
	mkdirSync(join(core, "src", "generated"), { recursive: true });
	mkdirSync(join(core, "dist", "generated"), { recursive: true });
	writeFileSync(join(core, "tsconfig.json"), "{}\n");
	writeFileSync(join(core, "src", "index.ts"), "export const value = 1;\n");
	writeFileSync(join(core, "src", "generated", "data.json"), "{\"value\":1}\n");
	writeFileSync(join(core, "dist", "generated", "data.json"), "{\"value\":1}\n");
	writeFileSync(join(core, "dist", "index.js"), "export const stale = true;\n");
	writeFileSync(join(core, "dist", "index.d.ts"), "export declare const stale: true;\n");
	writeFileSync(join(core, "dist", "aig-infra-scan.d.ts.map"), "stale declaration map\n");
	return { root, core };
}

function emitReleaseCore(core) {
	rmSync(join(core, "dist"), { recursive: true, force: true });
	mkdirSync(join(core, "dist", "generated"), { recursive: true });
	writeFileSync(join(core, "dist", "generated", "data.json"), "{\"value\":1}\n");
	writeFileSync(join(core, "dist", "index.js"), "export const release = true;\n");
	writeFileSync(join(core, "dist", "index.d.ts"), "export declare const release: true;\n");
	const future = new Date(Date.now() + 2_000);
	utimesSync(join(core, "dist", "index.js"), future, future);
	utimesSync(join(core, "dist", "index.d.ts"), future, future);
}

function mapsUnder(dir) {
	const found = [];
	const walk = (current) => {
		for (const entry of readdirSync(current, { withFileTypes: true })) {
			const full = join(current, entry.name);
			if (entry.isDirectory()) walk(full);
			else if (entry.name.endsWith(".map")) found.push(full);
		}
	};
	walk(dir);
	return found;
}

test("release build removes stale maps and blocks normal connector core rebuilds", () => {
	const { root, core } = fixture();
	let normalCoreBuilds = 0;
	let connectorEnsures = 0;
	try {
		const status = runWorkspaceBuild({
			releaseMode: true,
			repoRoot: root,
			finalizeRelease: false,
			runPnpm(args, env) {
				if (args.includes("@singularityrd/aidr-core")) {
					emitReleaseCore(core);
					return 0;
				}
				if (args[0] === "-r") {
					for (let index = 0; index < 3; index += 1) {
						connectorEnsures += 1;
						assert.equal(
							ensureCoreBuild({ repoRoot: root, env, runBuild: () => (normalCoreBuilds += 1) }),
							0,
						);
					}

					// Simulate a source edit making core look stale while a separate normal
					// connector tries to ensure core. The release lock must reject it before
					// its normal tsc can restore declaration/source maps.
					const future = new Date(Date.now() + 4_000);
					utimesSync(join(core, "src", "index.ts"), future, future);
					assert.equal(
						ensureCoreBuild({ repoRoot: root, env: {}, runBuild: () => {
							normalCoreBuilds += 1;
							writeFileSync(join(core, "dist", "aig-infra-scan.d.ts.map"), "normal map\n");
						} }),
						1,
					);
					return 0;
				}
				return 0;
			},
		});

		assert.equal(status, 0);
		assert.equal(connectorEnsures, 3);
		assert.equal(normalCoreBuilds, 0);
		assert.deepEqual(mapsUnder(join(core, "dist")), []);
		assert.equal(existsSync(join(core, ".aidr-build.lock")), false);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("release build fails closed if core output gains a map", () => {
	const { root, core } = fixture();
	try {
		const status = runWorkspaceBuild({
			releaseMode: true,
			repoRoot: root,
			finalizeRelease: false,
			runPnpm(args) {
				if (args.includes("@singularityrd/aidr-core")) emitReleaseCore(core);
				if (args[0] === "-r") writeFileSync(join(core, "dist", "aig-infra-scan.d.ts.map"), "contamination\n");
				return 0;
			},
		});
		assert.equal(status, 1);
		assert.equal(existsSync(join(core, ".aidr-build.lock")), false);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

// A release publishes every package's dist, not only core's. The original guard
// inspected packages/core alone, so a concurrent non-release rebuild of another
// package could drop maps into an already-finalized artifact and the release
// would still assemble. Observed in production use: 363 maps across cli (56),
// opencode (18), core (276), claude-code (5), extension (3), sdk (3), codex (1)
// and openclaw (1).
test("release build fails closed if ANY published package gains a map", () => {
	const { root, core } = fixture();
	try {
		const status = runWorkspaceBuild({
			releaseMode: true,
			repoRoot: root,
			finalizeRelease: false,
			runPnpm(args) {
				if (args.includes("@singularityrd/aidr-core")) emitReleaseCore(core);
				if (args[0] === "-r") {
					// A sibling package's own release build is not the only writer;
					// a non-release rebuild contaminates its dist the same way.
					mkdirSync(join(root, "packages", "cli", "dist", "commands"), { recursive: true });
					writeFileSync(join(root, "packages", "cli", "dist", "commands", "collect.js.map"), "contamination\n");
				}
				return 0;
			},
		});
		assert.equal(status, 1);
		assert.equal(existsSync(join(core, ".aidr-build.lock")), false);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

// A release build is expected to start from a checkout whose connector dists
// hold maps from an ordinary `pnpm build` (which every test run performs via
// globalSetup). Those packages are about to be rebuilt in release mode, so their
// pre-existing maps must not abort the build before it can clean them. Checking
// every package immediately after the core step did exactly that and made a
// valid release fail with "contaminated in 7 package(s)" while naming packages
// the build had not reached yet.
test("release build tolerates pre-existing connector maps it is about to rebuild", () => {
	const { root, core } = fixture();
	let connectorRebuilt = false;
	try {
		// A previous normal build left maps in two connector dists.
		for (const packageName of ["cli", "opencode"]) {
			mkdirSync(join(root, "packages", packageName, "dist"), { recursive: true });
			writeFileSync(join(root, "packages", packageName, "dist", "index.js.map"), "stale normal map\n");
			writeFileSync(join(root, "packages", packageName, "dist", "index.js"), "export {};\n");
		}

		const status = runWorkspaceBuild({
			releaseMode: true,
			repoRoot: root,
			finalizeRelease: false,
			runPnpm(args) {
				if (args.includes("@singularityrd/aidr-core")) {
					emitReleaseCore(core);
					return 0;
				}
				if (args[0] === "-r") {
					// The connector release builds clean their own dists.
					connectorRebuilt = true;
					for (const packageName of ["cli", "opencode"]) {
						rmSync(join(root, "packages", packageName, "dist"), { recursive: true, force: true });
						mkdirSync(join(root, "packages", packageName, "dist"), { recursive: true });
						writeFileSync(join(root, "packages", packageName, "dist", "index.js"), "export const release = true;\n");
					}
				}
				return 0;
			},
		});

		assert.equal(connectorRebuilt, true, "the connector build phase must be reached");
		assert.equal(status, 0, "pre-existing connector maps must not abort a release build");
		assert.deepEqual(mapsUnder(join(root, "packages", "cli", "dist")), []);
		assert.deepEqual(mapsUnder(join(root, "packages", "opencode", "dist")), []);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("release build still fails when a connector leaves a map behind after its own rebuild", () => {
	const { root, core } = fixture();
	try {
		mkdirSync(join(root, "packages", "cli", "dist"), { recursive: true });
		writeFileSync(join(root, "packages", "cli", "dist", "index.js"), "export {};\n");
		const status = runWorkspaceBuild({
			releaseMode: true,
			repoRoot: root,
			finalizeRelease: false,
			runPnpm(args) {
				if (args.includes("@singularityrd/aidr-core")) emitReleaseCore(core);
				if (args[0] === "-r") {
					// The connector's own release build is the writer this time, so the
					// map survives into the published artifact and must fail the build.
					writeFileSync(join(root, "packages", "cli", "dist", "index.js.map"), "post-rebuild contamination\n");
				}
				return 0;
			},
		});
		assert.equal(status, 1);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});

test("release source-map guard covers every published package, not only core", () => {
	for (const packageName of ["core", "cli", "opencode", "claude-code", "extension", "sdk", "codex", "openclaw", "dashboard", "mcp-gateway"]) {
		const root = mkdtempSync(join(tmpdir(), "aidr-release-maps-"));
		try {
			mkdirSync(join(root, "packages", packageName, "dist"), { recursive: true });
			writeFileSync(join(root, "packages", packageName, "dist", "index.js"), "export {};\n");
			assert.doesNotThrow(
				() => assertNoReleaseSourceMaps(root),
				`${packageName}: a clean dist must pass`,
			);
			writeFileSync(join(root, "packages", packageName, "dist", "index.js.map"), "{}");
			assert.throws(
				() => assertNoReleaseSourceMaps(root),
				(error) => error.message.includes("source maps") && error.message.includes(packageName),
				`${packageName}: a map in this package must fail the release`,
			);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	}
});

test("release source-map guard reports nested maps, tolerates absent dist, and lists every offender", () => {
	const root = mkdtempSync(join(tmpdir(), "aidr-release-maps-"));
	try {
		// An absent dist is clean, not an error: not every package ships one.
		assert.deepEqual(sourceMapsInPackageDist(root, "sdk"), []);
		assert.doesNotThrow(() => assertNoReleaseSourceMaps(root));

		const nested = Array.from({ length: 8 }, (_, index) => `commands/deep/command-${index}.d.ts.map`);
		mkdirSync(join(root, "packages", "cli", "dist", "commands", "deep"), { recursive: true });
		for (const relativePath of nested) writeFileSync(join(root, "packages", "cli", "dist", relativePath), "{}");
		assert.equal(sourceMapsInPackageDist(root, "cli").length, 8);

		mkdirSync(join(root, "packages", "codex", "dist"), { recursive: true });
		writeFileSync(join(root, "packages", "codex", "dist", "pre-tool-use.cjs.map"), "{}");
		assert.throws(() => assertNoReleaseSourceMaps(root), (error) => {
			// Both offenders are named, and the detail is capped so the message stays readable.
			return error.message.includes("cli") && error.message.includes("codex") &&
				error.message.includes("(+3 more)") && error.message.includes("2 package(s)");
		});

		// A non-map file whose name merely mentions maps must not be treated as one.
		writeFileSync(join(root, "packages", "codex", "dist", "sourcemap-notes.txt"), "{}");
		assert.deepEqual(sourceMapsInPackageDist(root, "codex"), ["pre-tool-use.cjs.map"]);
	} finally {
		rmSync(root, { recursive: true, force: true });
	}
});
