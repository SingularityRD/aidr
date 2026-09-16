import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runWorkspaceBuild } from "./build-workspace.mjs";
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
