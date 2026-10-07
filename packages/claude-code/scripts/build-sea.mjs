#!/usr/bin/env node
// Build standalone Single Executable Application (SEA) binaries for the Claude
// Code hook entry points, using the documented Node.js SEA flow:
//
//   1. bundle the entry points (esbuild.config.js)
//   2. node --experimental-sea-config sea-config.json  -> sea-prep.blob
//   3. copy process.execPath to the output binary
//   4. (macOS) strip the signature, inject the blob with postject, re-sign ad hoc
//
// Portable across Linux, macOS and Windows; requires an official Node.js build
// that carries the SEA sentinel fuse (Homebrew and other shared-libnode builds
// do not). Outputs: <repo>/bin/aidr-pre-tool-use and <repo>/bin/aidr-session-start
// (".exe" appended on Windows).

import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const SEA_SENTINEL_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
export const MIN_NODE_MAJOR = 20;

export const ENTRY_POINTS = [
	{ entry: "pre-tool-use", binary: "aidr-pre-tool-use" },
	{ entry: "session-start", binary: "aidr-session-start" },
];

/**
 * Decide whether a Node runtime can produce SEA binaries.
 * Pure function so it can be unit-tested without a real Node binary.
 *
 * @param {{ version: string, nodeShared?: boolean, binary?: Buffer | Uint8Array | null }} info
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function checkSeaSupport({ version, nodeShared = false, binary = null }) {
	const match = /^v?(\d+)\./.exec(version);
	const major = match ? Number(match[1]) : Number.NaN;
	if (!Number.isFinite(major) || major < MIN_NODE_MAJOR) {
		return {
			ok: false,
			reason: `Node ${version} does not support single executable applications; Node >= ${MIN_NODE_MAJOR} is required (the repo targets >= 22.12).`,
		};
	}
	if (nodeShared) {
		return {
			ok: false,
			reason: "This Node binary is built against a shared libnode (e.g. Homebrew), which cannot host a SEA blob.",
		};
	}
	if (binary) {
		const buf = Buffer.isBuffer(binary) ? binary : Buffer.from(binary);
		const first = buf.indexOf(SEA_SENTINEL_FUSE);
		if (first === -1) {
			return {
				ok: false,
				reason: `This Node binary does not contain the SEA sentinel fuse (${SEA_SENTINEL_FUSE}); it was built without SEA support (e.g. Homebrew).`,
			};
		}
		if (buf.lastIndexOf(SEA_SENTINEL_FUSE) !== first) {
			return { ok: false, reason: "The SEA sentinel fuse occurs more than once in this Node binary." };
		}
		const state = buf.subarray(first + SEA_SENTINEL_FUSE.length, first + SEA_SENTINEL_FUSE.length + 2).toString();
		if (state === ":1") {
			return { ok: false, reason: "This Node binary is itself a SEA (fuse already flipped); run the build with a plain node." };
		}
	}
	return { ok: true };
}

/** Output file name for a binary on the given platform. */
export function binaryFileName(name, platform = process.platform) {
	return platform === "win32" ? `${name}.exe` : name;
}

function fail(message) {
	console.error(`ERROR: ${message}`);
	console.error("       Install the official Node.js binary from https://nodejs.org (or use nvm/fnm/volta);");
	console.error("       CI uses actions/setup-node, which provides the official binary.");
	process.exit(1);
}

function run(cmd, args, opts = {}) {
	const result = spawnSync(cmd, args, { stdio: "inherit", ...opts });
	if (result.error) throw result.error;
	if (result.status !== 0) {
		throw new Error(`${cmd} ${args.join(" ")} exited with status ${result.status}`);
	}
}

async function main() {
	const scriptDir = dirname(fileURLToPath(import.meta.url));
	const pkgDir = resolve(scriptDir, "..");
	const repoRoot = resolve(pkgDir, "..", "..");
	const binDir = join(repoRoot, "bin");
	const distDir = join(pkgDir, "dist");
	const nodePath = process.execPath;

	const support = checkSeaSupport({
		version: process.version,
		nodeShared: process.config?.variables?.node_shared === true,
		binary: readFileSync(nodePath),
	});
	if (!support.ok) fail(`${support.reason}\n       Node binary: ${nodePath}`);

	// Resolve postject locally (devDependency) — never via npx / network.
	const require = createRequire(import.meta.url);
	let inject;
	try {
		({ inject } = require("postject"));
	} catch {
		fail("postject is not installed. Run `pnpm install` at the repo root.");
	}

	console.log("Building JS bundles...");
	run(nodePath, ["esbuild.config.js"], { cwd: pkgDir });

	mkdirSync(binDir, { recursive: true });

	for (const { entry, binary } of ENTRY_POINTS) {
		const main = join(distDir, `${entry}.cjs`);
		statSync(main); // throws a clear ENOENT if the bundle is missing
		const blob = join(distDir, `sea-prep-${entry}.blob`);
		const seaConfig = join(distDir, `sea-config-${entry}.json`);
		const output = join(binDir, binaryFileName(binary));

		console.log(`Building SEA binary: ${output}`);
		writeFileSync(
			seaConfig,
			`${JSON.stringify({ main, output: blob, disableExperimentalSEAWarning: true, useCodeCache: false }, null, 2)}\n`,
		);
		run(nodePath, ["--experimental-sea-config", seaConfig], { cwd: pkgDir });

		rmSync(output, { force: true });
		copyFileSync(nodePath, output);
		if (process.platform !== "win32") chmodSync(output, 0o755);

		if (process.platform === "darwin") {
			run("codesign", ["--remove-signature", output]);
		}

		await inject(output, "NODE_SEA_BLOB", readFileSync(blob), {
			sentinelFuse: SEA_SENTINEL_FUSE,
			...(process.platform === "darwin" ? { machoSegmentName: "NODE_SEA" } : {}),
		});

		if (process.platform === "darwin") {
			run("codesign", ["--sign", "-", output]);
		}

		rmSync(blob, { force: true });
		rmSync(seaConfig, { force: true });
		console.log(`Built: ${output}`);
	}

	console.log(`\nSEA build complete. Binaries in ${binDir}`);
	if (process.platform === "win32") {
		console.log("Note: Windows binaries are unsigned; sign them with signtool before distribution.");
	}
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
	main().catch((err) => {
		console.error(`ERROR: SEA build failed: ${err?.message ?? err}`);
		process.exit(1);
	});
}
