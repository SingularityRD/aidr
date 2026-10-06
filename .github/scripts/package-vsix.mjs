/**
 * Build both supported VS Code-family extension bundles from the already
 * built release dist. The frozen workspace lock supplies `@vscode/vsce`; the
 * workflow's exact version is checked before packaging.
 *
 * Required environment:
 *   VSCE_VERSION      exact @vscode/vsce version (x.y.z)
 *   VSIX_OUTPUT_DIR   output directory
 */

import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { finalizeReleaseBundle } from "../../scripts/lib/finalize-release-bundle.mjs";
import {
	assertVsixIntegrityEvidence,
} from "../../scripts/lib/vsix-package-files.mjs";

const repoRoot = resolve(import.meta.dirname, "../..");
const extensionRoot = join(repoRoot, "packages", "extension");
const outputDir = resolve(process.env.VSIX_OUTPUT_DIR ?? join(repoRoot, "release-output"));
const vsceVersion = process.env.VSCE_VERSION;
const { values } = parseArgs({ options: { "unsigned-candidate": { type: "boolean", default: false } } });

if (!/^\d+\.\d+\.\d+$/.test(vsceVersion ?? "")) {
	fail("VSCE_VERSION must be an exact x.y.z version");
}
assertVsceVersion(vsceVersion);

const baseManifest = JSON.parse(await readFile(join(extensionRoot, "package.json"), "utf8"));
await mkdir(outputDir, { recursive: true });

const variants = [
	{
		name: "aidr-cursor",
		main: "./dist/cursor_extension.js",
		output: "aidr-cursor.vsix",
	},
	{
		name: "aidr-vscode",
		main: "./dist/vscode_extension.js",
		output: "aidr-vscode.vsix",
	},
];

for (const variant of variants) {
	const stageDir = join(extensionRoot, ".vsce", `release-${variant.name}`);
	await rm(stageDir, { recursive: true, force: true });
	await mkdir(stageDir, { recursive: true });

	await cp(join(extensionRoot, "dist"), join(stageDir, "dist"), { recursive: true });
	for (const file of ["README.md", "LICENSE", "aidr-icon.png"]) {
		await cp(join(extensionRoot, file), join(stageDir, file));
	}
	const packageFiles = await assertVsixIntegrityEvidence(stageDir, { requireSignature: !values["unsigned-candidate"] });

	const manifest = {
		...baseManifest,
		name: variant.name,
		main: variant.main,
		private: undefined,
		files: packageFiles,
	};
	delete manifest.private;
	manifest.name = variant.name;
	if (variant.name === "aidr-vscode") {
		manifest.contributes = {
			...baseManifest.contributes,
			configuration: {
				title: "Singularity AIDR",
				properties: {
					"aidr.vscode.scope": {
						type: "string",
						default: "user",
						enum: ["workspace", "user"],
						description: "Where Singularity AIDR installs VS Code hooks.",
					},
					"aidr.hookRunnerPath": {
						type: "string",
						scope: "application",
						default: "",
						description: "Optional absolute path to an aidr-hook runner script.",
					},
				},
			},
		};
	}
	await writeFile(join(stageDir, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
	await assertNoSourceMaps(join(stageDir, "dist"));

	const outputPath = join(outputDir, variant.output);
	await runVsce(stageDir, outputPath);
	console.log(`Wrote ${outputPath}`);
}
if (values["unsigned-candidate"]) console.log("Unsigned VSIX candidate only; publisher signing and commercial runtime verification remain required.");

let releaseBundle = true;
try {
	await readFile(join(outputDir, "release-inventory.json"), "utf8");
} catch (error) {
	if (error?.code !== "ENOENT") throw error;
	releaseBundle = false;
}
// Standalone VSIX packaging has no release metadata to finalize.
if (releaseBundle) await finalizeReleaseBundle(outputDir);

async function assertNoSourceMaps(distDir) {
	const offenders = [];
	const stack = [distDir];
	while (stack.length > 0) {
		const current = stack.pop();
		const entries = await readdir(current, { withFileTypes: true });
		for (const entry of entries) {
			const full = join(current, entry.name);
			if (entry.isDirectory()) {
				stack.push(full);
				continue;
			}
			if (!entry.isFile()) continue;
			if (entry.name.endsWith(".map")) {
				offenders.push(`${full}: .map`);
				continue;
			}
			if (!/\.(?:c|m)?js$/.test(entry.name)) continue;
			const text = await readFile(full, "utf8");
			if (/^[ \t]*(?:\/\/#|\/\*#)\s*sourceMappingURL\s*[:=]/m.test(text)) {
				offenders.push(`${full}: sourceMappingURL`);
			}
		}
	}
	if (offenders.length > 0) fail(`Refusing to package source maps:\n${offenders.join("\n")}`);
}

function runVsce(cwd, outputPath) {
	return new Promise((resolveRun, rejectRun) => {
		const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
		const child = spawn(
			command,
			[
				"exec",
				"vsce",
				"package",
				"-o",
				outputPath,
				"--no-dependencies",
				"--allow-package-secrets",
				"github",
				"--allow-package-secrets",
				"slack",
			],
			// Windows resolves pnpm through a .cmd shim; direct child spawning can
			// return EINVAL. Keep Linux/macOS direct and use the shell only there.
			{ cwd, stdio: "inherit", shell: process.platform === "win32" },
		);
		child.on("error", rejectRun);
		child.on("exit", (code) => {
			if (code === 0) resolveRun();
			else rejectRun(new Error(`vsce exited with code ${code ?? "unknown"}`));
		});
	});
}

function assertVsceVersion(expected) {
	const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
	const result = spawnSync(command, ["exec", "vsce", "--version"], {
		cwd: repoRoot,
		encoding: "utf8",
		shell: process.platform === "win32",
	});
	if (result.error || result.status !== 0 || result.stdout.trim() !== expected) {
		fail(`installed @vscode/vsce must be exactly ${expected}`);
	}
}

function fail(message) {
	console.error(`ERROR: ${message}`);
	process.exit(1);
}
