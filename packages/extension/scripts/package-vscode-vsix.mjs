import { spawn } from "node:child_process";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	assertVsixIntegrityEvidence,
	VSIX_PACKAGE_FILES,
} from "../../../scripts/lib/vsix-package-files.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);
const extensionRoot = resolve(scriptDir, "..");
const repoRoot = resolve(extensionRoot, "..", "..");

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
	await main();
}

async function main() {
	await packageVsixVariant("vscode");
}

export async function packageVsixVariant(variant) {
	if (variant !== "cursor" && variant !== "vscode") {
		throw new Error(`Unsupported VSIX variant: ${variant}`);
	}
	const stageDir = join(extensionRoot, ".vsce", `${variant}_extension`);
	const outputVsix = join(repoRoot, `aidr-${variant}.vsix`);

	const baseManifest = JSON.parse(await readFile(join(extensionRoot, "package.json"), "utf8"));
	const stagedManifest = variant === "vscode" ? buildVsCodeManifest(baseManifest) : buildCursorManifest(baseManifest);

	await rm(stageDir, { recursive: true, force: true });
	await mkdir(stageDir, { recursive: true });
	await cp(join(extensionRoot, "dist"), join(stageDir, "dist"), {
		recursive: true,
		force: true,
	});
	await cp(join(extensionRoot, "README.md"), join(stageDir, "README.md"), { force: true });
	await cp(join(extensionRoot, "LICENSE"), join(stageDir, "LICENSE"), { force: true });
	await cp(join(extensionRoot, "aidr-icon.png"), join(stageDir, "aidr-icon.png"), {
		force: true,
	});
	await copyLocalizationFiles(extensionRoot, stageDir);
	await writeFile(
		join(stageDir, "package.json"),
		`${JSON.stringify(stagedManifest, null, 2)}\n`,
		"utf8",
	);

	await assertNoSourceMaps(join(stageDir, "dist"));
	await assertVsixIntegrityEvidence(stageDir);
	await runVscePackage(stageDir, outputVsix);
}

/** Manifest translations and runtime l10n bundles; package.json refers to them by key. */
export async function copyLocalizationFiles(fromDir, toDir) {
	for (const file of ["package.nls.json", "package.nls.tr.json"]) {
		await cp(join(fromDir, file), join(toDir, file), { force: true });
	}
	await cp(join(fromDir, "l10n"), join(toDir, "l10n"), { recursive: true, force: true });
}

export function buildCursorManifest(base) {
	return { ...base, files: [...VSIX_PACKAGE_FILES] };
}

export function buildVsCodeManifest(base) {
	const manifest = { ...base };
	manifest.name = "aidr-vscode";
	manifest.displayName = "Singularity AIDR";
	manifest.description = "%extension.description%";
	manifest.main = "./dist/vscode_extension.js";
	manifest.files = [...VSIX_PACKAGE_FILES];
	manifest.contributes = {
		...base.contributes,
		configuration: {
			title: "Singularity AIDR",
			properties: {
				"aidr.vscode.scope": {
					type: "string",
					default: "user",
					enum: ["workspace", "user"],
					description: "%config.vscodeScope.description%",
				},
				"aidr.hookRunnerPath": {
					type: "string",
					scope: "application",
					default: "",
					description: "%config.hookRunnerPath.description%",
				},
			},
		},
	};
	return manifest;
}

function runVscePackage(workingDirectory, outputPath) {
	return new Promise((resolveRun, rejectRun) => {
		const child = spawn(
			"pnpm",
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
			{
				cwd: workingDirectory,
				stdio: "inherit",
				shell: process.platform === "win32",
			},
		);
		child.on("error", rejectRun);
		child.on("exit", (code) => {
			if (code === 0) {
				resolveRun(undefined);
				return;
			}
			rejectRun(new Error(`vsce exited with code ${code ?? "unknown"}`));
		});
	});
}

async function assertNoSourceMaps(distDir) {
	const sourceMappingDirectiveRe = /^[ \t]*(?:\/\/#|\/\*#)\s*sourceMappingURL\s*[:=]/m;
	const offenders = [];
	const stack = [distDir];
	while (stack.length) {
		const dir = stack.pop();
		let entries;
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			const full = join(dir, entry.name);
			if (entry.isDirectory()) {
				stack.push(full);
				continue;
			}
			if (!entry.isFile()) continue;
			if (entry.name.endsWith(".map")) {
				offenders.push(`${full} (.map)`);
				continue;
			}
			if (entry.name.endsWith(".js") || entry.name.endsWith(".cjs") || entry.name.endsWith(".mjs")) {
				const raw = await readFile(full, "utf8");
				if (sourceMappingDirectiveRe.test(raw)) {
					offenders.push(`${full} (sourceMappingURL=)`);
				}
			}
		}
	}

	if (offenders.length) {
		throw new Error(
			`Refusing to package VSIX with sourcemap artifacts:\n${offenders.map((o) => `- ${o}`).join("\n")}`,
		);
	}
}
