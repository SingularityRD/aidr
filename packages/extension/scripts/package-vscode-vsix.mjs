import { spawn } from "node:child_process";
import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(scriptDir, "..");
const repoRoot = resolve(extensionRoot, "..", "..");

const stageDir = join(extensionRoot, ".vsce", "vscode_extension");
const outputVsix = join(repoRoot, "aidr-vscode.vsix");

const baseManifest = JSON.parse(await readFile(join(extensionRoot, "package.json"), "utf8"));
const vscodeManifest = buildVsCodeManifest(baseManifest);

await rm(stageDir, { recursive: true, force: true });
await mkdir(stageDir, { recursive: true });
await cp(join(extensionRoot, "dist"), join(stageDir, "dist"), { recursive: true, force: true });
await cp(join(extensionRoot, "resources"), join(stageDir, "resources"), {
	recursive: true,
	force: true,
});
await cp(join(extensionRoot, "README.md"), join(stageDir, "README.md"), { force: true });
await cp(join(extensionRoot, "LICENSE"), join(stageDir, "LICENSE"), { force: true });
await cp(join(extensionRoot, "aidr-icon.png"), join(stageDir, "aidr-icon.png"), { force: true });
await writeFile(join(stageDir, "package.json"), `${JSON.stringify(vscodeManifest, null, 2)}\n`, "utf8");

await assertNoSourceMaps(join(stageDir, "dist"));

await runVscePackage(stageDir, outputVsix);

function buildVsCodeManifest(base) {
	const manifest = { ...base };
	manifest.name = "aidr-vscode";
	manifest.displayName = "Singularity AIDR";
	manifest.description =
		"Singularity AIDR — protects AI agent tool calls against dangerous commands, malicious URLs, and harmful file writes.";
	manifest.main = "./dist/vscode_extension.js";
	manifest.files = [
		"dist/vscode_extension.js",
		"dist/aidr-hook.cjs",
		"resources/**",
		"aidr-icon.png",
		"package.json",
		"README.md",
		"LICENSE",
	];
	manifest.contributes = {
		...base.contributes,
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
	return manifest;
}

function runVscePackage(workingDirectory, outputPath) {
	return new Promise((resolveRun, rejectRun) => {
		const child = spawn(
			"pnpm",
			[
				"dlx",
				"@vscode/vsce",
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
