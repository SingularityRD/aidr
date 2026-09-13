import { access, cp, mkdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDir, "..");
const repositoryRoot = resolve(packageRoot, "..", "..");

const resourcesRoot = join(packageRoot, "resources");
const requiredAssets = ["threats", "allowlists"];

for (const asset of requiredAssets) {
	const source = join(repositoryRoot, asset);
	await assertReadableDir(source);
	await rm(join(resourcesRoot, asset), { recursive: true, force: true });
	await mkdir(resourcesRoot, { recursive: true });
	await cp(source, join(resourcesRoot, asset), { recursive: true, force: true });
}

console.log("Synced Codex connector assets (threats + allowlists).");

async function assertReadableDir(directory) {
	try {
		await access(directory);
	} catch {
		throw new Error(`Missing required connector asset directory: ${directory}`);
	}
}
