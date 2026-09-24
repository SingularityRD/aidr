import { access, cp, mkdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDir, "..");
const repositoryRoot = resolve(packageRoot, "..", "..");

// Runtime assets live under dist so the signed artifact manifest and the hook
// verify one closed tree. Keeping executable code in dist while loading policy
// from an unsigned sibling directory would let an installed rule set change
// without failing commercial startup.
const resourcesRoot = join(packageRoot, "dist", "resources");
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
