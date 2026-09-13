import { access, cp, mkdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The CLI has to be able to load real threat definitions without depending on a
 * connector being installed, so it ships its own copy of the rule data (the same
 * approach the connector packages already use).
 *
 * `@singularityrd/aidr-core` intentionally publishes only `dist/` — it does not
 * ship the YAML rules — so resolving them from the core package at runtime is
 * not possible for a published install.
 */

const scriptDir = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDir, "..");
const repoRoot = resolve(packageRoot, "..", "..");

const sourceThreats = join(repoRoot, "threats");
const sourceAllowlists = join(repoRoot, "allowlists");

const resourcesDir = join(packageRoot, "resources");
const targetThreats = join(resourcesDir, "threats");
const targetAllowlists = join(resourcesDir, "allowlists");

await assertReadableDir(sourceThreats);
await assertReadableDir(sourceAllowlists);

await rm(resourcesDir, { recursive: true, force: true });
await mkdir(resourcesDir, { recursive: true });
await cp(sourceThreats, targetThreats, { recursive: true, force: true });
await cp(sourceAllowlists, targetAllowlists, { recursive: true, force: true });

console.log("Synced CLI assets (threats + allowlists).");

async function assertReadableDir(path) {
	try {
		await access(path);
	} catch {
		throw new Error(`Missing required directory: ${path}`);
	}
}
