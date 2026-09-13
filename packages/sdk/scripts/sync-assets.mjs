import { access, cp, mkdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The SDK has to be able to load real threat definitions from a published
 * install, so it ships its own copy of the rule data (the same approach the CLI
 * and connector packages already use).
 *
 * `@singularityrd/aidr-core` intentionally publishes only `dist/` — it does not
 * ship the YAML rules — so resolving them from the core package at runtime is
 * not possible for a published install, and `process.cwd()` is the *consumer's*
 * working directory, never the SDK's. Before this existed the SDK loaded
 * `"threats"` relative to the cwd, so every packaged `init()` threw.
 *
 * `resources/` is gitignored and generated here by `pnpm build`; the published
 * tarball picks it up through the `files` field in package.json.
 * `src/bundled-dirs.ts` resolves it relative to the running module.
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

console.log("Synced SDK assets (threats + allowlists).");

async function assertReadableDir(path) {
	try {
		await access(path);
	} catch {
		throw new Error(`Missing required directory: ${path}`);
	}
}
