/**
 * Resolve Claude connector assets for both the repository plugin and a
 * packaged @singularityrd/aidr-claude-code install.
 *
 * The marketplace plugin keeps `threats/` and `allowlists/` at the plugin
 * root. A package consumer cannot rely on the monorepo cwd, so release builds
 * copy the same directories to integrity-covered `dist/resources/` and this resolver prefers
 * that location. Explicit environment overrides remain available for managed
 * deployments and customer-specific rule stores.
 */

import { existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

type AssetKind = "threats" | "allowlists";

const packageRoot = resolve(dirname(__dirname));
const repositoryRoot = resolve(packageRoot, "..", "..");

/**
 * Resolve a connector asset directory without assuming process.cwd() is the
 * repository. The first existing directory wins; if none exists, the
 * packaged resource path is returned so callers still produce a deterministic
 * missing-data signal rather than silently using an unrelated cwd directory.
 */
export function resolveAssetDir(kind: AssetKind): string {
	const envName = kind === "threats" ? "AIDR_THREATS_DIR" : "AIDR_ALLOWLISTS_DIR";
	const packaged = join(packageRoot, "dist", "resources", kind);
	const candidates = [
		process.env[envName],
		packaged,
		join(packageRoot, "resources", kind),
		join(packageRoot, kind),
		join(repositoryRoot, kind),
		join(process.cwd(), kind),
		join(homedir(), ".singularity-aidr", kind),
	];

	for (const candidate of candidates) {
		if (candidate && isDirectory(candidate)) return resolve(candidate);
	}

	return packaged;
}

/**
 * Resolve the Claude plugin root used for its optional plugin manifest and
 * installed-plugin discovery. `CLAUDE_PLUGIN_ROOT` is authoritative when the
 * host provides it; otherwise the marketplace checkout and package root are
 * considered in that order.
 */
export function resolvePluginRoot(): string {
	const explicit = process.env.CLAUDE_PLUGIN_ROOT || process.env.AIDR_PLUGIN_ROOT;
	if (explicit) return resolve(explicit);

	const candidates = [repositoryRoot, packageRoot, process.cwd()];
	for (const candidate of candidates) {
		if (existsSync(join(candidate, ".claude-plugin", "plugin.json"))) {
			return candidate;
		}
	}

	return packageRoot;
}

function isDirectory(candidate: string): boolean {
	try {
		return statSync(candidate).isDirectory();
	} catch {
		return false;
	}
}
