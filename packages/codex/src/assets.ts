/**
 * Resolve Codex connector assets without assuming process.cwd() is the
 * repository.
 *
 * A package consumer cannot rely on the monorepo cwd, so release builds copy
 * `threats/` and `allowlists/` into `resources/` next to `dist/`, and this
 * resolver prefers that location. Explicit environment overrides stay available
 * for managed deployments and customer-specific rule stores.
 *
 * Mirrors the proven resolver in `@singularityrd/aidr-claude-code` so every
 * connector answers "where are my rules?" the same way.
 */

import { existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

type AssetKind = "threats" | "allowlists";

const moduleDir = typeof __dirname === "string" ? __dirname : dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(dirname(moduleDir));
const repositoryRoot = resolve(packageRoot, "..", "..");

function isDirectory(candidate: string): boolean {
	try {
		return statSync(candidate).isDirectory();
	} catch {
		return false;
	}
}

/**
 * Resolve a connector asset directory. The first existing directory wins; if
 * none exists the packaged resource path is returned so that callers still
 * produce a deterministic missing-data signal instead of silently reading an
 * unrelated cwd directory.
 */
export function resolveAssetDir(kind: AssetKind): string {
	const envName = kind === "threats" ? "AIDR_THREATS_DIR" : "AIDR_ALLOWLISTS_DIR";
	const packaged = join(packageRoot, "resources", kind);
	const candidates = [
		process.env[envName],
		packaged,
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
 * True when a rule directory is actually present. Callers must use this to
 * report a missing rule set explicitly rather than treating "no rules" as
 * "nothing malicious found".
 */
export function hasAssetDir(kind: AssetKind): boolean {
	return existsSync(resolveAssetDir(kind));
}
