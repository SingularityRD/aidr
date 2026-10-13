/**
 * Resolve Codex connector assets without assuming process.cwd() is the
 * repository.
 *
 * A package consumer cannot rely on the monorepo cwd, so builds copy
 * `threats/` and `allowlists/` into `dist/resources/`, inside the signed
 * artifact root, and this resolver prefers that location. The
 * `AIDR_THREATS_DIR` / `AIDR_ALLOWLISTS_DIR` overrides are honoured only in
 * development builds and are always reported (core `rule-dir-override.ts`,
 * {@link assetOverrideNotice}); a commercial build ignores them.
 *
 * Mirrors the proven resolver in `@singularityrd/aidr-claude-code` so every
 * connector answers "where are my rules?" the same way.
 */

import { existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	ruleDirOverride,
	ruleDirOverrideNotice,
	ruleDirOverrides,
	runningAsSea,
} from "@singularityrd/aidr-core";

type AssetKind = "threats" | "allowlists";

const moduleDir =
	typeof __dirname === "string" && isAbsolute(__dirname)
		? __dirname
		: dirname(fileURLToPath(import.meta.url));
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
	const override = ruleDirOverride(kind);
	if (runningAsSea()) {
		// Standalone bundle (desktop installers): the hook runs as `<bundle>/bin/aidr
		// hook aidr-codex-hook` and its rules ship in `<bundle>/dist/resources`,
		// covered by the bundle's runtime manifest. Nothing outside the bundle
		// (cwd, home, a parent directory) may stand in for them.
		const bundled = join(packageRoot, "dist", "resources", kind);
		return resolve(override?.accepted ? override.path : bundled);
	}
	const packaged = join(moduleDir, "resources", kind);
	const candidates = [
		override?.accepted ? override.path : undefined,
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

/**
 * The warning to show while an `AIDR_THREATS_DIR` / `AIDR_ALLOWLISTS_DIR`
 * override is set (used or, in a commercial build, ignored), else null.
 */
export function assetOverrideNotice(): string | null {
	return ruleDirOverrideNotice(ruleDirOverrides());
}
