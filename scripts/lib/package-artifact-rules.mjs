/**
 * Packaging rules shared by the release artifact gates.
 *
 * `check-no-sourcemaps.mjs` and `verify-package-install.mjs` must agree on what
 * counts as debug/source leakage. The rules live here instead of being restated
 * in each gate, so a release artifact can never satisfy one gate and fail the
 * other for the same bytes.
 *
 * Keep this module dependency-free: every gate and its `node --test` suite
 * imports it directly.
 */

import path from "node:path";

/** Directories that are never part of a shipped release artifact. */
export const IGNORE_DIRS = new Set(["node_modules", ".git", ".changeset", ".pnpm", ".vscode", ".idea"]);

export const SOURCE_MAPPING_DIRECTIVE_RE = /^[ \t]*(?:\/\/#|\/\*#)\s*sourceMappingURL\s*[:=]/m;
export const SOURCE_URL_DIRECTIVE_RE = /^[ \t]*(?:\/\/#|\/\*#)\s*sourceURL\s*[:=]/m;

/** True when the file name carries debug/sourcemap information. */
export function isSourceMapFile(fileName) {
	return fileName.endsWith(".map");
}

/** Archives assembled for consumers and therefore subject to package hygiene checks. */
export function isConsumerArchive(fileName) {
	return fileName.endsWith(".tgz") || fileName.endsWith(".tar.gz");
}

/** True when a tar listing exposes source, test, dependency, or environment content. */
export function hasForbiddenArchiveEntry(listing) {
	return /\.map(?:\s|$)|node_modules|(?:^|\/)\.env(?:\.|$)|(?:^|\/)package\/(?:src|tests|__tests__)\/|(?:^|\/)__tests__\/|\.(?:test|spec)\.(?:[cm]?[jt]sx?|d\.ts)(?:\s|$)/im.test(listing);
}

/** True when the directory is the one release artifacts are emitted into. */
export function isDistDir(dirPath) {
	return path.basename(dirPath) === "dist";
}
