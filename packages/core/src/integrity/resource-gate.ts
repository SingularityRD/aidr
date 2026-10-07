/**
 * Resource gate for verified artifacts.
 *
 * The integrity manifest proves that every file it LISTS is unmodified. On its
 * own it says nothing about files it does not list, and the rule and allowlist
 * loaders enumerate their directories: an extra `dist/resources/allowlists/*.yaml`
 * (a new trusted installer domain) or an extra threat file (a rule ID that
 * shadows nothing but changes matching) would be loaded although no signature
 * covers it.
 *
 * Once a manifest has verified (`verifyArtifactIntegrityAndLog` registers it),
 * integrity is being enforced for this process and every bundled resource file
 * must be one of the files that manifest lists. A file outside the verified
 * artifact root, or inside it but unlisted, is refused. Nothing is registered
 * when integrity is not enforced (development builds with integrity off,
 * tests), so the gate is then a no-op.
 */

import path from "node:path";

interface VerifiedManifest {
	root: string;
	files: ReadonlySet<string>;
}

let verified: VerifiedManifest | null = null;

function normalizeKey(value: string): string {
	const slashed = value.replace(/\\/g, "/");
	// NTFS and APFS (default) are case-insensitive; compare like the filesystem.
	return process.platform === "win32" || process.platform === "darwin"
		? slashed.toLowerCase()
		: slashed;
}

/** Record the files a verified manifest covers. Called only after verification succeeded. */
export function registerVerifiedManifest(artifactDir: string, files: readonly string[]): void {
	verified = {
		root: path.resolve(artifactDir),
		files: new Set(files.map((file) => normalizeKey(file.trim()))),
	};
}

/** Test hook and integrity-failure path: forget any registered manifest. */
export function clearVerifiedManifest(): void {
	verified = null;
}

/** True when a verified manifest is constraining which resource files may load. */
export function isResourceGateActive(): boolean {
	return verified !== null;
}

/**
 * Why a bundled resource file may not be loaded, or null when it may. Always
 * null when no verified manifest is registered.
 */
export function unlistedResourceReason(filePath: string): string | null {
	if (!verified) return null;
	const relative = path.relative(verified.root, path.resolve(filePath));
	if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
		return `${filePath} is outside the integrity-verified artifact`;
	}
	if (!verified.files.has(normalizeKey(relative))) {
		return `${relative.replace(/\\/g, "/")} is not listed in the verified integrity manifest`;
	}
	return null;
}
