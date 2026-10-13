/**
 * Integrity target of a standalone (single executable) installation.
 *
 * The desktop installers ship one multi-call SEA binary
 * (`packages/claude-code/scripts/build-sea.mjs`):
 *
 *   <bundle>/bin/aidr[.exe]                      CLI and every hook (`aidr hook <name>`)
 *   <bundle>/dist/{resources,response-worker.cjs,vendor,native}
 *   <bundle>/dist/aidr-artifact.manifest.json    runtime manifest ({@link STANDALONE_RUNTIME_ARTIFACT_ID})
 *   <bundle>/dist/aidr-artifact.manifest.sig     its Ed25519 signature (release builds)
 *   <bundle>/aidr-artifact.manifest.json         the whole bundle, checked by `aidr setup`
 *
 * Inside a SEA `__dirname` is the binary's directory, which holds no manifest,
 * so a hook passing its own `__dirname` would always report a missing manifest.
 * A hook running from the bundle verifies the runtime manifest instead: the
 * files it reads at run time (rules, allowlists, worker, native adapter). The
 * binary itself is checked by `aidr setup` against the bundle manifest; a hook
 * re-hashing its own executable would prove nothing a modified binary could
 * not skip.
 */

import { dirname, join } from "node:path";

/** `artifact_id` of `<bundle>/dist/aidr-artifact.manifest.json`. */
export const STANDALONE_RUNTIME_ARTIFACT_ID = "sea/dist";

/** Release reason recorded when a standalone bundle runs without its release key. */
export const RELEASE_KEY_MISSING_REASON = "release_key_missing";

interface SeaModule {
	isSea(): boolean;
}

/**
 * Whether this process is a Node single executable application. Resolved
 * without a static `node:sea` import so the same core code still loads in
 * hosts whose embedded Node predates that module (editor extension hosts).
 */
export function runningAsSea(): boolean {
	try {
		const getBuiltin = (process as unknown as { getBuiltinModule?: (id: string) => unknown })
			.getBuiltinModule;
		const sea = getBuiltin?.("node:sea") as SeaModule | undefined;
		return typeof sea?.isSea === "function" && sea.isSea() === true;
	} catch {
		return false;
	}
}

/** The runtime manifest a standalone hook verifies, or null outside a SEA. */
export function standaloneRuntimeArtifact(): { artifactDir: string; artifactId: string } | null {
	if (!runningAsSea()) return null;
	return {
		artifactDir: join(dirname(dirname(process.execPath)), "dist"),
		artifactId: STANDALONE_RUNTIME_ARTIFACT_ID,
	};
}
