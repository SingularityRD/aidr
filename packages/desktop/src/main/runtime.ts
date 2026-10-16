import { cpSync, existsSync, readFileSync, renameSync, rmSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import {
	type StandaloneBundleCheck,
	verifyStandaloneBundle,
} from "../../../cli/src/utils/standalone.js";
import { runtimesDir } from "./paths.js";

/**
 * The AIDR runtime the app ships is the relocatable standalone bundle built by
 * `packages/claude-code/scripts/build-sea.mjs` (one multi-call `aidr.exe` that
 * serves the CLI and every hook, plus the rules it loads). The desktop
 * installers of the product register the hooks of exactly this bundle.
 *
 * Hooks must keep working when the app is closed, updated or uninstalled, so
 * they never point into the app's install directory. Before connecting, the
 * bundle is copied to a per-user, version-addressed directory under
 * `~/.singularity-aidr/desktop/runtime/<version>-<manifest digest>` and
 * verified there file by file against its manifest.
 */

export interface InstalledRuntime {
	root: string;
	check: StandaloneBundleCheck;
	copied: boolean;
}

export function checkRuntime(root: string): StandaloneBundleCheck {
	return verifyStandaloneBundle(root);
}

function isInside(child: string, parent: string): boolean {
	const path = relative(resolve(parent), resolve(child));
	return path !== "" && !path.startsWith("..") && !isAbsolute(path);
}

/** The stable per-user directory for a verified bundle. */
export function installedRuntimeDir(home: string, check: StandaloneBundleCheck): string {
	if (!check.manifestSha256) throw new Error("the bundle has no manifest digest");
	const version = (check.version ?? "0.0.0").replace(/[^0-9A-Za-z.+-]/g, "_");
	return join(runtimesDir(home), `${version}-${check.manifestSha256.slice(0, 16)}`);
}

/**
 * Copy the bundled runtime to its per-user directory (once per bundle digest)
 * and verify the copy. A copy that fails verification is replaced; a bundle
 * that fails verification is never copied.
 */
export function ensureInstalledRuntime(source: string, home: string): InstalledRuntime {
	const sourceCheck = checkRuntime(source);
	if (!sourceCheck.ok) {
		throw new Error(
			`the AIDR runtime shipped with the app failed verification: ${sourceCheck.problems.slice(0, 3).join("; ")}`,
		);
	}
	const target = installedRuntimeDir(home, sourceCheck);
	if (existsSync(target)) {
		const existing = checkRuntime(target);
		if (existing.ok && existing.manifestSha256 === sourceCheck.manifestSha256) {
			return { root: target, check: existing, copied: false };
		}
		if (!isInside(target, runtimesDir(home))) throw new Error(`refusing to replace ${target}`);
		rmSync(target, { recursive: true, force: true });
	}
	const staging = `${target}.staging-${process.pid}-${Date.now()}`;
	try {
		cpSync(source, staging, { recursive: true, errorOnExist: true, force: false });
		const staged = checkRuntime(staging);
		if (!staged.ok || staged.manifestSha256 !== sourceCheck.manifestSha256) {
			throw new Error(
				`the copied runtime failed verification: ${staged.problems.slice(0, 3).join("; ")}`,
			);
		}
		renameSync(staging, target);
	} finally {
		rmSync(staging, { recursive: true, force: true });
	}
	const check = checkRuntime(target);
	if (!check.ok) throw new Error(`the installed runtime failed verification: ${check.problems[0]}`);
	return { root: target, check, copied: true };
}

/** `sea.flavor` and signature facts from a bundle manifest, for display. */
export function runtimeFlavor(root: string): { flavor: string | null; signed: boolean } {
	try {
		const manifest = JSON.parse(
			readFileSync(join(root, "aidr-artifact.manifest.json"), "utf8"),
		) as {
			sea?: { flavor?: unknown; signed?: unknown };
		};
		return {
			flavor: typeof manifest.sea?.flavor === "string" ? manifest.sea.flavor : null,
			signed: manifest.sea?.signed === true,
		};
	} catch {
		return { flavor: null, signed: false };
	}
}
