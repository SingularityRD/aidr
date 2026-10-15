/**
 * Best-effort V8 compile cache for the per-call hook processes.
 *
 * Every hook call is a new Node process that compiles a multi-megabyte bundle
 * (~115 ms of a ~0.5 s call, docs/production-readiness/hook-latency-2026-10-11.md).
 * `module.enableCompileCache(dir)` (Node >= 22.1) lets later processes reuse
 * the V8 code cache that an earlier one wrote. It only applies to modules
 * loaded AFTER it is enabled, so a connector calls this from a tiny bootstrap
 * file that then requires the real bundle (see scripts/hook-bootstrap.mjs).
 *
 * Safety contract:
 *   - Never throws and never writes to stdout/stderr: enabling the cache must
 *     not change the verdict or fail the hook. Errors from the bundle itself
 *     are not caught here because the bundle is loaded after this returns.
 *   - The cache lives in `~/.singularity-aidr/compile-cache`, prepared by
 *     `preparePrivateLocalDirectory` (0700 owner-checked on POSIX, protected
 *     owner/SYSTEM/Administrators ACL on Windows) BEFORE Node is pointed at
 *     it. Node only writes inside that directory. The state directory is
 *     also agent-inaccessible through the CLT-SELF-008 self-defense rule.
 *   - Node rejects a cache entry whose recorded source hash does not match the
 *     file being loaded, so a modified bundle is compiled from its own bytes,
 *     never from a stale entry.
 *   - `AIDR_DISABLE_COMPILE_CACHE=1` (or `true`) turns it off, as does Node's
 *     own `NODE_DISABLE_COMPILE_CACHE`.
 *   - Off by default on Windows: hardening the directory there runs native
 *     ACL probes (and PowerShell on first use) before the hook's deadline
 *     watchdog exists, which could cost more than the cache saves and is not
 *     yet measured. `AIDR_ENABLE_COMPILE_CACHE=1` opts in for measurement.
 */

import * as nodeModule from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import { preparePrivateLocalDirectory } from "./private-local-file.js";

const DISABLE_COMPILE_CACHE_ENV = "AIDR_DISABLE_COMPILE_CACHE";
const ENABLE_COMPILE_CACHE_ENV = "AIDR_ENABLE_COMPILE_CACHE";

type HookCompileCacheStatus = "enabled" | "already_enabled" | "disabled" | "unsupported" | "failed";

export interface HookCompileCacheResult {
	status: HookCompileCacheStatus;
	directory?: string;
	reason?: string;
}

/** The subset of `node:module` this uses; injectable for tests. */
export interface CompileCacheModuleApi {
	enableCompileCache?: (cacheDir?: string) => {
		status: number;
		message?: string;
		directory?: string;
	};
	constants?: {
		compileCacheStatus?: Partial<
			Record<"FAILED" | "ENABLED" | "ALREADY_ENABLED" | "DISABLED", number>
		>;
	};
}

export interface HookCompileCacheOptions {
	env?: Record<string, string | undefined>;
	platform?: NodeJS.Platform;
	moduleApi?: CompileCacheModuleApi;
	prepareDirectory?: (path: string) => void;
}

function flagSet(value: string | undefined): boolean {
	const normalized = value?.trim().toLowerCase();
	return normalized === "1" || normalized === "true";
}

/** `~/.singularity-aidr/compile-cache`, with `~` resolved like core's `resolvePath`. */
export function resolveHookCompileCacheDir(
	env: Record<string, string | undefined> = process.env,
): string {
	const envHome = env.HOME?.trim();
	return join(
		envHome && envHome.length > 0 ? envHome : homedir(),
		".singularity-aidr",
		"compile-cache",
	);
}

/** Map Node's numeric `compileCacheStatus` onto this module's result. */
function interpretNodeResult(
	api: CompileCacheModuleApi,
	result: { status: number; message?: string; directory?: string } | undefined,
	directory: string,
): HookCompileCacheResult {
	const codes = api.constants?.compileCacheStatus;
	const status = result?.status;
	if (codes === undefined || typeof status !== "number") {
		return { status: "failed", reason: "unrecognised enableCompileCache result" };
	}
	if (status === codes.ENABLED)
		return { status: "enabled", directory: result?.directory ?? directory };
	if (status === codes.ALREADY_ENABLED)
		return { status: "already_enabled", directory: result?.directory };
	if (status === codes.DISABLED) {
		return { status: "disabled", reason: result?.message ?? "NODE_DISABLE_COMPILE_CACHE" };
	}
	return { status: "failed", reason: result?.message ?? "enableCompileCache failed" };
}

export function enableHookCompileCache(
	options: HookCompileCacheOptions = {},
): HookCompileCacheResult {
	try {
		const env = options.env ?? process.env;
		if (flagSet(env[DISABLE_COMPILE_CACHE_ENV])) {
			return { status: "disabled", reason: DISABLE_COMPILE_CACHE_ENV };
		}
		if (
			(options.platform ?? process.platform) === "win32" &&
			!flagSet(env[ENABLE_COMPILE_CACHE_ENV])
		) {
			return { status: "disabled", reason: "win32_default_off" };
		}
		const api: CompileCacheModuleApi = options.moduleApi ?? (nodeModule as CompileCacheModuleApi);
		if (typeof api.enableCompileCache !== "function") {
			return { status: "unsupported", reason: "module.enableCompileCache unavailable" };
		}

		// Create and verify the private directory first: Node is never pointed at
		// a path that is missing, a symlink, foreign-owned or group/world
		// accessible. (Node 22 also spins on some uncreatable paths, e.g. under
		// /proc, instead of failing; an existing directory avoids that path.)
		const directory = resolveHookCompileCacheDir(env);
		(options.prepareDirectory ?? preparePrivateLocalDirectory)(directory);

		return interpretNodeResult(api, api.enableCompileCache(directory), directory);
	} catch (error) {
		return { status: "failed", reason: error instanceof Error ? error.message : String(error) };
	}
}
