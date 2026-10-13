/**
 * The update check shared by `aidr update` and the session-start update
 * notice: pick the source, verify its signed catalog, find this platform's
 * installer and compare versions. Installing is the CLI's job.
 */
import { spawn } from "node:child_process";
import type { KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { compare as compareSemver, valid as validSemver } from "semver";
import { resolvePath } from "../config.js";
import {
	getAuthToken,
	getEffectiveManagedApiKey,
	loadManagedState,
	managedStatePath,
} from "../managed.js";
import type { Config } from "../types.js";
import type { InstallerCatalog, InstallerCatalogFile, InstallerPlatform } from "./catalog.js";
import {
	detectMdmManaged,
	effectiveAutoMode,
	type InstallerLayout,
	installerLayoutFor,
	installerPlatform,
	trustedCatalogKeys,
	type UpdateEnvironmentDeps,
} from "./environment.js";
import { loadCatalog, type SourceDeps, type UpdateSource } from "./source.js";

/** semver precedence: <0 when a is older than b. Unparseable versions compare as equal (no action). */
export function compareReleaseVersions(a: string, b: string): number {
	const left = validSemver(a.replace(/^v/u, ""));
	const right = validSemver(b.replace(/^v/u, ""));
	if (!left || !right) return 0;
	return compareSemver(left, right);
}

export type UpdateStatus = "up_to_date" | "available" | "older";

export type UpdateCheck =
	| {
			ok: true;
			status: UpdateStatus;
			current: string;
			latest: string;
			catalog: InstallerCatalog;
			/** This platform's installer; null when the catalog has none for it. */
			file: InstallerCatalogFile | null;
	  }
	| { ok: false; error: string; status?: number; detail?: string };

/**
 * Which source `aidr update` uses: `--from` first; then the tenant portal in
 * managed mode; then a configured mirror. Null: nothing to update from.
 */
export function resolveUpdateSource(
	config: Pick<Config, "mode" | "control_plane" | "update">,
	apiKey: string | undefined,
	from?: string,
): UpdateSource | null {
	const allowInsecureLoopback = config.control_plane.allow_insecure_loopback === true;
	if (from?.trim()) {
		const location = from.trim();
		let directory = false;
		if (!/^[a-z][a-z0-9+.-]*:\/\//iu.test(location) || /^file:/iu.test(location)) {
			try {
				directory = statSync(resolvePath(location.replace(/^file:\/\//iu, ""))).isDirectory();
			} catch {
				directory = false;
			}
		}
		if (directory || location.endsWith("/"))
			return { kind: "mirror", location, allowInsecureLoopback };
		if (/(^|[/\\])latest\.json$/u.test(location)) {
			return {
				kind: "mirror",
				location: location.replace(/latest\.json$/u, ""),
				allowInsecureLoopback,
			};
		}
		return { kind: "file", installer: location, allowInsecureLoopback };
	}
	const endpoint = config.control_plane.endpoint?.trim();
	if (config.mode === "managed" && endpoint && apiKey?.trim()) {
		return { kind: "portal", endpoint, apiKey: apiKey.trim(), allowInsecureLoopback };
	}
	const mirror = config.update.source?.trim();
	if (mirror) return { kind: "mirror", location: mirror, allowInsecureLoopback };
	return null;
}

/** The endpoint's managed API key (configured or issued at enrollment), if any. */
export async function resolveManagedApiKey(config: Config): Promise<string | undefined> {
	if (config.mode !== "managed") return undefined;
	const token = getAuthToken(config.auth);
	try {
		const state = await loadManagedState(managedStatePath(), {
			authToken: token,
			publicKeysPem: config.licensing.public_keys_pem,
		});
		return getEffectiveManagedApiKey(config.auth.api_key, state) || token;
	} catch {
		return token;
	}
}

/** Verify the source's catalog and compare it with the running version. */
export async function checkInstallerUpdate(params: {
	currentVersion: string;
	platform: InstallerPlatform;
	source: UpdateSource;
	keys: readonly KeyObject[];
	deps?: SourceDeps;
}): Promise<UpdateCheck> {
	const loaded = await loadCatalog(params.source, params.keys, params.deps);
	if (!loaded.ok) {
		return {
			ok: false,
			error: loaded.error,
			...("status" in loaded && loaded.status ? { status: loaded.status } : {}),
			...("detail" in loaded && loaded.detail ? { detail: loaded.detail } : {}),
		};
	}
	const { catalog } = loaded;
	const file = catalog.files.find((entry) => entry.platform === params.platform) ?? null;
	if ("providedFile" in loaded && loaded.providedFile && file?.file !== loaded.providedFile) {
		return {
			ok: false,
			error: "installer_not_in_catalog",
			detail: loaded.providedFile,
		};
	}
	const order = compareReleaseVersions(params.currentVersion, catalog.version);
	return {
		ok: true,
		status: order < 0 ? "available" : order > 0 ? "older" : "up_to_date",
		current: params.currentVersion,
		latest: catalog.version,
		catalog,
		file,
	};
}

// ── Automatic checks (session start) ─────────────────────────────────────────

/** Small, non-secret record of the last automatic check. */
export interface UpdateCheckState {
	checked_at: string;
	current: string;
	latest: string | null;
	status: UpdateStatus | "error";
	/** Last automatic install attempt, so a failing install is not retried every session. */
	install_attempted_at?: string;
}

export const UPDATE_STATE_FILE = "~/.singularity-aidr/update-check.json";

export function readUpdateState(path = resolvePath(UPDATE_STATE_FILE)): UpdateCheckState | null {
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8")) as UpdateCheckState;
		return parsed && typeof parsed.checked_at === "string" && typeof parsed.current === "string"
			? parsed
			: null;
	} catch {
		return null;
	}
}

export function writeUpdateState(
	state: UpdateCheckState,
	path = resolvePath(UPDATE_STATE_FILE),
): void {
	try {
		mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
		writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
	} catch {
		// A missing record only means the next session checks again.
	}
}

export interface UpdateNotice {
	currentVersion: string;
	latestVersion: string;
	updateAvailable: boolean;
	/** How to act on it: `aidr update` (or it is being installed automatically). */
	action: "aidr_update" | "installing";
}

export interface UpdateNoticeOptions {
	config: Config;
	currentVersion: string;
	apiKey?: string;
	/** The running executable (process.execPath in a hook binary). */
	executable?: string;
	now?: number;
	statePath?: string;
	deps?: SourceDeps & UpdateEnvironmentDeps;
	/** Starts `aidr update --auto` in the background (tests stub it). */
	startInstall?: (aidr: string) => void;
}

/**
 * True when `executable` runs from a desktop-installer layout on a platform the
 * portal serves: its updates come from `aidr update`, not from the generic
 * version-check notice.
 */
export function installerUpdatesApply(
	executable: string | undefined,
	deps: UpdateEnvironmentDeps = {},
): boolean {
	return (
		!!executable &&
		!!installerLayoutFor(executable, deps) &&
		!!installerPlatform(deps.platform, deps.arch)
	);
}

function startDetached(aidr: string): void {
	try {
		const child = spawn(aidr, ["update", "--auto"], {
			detached: true,
			stdio: "ignore",
			windowsHide: true,
		});
		child.on("error", () => {});
		child.unref();
	} catch {
		// Best effort: the notice still tells the user to run `aidr update`.
	}
}

/** True when `at` (ISO time) lies within the last `intervalMs` before `now`. */
function withinInterval(at: string | undefined, now: number, intervalMs: number): boolean {
	const time = at ? Date.parse(at) : Number.NaN;
	return Number.isFinite(time) && now >= time && now - time < intervalMs;
}

/** The cached check when still fresh, else a new check (null: nothing to check with). */
async function currentState(
	options: UpdateNoticeOptions,
	layout: InstallerLayout,
	platform: InstallerPlatform,
	now: number,
	statePath: string,
): Promise<UpdateCheckState | null> {
	const deps = options.deps ?? {};
	const intervalMs = options.config.update.check_interval_hours * 3_600_000;
	const cached = readUpdateState(statePath);
	if (
		cached?.current === options.currentVersion &&
		withinInterval(cached.checked_at, now, intervalMs)
	) {
		return cached;
	}
	const keys = trustedCatalogKeys(layout, options.config.update.catalog_public_keys, deps);
	const source = resolveUpdateSource(options.config, options.apiKey);
	if (!source || keys.keys.length === 0) return null;
	const result = await checkInstallerUpdate({
		currentVersion: options.currentVersion,
		platform,
		source,
		keys: keys.keys,
		deps: { ...deps, timeoutMs: deps.timeoutMs ?? 5_000 },
	});
	const state: UpdateCheckState = {
		checked_at: new Date(now).toISOString(),
		current: options.currentVersion,
		latest: result.ok ? result.latest : null,
		status: result.ok ? (result.file ? result.status : "up_to_date") : "error",
		...(cached?.install_attempted_at ? { install_attempted_at: cached.install_attempted_at } : {}),
	};
	writeUpdateState(state, statePath);
	return state;
}

/** Start `aidr update --auto` unless an attempt was made within the interval. */
function startBackgroundInstall(
	options: UpdateNoticeOptions,
	layout: InstallerLayout,
	state: UpdateCheckState,
	now: number,
	statePath: string,
): boolean {
	const deps = options.deps ?? {};
	const intervalMs = options.config.update.check_interval_hours * 3_600_000;
	if (withinInterval(state.install_attempted_at, now, intervalMs)) return false;
	const windows = (deps.platform ?? process.platform) === "win32";
	// A per-machine MSI needs an elevated msiexec a user session cannot start
	// silently: keep telling the user to run `aidr update` instead.
	if (windows && !layout.perUser) return false;
	const executable = windows ? "aidr.exe" : "aidr";
	const aidr = join(layout.bundle, "bin", executable);
	if (!(deps.exists ?? existsSync)(aidr)) return false;
	(options.startInstall ?? startDetached)(aidr);
	writeUpdateState({ ...state, install_attempted_at: new Date(now).toISOString() }, statePath);
	return true;
}

/**
 * Update notice for an endpoint installed with the desktop installers, or null
 * when it does not apply (not a standalone install, `update.auto: off`, device
 * management owns updates, no source or key, or an error). At most one network
 * check per `update.check_interval_hours`; the result is cached. With
 * `update.auto: install` an available update starts `aidr update --auto`
 * (verified, non-interactive) in the background, at most once per interval.
 * Never throws and never affects enforcement.
 */
export async function installerUpdateNotice(
	options: UpdateNoticeOptions,
): Promise<UpdateNotice | null> {
	try {
		const deps = options.deps ?? {};
		const layout = options.executable ? installerLayoutFor(options.executable, deps) : null;
		const platform = installerPlatform(deps.platform, deps.arch);
		if (!layout || !platform) return null;
		const auto = effectiveAutoMode(options.config.update.auto, detectMdmManaged(deps));
		if (auto.mode === "off") return null;

		const now = options.now ?? Date.now();
		const statePath = options.statePath ?? resolvePath(UPDATE_STATE_FILE);
		const state = await currentState(options, layout, platform, now, statePath);
		if (state?.status !== "available" || !state.latest) return null;
		const installing =
			auto.mode === "install" && startBackgroundInstall(options, layout, state, now, statePath);
		return {
			currentVersion: options.currentVersion,
			latestVersion: state.latest,
			updateAvailable: true,
			action: installing ? "installing" : "aidr_update",
		};
	} catch {
		return null;
	}
}
