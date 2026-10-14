/**
 * Where this endpoint stands for `aidr update`: which installer platform it
 * is, whether it runs from a desktop-installer layout, whether device
 * management owns its updates, and which installer-catalog keys it trusts.
 *
 * Desktop-installer layout (deploy/installers/lib/common.mjs):
 *
 *   <prefix>/bundle/bin/aidr[.exe], aidr-*-tool-use[.exe], ...   the SEA bundle
 *   <prefix>/config/release-public.pem                            release trust key
 *   <prefix>/config/installer-catalog-public.pem                  catalog key (optional)
 */
import { spawnSync } from "node:child_process";
import type { KeyObject } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { type InstallerPlatform, parseCatalogPublicKey } from "./catalog.js";

export type UpdateAutoMode = "off" | "notify" | "install";

/** File name of the pinned installer-catalog key next to the release key. */
export const CATALOG_KEY_FILE = "installer-catalog-public.pem";

/**
 * Device-management markers. An MDM / Intune / SCCM / GPO / configuration
 * management deployment sets one of these (the MSI property
 * AIDR_MDM_MANAGED=1 writes the registry value; the Linux package hook writes
 * the file when AIDR_MDM_MANAGED=1 is set), and the endpoint then leaves
 * updates to that tool: no automatic check or install, and `aidr update`
 * refuses to install (it can still `--check`).
 */
export const LINUX_MDM_MARKER = "/etc/singularity-aidr/mdm-managed";
const WINDOWS_MDM_MARKER_NAME = join("Singularity AIDR", "mdm-managed");
export const WINDOWS_MDM_POLICY_KEY = "HKLM\\SOFTWARE\\Policies\\Singularity AIDR";
export const WINDOWS_MDM_POLICY_VALUE = "MdmManaged";

export interface UpdateEnvironmentDeps {
	platform?: NodeJS.Platform;
	arch?: string;
	env?: NodeJS.ProcessEnv;
	exists?: (path: string) => boolean;
	readFile?: (path: string) => string;
	/** `reg query` for one value; returns stdout or null (tests stub it). */
	regQuery?: (key: string, value: string) => string | null;
}

/** The catalog platform of this machine, or null where no installer is offered (macOS, 32-bit). */
export function installerPlatform(
	platform: NodeJS.Platform = process.platform,
	arch: string = process.arch,
): InstallerPlatform | null {
	const os = platform === "win32" ? "windows" : platform === "linux" ? "linux" : null;
	if (!os || (arch !== "x64" && arch !== "arm64")) return null;
	return `${os}-${arch}` as InstallerPlatform;
}

export interface InstallerLayout {
	/** Installation prefix: C:\Program Files\Singularity AIDR, /opt/singularity-aidr, ... */
	prefix: string;
	/** The SEA bundle directory (<prefix>/bundle). */
	bundle: string;
	/** True for a per-user MSI install under %LOCALAPPDATA%\Programs. */
	perUser: boolean;
}

/**
 * The installer layout an executable runs from, or null when it is not
 * `<prefix>/bundle/bin/<file>` with the release key at `<prefix>/config`.
 */
export function installerLayoutFor(
	executable: string,
	deps: UpdateEnvironmentDeps = {},
): InstallerLayout | null {
	const exists = deps.exists ?? existsSync;
	const binDir = dirname(executable);
	const bundle = dirname(binDir);
	if (basename(binDir) !== "bin" || basename(bundle) !== "bundle") return null;
	const prefix = dirname(bundle);
	if (!exists(join(prefix, "config", "release-public.pem"))) return null;
	const env = deps.env ?? process.env;
	const localAppData = env.LOCALAPPDATA?.trim();
	const platform = deps.platform ?? process.platform;
	const perUser =
		platform === "win32" &&
		!!localAppData &&
		prefix.toLowerCase().startsWith(localAppData.toLowerCase());
	return { prefix, bundle, perUser };
}

/** reg.exe by absolute path, so a directory earlier on PATH cannot stand in for it. */
function regExecutable(env: NodeJS.ProcessEnv = process.env): string {
	return join(
		env.SystemRoot?.trim() || env.SYSTEMROOT?.trim() || "C:\\Windows",
		"System32",
		"reg.exe",
	);
}

/** `reg query <key> /v <value>` stdout, or null when absent or unreadable (Windows only). */
export function defaultRegQuery(key: string, value: string): string | null {
	try {
		const result = spawnSync(regExecutable(), ["query", key, "/v", value], {
			encoding: "utf8",
			timeout: 5_000,
			windowsHide: true,
		});
		return result.status === 0 ? (result.stdout ?? "") : null;
	} catch {
		return null;
	}
}

export interface MdmStatus {
	managed: boolean;
	/** What marked the machine as managed (shown to the user). */
	source?: string;
}

const UNMANAGED: MdmStatus = { managed: false };

function windowsMdmStatus(deps: UpdateEnvironmentDeps): MdmStatus {
	const env = deps.env ?? process.env;
	const programData = env.ProgramData?.trim() || env.PROGRAMDATA?.trim();
	const marker = programData ? join(programData, WINDOWS_MDM_MARKER_NAME) : null;
	if (marker && (deps.exists ?? existsSync)(marker)) return { managed: true, source: marker };
	const output = (deps.regQuery ?? defaultRegQuery)(
		WINDOWS_MDM_POLICY_KEY,
		WINDOWS_MDM_POLICY_VALUE,
	);
	return output && /REG_(?:DWORD|SZ)\s+(?:0x0*1|1)\s*$/imu.test(output)
		? { managed: true, source: `${WINDOWS_MDM_POLICY_KEY}\\${WINDOWS_MDM_POLICY_VALUE}` }
		: UNMANAGED;
}

/** Is this machine's AIDR installation owned by device management? */
export function detectMdmManaged(deps: UpdateEnvironmentDeps = {}): MdmStatus {
	const platform = deps.platform ?? process.platform;
	if (platform === "win32") return windowsMdmStatus(deps);
	if (platform === "linux" && (deps.exists ?? existsSync)(LINUX_MDM_MARKER)) {
		return { managed: true, source: LINUX_MDM_MARKER };
	}
	return UNMANAGED;
}

/** The automatic-update mode in force: device management turns it off. */
export function effectiveAutoMode(
	configured: UpdateAutoMode | undefined,
	mdm: MdmStatus,
): { mode: UpdateAutoMode; reason?: "mdm" } {
	if (mdm.managed) return { mode: "off", reason: "mdm" };
	return { mode: configured ?? "notify" };
}

export interface TrustedCatalogKeys {
	keys: KeyObject[];
	/** Where the keys came from (shown in --check output). */
	source: string | null;
	/** Entries that could not be parsed; any such entry fails closed. */
	invalid: string[];
}

function keyFromFile(file: string, deps: UpdateEnvironmentDeps): TrustedCatalogKeys {
	let key: KeyObject | null = null;
	try {
		key = parseCatalogPublicKey((deps.readFile ?? ((path) => readFileSync(path, "utf8")))(file));
	} catch {
		key = null;
	}
	return key
		? { keys: [key], source: file, invalid: [] }
		: { keys: [], source: file, invalid: [file] };
}

/**
 * The installer-catalog keys this endpoint trusts. A key file the installer
 * placed next to the release key wins and is the only one used; otherwise the
 * `update.catalog_public_keys` configuration. No key means no update.
 */
export function trustedCatalogKeys(
	layout: Pick<InstallerLayout, "prefix"> | null,
	configured: readonly string[] | undefined,
	deps: UpdateEnvironmentDeps = {},
): TrustedCatalogKeys {
	const file = layout ? join(layout.prefix, "config", CATALOG_KEY_FILE) : null;
	if (file && (deps.exists ?? existsSync)(file)) return keyFromFile(file, deps);
	const keys: KeyObject[] = [];
	const invalid: string[] = [];
	for (const [index, entry] of (configured ?? []).entries()) {
		const key = parseCatalogPublicKey(entry);
		if (key) keys.push(key);
		else invalid.push(`update.catalog_public_keys[${index}]`);
	}
	return {
		keys: invalid.length > 0 ? [] : keys,
		source: keys.length > 0 || invalid.length > 0 ? "update.catalog_public_keys" : null,
		invalid,
	};
}
