/** Types for scripts/native-host.mjs (per-user native messaging host registration). */

export type Browser = "chrome" | "edge" | "chromium";
export type Platform = "win32" | "darwin" | "linux";

/** HKCU default-value access; the default implementation uses reg.exe and PowerShell. */
export interface RegistryAccess {
	setDefault(key: string, value: string): void;
	/** null when the key does not exist, "" when it has no default value. */
	getDefault(key: string): string | null;
	deleteKey(key: string): boolean;
}

export interface HostManifest {
	readonly name: "com.singularity.aidr_privacy";
	readonly description: string;
	readonly path: string;
	readonly type: "stdio";
	readonly allowed_origins: readonly string[];
}

export interface Registration {
	readonly browser: Browser;
	readonly manifestPath: string;
	/** Windows only. */
	readonly registryKey?: string;
}

export interface BrowserStatus {
	readonly browser: Browser;
	readonly registered: boolean;
	/** Manifest readable, right name, absolute existing host, at least one allowed origin. */
	readonly usable: boolean;
	readonly manifestPath: string | null;
	readonly hostPath: string | null;
	readonly allowedOrigins: readonly string[];
	readonly registryKey?: string;
	readonly problem?:
		| "MANIFEST_NAME_MISMATCH"
		| "HOST_PATH_NOT_ABSOLUTE"
		| "HOST_NOT_FOUND"
		| "NO_ALLOWED_ORIGINS"
		| "MANIFEST_UNREADABLE";
}

interface PlatformOptions {
	/** Default: chrome and edge. */
	browsers?: readonly Browser[];
	platform?: Platform;
	home?: string;
	reg?: RegistryAccess;
	registryKeys?: Readonly<Record<Browser, string>>;
}

export const NATIVE_HOST_NAME: "com.singularity.aidr_privacy";
export const HOST_DESCRIPTION: string;
export const MANIFEST_FILE: string;
export const BROWSERS: readonly Browser[];
export const DEFAULT_BROWSERS: readonly Browser[];
export const WINDOWS_REGISTRY_KEYS: Readonly<Record<Browser, string>>;
export const windowsRegistry: RegistryAccess;

export function userManifestDirs(platform?: Platform, home?: string): Record<Browser, string>;
export function defaultWindowsManifestDir(env?: NodeJS.ProcessEnv): string;
export function unpackedExtensionId(dir: string, platform?: Platform): string;
export function extensionIdForPath(absolutePath: string, platform?: Platform): string;
export function hostManifest(options: { hostPath: string; extensionIds: readonly string[] }): HostManifest;

export function registerNativeHost(
	options: PlatformOptions & {
		hostPath: string;
		extensionIds: readonly string[];
		/** Windows: directory for the manifest (default %LOCALAPPDATA%\SingularityAIDR\NativeMessagingHosts). */
		manifestDir?: string;
		env?: NodeJS.ProcessEnv;
	},
): { ok: true; manifest: HostManifest; registrations: Registration[] };

export function unregisterNativeHost(options?: PlatformOptions): {
	ok: true;
	removed: { browser: Browser; registryKey?: string; manifestPath?: string }[];
};

export function nativeHostStatus(options?: PlatformOptions): { ok: true; browsers: BrowserStatus[] };

export function privacyHostScript(): string;
export function createDevLauncher(options: {
	configPath: string;
	outDir: string;
	nodePath?: string;
	hostScript?: string;
}): { ok: true; launcherPath: string };

export function main(
	argv: readonly string[],
	io?: { log?: (line: string) => void; error?: (line: string) => void },
): 0 | 1 | 2;
