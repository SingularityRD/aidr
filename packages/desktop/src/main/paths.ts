import { homedir } from "node:os";
import { join } from "node:path";

/**
 * The home directory exactly as the AIDR hooks and CLI resolve `~`
 * (core `resolvePath`: HOME when set, else the OS home), so the app reads and
 * writes the same files the hooks do.
 */
export function aidrHome(env: NodeJS.ProcessEnv = process.env): string {
	const fromEnv = env.HOME?.trim();
	return fromEnv && fromEnv.length > 0 ? fromEnv : homedir();
}

export function dataDir(home: string): string {
	return join(home, ".singularity-aidr");
}

export function claudeSettingsPath(home: string): string {
	return join(home, ".claude", "settings.json");
}

export function receiptPath(home: string): string {
	return join(dataDir(home), "installation.json");
}

export function configPath(home: string): string {
	return join(dataDir(home), "config.json");
}

/** Per-user, version-addressed copies of the AIDR runtime the hooks execute. */
export function runtimesDir(home: string): string {
	return join(dataDir(home), "desktop", "runtime");
}

/** Per-user copies of the unpacked Browser Guard extension (Chrome loads it from here). */
export function browserGuardDir(home: string): string {
	return join(dataDir(home), "desktop", "browser-guard");
}

/** The multi-call binary of a standalone runtime. */
export function runtimeBinary(root: string, platform: NodeJS.Platform = process.platform): string {
	return join(root, "bin", platform === "win32" ? "aidr.exe" : "aidr");
}
