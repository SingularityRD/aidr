import { cpSync, existsSync, readdirSync, readFileSync, renameSync, rmSync, statSync } from "node:fs";
import { isAbsolute, join, win32 } from "node:path";
import type {
	BrowserExtensionHit,
	BrowserGuardStatus,
	NativeHostFacts,
} from "../shared/contract.js";
import type { Runner } from "./exec.js";
import { browserGuardDir } from "./paths.js";

/**
 * Browser Guard status for Chrome and Edge on Windows.
 *
 * - The extension is found by reading each browser profile's `Preferences` /
 *   `Secure Preferences` (read only) and the manifest of every extension they
 *   list: Browser Guard is the one whose resolved name is Browser Guard's.
 * - The optional native helper (`com.singularity.aidr_privacy`, shipped by
 *   packages/privacy and registered by an administrator, see
 *   packages/browser-guard/docs/native-host.md) is found through its
 *   native-messaging registry keys, queried with `reg.exe` and an argument array.
 * - Installing: Browser Guard is not yet listed in the Chrome Web Store / Edge
 *   Add-ons, so the app copies the unpacked build it ships to a stable folder in
 *   the profile and opens the browser's extensions page, where the user loads it.
 */

const NATIVE_HOST_NAME = "com.singularity.aidr_privacy";
const NAME_PATTERN = /browser guard/i;

type BrowserId = "chrome" | "edge";

interface BrowserLayout {
	id: BrowserId;
	userData: string;
	executables: string[];
	registryKey: string;
	extensionsUrl: string;
}

function browserLayouts(env: NodeJS.ProcessEnv = process.env): BrowserLayout[] {
	const local = env.LOCALAPPDATA ?? "";
	const programFiles = [env.ProgramFiles, env["ProgramFiles(x86)"]].filter(
		(value): value is string => typeof value === "string" && value.length > 0,
	);
	return [
		{
			id: "chrome",
			userData: join(local, "Google", "Chrome", "User Data"),
			executables: [
				...programFiles.map((root) => join(root, "Google", "Chrome", "Application", "chrome.exe")),
				join(local, "Google", "Chrome", "Application", "chrome.exe"),
			],
			registryKey: `Software\\Google\\Chrome\\NativeMessagingHosts\\${NATIVE_HOST_NAME}`,
			extensionsUrl: "chrome://extensions/",
		},
		{
			id: "edge",
			userData: join(local, "Microsoft", "Edge", "User Data"),
			executables: [
				...programFiles.map((root) => join(root, "Microsoft", "Edge", "Application", "msedge.exe")),
				join(local, "Microsoft", "Edge", "Application", "msedge.exe"),
			],
			registryKey: `Software\\Microsoft\\Edge\\NativeMessagingHosts\\${NATIVE_HOST_NAME}`,
			extensionsUrl: "edge://extensions/",
		},
	];
}

function readJson(path: string): Record<string, unknown> | null {
	try {
		const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: null;
	} catch {
		return null;
	}
}

/** A manifest's display name, resolving `__MSG_key__` from its default locale. */
export function manifestName(dir: string): { name: string; version: string | null } | null {
	const manifest = readJson(join(dir, "manifest.json"));
	if (!manifest || typeof manifest.name !== "string") return null;
	let name = manifest.name;
	const message = /^__MSG_(\w+)__$/.exec(name);
	if (message) {
		const locale = typeof manifest.default_locale === "string" ? manifest.default_locale : "en";
		const messages = readJson(join(dir, "_locales", locale, "messages.json"));
		const key = message[1] as string;
		const entry = messages
			? (Object.entries(messages).find(([k]) => k.toLowerCase() === key.toLowerCase())?.[1] as
					| { message?: unknown }
					| undefined)
			: undefined;
		name = typeof entry?.message === "string" ? entry.message : name;
	}
	return { name, version: typeof manifest.version === "string" ? manifest.version : null };
}

function profiles(userData: string): string[] {
	try {
		return readdirSync(userData).filter(
			(name) =>
				(name === "Default" || /^Profile \d+$/.test(name)) &&
				statSync(join(userData, name)).isDirectory(),
		);
	} catch {
		return [];
	}
}

/** Browser Guard entries in one profile's preference files. */
export function findInProfile(
	browser: BrowserId,
	userData: string,
	profile: string,
): BrowserExtensionHit[] {
	const hits = new Map<string, BrowserExtensionHit>();
	for (const file of ["Secure Preferences", "Preferences"]) {
		const prefs = readJson(join(userData, profile, file));
		const settings = (prefs?.extensions as { settings?: unknown } | undefined)?.settings;
		if (typeof settings !== "object" || settings === null) continue;
		for (const [id, raw] of Object.entries(settings as Record<string, unknown>)) {
			if (hits.has(id) || typeof raw !== "object" || raw === null) continue;
			const entry = raw as { path?: unknown; location?: unknown; state?: unknown; disable_reasons?: unknown };
			if (typeof entry.path !== "string") continue;
			// Chrome writes Windows separators ("id\\1.0.0_0"); split on both so a
			// relative store path resolves under the profile on any platform.
			const absolute = isAbsolute(entry.path) || win32.isAbsolute(entry.path);
			const dir = absolute
				? entry.path
				: join(userData, profile, "Extensions", ...entry.path.split(/[\\/]/));
			const manifest = manifestName(dir);
			if (!manifest || !NAME_PATTERN.test(manifest.name)) continue;
			const reasons = entry.disable_reasons;
			const disabled =
				entry.state === 0 ||
				(Array.isArray(reasons) && reasons.length > 0) ||
				(typeof reasons === "number" && reasons !== 0);
			hits.set(id, {
				browser,
				profile,
				extensionId: id,
				version: manifest.version,
				enabled: !disabled,
				unpacked: entry.location === 4 || absolute,
				path: dir,
			});
		}
	}
	return [...hits.values()];
}

async function nativeHostRegistrations(
	run: Runner,
	layouts: BrowserLayout[],
): Promise<NativeHostFacts[]> {
	const found: NativeHostFacts[] = [];
	for (const layout of layouts) {
		for (const scope of ["HKCU", "HKLM"] as const) {
			const result = await run("reg.exe", ["query", `${scope}\\${layout.registryKey}`, "/ve"], {
				timeoutMs: 10_000,
			});
			if (result.exitCode !== 0) continue;
			const value = /REG_(?:EXPAND_)?SZ\s+(.+)$/m.exec(result.stdout)?.[1]?.trim() ?? null;
			found.push({
				browser: layout.id,
				scope,
				manifestPath: value,
				manifestExists: value !== null && existsSync(value),
			});
		}
	}
	return found;
}

export interface BrowserGuardDeps {
	home: string;
	run: Runner;
	/** The unpacked Chrome/Edge build shipped with the app (null when absent). */
	bundledExtension: string | null;
	env?: NodeJS.ProcessEnv;
}

function bundledVersion(dir: string | null): string | null {
	return dir ? (manifestName(dir)?.version ?? null) : null;
}

export function stagedExtensionDir(deps: BrowserGuardDeps): string | null {
	const version = bundledVersion(deps.bundledExtension);
	return version ? join(browserGuardDir(deps.home), `chrome-${version}`) : null;
}

export async function browserGuardStatus(deps: BrowserGuardDeps): Promise<BrowserGuardStatus> {
	const layouts = browserLayouts(deps.env);
	const extensions: BrowserExtensionHit[] = [];
	for (const layout of layouts) {
		for (const profile of profiles(layout.userData)) {
			extensions.push(...findInProfile(layout.id, layout.userData, profile));
		}
	}
	const staged = stagedExtensionDir(deps);
	return {
		browsers: layouts.map((layout) => {
			const executable = layout.executables.find((path) => existsSync(path)) ?? null;
			return { browser: layout.id, installed: executable !== null, executable };
		}),
		extensions,
		nativeHost: { name: NATIVE_HOST_NAME, registrations: await nativeHostRegistrations(deps.run, layouts) },
		bundled: {
			available: deps.bundledExtension !== null && existsSync(join(deps.bundledExtension, "manifest.json")),
			version: bundledVersion(deps.bundledExtension),
			stagedPath: staged && existsSync(join(staged, "manifest.json")) ? staged : null,
		},
	};
}

/** Copy the shipped unpacked extension to its stable per-user folder. */
export function stageExtension(deps: BrowserGuardDeps): string {
	const target = stagedExtensionDir(deps);
	if (!deps.bundledExtension || !target) throw new Error("this build does not include Browser Guard");
	if (existsSync(join(target, "manifest.json"))) return target;
	const staging = `${target}.staging-${process.pid}`;
	try {
		cpSync(deps.bundledExtension, staging, { recursive: true });
		renameSync(staging, target);
	} finally {
		rmSync(staging, { recursive: true, force: true });
	}
	return target;
}

/** Start the browser on its extensions page (program + URL argument, no shell). */
export function extensionsPageCommand(
	browser: BrowserId,
	env: NodeJS.ProcessEnv = process.env,
): { file: string; args: string[]; url: string } | null {
	const layout = browserLayouts(env).find((entry) => entry.id === browser);
	const executable = layout?.executables.find((path) => existsSync(path));
	if (!layout || !executable) return null;
	return { file: executable, args: [layout.extensionsUrl], url: layout.extensionsUrl };
}
