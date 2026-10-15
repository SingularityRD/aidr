#!/usr/bin/env node
/**
 * Per-user registration of the AIDR Privacy native messaging host
 * (`com.singularity.aidr_privacy`, packages/privacy) for Browser Guard in Chrome and Edge.
 * No administrator rights: on Windows only HKCU is written, on macOS/Linux only the
 * user's own NativeMessagingHosts directories. Importable (the desktop app calls these
 * functions) and a CLI with JSON output:
 *
 *   node scripts/native-host.mjs register   --host <abs launcher> --extension-id <id> [--extension-id <id>]
 *                                           [--browser chrome,edge] [--manifest-dir <abs>] [--json]
 *   node scripts/native-host.mjs unregister [--browser chrome,edge] [--json]
 *   node scripts/native-host.mjs status     [--browser chrome,edge] [--json]
 *   node scripts/native-host.mjs create-launcher --config <abs host config> --out <abs dir> [--node <abs node.exe>] [--json]
 *   node scripts/native-host.mjs extension-id <unpacked extension dir>
 *
 * Exit codes: 0 ok, 1 failed (message on stderr, or `{ ok: false, error }` with --json),
 * 2 usage error. See packages/browser-guard/docs/native-host.md "Per-user registration".
 *
 * What it does NOT do: build or sign the host launcher (packages/privacy/native/
 * prepare-host.mjs + build-windows.ps1 do that), grant the extension's optional
 * `nativeMessaging` permission (the user does, on the options page), or write
 * HKLM/system directories (use the enterprise deployment for machine-wide installs).
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Host name; must equal NATIVE_HOST_NAME in src/background/native.ts. */
export const NATIVE_HOST_NAME = "com.singularity.aidr_privacy";
export const HOST_DESCRIPTION = "Singularity AIDR local text and screenshot privacy scanner";
export const MANIFEST_FILE = `${NATIVE_HOST_NAME}.json`;

/** Browsers this module registers for; Chromium is the open-source build (and tests). */
export const BROWSERS = Object.freeze(["chrome", "edge", "chromium"]);
export const DEFAULT_BROWSERS = Object.freeze(["chrome", "edge"]);

/** Per-user registry keys (Windows) under which each browser looks up native hosts. */
export const WINDOWS_REGISTRY_KEYS = Object.freeze({
	chrome: "HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts",
	edge: "HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts",
	chromium: "HKCU\\Software\\Chromium\\NativeMessagingHosts",
});

const EXTENSION_ID = /^[a-p]{32}$/;
/** Characters that change meaning inside a quoted cmd.exe argument or a .cmd file. */
const CMD_UNSAFE = /["%^&|<>!\r\n]/;

/** Per-user manifest directories (macOS/Linux), where the browser reads the manifest itself. */
export function userManifestDirs(platform = process.platform, home = homedir()) {
	if (platform === "darwin") {
		const base = join(home, "Library", "Application Support");
		return {
			chrome: join(base, "Google", "Chrome", "NativeMessagingHosts"),
			edge: join(base, "Microsoft Edge", "NativeMessagingHosts"),
			chromium: join(base, "Chromium", "NativeMessagingHosts"),
		};
	}
	return {
		chrome: join(home, ".config", "google-chrome", "NativeMessagingHosts"),
		edge: join(home, ".config", "microsoft-edge", "NativeMessagingHosts"),
		chromium: join(home, ".config", "chromium", "NativeMessagingHosts"),
	};
}

/** Default directory for the manifest on Windows (per user, no admin): %LOCALAPPDATA%\SingularityAIDR\NativeMessagingHosts. */
export function defaultWindowsManifestDir(env = process.env) {
	const base = env.LOCALAPPDATA || join(env.USERPROFILE || homedir(), "AppData", "Local");
	return join(base, "SingularityAIDR", "NativeMessagingHosts");
}

/**
 * Id Chromium gives an unpacked extension loaded from `dir`: the first 128 bits of SHA-256
 * of its absolute path, hex digits mapped to a-p. Windows hashes the UTF-16LE path with an
 * upper-case drive letter, other platforms the UTF-8 path.
 */
export function unpackedExtensionId(dir, platform = process.platform) {
	return extensionIdForPath(realpathSync(dir), platform);
}

/** `unpackedExtensionId` for an already absolute, resolved path. */
export function extensionIdForPath(absolutePath, platform = process.platform) {
	let path = absolutePath;
	let bytes;
	if (platform === "win32") {
		if (/^[a-z]:/.test(path)) path = path[0].toUpperCase() + path.slice(1);
		bytes = Buffer.from(path, "utf16le");
	} else {
		bytes = Buffer.from(path, "utf8");
	}
	const hex = createHash("sha256").update(bytes).digest("hex").slice(0, 32);
	return [...hex].map((d) => String.fromCharCode(97 + Number.parseInt(d, 16))).join("");
}

function browsersOf(list) {
	const browsers = [...new Set(list ?? DEFAULT_BROWSERS)];
	if (browsers.length === 0 || browsers.some((b) => !BROWSERS.includes(b))) {
		throw new Error(`BROWSER_INVALID: expected some of ${BROWSERS.join(", ")}`);
	}
	return browsers;
}

function extensionIdsOf(ids) {
	const list = [...new Set(ids ?? [])];
	if (list.length === 0 || list.some((id) => !EXTENSION_ID.test(id))) {
		throw new Error("EXTENSION_ID_INVALID: expected one or more 32-letter (a-p) extension ids");
	}
	return list;
}

/** The host manifest Chrome/Edge read: `path` must be absolute, origins exact. */
export function hostManifest({ hostPath, extensionIds }) {
	if (typeof hostPath !== "string" || !isAbsolute(hostPath)) throw new Error("HOST_PATH_NOT_ABSOLUTE");
	return {
		name: NATIVE_HOST_NAME,
		description: HOST_DESCRIPTION,
		path: hostPath,
		type: "stdio",
		allowed_origins: extensionIdsOf(extensionIds).map((id) => `chrome-extension://${id}/`),
	};
}

const HKCU_KEY = /^HKCU\\[A-Za-z0-9 _.\\-]+$/;

function assertHkcu(key) {
	// Per-user only: never HKLM, and no characters that could escape the PowerShell literal.
	if (!HKCU_KEY.test(key)) throw new Error(`REGISTRY_KEY_INVALID: ${key}`);
}

/**
 * Windows registry access for HKCU default values. Writes go through reg.exe (arguments
 * reach it as UTF-16, so non-ASCII profile paths are stored exactly); reads go through
 * PowerShell with UTF-8 output, because reg.exe prints in the OEM code page and localises
 * "(Default)" (e.g. "(Varsayılan)" on Turkish Windows). Replaceable in tests.
 */
export const windowsRegistry = Object.freeze({
	/** Sets the key's default value (creating the key). */
	setDefault(key, value) {
		assertHkcu(key);
		execFileSync("reg.exe", ["add", key, "/ve", "/t", "REG_SZ", "/d", value, "/f"], {
			stdio: ["ignore", "ignore", "pipe"],
			windowsHide: true,
		});
	},
	/** The key's default value, "" when it has none, null when the key does not exist. */
	getDefault(key) {
		assertHkcu(key);
		const psPath = `Registry::HKEY_CURRENT_USER\\${key.slice("HKCU\\".length)}`;
		const script = [
			"[Console]::OutputEncoding = [Text.Encoding]::UTF8",
			`$k = '${psPath}'`,
			"if (-not (Test-Path -LiteralPath $k)) { exit 3 }",
			"$v = (Get-Item -LiteralPath $k).GetValue('')",
			"if ($null -eq $v) { $v = '' }",
			"[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$v)))",
		].join("; ");
		try {
			const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
				encoding: "utf8",
				stdio: ["ignore", "pipe", "pipe"],
				windowsHide: true,
			});
			return Buffer.from(out.trim(), "base64").toString("utf8");
		} catch (error) {
			if (error?.status === 3) return null;
			throw new Error(`REGISTRY_READ_FAILED: ${key}`);
		}
	},
	/** Deletes the key (callers check that it exists first). */
	deleteKey(key) {
		assertHkcu(key);
		execFileSync("reg.exe", ["delete", key, "/f"], { stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
		return true;
	},
});

function windowsKeys(browsers, registryKeys) {
	return browsers.map((browser) => ({ browser, key: `${registryKeys[browser]}\\${NATIVE_HOST_NAME}` }));
}

/**
 * Writes the host manifest and registers it for the current user.
 *
 * @param {object} options
 * @param {string} options.hostPath absolute path of the host launcher (.exe; .cmd/.bat for development)
 * @param {string[]} options.extensionIds Browser Guard extension ids allowed to call the host
 * @param {string[]} [options.browsers] subset of BROWSERS (default chrome, edge)
 * @param {string} [options.manifestDir] Windows: where the manifest is written (default per-user LOCALAPPDATA)
 * @returns {{ ok: true, manifest: object, registrations: { browser: string, manifestPath: string, registryKey?: string }[] }}
 */
export function registerNativeHost({
	hostPath,
	extensionIds,
	browsers,
	manifestDir,
	platform = process.platform,
	env = process.env,
	home = homedir(),
	reg = windowsRegistry,
	registryKeys = WINDOWS_REGISTRY_KEYS,
}) {
	const list = browsersOf(browsers);
	const manifest = hostManifest({ hostPath, extensionIds });
	if (!existsSync(hostPath) || !statSync(hostPath).isFile()) throw new Error(`HOST_NOT_FOUND: ${hostPath}`);
	const json = `${JSON.stringify(manifest, null, 2)}\n`;
	const registrations = [];
	if (platform === "win32") {
		if (CMD_UNSAFE.test(hostPath)) throw new Error("HOST_PATH_UNSAFE: the path contains characters cmd.exe would interpret");
		const dir = manifestDir ?? defaultWindowsManifestDir(env);
		if (!isAbsolute(dir)) throw new Error("MANIFEST_DIR_NOT_ABSOLUTE");
		mkdirSync(dir, { recursive: true });
		const manifestPath = join(dir, MANIFEST_FILE);
		writeFileSync(manifestPath, json);
		for (const { browser, key } of windowsKeys(list, registryKeys)) {
			try {
				reg.setDefault(key, manifestPath);
			} catch {
				throw new Error(`REGISTRY_WRITE_FAILED: ${key}`);
			}
			if (reg.getDefault(key) !== manifestPath) throw new Error(`REGISTRY_VERIFY_FAILED: ${key}`);
			registrations.push({ browser, manifestPath, registryKey: key });
		}
	} else {
		const dirs = userManifestDirs(platform, home);
		for (const browser of list) {
			mkdirSync(dirs[browser], { recursive: true });
			const manifestPath = join(dirs[browser], MANIFEST_FILE);
			writeFileSync(manifestPath, json);
			registrations.push({ browser, manifestPath });
		}
	}
	return { ok: true, manifest, registrations };
}

/**
 * Removes the per-user registration (registry key / manifest file). The Windows manifest
 * file is removed too when no remaining registration points at it. Missing entries are fine.
 * @returns {{ ok: true, removed: { browser: string, registryKey?: string, manifestPath?: string }[] }}
 */
export function unregisterNativeHost({
	browsers,
	platform = process.platform,
	home = homedir(),
	reg = windowsRegistry,
	registryKeys = WINDOWS_REGISTRY_KEYS,
} = {}) {
	const list = browsersOf(browsers);
	const removed = [];
	if (platform === "win32") {
		const manifests = new Set();
		for (const { browser, key } of windowsKeys(list, registryKeys)) {
			const current = reg.getDefault(key);
			if (current === null) continue;
			try {
				reg.deleteKey(key);
			} catch {
				throw new Error(`REGISTRY_DELETE_FAILED: ${key}`);
			}
			if (current) manifests.add(current);
			removed.push({ browser, registryKey: key, manifestPath: current || undefined });
		}
		// A manifest another browser's registration still points at is kept.
		const others = BROWSERS.filter((b) => !list.includes(b));
		const stillUsed = new Set(
			manifests.size === 0
				? []
				: windowsKeys(others, registryKeys)
						.map(({ key }) => reg.getDefault(key))
						.filter(Boolean),
		);
		for (const file of manifests) {
			if (!stillUsed.has(file) && file.endsWith(MANIFEST_FILE)) rmSync(file, { force: true });
		}
	} else {
		const dirs = userManifestDirs(platform, home);
		for (const browser of list) {
			const manifestPath = join(dirs[browser], MANIFEST_FILE);
			if (!existsSync(manifestPath)) continue;
			rmSync(manifestPath, { force: true });
			removed.push({ browser, manifestPath });
		}
	}
	return { ok: true, removed };
}

/**
 * Reports, per browser, whether the host is registered for this user and whether the
 * registration is usable (manifest readable, right name, absolute existing host path).
 * @returns {{ ok: true, browsers: { browser: string, registered: boolean, usable: boolean, manifestPath: string | null, hostPath: string | null, allowedOrigins: string[], problem?: string }[] }}
 */
export function nativeHostStatus({
	browsers,
	platform = process.platform,
	home = homedir(),
	reg = windowsRegistry,
	registryKeys = WINDOWS_REGISTRY_KEYS,
} = {}) {
	const list = browsersOf(browsers);
	const out = [];
	for (const browser of list) {
		let manifestPath = null;
		let registryKey;
		if (platform === "win32") {
			registryKey = `${registryKeys[browser]}\\${NATIVE_HOST_NAME}`;
			manifestPath = reg.getDefault(registryKey) || null;
		} else {
			const file = join(userManifestDirs(platform, home)[browser], MANIFEST_FILE);
			manifestPath = existsSync(file) ? file : null;
		}
		const entry = { browser, registered: manifestPath !== null, usable: false, manifestPath, hostPath: null, allowedOrigins: [] };
		if (registryKey) entry.registryKey = registryKey;
		if (manifestPath) {
			try {
				const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
				entry.hostPath = typeof manifest.path === "string" ? manifest.path : null;
				entry.allowedOrigins = Array.isArray(manifest.allowed_origins) ? manifest.allowed_origins : [];
				if (manifest.name !== NATIVE_HOST_NAME) entry.problem = "MANIFEST_NAME_MISMATCH";
				else if (!entry.hostPath || !isAbsolute(entry.hostPath)) entry.problem = "HOST_PATH_NOT_ABSOLUTE";
				else if (!existsSync(entry.hostPath)) entry.problem = "HOST_NOT_FOUND";
				else if (entry.allowedOrigins.length === 0) entry.problem = "NO_ALLOWED_ORIGINS";
				else entry.usable = true;
			} catch {
				entry.problem = "MANIFEST_UNREADABLE";
			}
		}
		out.push(entry);
	}
	return { ok: true, browsers: out };
}

/** packages/privacy's built host entry point. */
export function privacyHostScript() {
	return resolve(dirname(fileURLToPath(import.meta.url)), "../../privacy/dist/native/host.js");
}

/**
 * Development/demo launcher for Windows: a .cmd file that starts the privacy package's
 * host with Node and the given config, passing the browser's arguments through. Chrome
 * and Edge start a non-.exe host through cmd.exe. Production installs use the signed
 * launcher built by packages/privacy/native (or the desktop app's own executable).
 * @returns {{ ok: true, launcherPath: string }}
 */
export function createDevLauncher({ configPath, outDir, nodePath = process.execPath, hostScript = privacyHostScript() }) {
	for (const [name, value] of [
		["config", configPath],
		["out", outDir],
		["node", nodePath],
		["host", hostScript],
	]) {
		if (typeof value !== "string" || !isAbsolute(value)) throw new Error(`ARGUMENT_NOT_ABSOLUTE: ${name}`);
		if (CMD_UNSAFE.test(value)) throw new Error(`PATH_UNSAFE: ${name}`);
	}
	if (!existsSync(hostScript)) throw new Error(`BUILD_REQUIRED: ${hostScript} (pnpm --filter @singularityrd/aidr-privacy build)`);
	if (!existsSync(configPath)) throw new Error(`CONFIG_NOT_FOUND: ${configPath}`);
	mkdirSync(outDir, { recursive: true });
	const launcherPath = join(outDir, "aidr-native-host.cmd");
	// stdout is the binary native-messaging channel: nothing else may print to it.
	writeFileSync(launcherPath, `@echo off\r\n"${nodePath}" "${hostScript}" --config "${configPath}" %*\r\n`);
	return { ok: true, launcherPath };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
	const [command, ...rest] = argv;
	const opts = { command, extensionIds: [], json: false, positional: [] };
	for (let i = 0; i < rest.length; i++) {
		const arg = rest[i];
		const value = () => {
			const v = rest[++i];
			if (v === undefined) throw new UsageError(`${arg} needs a value`);
			return v;
		};
		if (arg === "--json") opts.json = true;
		else if (arg === "--host") opts.hostPath = resolve(value());
		else if (arg === "--extension-id") opts.extensionIds.push(value());
		else if (arg === "--browser") opts.browsers = value().split(",").map((b) => b.trim()).filter(Boolean);
		else if (arg === "--manifest-dir") opts.manifestDir = resolve(value());
		else if (arg === "--config") opts.configPath = resolve(value());
		else if (arg === "--out") opts.outDir = resolve(value());
		else if (arg === "--node") opts.nodePath = resolve(value());
		else if (arg.startsWith("--")) throw new UsageError(`unknown option ${arg}`);
		else opts.positional.push(arg);
	}
	return opts;
}

class UsageError extends Error {}

const USAGE = `usage: node scripts/native-host.mjs <register|unregister|status|create-launcher|extension-id> [options]
  register        --host <abs launcher> --extension-id <id> [--extension-id <id>] [--browser chrome,edge] [--manifest-dir <dir>]
  unregister      [--browser chrome,edge]
  status          [--browser chrome,edge]
  create-launcher --config <host config.json> --out <dir> [--node <node.exe>]   (Windows development/demo launcher)
  extension-id    <unpacked extension dir>
  --json          machine-readable output (one JSON object on stdout)`;

export function main(argv, { log = console.log, error = console.error } = {}) {
	let opts;
	try {
		opts = parseArgs(argv);
		let result;
		switch (opts.command) {
			case "register":
				if (!opts.hostPath) throw new UsageError("register needs --host");
				result = registerNativeHost(opts);
				break;
			case "unregister":
				result = unregisterNativeHost(opts);
				break;
			case "status":
				result = nativeHostStatus(opts);
				break;
			case "create-launcher":
				if (!opts.configPath || !opts.outDir) throw new UsageError("create-launcher needs --config and --out");
				result = createDevLauncher(opts);
				break;
			case "extension-id":
				if (opts.positional.length !== 1) throw new UsageError("extension-id needs one directory");
				result = { ok: true, extensionId: unpackedExtensionId(opts.positional[0]) };
				break;
			default:
				throw new UsageError(opts.command ? `unknown command ${opts.command}` : "missing command");
		}
		log(opts.json ? JSON.stringify(result) : humanReadable(opts.command, result));
		return 0;
	} catch (e) {
		const message = e instanceof Error ? e.message : String(e);
		if (e instanceof UsageError) {
			error(`${message}\n${USAGE}`);
			return 2;
		}
		if (opts?.json) log(JSON.stringify({ ok: false, error: message }));
		else error(`[native-host] ${message}`);
		return 1;
	}
}

function humanReadable(command, result) {
	switch (command) {
		case "register":
			return result.registrations
				.map((r) => `registered for ${r.browser}: ${r.registryKey ? `${r.registryKey} -> ` : ""}${r.manifestPath}`)
				.join("\n");
		case "unregister":
			return result.removed.length === 0
				? "nothing was registered"
				: result.removed.map((r) => `removed for ${r.browser}: ${r.registryKey ?? r.manifestPath}`).join("\n");
		case "status":
			return result.browsers
				.map((b) =>
					b.registered
						? `${b.browser}: registered (${b.usable ? "usable" : b.problem}) ${b.manifestPath} -> ${b.hostPath ?? "?"}`
						: `${b.browser}: not registered`,
				)
				.join("\n");
		case "create-launcher":
			return `launcher: ${result.launcherPath}`;
		default:
			return result.extensionId;
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = main(process.argv.slice(2));
}
