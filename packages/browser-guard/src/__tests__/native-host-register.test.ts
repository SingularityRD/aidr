import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
	createDevLauncher,
	extensionIdForPath,
	hostManifest,
	main,
	NATIVE_HOST_NAME,
	nativeHostStatus,
	registerNativeHost,
	unpackedExtensionId,
	unregisterNativeHost,
	WINDOWS_REGISTRY_KEYS,
	windowsRegistry,
} from "../../scripts/native-host.mjs";
import { NATIVE_HOST_NAME as BRIDGE_HOST_NAME } from "../background/native";

const ID = "ibdhpgfoldmfbkodfbnlojbbgggmcjnm";
const ID2 = "abcdefghijklmnopabcdefghijklmnop";

const temps: string[] = [];
function tempDir(prefix = "aidr-native-host-"): string {
	const dir = mkdtempSync(join(tmpdir(), prefix));
	temps.push(dir);
	return dir;
}
afterAll(() => {
	for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

/** In-memory HKCU default values, same interface as windowsRegistry. */
function fakeRegistry() {
	const values = new Map<string, string>();
	return {
		values,
		setDefault(key: string, value: string) {
			values.set(key, value);
		},
		getDefault(key: string) {
			return values.has(key) ? (values.get(key) as string) : null;
		},
		deleteKey(key: string) {
			return values.delete(key);
		},
	};
}

function fakeHost(dir: string): string {
	const host = join(dir, "aidr-native-launcher.exe");
	writeFileSync(host, "MZ");
	return host;
}

describe("native host registration: manifest", () => {
	it("uses the bridge's host name and exact extension origins", () => {
		expect(NATIVE_HOST_NAME).toBe(BRIDGE_HOST_NAME);
		const manifest = hostManifest({
			hostPath: join(tmpdir(), "host.exe"),
			extensionIds: [ID, ID2, ID],
		});
		expect(manifest).toEqual({
			name: "com.singularity.aidr_privacy",
			description: expect.any(String),
			path: join(tmpdir(), "host.exe"),
			type: "stdio",
			allowed_origins: [`chrome-extension://${ID}/`, `chrome-extension://${ID2}/`],
		});
	});

	it("refuses relative host paths and malformed extension ids", () => {
		expect(() => hostManifest({ hostPath: "host.exe", extensionIds: [ID] })).toThrow(
			"HOST_PATH_NOT_ABSOLUTE",
		);
		expect(() => hostManifest({ hostPath: join(tmpdir(), "h.exe"), extensionIds: [] })).toThrow(
			"EXTENSION_ID_INVALID",
		);
		expect(() =>
			hostManifest({ hostPath: join(tmpdir(), "h.exe"), extensionIds: ["ABC"] }),
		).toThrow("EXTENSION_ID_INVALID");
		expect(() =>
			hostManifest({ hostPath: join(tmpdir(), "h.exe"), extensionIds: ["q".repeat(32)] }),
		).toThrow("EXTENSION_ID_INVALID");
	});
});

describe("native host registration: unpacked extension id", () => {
	it("matches the id Chromium assigned on Windows (UTF-16LE path, upper-case drive)", () => {
		// Observed: Chrome for Testing 153 loaded this path as ibdhpgfoldmfbkodfbnlojbbgggmcjnm.
		const path =
			"C:\\Users\\anill\\Desktop\\aidr-restored\\.claude\\worktrees\\agent-abcc7bfd6c549d667\\packages\\browser-guard\\dist\\chrome";
		expect(extensionIdForPath(path, "win32")).toBe(ID);
		expect(extensionIdForPath(`c${path.slice(1)}`, "win32")).toBe(ID);
		expect(extensionIdForPath(path, "linux")).not.toBe(ID);
		expect(extensionIdForPath("/opt/ext", "linux")).toMatch(/^[a-p]{32}$/);
		expect(unpackedExtensionId(tempDir())).toMatch(/^[a-p]{32}$/);
	});
});

describe("native host registration: Windows (HKCU)", () => {
	it("writes one manifest and points each browser's HKCU key at it", () => {
		const reg = fakeRegistry();
		const dir = tempDir();
		const host = fakeHost(dir);
		const manifestDir = join(dir, "manifests");
		const result = registerNativeHost({
			hostPath: host,
			extensionIds: [ID],
			manifestDir,
			platform: "win32",
			reg,
		});
		const manifestPath = join(manifestDir, "com.singularity.aidr_privacy.json");
		expect(result.registrations).toEqual([
			{
				browser: "chrome",
				manifestPath,
				registryKey:
					"HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.singularity.aidr_privacy",
			},
			{
				browser: "edge",
				manifestPath,
				registryKey:
					"HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.singularity.aidr_privacy",
			},
		]);
		expect([...reg.values.keys()].every((k) => k.startsWith("HKCU\\"))).toBe(true);
		expect(JSON.parse(readFileSync(manifestPath, "utf8")).path).toBe(host);

		const status = nativeHostStatus({
			browsers: ["chrome", "edge", "chromium"],
			platform: "win32",
			reg,
		});
		expect(
			status.browsers.map((b: { browser: string; usable: boolean }) => [b.browser, b.usable]),
		).toEqual([
			["chrome", true],
			["edge", true],
			["chromium", false],
		]);
		expect(status.browsers[0].allowedOrigins).toEqual([`chrome-extension://${ID}/`]);

		// Removing Chrome keeps the shared manifest for Edge; removing Edge deletes it.
		unregisterNativeHost({ browsers: ["chrome"], platform: "win32", reg });
		expect(existsSync(manifestPath)).toBe(true);
		const removed = unregisterNativeHost({ browsers: ["chrome", "edge"], platform: "win32", reg });
		expect(removed.removed.map((r: { browser: string }) => r.browser)).toEqual(["edge"]);
		expect(existsSync(manifestPath)).toBe(false);
		expect(reg.values.size).toBe(0);
	});

	it("reports a registration whose host is gone or whose manifest is broken as not usable", () => {
		const reg = fakeRegistry();
		const dir = tempDir();
		const host = fakeHost(dir);
		registerNativeHost({
			hostPath: host,
			extensionIds: [ID],
			manifestDir: dir,
			browsers: ["edge"],
			platform: "win32",
			reg,
		});
		rmSync(host);
		let status = nativeHostStatus({ browsers: ["edge"], platform: "win32", reg }).browsers[0];
		expect([status.registered, status.usable, status.problem]).toEqual([
			true,
			false,
			"HOST_NOT_FOUND",
		]);
		writeFileSync(join(dir, "com.singularity.aidr_privacy.json"), "{");
		status = nativeHostStatus({ browsers: ["edge"], platform: "win32", reg }).browsers[0];
		expect(status.problem).toBe("MANIFEST_UNREADABLE");
	});

	it("refuses a missing host, unknown browsers and paths cmd.exe would interpret", () => {
		const reg = fakeRegistry();
		const dir = tempDir();
		expect(() =>
			registerNativeHost({
				hostPath: join(dir, "missing.exe"),
				extensionIds: [ID],
				platform: "win32",
				reg,
			}),
		).toThrow("HOST_NOT_FOUND");
		const host = fakeHost(dir);
		expect(() =>
			registerNativeHost({
				hostPath: host,
				extensionIds: [ID],
				browsers: ["firefox"],
				platform: "win32",
				reg,
			}),
		).toThrow("BROWSER_INVALID");
		const unsafeDir = join(dir, "a&b");
		mkdirSync(unsafeDir);
		const unsafe = fakeHost(unsafeDir);
		expect(() =>
			registerNativeHost({ hostPath: unsafe, extensionIds: [ID], platform: "win32", reg }),
		).toThrow("HOST_PATH_UNSAFE");
		expect(reg.values.size).toBe(0);
	});

	it("fails when the registry does not hold what was written", () => {
		const dir = tempDir();
		const reg = { ...fakeRegistry(), getDefault: () => "C:\\elsewhere.json" };
		expect(() =>
			registerNativeHost({
				hostPath: fakeHost(dir),
				extensionIds: [ID],
				manifestDir: dir,
				platform: "win32",
				reg,
			}),
		).toThrow("REGISTRY_VERIFY_FAILED");
	});

	it("only ever touches HKCU keys", () => {
		expect(
			Object.values(WINDOWS_REGISTRY_KEYS).every((k) =>
				(k as string).startsWith("HKCU\\Software\\"),
			),
		).toBe(true);
		expect(() => windowsRegistry.getDefault("HKLM\\Software\\Google")).toThrow(
			"REGISTRY_KEY_INVALID",
		);
		expect(() => windowsRegistry.setDefault("HKCU\\Software\\x'; Remove-Item C:\\", "v")).toThrow(
			"REGISTRY_KEY_INVALID",
		);
	});
});

describe("native host registration: macOS and Linux (per-user manifest directories)", () => {
	for (const [platform, chromeDir, edgeDir] of [
		[
			"linux",
			".config/google-chrome/NativeMessagingHosts",
			".config/microsoft-edge/NativeMessagingHosts",
		],
		[
			"darwin",
			"Library/Application Support/Google/Chrome/NativeMessagingHosts",
			"Library/Application Support/Microsoft Edge/NativeMessagingHosts",
		],
	] as const) {
		it(`writes the manifest into the user's ${platform} browser directories`, () => {
			const home = tempDir();
			const host = fakeHost(home);
			const result = registerNativeHost({ hostPath: host, extensionIds: [ID], platform, home });
			expect(result.registrations.map((r: { manifestPath: string }) => r.manifestPath)).toEqual([
				join(home, chromeDir, "com.singularity.aidr_privacy.json"),
				join(home, edgeDir, "com.singularity.aidr_privacy.json"),
			]);
			expect(
				nativeHostStatus({ platform, home }).browsers.every((b: { usable: boolean }) => b.usable),
			).toBe(true);
			unregisterNativeHost({ platform, home });
			expect(
				nativeHostStatus({ platform, home }).browsers.some(
					(b: { registered: boolean }) => b.registered,
				),
			).toBe(false);
		});
	}
});

describe("native host registration: development launcher and CLI", () => {
	it("writes a .cmd launcher that passes the browser's arguments to the privacy host", () => {
		const dir = tempDir();
		const config = join(dir, "config.json");
		writeFileSync(config, "{}");
		const hostScript = join(dir, "host.js");
		writeFileSync(hostScript, "");
		const { launcherPath } = createDevLauncher({
			configPath: config,
			outDir: join(dir, "out"),
			nodePath: process.execPath,
			hostScript,
		});
		expect(readFileSync(launcherPath, "utf8")).toBe(
			`@echo off\r\n"${process.execPath}" "${hostScript}" --config "${config}" %*\r\n`,
		);
		expect(() =>
			createDevLauncher({
				configPath: join(dir, "50%.json"),
				outDir: dir,
				nodePath: process.execPath,
				hostScript,
			}),
		).toThrow("PATH_UNSAFE: config");
		expect(() => createDevLauncher({ configPath: "config.json", outDir: dir, hostScript })).toThrow(
			"ARGUMENT_NOT_ABSOLUTE: config",
		);
	});

	it("CLI: usage errors exit 2, --json prints one object, failures exit 1", () => {
		const out: string[] = [];
		const err: string[] = [];
		const io = { log: (s: string) => out.push(s), error: (s: string) => err.push(s) };
		expect(main([], io)).toBe(2);
		expect(main(["register", "--json"], io)).toBe(2);
		expect(main(["frobnicate"], io)).toBe(2);
		const dir = tempDir();
		expect(main(["extension-id", dir, "--json"], io)).toBe(0);
		expect(JSON.parse(out.at(-1) as string)).toEqual({
			ok: true,
			extensionId: unpackedExtensionId(dir),
		});
		expect(
			main(["register", "--host", join(dir, "missing.exe"), "--extension-id", ID, "--json"], io),
		).toBe(1);
		expect(JSON.parse(out.at(-1) as string)).toMatchObject({
			ok: false,
			error: expect.stringContaining("HOST_NOT_FOUND"),
		});
	});
});

// Real registry, Windows only: a scratch HKCU key stands in for the browsers' keys, so the
// user's Chrome/Edge registrations are never touched. A non-ASCII manifest directory checks
// that the path survives reg.exe and the PowerShell read (Turkish profile names).
describe.runIf(process.platform === "win32")(
	"native host registration: live HKCU round trip (scratch key)",
	() => {
		it("registers, reads back, reports and removes", () => {
			const scratch = `HKCU\\Software\\SingularityAIDR-Test-${process.pid}-${Date.now()}`;
			const registryKeys = {
				chrome: `${scratch}\\Chrome`,
				edge: `${scratch}\\Edge`,
				chromium: `${scratch}\\Chromium`,
			};
			const dir = tempDir("aidr-native-host-İşçi Ömer-");
			const host = fakeHost(dir);
			try {
				const result = registerNativeHost({
					hostPath: host,
					extensionIds: [ID],
					manifestDir: join(dir, "manifests"),
					platform: "win32",
					registryKeys,
				});
				const manifestPath = result.registrations[0].manifestPath;
				expect(windowsRegistry.getDefault(`${registryKeys.chrome}\\${NATIVE_HOST_NAME}`)).toBe(
					manifestPath,
				);
				const status = nativeHostStatus({ platform: "win32", registryKeys });
				expect(status.browsers.map((b: { usable: boolean }) => b.usable)).toEqual([true, true]);
				unregisterNativeHost({ platform: "win32", registryKeys });
				expect(windowsRegistry.getDefault(`${registryKeys.edge}\\${NATIVE_HOST_NAME}`)).toBeNull();
				expect(existsSync(manifestPath)).toBe(false);
			} finally {
				try {
					execFileSync("reg.exe", ["delete", scratch, "/f"], { stdio: "ignore" });
				} catch {
					// already gone
				}
			}
		}, 30_000);
	},
);
