/**
 * Shared Chromium launch for the print renderers (scripts/render-brochure.mjs,
 * render-catalog.mjs, render-feature-guide.mjs).
 *
 * Two things make a re-render of an unchanged page differ from machine to machine, and the
 * renderers' layout checks (rightly) fail on the difference:
 *
 * - Fonts. The brochure and catalog are fixed A4 pages fitted to Liberation Sans / Liberation
 *   Mono, which is what their CSS font stacks resolve to on Linux without Inter or Segoe UI.
 *   With Inter installed (or a fontconfig rule preferring Inter for Segoe UI, Helvetica Neue
 *   and sans-serif) the same text is wider and pages overflow. On Linux the renderer
 *   therefore runs Chromium with FONTCONFIG_FILE=scripts/lib/render-fonts.conf, which hides
 *   every font except Liberation, DejaVu and Noto Color Emoji.
 * - The Chromium build. playwright-core looks for the exact revision it pins; when only
 *   another Playwright Chromium is installed (a CI image that lags the pin), the newest
 *   installed one is used and logged, the same fallback as the Browser Guard E2E harness.
 *   AIDR_CHROMIUM_PATH overrides both.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const RENDER_FONTS_CONF = path.join(repositoryRoot, "scripts", "lib", "render-fonts.conf");
/** The families the fixed-size pages are fitted to; rendering without them is refused. */
const REQUIRED_FAMILIES = ["Liberation Sans", "Liberation Mono"];

const browserGuardRequire = () => createRequire(path.join(repositoryRoot, "packages", "browser-guard", "package.json"));

/** Where Playwright installs browsers, per platform, plus the CI image location. */
function browserRoots() {
	const home = os.homedir();
	return [
		process.env.PLAYWRIGHT_BROWSERS_PATH,
		"/opt/pw-browsers",
		process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, "ms-playwright"),
		path.join(home, ".cache", "ms-playwright"),
		path.join(home, "Library", "Caches", "ms-playwright"),
	].filter((dir) => dir && existsSync(dir));
}

function chromiumExecutable(dir) {
	const mac = path.join("Chromium.app", "Contents", "MacOS", "Chromium");
	const layouts = [
		path.join("chrome-linux", "chrome"),
		path.join("chrome-linux64", "chrome"),
		path.join("chrome-win", "chrome.exe"),
		path.join("chrome-win64", "chrome.exe"),
		path.join("chrome-mac", mac),
		path.join("chrome-mac-arm64", mac),
		path.join("chrome-mac-x64", mac),
	];
	return layouts.map((layout) => path.join(dir, layout)).find((file) => existsSync(file));
}

/**
 * undefined when playwright-core can launch its own pinned build; otherwise the executable to
 * pass as `executablePath` (AIDR_CHROMIUM_PATH, or the newest installed Playwright Chromium).
 */
function chromiumExecutablePath(chromium, log = console.error) {
	if (process.env.AIDR_CHROMIUM_PATH) return process.env.AIDR_CHROMIUM_PATH;
	try {
		if (existsSync(chromium.executablePath())) return undefined;
	} catch {
		// Unknown pinned executable: look for an installed build below.
	}
	let pinned;
	try {
		const browsers = JSON.parse(readFileSync(path.join(path.dirname(browserGuardRequire().resolve("playwright-core/package.json")), "browsers.json"), "utf8"));
		pinned = browsers.browsers.find((browser) => browser.name === "chromium")?.revision;
	} catch {
		// Fall through to the newest installed build.
	}
	const installed = [];
	for (const root of browserRoots()) {
		for (const entry of readdirSync(root)) {
			const revision = Number(/^chromium-(\d+)$/.exec(entry)?.[1]);
			const executable = revision ? chromiumExecutable(path.join(root, entry)) : undefined;
			if (executable) installed.push({ revision, executable });
		}
	}
	const newest = installed.sort((a, b) => b.revision - a.revision)[0];
	if (!newest) return undefined; // let playwright-core report the missing browser
	log(`chromium: chromium-${pinned ?? "?"} (pinned by playwright-core) is not installed; using chromium-${newest.revision} at ${newest.executable} (set AIDR_CHROMIUM_PATH to choose another build)`);
	return newest.executable;
}

/** Environment for Chromium: on Linux, only the fonts in render-fonts.conf are visible. */
function renderEnvironment() {
	if (process.platform !== "linux") return { ...process.env };
	const env = { ...process.env, FONTCONFIG_FILE: RENDER_FONTS_CONF };
	let families;
	try {
		families = execFileSync("fc-list", [":", "family"], { env, encoding: "utf8" });
	} catch {
		return env; // no fc-list to check with; Chromium still reads the config
	}
	const missing = REQUIRED_FAMILIES.filter((family) => !families.split("\n").some((line) => line.split(",").includes(family)));
	if (missing.length > 0) {
		throw new Error(`The renderer needs the ${missing.join(" and ")} fonts (Debian/Ubuntu: apt-get install fonts-liberation; Fedora: dnf install liberation-fonts). The pages are fitted to their metrics.`);
	}
	return env;
}

/** playwright-core's chromium, resolved from packages/browser-guard where it is a devDependency. */
export function loadChromium() {
	try {
		return browserGuardRequire()("playwright-core").chromium;
	} catch (error) {
		throw new Error(`playwright-core is not installed for packages/browser-guard (run pnpm install): ${error.message}`);
	}
}

/** Launch Chromium with the pinned font set and a usable Chromium build. */
export function launchRenderBrowser(chromium) {
	const executablePath = chromiumExecutablePath(chromium);
	return chromium.launch({ env: renderEnvironment(), ...(executablePath ? { executablePath } : {}) });
}
