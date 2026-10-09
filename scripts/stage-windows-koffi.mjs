/**
 * Stage the Windows koffi native addon inside a connector's `dist/vendor/koffi`.
 *
 * Bundled connectors (Claude Code hooks, the Cursor/VS Code hook runner, the
 * OpenClaw plugin) load the native AMSI backend from `dist/vendor/koffi` (see
 * `loadKoffi` in packages/core/src/clients/amsi.ts). Shipping it inside `dist`
 * means the release manifest and installer digest cover the exact bytes the
 * hook loads, and the PowerShell fallback (hundreds of ms per call) is not used.
 *
 * Koffi 3 split its native code out of the `koffi` package: the loader lives in
 * `koffi/src/koffi/index.{js,cjs}` and each prebuilt `koffi.node` ships in its
 * own `@koromix/koffi-<platform>-<arch>` optional dependency. The root
 * `pnpm.supportedArchitectures` setting makes pnpm install the three Windows
 * builds on every host so a release can be staged from any OS.
 *
 * Staged layout (`dist/vendor/koffi`):
 *   index.js / index.cjs        generated entry points re-exporting the loader
 *   lib/koffi/index.{js,cjs}    koffi's loader, with `loadStatic` disabled
 *   build/koffi/win32_<arch>/koffi.node
 *   package.json, LICENSE.txt   copied verbatim
 *
 * The loader is moved from `src/koffi` to `lib/koffi` because release packages
 * must not ship a `src/` directory (verify-package-install.mjs); it stays two
 * levels below the payload root, so its `../../build/koffi/<triplet>` probe finds
 * the staged binaries (the same paths koffi 2 used). Koffi's other lookup,
 * `loadStatic`, would `require("@koromix/koffi-…")` from whatever `node_modules`
 * sits above the installed connector, i.e. load bytes the manifest does not
 * cover, so the staged loader replaces it with a function that returns null.
 * Every rewrite asserts a single exact match: a koffi update that changes the
 * loader fails the build instead of shipping an unpatched copy.
 *
 * No dependency tree is copied and no links are followed.
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

/** Windows architectures shipped, as koffi names its native build folders. */
export const KOFFI_WINDOWS_ARCHES = Object.freeze(["win32_x64", "win32_arm64", "win32_ia32"]);

const HEADER = "// Staged by Singularity AIDR (scripts/stage-windows-koffi.mjs).\n";

/** Files copied verbatim from the koffi package (POSIX-relative). */
const KOFFI_COPIED_FILES = Object.freeze(["package.json", "LICENSE.txt"]);

/** Generated entry points (koffi's own point at `./src/koffi`). */
const KOFFI_ENTRY_FILES = Object.freeze({
	"index.js": `${HEADER}export { default } from "./lib/koffi/index.js";\nexport * from "./lib/koffi/index.js";\n`,
	"index.cjs": `${HEADER}module.exports = require("./lib/koffi/index.cjs");\n`,
});

/** Loader files: staged path -> [koffi source path, exact text to replace, replacement]. */
const KOFFI_LOADER_FILES = Object.freeze({
	"lib/koffi/index.js": [
		"src/koffi/index.js",
		'import { loadStatic } from "./src/static.js";',
		"const loadStatic = () => null; // AIDR: only load the staged build/koffi binaries",
	],
	"lib/koffi/index.cjs": [
		"src/koffi/index.cjs",
		'var { loadStatic } = require("./src/static.cjs");',
		"var loadStatic = () => null; // AIDR: only load the staged build/koffi binaries",
	],
});

/** Every non-binary file of the staged payload, POSIX-relative to `dist/vendor/koffi`. */
export const KOFFI_RUNTIME_FILES = Object.freeze([
	...KOFFI_COPIED_FILES,
	...Object.keys(KOFFI_ENTRY_FILES),
	...Object.keys(KOFFI_LOADER_FILES),
]);

/** Path of one architecture's native build, POSIX-relative to `dist/vendor/koffi`. */
export function koffiNativeBinary(arch) {
	return `build/koffi/${arch}/koffi.node`;
}

/** The complete staged payload, POSIX-relative to `dist/vendor/koffi`. */
export const KOFFI_WINDOWS_PAYLOAD_FILES = Object.freeze([
	...KOFFI_RUNTIME_FILES,
	...KOFFI_WINDOWS_ARCHES.map(koffiNativeBinary),
]);

/** The host architecture's koffi build folder name on Windows. */
export function hostKoffiWindowsArch() {
	return process.arch === "arm64" ? "win32_arm64" : process.arch === "ia32" ? "win32_ia32" : "win32_x64";
}

function requireFile(path, label) {
	if (!existsSync(path) || !statSync(path).isFile()) {
		throw new Error(`Windows AMSI release dependency is incomplete: ${label}`);
	}
	return path;
}

function writeStaged(vendor, relative, content) {
	const to = join(vendor, ...relative.split("/"));
	mkdirSync(dirname(to), { recursive: true });
	writeFileSync(to, content);
}

/**
 * @param {string} packageDir connector package directory (resolves koffi from there)
 * @param {{ isRelease: boolean, vendorDir?: string }} options a release (or any Windows
 *   build) requires koffi; `vendorDir` defaults to `<packageDir>/dist/vendor/koffi`
 * @returns {boolean} whether the addon was staged
 */
export function stageWindowsKoffi(packageDir, { isRelease, vendorDir }) {
	const require = createRequire(join(packageDir, "package.json"));
	let source;
	try {
		source = dirname(require.resolve("koffi"));
	} catch (error) {
		if (isRelease || process.platform === "win32") {
			throw new Error("Windows AMSI release requires the pinned koffi package", { cause: error });
		}
		return false;
	}
	const { version } = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
	const fromKoffi = createRequire(join(source, "package.json"));

	const copies = KOFFI_COPIED_FILES.map((relative) => [
		requireFile(join(source, ...relative.split("/")), `koffi/${relative}`),
		relative,
	]);
	for (const arch of KOFFI_WINDOWS_ARCHES) {
		const nativePackage = `@koromix/koffi-${arch.replace("_", "-")}`;
		let nativeRoot;
		try {
			nativeRoot = dirname(fromKoffi.resolve(`${nativePackage}/package.json`));
		} catch (error) {
			throw new Error(
				`Windows AMSI release dependency is missing: ${nativePackage} (pnpm.supportedArchitectures must include win32 x64/arm64/ia32)`,
				{ cause: error },
			);
		}
		const nativeVersion = JSON.parse(readFileSync(join(nativeRoot, "package.json"), "utf8")).version;
		if (nativeVersion !== version) {
			throw new Error(`Windows AMSI release dependency mismatch: ${nativePackage}@${nativeVersion} != koffi@${version}`);
		}
		copies.push([requireFile(join(nativeRoot, arch, "koffi.node"), `${nativePackage}/${arch}/koffi.node`), koffiNativeBinary(arch)]);
	}
	const loaders = Object.entries(KOFFI_LOADER_FILES).map(([relative, [from, search, replacement]]) => {
		const text = readFileSync(requireFile(join(source, ...from.split("/")), `koffi/${from}`), "utf8");
		if (text.split(search).length !== 2) {
			throw new Error(`koffi@${version} loader koffi/${from} changed: cannot disable loadStatic; review the staging script`);
		}
		return [relative, text.replace(search, replacement)];
	});

	const vendor = vendorDir ?? join(packageDir, "dist", "vendor", "koffi");
	for (const [from, relative] of copies) {
		const to = join(vendor, ...relative.split("/"));
		mkdirSync(dirname(to), { recursive: true });
		copyFileSync(from, to);
	}
	for (const [relative, content] of [...Object.entries(KOFFI_ENTRY_FILES), ...loaders]) {
		writeStaged(vendor, relative, content);
	}
	return true;
}
