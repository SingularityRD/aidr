/**
 * Stage the Windows koffi native addon inside a connector's `dist/vendor/koffi`.
 *
 * Bundled connectors (Claude Code hooks, the Cursor/VS Code hook runner, the
 * OpenClaw plugin) load the native AMSI backend from `dist/vendor/koffi` (see
 * `loadKoffi` in packages/core/src/clients/amsi.ts). Shipping it inside `dist`
 * means the release manifest and installer digest cover the exact bytes the
 * hook loads, and the PowerShell fallback (hundreds of ms per call) is not used.
 *
 * Only the files koffi needs on Windows are copied: its loader, package.json,
 * MIT licence and the three Windows `koffi.node` builds. No dependency tree is
 * copied and no links are followed.
 */
import { copyFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const KOFFI_SHIPPED_FILES = Object.freeze([
	"index.js",
	"package.json",
	"LICENSE.txt",
	...["win32_x64", "win32_arm64", "win32_ia32"].map((arch) =>
		join("build", "koffi", arch, "koffi.node"),
	),
]);

/**
 * @param {string} packageDir connector package directory (resolves koffi from there)
 * @param {{ isRelease: boolean }} options a release (or any Windows build) requires koffi
 * @returns {boolean} whether the addon was staged
 */
export function stageWindowsKoffi(packageDir, { isRelease }) {
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
	const vendor = join(packageDir, "dist", "vendor", "koffi");
	for (const relative of KOFFI_SHIPPED_FILES) {
		const from = join(source, relative);
		if (!existsSync(from) || !statSync(from).isFile()) {
			throw new Error(
				`Windows AMSI release dependency is incomplete: koffi/${relative.replaceAll("\\", "/")}`,
			);
		}
		const to = join(vendor, relative);
		mkdirSync(dirname(to), { recursive: true });
		copyFileSync(from, to);
	}
	return true;
}
