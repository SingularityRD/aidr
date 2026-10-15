// The Electron binary of this package's devDependency. Its download is a
// postinstall step; when pnpm skipped it, run the package's own installer once.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

export function electronBinary() {
	const require = createRequire(import.meta.url);
	const packageDir = dirname(require.resolve("electron/package.json"));
	const resolveBinary = () => {
		try {
			const path = require("electron");
			return typeof path === "string" && existsSync(path) ? path : null;
		} catch {
			return null;
		}
	};
	let binary = resolveBinary();
	if (!binary) {
		console.log("Downloading the Electron binary (electron/install.js)...");
		const result = spawnSync(process.execPath, [join(packageDir, "install.js")], { stdio: "inherit" });
		if (result.status !== 0) throw new Error("the Electron binary could not be installed");
		binary = resolveBinary();
	}
	if (!binary) throw new Error("the Electron binary is missing after install");
	return binary;
}
