import { chmodSync, copyFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

// Avoid Node's recursive cp binding failing on Windows paths with non-ASCII
// characters. These are public deployment inputs; private secrets are written
// separately by deployment-prepare with their existing restrictive modes.
export function cpSync(source, destination, options = {}) {
	if (options.filter && !options.filter(source)) return;
	const sourceInfo = statSync(source);
	if (sourceInfo.isDirectory()) {
		mkdirSync(destination, { recursive: true, mode: 0o755 });
		for (const entry of readdirSync(source)) cpSync(join(source, entry), join(destination, entry), options);
	} else {
		mkdirSync(dirname(destination), { recursive: true, mode: 0o755 });
		copyFileSync(source, destination);
		if (process.platform !== "win32") chmodSync(destination, sourceInfo.mode & 0o755);
	}
}
