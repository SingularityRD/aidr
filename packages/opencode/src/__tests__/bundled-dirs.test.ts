import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { getAidrVersion, getBundledDataDirs } from "../bundled-dirs.js";

describe("bundled-dirs", () => {
	it("reports the OpenCode connector's own package version", () => {
		const pkg = JSON.parse(
			readFileSync(resolve(__dirname, "..", "..", "package.json"), "utf8"),
		) as { version: string };
		expect(getAidrVersion()).toBe(pkg.version);
	});

	it("resolves bundled threat and allowlist directories next to the plugin entry", () => {
		// sync-assets writes them to dist/resources, beside the shipped plugin.
		const dirs = getBundledDataDirs();
		expect(dirs.packageRoot).toBe(join(dirs.pluginDir, ".."));
		expect(dirs.threatsDir).toBe(join(dirs.pluginDir, "resources", "threats"));
		expect(dirs.allowlistsDir).toBe(join(dirs.pluginDir, "resources", "allowlists"));
	});
});
