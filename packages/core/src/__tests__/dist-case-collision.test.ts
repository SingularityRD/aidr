import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Every package's `src` tree is emitted 1:1 into `dist`, and the build copies the repository
// LICENSE to `dist/LICENSE`. On case-insensitive file systems (Windows, default macOS) a source
// entry named `license` would become the same path, breaking the build and the npm extraction.
const packagesRoot = join(__dirname, "..", "..", "..");
const reserved = new Set(["license", "license.md", "license.txt"]);

describe("dist output has no case-insensitive collisions", () => {
	for (const pkg of readdirSync(packagesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory())) {
		it(`${pkg.name}/src has no entry that collides with dist/LICENSE`, () => {
			let entries: string[];
			try {
				entries = readdirSync(join(packagesRoot, pkg.name, "src"));
			} catch {
				return;
			}
			const lower = entries.map((name) => name.replace(/\.(ts|tsx|js|mjs)$/, "").toLowerCase());
			expect(lower.filter((name) => reserved.has(name))).toEqual([]);
			expect(new Set(lower).size, "two src entries differ only by letter case").toBe(lower.length);
		});
	}
});
