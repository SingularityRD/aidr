import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// Every package's `src` tree is emitted 1:1 into `dist`, and the build copies the repository
// LICENSE to `dist/LICENSE`. On case-insensitive file systems (Windows, default macOS) a source
// entry named `license` would become the same path, breaking the build and the npm extraction.
const packagesRoot = join(__dirname, "..", "..", "..");
const reserved = new Set(["license", "license.md", "license.txt"]);

describe("dist output has no case-insensitive collisions", () => {
	for (const pkg of readdirSync(packagesRoot, { withFileTypes: true }).filter((entry) =>
		entry.isDirectory(),
	)) {
		it(`${pkg.name}/src has no entry that collides with dist/LICENSE`, () => {
			let entries: string[];
			try {
				entries = readdirSync(join(packagesRoot, pkg.name, "src"));
			} catch {
				return;
			}
			// A source file is emitted with a .js extension (license.ts -> license.js), so only an entry
			// that keeps its exact name in dist (a directory or an extensionless file) can collide.
			const emitted = entries.map((name) =>
				name.replace(/\.(ts|tsx|mts|cts)$/, ".js").toLowerCase(),
			);
			expect(emitted.filter((name) => reserved.has(name))).toEqual([]);
			expect(new Set(emitted).size, "two src entries differ only by letter case").toBe(
				emitted.length,
			);
		});
	}
});
